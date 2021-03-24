package nebula

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/flynn/noise"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/net/ipv4"
)

const (
	minFwPacketLen = 4
)

func (f *Interface) readOutsidePackets(pair *pair, addr *udpAddr, out []byte, packet []byte, header *Header, gossipPacket *GossipPacket, fwPacket *FirewallPacket, lhh *LightHouseHandler, nb []byte) {
	err := header.Parse(packet)
	if err != nil {
		// TODO: best if we return this and let caller log
		// TODO: Might be better to send the literal []byte("holepunch") packet and ignore that?
		// Hole punch packets are 0 or 1 byte big, so lets ignore printing those errors
		if len(packet) > 1 {
			l.WithField("packet", packet).Infof("Error while parsing inbound packet from %s: %s", addr, err)
		}
		return
	}

	// verify if we've seen this index before, otherwise respond to the handshake initiation
	hostinfo, err := f.hostMap.QueryIndex(header.RemoteIndex)

	var ci *ConnectionState
	if err == nil {
		ci = hostinfo.ConnectionState
	}

	switch header.Type {
	case message:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		f.decryptToTun(pair, hostinfo, header.MessageCounter, out, packet, gossipPacket, fwPacket, nb)

		// Fallthrough to the bottom to record incoming traffic
	case ackPath:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		f.handlePathAck(hostinfo, header.MessageCounter, fwPacket, packet, nb, out)

	case lightHouse:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		d, err := f.decrypt(hostinfo, header.MessageCounter, out, packet, header, nb)
		if err != nil {
			hostinfo.logger().WithError(err).WithField("udpAddr", addr).
				WithField("packet", packet).
				Error("Failed to decrypt lighthouse packet")

			//TODO: maybe after build 64 is out? 06/14/2018 - NB
			//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
			return
		}

		lhh.HandleRequest(addr, hostinfo.hostId, d, hostinfo.GetCert(), f)

		// Fallthrough to the bottom to record incoming traffic

	case test:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		d, err := f.decrypt(hostinfo, header.MessageCounter, out, packet, header, nb)
		if err != nil {
			hostinfo.logger().WithError(err).WithField("udpAddr", addr).
				WithField("packet", packet).
				Error("Failed to decrypt test packet")

			//TODO: maybe after build 64 is out? 06/14/2018 - NB
			//f.sendRecvError(net.Addr(addr), header.RemoteIndex)
			return
		}

		if header.Subtype == testRequest {
			// This testRequest might be from TryPromoteBest, so we should roam
			// to the new IP address before responding
			f.handleHostRoaming(hostinfo, addr)
			f.send(test, testReply, ci, hostinfo, hostinfo.remote, d, nb, out)
		}

		// Fallthrough to the bottom to record incoming traffic

		// Non encrypted messages below here, they should not fall through to avoid tracking incoming traffic since they
		// are unauthenticated

	case handshake:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		HandleIncomingHandshake(f, addr, packet, header, hostinfo)
		return

	case recvError:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		// TODO: Remove this with recv_error deprecation
		f.handleRecvError(addr, header)
		return

	case closeTunnel:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		if !f.handleEncrypted(ci, addr, header) {
			return
		}

		hostinfo.logger().WithField("udpAddr", addr).
			Info("Close tunnel received, tearing down.")

		f.closeTunnel(hostinfo)
		return

	default:
		f.messageMetrics.Rx(header.Type, header.Subtype, 1)
		hostinfo.logger().Debugf("Unexpected packet received from %s", addr)
		return
	}

	f.handleHostRoaming(hostinfo, addr)

	f.connectionManager.In(hostinfo.hostId)
}

func (f *Interface) handlePathAck(hostinfo *HostInfo, messageCounter uint64, fwPacket *FirewallPacket, packet, nb, out []byte) {
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:HeaderLen], packet[HeaderLen:], messageCounter, nb)
	if err != nil {
		hostinfo.logger().WithError(err).Error("Failed to decrypt packet")
		//TODO: maybe after build 64 is out? 06/14/2018 - NB
		//f.sendRecvError(hostinfo.remote, header.RemoteIndex)
		return
	}

	err = newPacket(out, false, fwPacket)
	if err != nil {
		hostinfo.logger().
			WithError(err).
			WithField("udpAddr", hostinfo.remote).
			WithField("packet", out).
			Error("Failed to parse ack path firewall packet")
		return
	}

	fwPacket.withLogger(hostinfo.logger()).Info("received path ACK")

	pair, err := f.pathManager.Establish(fwPacket.LocalIP, fwPacket.RemoteIP, hostinfo)
	if err != nil {
		fwPacket.
			withLogger(hostinfo.logger()).
			WithError(err).
			Error("Failed to establish a path")
		return
	}

	if pair.from != 0 {
		h, err := f.hostMap.QueryVpnIP(pair.from)
		if err != nil {
			pair.withLogger(l).WithError(err).Error("Error querying host")
			return
		}

		mc, err := f.plainSend(ackPath, h, out, make([]byte, 12, 12), make([]byte, mtu))
		if err != nil {
			h.logger().WithError(err).
				Error("failed to forward ACK path message")
			return
		}
		if f.lightHouse != nil && mc%5000 == 0 {
			f.lightHouse.Query(fwPacket.RemoteIP, f)
		}
	}
}

func (f *Interface) closeTunnel(hostInfo *HostInfo) {
	//TODO: this would be better as a single function in ConnectionManager that handled locks appropriately
	f.connectionManager.ClearIP(hostInfo.hostId)
	f.connectionManager.ClearPendingDeletion(hostInfo.hostId)
	f.lightHouse.DeleteVpnIP(hostInfo.hostId)
	f.hostMap.DeleteHostInfo(hostInfo)
}

func (f *Interface) handleHostRoaming(hostinfo *HostInfo, addr *udpAddr) {
	if hostDidRoam(hostinfo.remote, addr) {
		if !f.lightHouse.remoteAllowList.Allow(udp2ipInt(addr)) {
			hostinfo.logger().WithField("newAddr", addr).Debug("lighthouse.remote_allow_list denied roaming")
			return
		}
		if !hostinfo.lastRoam.IsZero() && addr.Equals(hostinfo.lastRoamRemote) && time.Since(hostinfo.lastRoam) < RoamingSupressSeconds*time.Second {
			if l.Level >= logrus.DebugLevel {
				hostinfo.logger().WithField("udpAddr", hostinfo.remote).WithField("newAddr", addr).
					Debugf("Supressing roam back to previous remote for %d seconds", RoamingSupressSeconds)
			}
			return
		}

		hostinfo.logger().WithField("udpAddr", hostinfo.remote).WithField("newAddr", addr).
			Info("Host roamed to new udp ip/port.")
		hostinfo.lastRoam = time.Now()
		remoteCopy := *hostinfo.remote
		hostinfo.lastRoamRemote = &remoteCopy
		hostinfo.SetRemote(*addr)
		if f.lightHouse.amLighthouse {
			f.lightHouse.AddRemote(hostinfo.hostId, addr, false)
		}
	}

}

func (f *Interface) handleEncrypted(ci *ConnectionState, addr *udpAddr, header *Header) bool {
	// If connection state exists and the replay protector allows, process packet
	// Else, send recv errors for 300 seconds after a restart to allow fast reconnection.
	if ci == nil || !ci.window.Check(header.MessageCounter) {
		f.sendRecvError(addr, header.RemoteIndex)
		return false
	}

	return true
}

func newAckPathPacket(fp *FirewallPacket, data []byte, out []byte) error {

	// extract the IPV4 header from the packet
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return fmt.Errorf("packet is less than %v bytes", ipv4.HeaderLen)
	}

	// Is it an ipv4 packet?
	if int((data[0]>>4)&0x0f) != 4 {
		return fmt.Errorf("packet is not ipv4, type: %v", int((data[0]>>4)&0x0f))
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2
	if !fp.Fragment && fp.Protocol != fwProtoICMP {
		ihl += minFwPacketLen
	}

	out = data[:ihl]

	return nil
}

// newPacket validates and parses the interesting bits for the firewall out of the ip and sub protocol headers
func newPacket(data []byte, incoming bool, fp *FirewallPacket) error {
	// Do we at least have an ipv4 header worth of data?
	if len(data) < ipv4.HeaderLen {
		return fmt.Errorf("packet is less than %v bytes", ipv4.HeaderLen)
	}

	// Is it an ipv4 packet?
	if int((data[0]>>4)&0x0f) != 4 {
		return fmt.Errorf("packet is not ipv4, type: %v", int((data[0]>>4)&0x0f))
	}

	// Adjust our start position based on the advertised ip header length
	ihl := int(data[0]&0x0f) << 2

	// Well formed ip header length?
	if ihl < ipv4.HeaderLen {
		return fmt.Errorf("packet had an invalid header length: %v", ihl)
	}

	// Check if this is the second or further fragment of a fragmented packet.
	flagsfrags := binary.BigEndian.Uint16(data[6:8])
	fp.Fragment = (flagsfrags & 0x1FFF) != 0

	// Firewall handles protocol checks
	fp.Protocol = data[9]

	// Accounting for a variable header length, do we have enough data for our src/dst tuples?
	minLen := ihl
	if !fp.Fragment && fp.Protocol != fwProtoICMP {
		minLen += minFwPacketLen
	}
	if len(data) < minLen {
		return fmt.Errorf("packet is less than %v bytes, ip header len: %v", minLen, ihl)
	}

	// Firewall packets are locally oriented
	if incoming { // Do we at least have an ipv4 header worth of data?r
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("packet is less than %v bytes", ipv4.HeaderLen)
		}

		// Is it an ipv4 packet?
		if int((data[0]>>4)&0x0f) != 4 {
			return fmt.Errorf("packet is not ipv4, type: %v", int((data[0]>>4)&0x0f))
		}

		// Adjust our start position based on the advertised ip header length
		ihl := int(data[0]&0x0f) << 2

		fp.RemoteIP = binary.BigEndian.Uint32(data[12:16])
		fp.LocalIP = binary.BigEndian.Uint32(data[16:20])
		if fp.Fragment || fp.Protocol == fwProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	} else {
		fp.LocalIP = binary.BigEndian.Uint32(data[12:16])
		fp.RemoteIP = binary.BigEndian.Uint32(data[16:20])
		if fp.Fragment || fp.Protocol == fwProtoICMP {
			fp.RemotePort = 0
			fp.LocalPort = 0
		} else {
			fp.LocalPort = binary.BigEndian.Uint16(data[ihl : ihl+2])
			fp.RemotePort = binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
		}
	}

	return nil
}

func (f *Interface) decrypt(hostinfo *HostInfo, mc uint64, out []byte, packet []byte, header *Header, nb []byte) ([]byte, error) {
	var err error
	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:HeaderLen], packet[HeaderLen:], mc, nb)
	if err != nil {
		return nil, err
	}

	if !hostinfo.ConnectionState.window.Update(mc) {
		hostinfo.logger().WithField("header", header).
			Debugln("dropping out of window packet")
		return nil, errors.New("out of window packet")
	}

	return out, nil
}

func (f *Interface) decryptToTun(pair *pair, hostinfo *HostInfo, messageCounter uint64, out []byte, packet []byte, gossipPacket *GossipPacket, fwPacket *FirewallPacket, nb []byte) {
	var err error

	out, err = hostinfo.ConnectionState.dKey.DecryptDanger(out, packet[:HeaderLen], packet[HeaderLen:], messageCounter, nb)
	if err != nil {
		hostinfo.logger().WithError(err).Error("Failed to decrypt packet")
		//TODO: maybe after build 64 is out? 06/14/2018 - NB
		//f.sendRecvError(hostinfo.remote, header.RemoteIndex)
		return
	}

	err = parseGossipPacket(out, gossipPacket)
	if err != nil {
		hostinfo.logger().WithError(err).WithField("packet", out).
			Error("Error while parsing gossip header")
		return
	}

	gossipPacket.withLogger(hostinfo.logger()).Debug("Parsed inbound gossip packet")

	if f.packetCache.cache(gossipPacket.ID) {
		hostinfo.withLogger(gossipPacket.withLogger(l)).
			Debug("Packet seen, dropping")
		return
	}

	out = out[gpLength:]
	err = newPacket(out, false, fwPacket)
	if err != nil {
		hostinfo.logger().
			WithError(err).WithField("packet", out).
			Warnf("Error validating inbound packet")
		return
	}

	if !hostinfo.ConnectionState.window.Update(messageCounter) {
		hostinfo.logger().WithField("fwPacket", fwPacket).
			Info("dropping out of window packet")
		return
	}

	f.pathManager.GetEstablished(fwPacket.LocalIP, fwPacket.RemoteIP, pair)
	if !pair.IsEmpty() && (pair.from != hostinfo.hostId && pair.to != hostinfo.hostId) {
		f.pathManager.deleteEstablished(fwPacket.LocalIP, fwPacket.RemoteIP)
		pair.Clear()
	}

	if fwPacket.RemoteIP == f.lightHouse.myIp {
		hostinfo.logger().Debug("packet reached the destination")

		err = f.inside.WriteRaw(out)
		if err != nil {
			l.WithError(err).Error("Failed to write to tun")
		}
		f.connectionManager.In(hostinfo.hostId)

		if pair.IsEmpty() {
			err = f.establishPath(fwPacket, hostinfo, out)
			if err != nil {
				fwPacket.withLogger(hostinfo.logger()).WithError(err).Warnf("Could not establish a path")
			}
		}
	} else if !pair.IsEmpty() {
		startFwd := time.Now()
		hIP := pair.to
		// check which way the packet is flowing
		if hIP == hostinfo.hostId {
			hIP = pair.from
		}

		h, err := f.hostMap.QueryVpnIP(hIP)
		if err != nil {
			pair.withLogger(l).WithError(err).Error("Error querying host")
			return
		}
		h.logger().Debug("Forwarding packet via established route")
		gossipPacket.RemoteIP = h.hostId
		out = GossipEncode(out, gossipPacket, true)

		_, err = f.plainSend(message, h, out, nb, packet[:0])
		if err != nil {
			h.logger().WithError(err).Error("failed to send packet to peer; falling back to gossip")
			f.gossip(hostinfo, gossipPacket, fwPacket, out, nb, out)
			return
		}
		f.messageMetrics.fwd.Update(time.Now().Sub(startFwd).Microseconds())
	} else {
		f.gossip(hostinfo, gossipPacket, fwPacket, out, nb, packet[:0])
	}
}

func (f *Interface) establishPath(fwPacket *FirewallPacket, hostinfo *HostInfo, out []byte) error {
	f.pathManager.AddPending(fwPacket.LocalIP, fwPacket.RemoteIP, hostinfo, nil)
	err := newAckPathPacket(fwPacket, out, out)
	if err != nil {
		return err
	}

	_, err = f.plainSend(ackPath,
		hostinfo,
		out, make([]byte, 12, 12), make([]byte, mtu))
	if err != nil {
		return err
	}

	_, err = f.pathManager.Establish(fwPacket.LocalIP, fwPacket.RemoteIP, hostinfo)
	return err
}

func (f *Interface) gossip(sender *HostInfo, gossipPacket *GossipPacket, fwPacket *FirewallPacket, packet []byte, nb []byte, out []byte) {
	startGossip := time.Now()
	shift := true
	for _, h := range f.hostMap.GetRemoteActiveHosts() {
		if h.hostId == fwPacket.LocalIP ||
			h.hostId == gossipPacket.RemoteIP ||
			f.lightHouse.IsLighthouseIP(h.hostId) {
			gossipPacket.withLogger(fwPacket.withLogger(h.logger())).
				Debug("Skipping remote")

			continue
		}

		gossipPacket.RemoteIP = h.hostId
		h.withLogger(gossipPacket.withLogger(fwPacket.withLogger(l))).
			Debug("Outbound gossip and firewall headers")

		packet = GossipEncode(packet, gossipPacket, shift)
		shift = false

		mc, err := f.plainSend(message, h, packet, nb, out)
		if f.lightHouse != nil && mc%5000 == 0 {
			f.lightHouse.Query(fwPacket.RemoteIP, f)
		}
		if err != nil {
			h.logger().WithError(err).Error("failed to forward a packet")
		}

		f.pathManager.AddPending(fwPacket.LocalIP, fwPacket.RemoteIP, sender, h)
		f.messageMetrics.Tx(message, 2, 1)
	}

	f.messageMetrics.gossip.Update(time.Now().Sub(startGossip).Microseconds())
}

func AnyOverlap(x, y []byte) bool {

	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))

}

func InexactOverlap(x, y []byte) bool {

	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {

		return false

	}

	return AnyOverlap(x, y)

}

func (f *Interface) sendRecvError(endpoint *udpAddr, index uint32) {
	f.messageMetrics.Tx(recvError, 0, 1)

	//TODO: this should be a signed message so we can trust that we should drop the index
	b := HeaderEncode(make([]byte, HeaderLen), Version, uint8(recvError), 0, index, 0)
	f.outside.WriteTo(b, endpoint)
	if l.Level >= logrus.DebugLevel {
		l.WithField("index", index).
			WithField("udpAddr", endpoint).
			Debug("Recv error sent")
	}
}

func (f *Interface) handleRecvError(addr *udpAddr, h *Header) {
	// This flag is to stop caring about recv_error from old versions
	// This should go away when the old version is gone from prod
	if l.Level >= logrus.DebugLevel {
		l.WithField("index", h.RemoteIndex).
			WithField("udpAddr", addr).
			Debug("Recv error received")
	}

	hostinfo, err := f.hostMap.QueryReverseIndex(h.RemoteIndex)
	if err != nil {
		l.Debugln(err, ": ", h.RemoteIndex)
		return
	}

	if !hostinfo.RecvErrorExceeded() {
		return
	}
	if hostinfo.remote != nil && hostinfo.remote.String() != addr.String() {
		l.Infoln("Someone spoofing recv_errors? ", addr, hostinfo.remote)
		return
	}

	// We delete this host from the main hostmap
	f.hostMap.DeleteHostInfo(hostinfo)
	// We also delete it from pending to allow for
	// fast reconnect. We must null the connectionstate
	// or a counter reuse may happen
	hostinfo.ConnectionState = nil
	f.handshakeManager.DeleteHostInfo(hostinfo)
}

/*
func (f *Interface) sendMeta(ci *ConnectionState, endpoint *net.UDPAddr, meta *NebulaMeta) {
	if ci.eKey != nil {
		//TODO: log error?
		return
	}

	msg, err := proto.Marshal(meta)
	if err != nil {
		l.Debugln("failed to encode header")
	}

	c := ci.messageCounter
	b := HeaderEncode(nil, Version, uint8(metadata), 0, hostinfo.remoteIndexId, c)
	ci.messageCounter++

	msg := ci.eKey.EncryptDanger(b, nil, msg, c)
	//msg := ci.eKey.EncryptDanger(b, nil, []byte(fmt.Sprintf("%d", counter)), c)
	f.outside.WriteTo(msg, endpoint)
}
*/

func RecombineCertAndValidate(h *noise.HandshakeState, rawCertBytes []byte) (*cert.NebulaCertificate, error) {
	pk := h.PeerStatic()

	if pk == nil {
		return nil, errors.New("no peer static key was present")
	}

	if rawCertBytes == nil {
		return nil, errors.New("provided payload was empty")
	}

	r := &cert.RawNebulaCertificate{}
	err := proto.Unmarshal(rawCertBytes, r)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling cert: %s", err)
	}

	// If the Details are nil, just exit to avoid crashing
	if r.Details == nil {
		return nil, fmt.Errorf("certificate did not contain any details")
	}

	r.Details.PublicKey = pk
	recombined, err := proto.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("error while recombining certificate: %s", err)
	}

	c, _ := cert.UnmarshalNebulaCertificate(recombined)
	isValid, err := c.Verify(time.Now(), trustedCAs)
	if err != nil {
		return c, fmt.Errorf("certificate validation failed: %s", err)
	} else if !isValid {
		// This case should never happen but here's to defensive programming!
		return c, errors.New("certificate validation failed but did not return an error")
	}

	return c, nil
}
