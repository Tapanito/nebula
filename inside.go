package nebula

import (
	"github.com/flynn/noise"
	"github.com/sirupsen/logrus"
	"sync/atomic"
	"time"
)

func (f *Interface) consumeInsidePacket(packet []byte, gossipPacket *GossipPacket, fwPacket *FirewallPacket, nb, out []byte) {
	err := newPacket(packet, false, fwPacket)
	if err != nil {
		l.WithField("packet", packet).Debugf("Error while validating outbound packet: %s", err)
		return
	}

	// Ignore local broadcast packets
	if f.dropLocalBroadcast && fwPacket.RemoteIP == f.localBroadcast {
		return
	}

	// Ignore packets from self to self
	if fwPacket.RemoteIP == f.lightHouse.myIp {
		return
	}

	// Ignore broadcast packets
	if f.dropMulticast && isMulticast(fwPacket.RemoteIP) {
		return
	}

	// TODO: rand number generation will require optimising
	gossipPacket.ID = f.rand.Uint32()
	gossipPacket.LocalIP = fwPacket.LocalIP

	if pair := f.pathManager.GetEstablished(fwPacket.LocalIP, fwPacket.RemoteIP); pair != nil {
		// This is the source of the packet, pair from will be nil
		gossipPacket.RemoteIP = pair.to
		gp, err := gossipPacket.Marshal()
		if err != nil {
			l.WithError(err).
				Error("failed to marshal gossip packet")
			return
		}
		gp = append(gp, packet...)

		h := f.hostMap.getByVpnIP(pair.to)
		if h == nil {
			l.WithField("pair.to", int2ip(pair.to)).
				Error("failed to find peer with IP")
			return
		}
		mc, err := f.plainSend(message, 0, h, gp, nb, out)

		if err != nil {
			f.gossip(nil, gossipPacket, fwPacket, packet, nb, out)
		}
		if f.lightHouse != nil && mc%5000 == 0 {
			f.lightHouse.Query(fwPacket.RemoteIP, f)
		}
	} else {
		f.gossip(nil, gossipPacket, fwPacket, packet, nb, out)
	}

	f.packetCache.cache(gossipPacket.ID, 5*time.Second)

	//dropReason := f.firewall.Drop(packet, *fwPacket, false, hostinfo, trustedCAs)
	//if dropReason == nil {
	//	mc := f.sendNoMetrics(message, 0, ci, hostinfo, hostinfo.remote, packet, nb, out)
	//	if f.lightHouse != nil && mc%5000 == 0 {
	//		f.lightHouse.Query(fwPacket.RemoteIP, f)
	//	}
	//
	//} else if l.Level >= logrus.DebugLevel {
	//	hostinfo.logger().
	//		WithField("fwPacket", fwPacket).
	//		WithField("reason", dropReason).
	//		Debugln("dropping outbound packet")
	//}
}

// getOrHandshake returns nil if the vpnIp is not routable
func (f *Interface) getOrHandshake(vpnIp uint32) *HostInfo {
	if f.hostMap.vpnCIDR.Contains(int2ip(vpnIp)) == false {
		vpnIp = f.hostMap.queryUnsafeRoute(vpnIp)
		if vpnIp == 0 {
			return nil
		}
	}

	hostinfo, err := f.hostMap.PromoteBestQueryVpnIP(vpnIp, f)

	//if err != nil || hostinfo.ConnectionState == nil {
	if err != nil {
		hostinfo, err = f.handshakeManager.pendingHostMap.QueryVpnIP(vpnIp)
		if err != nil {
			hostinfo = f.handshakeManager.AddVpnIP(vpnIp)
		}
	}

	ci := hostinfo.ConnectionState

	if ci != nil && ci.eKey != nil && ci.ready {
		return hostinfo
	}

	if ci == nil {
		// if we don't have a connection state, then send a handshake initiation
		ci = f.newConnectionState(true, noise.HandshakeIX, []byte{}, 0)
		// FIXME: Maybe make XX selectable, but probably not since psk makes it nearly pointless for us.
		//ci = f.newConnectionState(true, noise.HandshakeXX, []byte{}, 0)
		hostinfo.ConnectionState = ci
	} else if ci.eKey == nil {
		// if we don't have any state at all, create it
	}

	// If we have already created the handshake packet, we don't want to call the function at all.
	if !hostinfo.HandshakeReady {
		ixHandshakeStage0(f, vpnIp, hostinfo)
		// FIXME: Maybe make XX selectable, but probably not since psk makes it nearly pointless for us.
		//xx_handshakeStage0(f, ip, hostinfo)

		// If this is a static host, we don't need to wait for the HostQueryReply
		// We can trigger the handshake right now
		if _, ok := f.lightHouse.staticList[vpnIp]; ok {
			select {
			case f.handshakeManager.trigger <- vpnIp:
			default:
			}
		}
	}

	return hostinfo
}

// getPeer fetch hostInfo of an existing peer,
// if a connection with the peer is not established nil is returned
func (f *Interface) getPeer(vpnIp uint32) *HostInfo {
	if f.hostMap.vpnCIDR.Contains(int2ip(vpnIp)) == false {
		vpnIp = f.hostMap.queryUnsafeRoute(vpnIp)
		if vpnIp == 0 {
			return nil
		}
	}

	hostinfo, err := f.hostMap.PromoteBestQueryVpnIP(vpnIp, f)
	if err != nil {
		return nil
	}

	ci := hostinfo.ConnectionState

	if ci != nil && ci.eKey != nil && ci.ready {
		return hostinfo
	}

	return nil
}

func (f *Interface) sendMessageNow(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	fp := &FirewallPacket{}
	err := newPacket(p, false, fp)
	if err != nil {
		l.Warnf("error while parsing outgoing packet for firewall check; %v", err)
		return
	}

	// check if packet is in outbound fw rules
	dropReason := f.firewall.Drop(p, *fp, false, hostInfo, trustedCAs)
	if dropReason != nil {
		if l.Level >= logrus.DebugLevel {
			l.WithField("fwPacket", fp).
				WithField("reason", dropReason).
				Debugln("dropping cached packet")
		}
		return
	}

	f.sendNoMetrics(message, st, hostInfo.ConnectionState, hostInfo, hostInfo.remote, p, nb, out)
	if f.lightHouse != nil && *hostInfo.ConnectionState.messageCounter%5000 == 0 {
		f.lightHouse.Query(fp.RemoteIP, f)
	}
}

// SendMessageToVpnIp handles real ip:port lookup and sends to the current best known address for vpnIp
func (f *Interface) SendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	hostInfo := f.getOrHandshake(vpnIp)
	if hostInfo == nil {
		if l.Level >= logrus.DebugLevel {
			l.WithField("vpnIp", IntIp(vpnIp)).
				Debugln("dropping SendMessageToVpnIp, vpnIp not in our CIDR or in unsafe routes")
		}
		return
	}

	if !hostInfo.ConnectionState.ready {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		hostInfo.ConnectionState.queueLock.Lock()
		if !hostInfo.ConnectionState.ready {
			hostInfo.cachePacket(t, st, p, f.sendMessageToVpnIp)
			hostInfo.ConnectionState.queueLock.Unlock()
			return
		}
		hostInfo.ConnectionState.queueLock.Unlock()
	}

	f.sendMessageToVpnIp(t, st, hostInfo, p, nb, out)
	return
}

func (f *Interface) sendMessageToVpnIp(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, out []byte) {
	f.send(t, st, hostInfo.ConnectionState, hostInfo, hostInfo.remote, p, nb, out)
}

// SendMessageToAll handles real ip:port lookup and sends to all known addresses for vpnIp
func (f *Interface) SendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, vpnIp uint32, p, nb, out []byte) {
	hostInfo := f.getOrHandshake(vpnIp)
	if hostInfo == nil {
		if l.Level >= logrus.DebugLevel {
			l.WithField("vpnIp", IntIp(vpnIp)).
				Debugln("dropping SendMessageToAll, vpnIp not in our CIDR or in unsafe routes")
		}
		return
	}

	if hostInfo.ConnectionState.ready == false {
		// Because we might be sending stored packets, lock here to stop new things going to
		// the packet queue.
		hostInfo.ConnectionState.queueLock.Lock()
		if !hostInfo.ConnectionState.ready {
			hostInfo.cachePacket(t, st, p, f.sendMessageToAll)
			hostInfo.ConnectionState.queueLock.Unlock()
			return
		}
		hostInfo.ConnectionState.queueLock.Unlock()
	}

	f.sendMessageToAll(t, st, hostInfo, p, nb, out)
	return
}

func (f *Interface) sendMessageToAll(t NebulaMessageType, st NebulaMessageSubType, hostInfo *HostInfo, p, nb, b []byte) {
	for _, r := range hostInfo.RemoteUDPAddrs() {
		f.send(t, st, hostInfo.ConnectionState, hostInfo, r, p, nb, b)
	}
}

func (f *Interface) send(t NebulaMessageType, st NebulaMessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote *udpAddr, p, nb, out []byte) {
	f.messageMetrics.Tx(t, st, 1)
	f.sendNoMetrics(t, st, ci, hostinfo, remote, p, nb, out)
}

func (f *Interface) sendNoMetrics(t NebulaMessageType, st NebulaMessageSubType, ci *ConnectionState, hostinfo *HostInfo, remote *udpAddr, p, nb, out []byte) uint64 {
	if ci.eKey == nil {
		//TODO: log warning
		return 0
	}

	var err error
	//TODO: enable if we do more than 1 tun queue
	//ci.writeLock.Lock()
	c := atomic.AddUint64(ci.messageCounter, 1)

	//l.WithField("trace", string(debug.Stack())).Error("out Header ", &Header{Version, t, st, 0, hostinfo.remoteIndexId, c}, p)
	out = HeaderEncode(out, Version, uint8(t), uint8(st), hostinfo.remoteIndexId, c)
	f.connectionManager.Out(hostinfo.hostId)

	out, err = ci.eKey.EncryptDanger(out, out, p, c, nb)
	//TODO: see above note on lock
	//ci.writeLock.Unlock()
	if err != nil {
		hostinfo.logger().WithError(err).
			WithField("udpAddr", remote).WithField("counter", c).
			WithField("attemptedCounter", ci.messageCounter).
			Error("Failed to encrypt outgoing packet")
		return c
	}

	err = f.outside.WriteTo(out, remote)
	if err != nil {
		hostinfo.logger().WithError(err).
			WithField("udpAddr", remote).Error("Failed to write outgoing packet")
	}
	return c
}

func (f *Interface) plainSend(t NebulaMessageType, st NebulaMessageSubType, hostinfo *HostInfo, p, nb, out []byte) (uint64, error) {
	ci := hostinfo.ConnectionState
	remote := hostinfo.remote
	if ci.eKey == nil {
		//TODO: log warning
		return 0, nil
	}

	var err error
	//TODO: enable if we do more than 1 tun queue
	//ci.writeLock.Lock()
	c := atomic.AddUint64(ci.messageCounter, 1)

	//l.WithField("trace", string(debug.Stack())).Error("out Header ", &Header{Version, t, st, 0, hostinfo.remoteIndexId, c}, p)
	out = HeaderEncode(out, Version, uint8(t), uint8(st), hostinfo.remoteIndexId, c)
	f.connectionManager.Out(hostinfo.hostId)

	out, err = ci.eKey.EncryptDanger(out, out, p, c, nb)
	//TODO: see above note on lock
	//ci.writeLock.Unlock()
	if err != nil {
		hostinfo.logger().WithError(err).
			WithField("udpAddr", remote).WithField("counter", c).
			WithField("attemptedCounter", ci.messageCounter).
			Error("Failed to encrypt outgoing packet")
		return c, err
	}

	err = f.outside.WriteTo(out, remote)
	if err != nil {
		hostinfo.logger().WithError(err).
			WithField("udpAddr", remote).Error("Failed to write outgoing packet")
	}
	return c, err
}

func isMulticast(ip uint32) bool {
	// Class D multicast
	if (((ip >> 24) & 0xff) & 0xf0) == 0xe0 {
		return true
	}

	return false
}
