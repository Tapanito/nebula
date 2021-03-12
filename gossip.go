package nebula

import (
	"encoding/binary"
	"fmt"
	"github.com/sirupsen/logrus"
)

const gpLength = 12

type GossipPacket struct {
	ID       uint32
	LocalIP  uint32
	RemoteIP uint32
}

func (gp GossipPacket) withLogger(logger logrus.FieldLogger) logrus.FieldLogger {
	return logger.
		WithField("ID", gp.ID).
		WithField("gossipPacket.LocalIP", IntIp(gp.LocalIP)).
		WithField("gossipPacket.RemoteIP", IntIp(gp.RemoteIP))
}

func GossipEncode(out []byte, gp *GossipPacket, shift bool) []byte {
	if shift {
		out = out[0 : len(out)+gpLength]
		copy(out[gpLength:], out[:len(out)-gpLength])
	}
	binary.BigEndian.PutUint32(out, gp.ID)
	binary.BigEndian.PutUint32(out[4:8], gp.RemoteIP)
	binary.BigEndian.PutUint32(out[8:], gp.LocalIP)

	return out
}

func parseGossipPacket(data []byte, gp *GossipPacket) error {
	if len(data) < gpLength {
		return fmt.Errorf("gossip packet is less than %d bytes", gpLength)
	}
	gp.ID = binary.BigEndian.Uint32(data[:4])
	gp.LocalIP = binary.BigEndian.Uint32(data[4:8])
	gp.RemoteIP = binary.BigEndian.Uint32(data[8:])

	return nil
}
