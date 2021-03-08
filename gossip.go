package nebula

import (
	"encoding/binary"
	"fmt"
)

const gpLength = 12

type GossipPacket struct {
	ID       uint32
	LocalIP  uint32
	RemoteIP uint32
	//FlowID   uint32
}

func (gp *GossipPacket) Marshal() ([]byte, error) {
	buf := make([]byte, gpLength)

	binary.BigEndian.PutUint32(buf, gp.ID)
	binary.BigEndian.PutUint32(buf[4:8], gp.RemoteIP)
	binary.BigEndian.PutUint32(buf[8:], gp.LocalIP)
	//binary.BigEndian.PutUint32(buf[12:16], gp.FlowID)

	return buf, nil
}

func parseIncomingGossipPacket(data []byte, gp *GossipPacket) error {
	if len(data) < gpLength {
		return fmt.Errorf("gossip packet is less than %d bytes", gpLength)
	}
	gp.ID = binary.BigEndian.Uint32(data[:4])
	gp.LocalIP = binary.BigEndian.Uint32(data[4:8])
	gp.RemoteIP = binary.BigEndian.Uint32(data[8:])
	//gp.FlowID = binary.BigEndian.Uint32(data[12:16])

	return nil
}
