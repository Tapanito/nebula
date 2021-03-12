package nebula

import (
	"testing"
)

func BenchmarkGossipEncode(b *testing.B) {
	packet := &GossipPacket{ID: 1, LocalIP: ip2int([]byte{4, 4, 4, 4}), RemoteIP: ip2int([]byte{5, 5, 5, 5})}
	buf := make([]byte, 3, gpLength+3)
	buf[0] = 1
	buf[1] = 2
	buf[2] = 3

	for i := 0; i < b.N; i++ {
		GossipEncode(buf, packet, true)
	}
}

func BenchmarkParseGossipPacket(b *testing.B) {
	packet := &GossipPacket{ID: 1, LocalIP: ip2int([]byte{4, 4, 4, 4}), RemoteIP: ip2int([]byte{5, 5, 5, 5})}
	buf := make([]byte, gpLength)
	GossipEncode(buf, packet, false)
	newPacket := &GossipPacket{}

	for i := 0; i < b.N; i++ {
		err := parseGossipPacket(buf, newPacket)
		if err != nil {
			b.Fatal(err)
		}
	}


}
