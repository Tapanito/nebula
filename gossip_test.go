package nebula

import (
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestMarshal(t *testing.T) {
	local := []byte{10, 0, 2, 4}
	remote := []byte{10, 0, 2, 5}
	id := rand.Uint32()
	//fid := rand.Uint32()
	gp := &GossipPacket{
		//FlowID:   fid,
		ID:       id,
		LocalIP:  ip2int(local),
		RemoteIP: ip2int(remote),
	}
	data, err := gp.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, id, binary.BigEndian.Uint32(data[:4]))
	assert.Equal(t, remote, data[4:8])
	assert.Equal(t, local, data[8:12])
	//assert.Equal(t, fid, binary.BigEndian.Uint32(data[12:16]))
}
