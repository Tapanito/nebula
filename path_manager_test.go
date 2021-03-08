package nebula

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestUniqueCombination(t *testing.T) {
	for i := uint32(0); i <= 253; i++ {
		index := i<<24 + (i+1)<<16 + (i + 2)
		ip1dec := index >> 24
		ip2dec := index >> 16 & 0xFF
		ip3dec := index & 0xFF

		assert.Equal(t, int2ip(i), int2ip(ip1dec))
		assert.Equal(t, int2ip(i+1), int2ip(ip2dec))
		assert.Equal(t, int2ip(i+2), int2ip(ip3dec))
	}
}

func TestIndex(t *testing.T) {
	ip1 := ip2int(net.IP{192, 168, 0, 30})
	ip2 := ip2int(net.IP{192, 168, 0, 40})
	idx := index(ip1, ip2)
	msb1 := idx >> 8
	msb2 := idx & 0xFF

	assert.Equal(t, uint32(30), msb1)
	assert.Equal(t, uint32(40), msb2)
}

func TestPathManager_AddPending(t *testing.T) {
	pm := NewPathManager()
	h1 := &HostInfo{
		hostId: ip2int(net.IP{192, 168, 0, 1}),
	}
	h2 := &HostInfo{
		hostId: ip2int(net.IP{192, 168, 0, 5}),
	}
	src := ip2int(net.IP{192, 168, 0, 20})
	dst := ip2int(net.IP{192, 168, 0, 30})
	pm.AddPending(src, dst, h1, h2)

	idx := index(src, dst)

	assert.Equal(t, pm.pendingTraffic[idx], int32(1))
	assert.Equal(t, len(pm.pendingPaths), 1)

	pm.AddPending(src, dst, h1, h2)

	assert.Equal(t, pm.pendingTraffic[idx], int32(2))
	assert.Equal(t, len(pm.pendingPaths), 1)
}

func TestPathManager_Establish(t *testing.T) {
	pm := NewPathManager()
	h1 := &HostInfo{
		hostId: ip2int(net.IP{192, 168, 0, 1}),
	}
	h2 := &HostInfo{
		hostId: ip2int(net.IP{192, 168, 0, 5}),
	}
	src := ip2int(net.IP{192, 168, 0, 20})
	dst := ip2int(net.IP{192, 168, 0, 30})
	_, err := pm.Establish(src, dst, h1)
	assert.Equal(t, err, errPathNotPending)

	pm.AddPending(src, dst, h1, h2)

	_, err = pm.Establish(src, dst, h1)
	assert.Nil(t, err)

	idx := index(src, dst)

	assert.Equal(t, pm.establishedPaths[idx].from, h1)
	assert.Equal(t, pm.establishedPaths[idx].to, h2)
	assert.Equal(t, pm.establishedTraffic[idx], int32(1))
}

func TestPathManager_GetEstablished(t *testing.T) {
	pm := NewPathManager()
	h1 := &HostInfo{
		hostId: ip2int(net.IP{192, 168, 0, 1}),
	}
	h2 := &HostInfo{
		hostId: ip2int(net.IP{192, 168, 0, 5}),
	}
	src := ip2int(net.IP{192, 168, 0, 20})
	dst := ip2int(net.IP{192, 168, 0, 30})
	est := pm.GetEstablished(src, dst)
	assert.Nil(t, est)
	pm.AddPending(src, dst, h1, h2)

	_, err := pm.Establish(src, dst, h1)
	assert.Nil(t, err)
	idx := index(src, dst)
	assert.Equal(t, pm.establishedTraffic[idx], int32(1))

	est = pm.GetEstablished(src, dst)
	assert.NotNil(t, est)
	assert.Equal(t, pm.establishedTraffic[idx], int32(2))
}
