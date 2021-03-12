package nebula

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestUniqueCombination(t *testing.T) {
	int1 := ip2int(net.IP{192, 168, 0, byte(10)})
	int2 := ip2int(net.IP{192, 168, 0, byte(20)})
	idx := index(int1,int2)
	ip1, ip2 := splitIndex(idx)

	assert.Equal(t, int2ip(int1).String(), int2ip(ip1).String())
	assert.Equal(t,int2ip(int2).String(), int2ip(ip2).String())
}


func TestPathManager_AddPending(t *testing.T) {
	pm := NewPathManager(NewCacheMetrics())
	h1 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 1})}
	h2 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 5})}
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
	pm := NewPathManager(NewCacheMetrics())
	h1 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 1})}
	h2 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 5})}

	src := ip2int(net.IP{192, 168, 0, 20})
	src2 := ip2int(net.IP{192, 168, 0, 10})
	dst := ip2int(net.IP{192, 168, 0, 30})

	_, err := pm.Establish(src, dst, h1)
	assert.Equal(t, err, errPathNotPending)

	pm.AddPending(src, dst, h1, h2)
	pm.AddPending(src2, dst, h1, h2)

	_, err = pm.Establish(src, dst, h1)
	assert.Nil(t, err)

	_, err = pm.Establish(src2, dst, h1)
	assert.Nil(t, err)

	idx := index(src, dst)

	assert.Equal(t, pm.establishedPaths[idx].from, h1)
	assert.Equal(t, pm.establishedPaths[idx].to, h2)
	assert.Equal(t, pm.establishedTraffic[idx], int32(1))
}

func BenchmarkPathManager_Establish(b *testing.B) {
	pm := NewPathManager(NewCacheMetrics())
	h1 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 1})}
	h2 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 5})}

	src := ip2int(net.IP{192, 168, 0, 20})
	dst := ip2int(net.IP{192, 168, 0, 30})
	pm.AddPending(src, dst, h1, h2)
	 pm.Establish(src, dst, h1)

	for i := 0; i < b.N; i++ {
		pair :=	pm.GetEstablished(src, dst)
		if pair == nil {
			b.Fatal(pair)
		}
	}
}

func TestPathManager_GetEstablished(t *testing.T) {
	pm := NewPathManager(NewCacheMetrics())

	h1 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 1})}
	h2 := &HostInfo{hostId:ip2int(net.IP{192, 168, 0, 5})}

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

	est = pm.GetEstablished(dst, src)
	assert.NotNil(t, est)
	assert.Equal(t, pm.establishedTraffic[idx], int32(3))

}
