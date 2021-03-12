package nebula

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func BenchmarkPacketCache_Cache(b *testing.B) {
	cache := NewPacketCache(NewCacheMetrics())
	go cache.addTimer()

	for i := 0; i < b.N; i++ {
		cache.cache(uint32(i))
	}
}

func TestPacketCache_cache(t *testing.T) {
	cache := NewPacketCache(NewCacheMetrics())

	assert.False(t, cache.cache(1))
	assert.True(t, cache.cache(1))
}