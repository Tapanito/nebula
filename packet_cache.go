package nebula

import (
	"sync"
	"time"
)

var packetTTL = time.Second
var cacheFlushTick = 5 * time.Second

type packetCache struct {
	sync.RWMutex
	messages map[uint32]int64
	timer    *SystemTimerWheel
	metrics  *CacheMetrics
	queue    chan uint32
}

func NewPacketCache(metrics *CacheMetrics) *packetCache {
	return &packetCache{
		metrics:  metrics,
		RWMutex:  sync.RWMutex{},
		messages: map[uint32]int64{},
		timer:    NewSystemTimerWheel(time.Second*5, time.Second*500),
		queue:    make(chan uint32, 512),
	}
}

func (p *packetCache) Run() {
	go p.addTimer()

	for now := range time.Tick(cacheFlushTick) {
		p.purge(now)
	}

}

func (p *packetCache) cache(id uint32) bool {
	p.Lock()
	p.messages[id]++
	p.Unlock()

	if p.messages[id] < 2 {
		p.queue <- id
		return false
	}

	return true
}

func (p *packetCache) contains(id uint32) bool {
	p.RLock()
	_, ok := p.messages[id]
	p.RUnlock()

	return ok
}

func (p *packetCache) addTimer() {
	for {
		id := <-p.queue
		p.timer.Add(id, packetTTL)

	}
}

func (p *packetCache) purge(tick time.Time) {
	p.Lock()
	p.timer.advance(tick)
	c := 0
	dp := int64(0)
	p.metrics.Set("packets.active", int64(len(p.messages)))

	// TODO: would this cause a skip in the cache?
	for ep := p.timer.Purge(); ep != nil; ep = p.timer.Purge() {
		v := ep.(uint32)

		dp += p.messages[v] - 1
		delete(p.messages, v)

		c++
	}
	p.Unlock()

	p.metrics.Set("packets.flushed", int64(c))
	p.metrics.Set("packets.duplicate", dp)
}
