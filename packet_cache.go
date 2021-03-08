package nebula

import (
	"sync"
	"time"
)

type packetCache struct {
	sync.RWMutex
	messages map[uint32]struct{}
	timer    *SystemTimerWheel
}

func NewPacketCache() *packetCache {
	return &packetCache{
		RWMutex:  sync.RWMutex{},
		messages: map[uint32]struct{}{},
		timer:    NewSystemTimerWheel(time.Second*5, time.Second*500),
	}
}

func (p *packetCache) Run() {
	go func() {
		clockSource := time.Tick(5 * time.Second)
		for now := range clockSource {
			p.purge(now)
		}
	}()
}

func (p *packetCache) cache(id uint32, timeout time.Duration) {
	p.timer.Add(id, timeout)
	p.Lock()
	p.messages[id] = struct{}{}
	p.Unlock()
}

func (p *packetCache) contains(id uint32) bool {
	p.RLock()
	_, ok := p.messages[id]
	p.RUnlock()

	return ok
}

func (p *packetCache) purge(tick time.Time) {
	p.timer.advance(tick)
	c := 0
	p.Lock()
	// TODO: would this cause a skip in the cache?
	for ep := p.timer.Purge(); ep != nil; ep = p.timer.Purge() {
		v := ep.(uint32)
		delete(p.messages, v)
		c++
	}
	p.Unlock()
	//if c > 0 {
	//	l.WithField("count", c).Info("flushed packet cache")
	//}
}
