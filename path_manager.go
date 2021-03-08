package nebula

import (
	"errors"
	"sync"
	"time"
)

const mask = 0x0F

var (
	errPathNotPending   = errors.New("attempted to establish a path over a non-pending path")
	errInvalidAckSource = errors.New("ack was sent by a non-pending peer")

	pendingCacheDuration     = 10 * time.Second
	establishedCacheDuration = 5 * time.Minute
)

func index(ip1, ip2 uint32) uint32 {
	return (ip1&0xFF)<<8 + (ip2 & 0xFF)
}

type pair struct {
	from uint32
	to   uint32
}

/*
PathManager works under the assumption that all hosts
run in the same sub-network, it uses the last byte of the IP address
to form a unique index of the path
*/
type pathManager struct {
	pendingLock sync.RWMutex
	// pendingPaths a map key is SRC-DST most significant byte combined
	pendingPaths map[uint32][]pair
	// for monitoring traffic over pending conn
	pendingTraffic map[uint32]int32
	pendingTimer   *SystemTimerWheel

	establishedLock    sync.RWMutex
	establishedPaths   map[uint32]pair
	establishedTraffic map[uint32]int32
	establishedTimer   *SystemTimerWheel
}

func NewPathManager() *pathManager {
	return &pathManager{
		//pendingLock:        sync.RWMutex{},
		pendingPaths:   map[uint32][]pair{},
		pendingTraffic: map[uint32]int32{},
		pendingTimer:   NewSystemTimerWheel(time.Second, 60*time.Second),
		//establishedLock:    sync.RWMutex{},
		establishedPaths:   map[uint32]pair{},
		establishedTraffic: map[uint32]int32{},
		establishedTimer:   NewSystemTimerWheel(10*time.Second, 5*time.Minute),
	}
}

func (p *pathManager) Run() {
	return
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		now := time.Now()
		p.handlePathDeletionTick(now)
		p.handlePendingDeletionTick(now)
	}
}

func (p *pathManager) AddPending(src, dst uint32, sender, recv uint32) {
	l.
		WithField("src", int2ip(src)).
		WithField("dst", int2ip(dst)).
		WithField("sender", int2ip(sender)).
		WithField("recv", int2ip(recv)).
		Info("Adding new pending path")

	idx := index(src, dst)

	p.pendingLock.RLock()
	pairs, ok := p.pendingPaths[idx]
	if !ok {
		pairs = []pair{}
	}

	found := false
	for _, p := range pairs {
		if p.from == sender || p.to == sender ||
			p.from == recv || p.to == recv {
			found = true
			break
		}
	}
	p.pendingLock.RUnlock()

	p.pendingLock.Lock()
	if !found {
		pairs = append(pairs, pair{from: sender, to: recv})
		p.pendingTimer.Add(idx, pendingCacheDuration)
		p.pendingPaths[idx] = pairs
	}

	p.pendingTraffic[idx]++

	p.pendingLock.Unlock()
}

func (p *pathManager) GetEstablished(src, dst uint32) *pair {
	idx := index(src, dst)

	p.
		establishedLock.
		Lock()
	pair, ok := p.establishedPaths[idx]
	if ok {
		p.establishedTraffic[idx]++
		p.establishedLock.Unlock()
		return &pair
	}
	p.establishedLock.Unlock()

	return nil
}

func (p *pathManager) Establish(src, dst uint32, sender uint32) (*pair, error) {
	idx := index(src, dst)

	p.pendingLock.RLock()
	pairs, ok := p.pendingPaths[idx]
	if !ok {
		p.pendingLock.RUnlock()
		return nil, errPathNotPending
	}

	var pair *pair
	for _, p := range pairs {
		if p.from == sender || p.to == sender {
			pair = &p
			break
		}
	}
	p.pendingLock.RUnlock()
	if pair == nil {
		return nil, errInvalidAckSource
	}

	p.establishedLock.Lock()
	p.establishedPaths[idx] = *pair
	p.establishedTraffic[idx]++
	p.establishedTimer.Add(idx, establishedCacheDuration)
	p.establishedLock.Unlock()

	return pair, nil
}

func (p *pathManager) handlePendingDeletionTick(now time.Time) {
	p.pendingLock.Lock()
	p.pendingTimer.advance(now)
	count := 0
	refresh := 0
	for {
		ep := p.pendingTimer.Purge()
		if ep == nil {
			break
		}

		idx := ep.(uint32)
		counter, ok := p.pendingTraffic[idx]
		// a state when an index is present in
		// the timer but was never added to traffic or paths
		// just ignore it
		// TODO: maybe log?
		if !ok {
			continue
		}

		// no traffic was seen since the last
		if counter <= 0 {
			delete(p.pendingPaths, idx)
			delete(p.pendingTraffic, idx)
			count++
			continue
		}
		p.pendingTraffic[idx] = 0
		refresh++
		p.pendingTimer.Add(idx, pendingCacheDuration)
	}

	p.pendingLock.Unlock()
	if refresh > 0 || count > 0 {
		l.WithField("refreshed", refresh).
			WithField("flushed", count).
			Info("cleared pending cache")
	}
}

func (p *pathManager) handlePathDeletionTick(now time.Time) {
	p.establishedLock.Lock()
	p.establishedTimer.advance(now)
	for {
		ep := p.establishedTimer.Purge()
		if ep == nil {
			break
		}

		idx := ep.(uint32)
		counter, ok := p.establishedTraffic[idx]
		if !ok {
			// TODO: log?
			continue
		}

		if counter <= 0 {
			delete(p.establishedTraffic, idx)
			delete(p.establishedPaths, idx)
			continue
		}

		p.establishedTraffic[idx] = 0
		p.establishedTimer.Add(idx, establishedCacheDuration)
	}
	p.establishedLock.Unlock()
}
