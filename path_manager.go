package nebula

import (
	"errors"
	"github.com/sirupsen/logrus"
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
	if ip1 > ip2 {
		ip1, ip2 = ip2, ip1
	}

	return (ip1)<<8 + (ip2)
}

func splitIndex(idx uint32) (ip1, ip2 uint32) {
	return idx >> 8, idx & 0xFF
}

type pair struct {
	from uint32
	to   uint32
}

func (p *pair) withLogger(l logrus.FieldLogger) logrus.FieldLogger {
	return l.WithField("pair.from", IntIp(p.from)).
		WithField("pair.to", IntIp(p.to))
}

func (p *pair) IsEmpty() bool {
	return p.from == 0 && p.to == 0
}

func (p *pair) Clear() {
	p.from = 0
	p.to = 0
}

/*
PathManager works under the assumption that all hosts
run in the same sub-network, it uses the last byte of the IP address
to form a unique index of the path
*/
type pathManager struct {
	pendingLock sync.RWMutex
	// pendingPaths a map key is SRC-DST most significant byte combined
	pendingPaths map[uint32]map[uint32]pair
	// for monitoring traffic over pending conn
	pendingTraffic map[uint32]int32
	pendingTimer   *SystemTimerWheel

	establishedLock    sync.RWMutex
	establishedPaths   map[uint32]pair
	establishedTraffic map[uint32]int32
	establishedTimer   *SystemTimerWheel

	metrics *CacheMetrics
}

func NewPathManager(metrics *CacheMetrics) *pathManager {
	return &pathManager{
		pendingPaths:       map[uint32]map[uint32]pair{},
		pendingTraffic:     map[uint32]int32{},
		pendingTimer:       NewSystemTimerWheel(time.Second, 60*time.Second),
		establishedPaths:   map[uint32]pair{},
		establishedTraffic: map[uint32]int32{},
		establishedTimer:   NewSystemTimerWheel(2*time.Second, 120*time.Second),
		metrics:            metrics,
	}
}

func (p *pathManager) Run() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		now := time.Now()
		p.handlePathDeletionTick(now)
		p.handlePendingDeletionTick(now)
	}
}

func (p *pathManager) AddPending(src, dst uint32, sender, recv *HostInfo) {
	idx := index(src, dst)

	var senderIp, recvIp uint32
	if sender != nil {
		senderIp = sender.hostId
	}

	if recv != nil {
		recvIp = recv.hostId
	}
	l.
		WithField("ID", idx).
		WithField("src", int2ip(src)).
		WithField("dst", int2ip(dst)).
		WithField("sender", int2ip(senderIp)).
		WithField("recv", int2ip(recvIp)).
		Debug("Adding new pending path")

	p.pendingLock.Lock()

	pairs, ok := p.pendingPaths[idx]
	if !ok {
		pairs = map[uint32]pair{}
	}

	idx2 := index(senderIp, recvIp)
	_, ok2 := pairs[idx2]
	if !ok2 {
		pair := pair{from: senderIp, to: recvIp}
		pairs[idx2] = pair
		(&pair).withLogger(l).Debug("added new pair")
	}
	p.pendingTimer.Add(idx, pendingCacheDuration)
	p.pendingPaths[idx] = pairs
	p.pendingTraffic[idx]++

	p.pendingLock.Unlock()
}

func (p *pathManager) GetEstablished(src, dst uint32, pair *pair) {
	idx := index(src, dst)
	p.establishedLock.Lock()
	pp, ok := p.establishedPaths[idx]
	if ok {
		p.establishedTraffic[idx]++
		pair.from = pp.from
		pair.to = pp.to
	} else {
		pair.from = 0
		pair.to = 0
	}

	p.establishedLock.Unlock()
}

func (p *pathManager) Establish(src, dst uint32, sender *HostInfo) (*pair, error) {
	idx := index(src, dst)
	l.
		WithField("ID", idx).
		WithField("src", int2ip(src)).
		WithField("dst", int2ip(dst)).
		WithField("sender", int2ip(sender.hostId)).
		Debug("Establishing a new path")

	p.pendingLock.RLock()
	pairs, ok := p.pendingPaths[idx]
	if !ok {
		p.pendingLock.RUnlock()
		return nil, errPathNotPending
	}

	var pair *pair
	for _, v := range pairs {
		if sender.hostId == v.from || sender.hostId == v.to {
			pair = &v
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
	flushed := 0
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
			flushed++
			continue
		}
		p.pendingTraffic[idx] = 0
		p.pendingTimer.Add(idx, pendingCacheDuration)
	}

	p.pendingLock.Unlock()
	p.metrics.Set("pending_paths.active", int64(len(p.pendingPaths)))
	p.metrics.Set("pending_paths.flushed", int64(flushed))
}

func (p *pathManager) handlePathDeletionTick(now time.Time) {
	p.establishedLock.Lock()
	p.establishedTimer.advance(now)
	flushed := 0
	for {
		ep := p.establishedTimer.Purge()
		if ep == nil {
			break
		}

		idx := ep.(uint32)
		counter, ok := p.establishedTraffic[idx]
		if !ok {
			delete(p.establishedPaths, idx)
			// TODO: log?
			continue
		}

		if counter <= 0 {
			delete(p.establishedTraffic, idx)
			delete(p.establishedPaths, idx)
			flushed++
			continue
		}

		p.establishedTraffic[idx] = 0
		p.establishedTimer.Add(idx, establishedCacheDuration)
	}
	p.establishedLock.Unlock()
	p.metrics.Set("established_paths.active", int64(len(p.establishedPaths)))
	p.metrics.Set("established_paths.flushed", int64(flushed))
}

func (p *pathManager) deleteEstablished(src, dst uint32) {
	idx := index(src, dst)
	p.establishedLock.Lock()
	delete(p.establishedTraffic, idx)
	delete(p.establishedPaths, idx)
	p.establishedLock.Unlock()
}
