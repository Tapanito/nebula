package nebula

import "github.com/rcrowley/go-metrics"

type CacheMetrics struct {
	gauges map[string]metrics.Gauge
}

func NewCacheMetrics() *CacheMetrics {
	return &CacheMetrics{gauges: map[string]metrics.Gauge{
		"pending_paths.active":      metrics.GetOrRegisterGauge("cache.paths_pending.active", nil),
		"pending_paths.flushed":     metrics.GetOrRegisterGauge("cache.paths_pending.flushed", nil),
		"established_paths.active":  metrics.GetOrRegisterGauge("cache.paths_established.active", nil),
		"established_paths.flushed": metrics.GetOrRegisterGauge("cache.paths_established.flushed", nil),
		"packets.active":            metrics.GetOrRegisterGauge("cache.packets.active", nil),
		"packets.flushed":           metrics.GetOrRegisterGauge("cache.packets.flushed", nil),
		"packets.duplicate":           metrics.GetOrRegisterGauge("cache.packets.duplicate", nil),
	}}
}

func (m *CacheMetrics) Set(key string, value int64) {
	g, ok := m.gauges[key]
	if ok {
		g.Update(value)
	}
}
