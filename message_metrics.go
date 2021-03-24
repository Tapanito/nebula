package nebula

import (
	"fmt"

	"github.com/rcrowley/go-metrics"
)

type MessageMetrics struct {
	rx [][]metrics.Counter
	tx [][]metrics.Counter

	// decryption metric
	dec metrics.Histogram
	// encryption metric
	enc metrics.Histogram

	proc   metrics.Histogram
	parse  metrics.Histogram
	fwd    metrics.Histogram
	gossip metrics.Histogram
	write  metrics.Histogram

	rxUnknown metrics.Counter
	txUnknown metrics.Counter
}

func (m *MessageMetrics) Rx(t NebulaMessageType, s NebulaMessageSubType, i int64) {
	if m != nil {
		if t >= 0 && int(t) < len(m.rx) && s >= 0 && int(s) < len(m.rx[t]) {
			m.rx[t][s].Inc(i)
		} else if m.rxUnknown != nil {
			m.rxUnknown.Inc(i)
		}
	}
}
func (m *MessageMetrics) Tx(t NebulaMessageType, s NebulaMessageSubType, i int64) {
	if m != nil {
		if t >= 0 && int(t) < len(m.tx) && s >= 0 && int(s) < len(m.tx[t]) {
			m.tx[t][s].Inc(i)
		} else if m.txUnknown != nil {
			m.txUnknown.Inc(i)
		}
	}
}

func newMessageMetrics() *MessageMetrics {
	// this is so fucking stupid
	gen := func(t string) [][]metrics.Counter {
		return [][]metrics.Counter{
			{
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.handshake_ixpsk0", t), nil),
			},
			{
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s", t), nil),
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.duplicate", t), nil),
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.forwarded", t), nil),
			},
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.recv_error", t), nil)},
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.lighthouse", t), nil)},
			{
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.test_request", t), nil),
				metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.test_response", t), nil),
			},
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.close_tunnel", t), nil)},
			nil,
			nil,
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.ack_path", t), nil)},
		}
	}
	return &MessageMetrics{
		rx: gen("rx"),
		tx: gen("tx"),

		enc: metrics.GetOrRegisterHistogram("messages.encrypt",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		dec: metrics.GetOrRegisterHistogram("messages.decrypt",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		proc: metrics.GetOrRegisterHistogram("messages.process",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		parse: metrics.GetOrRegisterHistogram("messages.parse",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		fwd: metrics.GetOrRegisterHistogram("messages.fwd",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		gossip: metrics.GetOrRegisterHistogram("messages.gossip",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		write: metrics.GetOrRegisterHistogram("messages.write",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		rxUnknown: metrics.GetOrRegisterCounter("messages.rx.other", nil),
		txUnknown: metrics.GetOrRegisterCounter("messages.tx.other", nil),
	}
}

// Historically we only recorded recv_error, so this is backwards compat
func newMessageMetricsOnlyRecvError() *MessageMetrics {
	gen := func(t string) [][]metrics.Counter {
		return [][]metrics.Counter{
			nil,
			nil,
			{metrics.GetOrRegisterCounter(fmt.Sprintf("messages.%s.recv_error", t), nil)},
		}
	}
	return &MessageMetrics{
		rx: gen("rx"),
		tx: gen("tx"),
	}
}

func newLighthouseMetrics() *MessageMetrics {
	gen := func(t string) [][]metrics.Counter {
		h := make([][]metrics.Counter, len(NebulaMeta_MessageType_name))
		used := []NebulaMeta_MessageType{
			NebulaMeta_HostQuery,
			NebulaMeta_HostQueryReply,
			NebulaMeta_HostUpdateNotification,
			NebulaMeta_HostPunchNotification,
		}
		for _, i := range used {
			h[i] = []metrics.Counter{metrics.GetOrRegisterCounter(fmt.Sprintf("lighthouse.%s.%s", t, i.String()), nil)}
		}
		return h
	}
	return &MessageMetrics{
		rx: gen("rx"),
		tx: gen("tx"),
		enc: metrics.GetOrRegisterHistogram("messages.encrypt",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		dec: metrics.GetOrRegisterHistogram("messages.decrypt",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		proc: metrics.GetOrRegisterHistogram("messages.process",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		parse: metrics.GetOrRegisterHistogram("messages.parse",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		fwd: metrics.GetOrRegisterHistogram("messages.fwd",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		gossip: metrics.GetOrRegisterHistogram("messages.gossip",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),
		write: metrics.GetOrRegisterHistogram("messages.write",
			nil,
			metrics.NewExpDecaySample(1024, 0.015)),

		rxUnknown: metrics.GetOrRegisterCounter("lighthouse.rx.other", nil),
		txUnknown: metrics.GetOrRegisterCounter("lighthouse.tx.other", nil),
	}
}
