package nebula

import (
	"errors"
	"net"
	"time"
)

var errInvalidAddress = errors.New("invalid IP address")
var errInvalidCIDRRange = errors.New("IP address outside of configured CIDR range")

func EstablishConnection(ifce *Interface, addrs []string) error {
	for {
		for _, addr := range addrs {
			parsedIp := net.ParseIP(addr)
			if parsedIp == nil {
				l.WithField("addr", addr).Error(errInvalidAddress)
				return errInvalidAddress
			}

			if !ifce.hostMap.vpnCIDR.Contains(parsedIp) {
				l.WithField("addr", addr).WithField("cidr", ifce.hostMap.vpnCIDR.String()).Error(errInvalidCIDRRange)
				return errInvalidCIDRRange
			}

			hostinfo := ifce.getOrHandshake(ip2int(parsedIp))
			if !hostinfo.HandshakeComplete {
				l.WithField("addr", addr).Info("connection with peer not ready")
			}
		}

		time.Sleep(5 * time.Second)
	}
}
