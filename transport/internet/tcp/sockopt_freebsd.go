//go:build freebsd
// +build freebsd

package tcp

import (
	"github.com/HZ-PRE/XrarCore/common/errors"
	"github.com/HZ-PRE/XrarCore/common/net"
	"github.com/HZ-PRE/XrarCore/transport/internet"
	"github.com/HZ-PRE/XrarCore/transport/internet/stat"
)

// GetOriginalDestination from tcp conn
func GetOriginalDestination(conn stat.Connection) (net.Destination, error) {
	la := conn.LocalAddr()
	ra := conn.RemoteAddr()
	ip, port, err := internet.OriginalDst(la, ra)
	if err != nil {
		return net.Destination{}, errors.New("failed to get destination").Base(err)
	}
	dest := net.TCPDestination(net.IPAddress(ip), net.Port(port))
	if !dest.IsValid() {
		return net.Destination{}, errors.New("failed to parse destination.")
	}
	return dest, nil
}
