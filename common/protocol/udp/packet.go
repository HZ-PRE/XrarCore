package udp

import (
	"github.com/HZ-PRE/XrarCore/common/buf"
	"github.com/HZ-PRE/XrarCore/common/net"
)

// Packet is a UDP packet together with its source and destination address.
type Packet struct {
	Payload *buf.Buffer
	Source  net.Destination
	Target  net.Destination
}
