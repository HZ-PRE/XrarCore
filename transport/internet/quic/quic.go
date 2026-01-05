package quic

import (
	"github.com/HZ-PRE/XrarCore/common"
	"github.com/HZ-PRE/XrarCore/transport/internet"
)

//go:generate go run github.com/HZ-PRE/XrarCore/common/errors/errorgen

// Here is some modification needs to be done before update quic vendor.
// * use bytespool in buffer_pool.go
// * set MaxReceivePacketSize to 1452 - 32 (16 bytes auth, 16 bytes head)
//
//

const (
	protocolName   = "quic"
	internalDomain = "quic.internal.example.com"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
