package udp

import (
	"github.com/HZ-PRE/XrarCore/common"
	"github.com/HZ-PRE/XrarCore/transport/internet"
)

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
