package outbound

import (
	"github.com/HZ-PRE/XrarCore/common/net"
	"github.com/HZ-PRE/XrarCore/common/protocol"
)

// As a stub command consumer.
func (h *Handler) handleCommand(dest net.Destination, cmd protocol.ResponseCommand) {
	switch cmd.(type) {
	default:
	}
}
