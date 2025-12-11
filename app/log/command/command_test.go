package command_test

import (
	"context"
	"testing"

	"github.com/HZ-PRE/XrarCore/app/dispatcher"
	"github.com/HZ-PRE/XrarCore/app/log"
	. "github.com/HZ-PRE/XrarCore/app/log/command"
	"github.com/HZ-PRE/XrarCore/app/proxyman"
	_ "github.com/HZ-PRE/XrarCore/app/proxyman/inbound"
	_ "github.com/HZ-PRE/XrarCore/app/proxyman/outbound"
	"github.com/HZ-PRE/XrarCore/common"
	"github.com/HZ-PRE/XrarCore/common/serial"
	"github.com/HZ-PRE/XrarCore/core"
)

func TestLoggerRestart(t *testing.T) {
	v, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
	})
	common.Must(err)
	common.Must(v.Start())

	server := &LoggerServer{
		V: v,
	}
	common.Must2(server.RestartLogger(context.Background(), &RestartLoggerRequest{}))
}
