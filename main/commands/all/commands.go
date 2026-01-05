package all

import (
	"github.com/HZ-PRE/XrarCore/main/commands/all/api"
	"github.com/HZ-PRE/XrarCore/main/commands/all/tls"
	"github.com/HZ-PRE/XrarCore/main/commands/base"
)

// go:generate go run github.com/HZ-PRE/XrarCore/common/errors/errorgen

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		// cmdConvert,
		tls.CmdTLS,
		cmdUUID,
		cmdX25519,
		cmdWG,
	)
}
