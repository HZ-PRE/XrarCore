package all

import (
	"github.com/HZ-PRE/XrarCore/main/commands/all/api"
	"github.com/HZ-PRE/XrarCore/main/commands/all/convert"
	"github.com/HZ-PRE/XrarCore/main/commands/all/tls"
	"github.com/HZ-PRE/XrarCore/main/commands/base"
)

func init() {
	base.RootCommand.Commands = append(
		base.RootCommand.Commands,
		api.CmdAPI,
		convert.CmdConvert,
		tls.CmdTLS,
		cmdUUID,
		cmdX25519,
		cmdWG,
	)
}
