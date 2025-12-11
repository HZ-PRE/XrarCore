package conf_test

import (
	"testing"

	"github.com/HZ-PRE/XrarCore/common/net"
	"github.com/HZ-PRE/XrarCore/common/protocol"
	. "github.com/HZ-PRE/XrarCore/infra/conf"
	"github.com/HZ-PRE/XrarCore/proxy/freedom"
	"github.com/HZ-PRE/XrarCore/transport/internet"
)

func TestFreedomConfig(t *testing.T) {
	creator := func() Buildable {
		return new(FreedomConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"domainStrategy": "AsIs",
				"redirect": "127.0.0.1:3366",
				"userLevel": 1
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				DomainStrategy: internet.DomainStrategy_AS_IS,
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: &net.IPOrDomain{
							Address: &net.IPOrDomain_Ip{
								Ip: []byte{127, 0, 0, 1},
							},
						},
						Port: 3366,
					},
				},
				UserLevel: 1,
			},
		},
	})
}
