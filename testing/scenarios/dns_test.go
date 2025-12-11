package scenarios

import (
	"fmt"
	"testing"
	"time"

	"github.com/HZ-PRE/XrarCore/app/dns"
	"github.com/HZ-PRE/XrarCore/app/proxyman"
	"github.com/HZ-PRE/XrarCore/app/router"
	"github.com/HZ-PRE/XrarCore/common"
	"github.com/HZ-PRE/XrarCore/common/net"
	"github.com/HZ-PRE/XrarCore/common/serial"
	"github.com/HZ-PRE/XrarCore/core"
	"github.com/HZ-PRE/XrarCore/proxy/blackhole"
	"github.com/HZ-PRE/XrarCore/proxy/freedom"
	"github.com/HZ-PRE/XrarCore/proxy/socks"
	"github.com/HZ-PRE/XrarCore/testing/servers/tcp"
	"github.com/HZ-PRE/XrarCore/transport/internet"
	xproxy "golang.org/x/net/proxy"
)

func TestResolveIP(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	serverPort := tcp.PickPort()
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dns.Config{
				StaticHosts: []*dns.Config_HostMapping{
					{
						Type:   dns.DomainMatchingType_Full,
						Domain: "google.com",
						Ip:     [][]byte{dest.Address.IP()},
					},
				},
			}),
			serial.ToTypedMessage(&router.Config{
				DomainStrategy: router.Config_IpIfNonMatch,
				Rule: []*router.RoutingRule{
					{
						Geoip: []*router.GeoIP{
							{
								Cidr: []*router.CIDR{
									{
										Ip:     []byte{127, 0, 0, 0},
										Prefix: 8,
									},
								},
							},
						},
						TargetTag: &router.RoutingRule_Tag{
							Tag: "direct",
						},
					},
				},
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&socks.ServerConfig{
					AuthType: socks.AuthType_NO_AUTH,
					Accounts: map[string]string{
						"Test Account": "Test Password",
					},
					Address:    net.NewIPOrDomain(net.LocalHostIP),
					UdpEnabled: false,
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
			},
			{
				Tag: "direct",
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					DomainStrategy: internet.DomainStrategy_USE_IP,
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	{
		noAuthDialer, err := xproxy.SOCKS5("tcp", net.TCPDestination(net.LocalHostIP, serverPort).NetAddr(), nil, xproxy.Direct)
		common.Must(err)
		conn, err := noAuthDialer.Dial("tcp", fmt.Sprintf("google.com:%d", dest.Port))
		common.Must(err)
		defer conn.Close()

		if err := testTCPConn2(conn, 1024, time.Second*5)(); err != nil {
			t.Error(err)
		}
	}
}
