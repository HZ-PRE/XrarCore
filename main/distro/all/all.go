package all

import (
	// The following are necessary as they register handlers in their init functions.

	// Mandatory features. Can't remove unless there are replacements.
	_ "github.com/HZ-PRE/XrarCore/app/dispatcher"
	_ "github.com/HZ-PRE/XrarCore/app/proxyman/inbound"
	_ "github.com/HZ-PRE/XrarCore/app/proxyman/outbound"

	// Default commander and all its services. This is an optional feature.
	_ "github.com/HZ-PRE/XrarCore/app/commander"
	_ "github.com/HZ-PRE/XrarCore/app/log/command"
	_ "github.com/HZ-PRE/XrarCore/app/proxyman/command"
	_ "github.com/HZ-PRE/XrarCore/app/stats/command"

	// Developer preview services
	_ "github.com/HZ-PRE/XrarCore/app/observatory/command"

	// Other optional features.
	_ "github.com/HZ-PRE/XrarCore/app/dns"
	_ "github.com/HZ-PRE/XrarCore/app/dns/fakedns"
	_ "github.com/HZ-PRE/XrarCore/app/log"
	_ "github.com/HZ-PRE/XrarCore/app/metrics"
	_ "github.com/HZ-PRE/XrarCore/app/policy"
	_ "github.com/HZ-PRE/XrarCore/app/reverse"
	_ "github.com/HZ-PRE/XrarCore/app/router"
	_ "github.com/HZ-PRE/XrarCore/app/stats"

	// Fix dependency cycle caused by core import in internet package
	_ "github.com/HZ-PRE/XrarCore/transport/internet/tagged/taggedimpl"

	// Developer preview features
	_ "github.com/HZ-PRE/XrarCore/app/observatory"

	// Inbound and outbound proxies.
	_ "github.com/HZ-PRE/XrarCore/proxy/blackhole"
	_ "github.com/HZ-PRE/XrarCore/proxy/dns"
	_ "github.com/HZ-PRE/XrarCore/proxy/dokodemo"
	_ "github.com/HZ-PRE/XrarCore/proxy/freedom"
	_ "github.com/HZ-PRE/XrarCore/proxy/http"
	_ "github.com/HZ-PRE/XrarCore/proxy/loopback"
	_ "github.com/HZ-PRE/XrarCore/proxy/shadowsocks"
	_ "github.com/HZ-PRE/XrarCore/proxy/socks"
	_ "github.com/HZ-PRE/XrarCore/proxy/trojan"
	_ "github.com/HZ-PRE/XrarCore/proxy/vless/inbound"
	_ "github.com/HZ-PRE/XrarCore/proxy/vless/outbound"
	_ "github.com/HZ-PRE/XrarCore/proxy/vmess/inbound"
	_ "github.com/HZ-PRE/XrarCore/proxy/vmess/outbound"
	_ "github.com/HZ-PRE/XrarCore/proxy/wireguard"

	// Transports
	_ "github.com/HZ-PRE/XrarCore/transport/internet/grpc"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/httpupgrade"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/kcp"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/reality"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/splithttp"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/tcp"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/tls"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/udp"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/websocket"

	// Transport headers
	_ "github.com/HZ-PRE/XrarCore/transport/internet/headers/http"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/headers/noop"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/headers/srtp"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/headers/tls"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/headers/utp"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/headers/wechat"
	_ "github.com/HZ-PRE/XrarCore/transport/internet/headers/wireguard"

	// JSON & TOML & YAML
	_ "github.com/HZ-PRE/XrarCore/main/json"
	_ "github.com/HZ-PRE/XrarCore/main/toml"
	_ "github.com/HZ-PRE/XrarCore/main/yaml"

	// Load config from file or http(s)
	_ "github.com/HZ-PRE/XrarCore/main/confloader/external"

	// Commands
	_ "github.com/HZ-PRE/XrarCore/main/commands/all"
)
