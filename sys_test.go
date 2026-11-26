package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 真实场景：机器上跑着 WARP，IPv4 trace 返回隧道的出口 IP，
// IPv6 trace 返回机器自己的地址。IPv4 那条必须丢掉，IPv6 那条要留着。
const (
	traceV4Warp   = "fl=1\nip=104.28.215.68\nts=1\nvisit_scheme=https\nwarp=on\nloc=HK\n"
	traceV6Direct = "fl=1\nip=2001:db8::1\nts=1\nvisit_scheme=https\nwarp=off\nloc=HK\n"
)

// traceIP 完整走一遍 HTTP：WARP 机器的 trace 正文必须被认成隧道出口，
// 正常机器的 trace 正文必须原样返回。这是 wawo 那台机器的真实场景。
func TestTraceIP(t *testing.T) {
	cases := []struct {
		body     string
		ip       string
		tunneled bool
	}{
		{traceV4Warp, "104.28.215.68", true},
		{traceV6Direct, "2001:db8::1", false},
		{"ip=150.230.42.75\nwarp=off\n", "150.230.42.75", false},
		{"fl=1\n", "", false},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(c.body))
		}))
		ip, tun := traceIP("tcp4", srv.URL)
		srv.Close()
		if ip != c.ip || tun != c.tunneled {
			t.Errorf("traceIP(%q) = %q, %v; want %q, %v", c.body, ip, tun, c.ip, c.tunneled)
		}
	}
}

func TestParseTrace(t *testing.T) {
	cases := []struct {
		body     string
		ip, warp string
	}{
		{traceV4Warp, "104.28.215.68", "on"},
		{traceV6Direct, "2001:db8::1", "off"},
		{"warp=plus\nip=172.67.1.2\n", "172.67.1.2", "plus"},
		{"ip=150.230.42.75\n", "150.230.42.75", ""},
		{"fl=1\nloc=HK\n", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		ip, warp := parseTrace(c.body)
		if ip != c.ip || warp != c.warp {
			t.Errorf("parseTrace(%q) = %q, %q; want %q, %q", c.body, ip, warp, c.ip, c.warp)
		}
	}
}

func TestTunnelExit(t *testing.T) {
	cases := []struct {
		ip, warp string
		want     bool
	}{
		// WARP 出口：warp=on，IP 也落在 CF 网段
		{"104.28.215.68", "on", true},
		{"172.67.1.2", "plus", true},
		// warp 没开，但 IP 本身落在 Cloudflare 公布的网段里，同样不能当服务器 IP
		{"104.16.1.1", "off", true},
		{"2606:4700:110::1", "off", true},
		// 正常公网 IP
		{"150.230.42.75", "off", false},
		{"141.11.140.94", "off", false},
		{"2001:db8::1", "off", false},
		// 没拿到 IP 时不算隧道出口，交给上层按无网络处理
		{"", "off", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := tunnelExit(c.ip, c.warp); got != c.want {
			t.Errorf("tunnelExit(%q, %q) = %v; want %v", c.ip, c.warp, got, c.want)
		}
	}
}

// 纯 IPv6 时解析和链接走的本来就是这条路：dnsSet 用 AAAA，
// srvAddr 返回带括号的 IPv6。隧道出口被丢掉后，IP4 为空，
// 必须落到这条路，不能退回 IPv4。
func TestSrvAddrIPv6Only(t *testing.T) {
	if got := (&State{IP6: "2001:db8::1"}).srvAddr(); got != "[2001:db8::1]" {
		t.Errorf("srvAddr IPv6-only = %q", got)
	}
	if got := (&State{IP4: "1.2.3.4", IP6: "2001:db8::1"}).srvAddr(); got != "1.2.3.4" {
		t.Errorf("srvAddr dual-stack = %q", got)
	}
}

func TestLinkRealityIPv6Only(t *testing.T) {
	st := &State{
		IP6: "2001:db8::1",
		TLS: &TLSHost{Host: "node.example.org"},
		Reality: &Reality{
			UUID:      "8f5b06a8-c62b-4576-b403-3565711432c9",
			PublicKey: "amY9oPsWzUQXrE36zpB7GicCCSAi-l5s19uP7pze9UM",
			ShortID:   "2c380db7",
			PubPort:   443,
		},
	}
	link := linkReality(st, "vps-Reality")
	if !strings.HasPrefix(link, "vless://8f5b06a8-c62b-4576-b403-3565711432c9@[2001:db8::1]:443?") {
		t.Errorf("Reality link = %q", link)
	}
	if !strings.Contains(link, "sni=node.example.org") || strings.Contains(link, "104.28.") {
		t.Errorf("Reality link SNI/address wrong: %q", link)
	}
}
