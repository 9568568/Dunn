package main

import (
	"net"
	"strings"
	"testing"
)

// WARP 加 IPv4/IPv6 判断：有 IPv4 的机器（纯 IPv4、双栈）走原来的 IPv4 入口，
// 只有 IPv6 的机器走 IPv6 出口；两个都没测到时也走原来的。
func TestIPv6Only(t *testing.T) {
	cases := []struct {
		ip4, ip6 string
		want     bool
	}{
		{"", "2400:c620:26:4e::a", true},         // 纯 IPv6：WaWo 那台
		{"1.2.3.4", "2400:c620:26:4e::a", false}, // 双栈：走原来的 IPv4
		{"1.2.3.4", "", false},                   // 纯 IPv4：走原来的
		{"", "", false},                          // 都没测到：走原来的
	}
	for _, c := range cases {
		st := &State{IP4: c.ip4, IP6: c.ip6}
		if got := st.ipv6Only(); got != c.want {
			t.Errorf("ipv6Only(IP4=%q, IP6=%q) = %v, want %v", c.ip4, c.ip6, got, c.want)
		}
	}
}

// 候选入口按 v4/v6 分流：IPv4 段里不能出现 IPv6 地址，IPv6 段里不能出现 IPv4 地址。
func TestWarpCandidatesFamily(t *testing.T) {
	o := &Outbound{Warp: &WarpAcct{Peer4: "162.159.192.1", Peer6: "2606:4700:d0::a29f:c005"}}
	for _, hp := range warpCandidates(o, true) {
		h, _, err := net.SplitHostPort(hp)
		if err != nil {
			t.Fatalf("warpCandidates(v4) 返回了坏地址 %q: %v", hp, err)
		}
		if strings.Contains(h, ":") {
			t.Errorf("IPv4 候选里混进了 IPv6 地址：%s", hp)
		}
	}
	for _, hp := range warpCandidates(o, false) {
		h, _, err := net.SplitHostPort(hp)
		if err != nil {
			t.Fatalf("warpCandidates(v6) 返回了坏地址 %q: %v", hp, err)
		}
		if !strings.Contains(h, ":") {
			t.Errorf("IPv6 候选里混进了 IPv4 地址：%s", hp)
		}
	}
}
