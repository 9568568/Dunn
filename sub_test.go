package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestParseAddr(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		addr string
		port int
	}{
		{"104.16.1.1:2053#家里最快", true, "104.16.1.1", 2053},
		{"[2606:4700::1111]:8443", true, "2606:4700::1111", 8443},
		{"2606:4700::1111", true, "2606:4700::1111", 443},
		{"cf.0sm.com", true, "cf.0sm.com", 443},
		{"cf.0sm.com:2096 # 备注", true, "cf.0sm.com", 2096},
		{"bad:port:x", false, "", 0},
		{"1.2.3.4:99999", false, "", 0},
		{"# 注释", false, "", 0},
		{"中文.com", false, "", 0},
	}
	for _, c := range cases {
		a, ok := parseAddr(c.in)
		if ok != c.ok || (ok && (a.Addr != c.addr || a.Port != c.port)) {
			t.Errorf("%q => %+v %v", c.in, a, ok)
		}
	}
}

func TestIsCFIP(t *testing.T) {
	for ip, want := range map[string]bool{"104.16.1.1": true, "172.66.201.155": true, "47.76.127.217": false, "2606:4700::1111": true, "8.8.8.8": false} {
		if isCFIP(ip) != want {
			t.Errorf("%s", ip)
		}
	}
}

func TestRandPadding(t *testing.T) {
	for i := 0; i < 200; i++ {
		p := randPadding()
		var stop int
		fmt.Sscanf(p[0], "stop=%d", &stop)
		if stop < 6 || stop > 10 || len(p) != stop+1 {
			t.Fatalf("行数不对: %v", p)
		}
		for j, l := range p[1:] {
			k, v, _ := strings.Cut(l, "=")
			if k != strconv.Itoa(j) {
				t.Fatalf("序号不对: %v", p)
			}
			for _, seg := range strings.Split(v, ",") {
				if seg == "c" {
					continue
				}
				var a, b int
				if n, _ := fmt.Sscanf(seg, "%d-%d", &a, &b); n != 2 || a < 1 || a > b || b > 1500 {
					t.Fatalf("区间不对 %q: %v", seg, p)
				}
			}
		}
		if p[1] == "0=30-30" {
			t.Fatal("撞上了官方默认")
		}
	}
}

func TestBuildLogin(t *testing.T) {
	seen := map[string]bool{}
	for s := uint64(1); s <= 50; s++ {
		p := buildLogin(s)
		h := string(p.html)
		if strings.Contains(h, "__") {
			i := strings.Index(h, "__")
			t.Fatalf("seed %d 有没替换的占位符: %q", s, h[i:i+20])
		}
		if !strings.Contains(h, p.endpoint) {
			t.Fatalf("seed %d 页面里没有接口路径", s)
		}
		seen[h] = true
	}
	if len(seen) < 50 {
		t.Fatalf("50 个种子只生成了 %d 种页面", len(seen))
	}
	if string(buildLogin(7).html) != string(buildLogin(7).html) {
		t.Fatal("同一个种子结果不稳定")
	}
}
