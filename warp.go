package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	warpAPI = "https://api.cloudflareclient.com/v0a2158"
	warpPub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)

type warpReg struct {
	ID      string `json:"id"`
	Token   string `json:"token"`
	Account struct {
		Type    string `json:"account_type"`
		License string `json:"license"`
	} `json:"account"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func warpDo(method, path, token string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, warpAPI+path, rd)
	req.Header.Set("CF-Client-Version", "a-6.30-3596")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("连不上 WARP 的接口：%v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		switch resp.StatusCode {
		case 429:
			return errors.New("请求太频繁，Cloudflare 限流了，过几分钟再试")
		case 403:
			return errors.New("Cloudflare 拒绝了这台机器的请求（403），有的机房 IP 注册不了 WARP")
		}
		var e struct {
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		json.Unmarshal(b, &e)
		if len(e.Errors) > 0 {
			return fmt.Errorf("HTTP %d：%s", resp.StatusCode, e.Errors[0].Message)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.Trim(s, "[]")
}

// 纯 IPv6 机器：没有公网 IPv4，只有 IPv6。WARP 入口就走 IPv6 出口；
// 有 IPv4 的机器（包括双栈）走原来的 IPv4 入口；两个都没测到时也走原来的。
func (st *State) ipv6Only() bool { return st.IP4 == "" && st.IP6 != "" }

// 注册一个免费 WARP 账号，返回 WireGuard endpoint
// v6 为 true 时初始入口就用 IPv6（纯 IPv6 机器上 IPv4 入口不可达）
func warpRegister(v6 bool) (*Outbound, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	e := base64.StdEncoding
	body := map[string]any{"key": e.EncodeToString(k.PublicKey().Bytes()), "install_id": "", "fcm_token": "",
		"tos": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "model": "PC", "serial_number": "", "locale": "en_US"}
	var r warpReg
	if err := warpDo("POST", "/reg", "", body, &r); err != nil {
		return nil, err
	}
	a := r.Config.Interface.Addresses
	if r.ID == "" || r.Token == "" || a.V4 == "" || len(r.Config.Peers) == 0 {
		return nil, errors.New("WARP 接口返回的内容不完整")
	}
	peer := r.Config.Peers[0]
	pub := first(peer.PublicKey, warpPub)
	acct := &WarpAcct{ID: r.ID, Token: r.Token, Type: r.Account.Type, License: r.Account.License,
		Peer4: hostOnly(peer.Endpoint.V4), Peer6: hostOnly(peer.Endpoint.V6)}
	addrs := []string{a.V4 + "/32"}
	if a.V6 != "" {
		addrs = append(addrs, a.V6+"/128")
	}
	epHost := "162.159.192.1"
	if v6 {
		epHost = "2606:4700:d0::a29f:c001"
	}
	ep := wgEndpoint(e.EncodeToString(k.Bytes()), pub, "", epHost, 2408, addrs, wgReserved(r.Config.ClientID), 1280)
	o := &Outbound{Name: "warp", Endpoint: true, Config: ep, Warp: acct}
	warpLabel(o)
	return o, nil
}

func warpLabel(o *Outbound) {
	o.Kind = map[string]string{"limited": "WARP+", "unlimited": "WARP Unlimited", "team": "WARP Teams"}[o.Warp.Type]
	if o.Kind == "" {
		o.Kind = "WARP 免费版"
	}
}

// 入口：先试注册时分到的 IP 换端口，再试别的段。机房封了某个 UDP 端口时能换着用
func warpCandidates(o *Outbound, v4 bool) []string {
	var hosts []string
	if v4 {
		hosts = []string{first(o.Warp.Peer4, "162.159.192.1"), "162.159.193.10", "188.114.97.1"}
	} else {
		hosts = []string{first(o.Warp.Peer6, "2606:4700:d0::a29f:c001"), "2606:4700:d0::a29f:c001"}
	}
	if hosts[1] == hosts[0] {
		hosts = append(hosts[:1], hosts[2:]...)
	}
	var r []string
	for _, p := range []string{"2408", "500", "4500"} {
		r = append(r, net.JoinHostPort(hosts[0], p))
	}
	for _, h := range hosts[1:] {
		r = append(r, net.JoinHostPort(h, "2408"))
	}
	return r
}

func warpPeer(o *Outbound) string {
	ps, _ := o.Config["peers"].([]any)
	if len(ps) == 0 {
		return ""
	}
	p, _ := ps[0].(map[string]any)
	h, _ := p["address"].(string)
	return net.JoinHostPort(h, fmt.Sprint(toInt(p["port"])))
}

func setWarpPeer(o *Outbound, hp string) {
	h, p, _ := net.SplitHostPort(hp)
	ps, _ := o.Config["peers"].([]any)
	if len(ps) == 0 {
		return
	}
	peer, _ := ps[0].(map[string]any)
	peer["address"] = h
	peer["port"] = toInt(p)
	o.Server = hp
}

// 绑定 WARP+ 授权码；成功后账号类型会变成 limited
func warpBind(o *Outbound, license string) error {
	if err := warpDo("PUT", "/reg/"+o.Warp.ID+"/account", o.Warp.Token, map[string]any{"license": license}, nil); err != nil {
		return err
	}
	var acc struct {
		Type    string `json:"account_type"`
		License string `json:"license"`
	}
	if err := warpDo("GET", "/reg/"+o.Warp.ID+"/account", o.Warp.Token, nil, &acc); err != nil {
		return err
	}
	o.Warp.Type, o.Warp.License = acc.Type, first(acc.License, license)
	warpLabel(o)
	return nil
}

// 删出站时顺手把设备注销掉，失败了也无所谓
func warpUnregister(o *Outbound) {
	if o.Warp == nil || o.Warp.ID == "" {
		return
	}
	warpDo("DELETE", "/reg/"+o.Warp.ID, o.Warp.Token, nil, nil)
}
