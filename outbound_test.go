package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func one(t *testing.T, s string) *Outbound {
	t.Helper()
	os, errs := parseOutbounds(s)
	if len(errs) > 0 || len(os) != 1 {
		t.Fatalf("%s → %v %v", s, os, errs)
	}
	return os[0]
}

func js(v any) string { b, _ := json.Marshal(v); return string(b) }

func has(t *testing.T, o *Outbound, wants ...string) {
	t.Helper()
	s := js(o.Config)
	for _, w := range wants {
		if !strings.Contains(s, w) {
			t.Errorf("缺 %s\n%s", w, s)
		}
	}
}

func TestSocksHTTP(t *testing.T) {
	o := one(t, "socks5://u%40x:p%3Aw@1.2.3.4:1080#家宽")
	has(t, o, `"type":"socks"`, `"version":"5"`, `"username":"u@x"`, `"password":"p:w"`, `"server_port":1080`)
	if o.Name != "家宽" || o.Kind != "SOCKS5" {
		t.Error(o.Name, o.Kind)
	}
	has(t, one(t, "socks://"+base64.StdEncoding.EncodeToString([]byte("user:pass"))+"@h.example.com:7890"), `"username":"user"`, `"password":"pass"`)
	has(t, one(t, "socks5h://[2001:db8::1]:1080"), `"server":"2001:db8::1"`)
	has(t, one(t, "http://user:pass@proxy.example.com:8080"), `"type":"http"`, `"username":"user"`)
	o = one(t, "https://user:pass@proxy.example.com")
	has(t, o, `"server_port":443`, `"tls":{"enabled":true,"server_name":"proxy.example.com"}`)
}

func TestBare(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4:1080":                    `"server":"1.2.3.4","server_port":1080,"type":"auto"`,
		"1.2.3.4:1080:user:pass":          `"password":"pass","server":"1.2.3.4","server_port":1080,"type":"auto","username":"user"`,
		"gate.example.com:7000:u-1:p:x":   `"password":"p:x"`,
		"user:pass@1.2.3.4:1080":          `"username":"user"`,
		"user:pass:gate.example.com:9999": `"server":"gate.example.com","server_port":9999`,
		"1.2.3.4 1080 user pass":          `"username":"user"`,
		"[2001:db8::2]:1080:u:p":          `"server":"2001:db8::2"`,
	} {
		has(t, one(t, in), want)
	}
	for _, bad := range []string{"1.2.3.4", "abc:def", "1.2.3.4:99999"} {
		if _, errs := parseOutbounds(bad); len(errs) == 0 {
			t.Errorf("%q 应该报错", bad)
		}
	}
}

func TestVless(t *testing.T) {
	o := one(t, "vless://uuid-1@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=PUBKEY&sid=ab12&type=tcp#hk-Reality")
	has(t, o, `"flow":"xtls-rprx-vision"`, `"reality":{"enabled":true,"public_key":"PUBKEY","short_id":"ab12"}`,
		`"server_name":"www.example.com"`, `"utls":{"enabled":true,"fingerprint":"chrome"}`)
	if o.Kind != "VLESS Reality" || o.Name != "hk-Reality" {
		t.Error(o.Kind, o.Name)
	}
	o = one(t, "vless://uuid@cf.example.com:443?encryption=none&security=tls&sni=ws.example.com&type=ws&host=ws.example.com&path=%2Fabc%3Fed%3D2048#ws")
	has(t, o, `"transport":{"early_data_header_name":"Sec-WebSocket-Protocol","headers":{"Host":"ws.example.com"},"max_early_data":2048,"path":"/abc","type":"ws"}`)
	has(t, one(t, "vless://u@h.example.com:443?security=tls&type=grpc&serviceName=svc"), `"service_name":"svc"`, `"server_name":"h.example.com"`)
	has(t, one(t, "vless://u@1.2.3.4:80?type=httpupgrade&host=a.com&path=/up"), `"type":"httpupgrade"`)
	for _, bad := range []string{"vless://u@h.com:443?type=xhttp", "vless://u@h.com:443?encryption=mlkem768x25519plus.native.0rtt.abc", "vless://u@h.com:443?security=reality"} {
		if _, errs := parseOutbounds(bad); len(errs) == 0 {
			t.Errorf("%s 应该报错", bad)
		}
	}
}

func TestVmess(t *testing.T) {
	j := `{"v":"2","ps":"美国","add":"v.example.com","port":"443","id":"uuid","aid":"0","scy":"auto","net":"ws","type":"none","host":"v.example.com","path":"/ws","tls":"tls","sni":""}`
	o := one(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(j)))
	has(t, o, `"type":"vmess"`, `"server_port":443`, `"transport":{"headers":{"Host":"v.example.com"},"path":"/ws","type":"ws"}`, `"server_name":"v.example.com"`)
	if o.Name != "美国" {
		t.Error(o.Name)
	}
	j = `{"add":"1.2.3.4","port":8080,"id":"uuid","aid":0,"net":"tcp"}`
	has(t, one(t, "vmess://"+base64.RawURLEncoding.EncodeToString([]byte(j))), `"server_port":8080`, `"alter_id":0`)
	// 小火箭写法
	sr := "vmess://" + base64.StdEncoding.EncodeToString([]byte("auto:uuid@r.example.com:443")) + "?remarks=sr&obfsParam=r.example.com&path=/p&obfs=websocket&tls=1&peer=r.example.com"
	o = one(t, sr)
	has(t, o, `"path":"/p"`, `"server_name":"r.example.com"`)
	has(t, one(t, "vmess://uuid@u.example.com:443?type=grpc&serviceName=g&security=tls"), `"service_name":"g"`)
}

func TestTrojanSS(t *testing.T) {
	has(t, one(t, "trojan://pa%23ss@t.example.com:443?sni=t.example.com&allowInsecure=1#tj"), `"password":"pa#ss"`, `"insecure":true`)
	// SIP002 base64url、2022 系列明文、老格式整段 base64、插件
	has(t, one(t, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw"))+"@1.2.3.4:8388#ss1"), `"method":"aes-256-gcm"`, `"password":"pw"`)
	has(t, one(t, "ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@1.2.3.4:8388"), `"password":"YWJjZGVmZ2hpamtsbW5vcA=="`)
	has(t, one(t, "ss://"+base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p@ss@5.6.7.8:443"))+"#old"), `"server":"5.6.7.8"`, `"password":"p@ss"`)
	has(t, one(t, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))+"@1.2.3.4:80/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#p"),
		`"plugin":"obfs-local"`, `"plugin_opts":"obfs=http;obfs-host=bing.com"`)
	if _, errs := parseOutbounds("ss://" + base64.StdEncoding.EncodeToString([]byte("rc4:pw")) + "@1.2.3.4:80"); len(errs) == 0 {
		t.Error("不支持的加密方式应该报错")
	}
}

func TestHy2TuicAnyTLS(t *testing.T) {
	// dun 自己生成的链接
	o := one(t, "hysteria2://pw@n.example.com:58851/?mport=25943-31275&obfs=gecko&obfs-password=ob&sni=n.example.com#vps-Hy2")
	has(t, o, `"server_ports":["25943:31275"]`, `"obfs":{"password":"ob","type":"gecko"}`, `"server_name":"n.example.com"`)
	if _, ok := o.Config["server_port"]; ok {
		t.Error("有端口跳跃就不该再写 server_port")
	}
	has(t, one(t, "hy2://a:b@1.2.3.4:443,20000-30000?insecure=1&obfs=salamander&obfs-password=x"), `"password":"a:b"`, `"server_ports":["443:443","20000:30000"]`, `"insecure":true`)
	has(t, one(t, "hysteria2://pw@1.2.3.4:443?pinSHA256=AA:BB"), `"insecure":true`, `"server_port":443`)
	has(t, one(t, "tuic://uuid:pw@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1"),
		`"congestion_control":"bbr"`, `"uuid":"uuid"`, `"password":"pw"`, `"insecure":true`)
	has(t, one(t, "anytls://pw@a.example.com:9443/?sni=a.example.com#vps-AnyTLS"), `"type":"anytls"`, `"server_name":"a.example.com"`)
}

func TestWireGuard(t *testing.T) {
	o := one(t, "wireguard://cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5cHI%3D@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A8a1b%3A%3A1&reserved=1%2C2%2C3&mtu=1280#warp")
	if !o.Endpoint {
		t.Fatal("WireGuard 应该是 endpoint")
	}
	has(t, o, `"private_key":"cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5cHI="`, `"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="`,
		`"address":["172.16.0.2/32","2606:4700:110:8a1b::1/128"]`, `"reserved":[1,2,3]`)
	// + 没编码被当成空格
	has(t, one(t, "wg://k@1.2.3.4:51820?publickey=ab+cd=&address=10.0.0.2&reserved=UJnM"), `"public_key":"ab+cd="`, `"reserved":[80,153,204]`)
	conf := "[Interface]\nPrivateKey = PRIV=\nAddress = 172.16.0.2/32\nAddress = 2606:4700::2/128\nMTU = 1280\n\n[Peer]\nPublicKey = PUB=\nAllowedIPs = 0.0.0.0/0\nEndpoint = engage.cloudflareclient.com:2408\n"
	o = one(t, conf)
	has(t, o, `"address":["172.16.0.2/32","2606:4700::2/128"]`, `"address":"engage.cloudflareclient.com"`, `"port":2408`)
}

func TestJSONAndMulti(t *testing.T) {
	o := one(t, `{"type":"socks","tag":"my","server":"1.2.3.4","server_port":1080,"detour":"x"}`)
	if o.Name != "my" || o.Server != "1.2.3.4:1080" {
		t.Error(o.Name, o.Server)
	}
	if _, ok := o.Config["detour"]; ok {
		t.Error("detour 应该去掉")
	}
	o = one(t, `{"type":"wireguard","tag":"wg","server":"1.2.3.4","server_port":2408,"local_address":["172.16.0.2/32"],"private_key":"a","peer_public_key":"b","reserved":[1,2,3]}`)
	has(t, o, `"peers":[{"address":"1.2.3.4","allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":30,"port":2408,"public_key":"b","reserved":[1,2,3]}]`)
	full := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"http","tag":"h","server":"1.1.1.1","server_port":80}],"endpoints":[{"type":"wireguard","tag":"w","peers":[{"address":"1.1.1.1","port":1}]}]}`
	os, errs := parseOutbounds(full)
	if len(os) != 2 || len(errs) != 0 || !os[1].Endpoint {
		t.Fatal(len(os), errs)
	}
	// 好几条链接、整段 base64 订阅
	multi := "socks5://1.2.3.4:1080#a\ntrojan://pw@t.example.com:443#b  vless://u@v.example.com:443#c\nvless://u@bad host:443"
	if os, errs := parseOutbounds(multi); len(os) != 3 || len(errs) != 1 {
		t.Fatalf("%d %v", len(os), errs)
	}
	sub := base64.StdEncoding.EncodeToString([]byte("socks5://1.2.3.4:1080#a\nhttp://5.6.7.8:80#b"))
	if os, errs := parseOutbounds(sub); len(os) != 2 || len(errs) != 0 {
		t.Fatalf("%d %v", len(os), errs)
	}
	if _, errs := parseOutbounds("ssr://abc"); len(errs) == 0 {
		t.Error("ssr 应该报错")
	}
	if _, errs := parseOutbounds("https://sub.example.com/api/v1/client/subscribe?token=x"); len(errs) == 0 || !strings.Contains(errs[0].Error(), "订阅") {
		t.Errorf("订阅地址应该提示：%v", errs)
	}
}

func TestNames(t *testing.T) {
	st := &State{Outbounds: []*Outbound{{Name: "warp"}, {Name: "socks5"}}}
	if n := uniqueName(st, cleanName(" 美国 家宽: 1 ")); n != "美国-家宽-1" {
		t.Error(n)
	}
	if n := uniqueName(st, "socks5"); n != "socks5-2" {
		t.Error(n)
	}
	if n := uniqueName(st, "direct"); n != "direct-2" {
		t.Error(n)
	}
	if defaultName(&Outbound{Kind: "Shadowsocks"}) != "ss" || defaultName(&Outbound{Kind: "VLESS Reality"}) != "vless" {
		t.Error("defaultName")
	}
}

func TestWarpCandidates(t *testing.T) {
	o := &Outbound{Warp: &WarpAcct{Peer4: "162.159.192.8", Peer6: "2606:4700:d0::a29f:c008"}}
	if c := warpCandidates(o, true); strings.Join(c, " ") != "162.159.192.8:2408 162.159.192.8:500 162.159.192.8:4500 162.159.193.10:2408 188.114.97.1:2408" {
		t.Error(c)
	}
	if c := warpCandidates(o, false); c[0] != "[2606:4700:d0::a29f:c008]:2408" || c[len(c)-1] != "[2606:4700:d0::a29f:c001]:2408" {
		t.Error(c)
	}
	o.Warp.Peer6 = ""
	if c := warpCandidates(o, false); len(c) != 3 {
		t.Error("默认 v6 入口不该重复", c)
	}
}
