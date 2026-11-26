package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// DUN_DUMP=目录 go test -run TestDump：每种链接生成一份完整配置，拿真的 sing-box check
func TestDump(t *testing.T) {
	dir := os.Getenv("DUN_DUMP")
	if dir == "" {
		t.Skip()
	}
	links := []string{
		"socks5://u:p@1.2.3.4:1080", "socks4://1.2.3.4:1080", "http://u:p@proxy.example.com:8080", "https://u:p@proxy.example.com",
		"vless://uuid-1@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab12&type=tcp",
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@cf.example.com:443?encryption=none&security=tls&sni=ws.example.com&type=ws&host=ws.example.com&path=%2Fabc%3Fed%3D2048",
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@h.example.com:443?security=tls&type=grpc&serviceName=svc",
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@1.2.3.4:80?type=httpupgrade&host=a.com&path=/up",
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@1.2.3.4:80?type=h2&security=tls&host=a.com&path=/h2",
		"vless://bf000d23-0752-40b4-affe-68f7707a9661@1.2.3.4:80?type=tcp&headerType=http&host=a.com&path=/",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"x","add":"v.example.com","port":"443","id":"bf000d23-0752-40b4-affe-68f7707a9661","aid":"0","scy":"auto","net":"ws","type":"none","host":"v.example.com","path":"/ws","tls":"tls"}`)),
		"vmess://bf000d23-0752-40b4-affe-68f7707a9661@u.example.com:443?type=grpc&serviceName=g&security=tls",
		"trojan://pass@t.example.com:443?sni=t.example.com&allowInsecure=1",
		"trojan://pass@t.example.com:443?type=ws&path=/tj&host=t.example.com",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@1.2.3.4:8388",
		"ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@1.2.3.4:8388",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:80/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@1.2.3.4:80/?plugin=v2ray-plugin%3Btls%3Bhost%3Da.com",
		"hysteria2://pw@n.example.com:58851/?mport=25943-31275&obfs=gecko&obfs-password=ob&sni=n.example.com",
		"hy2://a:b@1.2.3.4:443,20000-30000?insecure=1&obfs=salamander&obfs-password=x",
		"hysteria2://pw@1.2.3.4:443?pinSHA256=AA:BB&upmbps=50&downmbps=200",
		"hysteria://1.2.3.4:443?protocol=udp&auth=pw&peer=h.example.com&insecure=1&upmbps=50&downmbps=100&obfsParam=ob",
		"tuic://bf000d23-0752-40b4-affe-68f7707a9661:pw@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1",
		"anytls://pw@a.example.com:9443/?sni=a.example.com",
		"wireguard://8OXv9hP%2B8bPGL5W3tDqJiYXbsTUaiR8WjyH6oQ8oOGE%3D@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A8a1b%3A%3A1&reserved=1%2C2%2C3&mtu=1280",
		`{"type":"socks","tag":"my","server":"1.2.3.4","server_port":1080}`,
	}
	os.MkdirAll(dir, 0755)
	for i, l := range links {
		outs, errs := parseOutbounds(l)
		if len(errs) > 0 || len(outs) != 1 {
			t.Fatalf("%s: %v", l, errs)
		}
		o := outs[0]
		o.Name = fmt.Sprintf("o%d", i)
		st := &State{IP4: "1.2.3.4", TestPort: 30001, TestPass: "pw", Outbounds: []*Outbound{o},
			Rules: []*Rule{{Out: o.Name, Items: []string{"claude.ai", "1.0.0.0/24", "ipv4"}}}}
		cfg, _ := sbConfig(st)
		b, _ := json.MarshalIndent(cfg, "", " ")
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("c%02d.json", i)), b, 0644)
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("c%02d.link", i)), []byte(l), 0644)
	}
}
