package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// 用户给的原样列表，里面 geostie 是笔误
const joeyList = "geosite:openai,geosite:apple,tiktok,ai.google.dev,alkalimakersuite-pa.clients6.google.com,makersuite.google.com,bard.google.com,deepmind.com,deepmind.google,gemini.google.com,generativeai.google,proactivebackend-pa.googleapis.com,apis.google.com,colab,developerprofiles,generativelanguage,geostie:category-ai-!cn,claude.com,anthropic.com,claudeusercontent.com,claude.ai"

func TestParseItemsJoeyList(t *testing.T) {
	its, warns, err := parseItems(joeyList)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "geostie") {
		t.Fatalf("应该提示 geostie 笔误: %v", warns)
	}
	m := compileRule(&Rule{Items: itemStrings(its)})
	if strings.Join(m.sites, ",") != "openai,apple,category-ai-!cn" {
		t.Fatalf("sites = %v", m.sites)
	}
	if strings.Join(m.keyword, ",") != "tiktok,colab,developerprofiles,generativelanguage" {
		t.Fatalf("keyword = %v", m.keyword)
	}
	if len(m.suffix) != 14 || m.suffix[0] != "ai.google.dev" || m.suffix[13] != "claude.ai" {
		t.Fatalf("suffix = %v", m.suffix)
	}
	// 规范化以后再解析一遍结果不变
	again, _, _ := parseItems(strings.Join(itemStrings(its), ","))
	if strings.Join(itemStrings(again), ",") != strings.Join(itemStrings(its), ",") {
		t.Fatal("规范化写法再解析不一致")
	}
}

func TestParseItemsForms(t *testing.T) {
	cases := map[string]string{
		"geosite:Netflix":               "geosite:netflix",
		"GEOIP:telegram":                "geoip:telegram",
		"*.example.com":                 "example.com",
		"+.example.com":                 "example.com",
		"domain:cn":                     "domain:cn",
		"full:x.com":                    "full:x.com",
		"keyword:a.b":                   "keyword:a.b",
		"regexp:^ad\\.":                 "regexp:^ad\\.",
		"1.2.3.4":                       "1.2.3.4/32",
		"1.2.3.0/24":                    "1.2.3.0/24",
		"2001:db8::1":                   "2001:db8::1/128",
		"ip-cidr:10.0.0.0/8":            "10.0.0.0/8",
		"IPv4":                          "ipv4",
		"geosit:google":                 "geosite:google",
		"goeip:cn":                      "geoip:cn",
		"domain-suffix:abc.com":         "abc.com",
		"https://Chat.OpenAI.com/c/abc": "chat.openai.com",
	}
	for in, want := range cases {
		its, _, err := parseItems(in)
		if err != nil || len(its) != 1 || its[0].String() != want {
			t.Errorf("%s → %v %v，想要 %s", in, itemStrings(its), err, want)
		}
	}
	for _, bad := range []string{"ext:geosite.dat:x", "foo:bar", "website:x", "a*b.com", "regexp:(", "geosite:", ""} {
		if _, _, err := parseItems(bad); err == nil {
			t.Errorf("%q 应该报错", bad)
		}
	}
	// 中文逗号、换行、空格混着分隔；Clash 的类型名跳过
	its, warns, _ := parseItems("claude.ai，chatgpt.com\nDOMAIN-SUFFIX x.com、tiktok")
	if strings.Join(itemStrings(its), ",") != "claude.ai,chatgpt.com,x.com,tiktok" || len(warns) != 1 {
		t.Fatalf("%v %v", itemStrings(its), warns)
	}
}

func TestPresetsParse(t *testing.T) {
	for _, p := range presets {
		if _, _, err := parseItems(p.items); err != nil {
			t.Errorf("预设 %s: %v", p.key, err)
		}
	}
}

func TestRouteRules(t *testing.T) {
	st := &State{IP4: "1.2.3.4", Outbounds: []*Outbound{{Name: "warp", Endpoint: true, Config: map[string]any{"type": "wireguard"}}}}
	st.Rules = []*Rule{
		{Out: "warp", Items: []string{"geosite:openai", "claude.ai", "tiktok"}},
		{Out: "block", Items: []string{"geosite:cn", "geoip:cn"}},
		{Out: "gone", Items: []string{"x.com"}}, // 出站被删了，跳过
		{Out: "warp", Items: []string{"ipv4"}},
	}
	rules, sets := routeRules(st)
	b, _ := json.Marshal(rules)
	s := string(b)
	for _, want := range []string{
		`{"domain_keyword":["tiktok"],"domain_suffix":["claude.ai"],"outbound":"warp","rule_set":["geosite-openai"]}`,
		`{"action":"reject","rule_set":["geosite-cn","geoip-cn"]}`,
		`{"action":"resolve","strategy":"prefer_ipv6"}`,
		`{"action":"reject","ip_is_private":true}`,
		`{"action":"reject","rule_set":["geoip-cn"]}`,
		`{"invert":true,"ip_cidr":["::/0"],"outbound":"warp"}`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("缺 %s\n%s", want, s)
		}
	}
	if strings.Contains(s, "x.com") {
		t.Error("出站不存在的规则应该跳过")
	}
	if len(sets) != 3 {
		t.Errorf("规则集 %d 个", len(sets))
	}
	// 只有域名规则时不加 resolve
	st.Rules = st.Rules[:1]
	rules, _ = routeRules(st)
	if b, _ := json.Marshal(rules); strings.Contains(string(b), "resolve") {
		t.Error("只有域名规则不该 resolve")
	}
}

// 没配出站和规则时，生成的配置要和 1.0.0 一模一样，老用户升级不重启
func TestConfigUnchangedWithoutRoute(t *testing.T) {
	st := &State{IP4: "1.2.3.4", TLS: &TLSHost{Host: "a.b.example.com"},
		Reality: &Reality{Port: 443, Fallback: 20001, UUID: "u", PrivateKey: "k", ShortID: "s"}}
	cfg, n := sbConfig(st)
	if n != 1 {
		t.Fatal(n)
	}
	b, _ := json.Marshal(cfg)
	s := string(b)
	for _, bad := range []string{"final", "endpoints", "rule_set", testTag, "resolve"} {
		if strings.Contains(s, bad) {
			t.Errorf("不该出现 %s", bad)
		}
	}
	want := `"route":{"rules":[{"action":"sniff"},{"action":"reject","protocol":"bittorrent"},{"action":"reject","ip_is_private":true}]}`
	if !strings.Contains(s, want) {
		t.Errorf("route 变了：%s", s)
	}
	if !strings.Contains(s, `"outbounds":[{"tag":"direct","type":"direct"}]`) {
		t.Errorf("outbounds 变了：%s", s)
	}
}

func TestConfigWithRoute(t *testing.T) {
	st := &State{IP4: "1.2.3.4", TestPort: 30001, TestPass: "pw",
		Outbounds: []*Outbound{
			{Name: "warp", Endpoint: true, Config: map[string]any{"type": "wireguard", "private_key": "x"}},
			{Name: "家宽", Config: map[string]any{"type": "socks", "server": "1.1.1.1", "server_port": 1080}},
		},
		Rules: []*Rule{{Out: "家宽", Items: []string{"ip.sb"}}},
		Final: "warp",
	}
	cfg, _ := sbConfig(st)
	b, _ := json.Marshal(cfg)
	s := string(b)
	for _, want := range []string{`"endpoints":[{"private_key":"x","tag":"warp","type":"wireguard"}]`,
		`{"server":"1.1.1.1","server_port":1080,"tag":"家宽","type":"socks"}`,
		`"final":"warp"`, `"listen_port":30001`, `"auth_user":["` + testUser("家宽") + `"],"inbound":["dun-test"],"outbound":"家宽"`} {
		if !strings.Contains(s, want) {
			t.Errorf("缺 %s\n%s", want, s)
		}
	}
}

func TestLev(t *testing.T) {
	if lev("geostie", "geosite") != 1 || lev("goeip", "geoip") != 1 || lev("geosite", "geosite") != 0 || lev("geoip", "geosite") <= 2 {
		t.Fatal(lev("geostie", "geosite"), lev("geoip", "geosite"))
	}
}
