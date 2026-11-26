package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// ── 链接解析：各种分享链接和代理格式 → sing-box 出站 ──────────

// 一次粘进来的可能是好几条链接、一段 base64 订阅、JSON、WireGuard 配置或者文件路径
func parseOutbounds(raw string) ([]*Outbound, []error) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	if raw == "" {
		return nil, []error{errors.New("内容是空的")}
	}
	if strings.HasPrefix(raw, "/") && !strings.Contains(raw, "\n") {
		b, err := os.ReadFile(raw)
		if err != nil {
			return nil, []error{fmt.Errorf("读不了文件 %s：%v", raw, err)}
		}
		raw = strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	}
	low := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(low, "[interface]"):
		o, err := parseWGConf(raw)
		if err != nil {
			return nil, []error{err}
		}
		return []*Outbound{o}, nil
	case strings.HasPrefix(raw, "{") || (strings.HasPrefix(raw, "[") && json.Valid([]byte(raw))):
		return parseJSONOut(raw)
	}
	var items []string
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") {
			continue
		}
		// 一行里空格隔开好几条链接
		if fs := strings.Fields(l); len(fs) > 1 && allLinks(fs) {
			items = append(items, fs...)
			continue
		}
		items = append(items, l)
	}
	// 整段 base64：订阅内容
	if len(items) == 1 && !strings.Contains(items[0], "://") {
		if b, ok := b64(items[0]); ok && strings.Contains(string(b), "://") {
			return parseOutbounds(string(b))
		}
	}
	var res []*Outbound
	var errs []error
	for _, it := range items {
		o, err := parseLink(it)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s：%v", short(it), err))
			continue
		}
		res = append(res, o)
	}
	return res, errs
}

func allLinks(fs []string) bool {
	for _, f := range fs {
		if !strings.Contains(f, "://") {
			return false
		}
	}
	return true
}

func short(s string) string {
	r := []rune(s)
	if len(r) > 48 {
		return string(r[:45]) + "…"
	}
	return s
}

func parseLink(s string) (*Outbound, error) {
	s = strings.Trim(strings.TrimSpace(s), "\"'`")
	i := strings.Index(s, "://")
	if i < 0 {
		return parseBare(s)
	}
	switch scheme := strings.ToLower(s[:i]); scheme {
	case "vmess":
		return parseVmess(s)
	case "ss":
		return parseSS(s)
	case "ssr":
		return nil, errors.New("sing-box 不支持 SSR")
	case "vless", "trojan", "hysteria2", "hy2", "tuic", "anytls", "wireguard", "wg",
		"socks", "socks5", "socks5h", "socks4", "socks4a", "http", "https", "hysteria":
		l, err := splitURL(s)
		if err != nil {
			return nil, err
		}
		switch scheme {
		case "vless":
			return parseVless(l)
		case "trojan":
			return parseTrojan(l)
		case "hysteria2", "hy2":
			return parseHy2Link(l)
		case "tuic":
			return parseTuic(l)
		case "anytls":
			return parseAnyTLSLink(l)
		case "wireguard", "wg":
			return parseWGLink(l)
		case "hysteria":
			return parseHysteria(l)
		case "http", "https":
			return parseHTTPProxy(l)
		default:
			return parseSocks(l)
		}
	default:
		return nil, fmt.Errorf("不认识 %s:// 这种链接", scheme)
	}
}

// ── 通用的拆链接 ────────────────────────────────────

type lk struct {
	scheme   string
	userinfo string // 原样，没解码
	host     string
	port     int
	ports    string // 端口后面跟的端口段，hy2 端口跳跃用
	path     string
	q        url.Values
	name     string
}

// 不用 url.Parse：它不认 host:443,20000-30000 这种端口，userinfo 里有 / 也会拆错
func splitURL(s string) (*lk, error) {
	i := strings.Index(s, "://")
	l := &lk{scheme: strings.ToLower(s[:i])}
	rest := s[i+3:]
	if j := strings.Index(rest, "#"); j >= 0 {
		l.name = unesc(rest[j+1:])
		rest = rest[:j]
	}
	query := ""
	if j := strings.Index(rest, "?"); j >= 0 {
		query = rest[j+1:]
		rest = rest[:j]
	}
	l.q, _ = url.ParseQuery(query)
	auth := rest
	if j := strings.LastIndex(rest, "@"); j >= 0 {
		l.userinfo, auth = rest[:j], rest[j+1:]
	}
	if j := strings.Index(auth, "/"); j >= 0 {
		l.path, auth = auth[j:], auth[:j]
	}
	host, ports, err := splitHostPort(auth)
	if err != nil {
		return nil, err
	}
	l.host = host
	if ports != "" {
		if p, err := strconv.Atoi(ports); err == nil {
			l.port = p
		} else {
			// 443,20000-30000：第一段是单个端口就当主端口
			first := strings.Split(ports, ",")[0]
			if p, err := strconv.Atoi(first); err == nil {
				l.port = p
			}
			l.ports = ports
		}
	}
	if l.port == 0 && l.ports == "" {
		l.port = map[string]int{"http": 80, "https": 443, "socks": 1080, "socks5": 1080, "socks5h": 1080,
			"socks4": 1080, "socks4a": 1080}[l.scheme]
		if l.port == 0 {
			l.port = 443
		}
	}
	if l.port < 0 || l.port > 65535 {
		return nil, fmt.Errorf("端口 %d 不对", l.port)
	}
	return l, nil
}

func splitHostPort(a string) (string, string, error) {
	var host, port string
	switch {
	case strings.HasPrefix(a, "["):
		j := strings.Index(a, "]")
		if j < 0 {
			return "", "", errors.New("IPv6 地址少了 ]")
		}
		host = a[1:j]
		port = strings.TrimPrefix(a[j+1:], ":")
	case strings.Count(a, ":") == 1:
		host, port, _ = strings.Cut(a, ":")
	case strings.Count(a, ":") > 1 && net.ParseIP(a) != nil:
		host = a
	case !strings.Contains(a, ":"):
		host = a
	default:
		return "", "", fmt.Errorf("地址 %s 看不懂", a)
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", "", errors.New("缺服务器地址")
	}
	if net.ParseIP(host) == nil && !reServer.MatchString(host) {
		return "", "", fmt.Errorf("服务器地址 %s 不对", host)
	}
	return host, port, nil
}

var reServer = regexp.MustCompile(`^([a-z0-9_]([a-z0-9_-]*[a-z0-9_])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func unesc(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

func b64(s string) ([]byte, bool) {
	s = strings.TrimRight(strings.Join(strings.Fields(s), ""), "=")
	if s == "" {
		return nil, false
	}
	for _, e := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func first(ss ...string) string {
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitList(s string) []string {
	var r []string
	for _, x := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ';' || unicode.IsSpace(c) }) {
		if x != "" {
			r = append(r, x)
		}
	}
	return r
}

// 地址是域名才拿来当 SNI，IP 不行
func domainOf(h string) string {
	if net.ParseIP(h) != nil {
		return ""
	}
	return h
}

func newOut(l *lk, typ string) map[string]any {
	return map[string]any{"type": typ, "server": l.host, "server_port": l.port}
}

func outOf(l *lk, kind string, c map[string]any) *Outbound {
	return &Outbound{Name: l.name, Kind: kind, Server: hostPort(l.host, l.port), Config: c}
}

// ── TLS 和传输层 ─────────────────────────────────────

var utlsFPs = map[string]bool{"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true,
	"qq": true, "ios": true, "android": true, "random": true, "randomized": true}

func tlsOf(q url.Values, security, defSNI string) (map[string]any, error) {
	security = strings.ToLower(security)
	switch security {
	case "", "none":
		return nil, nil
	case "tls", "xtls", "reality":
	default:
		return nil, fmt.Errorf("不认识 security=%s", security)
	}
	t := map[string]any{"enabled": true}
	if sni := first(q.Get("sni"), q.Get("peer"), q.Get("servername"), defSNI); sni != "" {
		t["server_name"] = sni
	}
	if truthy(first(q.Get("allowInsecure"), q.Get("insecure"), q.Get("allow_insecure"), q.Get("skip-cert-verify"))) {
		t["insecure"] = true
	}
	if a := splitList(q.Get("alpn")); len(a) > 0 {
		t["alpn"] = a
	}
	fp := strings.ToLower(q.Get("fp"))
	if security == "reality" {
		pbk := q.Get("pbk")
		if pbk == "" {
			return nil, errors.New("Reality 链接缺 pbk（公钥）")
		}
		t["reality"] = map[string]any{"enabled": true, "public_key": pbk, "short_id": q.Get("sid")}
		if fp == "" {
			fp = "chrome"
		}
	}
	if fp != "" && fp != "none" {
		if fp == "randomizednoalpn" {
			fp = "randomized"
		}
		if !utlsFPs[fp] {
			fp = "chrome"
		}
		t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return t, nil
}

// /path?ed=2048 是 Xray 的 WS 早期数据写法
var reED = regexp.MustCompile(`[?&]ed=(\d+)`)

func transportOf(typ, host, path string, q url.Values) (map[string]any, string, error) {
	switch strings.ToLower(typ) {
	case "", "tcp", "raw", "none":
		if strings.EqualFold(q.Get("headerType"), "http") {
			t := map[string]any{"type": "http", "method": "GET"}
			if h := splitList(host); len(h) > 0 {
				t["host"] = h
			}
			if path != "" {
				t["path"] = path
			}
			return t, "TCP-HTTP", nil
		}
		return nil, "", nil
	case "ws", "websocket":
		t := map[string]any{"type": "ws"}
		if m := reED.FindStringSubmatch(path); m != nil {
			n, _ := strconv.Atoi(m[1])
			path = strings.TrimRight(reED.ReplaceAllString(path, ""), "?&")
			t["max_early_data"] = n
			t["early_data_header_name"] = "Sec-WebSocket-Protocol"
		}
		if path == "" {
			path = "/"
		}
		t["path"] = path
		if host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		return t, "WS", nil
	case "http", "h2":
		t := map[string]any{"type": "http"}
		if h := splitList(host); len(h) > 0 {
			t["host"] = h
		}
		if path != "" {
			t["path"] = path
		}
		return t, "H2", nil
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade"}
		if host != "" {
			t["host"] = host
		}
		if path != "" {
			t["path"] = path
		}
		return t, "HTTPUpgrade", nil
	case "grpc", "gun":
		return map[string]any{"type": "grpc", "service_name": first(q.Get("serviceName"), q.Get("service_name"), strings.TrimPrefix(path, "/"))}, "gRPC", nil
	case "quic":
		return map[string]any{"type": "quic"}, "QUIC", nil
	case "xhttp", "splithttp":
		return nil, "", errors.New("XHTTP 是 Xray 独有的，sing-box 不支持")
	case "kcp", "mkcp":
		return nil, "", errors.New("sing-box 不支持 mKCP")
	}
	return nil, "", fmt.Errorf("不认识的传输方式 type=%s", typ)
}

// vless、vmess、trojan 共用：传输层 + TLS，返回显示用的类型名
func v2Common(c map[string]any, l *lk, proto, security string) (string, error) {
	typ := strings.ToLower(l.q.Get("type"))
	host := first(l.q.Get("host"))
	tr, tn, err := transportOf(typ, host, l.q.Get("path"), l.q)
	if err != nil {
		return "", err
	}
	if tr != nil {
		c["transport"] = tr
	}
	h := strings.Split(host, ",")[0]
	t, err := tlsOf(l.q, security, first(h, domainOf(l.host)))
	if err != nil {
		return "", err
	}
	kind := proto
	if tn != "" {
		kind += " " + tn
	}
	if t != nil {
		c["tls"] = t
		if _, ok := t["reality"]; ok {
			kind += " Reality"
		} else {
			kind += " TLS"
		}
	}
	return kind, nil
}

// ── 各协议 ───────────────────────────────────────────

func parseVless(l *lk) (*Outbound, error) {
	id := unesc(l.userinfo)
	if id == "" {
		return nil, errors.New("缺 UUID")
	}
	if enc := strings.ToLower(l.q.Get("encryption")); enc != "" && enc != "none" {
		return nil, errors.New("VLESS Encryption 是 Xray 独有的，sing-box 不支持")
	}
	c := newOut(l, "vless")
	c["uuid"] = id
	if f := l.q.Get("flow"); f != "" {
		if !strings.HasPrefix(f, "xtls-rprx-vision") {
			return nil, fmt.Errorf("sing-box 不支持 flow=%s", f)
		}
		c["flow"] = "xtls-rprx-vision"
	}
	kind, err := v2Common(c, l, "VLESS", l.q.Get("security"))
	if err != nil {
		return nil, err
	}
	return outOf(l, kind, c), nil
}

func parseTrojan(l *lk) (*Outbound, error) {
	pw := unesc(l.userinfo)
	if pw == "" {
		return nil, errors.New("缺密码")
	}
	c := newOut(l, "trojan")
	c["password"] = pw
	sec := first(l.q.Get("security"), "tls")
	kind, err := v2Common(c, l, "Trojan", sec)
	if err != nil {
		return nil, err
	}
	return outOf(l, kind, c), nil
}

func parseVmess(s string) (*Outbound, error) {
	body := s[strings.Index(s, "://")+3:]
	name := ""
	if j := strings.Index(body, "#"); j >= 0 {
		name, body = unesc(body[j+1:]), body[:j]
	}
	main, query, _ := strings.Cut(body, "?")
	dec, ok := b64(unesc(main))
	switch {
	case ok && json.Valid(dec):
		return vmessJSON(dec, name)
	case ok && strings.Contains(string(dec), "@"):
		// 小火箭的写法：base64(加密方式:uuid@地址:端口)?remarks=…&obfs=websocket&tls=1
		mid, hp, _ := strings.Cut(string(dec), "@")
		scy, id, _ := strings.Cut(mid, ":")
		q, _ := url.ParseQuery(query)
		host, port, err := splitHostPort(hp)
		if err != nil {
			return nil, err
		}
		v := url.Values{}
		v.Set("id", id)
		v.Set("scy", scy)
		v.Set("aid", first(q.Get("alterId"), "0"))
		if strings.EqualFold(q.Get("obfs"), "websocket") {
			v.Set("net", "ws")
		} else if q.Get("obfs") == "http" || q.Get("obfs") == "h2" {
			v.Set("net", "h2")
		} else if q.Get("obfs") == "grpc" {
			v.Set("net", "grpc")
		}
		op := q.Get("obfsParam")
		var oj map[string]any
		if json.Unmarshal([]byte(op), &oj) == nil {
			op, _ = oj["Host"].(string)
		}
		v.Set("host", op)
		v.Set("path", q.Get("path"))
		if truthy(q.Get("tls")) {
			v.Set("tls", "tls")
		}
		v.Set("sni", q.Get("peer"))
		v.Set("allowInsecure", q.Get("allowInsecure"))
		return vmessBuild(host, port, v, first(name, q.Get("remarks")))
	}
	// 标准 URI：vmess://uuid@地址:端口?type=ws&security=tls…
	l, err := splitURL(s)
	if err != nil {
		return nil, err
	}
	id := unesc(l.userinfo)
	if id == "" {
		return nil, errors.New("vmess 链接解析不了")
	}
	c := newOut(l, "vmess")
	c["uuid"] = id
	c["security"] = first(l.q.Get("encryption"), "auto")
	c["alter_id"] = 0
	kind, err := v2Common(c, l, "VMess", l.q.Get("security"))
	if err != nil {
		return nil, err
	}
	return outOf(l, kind, c), nil
}

// v2rayN 的 JSON 里端口、alterId 有时是数字有时是字符串
func vmessJSON(b []byte, name string) (*Outbound, error) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(v)
		}
		return ""
	}
	v := url.Values{}
	for _, k := range []string{"id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp", "allowInsecure", "insecure", "skip-cert-verify"} {
		v.Set(k, str(k))
	}
	host, port, err := splitHostPort(strings.TrimSpace(str("add")))
	if err != nil {
		return nil, err
	}
	if port == "" {
		port = str("port")
	}
	return vmessBuild(host, port, v, first(name, str("ps")))
}

func vmessBuild(host, port string, v url.Values, name string) (*Outbound, error) {
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("端口 %q 不对", port)
	}
	if v.Get("id") == "" {
		return nil, errors.New("缺 UUID")
	}
	l := &lk{scheme: "vmess", host: host, port: p, name: name, q: url.Values{}}
	c := newOut(l, "vmess")
	c["uuid"] = v.Get("id")
	c["security"] = first(v.Get("scy"), "auto")
	aid, _ := strconv.Atoi(first(v.Get("aid"), "0"))
	c["alter_id"] = aid
	// 换成和 vless 一样的参数名，复用同一套传输层和 TLS 处理
	l.q.Set("type", v.Get("net"))
	l.q.Set("headerType", v.Get("type"))
	l.q.Set("host", v.Get("host"))
	l.q.Set("path", v.Get("path"))
	if strings.EqualFold(v.Get("net"), "grpc") {
		l.q.Set("serviceName", v.Get("path"))
	}
	for _, k := range []string{"sni", "alpn", "fp", "allowInsecure", "insecure", "skip-cert-verify"} {
		l.q.Set(k, v.Get(k))
	}
	sec := ""
	if strings.EqualFold(v.Get("tls"), "tls") {
		sec = "tls"
	}
	kind, err := v2Common(c, l, "VMess", sec)
	if err != nil {
		return nil, err
	}
	return outOf(l, kind, c), nil
}

var ssMethods = map[string]bool{"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true, "none": true, "aes-128-gcm": true, "aes-192-gcm": true,
	"aes-256-gcm": true, "chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true, "aes-128-cfb": true,
	"aes-192-cfb": true, "aes-256-cfb": true, "rc4-md5": true, "chacha20-ietf": true, "xchacha20": true}

func ssMethod(m string) string {
	m = strings.ToLower(strings.TrimSpace(m))
	switch m {
	case "chacha20-poly1305":
		return "chacha20-ietf-poly1305"
	case "xchacha20-poly1305":
		return "xchacha20-ietf-poly1305"
	}
	return m
}

func parseSS(s string) (*Outbound, error) {
	body := s[strings.Index(s, "://")+3:]
	name := ""
	if j := strings.Index(body, "#"); j >= 0 {
		name, body = unesc(body[j+1:]), body[:j]
	}
	body, query, _ := strings.Cut(body, "?")
	body = strings.TrimSuffix(body, "/")
	var method, pass, hp string
	if j := strings.LastIndex(body, "@"); j >= 0 {
		ui := body[:j]
		hp = strings.TrimSuffix(body[j+1:], "/")
		// SIP002：base64(方法:密码)；2022 系列常直接写成 方法:密码 再百分号编码
		if d, ok := b64(unesc(ui)); ok && strings.Contains(string(d), ":") && ssMethods[ssMethod(strings.SplitN(string(d), ":", 2)[0])] {
			method, pass, _ = strings.Cut(string(d), ":")
		} else {
			method, pass, _ = strings.Cut(unesc(ui), ":")
		}
	} else {
		// 老格式：整段 base64(方法:密码@地址:端口)
		d, ok := b64(unesc(body))
		if !ok {
			return nil, errors.New("ss 链接解析不了")
		}
		ds := string(d)
		j := strings.LastIndex(ds, "@")
		if j < 0 {
			return nil, errors.New("ss 链接解析不了")
		}
		method, pass, _ = strings.Cut(ds[:j], ":")
		hp = ds[j+1:]
	}
	method = ssMethod(method)
	if !ssMethods[method] {
		return nil, fmt.Errorf("sing-box 不支持加密方式 %s", method)
	}
	host, port, err := splitHostPort(hp)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("端口 %q 不对", port)
	}
	l := &lk{scheme: "ss", host: host, port: p, name: name}
	c := newOut(l, "shadowsocks")
	c["method"] = method
	c["password"] = pass
	q, _ := url.ParseQuery(query)
	if pl := q.Get("plugin"); pl != "" {
		parts := strings.Split(pl, ";")
		switch parts[0] {
		case "obfs-local", "simple-obfs":
			c["plugin"] = "obfs-local"
		case "v2ray-plugin":
			c["plugin"] = "v2ray-plugin"
		default:
			return nil, fmt.Errorf("sing-box 只支持 obfs-local 和 v2ray-plugin 插件，不支持 %s", parts[0])
		}
		c["plugin_opts"] = strings.Join(parts[1:], ";")
	}
	if truthy(first(q.Get("uot"), q.Get("udp-over-tcp"))) {
		c["udp_over_tcp"] = true
	}
	return outOf(l, "Shadowsocks", c), nil
}

// 端口段 20000-30000,40000-50000 → sing-box 的 20000:30000
func hopPorts(s string) []string {
	var r []string
	for _, x := range strings.Split(s, ",") {
		x = strings.TrimSpace(x)
		a, b, isRange := strings.Cut(x, "-")
		if !isRange {
			a, b, isRange = strings.Cut(x, ":")
		}
		pa, e1 := strconv.Atoi(a)
		if !isRange {
			if e1 == nil && pa > 0 && pa < 65536 {
				r = append(r, fmt.Sprintf("%d:%d", pa, pa))
			}
			continue
		}
		pb, e2 := strconv.Atoi(b)
		if e1 == nil && e2 == nil && pa > 0 && pb >= pa && pb < 65536 {
			r = append(r, fmt.Sprintf("%d:%d", pa, pb))
		}
	}
	return r
}

func parseHy2Link(l *lk) (*Outbound, error) {
	pw := unesc(l.userinfo)
	if pw == "" {
		pw = l.q.Get("auth")
	}
	c := map[string]any{"type": "hysteria2", "server": l.host, "password": pw}
	hop := hopPorts(first(l.q.Get("mport"), l.ports))
	if len(hop) > 0 {
		c["server_ports"] = hop
	} else {
		c["server_port"] = l.port
	}
	if o := strings.ToLower(l.q.Get("obfs")); o != "" && o != "none" {
		if o != "salamander" && o != "gecko" {
			return nil, fmt.Errorf("sing-box 不支持混淆 %s", o)
		}
		c["obfs"] = map[string]any{"type": o, "password": l.q.Get("obfs-password")}
	}
	t := map[string]any{"enabled": true, "alpn": []string{"h3"}}
	if sni := first(l.q.Get("sni"), l.q.Get("peer"), domainOf(l.host)); sni != "" {
		t["server_name"] = sni
	}
	if truthy(first(l.q.Get("insecure"), l.q.Get("allowInsecure"))) || l.q.Get("pinSHA256") != "" {
		// pinSHA256 是整张证书的指纹，sing-box 只认公钥指纹，只能跳过验证
		t["insecure"] = true
	}
	if a := splitList(l.q.Get("alpn")); len(a) > 0 {
		t["alpn"] = a
	}
	c["tls"] = t
	for k, f := range map[string]string{"up_mbps": "upmbps", "down_mbps": "downmbps"} {
		if n, err := strconv.Atoi(strings.TrimSuffix(strings.ToLower(first(l.q.Get(f), l.q.Get(strings.TrimSuffix(f, "mbps")))), "mbps")); err == nil && n > 0 {
			c[k] = n
		}
	}
	kind := "Hysteria2"
	if len(hop) > 0 {
		kind += " 端口跳跃"
	}
	return outOf(l, kind, c), nil
}

func parseHysteria(l *lk) (*Outbound, error) {
	if p := strings.ToLower(l.q.Get("protocol")); p != "" && p != "udp" {
		return nil, fmt.Errorf("sing-box 只支持 UDP 模式的 Hysteria，不支持 %s", p)
	}
	c := newOut(l, "hysteria")
	up, _ := strconv.Atoi(first(l.q.Get("upmbps"), "100"))
	down, _ := strconv.Atoi(first(l.q.Get("downmbps"), "100"))
	c["up_mbps"], c["down_mbps"] = up, down
	if a := first(l.q.Get("auth"), unesc(l.userinfo)); a != "" {
		c["auth_str"] = a
	}
	if o := first(l.q.Get("obfsParam"), l.q.Get("obfs-password")); o != "" {
		c["obfs"] = o
	}
	t := map[string]any{"enabled": true, "alpn": []string{first(l.q.Get("alpn"), "hysteria")}}
	if sni := first(l.q.Get("peer"), l.q.Get("sni"), domainOf(l.host)); sni != "" {
		t["server_name"] = sni
	}
	if truthy(first(l.q.Get("insecure"), l.q.Get("allowInsecure"))) {
		t["insecure"] = true
	}
	c["tls"] = t
	return outOf(l, "Hysteria", c), nil
}

func parseTuic(l *lk) (*Outbound, error) {
	id, pw, _ := strings.Cut(l.userinfo, ":")
	id, pw = unesc(id), unesc(pw)
	if id == "" {
		return nil, errors.New("缺 UUID")
	}
	c := newOut(l, "tuic")
	c["uuid"] = id
	c["password"] = pw
	if cc := first(l.q.Get("congestion_control"), l.q.Get("congestion-control")); cc != "" {
		c["congestion_control"] = strings.ToLower(cc)
	}
	if m := first(l.q.Get("udp_relay_mode"), l.q.Get("udp-relay-mode")); m != "" {
		c["udp_relay_mode"] = strings.ToLower(m)
	}
	t := map[string]any{"enabled": true, "alpn": []string{"h3"}}
	if a := splitList(l.q.Get("alpn")); len(a) > 0 {
		t["alpn"] = a
	}
	if sni := first(l.q.Get("sni"), domainOf(l.host)); sni != "" {
		t["server_name"] = sni
	}
	if truthy(first(l.q.Get("allow_insecure"), l.q.Get("allowInsecure"), l.q.Get("insecure"))) {
		t["insecure"] = true
	}
	if truthy(first(l.q.Get("disable_sni"), l.q.Get("disable-sni"))) {
		t["disable_sni"] = true
	}
	c["tls"] = t
	return outOf(l, "TUIC", c), nil
}

func parseAnyTLSLink(l *lk) (*Outbound, error) {
	pw := unesc(l.userinfo)
	if pw == "" {
		return nil, errors.New("缺密码")
	}
	c := newOut(l, "anytls")
	c["password"] = pw
	t, _ := tlsOf(l.q, "tls", domainOf(l.host))
	c["tls"] = t
	return outOf(l, "AnyTLS", c), nil
}

func parseSocks(l *lk) (*Outbound, error) {
	c := newOut(l, "socks")
	c["version"] = map[string]string{"socks4": "4", "socks4a": "4a"}[l.scheme]
	if c["version"] == "" {
		c["version"] = "5"
	}
	ui := unesc(l.userinfo)
	// v2rayN 的 socks:// 链接把 用户:密码 做了 base64
	if l.scheme == "socks" && ui != "" && !strings.Contains(ui, ":") {
		if d, ok := b64(ui); ok && strings.Contains(string(d), ":") {
			ui = string(d)
		}
	}
	if ui != "" {
		u, p, _ := strings.Cut(ui, ":")
		c["username"], c["password"] = u, p
	}
	kind := "SOCKS" + c["version"].(string)
	return outOf(l, kind, c), nil
}

func parseHTTPProxy(l *lk) (*Outbound, error) {
	if l.userinfo == "" && l.path != "" && l.path != "/" {
		return nil, errors.New("这是个网址，不是代理。机场订阅要在客户端里复制单个节点的链接再粘过来")
	}
	c := newOut(l, "http")
	if ui := l.userinfo; ui != "" {
		u, p, _ := strings.Cut(ui, ":")
		c["username"], c["password"] = unesc(u), unesc(p)
	}
	kind := "HTTP"
	if l.scheme == "https" {
		t := map[string]any{"enabled": true}
		if sni := first(l.q.Get("sni"), domainOf(l.host)); sni != "" {
			t["server_name"] = sni
		}
		if truthy(first(l.q.Get("insecure"), l.q.Get("allowInsecure"))) {
			t["insecure"] = true
		}
		c["tls"] = t
		kind = "HTTPS"
	}
	return outOf(l, kind, c), nil
}

// ── WireGuard ───────────────────────────────────────

// 链接里没编码的 + 会被当成空格，base64 的密钥要换回来
func wgKey(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), " ", "+") }

func wgAddrs(s string) []string {
	var r []string
	for _, a := range splitList(s) {
		if !strings.Contains(a, "/") {
			if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
				a += "/128"
			} else {
				a += "/32"
			}
		}
		r = append(r, a)
	}
	return r
}

// reserved 有写成 1,2,3 的，也有写 client_id（base64）的
func wgReserved(s string) []int {
	s = strings.Trim(strings.TrimSpace(s), "[]")
	if s == "" {
		return nil
	}
	if strings.Contains(s, ",") {
		var r []int
		for _, x := range strings.Split(s, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(x))
			if err != nil || n < 0 || n > 255 {
				return nil
			}
			r = append(r, n)
		}
		if len(r) == 3 {
			return r
		}
		return nil
	}
	if b, ok := b64(s); ok && len(b) == 3 {
		return []int{int(b[0]), int(b[1]), int(b[2])}
	}
	return nil
}

func wgEndpoint(priv, peerPub, psk, host string, port int, addrs []string, reserved []int, mtu int) map[string]any {
	if mtu <= 0 {
		mtu = 1280
	}
	peer := map[string]any{"address": host, "port": port, "public_key": peerPub,
		"allowed_ips": []string{"0.0.0.0/0", "::/0"}, "persistent_keepalive_interval": 30}
	if psk != "" {
		peer["pre_shared_key"] = psk
	}
	if len(reserved) == 3 {
		peer["reserved"] = reserved
	}
	return map[string]any{"type": "wireguard", "mtu": mtu, "address": addrs, "private_key": priv,
		"peers": []any{peer}}
}

func parseWGLink(l *lk) (*Outbound, error) {
	priv := wgKey(unesc(l.userinfo))
	pub := wgKey(first(l.q.Get("publickey"), l.q.Get("publicKey"), l.q.Get("public_key"), l.q.Get("peer_public_key")))
	addrs := wgAddrs(first(l.q.Get("address"), l.q.Get("ip"), l.q.Get("local_address")))
	if priv == "" || pub == "" {
		return nil, errors.New("WireGuard 链接缺私钥或 publickey")
	}
	if len(addrs) == 0 {
		return nil, errors.New("WireGuard 链接缺 address")
	}
	mtu, _ := strconv.Atoi(l.q.Get("mtu"))
	ep := wgEndpoint(priv, pub, wgKey(first(l.q.Get("presharedkey"), l.q.Get("pre_shared_key"), l.q.Get("psk"))),
		l.host, l.port, addrs, wgReserved(l.q.Get("reserved")), mtu)
	o := outOf(l, "WireGuard", ep)
	o.Endpoint = true
	return o, nil
}

func parseWGConf(raw string) (*Outbound, error) {
	kv := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if old, dup := kv[k]; dup && k == "address" {
			v = old + "," + v
		}
		kv[k] = v
	}
	if kv["privatekey"] == "" || kv["publickey"] == "" || kv["endpoint"] == "" {
		return nil, errors.New("WireGuard 配置里缺 PrivateKey、PublicKey 或 Endpoint")
	}
	host, port, err := splitHostPort(kv["endpoint"])
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("Endpoint 端口 %q 不对", port)
	}
	addrs := wgAddrs(kv["address"])
	if len(addrs) == 0 {
		return nil, errors.New("WireGuard 配置里缺 Address")
	}
	mtu, _ := strconv.Atoi(kv["mtu"])
	ep := wgEndpoint(kv["privatekey"], kv["publickey"], kv["presharedkey"], host, p, addrs, wgReserved(kv["reserved"]), mtu)
	return &Outbound{Kind: "WireGuard", Server: hostPort(host, p), Config: ep, Endpoint: true}, nil
}

// ── sing-box 的 JSON ─────────────────────────────────

var skipTypes = map[string]bool{"direct": true, "block": true, "dns": true, "selector": true, "urltest": true}

func parseJSONOut(raw string) ([]*Outbound, []error) {
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, []error{fmt.Errorf("JSON 格式不对：%v", err)}
	}
	var objs []map[string]any
	switch x := v.(type) {
	case map[string]any:
		if _, full := x["outbounds"]; full {
			for _, k := range []string{"outbounds", "endpoints"} {
				if a, ok := x[k].([]any); ok {
					for _, it := range a {
						if m, ok := it.(map[string]any); ok {
							objs = append(objs, m)
						}
					}
				}
			}
		} else {
			objs = append(objs, x)
		}
	case []any:
		for _, it := range x {
			if m, ok := it.(map[string]any); ok {
				objs = append(objs, m)
			}
		}
	}
	var res []*Outbound
	var errs []error
	for _, m := range objs {
		typ, _ := m["type"].(string)
		if typ == "" {
			errs = append(errs, errors.New("JSON 里缺 type 字段"))
			continue
		}
		if skipTypes[typ] {
			continue
		}
		name, _ := m["tag"].(string)
		delete(m, "tag")
		kind := map[string]string{"socks": "SOCKS5", "http": "HTTP", "vless": "VLESS", "vmess": "VMess", "trojan": "Trojan",
			"shadowsocks": "Shadowsocks", "hysteria2": "Hysteria2", "hysteria": "Hysteria", "tuic": "TUIC", "anytls": "AnyTLS",
			"shadowtls": "ShadowTLS", "ssh": "SSH", "tor": "Tor", "naive": "Naive"}[typ]
		// 引用的别的 tag 在 dun 的配置里不存在，去掉
		delete(m, "detour")
		if _, ok := m["domain_resolver"].(string); ok {
			delete(m, "domain_resolver")
		}
		o := &Outbound{Name: name, Kind: first(kind, typ), Config: m}
		if typ == "wireguard" {
			if _, ok := m["peers"]; !ok {
				// 老版本的 wireguard 出站，换成 endpoint 写法
				addrs := []string{}
				if a, ok := m["local_address"].([]any); ok {
					for _, x := range a {
						if s, ok := x.(string); ok {
							addrs = append(addrs, s)
						}
					}
				}
				var res3 []int
				if r, ok := m["reserved"].([]any); ok && len(r) == 3 {
					for _, x := range r {
						f, _ := x.(float64)
						res3 = append(res3, int(f))
					}
				}
				host, _ := m["server"].(string)
				port, _ := m["server_port"].(float64)
				mtu, _ := m["mtu"].(float64)
				priv, _ := m["private_key"].(string)
				pub, _ := m["peer_public_key"].(string)
				psk, _ := m["pre_shared_key"].(string)
				o.Config = wgEndpoint(priv, pub, psk, host, int(port), wgAddrs(strings.Join(addrs, ",")), res3, int(mtu))
			}
			o.Endpoint = true
			o.Kind = "WireGuard"
			if ps, ok := o.Config["peers"].([]any); ok && len(ps) > 0 {
				if p, ok := ps[0].(map[string]any); ok {
					h, _ := p["address"].(string)
					pt, _ := p["port"].(float64)
					if n, ok := p["port"].(int); ok {
						pt = float64(n)
					}
					o.Server = hostPort(h, int(pt))
				}
			}
		} else if h, ok := m["server"].(string); ok {
			pt, _ := m["server_port"].(float64)
			o.Server = hostPort(h, int(pt))
		}
		res = append(res, o)
	}
	if len(res) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("JSON 里没有能用的出站"))
	}
	return res, errs
}

// ── 不带协议头的代理：代理商常给的几种写法 ───────────────
// 地址:端口、地址:端口:用户:密码、用户:密码@地址:端口、用户:密码:地址:端口
// 协议要连上去探一下才知道，先标成 auto

func isPortStr(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n < 65536
}

func isHostStr(s string) bool {
	s = strings.ToLower(strings.Trim(s, "[]"))
	return net.ParseIP(s) != nil || (strings.Contains(s, ".") && reServer.MatchString(s))
}

func parseBare(s string) (*Outbound, error) {
	var host, port, user, pass string
	fs := strings.Fields(s)
	switch {
	case len(fs) == 2 || len(fs) == 4:
		host, port = fs[0], fs[1]
		if len(fs) == 4 {
			user, pass = fs[2], fs[3]
		}
	case strings.Contains(s, "@"):
		j := strings.LastIndex(s, "@")
		user, pass, _ = strings.Cut(s[:j], ":")
		h, p, err := splitHostPort(s[j+1:])
		if err != nil {
			return nil, err
		}
		host, port = h, p
	case strings.HasPrefix(s, "["):
		j := strings.Index(s, "]")
		if j < 0 {
			return nil, errors.New("IPv6 地址少了 ]")
		}
		host = s[1:j]
		parts := strings.SplitN(strings.TrimPrefix(s[j+1:], ":"), ":", 3)
		port = parts[0]
		if len(parts) == 3 {
			user, pass = parts[1], parts[2]
		}
	default:
		ps := strings.Split(s, ":")
		switch {
		case len(ps) == 2:
			host, port = ps[0], ps[1]
		case len(ps) >= 4 && isHostStr(ps[0]) && isPortStr(ps[1]):
			host, port, user, pass = ps[0], ps[1], ps[2], strings.Join(ps[3:], ":")
		case len(ps) == 4 && isHostStr(ps[2]) && isPortStr(ps[3]):
			user, pass, host, port = ps[0], ps[1], ps[2], ps[3]
		default:
			return nil, errors.New("认不出格式。支持：链接、地址:端口、地址:端口:用户:密码、用户:密码@地址:端口")
		}
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if !isHostStr(host) {
		return nil, fmt.Errorf("服务器地址 %s 不对", host)
	}
	if !isPortStr(port) {
		return nil, fmt.Errorf("端口 %s 不对", port)
	}
	p, _ := strconv.Atoi(port)
	c := map[string]any{"type": "auto", "server": host, "server_port": p}
	if user != "" {
		c["username"], c["password"] = user, pass
	}
	return &Outbound{Kind: "auto", Server: hostPort(host, p), Config: c}, nil
}
