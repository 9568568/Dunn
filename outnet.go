package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	testTag  = "dun-test"
	traceURL = "https://www.cloudflare.com/cdn-cgi/trace"
)

func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

// 不带协议头的代理：先发 socks5 握手，不像再试 HTTP CONNECT
func probeProxy(o *Outbound) error {
	c := o.Config
	host, _ := c["server"].(string)
	addr := net.JoinHostPort(host, strconv.Itoa(toInt(c["server_port"])))
	user, _ := c["username"].(string)
	pass, _ := c["password"].(string)
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return fmt.Errorf("连不上 %s：%v", addr, err)
	}
	conn.SetDeadline(time.Now().Add(6 * time.Second))
	conn.Write([]byte{5, 2, 0, 2})
	b := make([]byte, 2)
	_, err = io.ReadFull(conn, b)
	conn.Close()
	if err == nil && b[0] == 5 {
		c["type"], c["version"] = "socks", "5"
		o.Kind = "SOCKS5"
		return nil
	}
	conn, err = net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return fmt.Errorf("连不上 %s：%v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	req := "CONNECT www.cloudflare.com:443 HTTP/1.1\r\nHost: www.cloudflare.com:443\r\n"
	if user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	conn.Write([]byte(req + "\r\n"))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err == nil && strings.HasPrefix(line, "HTTP/1.") {
		c["type"] = "http"
		o.Kind = "HTTP"
		if strings.Contains(line, " 407") {
			return errors.New("是 HTTP 代理，但用户名或密码不对")
		}
		return nil
	}
	return fmt.Errorf("%s 既不像 socks5 也不像 http 代理", addr)
}

type exitInfo struct {
	IP, Loc, Warp string
	Dur           time.Duration
}

func (e exitInfo) String() string {
	s := fmt.Sprintf("出口 %s", e.IP)
	if e.Loc != "" {
		s += "（" + e.Loc + "）"
	}
	if e.Warp == "on" || e.Warp == "plus" {
		s += " WARP"
	}
	return s + fmt.Sprintf("，%d ms", e.Dur.Milliseconds())
}

func traceVia(px *url.URL, target string, timeout time.Duration) (exitInfo, error) {
	tr := &http.Transport{Proxy: http.ProxyURL(px), DisableKeepAlives: true, TLSHandshakeTimeout: timeout}
	c := &http.Client{Transport: tr, Timeout: timeout}
	t0 := time.Now()
	resp, err := c.Get(target)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return exitInfo{}, errors.New("超时")
		}
		return exitInfo{}, errors.New(strings.TrimPrefix(err.Error(), "Get \""+target+"\": "))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	e := exitInfo{Dur: time.Since(t0)}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "ip":
			e.IP = v
		case "loc":
			e.Loc = v
		case "warp":
			e.Warp = v
		}
	}
	if e.IP == "" {
		return e, fmt.Errorf("返回内容不对（HTTP %d）", resp.StatusCode)
	}
	return e, nil
}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// sing-box 的报错去掉颜色和前缀，只留最后一行
func sbErr(s string) string {
	s = strings.TrimSpace(reANSI.ReplaceAllString(s, ""))
	ls := strings.Split(s, "\n")
	l := ls[len(ls)-1]
	if i := strings.Index(l, "] "); i >= 0 && i < 20 {
		l = l[i+2:]
	}
	return l
}

func udpBusy(p int) bool {
	c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
	if err != nil {
		return true
	}
	c.Close()
	return false
}

// WireGuard 用固定的本地 UDP 端口。WARP 入口是任播，按来源端口分到不同后端；
// 每次重启换端口，有时会落到另一台机器上，旧会话没过期前新握手一直不理，实测要等一分多钟
func pickWGPort(st *State) int {
	used := map[int]bool{}
	for _, o := range st.Outbounds {
		if p := toInt(o.Config["listen_port"]); p > 0 {
			used[p] = true
		}
	}
	if h := st.Hy2; h != nil {
		used[h.Port] = true
	}
	for i := 0; i < 100; i++ {
		p := 20000 + mrand.IntN(40000)
		if h := st.Hy2; h != nil && h.HopStart > 0 && p >= h.HopStart && p <= h.HopEnd {
			continue
		}
		if !used[p] && udpOwner(p) == "" && !udpBusy(p) {
			return p
		}
	}
	return 0
}

func setWGPort(st *State, o *Outbound) {
	if !o.Endpoint || toInt(o.Config["listen_port"]) > 0 {
		return
	}
	if p := pickWGPort(st); p > 0 {
		o.Config["listen_port"] = p
	}
}

func freeLocalPort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 20000 + int(time.Now().UnixNano()%30000)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func cloneMap(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var r map[string]any
	json.Unmarshal(b, &r)
	return r
}

// 还没保存的出站起一个临时 sing-box 来测，只听本机
func tempProxy(o *Outbound) (*url.URL, func(), error) {
	port := freeLocalPort()
	ob := cloneMap(o.Config)
	ob["tag"] = "test"
	// 固定的本地端口被正在跑的 sing-box 占着（换入口时），临时进程就用随机端口
	if lp := toInt(ob["listen_port"]); lp > 0 && udpBusy(lp) {
		delete(ob, "listen_port")
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "test"},
	}
	if o.Endpoint {
		cfg["endpoints"] = []any{ob}
	} else {
		cfg["outbounds"] = append(cfg["outbounds"].([]any), ob)
	}
	b, _ := json.Marshal(cfg)
	f := fmt.Sprintf("%s/test-%s.json", baseDir, randLabel(6))
	if err := os.WriteFile(f, b, 0600); err != nil {
		return nil, nil, err
	}
	if out, err := runOut(sbBin, "check", "-c", f); err != nil {
		os.Remove(f)
		return nil, nil, fmt.Errorf("sing-box 不认这个出站：%s", sbErr(out))
	}
	cmd := exec.Command(sbBin, "run", "-c", f)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Start(); err != nil {
		os.Remove(f)
		return nil, nil, err
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	stop := func() {
		cmd.Process.Kill()
		<-done
		os.Remove(f)
	}
	for i := 0; i < 60; i++ {
		select {
		case <-done:
			os.Remove(f)
			return nil, nil, fmt.Errorf("sing-box 起不来：%s", sbErr(buf.String()))
		default:
		}
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			return &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", port)}, stop, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	return nil, nil, errors.New("sing-box 起不来")
}

// 本机测试入口的用户名：出站名可能是中文，换成固定的 ASCII
func testUser(name string) string {
	return fmt.Sprintf("t%x", sha256.Sum256([]byte(name)))[:10]
}

// 正在跑的 sing-box 里有没有这个出站，而且配置一样
func liveOut(st *State, o *Outbound) bool {
	if st.TestPort == 0 || !svcActive(svcBox) {
		return false
	}
	b, err := os.ReadFile(sbConf)
	if err != nil {
		return false
	}
	var cfg struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return false
	}
	want := cloneMap(o.Config)
	want["tag"] = o.Name
	wb, _ := json.Marshal(want)
	for _, m := range append(cfg.Outbounds, cfg.Endpoints...) {
		if mb, _ := json.Marshal(m); bytes.Equal(mb, wb) {
			return true
		}
	}
	return false
}

// 已经在跑的出站走正在跑的 sing-box 测：同一把 WARP 密钥两个进程同时用会互相顶掉
func testOut(st *State, o *Outbound, tries int) (exitInfo, error) {
	var px *url.URL
	if liveOut(st, o) {
		px = &url.URL{Scheme: "http", User: url.UserPassword(testUser(o.Name), st.TestPass),
			Host: fmt.Sprintf("127.0.0.1:%d", st.TestPort)}
	} else {
		p, stop, err := tempProxy(o)
		if err != nil {
			return exitInfo{}, err
		}
		defer stop()
		px = p
	}
	var e exitInfo
	var err error
	for i := 0; i < tries; i++ {
		if e, err = traceVia(px, traceURL, 12*time.Second); err == nil {
			return e, nil
		}
		time.Sleep(time.Second)
	}
	return e, err
}
