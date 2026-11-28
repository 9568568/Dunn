package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var (
	initSys string // systemd / openrc
	pkgMgr  string
)

func detectOS() {
	switch {
	case have("apt-get"):
		pkgMgr = "apt"
	case have("dnf"):
		pkgMgr = "dnf"
	case have("yum"):
		pkgMgr = "yum"
	case have("apk"):
		pkgMgr = "apk"
	}
	if have("systemctl") && isDir("/run/systemd/system") {
		initSys = "systemd"
	} else if have("rc-service") {
		initSys = "openrc"
	}
}

func have(c string) bool   { _, err := exec.LookPath(c); return err == nil }
func isDir(p string) bool  { fi, err := os.Stat(p); return err == nil && fi.IsDir() }
func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func runOut(name string, args ...string) (string, error) {
	b, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func runTTY(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if ttyFile != nil {
		c.Stdin = ttyFile
	}
	return c.Run()
}

func pkgInstall(pkgs ...string) error {
	switch pkgMgr {
	case "apt":
		if exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...).Run() == nil {
			return nil
		}
		run("apt-get", "update", "-q")
		c := exec.Command("apt-get", append([]string{"install", "-y", "-q"}, pkgs...)...)
		c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		return c.Run()
	case "dnf", "yum":
		return run(pkgMgr, append([]string{"install", "-y", "-q"}, pkgs...)...)
	case "apk":
		return run("apk", append([]string{"add", "--no-cache", "-q"}, pkgs...)...)
	}
	return fmt.Errorf("不认识的包管理器")
}

// 极简系统可能没有根证书，访问 GitHub 和 CF 会失败
func ensureCA() {
	if p, err := x509.SystemCertPool(); err == nil && p != nil && !p.Equal(x509.NewCertPool()) {
		return
	}
	info("安装根证书 ca-certificates")
	pkgInstall("ca-certificates")
}

// ── 服务 ─────────────────────────────────────────────
func writeServices() {
	if initSys == "systemd" {
		box := fmt.Sprintf(`[Unit]
Description=dun sing-box
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run -c %s
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, sbBin, sbConf)
		web := fmt.Sprintf(`[Unit]
Description=dun 伪装站、订阅和证书续期
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s serve
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, selfPath)
		os.WriteFile("/etc/systemd/system/"+svcBox+".service", []byte(box), 0644)
		os.WriteFile("/etc/systemd/system/"+svcWeb+".service", []byte(web), 0644)
		run("systemctl", "daemon-reload")
		return
	}
	if initSys == "openrc" {
		// 只排在 net 后面，不用 need net：LXC 这类容器没有 networking 服务，need 会把它拉起来，起不来就连累节点
		tpl := `#!/sbin/openrc-run
name="%s"
command="%s"
command_args="%s"
supervisor=supervise-daemon
respawn_delay=3
output_log="/var/log/%s.log"
error_log="/var/log/%s.log"
depend() { after net firewall; }
`
		os.WriteFile("/etc/init.d/"+svcBox, []byte(fmt.Sprintf(tpl, svcBox, sbBin, "run -c "+sbConf, svcBox, svcBox)), 0755)
		os.WriteFile("/etc/init.d/"+svcWeb, []byte(fmt.Sprintf(tpl, svcWeb, selfPath, "serve", svcWeb, svcWeb)), 0755)
	}
}

func servicesWritten() bool {
	return exists("/etc/systemd/system/"+svcWeb+".service") || exists("/etc/init.d/"+svcWeb)
}

func svcDo(action, name string) error {
	if initSys == "systemd" {
		if action == "restart" || action == "start" {
			// 连着改几次配置会撞上 systemd 的启动频率限制（10 秒 5 次），撞上了服务就一直停着
			run("systemctl", "reset-failed", name)
		}
		return run("systemctl", action, name)
	}
	return run("rc-service", name, action)
}

func svcEnable(name string) {
	if initSys == "systemd" {
		run("systemctl", "enable", name)
	} else {
		run("rc-update", "add", name, "default")
	}
}

func svcDisable(name string) {
	if initSys == "systemd" {
		run("systemctl", "disable", "--now", name)
	} else {
		run("rc-service", name, "stop")
		run("rc-update", "del", name, "default")
	}
}

func svcActive(name string) bool {
	if initSys == "systemd" {
		return run("systemctl", "is-active", "--quiet", name) == nil
	}
	return run("rc-service", name, "status") == nil
}

func svcLog(n int, follow bool) {
	if initSys == "systemd" {
		args := []string{"-u", svcBox, "-u", svcWeb, "--no-pager", "-o", "short", "-n", strconv.Itoa(n)}
		if follow {
			args = append(args, "-f")
		}
		runTTY("journalctl", args...)
		return
	}
	args := []string{"-n", strconv.Itoa(n)}
	if follow {
		args = append(args, "-f")
	}
	runTTY("tail", append(args, "/var/log/"+svcBox+".log", "/var/log/"+svcWeb+".log")...)
}

// OpenRC 下两个服务的输出直接写 /var/log，没人轮转。超过 20MB 就只留最后 2MB，免得把小鸡的硬盘写满
func trimLogs() {
	for _, s := range []string{svcBox, svcWeb} {
		trimLog("/var/log/"+s+".log", 20<<20, 2<<20)
	}
}

func logTrimLoop() {
	for {
		time.Sleep(6 * time.Hour)
		trimLogs()
	}
}

// 原地截断，supervise-daemon 是追加写的，截完接着往末尾写
func trimLog(p string, max, keep int64) {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.Size() <= max {
		return
	}
	buf := make([]byte, keep)
	n, _ := f.ReadAt(buf, fi.Size()-keep)
	buf = buf[:n]
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	if f.Truncate(0) == nil {
		f.WriteAt(buf, 0)
	}
}

// ── 端口 ─────────────────────────────────────────────
func listenInodes(port int) []string { return sockInodes(port, false) }

// UDP 没有监听状态，未连接的套接字是 07
func sockInodes(port int, udp bool) []string {
	files, state := []string{"/proc/net/tcp", "/proc/net/tcp6"}, "0A"
	if udp {
		files, state = []string{"/proc/net/udp", "/proc/net/udp6"}, "07"
	}
	var res []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 10 || fs[3] != state {
				continue
			}
			idx := strings.LastIndex(fs[1], ":")
			if p, err := strconv.ParseUint(fs[1][idx+1:], 16, 32); err == nil && int(p) == port {
				res = append(res, fs[9])
			}
		}
	}
	return res
}

// 返回占用端口的进程名；空 = 空闲，ours = 本程序或它管的 sing-box
func portOwner(port int) string { return sockOwner(port, false) }
func udpOwner(port int) string  { return sockOwner(port, true) }

func sockOwner(port int, udp bool) string {
	inodes := sockInodes(port, udp)
	if len(inodes) == 0 {
		if udp {
			return ""
		}
		if !exists("/proc/net/tcp") {
			ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err != nil {
				return "未知进程"
			}
			ln.Close()
		}
		return ""
	}
	want := map[string]bool{}
	for _, i := range inodes {
		want["socket:["+i+"]"] = true
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		if !p.IsDir() || p.Name()[0] < '0' || p.Name()[0] > '9' {
			continue
		}
		dir := "/proc/" + p.Name()
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil || !want[l] {
				continue
			}
			cmd, _ := os.ReadFile(dir + "/cmdline")
			c := strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
			if strings.Contains(c, sbConf) || strings.HasSuffix(c, "dun serve") {
				return "ours"
			}
			if comm, _ := os.ReadFile(dir + "/comm"); len(strings.TrimSpace(string(comm))) > 0 {
				return strings.TrimSpace(string(comm))
			}
			return "未知进程"
		}
	}
	return "未知进程"
}

func (s *State) usedPorts(skip string) map[int]string {
	m := map[int]string{}
	if s.Reality != nil {
		m[s.Reality.Fallback] = "reality"
		if skip != "reality" {
			m[s.Reality.Port] = "reality"
		}
	}
	if s.AnyTLS != nil && skip != "anytls" {
		m[s.AnyTLS.Port] = "anytls"
	}
	if s.WS != nil {
		m[s.WS.Inner] = "ws"
		if skip != "ws" {
			m[s.WS.Port] = "ws"
		}
	}
	if s.TestPort > 0 {
		m[s.TestPort] = "test"
	}
	return m
}

func randPort(st *State, avoid ...int) int {
	used := st.usedPorts("")
	for _, a := range avoid {
		used[a] = "x"
	}
	for i := 0; i < 100; i++ {
		p := 20000 + rand.IntN(40000)
		if _, u := used[p]; !u && portOwner(p) == "" {
			return p
		}
	}
	die("找不到空闲端口")
	return 0
}

func curPorts(st *State, key string) (int, int) {
	switch {
	case key == "reality" && st.Reality != nil:
		return st.Reality.Port, st.Reality.PubPort
	case key == "anytls" && st.AnyTLS != nil:
		return st.AnyTLS.Port, st.AnyTLS.PubPort
	case key == "ws" && st.WS != nil:
		return st.WS.Port, st.WS.PubPort
	case key == "hy2" && st.Hy2 != nil:
		return st.Hy2.Port, st.Hy2.PubPort
	}
	return 0, 0
}

func askPort(st *State, prompt string, def int, key string) int {
	used := st.usedPorts(key)
	current, _ := curPorts(st, key)
	for {
		p := askInt(prompt, def, 1, 65535)
		if _, u := used[p]; u {
			warn("%d 已经分给本脚本的其他协议了", p)
			continue
		}
		if o := portOwner(p); o != "" && o != "ours" && p != current {
			warn("%d 被 %s 占用，换一个", p, o)
			continue
		}
		return p
	}
}

const (
	portDirect = "direct"
	portMapped = "mapped"
)

func hasLocalIP(ip string, addrs []net.Addr) bool {
	want := net.ParseIP(ip)
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && want.Equal(n.IP) {
			return true
		}
	}
	return false
}

func (st *State) hasMappedPorts() bool {
	for _, key := range []string{"reality", "anytls", "ws", "hy2"} {
		port, pub := curPorts(st, key)
		if pub > 0 && pub != port {
			return true
		}
	}
	return false
}

func selectPortMode(st *State, addrs []net.Addr) string {
	mapped := st.hasMappedPorts()
	if !mapped && st.PortMode != portMapped && (st.IP4 == "" || hasLocalIP(st.IP4, addrs)) {
		return portDirect
	}
	def := 1
	if st.PortMode == portMapped || (st.PortMode == "" && mapped) {
		def = 2
	}
	info("请选择服务商给这台机器分配端口的方式")
	info("1. 独享公网 IP，可以自行开放端口，比如绑定公网 IP 的甲骨文实例")
	info("2. 只能用服务商分配的映射端口，包括内外端口号相同的情况")
	if askInt("端口方式", def, 1, 2) == 2 {
		return portMapped
	}
	return portDirect
}

func askPubPort(st *State, p int) int {
	if st.PortMode != portDirect && st.PortMode != portMapped {
		addrs, _ := net.InterfaceAddrs()
		st.PortMode = selectPortMode(st, addrs)
	}
	if st.PortMode == portMapped {
		return askInt("  服务商分配的外网端口", p, 1, 65535)
	}
	return p
}

// ── 公网 IP ──────────────────────────────────────────
// parseTrace 从 Cloudflare trace 的正文里取 ip= 和 warp= 两行。
func parseTrace(body string) (ip, warp string) {
	for _, l := range strings.Split(body, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "ip":
			ip = v
		case "warp":
			warp = v
		}
	}
	return ip, warp
}

// tunnelExit 判断一个出口 IP 是不是隧道的出口：
// warp=on/plus 说明流量走了 WARP，落在 Cloudflare 网段里的 IP 同样是
// CF 的出口（isCFIP）。隧道出口只能出不能进，把它写进 DNS 解析、节点
// 链接，客户端连过去根本到不了这台机器，全都不通，必须丢掉。
func tunnelExit(ip, warp string) bool {
	return warp == "on" || warp == "plus" || isCFIP(ip)
}

func traceIP(network, u string) (string, bool) {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
	c := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	ip, warp := parseTrace(string(b))
	return ip, tunnelExit(ip, warp)
}

// 检测到的 IPv4 落在 Cloudflare 网段里，说明出口走了 WARP 或代理，这个地址不是本机的。
// 写进解析和链接会让节点连不上：直连协议被 CF 截获握手，CF WS 回源也指到 CF 自己。直接丢掉，按纯 IPv6 处理
func dropCFIP4(ip string) string {
	if ip != "" && isCFIP(ip) {
		return ""
	}
	return ip
}

func detectIP(st *State) {
	oldIP4 := st.IP4
	if ip, tun := traceIP("tcp4", "https://1.1.1.1/cdn-cgi/trace"); tun {
		warn("IPv4 出口走了隧道（%s），不是服务器 IP，已忽略，改用 IPv6", ip)
	} else {
		st.IP4 = ip
	}
	if ip, tun := traceIP("tcp6", "https://[2606:4700:4700::1111]/cdn-cgi/trace"); tun {
		warn("IPv6 出口走了隧道（%s），不是服务器 IP，已忽略", ip)
	} else {
		st.IP6 = ip
	}
	// 兜底：不管这个 IPv4 是刚测到的还是以前存下来的，只要落在 Cloudflare 段
	// （WARP 或代理出口），就不是机器的地址，直接丢掉，只按纯 IPv6 处理
	st.IP4 = dropCFIP4(st.IP4)
	if st.IP4 == "" && st.IP6 == "" {
		die("拿不到公网 IP，检查网络")
	}
	if oldIP4 != st.IP4 {
		st.PortMode = ""
	}
	st.save()
}

func (s *State) srvAddr() string {
	if s.IP4 != "" {
		return s.IP4
	}
	return "[" + s.IP6 + "]"
}

func listenAll() string {
	if exists("/proc/net/if_inet6") {
		return "::"
	}
	return "0.0.0.0"
}

func enableBBR() {
	cur, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if strings.TrimSpace(string(cur)) == "bbr" {
		ok("BBR 已经开着")
		return
	}
	run("modprobe", "tcp_bbr")
	f := "/etc/sysctl.d/99-dun-bbr.conf"
	os.WriteFile(f, []byte("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"), 0644)
	run("sysctl", "-p", f)
	cur, _ = os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if strings.TrimSpace(string(cur)) == "bbr" {
		ok("BBR 已开启")
		return
	}
	os.Remove(f)
	warn("这台机器开不了 BBR，内核太老或者容器不让改")
}
