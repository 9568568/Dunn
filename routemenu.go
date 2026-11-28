package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// ── 出站和分流的菜单、命令行 ────────────────────────────

func outLabel(name string) string {
	switch name {
	case "", "direct":
		return "直连"
	case "block":
		return "拦截"
	}
	return name
}

// 中文占两格，按显示宽度补空格才对得齐
func dispWidth(s string) int {
	w := 0
	for _, r := range s {
		if r >= 0x2e80 {
			w += 2
		} else {
			w++
		}
	}
	return w
}

func pad(s string, w int) string {
	if d := w - dispWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func ruleLine(i int, r *Rule) string {
	label := r.Label
	if label == "" {
		label = "自定义"
	}
	return fmt.Sprintf("%d. %s → %s：%s", i+1, label, outLabel(r.Out), clip(strings.Join(r.Items, ", "), 60))
}

func routeStatus(st *State) {
	if len(st.Outbounds) == 0 && len(st.Rules) == 0 {
		fmt.Fprintln(os.Stderr, "  还没有出站。先添加 WARP 或者导入一个出站，再加分流规则")
	}
	if len(st.Outbounds) > 0 {
		fmt.Fprintln(os.Stderr, "  出站：")
		nw, kw := 0, 0
		for _, o := range st.Outbounds {
			nw, kw = max(nw, dispWidth(o.Name)), max(kw, dispWidth(o.Kind))
		}
		for _, o := range st.Outbounds {
			fmt.Fprintf(os.Stderr, "    %s  %s  %s\n", pad(o.Name, nw), pad(o.Kind, kw), o.Server)
		}
	}
	if len(st.Rules) > 0 {
		fmt.Fprintln(os.Stderr, "  分流规则，从上往下匹配：")
		for i, r := range st.Rules {
			fmt.Fprintln(os.Stderr, "    "+ruleLine(i, r))
		}
	}
	if len(st.Outbounds) > 0 || len(st.Rules) > 0 {
		fmt.Fprintf(os.Stderr, "  其他流量 → %s\n", outLabel(finalOut(st)))
	}
	if !st.installed() {
		warn("还没装协议，分流要装了协议才生效")
	}
}

func routeMenu(st *State) {
	for {
		hr()
		routeStatus(st)
		i := choose([]string{"添加 WARP", "添加出站：粘贴链接，或者 IP:端口:用户:密码", "添加分流规则",
			"删除分流规则", "其他流量走哪（默认直连）", "测试出站", "删除出站"}, 1)
		switch i {
		case -1:
			return
		case 0:
			warpMenu(st)
		case 1:
			info("支持 vless、vmess、trojan、ss、hysteria2、tuic、anytls、wireguard、socks5、http 链接，")
			info("代理商给的 IP:端口:用户:密码、用户:密码@IP:端口，sing-box 的 JSON，或者 WireGuard 配置文件的路径")
			info("一次粘好几条也行")
			raw := askPaste("粘贴到这里")
			if raw == "" {
				continue
			}
			importOuts(st, raw, "", true)
		case 2:
			addRuleMenu(st)
		case 3:
			if len(st.Rules) == 0 {
				warn("还没有规则")
				continue
			}
			var ls []string
			for i, r := range st.Rules {
				ls = append(ls, strings.TrimPrefix(ruleLine(i, r), fmt.Sprintf("%d. ", i+1)))
			}
			if k := choose(ls, 1); k >= 0 {
				st.Rules = append(st.Rules[:k], st.Rules[k+1:]...)
				if commit(st) {
					ok("已删除")
				}
			}
		case 4:
			finalMenu(st)
		case 5:
			testAll(st, nil)
		case 6:
			if len(st.Outbounds) == 0 {
				warn("还没有出站")
				continue
			}
			var ls []string
			for _, o := range st.Outbounds {
				ls = append(ls, o.Name+"  "+o.Kind+"  "+o.Server)
			}
			if k := choose(ls, 1); k >= 0 && confirm("删除出站 "+st.Outbounds[k].Name+"？", false) {
				delOut(st, st.Outbounds[k].Name)
			}
		}
	}
}

// ── 出站 ─────────────────────────────────────────────

var reservedNames = map[string]bool{"direct": true, "block": true, "reject": true, "dns": true, "reality": true,
	"anytls": true, "hy2": true, "ws": true, testTag: true, "直连": true, "拦截": true}

func cleanName(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case unicode.IsSpace(r):
			b.WriteRune('-')
		case unicode.IsControl(r) || strings.ContainsRune("\"'\\:,，", r):
		default:
			b.WriteRune(r)
		}
	}
	return clip(strings.Trim(b.String(), "-"), 24)
}

func defaultName(o *Outbound) string {
	if o.Warp != nil {
		return "warp"
	}
	k := strings.ToLower(strings.Fields(o.Kind + " out")[0])
	if s, ok := map[string]string{"shadowsocks": "ss", "hysteria2": "hy2", "wireguard": "wg"}[k]; ok {
		return s
	}
	return k
}

func uniqueName(st *State, n string) string {
	if n == "" {
		n = "out"
	}
	if strings.EqualFold(n, "warp") {
		n = "warp"
	}
	cand := n
	for i := 2; findOut(st, cand) != nil || reservedNames[strings.ToLower(cand)]; i++ {
		cand = fmt.Sprintf("%s-%d", n, i)
	}
	return cand
}

func ensureTestPort(st *State) {
	if st.TestPort == 0 {
		st.TestPort = randPort(st)
	}
	if st.TestPass == "" {
		st.TestPass = randLabel(16)
	}
}

// 改动先检查，过了才保存生效；不过就把内存里的状态退回去
func commit(st *State) bool {
	if err := tryConfig(st); err != nil {
		warn("%v", err)
		*st = *loadState()
		warn("没有保存，配置还是原来的")
		return false
	}
	if !st.installed() {
		st.save()
		return true
	}
	applyAll(st)
	return true
}

// 解析、探测、测试，通过的一次性加进去，只重启一次
func importOuts(st *State, raw, name string, interactive bool) int {
	outs, errs := parseOutbounds(raw)
	for _, e := range errs {
		warn("%v", e)
	}
	var good []*Outbound
	for _, o := range outs {
		if o.Config["type"] == "auto" {
			info("%s 没写协议，连上去探一下", o.Server)
			if err := probeProxy(o); err != nil {
				warn("%v", err)
				continue
			}
			ok("是 %s 代理", o.Kind)
		}
		setWGPort(st, o)
		label := first(o.Name, o.Server)
		info("测试 %s（%s）", label, o.Kind)
		e, err := testOut(st, o, 2)
		if err != nil {
			warn("%s 不通：%v", label, err)
			if !confirm("还是加上？", false) {
				continue
			}
		} else {
			ok("通了，%s", e)
		}
		good = append(good, o)
		st.Outbounds = append(st.Outbounds, o) // 先占上，给下一个挑端口时避开
	}
	st.Outbounds = st.Outbounds[:len(st.Outbounds)-len(good)]
	if len(good) == 0 {
		return 0
	}
	for _, o := range good {
		n := o.Name
		if name != "" && len(good) == 1 {
			n = name
		}
		n = uniqueName(st, cleanName(first(n, defaultName(o))))
		if interactive && len(good) == 1 {
			n = uniqueName(st, cleanName(ask("给它起个名字，分流规则里用", n)))
		}
		o.Name = n
		st.Outbounds = append(st.Outbounds, o)
	}
	ensureTestPort(st)
	if !commit(st) {
		return 0
	}
	for _, o := range good {
		ok("已添加出站 %s（%s %s）", o.Name, o.Kind, o.Server)
	}
	info("下一步：添加分流规则，选上它")
	return len(good)
}

func delOut(st *State, name string) {
	o := findOut(st, name)
	if o == nil {
		warn("没有叫 %s 的出站", name)
		return
	}
	var keep []*Rule
	n := 0
	for _, r := range st.Rules {
		if r.Out == name {
			n++
			continue
		}
		keep = append(keep, r)
	}
	st.Rules = keep
	if st.Final == name {
		st.Final = ""
		info("其他流量改回直连")
	}
	var outs []*Outbound
	for _, x := range st.Outbounds {
		if x.Name != name {
			outs = append(outs, x)
		}
	}
	st.Outbounds = outs
	if len(outs) == 0 {
		st.TestPort, st.TestPass = 0, ""
	}
	if !commit(st) {
		return
	}
	if o.Warp != nil {
		warpUnregister(o)
	}
	if n > 0 {
		ok("已删除出站 %s，连同用到它的 %d 条规则", name, n)
	} else {
		ok("已删除出站 %s", name)
	}
}

func testAll(st *State, names []string) {
	if len(st.Outbounds) == 0 {
		warn("还没有出站")
		return
	}
	for _, o := range st.Outbounds {
		if len(names) > 0 && !contains(names, o.Name) {
			continue
		}
		fmt.Fprintf(os.Stderr, "  %-12s ", o.Name)
		if e, err := testOut(st, o, 2); err != nil {
			fmt.Fprintf(os.Stderr, "\033[33m不通：%v\033[0m\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "\033[32m通\033[0m  %s\n", e)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ── WARP ────────────────────────────────────────────

func warpOut(st *State) *Outbound {
	for _, o := range st.Outbounds {
		if o.Warp != nil {
			return o
		}
	}
	return nil
}

// 挨个入口起临时进程试，第一个能握手的留下
func warpPick(st *State, o *Outbound) bool {
	for _, hp := range warpCandidates(o, !st.ipv6Only()) {
		setWarpPeer(o, hp)
		fmt.Fprintf(os.Stderr, "  试入口 %s … ", hp)
		e, err := testOut(st, o, 1)
		if err == nil {
			fmt.Fprintf(os.Stderr, "\033[32m通了\033[0m，%s\n", e)
			return true
		}
		fmt.Fprintf(os.Stderr, "不通：%v\n", err)
	}
	setWarpPeer(o, warpCandidates(o, !st.ipv6Only())[0])
	return false
}

func addWarp(st *State, license string) bool {
	info("注册 WARP 免费账号")
	o, err := warpRegister(st.ipv6Only())
	if err != nil {
		warn("注册失败：%v", err)
		info("也可以在别处生成 WARP 账号，用「添加出站」导入 wireguard:// 链接或者 WireGuard 配置文件")
		return false
	}
	ok("注册好了")
	setWGPort(st, o)
	if license != "" {
		if err := warpBind(o, license); err != nil {
			warn("WARP+ 授权码绑定失败：%v，先用免费版", err)
		} else {
			ok("已绑定 WARP+")
		}
	}
	if !warpPick(st, o) {
		warn("几个入口都没握手成功，可能是机房封了 WARP 的 UDP")
		if !confirm("还是加上？", false) {
			warpUnregister(o)
			return false
		}
	}
	o.Name = uniqueName(st, "warp")
	st.Outbounds = append(st.Outbounds, o)
	ensureTestPort(st)
	if !commit(st) {
		warpUnregister(o)
		return false
	}
	ok("已添加出站 %s（%s，入口 %s）", o.Name, o.Kind, o.Server)
	if st.installed() {
		warpCheck(st, o)
	}
	return true
}

// sing-box 重启以后 WARP 要重新握手，确认一下真的通了
func warpCheck(st *State, o *Outbound) {
	if e, err := testOut(st, o, 4); err != nil {
		warn("WARP 暂时没通：%v。一般半分钟内会自己好，一直不通在 WARP 菜单里换个入口", err)
	} else {
		ok("WARP 已连上，%s", e)
	}
}

func warpMenu(st *State) {
	o := warpOut(st)
	if o == nil {
		if addWarp(st, "") {
			info("下一步：添加分流规则，选 %s。不知道选什么就选第 1 个 AI", warpOut(st).Name)
		}
		return
	}
	info("已经有 WARP 了：%s，入口 %s", o.Kind, o.Server)
	switch choose([]string{"测一下", "绑定 WARP+ 授权码", "换个入口", "重新注册一个账号"}, 1) {
	case 0:
		testAll(st, []string{o.Name})
	case 1:
		key := ask("WARP+ 授权码（26 位，形如 xxxxxxxx-xxxxxxxx-xxxxxxxx）", "")
		if key == "" {
			return
		}
		if err := warpBind(o, key); err != nil {
			warn("绑定失败：%v", err)
			return
		}
		st.save()
		ok("已绑定，现在是 %s", o.Kind)
	case 2:
		old := o.Server
		if !warpPick(st, o) {
			warn("几个入口都没通，入口不变")
			setWarpPeer(o, old)
			return
		}
		if commit(st) {
			warpCheck(st, o)
		}
	case 3:
		fresh, err := warpRegister(st.ipv6Only())
		if err != nil {
			warn("注册失败：%v", err)
			return
		}
		if lp := toInt(o.Config["listen_port"]); lp > 0 {
			fresh.Config["listen_port"] = lp
		}
		if !warpPick(st, fresh) {
			warn("新账号几个入口都没通，还用原来的")
			warpUnregister(fresh)
			return
		}
		fresh.Name = o.Name
		old := *o
		*o = *fresh
		if commit(st) {
			warpUnregister(&old)
			ok("已换成新账号")
			warpCheck(st, warpOut(st))
		} else {
			warpUnregister(fresh)
		}
	}
}

// ── 规则 ─────────────────────────────────────────────

// 规则指向哪：出站名、直连或者拦截
func pickTarget(st *State) string {
	var ks, ls []string
	for _, o := range st.Outbounds {
		ks, ls = append(ks, o.Name), append(ls, o.Name+"  "+o.Kind)
	}
	ks, ls = append(ks, "direct", "block"), append(ls, "直连", "拦截")
	if len(st.Outbounds) == 0 {
		info("还没有出站，规则只能选直连或拦截。要走 WARP 先添加 WARP")
	}
	info("这些流量走哪：")
	i := choose(ls, 1)
	if i < 0 {
		return ""
	}
	return ks[i]
}

const ruleHelp = `  逗号分隔，比如：geosite:openai,geosite:apple,claude.ai,tiktok
    geosite:xxx / geoip:xxx  用 MetaCubeX 的规则集
    带点的按域名后缀匹配，子域名也算；不带点的按关键词匹配
    full:x.com 只匹配这一个域名，regexp: 正则，IP 段直接写，比如 1.2.3.0/24`

func addRuleMenu(st *State) {
	out := pickTarget(st)
	if out == "" {
		return
	}
	var ls []string
	for _, p := range presets {
		ls = append(ls, p.label)
	}
	ls = append(ls, "自己填")
	for i, s := range ls {
		fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, s)
	}
	ans := ask("选规则，可以多选，用逗号隔开，比如 1,4（0 返回）", "1")
	var picks []int
	for _, x := range splitRule.Split(ans, -1) {
		n, err := strconv.Atoi(x)
		if err != nil || n < 0 || n > len(ls) {
			warn("输入列表里的序号")
			return
		}
		if n == 0 {
			return
		}
		picks = append(picks, n-1)
	}
	var add []*Rule
	for _, k := range picks {
		if k < len(presets) {
			p := presets[k]
			its, _, _ := parseItems(p.items)
			add = append(add, &Rule{Out: out, Items: itemStrings(its), Label: presetShort(p)})
			continue
		}
		fmt.Fprintln(os.Stderr, ruleHelp)
		for {
			s := askPaste("规则")
			if s == "" {
				return
			}
			its, warns, err := parseItems(s)
			for _, w := range warns {
				warn("%s", w)
			}
			if err != nil {
				warn("%v", err)
				continue
			}
			add = append(add, &Rule{Out: out, Items: itemStrings(its)})
			break
		}
	}
	addRules(st, add)
}

func presetShort(p preset) string {
	if i := strings.Index(p.label, "："); i > 0 {
		return p.label[:i]
	}
	return p.label
}

func addRules(st *State, add []*Rule) bool {
	if len(add) == 0 {
		return false
	}
	st.Rules = append(st.Rules, add...)
	if len(usedSets(st)) > 0 {
		info("下载规则集")
	}
	if !commit(st) {
		return false
	}
	for _, r := range add {
		ok("已添加：%s", strings.TrimPrefix(ruleLine(0, r), "1. "))
	}
	return true
}

func finalMenu(st *State) {
	ks, ls := []string{""}, []string{"直连（默认）"}
	for _, o := range st.Outbounds {
		ks, ls = append(ks, o.Name), append(ls, o.Name+"  "+o.Kind)
	}
	info("没匹配到规则的流量走哪：")
	i := choose(ls, 1)
	if i < 0 {
		return
	}
	setFinal(st, ks[i])
}

func setFinal(st *State, name string) {
	if name == "direct" {
		name = ""
	}
	if st.Final == name {
		ok("其他流量本来就走%s", outLabel(name))
		return
	}
	st.Final = name
	if !commit(st) {
		return
	}
	if name == "" {
		ok("其他流量走直连")
	} else {
		ok("其他流量都走 %s，速度和稳定性跟着它走", name)
	}
}

// ── 命令行 ───────────────────────────────────────────

func nonEmpty(a []string) []string {
	var r []string
	for _, s := range a {
		if strings.TrimSpace(s) != "" {
			r = append(r, s)
		}
	}
	return r
}

func warpCmd(st *State, args []string) {
	args = nonEmpty(args)
	o := warpOut(st)
	if o == nil {
		lic := ""
		if len(args) > 0 {
			lic = args[0]
		}
		addWarp(st, lic)
		return
	}
	if len(args) > 0 {
		if err := warpBind(o, args[0]); err != nil {
			die("绑定失败：%v", err)
		}
		st.save()
		ok("已绑定，现在是 %s", o.Kind)
		return
	}
	info("%s：%s，入口 %s", o.Name, o.Kind, o.Server)
	testAll(st, []string{o.Name})
}

func outCmd(st *State, args []string) {
	args = nonEmpty(args)
	if len(args) == 0 {
		routeMenu(st)
		return
	}
	switch args[0] {
	case "add":
		rest := args[1:]
		if len(rest) == 0 {
			die("用法：dun out add <链接> [名字]")
		}
		name := ""
		if len(rest) == 2 && !strings.Contains(rest[1], "://") && !strings.ContainsAny(rest[1], ":@") {
			name, rest = rest[1], rest[:1]
		}
		if importOuts(st, strings.Join(rest, "\n"), name, false) == 0 {
			os.Exit(1)
		}
	case "ls", "list":
		routeStatus(st)
	case "rm", "del":
		if len(args) < 2 {
			die("用法：dun out rm <名字>")
		}
		delOut(st, args[1])
	case "test":
		testAll(st, args[1:])
	default:
		die("用法：dun out [add|ls|rm|test]")
	}
}

func routeCmd(st *State, args []string) {
	args = nonEmpty(args)
	if len(args) == 0 {
		routeMenu(st)
		return
	}
	switch args[0] {
	case "add":
		if len(args) < 3 {
			die("用法：dun route add <出站|direct|block> <规则或预设名>")
		}
		out := args[1]
		switch strings.ToLower(out) {
		case "direct", "直连":
			out = "direct"
		case "block", "reject", "拦截":
			out = "block"
		default:
			if findOut(st, out) == nil {
				die("没有叫 %s 的出站，先 dun out ls 看看", out)
			}
		}
		spec := strings.Join(args[2:], ",")
		var add []*Rule
		toks := nonEmpty(splitRule.Split(spec, -1))
		allPreset := len(toks) > 0
		for _, t := range toks {
			allPreset = allPreset && presetByKey(t) != nil
		}
		if allPreset {
			for _, t := range toks {
				p := presetByKey(t)
				its, _, _ := parseItems(p.items)
				add = append(add, &Rule{Out: out, Items: itemStrings(its), Label: presetShort(*p)})
			}
		} else {
			its, warns, err := parseItems(spec)
			for _, w := range warns {
				warn("%s", w)
			}
			if err != nil {
				die("%v", err)
			}
			add = append(add, &Rule{Out: out, Items: itemStrings(its)})
		}
		if !addRules(st, add) {
			os.Exit(1)
		}
	case "ls", "list":
		routeStatus(st)
	case "rm", "del":
		n := 0
		if len(args) > 1 {
			n, _ = strconv.Atoi(args[1])
		}
		if n < 1 || n > len(st.Rules) {
			die("用法：dun route rm <序号>，序号看 dun route ls")
		}
		st.Rules = append(st.Rules[:n-1], st.Rules[n:]...)
		if commit(st) {
			ok("已删除第 %d 条", n)
		}
	case "final":
		if len(args) < 2 {
			die("用法：dun route final <出站|direct>")
		}
		if n := args[1]; n != "direct" && n != "直连" && findOut(st, n) == nil {
			die("没有叫 %s 的出站", n)
		}
		setFinal(st, map[bool]string{true: "", false: args[1]}[args[1] == "直连"])
	case "presets":
		for _, p := range presets {
			fmt.Printf("  %-9s %s\n           %s\n", p.key, p.label, p.items)
		}
	default:
		die("用法：dun route [add|ls|rm|final|presets]")
	}
}
