package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ── 规则条目 ─────────────────────────────────────────
// 写法和 Xray、3x-ui 的路由规则一样，逗号分隔：
//   geosite:openai   geoip:telegram     规则集（MetaCubeX 的 geosite / geoip）
//   claude.ai        带点的按域名后缀匹配，子域名也算
//   tiktok           不带点的按关键词匹配
//   full:x.com  domain:cn  keyword:a.b  regexp:…   显式指定
//   1.2.3.0/24       IP 段
//   ipv4 / ipv6      目标只有 IPv4（IPv6）地址的流量

type ruleItem struct{ kind, val string }

func (it ruleItem) String() string {
	switch it.kind {
	case "geosite", "geoip", "full", "regexp":
		return it.kind + ":" + it.val
	case "suffix":
		if strings.Contains(it.val, ".") {
			return it.val
		}
		return "domain:" + it.val
	case "keyword":
		if strings.Contains(it.val, ".") {
			return "keyword:" + it.val
		}
		return it.val
	case "ipv4", "ipv6":
		return it.kind
	}
	return it.val // ip
}

var (
	reSetName = regexp.MustCompile(`^[a-z0-9][a-z0-9!@._-]*$`)
	reDomain  = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$`)
	splitRule = regexp.MustCompile(`[,，、;；\s]+`)
)

var prefixKinds = map[string]string{
	"geosite": "geosite", "geoip": "geoip",
	"domain": "suffix", "suffix": "suffix", "domain-suffix": "suffix", "domain_suffix": "suffix", "host-suffix": "suffix",
	"full": "full", "domain-full": "full",
	"keyword": "keyword", "domain-keyword": "keyword", "domain_keyword": "keyword",
	"regexp": "regexp", "regex": "regexp", "domain-regex": "regexp", "domain_regex": "regexp",
	"ip": "ip", "ip-cidr": "ip", "ip-cidr6": "ip", "ipcidr": "ip", "cidr": "ip",
}

// Clash 规则里的类型名，被逗号拆开以后会单独冒出来
var clashWords = map[string]bool{"domain": true, "domain-suffix": true, "domain-keyword": true, "domain-regex": true,
	"ip-cidr": true, "ip-cidr6": true, "geosite": true, "geoip": true, "match": true, "rule-set": true, "no-resolve": true}

// 编辑距离，两个字母对调算一次（geostie、goeip 这类笔误）
func lev(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

func parseItems(s string) ([]ruleItem, []string, error) {
	var items []ruleItem
	var warns []string
	seen := map[string]bool{}
	add := func(it ruleItem) {
		if k := it.String(); !seen[k] {
			seen[k] = true
			items = append(items, it)
		}
	}
	for _, tok := range splitRule.Split(s, -1) {
		tok = strings.Trim(tok, "\"'`[]")
		if tok == "" {
			continue
		}
		// 直接贴了网址，只要域名
		if strings.Contains(tok, "://") {
			if u, err := url.Parse(tok); err == nil && u.Hostname() != "" {
				tok = u.Hostname()
			}
		}
		low := strings.ToLower(tok)
		if low == "ipv4" || low == "ipv6" {
			add(ruleItem{kind: low})
			continue
		}
		if n, ok := parseCIDR(tok); ok {
			add(ruleItem{"ip", n})
			continue
		}
		if i := strings.Index(low, ":"); i > 0 {
			pre, val := low[:i], strings.TrimSpace(tok[i+1:])
			kind := prefixKinds[pre]
			if kind == "" {
				switch {
				case pre == "ext":
					return nil, warns, fmt.Errorf("%s：ext: 外部规则文件不支持，换成 geosite: 或者直接写域名", tok)
				case pre[0] == 'g' && lev(pre, "geosite") <= 2:
					kind = "geosite"
					warns = append(warns, fmt.Sprintf("%s: 当成 geosite: 了", pre))
				case pre[0] == 'g' && lev(pre, "geoip") <= 1:
					kind = "geoip"
					warns = append(warns, fmt.Sprintf("%s: 当成 geoip: 了", pre))
				default:
					return nil, warns, fmt.Errorf("%s：不认识 %s: 这个前缀", tok, pre)
				}
			}
			if kind != "regexp" {
				val = strings.ToLower(val)
			}
			switch kind {
			case "geosite", "geoip":
				if !reSetName.MatchString(val) {
					return nil, warns, fmt.Errorf("%s：分类名不对", tok)
				}
			case "suffix", "full":
				val = strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(val, "*."), "+."), ".")
				if !reDomain.MatchString(val) {
					return nil, warns, fmt.Errorf("%s：域名不对", tok)
				}
			case "keyword":
				if val == "" {
					return nil, warns, fmt.Errorf("%s：关键词是空的", tok)
				}
			case "regexp":
				if _, err := regexp.Compile(val); err != nil {
					return nil, warns, fmt.Errorf("%s：正则写错了：%v", tok, err)
				}
			case "ip":
				n, ok := parseCIDR(val)
				if !ok {
					return nil, warns, fmt.Errorf("%s：IP 段不对", tok)
				}
				val = n
			}
			add(ruleItem{kind, val})
			continue
		}
		if clashWords[low] {
			warns = append(warns, fmt.Sprintf("%s 像是 Clash 规则的写法，跳过了", tok))
			continue
		}
		if strings.Contains(low, ".") {
			d := strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(low, "*."), "+."), ".")
			if strings.Contains(d, "*") {
				return nil, warns, fmt.Errorf("%s：通配符只支持写在开头，比如 *.example.com", tok)
			}
			if !reDomain.MatchString(d) {
				return nil, warns, fmt.Errorf("%s：域名不对", tok)
			}
			add(ruleItem{"suffix", d})
			continue
		}
		add(ruleItem{"keyword", low})
	}
	if len(items) == 0 {
		return nil, warns, errors.New("没有填规则")
	}
	return items, warns, nil
}

func parseCIDR(s string) (string, bool) {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return "", false
		}
		return n.String(), true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", false
	}
	if ip.To4() != nil {
		return ip.String() + "/32", true
	}
	return ip.String() + "/128", true
}

func itemStrings(its []ruleItem) []string {
	var r []string
	for _, it := range its {
		r = append(r, it.String())
	}
	return r
}

// ── 预设 ─────────────────────────────────────────────

type preset struct{ key, label, items string }

var presets = []preset{
	{"ai", "AI：ChatGPT、Claude、Gemini 等", "geosite:category-ai-!cn,apis.google.com,colab,developerprofiles"},
	{"google", "Google：解决人机验证和送中", "geosite:google"},
	{"youtube", "YouTube", "geosite:youtube"},
	{"stream", "流媒体：Netflix、Disney+、HBO、Prime Video、Hulu", "geosite:netflix,geosite:disney,geosite:hbo,geosite:primevideo,geosite:hulu"},
	{"tiktok", "TikTok", "geosite:tiktok"},
	{"telegram", "Telegram", "geosite:telegram,geoip:telegram"},
	{"cn", "国内网站和 IP：一般配「拦截」，免得节点被拿去回国", "geosite:cn,geoip:cn"},
	{"ads", "广告和跟踪：一般配「拦截」", "geosite:category-ads-all"},
	{"ipv4", "IPv4 流量：纯 IPv6 机器配 WARP，就能上只有 IPv4 的网站", "ipv4"},
	{"ipv6", "IPv6 流量：纯 IPv4 机器配 WARP，就能上只有 IPv6 的网站", "ipv6"},
}

func presetByKey(k string) *preset {
	for i := range presets {
		if presets[i].key == strings.ToLower(k) {
			return &presets[i]
		}
	}
	return nil
}

// ── 编译成 sing-box 的路由 ─────────────────────────────

type matcher struct {
	domain, suffix, keyword, regex, cidr, sites, ips []string
	v4, v6                                           bool
}

func compileRule(r *Rule) matcher {
	var m matcher
	its, _, _ := parseItems(strings.Join(r.Items, ","))
	for _, it := range its {
		switch it.kind {
		case "geosite":
			m.sites = append(m.sites, it.val)
		case "geoip":
			m.ips = append(m.ips, it.val)
		case "suffix":
			m.suffix = append(m.suffix, it.val)
		case "keyword":
			m.keyword = append(m.keyword, it.val)
		case "full":
			m.domain = append(m.domain, it.val)
		case "regexp":
			m.regex = append(m.regex, it.val)
		case "ip":
			m.cidr = append(m.cidr, it.val)
		case "ipv4":
			m.v4 = true
		case "ipv6":
			m.v6 = true
		}
	}
	return m
}

func findOut(st *State, name string) *Outbound {
	for _, o := range st.Outbounds {
		if o.Name == name {
			return o
		}
	}
	return nil
}

// 规则指向的出站；被删掉的出站返回 nil
func ruleTarget(st *State, out string) map[string]any {
	switch out {
	case "direct":
		return map[string]any{"outbound": "direct"}
	case "block":
		return map[string]any{"action": "reject"}
	}
	if findOut(st, out) != nil {
		return map[string]any{"outbound": out}
	}
	return nil
}

func withTarget(r, t map[string]any) map[string]any {
	for k, v := range t {
		r[k] = v
	}
	return r
}

// 先按域名匹配；有 IP 类规则时再解析一次域名，按 IP 匹配
func routeRules(st *State) (rules []any, sets []any) {
	type cr struct {
		m matcher
		t map[string]any
	}
	var crs []cr
	usedSet := map[string]bool{}
	var setTags []string
	needResolve, wantV4, wantV6 := false, false, false
	for _, r := range st.Rules {
		t := ruleTarget(st, r.Out)
		if t == nil {
			continue
		}
		m := compileRule(r)
		crs = append(crs, cr{m, t})
		for _, s := range m.sites {
			if tag := "geosite-" + s; !usedSet[tag] {
				usedSet[tag] = true
				setTags = append(setTags, tag)
			}
		}
		for _, s := range m.ips {
			if tag := "geoip-" + s; !usedSet[tag] {
				usedSet[tag] = true
				setTags = append(setTags, tag)
			}
		}
		if len(m.cidr) > 0 || len(m.ips) > 0 || m.v4 || m.v6 {
			needResolve = true
		}
		wantV4 = wantV4 || m.v4
		wantV6 = wantV6 || m.v6
	}
	for _, c := range crs {
		r := map[string]any{}
		for k, v := range map[string][]string{"domain": c.m.domain, "domain_suffix": c.m.suffix,
			"domain_keyword": c.m.keyword, "domain_regex": c.m.regex, "ip_cidr": c.m.cidr} {
			if len(v) > 0 {
				r[k] = v
			}
		}
		var rs []string
		for _, s := range c.m.sites {
			rs = append(rs, "geosite-"+s)
		}
		for _, s := range c.m.ips {
			rs = append(rs, "geoip-"+s)
		}
		if len(rs) > 0 {
			r["rule_set"] = rs
		}
		if len(r) > 0 {
			rules = append(rules, withTarget(r, c.t))
		}
	}
	if needResolve {
		strategy := "prefer_ipv4"
		if wantV4 || (st.IP4 == "" && !wantV6) {
			strategy = "prefer_ipv6"
		}
		rules = append(rules, map[string]any{"action": "resolve", "strategy": strategy},
			map[string]any{"ip_is_private": true, "action": "reject"})
		for _, c := range crs {
			r := map[string]any{}
			if len(c.m.cidr) > 0 {
				r["ip_cidr"] = c.m.cidr
			}
			var rs []string
			for _, s := range c.m.ips {
				rs = append(rs, "geoip-"+s)
			}
			if len(rs) > 0 {
				r["rule_set"] = rs
			}
			if len(r) > 0 {
				rules = append(rules, withTarget(r, c.t))
			}
		}
		// 目标一个 IPv6 地址都没有 = 只有 IPv4
		for _, c := range crs {
			if c.m.v4 {
				rules = append(rules, withTarget(map[string]any{"ip_cidr": []string{"::/0"}, "invert": true}, c.t))
			}
			if c.m.v6 {
				rules = append(rules, withTarget(map[string]any{"ip_cidr": []string{"0.0.0.0/0"}, "invert": true}, c.t))
			}
		}
	}
	for _, tag := range setTags {
		kind, name, _ := strings.Cut(tag, "-")
		sets = append(sets, map[string]any{"type": "local", "tag": tag, "format": "binary", "path": ruleFile(kind, name)})
	}
	return rules, sets
}

func finalOut(st *State) string {
	if st.Final != "" && findOut(st, st.Final) != nil {
		return st.Final
	}
	return "direct"
}

// ── 规则集文件 ───────────────────────────────────────
// sing-box 1.12 起不再内置 geosite，规则集由 dun 下载到本地，dun 服务每天刷新；
// 文件一换 sing-box 自己会重新加载，不用重启

var ruleSrcs = []string{
	"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/%s/%s.srs",
	"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/%s/%s.srs",
}

func ruleFile(kind, name string) string { return rulesDir + "/" + kind + "-" + name + ".srs" }

func fetchRuleSet(kind, name string) (bool, error) {
	var last error
	notFound := 0
	c := &http.Client{Timeout: 60 * time.Second}
	for _, src := range ruleSrcs {
		resp, err := c.Get(fmt.Sprintf(src, kind, url.PathEscape(name)))
		if err != nil {
			last = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 404:
			notFound++
			last = errors.New("HTTP 404")
			continue
		case resp.StatusCode != 200 || err != nil:
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		case len(b) < 4 || string(b[:3]) != "SRS":
			last = errors.New("下载到的不是规则集文件")
			continue
		}
		f := ruleFile(kind, name)
		if old, err := os.ReadFile(f); err == nil && bytes.Equal(old, b) {
			now := time.Now()
			os.Chtimes(f, now, now)
			return false, nil
		}
		if err := writeFileAtomic(f, b, 0644); err != nil {
			return false, err
		}
		return true, nil
	}
	if notFound == len(ruleSrcs) {
		return false, fmt.Errorf("没有 %s:%s 这个分类", kind, name)
	}
	return false, fmt.Errorf("%s:%s 下载失败：%v", kind, name, last)
}

func usedSets(st *State) [][2]string {
	var r [][2]string
	seen := map[string]bool{}
	for _, rl := range st.Rules {
		m := compileRule(rl)
		for _, s := range m.sites {
			if !seen["geosite-"+s] {
				seen["geosite-"+s] = true
				r = append(r, [2]string{"geosite", s})
			}
		}
		for _, s := range m.ips {
			if !seen["geoip-"+s] {
				seen["geoip-"+s] = true
				r = append(r, [2]string{"geoip", s})
			}
		}
	}
	return r
}

// 缺的规则集补下载
func ensureRuleSets(st *State) error {
	var errs []string
	for _, s := range usedSets(st) {
		if exists(ruleFile(s[0], s[1])) {
			continue
		}
		os.MkdirAll(rulesDir, 0755)
		if _, err := fetchRuleSet(s[0], s[1]); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "；"))
	}
	return nil
}

// 配置生效以后再删用不到的，检查失败退回旧配置时文件还在
func cleanRuleSets(st *State) {
	keep := map[string]bool{}
	for _, s := range usedSets(st) {
		keep[filepath.Base(ruleFile(s[0], s[1]))] = true
	}
	fs, err := os.ReadDir(rulesDir)
	if err != nil {
		return
	}
	for _, f := range fs {
		if !keep[f.Name()] {
			os.Remove(filepath.Join(rulesDir, f.Name()))
		}
	}
	if len(keep) == 0 {
		os.Remove(rulesDir)
	}
}

// 超过 maxAge 的重新下载，返回有变化的个数
func refreshRuleSets(st *State, maxAge time.Duration) (int, error) {
	n := 0
	var errs []string
	for _, s := range usedSets(st) {
		f := ruleFile(s[0], s[1])
		if fi, err := os.Stat(f); err == nil && time.Since(fi.ModTime()) < maxAge {
			continue
		}
		changed, err := fetchRuleSet(s[0], s[1])
		if err != nil {
			errs = append(errs, err.Error())
		} else if changed {
			n++
		}
	}
	if len(errs) > 0 {
		return n, errors.New(strings.Join(errs, "；"))
	}
	return n, nil
}
