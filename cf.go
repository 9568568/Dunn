package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const cfAPI = "https://api.cloudflare.com/client/v4"

type CF struct {
	Email string `json:"email"`
	Key   string `json:"key"`
}

type cfEnv struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

var httpc = &http.Client{Timeout: 30 * time.Second}

func (c *CF) do(method, path string, body any, out any) error {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, cfAPI+path, rd)
	req.Header.Set("X-Auth-Email", c.Email)
	req.Header.Set("X-Auth-Key", c.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("连不上 Cloudflare: %v", err)
	}
	defer resp.Body.Close()
	var env cfEnv
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("HTTP %d，返回内容解析不了", resp.StatusCode)
	}
	if !env.Success {
		var ms []string
		for _, e := range env.Errors {
			ms = append(ms, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		if len(ms) == 0 {
			ms = append(ms, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return errors.New(strings.Join(ms, "; "))
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func (c *CF) Check() error { return c.do("GET", "/user", nil, nil) }

type cfZone struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	NS   []string `json:"name_servers"`
}

func (c *CF) Zones() ([]cfZone, error) {
	var z []cfZone
	err := c.do("GET", "/zones?per_page=50&status=active", nil, &z)
	return z, err
}

type cfRecord struct {
	ID string `json:"id"`
	DNSRecord
}

func (c *CF) DNSList(zid, name string) ([]cfRecord, error) {
	var r []cfRecord
	err := c.do("GET", "/zones/"+zid+"/dns_records?per_page=100&name="+url.QueryEscape(name), nil, &r)
	return r, err
}

func (c *CF) DNSCreate(zid string, rec DNSRecord) (string, error) {
	var r cfRecord
	err := c.do("POST", "/zones/"+zid+"/dns_records", rec, &r)
	return r.ID, err
}

func (c *CF) DNSDelete(zid, id string) error {
	return c.do("DELETE", "/zones/"+zid+"/dns_records/"+id, nil, nil)
}

// 规则集原样读出来，只增删自己那条，别人的规则不碰
func (c *CF) RulesGet(zid, phase string) ([]map[string]any, error) {
	var r struct {
		Rules []map[string]any `json:"rules"`
	}
	err := c.do("GET", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", nil, &r)
	if err != nil {
		if strings.Contains(err.Error(), "10003") || strings.Contains(err.Error(), "not find") || strings.Contains(err.Error(), "HTTP 404") {
			return nil, nil
		}
		return nil, err
	}
	return r.Rules, nil
}

func (c *CF) rulesEdit(zid, phase, desc string, add map[string]any) error {
	rules, err := c.RulesGet(zid, phase)
	if err != nil {
		return err
	}
	kept := []map[string]any{}
	found := false
	for _, r := range rules {
		if d, _ := r["description"].(string); d == desc {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if add == nil && !found {
		return nil
	}
	if add != nil {
		kept = append(kept, add)
	}
	return c.do("PUT", "/zones/"+zid+"/rulesets/phases/"+phase+"/entrypoint", map[string]any{"rules": kept}, nil)
}

func (c *CF) RuleUpsert(zid, phase, desc string, rule map[string]any) error {
	rule["description"] = desc
	rule["enabled"] = true
	return c.rulesEdit(zid, phase, desc, rule)
}

func (c *CF) RuleRemove(zid, phase, desc string) error { return c.rulesEdit(zid, phase, desc, nil) }

func (c *CF) Setting(zid, name string) string {
	var r struct {
		Value any `json:"value"`
	}
	if c.do("GET", "/zones/"+zid+"/settings/"+name, nil, &r) != nil {
		return ""
	}
	return fmt.Sprint(r.Value)
}

func (c *CF) SetSetting(zid, name string, v any) error {
	return c.do("PATCH", "/zones/"+zid+"/settings/"+name, map[string]any{"value": v}, nil)
}

// ── 凭据 ─────────────────────────────────────────────
var cfCur *CF

func cfLoad() *CF {
	b, err := os.ReadFile(cfPath)
	if err != nil {
		return nil
	}
	c := &CF{}
	if json.Unmarshal(b, c) != nil || c.Email == "" || c.Key == "" {
		return nil
	}
	return c
}

func cfLogin() *CF {
	if cfCur != nil {
		return cfCur
	}
	if c := cfLoad(); c != nil {
		if err := c.Check(); err == nil {
			cfCur = c
			return c
		}
		warn("保存的 CF 账号验证不过了，重新输入一次")
	}
	fmt.Fprintln(os.Stderr)
	info("需要 Cloudflare 账号邮箱和 Global API Key")
	info("Key 在 CF 后台右上角头像 → 我的个人资料 → API 令牌 → Global API Key → 查看")
	for {
		c := &CF{Email: ask("CF 登录邮箱", ""), Key: askSecret("Global API Key（输入时不显示）")}
		if c.Email == "" || c.Key == "" {
			warn("不能为空")
			continue
		}
		if err := c.Check(); err != nil {
			warn("验证失败：%v。再来一次（Ctrl+C 退出）", err)
			continue
		}
		b, _ := json.Marshal(c)
		writeFileAtomic(cfPath, b, 0600)
		ok("CF 账号验证通过")
		cfCur = c
		return c
	}
}
