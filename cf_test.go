package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type cfTransport func(*http.Request) (*http.Response, error)

func (f cfTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func mockCF(t *testing.T, f cfTransport) {
	t.Helper()
	old := httpc
	httpc = &http.Client{Transport: f}
	t.Cleanup(func() { httpc = old })
}

func cfResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestCFCredentials(t *testing.T) {
	for _, tc := range []struct{ name, stored, path, token string }{
		{"原有 Key 配置", `{"email":"test@example.org","key":"test-key"}`, "/user", ""},
		{"限定域名的 Token", `{"token":"test-token"}`, "/zones", "Bearer test-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c CF
			if err := json.Unmarshal([]byte(tc.stored), &c); err != nil || !c.valid() {
				t.Fatal("读取凭据失败")
			}
			mockCF(t, func(req *http.Request) (*http.Response, error) {
				if tc.token != req.Header.Get("Authorization") || c.Email != req.Header.Get("X-Auth-Email") || c.Key != req.Header.Get("X-Auth-Key") {
					t.Fatal("鉴权请求头错误")
				}
				if req.URL.Path != "/client/v4"+tc.path {
					t.Fatalf("验证路径错误：%s", req.URL.Path)
				}
				return cfResponse(200, `{"success":true,"result":[{"id":"test-zone"}]}`), nil
			})
			if err := c.Check(); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(c)
			if err != nil || string(data) != tc.stored {
				t.Fatal("凭据保存格式错误")
			}
		})
	}
}

func TestCFTokenScope(t *testing.T) {
	c := &CF{Token: "test-token"}
	mockCF(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/client/v4/zones":
			return cfResponse(200, `{"success":true,"result":[]}`), nil
		case "/client/v4/zones/z/rulesets/phases/http_request_origin/entrypoint":
			return cfResponse(403, `{"success":false,"errors":[{"code":10003,"message":"permission denied"}]}`), nil
		default:
			return cfResponse(404, `{"success":false,"errors":[{"message":"entrypoint not found"}]}`), nil
		}
	})
	if c.Check() == nil {
		t.Error("应拒绝看不到域名的 Token")
	}
	if _, err := c.RulesGet("z", "http_request_origin"); err == nil {
		t.Error("权限错误被当成空规则集")
	}
	if _, err := c.RulesGet("z", "http_config_settings"); err != nil {
		t.Errorf("规则集尚未创建：%v", err)
	}
}

func TestCFErrorHint(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		c          *CF
		want       []string
	}{
		{"Key 栏贴了 Token", `{"success":false,"errors":[{"code":6003,"message":"Invalid request headers","error_chain":[{"code":6103,"message":"Invalid format for X-Auth-Key header"}]}]}`,
			&CF{Email: "a@example.org", Key: "x"}, []string{"6003 Invalid request headers，具体是 6103 Invalid format for X-Auth-Key header", "37 位", "选 2"}},
		{"邮箱格式不对", `{"success":false,"errors":[{"code":6003,"message":"Invalid request headers","error_chain":[{"code":6102,"message":"Invalid format for X-Auth-Email header"}]}]}`,
			&CF{Email: "a", Key: "x"}, []string{"6102", "登录邮箱"}},
		{"Token 缺 DNS 权限", `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`,
			&CF{Token: "t"}, []string{"10000 Authentication error", "DNS Edit"}},
		{"Token 无效", `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`,
			&CF{Token: "t"}, []string{"9109", "没被删除"}},
		{"没见过的码原样给", `{"success":false,"errors":[{"code":7003,"message":"Could not route"}]}`,
			&CF{Token: "t"}, []string{"7003 Could not route"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockCF(t, func(*http.Request) (*http.Response, error) { return cfResponse(400, tc.body), nil })
			err := tc.c.do("GET", "/zones", nil, nil)
			if err == nil {
				t.Fatal("应该报错")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("报错 %q 里没有 %q", err, w)
				}
			}
			if tc.name == "没见过的码原样给" && strings.Contains(err.Error(), "。") {
				t.Fatalf("不该带提示：%q", err)
			}
		})
	}
}

func TestCFKeyAsToken(t *testing.T) {
	calls := 0
	mockCF(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Header.Get("Authorization") != "Bearer abcdefghijABCDEFGHIJ0123456789_-abcdefg" {
			return cfResponse(400, `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}`), nil
		}
		return cfResponse(200, `{"success":true,"result":[{"id":"z","name":"example.org"}]}`), nil
	})
	key := strings.Repeat("0123456789abcdef", 3)[:37]
	if c, switched := cfKeyAsToken(&CF{Email: "a@example.org", Key: key}); switched || c.Key != key || calls != 0 {
		t.Fatal("37 位的 Key 不该当成 Token")
	}
	c, switched := cfKeyAsToken(&CF{Email: "a@example.org", Key: "abcdefghijABCDEFGHIJ0123456789_-abcdefg"})
	if !switched || c.Token == "" || c.Key != "" || c.Email != "" {
		t.Fatalf("Key 栏里的 Token 没认出来：%+v", c)
	}
	if _, switched := cfKeyAsToken(&CF{Email: "a@example.org", Key: "0123"}); switched {
		t.Fatal("验证不过的不该当成 Token")
	}
	if !reGlobalKey.MatchString(key) || reGlobalKey.MatchString(key+"0") || reGlobalKey.MatchString("abcdefghijABCDEFGHIJ0123456789_-abcdefg") {
		t.Fatal("Global API Key 格式判断不对")
	}
}
