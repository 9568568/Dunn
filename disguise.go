package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
)

// 伪装登录页按每台机器的种子随机生成：文案、配色、类名、接口路径、报错都不一样，
// 免得 dun 用的人多了，这一页本身变成指纹
type loginPage struct {
	html     []byte
	endpoint string
	status   int
	body     []byte
}

func pick[T any](r *rand.Rand, xs ...T) T { return xs[r.IntN(len(xs))] }

func randIdent(r *rand.Rand) string {
	const cs = "abcdefghijklmnopqrstuvwxyz"
	n := 3 + r.IntN(5)
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[r.IntN(len(cs))]
	}
	return string(b)
}

func buildLogin(seed uint64) *loginPage {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	brand := pick(r, "Console", "Admin Console", "Control Panel", "Management Portal", "Dashboard",
		"Operations Center", "Cloud Portal", "Workspace", "Service Portal", "Admin", "Monitoring", "Gateway")
	heading := pick(r, "Sign in", "Log in", "Welcome back", "Sign in to "+brand, "Account login", brand)
	sub := pick(r, "Enter your credentials to access the console.", "Please sign in to continue.",
		"Use your account to continue.", "Authorized personnel only.", "Sign in with your administrator account.",
		"Sign in to manage your services.")
	btn := pick(r, "Sign in", "Log in", "Continue", "Sign in securely")
	accent := pick(r, "#2f5bea", "#1f6feb", "#0f766e", "#7c3aed", "#c2410c", "#0e7490", "#4338ca", "#15803d", "#be123c", "#334155")
	fg := pick(r, "#1d2433", "#111827", "#1f2937", "#18181b", "#0f172a")
	bg := pick(r, "#f4f6f9", "#f5f5f4", "#f3f4f6", "#f8fafc", "#eef2f7", "#fafafa")
	errMsg := pick(r, "Invalid username or password", "Incorrect username or password.", "Authentication failed",
		"The credentials you entered are incorrect.", "Login failed. Please check your credentials.")
	errKey := pick(r, "message", "msg", "error", "detail")
	status := pick(r, 401, 401, 403, 400)
	icons := []string{
		`<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>`,
		`<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>`,
		`<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3"/>`,
		`<rect x="4" y="4" width="7" height="7" rx="1"/><rect x="13" y="4" width="7" height="7" rx="1"/><rect x="4" y="13" width="7" height="7" rx="1"/><rect x="13" y="13" width="7" height="7" rx="1"/>`,
		`<path d="M4 17l6-6-6-6M12 19h8"/>`,
		`<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>`,
	}
	center := r.IntN(3) == 0
	align, markM := "left", "0"
	if center {
		align, markM = "center", "auto"
	}
	radius := 6 + r.IntN(9)
	ids := map[string]string{}
	for _, k := range []string{"F", "E", "U", "P", "G", "B", "Y"} {
		ids[k] = randIdent(r)
	}
	year := `&copy; <span id="` + ids["Y"] + `"></span>`
	footer := pick(r, year+" All rights reserved.", year+" "+brand, "Need help? Contact your administrator.", "", year)
	unames := pick(r, "username", "user", "account", "email", "login")
	ulabel := pick(r, "Username", "Email", "Email address", "Account", "User ID", "Username or email")
	rep := []string{
		"__TITLE__", pick(r, "Sign in", "Login", brand, brand+" - Sign in", "Sign in · "+brand),
		"__FG__", fg, "__BG__", bg, "__ACCENT__", accent, "__LINE__", pick(r, "#dfe3ea", "#e5e7eb", "#e4e4e7", "#d9dee7"),
		"__ACCENTA__", accent + "1f",
		"__FONT__", pick(r, `-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif`,
			`system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif`,
			`Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif`),
		"__WIDTH__", fmt.Sprint(340 + r.IntN(70)), "__RADIUS__", fmt.Sprint(radius), "__IRADIUS__", fmt.Sprint(max(3, radius-4)),
		"__ALIGN__", align, "__MARKM__", markM, "__MARKR__", pick(r, "8px", "50%", "10px", "6px"),
		"__MARKD__", pick(r, "flex", "flex", "flex", "none"),
		"__ROWD__", pick(r, "flex", "flex", "none"), "__BTNM__", fmt.Sprint(r.IntN(2) * 8),
		"__BTNBG__", pick(r, "var(--fg)", "var(--accent)"),
		"__ICON__", pick(r, icons...), "__HEADING__", heading, "__SUB__", sub,
		"__ULABEL__", ulabel, "__UNAME__", unames, "__PLABEL__", pick(r, "Password", "Password", "Passphrase"),
		"__REMEMBER__", pick(r, "Remember me", "Keep me signed in", "Stay signed in"),
		"__FORGOT__", pick(r, "Forgot password?", "Reset password", "Can't sign in?"),
		"__FORGOTMSG__", pick(r, "Please contact your administrator to reset your password.",
			"Password reset is managed by your administrator.", "Contact support to recover your account."),
		"__EMPTYMSG__", pick(r, "Please enter your username and password.", "Both fields are required.",
			"Please fill in all fields."),
		"__BTN__", btn, "__BUSY__", pick(r, "Signing in\\u2026", "Please wait\\u2026", "Verifying\\u2026"),
		"__ENDPOINT__", "", // 下面补
		"__LOCKN__", fmt.Sprint(3 + r.IntN(4)),
		"__LOCKMSG__", pick(r, "Too many failed attempts. Please try again later.",
			"Your account is temporarily locked. Try again in a few minutes.", "Too many attempts. Please wait and try again."),
		"__ERRKEY__", errKey, "__ERRMSG__", errMsg, "__FOOTER__", footer,
	}
	endpoint := pick(r, "/api/login", "/api/auth/login", "/login", "/api/v1/session", "/auth/signin",
		"/api/user/login", "/session", "/api/v2/auth")
	for i := range rep {
		if rep[i] == "__ENDPOINT__" {
			rep[i+1] = endpoint
		}
	}
	for _, k := range []string{"BOX", "CARD", "MARK", "SUB", "FIELD", "ROW", "ERR"} {
		rep = append(rep, "__C_"+k+"__", randIdent(r))
	}
	for k, v := range ids {
		rep = append(rep, "__ID_"+k+"__", v)
	}
	html := strings.NewReplacer(rep...).Replace(string(loginHTML))
	body, _ := json.Marshal(map[string]any{errKey: errMsg, "code": status})
	return &loginPage{html: []byte(html), endpoint: endpoint, status: status, body: body}
}
