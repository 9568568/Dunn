package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var (
	in      *bufio.Reader
	ttyFile *os.File
)

// 从终端读输入，curl | bash 启动时也能交互
func initTTY() {
	if f, err := os.Open("/dev/tty"); err == nil {
		ttyFile = f
		in = bufio.NewReader(f)
		return
	}
	in = bufio.NewReader(os.Stdin)
}

func ok(f string, a ...any)   { fmt.Fprintf(os.Stderr, "\033[32m✓\033[0m "+f+"\n", a...) }
func info(f string, a ...any) { fmt.Fprintf(os.Stderr, "\033[36m·\033[0m "+f+"\n", a...) }
func warn(f string, a ...any) { fmt.Fprintf(os.Stderr, "\033[33m! "+f+"\033[0m\n", a...) }
func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "\033[31m✗ "+f+"\033[0m\n", a...)
	os.Exit(1)
}
func hr() { fmt.Fprintln(os.Stderr, strings.Repeat("─", 44)) }

func ask(prompt, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", prompt, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
	}
	s, err := in.ReadString('\n')
	s = strings.TrimSpace(s)
	if err != nil && s == "" {
		fmt.Fprintln(os.Stderr)
		if def != "" {
			return def
		}
		die("输入中断")
	}
	if s == "" {
		return def
	}
	return s
}

func askSecret(prompt string) string {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	if ttyFile != nil {
		b, err := term.ReadPassword(int(ttyFile.Fd()))
		fmt.Fprintln(os.Stderr)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

func confirm(prompt string, def bool) bool {
	d := "n"
	if def {
		d = "y"
	}
	a := strings.ToLower(ask(prompt+" (y/n)", d))
	return a == "y" || a == "yes"
}

func askInt(prompt string, def, min, max int) int {
	for {
		v, err := strconv.Atoi(ask(prompt, strconv.Itoa(def)))
		if err == nil && v >= min && v <= max {
			return v
		}
		warn("请输入 %d-%d 之间的数字", min, max)
	}
}

// 列出选项，返回下标；-1 表示取消
func choose(items []string, def int) int {
	for i, s := range items {
		fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, s)
	}
	for {
		a := ask("选哪个（0 返回）", strconv.Itoa(def))
		n, err := strconv.Atoi(a)
		if err == nil && n == 0 {
			return -1
		}
		if err == nil && n >= 1 && n <= len(items) {
			return n - 1
		}
		warn("输入列表里的序号")
	}
}

func pause() {
	fmt.Fprint(os.Stderr, "按回车继续...")
	in.ReadString('\n')
}

// 终端里还有没读的输入：粘贴的内容会分好几行、好几批到
func moreInput(d time.Duration) bool {
	if in.Buffered() > 0 {
		return true
	}
	f := ttyFile
	if f == nil {
		f = os.Stdin
	}
	fds := []unix.PollFd{{Fd: int32(f.Fd()), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, int(d.Milliseconds()))
	return err == nil && n > 0
}

// 粘贴多行：好几条链接、JSON、WireGuard 配置一次读完，免得剩下的行被后面的提问吃掉
func askPaste(prompt string) string {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	var b strings.Builder
	for {
		l, err := in.ReadString('\n')
		b.WriteString(l)
		if err != nil {
			break
		}
		if moreInput(200 * time.Millisecond) {
			continue
		}
		// JSON 没粘完整、WireGuard 配置还没到 [Peer]，继续等，空行结束
		t := strings.TrimSpace(b.String())
		lt := strings.ToLower(t)
		if strings.TrimSpace(l) != "" && ((strings.HasPrefix(t, "{") && !json.Valid([]byte(t))) ||
			(strings.HasPrefix(lt, "[interface]") && !strings.Contains(lt, "endpoint"))) {
			continue
		}
		break
	}
	return strings.TrimSpace(b.String())
}
