package main

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// 半格字符画二维码，强制白底黑字，深浅色终端都能扫
func printQR(s string) {
	c, err := qr.Encode(s, qr.L)
	if err != nil {
		return
	}
	n := c.Size
	light := func(x, y int) bool {
		if x < 0 || y < 0 || x >= n || y >= n {
			return true
		}
		return !c.Black(x, y)
	}
	var b strings.Builder
	for y := -1; y < n+1; y += 2 {
		b.WriteString("\033[40;37m")
		for x := -1; x < n+1; x++ {
			t, u := light(x, y), light(x, y+1)
			switch {
			case t && u:
				b.WriteString("█")
			case t:
				b.WriteString("▀")
			case u:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\033[0m\n")
	}
	fmt.Print(b.String())
}
