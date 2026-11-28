#!/bin/sh
# dun 一键安装：下载对应架构的二进制，然后打开菜单。sh、bash 都能跑，没有 curl 就用 wget
# 注意：GitHub 没有 IPv6 地址，纯 IPv6 的机器靠 NAT64/DNS64 或 WARP
# （IPv4 出口）才能连上它；下载不通会改用 IPv6 再试一次。
set -e
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
mkdir -p /usr/local/bin
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "暂不支持 $(uname -m)"; exit 1 ;;
esac
url="https://github.com/9568568/Dunn/releases/latest/download/dun-linux-$arch"
# 装前检测：先看 GitHub 通不通。纯 IPv6 又没有 NAT64/WARP 的机器，
# 在这一步就会失败；先明说原因，比让下载报一串看不懂的错强。
if command -v curl >/dev/null 2>&1; then
    probe_rc=0
    curl -sSI --connect-timeout 10 --max-time 15 https://github.com -o /dev/null 2>/dev/null || probe_rc=$?
    if [ "$probe_rc" -ne 0 ]; then
        if [ "$probe_rc" -eq 6 ]; then
            echo "域名 github.com 解析失败，装不下去。"
        else
            echo "GitHub 连不上，装不下去（curl 退出码 $probe_rc）。"
        fi
        echo "GitHub（github.com）没有 IPv6 地址：纯 IPv6 的机器要靠 NAT64/DNS64"
        echo "或者先跑通 WARP（IPv4 出口）才能连上它。确认一种再重跑，"
        echo "或者在别的机器上把 dun-linux-$arch 下好，传到这台的 /usr/local/bin/dun。"
        exit 1
    fi
fi
echo "下载 dun ($arch)"
# curl 自己选 IPv4/IPv6；github.com 没有 IPv6 地址，纯 IPv6 的机器靠 NAT64/DNS64
# 或 WARP（IPv4 出口）才能连上，前面探针已经验过，不通前面就退出了。
# 这里不用 -6 强制重试：github.com 本来就没有 AAAA，强制 IPv6 永远下不到东西。
if command -v curl >/dev/null 2>&1; then
    if ! curl -fL --retry 2 --connect-timeout 15 --progress-bar "$url" -o /usr/local/bin/dun.new; then
        echo "下载失败，检查网络后重试"
        exit 1
    fi
elif command -v wget >/dev/null 2>&1; then
    wget -O /usr/local/bin/dun.new "$url"
else
    echo "需要 curl 或 wget，先装一个，比如 apk add curl"
    exit 1
fi
# 别把报错页面当成二进制装上去：ELF 文件头（7f 45 4c 46）才算下对了
magic="$(head -c 4 /usr/local/bin/dun.new 2>/dev/null | od -An -tx1 | tr -d ' \n')"
if [ "$magic" != "7f454c46" ]; then
    echo "下载的文件不是可执行文件，检查网络后重试"
    rm -f /usr/local/bin/dun.new
    exit 1
fi
chmod +x /usr/local/bin/dun.new
mv -f /usr/local/bin/dun.new /usr/local/bin/dun
exec /usr/local/bin/dun "$@" </dev/tty
