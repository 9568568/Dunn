#!/usr/bin/env bash
# dun 一键安装：下载对应架构的二进制，然后打开菜单
# 纯 IPv6 机器也能用：GitHub 有 IPv6，下载不通会自动改用 IPv6 再试一次。
set -e
[ "$(id -u)" = 0 ] || { echo "请用 root 运行"; exit 1; }
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "暂不支持 $(uname -m)"; exit 1 ;;
esac
url="https://github.com/9568568/Dunn/releases/latest/download/dun-linux-$arch"
echo "下载 dun ($arch)"
# 先正常下（curl 自己选 IPv4/IPv6）；不通再强制 IPv6 试一次，
# 免得只有 IPv6 的机器卡在解析/连接上。
if ! curl -fL --retry 2 --connect-timeout 15 --progress-bar "$url" -o /usr/local/bin/dun.new; then
    echo "重试：强制 IPv6 下载"
    curl -fL -6 --retry 2 --connect-timeout 15 --progress-bar "$url" -o /usr/local/bin/dun.new
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
