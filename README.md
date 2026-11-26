# dun 盾

> 本仓库基于 [byJoey/dun](https://github.com/byJoey/dun) 1.1.0 修改，只改了纯 IPv6 VPS 适配相关的部分（测 IP 时丢弃隧道出口、安装脚本支持纯 IPv6 下载等），其余功能与原项目一致，版权归原作者所有。

一条命令装好三种节点：Reality 偷自己、AnyTLS、套 Cloudflare 的 VLESS + WS；线路差的机器还可以加装 Hysteria2。装完输入 `dun` 就能管理。

dun 是一个 Go 写的单文件程序。节点由官方 sing-box 跑，伪装站、订阅和证书续期由 dun 自己的后台服务负责。

还能在服务端分流：ChatGPT、Claude 这类流量走 WARP，别的走你自己的落地代理，链接粘进来就能用。

## 快速开始

准备三样东西：

- 一台 VPS，root 登录。带 systemd 的 Linux 都行，比如 Debian、Ubuntu、CentOS、Alma、Rocky，amd64 和 arm64 都支持
- 一个已经接入 Cloudflare 的域名
- Cloudflare 的 Global API Key。在 CF 后台点右上角头像，进「我的个人资料」→「API 令牌」，Global API Key 那一栏点「查看」

登录 VPS，执行：

```bash
bash <(curl -fsSL https://github.com/9568568/Dunn/releases/latest/download/install.sh)
```

菜单里选 `4` 三个一起装。中间会问 CF 邮箱和 Key，让你选一个域名，其他问题一路回车用默认值就行。装完屏幕上会打出订阅地址，复制进客户端就能用。

以后再管理，输入：

```bash
dun
```

不想进菜单也可以直接敲命令：

```bash
dun install reality      # 只装一个，reality / anytls / ws / all / hy2
dun links                # 再看一遍订阅和链接
dun log                  # 看日志
dun syncip               # 机器换了 IP 以后同步解析
dun uninstall            # 全部卸载
```

## 订阅

装完会给两个订阅地址，三个协议的节点都在里面：

- `…/sub`：v2rayN、Shadowrocket、NekoBox 用
- `…/clash`：Clash Verge、FlClash 这类 mihomo 客户端用，自带「自动选择」分组

装了 CF WS 的话，订阅走 CF WS 的域名，VPS 的 IP 被墙了也能更新。订阅里除了原始的 CF WS 节点，还会带上一批优选地址：

- wetest 的三网优选 IP，每 3 小时自动刷新
- 内置优选域名，刷新时逐个解析，解析不到 Cloudflare 的自动剔除
- 你自己加的地址，菜单「优选地址和订阅」里添加，格式是 `地址[:端口][#备注]`

这些都在你自己的 VPS 上生成，不经过任何第三方订阅服务。订阅地址里带一段随机字符，泄露了就在菜单里重置。

## 分流

Clash 订阅自带分流规则，导入就能用：

| 分组 | 默认 | 管哪些 |
|---|---|---|
| 广告拦截 | 拦截 | 常见广告和跟踪域名 |
| AI | 走代理 | ChatGPT、Claude、Gemini 等 |
| Telegram / YouTube / 流媒体 / 谷歌 | 走代理 | 各自的域名和 IP |
| 微软 / 苹果 | 直连 | 下载更新走国内更快 |
| 国内网站和 IP | 直连 | |
| 漏网之鱼 | 走代理 | 上面都没匹配到的 |

每个分组都能在客户端里单独切换节点或改成直连。规则库用的是 MetaCubeX 的 geosite 和 geoip，从 jsDelivr 下载，每天自动更新。

DNS 防泄露也配好了。常见的泄露是这样来的：一个国外域名不在规则列表里，客户端为了判断它是不是国内 IP，会先拿国内 DNS 解析一次，这时国内 DNS 就看到了你访问的域名。dun 的订阅默认用国外 DoH，并让 DNS 请求跟着分流规则走代理，国内 DNS 只用来解析国内域名和直连流量。用 DNS 泄露测试网站测，看不到国内的 DNS 服务器。

v2rayN、Shadowrocket 用的 `/sub` 订阅装不下规则，用客户端自带的分流就行，比如 v2rayN 的「绕过大陆」。

服务端另外拦两样：BT 下载，VPS 商家看到了会封机；通过节点访问内网地址，免得别人借你的节点摸进机器本地的服务。

## 服务端分流：WARP 和落地代理

上面的分流是在客户端里选节点。这里是另一层：流量到了 VPS 以后从哪出去。比如 ChatGPT、Claude、Gemini 嫌 VPS 的 IP 不干净，就让这部分走 Cloudflare 的 WARP；想要家宽 IP，就让它走你买的住宅代理。客户端什么都不用改，所有协议的节点一起生效。

菜单第 21 项进去，先加出站，再加规则。

### 出站

**WARP**：选「添加 WARP」，dun 自动注册一个免费账号，挨个试入口，留下第一个能握手的。有 WARP+ 授权码的话可以绑上。命令行一句搞定：

```bash
dun warp
```

**别的出站**：选「添加出站」，把链接粘进去，一次粘好几条也行。认这些格式：

| 格式 | 例子 |
|---|---|
| 分享链接 | `vless://` `vmess://` `trojan://` `ss://` `hysteria2://` `hy2://` `tuic://` `anytls://` `wireguard://` `hysteria://` |
| 代理链接 | `socks5://用户:密码@IP:端口`、`http://…`、`https://…` |
| 代理商常给的写法 | `IP:端口:用户:密码`、`用户:密码@IP:端口`、`IP:端口`，没写协议的 dun 会连上去探是 socks5 还是 http |
| sing-box 的 JSON | 单个出站，或者整份配置里的出站 |
| WireGuard 配置文件 | 填文件路径，比如 `/root/wgcf-profile.conf` |
| 订阅内容 | 整段 base64，里面的节点都导进来 |

每个出站加之前都会真连一次，打出出口 IP 和地区，不通会问你还加不加。XHTTP、mKCP、VLESS Encryption 这些 sing-box 不支持的，会直接告诉你。

```bash
dun out add 'socks5://user:pass@1.2.3.4:1080' 家宽   # 后面可以跟个名字
dun out add '1.2.3.4:1080:user:pass'
dun out test                                         # 测一遍所有出站
dun out ls
dun out rm 家宽
```

链接里有 `&`，命令行里记得用单引号包起来。

### 规则

写法和 Xray、3x-ui 的路由规则一样，逗号分隔，以前用的列表可以直接粘进来：

```
geosite:openai,geosite:apple,tiktok,ai.google.dev,claude.ai,geoip:telegram
```

| 写法 | 意思 |
|---|---|
| `geosite:openai` | 规则集，用的是 MetaCubeX 的 geosite，`geoip:` 同理 |
| `claude.ai` | 带点的按域名后缀匹配，子域名也算 |
| `tiktok` | 不带点的按关键词匹配，域名里有这个词就算 |
| `full:x.com` | 只匹配这一个域名 |
| `domain:` `keyword:` `regexp:` | 明确指定后缀、关键词、正则 |
| `1.2.3.0/24` | IP 段 |
| `ipv4` / `ipv6` | 目标只有 IPv4（或 IPv6）地址的流量 |

`geostie:` 这种手滑打错的前缀会自动纠正，提示一句。规则集下载到 `/etc/dun/rules`，每天自动更新，sing-box 不用重启。

规则从上往下匹配，都没匹配到的算「其他流量」，默认直连，也可以改成全走 WARP 或者某个落地。规则的去向除了出站，还能选直连和拦截。

常用的做成了预设，菜单里可以多选：

| 预设 | 管哪些 |
|---|---|
| `ai` | ChatGPT、Claude、Gemini 等，`geosite:category-ai-!cn` 再补几条 Google AI 的域名 |
| `google` | Google 全家，解决人机验证和送中 |
| `youtube` | YouTube |
| `stream` | Netflix、Disney+、HBO、Prime Video、Hulu |
| `tiktok` | TikTok |
| `telegram` | Telegram 的域名和 IP |
| `cn` | 国内网站和 IP，一般配拦截，免得节点被拿去回国 |
| `ads` | 广告和跟踪，一般配拦截 |
| `ipv4` | 纯 IPv6 机器配 WARP，就能上只有 IPv4 的网站 |
| `ipv6` | 纯 IPv4 机器配 WARP，就能上只有 IPv6 的网站 |

```bash
dun route add warp ai                        # 用预设
dun route add warp ai,stream                 # 好几个预设
dun route add 家宽 geosite:openai,claude.ai   # 自己写
dun route add block cn                       # 拦截
dun route final warp                         # 其他流量全走 WARP，改回来是 dun route final direct
dun route ls
dun route rm 2
```

每次改动都先让 sing-box 检查一遍，过了才生效。填错了会告诉你哪里不对，原来的配置不动。

## 抗封锁做了什么

- **Reality 偷自己**：用你自己域名的真证书和伪装站，Vision 流控，chrome 指纹
- **证书不暴露节点域名**：证书签成 `*.<随机>.<你的域名>`，证书公开日志里只有通配符，扫描器拿不到真正的节点域名。觉得域名被盯上了，`dun rehost` 一键换
- **AnyTLS**：填充方案每台机器随机生成，不用官方默认那套
- **Hysteria2**：gecko 混淆，握手包切成随机大小；端口跳跃的范围和间隔每台机器随机；没有密码的探测一律不回应
- **CF WS**：回源端口只回应 Cloudflare 的 IP，别人直连就是一个没开的端口；路径随机
- **伪装站**：登录页每台机器随机生成，标题、文案、配色、页面结构、登录接口和报错都不一样
- **客户端**：DNS 防泄露，分流规则

## Hysteria2

菜单第 5 项单独装，不在「三个一起装」里。走 UDP，丢包多、晚高峰拥堵的线路上明显比 TCP 协议快，适合线路不好的机器。

默认就是最抗封锁的配置：gecko 混淆、端口跳跃，参数每台机器随机，不用自己选。客户端要求 mihomo 1.19.34、sing-box 1.14 以上，老版本不认 gecko。云厂商的安全组记得放行 UDP。

## 伪装站

别人直接打开你的节点域名，看到的是一个登录页。随便输账号密码，都会提示用户名或密码错误。每台机器的登录页长得都不一样，想换个样子，在「伪装站」里选「换一个登录页样式」。

想换成别的网站，在菜单「伪装站」里选「反代一个网站」，填个网址就行。Reality 偷自己和 CF WS 的域名会一起换过去。CF WS 的回源端口只认 Cloudflare，直接连 IP 什么都看不到。反代只在 HTTP 这一层，TLS 握手用的还是你自己域名的真证书。

## 菜单能做什么

| 序号 | 功能 |
|---|---|
| 1-4 | 单独装某个协议，或者三个一起装 |
| 5 | 装 Hysteria2 |
| 6 / 7 | 看订阅、链接和二维码，看 mihomo 配置 |
| 8 | 优选地址：刷新、看列表、加自选、开关来源、重置订阅地址 |
| 9 | 伪装站：登录页、反代网站、换登录页样式 |
| 10 / 11 | 改端口，重置密码和 UUID |
| 12 | 卸载单个协议，顺带删掉它的解析和 CF 规则 |
| 13 | 重启、停止、看日志 |
| 14 / 19 | 更新 sing-box，更新 dun |
| 15 | 开 BBR |
| 16 | IP 变了，同步解析 |
| 17 | 更换节点域名，证书一起换 |
| 18 | 换 CF 账号 |
| 20 | 全部卸载 |
| 21 | 出站分流：WARP、导入落地代理、分流规则、其他流量走哪、测出口 |

## 常见问题

**三个协议该用哪个？**

优先用 Reality 偷自己，直连，速度最好。AnyTLS 也是直连，换个协议换个特征，当备用。CF WS 走 Cloudflare 中转，速度一般，但 VPS 的 IP 被墙了它照样能用，属于保底。直接导入订阅，三个都有，客户端里切换最省心。

**为什么要 Global API Key，安全吗？**

用 Global Key 是因为小白只要复制一串字符，不用自己建令牌、勾权限。代价是这把 Key 权限很大，能管你整个 CF 账号。dun 把它存在 VPS 的 `/etc/dun/cf.json`，只有 root 能读，续期证书要用，所以会一直留着，卸载时一起删掉。VPS 要是被人拿下，Key 也就跟着泄露了。介意的话，单独注册一个 CF 账号放节点用的域名。

**会动我域名的哪些设置？**

只加这几样：

- 两条解析。一条给 Reality、AnyTLS、Hysteria2 用，只解析不开代理；另一条给 CF WS 用，开橙云
- CF WS 那个子域名一条回源规则，把 CF 回源的端口改成节点端口
- CF WS 那个子域名一条配置规则，单独把 SSL 设成 Flexible，安全级别调低，免得订阅和连接被拦

整个域名的 SSL 模式不改，你原来的规则也不碰。子域名要是已经有解析，dun 会先问你，覆盖前会备份，卸载时还原。

**443 被占了怎么办？**

Reality 和 AnyTLS 默认用 443，被占了会提示换个端口，填别的也能用。机器上原来的网站不受影响，dun 的伪装站只监听本机 127.0.0.1，80 端口空着才会用来做跳转。

**装完连不上？**

按这个顺序查：

1. 云厂商后台的安全组有没有放行端口。甲骨文、谷歌云、AWS 都要在网页上单独放行，dun 只能处理机器里面的防火墙
2. CF WS 刚装好，解析可能要一两分钟才生效
3. 客户端是不是太老。AnyTLS 要新版客户端，见下一条
4. 输入 `dun log` 看日志，有报错截图发到群里

**AnyTLS 和官方默认有什么不一样？**

AnyTLS 靠填充打乱包长，但官方默认的填充方案人人都在用，包长分布本身就成了特征，比如认证包永远是同一个长度。dun 每台机器装的时候随机生成一份自己的方案，客户端连上以后由服务端下发，从第二条连接开始就按你的方案走。重置 AnyTLS 密码时方案也会一起换。

**哪些客户端能用 AnyTLS？**

sing-box 官方客户端、Clash Verge Rev、FlClash 这类 mihomo 内核的客户端，还有新版的 v2rayN、Shadowrocket。Reality 和 WS 基本所有客户端都支持。

**CF WS 很慢？**

导入订阅后，在客户端里给 CF WS 那一组测个速，挑最快的。也可以把你自己测出来的好 IP 加进「自选地址」，订阅马上就有。

**NAT 小鸡能用吗？**

能。dun 发现是 NAT 机器，会多问一句外网端口，填服务商给你映射的那个端口就行。甲骨文这种内外端口一样的，直接回车。

**纯 IPv6 的机器能用吗？**

能。dun 测公网 IP 时会把隧道出口（比如机器上跑着 WARP 时测到的 Cloudflare 出口 IP）丢掉，只用机器自己真正能被连到的 IPv6 地址写解析、生成链接：直连的三个协议走 AAAA 解析。没有 IPv6 的客户端连不上直连节点，用订阅里走 Cloudflare 的 CF WS 那组。机器上跑着 WARP 也不影响安装和节点本身，WARP 只影响它自己那条出站。

**证书会过期吗？**

不会。后台服务每 12 小时检查一次，剩不到 30 天就自动续，续完自动生效。想手动续就敲 `dun renew`。

**机器换 IP 了怎么办？**

输入 `dun syncip`，解析改成新 IP。订阅会自动跟着变，客户端更新一下订阅就行。

**WARP 连不上？**

有的机房封了去 WARP 的 UDP。dun 添加 WARP 时会挨个试几个入口和端口，都不通会提示你；以后想换，在菜单 21 的 WARP 里选「换个入口」。注册时报 403 或者 429，是 Cloudflare 不让这台机器注册，可以在别的机器上生成 WARP 账号，把 `wireguard://` 链接或者配置文件导进来。

**改了规则，正在用的连接会断吗？**

会断一下。每次改动 sing-box 要重启，已有的连接断开重连，一般一秒内恢复。WARP 用的是固定的本地端口，重启后马上就能重新握手。

**怎么卸载干净？**

输入 `dun uninstall`。dun 加的解析、CF 规则、证书、WARP 账号、sing-box 和它自己全删掉，BBR 设置会保留。

## 自己编译

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=dev" -o dun .
```

打 `v*` 的 tag 推上去，GitHub Actions 会自动编译 amd64、arm64 两个版本并发布 Release。
