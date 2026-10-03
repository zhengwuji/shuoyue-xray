# 朔月 Shuoyue — 多协议旁路网关 & DNS(原 de_GWD 重制版)

> **一键安装:**
> ```bash
> bash <(curl -fsSL https://raw.githubusercontent.com/zhengwuji/shuoyue-xray/main/install.sh)
> ```
> 装完自动打印全部节点地址、订阅与 v2rayN 二维码;随时输入 `shuoyue` 打开管理菜单。
> 支持 Debian / Ubuntu 全功能安装,并可在 **OpenWrt** 上装成客户端。

基于 [jacyl4/de_GWD](https://github.com/jacyl4/de_GWD)(寒月,已归档)的功能规格重写的**自包含**安装/管理脚本,含服务端与客户端两部分。原版采用 EPL-2.0 协议,本重制版沿用并向原作者致谢。

> 仅供学习与研究。请遵守所在地区法律法规。

## 这是什么

- **server**:一台 Debian VPS 变成多协议代理服务端 —— **19 种协议任意勾选**:Xray 侧 vmess/vless/trojan(WS+TLS)、VLESS+WS+VLESS加密、trojan+WS(明文回源)、trojan+TCP+TLS、VLESS+Reality+Vision、VLESS+XHTTP+TLS(TCP/UDP)、VLESS+XHTTP+TLS+UpIP、VLESS+XHTTP+VLESS加密、VLESS+XHTTP+Reality+加密、Shadowsocks-2022、SOCKS5;sing-box 侧 Hysteria2、TUIC v5、AnyTLS、NaiveProxy、VLESS+Reality(any reality)、Shadowsocks-2022 —— 外加 nginx 伪装站 + DoH + **订阅服务(/sub)** + **Web 控制面板** + BBR/CAKE 流量整形 + nftables flowtable + WARP 出站 + HAProxy 端口转发,菜单化管理。
- **client**:一台 Debian 闲置设备变成局域网**旁路网关** —— LAN 设备把网关/DNS 指向它,即获得透明代理分流:国内直连、国外走代理、CAKE 双向抗 bufferbloat、可选 AdGuard Home 广告拦截,菜单化管理。节点支持**直接粘贴 v2rayN 分享链接导入**。
- **Web 控制面板**:浏览器里勾选协议、改全局配置、一键生效,并直接复制订阅地址 / 分享链接到 v2rayN。

两个脚本都是**单文件、模板全内嵌**,不依赖任何第三方发布仓库的 zip/二进制;所有外部组件一律取自官方上游,下载时带 sha256 校验。

## 快速开始

### 服务端

方式一(一键,推荐):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/zhengwuji/shuoyue-xray/main/install.sh)
# 选 [1] → 勾选协议(回车=全部) → 含域名类协议时输入域名
# 装完自动打印: 全部协议分享链接 + 订阅地址 + 二维码 + v2rayN 导入示例
# 之后随时输入 shuoyue 打开菜单
```

> **下载完整性**:`install.sh` 会先取仓库根目录的 `SHA256SUMS` 校验 `server` /
> `client` / `client-openwrt` / `panel.py` 的哈希,不匹配立即中止;取不到清单时
> 退回体积下限 + 特征串的弱校验(会打印警告)。清单由仓库根目录的
> `gen_sums.sh` 生成 —— 改动上述任一文件后必须重新生成,否则安装会被
> 自己的校验挡下。

方式二(手动上传):

```bash
# 上传 server 到 VPS(Debian 12/13 或 Ubuntu 22.04/24.04),然后:
bash server
```

**管理菜单:**

| 项 | 功能 |
|---|---|
| 1 | 安装(协议勾选,回车=全部) |
| 2 | 升级(全部组件拉最新 release + 系统全面升级) |
| 3 | 卸载(完整移除服务/配置/证书/数据) |
| 4 | 更改配置(更换域名 / 协议开关 / Reality 密钥 / WS path / WARP / HAProxy 转发) |
| 5 | 更改端口(nginx 类协议 443 ↔ 自定义) |
| 6 | 重置 UUID/密码(所有协议同步轮换,订阅自动更新) |
| 7 | 安装/重装 Web 控制面板 |
| 8 | 节点信息/订阅(全部协议链接 + 二维码 + v2rayN 导入示例) |
| 9 | Cloudflare 测速 |
| 10 | 升级内核(Zabbly) |
| 0 | 自动更新开关(每日 04:30,仅更新脚本) |

### Web 控制面板

菜单里选「安装 Web 面板」,或用 `shuoyue --panel-install`。面板是**单文件 Python3 标准库**实现(`panel.py`,无需 pip),监听 `127.0.0.1:3000`,由 nginx 反代到一个**随机路径**下,只有持有 token 的人能打开:

```
https://<你的域名>/<10位随机路径>/?t=<token>
```

面板能力:

- **协议勾选**:19 种协议按内核分组列出,显示端口与「需域名 / 免域名」,支持全选 / 仅 Xray / 仅 Sing-box;点「保存并应用」即写入并重建 Xray / sing-box / nginx 配置、重启服务
- **全局配置**:域名(可含端口)、服务端口、UUID(带一键生成)、订阅路径密码、CDN 优选 IP / 落地域名
- **订阅**:直接显示并一键复制 `https://<域名>/sub/<token>`
- **分享链接**:逐条卡片展示全部已启用协议的 v2rayN 链接,单条 / 全部一键复制
- **凭据**:token 与随机路径存于 `/opt/de_GWD/conf.json`(0600),`shuoyue --cli status` 可重新查看

安全设计:token 常量时间比较、POST 校验 Origin/Referer 与 Host 一致(CSRF)、请求体上限 256 KiB、协议 id 与域名/UUID/端口全部白名单校验、所有对 server 的调用串行化(`--cli` 单入口,避免并发重建配置)。

### 客户端(旁路网关)

```bash
# 上传 client 到局域网 Debian 设备,然后:
bash client
# 菜单选 1,按提示输入:本机静态IP、上级路由IP、服务端地址/UUID/Path、全球分流DoH
# 完成后,把其他设备的 网关 和 DNS 指向本机IP即可
```

### OpenWrt 客户端

```bash
# 在 OpenWrt / Kwrt 上(SSH 进去,root):
bash <(curl -fsSL https://raw.githubusercontent.com/zhengwuji/shuoyue-xray/main/install.sh)
# 会自动识别 OpenWrt,装好 bash 与客户端,然后进入客户端安装向导
# 之后输入 shuoyue-gw 打开菜单
```

install.sh 会自动识别 OpenWrt,下载 OpenWrt 原生客户端(`client-openwrt`),**不依赖 systemd/apt**:服务用 procd 托管(`/etc/init.d/degwd-gw|degwd-sb|degwd-nft|degwd-dns`),依赖走 opkg,开机自启用 `service_triggers`,DNS 走 dnsmasq 的 nftset 集成。

- **精简版固件自动补 bash**:client-openwrt 需要 bash(数组、`[[ ]]`),只有 ash 的固件会在安装前自动 `opkg install bash`
- **不会破坏其他代理插件**:只创建自己的 nft 表(`de_GWD`),卸载时也只删自己的表;全程使用 `firewall reload` 而非 `firewall stop`(后者会 `fw4 flush` 掉全部表,包括 passwall2)
- **与 passwall2 共存**:本方案用 `priority -280`,passwall2 的 `dstnat-1`/`mangle-1` 不受影响
- **sysupgrade 前请备份**:`/opt` 位于 overlayfs,升级固件会丢失。先执行 `sysupgrade -b /tmp/gwd-backup.tar.gz` 并取回本地

功能与服务端对齐:19 种协议链接导入、TPROXY 透明分流、smartdns 分流、WireGuard(走 uci,不用 wg-quick)、DDNS、DNS 劫持、节点增删/测延迟/测速、更新与卸载。

## 系统支持与版本策略

**发行版支持矩阵:**

| 系统 | 支持度 | 说明 |
|---|---|---|
| Debian 12 / 13 (amd64/arm64) | ✅ 完整支持 | 主力目标,所有功能可用 |
| Ubuntu 22.04 / 24.04 | ✅ 完整支持 | 自动适配:nginx 官方源走 /ubuntu、静态 IP 走 netplan、systemd-resolved 正确接管 |
| OpenWrt (客户端) | ✅ 支持 | procd 服务、opkg 依赖、uci/dnsmasq 集成、nft TPROXY;自动补 bash;服务端不适用 |
| Debian 11 | ⚠️ 可用 | 个别包(如 libmimalloc)缺失自动跳过;内核 5.10 已带 WireGuard |
| Ubuntu 20.04 | ⚠️ 可用 | smartdns 未收录(客户端会明确报错提示);建议升级到 22.04+ |
| 其他 apt 系(Mint 等) | ❓ 未测 | 理论同 Ubuntu 流程 |
| RHEL / Arch / Alpine | ❌ 不支持 | 脚本基于 apt/dpkg |

**版本策略:**

- **安装即最新**:Xray、sing-box、dnsproxy(DoH)、AdGuard Home、wgcf、acme.sh 均从各自官方 GitHub release 拉 latest(带 sha256 校验);nginx 优先 nginx.org 官方源(支持 HTTP3),不可用时回退发行版包;系统包在安装时执行 `apt full-upgrade`
- **菜单 0(更新)**:重新拉取上述全部组件最新版 + 重建配置,系统包同样 full-upgrade
- **自动更新(cron)**:仅更新脚本自身(版本号比对),不触碰组件——组件升级统一走菜单 0,避免半夜自动大动干戈
- 内核升级是可选菜单(Zabbly 源,支持 Debian 12/13 与 Ubuntu 22.04/24.04),不强制


## v2rayN 导入示例

服务端全部 19 种协议的分享链接都按 v2rayN 7.x 的解析格式生成,安装完或菜单「节点信息」会直接打印,Web 面板里也能逐条复制。链接形态如下(`example.com` 换成你的域名或 IP,UUID 为服务端生成的那个,所有协议共用同一套 UUID/密码):

```
vmess://eyJ2IjoiMiIsInBzIjoiZXhhbXBsZS5jb20tdm1lc3MiLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjExMTExMTExLTIyMjItMzMzMy00NDQ0LTU1NTU1NTU1NTU1NSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJleGFtcGxlLmNvbSIsInBhdGgiOiIvYWJjMTIzIiwidGxzIjoidGxzIiwic25pIjoiZXhhbXBsZS5jb20ifQ==   (base64 JSON)
vless://<uuid>@example.com:443?encryption=none&security=tls&sni=example.com&fp=chrome&type=ws&host=example.com&path=/v-abc123#vless-ws
vless://<uuid>@example.com:443?encryption=<vless加密串>&security=tls&sni=example.com&fp=chrome&type=ws&host=example.com&path=/ve-abc123#vless-ws-enc
vless://<uuid>@example.com:8443?security=reality&encryption=none&pbk=<公钥>&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&sid=<shortId>#reality
vless://<uuid>@example.com:8450?security=reality&encryption=none&pbk=<公钥>&fp=chrome&type=xhttp&path=%2Fxr-abc123&mode=auto&sni=www.microsoft.com&sid=<shortId>#xhttp-reality
vless://<uuid>@example.com:8448?encryption=none&security=tls&sni=example.com&fp=chrome&type=xhttp&host=example.com&path=%2Fxt-abc123&mode=auto#xhttp-tls
vless://<uuid>@<优选IP>:8448?encryption=none&security=tls&sni=example.com&fp=chrome&type=xhttp&host=example.com&path=%2Fxt-abc123&mode=auto#xhttp-tls-upip
trojan://<uuid>@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=/t-abc123#trojan-ws
trojan://<uuid>@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=/tw-abc123#trojan-ws2
trojan://<uuid>@example.com:8442?security=tls&sni=example.com&type=tcp#trojan-tcp
ss://<websafe-base64(2022-blake3-aes-128-gcm:密码)>@example.com:8388#shadowsocks-2022
socks://<websafe-base64(用户名:密码)>@example.com:1080#socks5
hysteria2://<uuid>@example.com:8444?sni=example.com&insecure=0#hysteria2
tuic://<uuid>:<uuid>@example.com:8445?congestion_control=bbr&alpn=h3&sni=example.com&allow_insecure=0#tuic
anytls://<uuid>@example.com:8446?sni=example.com&insecure=0#anytls
naive://<urlencode(用户名:密码)>@example.com:8447?sni=example.com&insecure=0#naive
```

导入方式(三选一):

1. **单节点**:复制任意一条链接 → v2rayN 主界面 `Ctrl+V`(从剪贴板导入批量URL),支持一次粘贴多条;
2. **订阅(推荐)**:订阅分组 → 订阅分组设置 → 添加 → 粘贴订阅地址 `https://你的域名/sub/<token>`(安装后菜单会打印,含二维码;Web 面板里也可一键复制)→ 更新订阅;以后换 UUID/协议无需重新导入;
3. **二维码**:菜单「节点信息」打印首个节点与订阅地址的终端二维码 → 服务器 → 扫描屏幕上的二维码。

协议与内核对应(v2rayN 7.x 自动分派,无需手动选核):

| 协议 ID | 名称 | 内核 | 端口 | 需要域名 |
|---|---|---|---|---|
| vmess | Vmess-ws | Xray | 443(nginx) | 是 |
| vless | Vless-ws-tls | Xray | 443(nginx) | 是 |
| trojan | Trojan-ws-tls | Xray | 443(nginx) | 是 |
| wsenc | Vless-ws-enc | Xray | 443(nginx) | 是 |
| trojanws | Trojan-ws | Xray | 443(nginx) | 是 |
| trojantcp | Trojan-tcp-tls | Xray | 8442 | 是 |
| reality | Vless-tcp-reality-vision | Xray | 8443 | 否 |
| xhttptls | Vless-xhttp-tls-TCP/UDP | Xray | 8448 | 是 |
| xhttpupip | Vless-xhttp-tls-UpIP | Xray | 8448 | 是 |
| xhttpenc | Vless-xhttp-enc | Xray | 8449 | 是 |
| realityxhttp | Vless-xhttp-reality-enc | Xray | 8450 | 否 |
| ss | Shadowsocks-2022(xray) | Xray | 8388 (tcp+udp) | 否 |
| socks5 | Socks5 | Xray | 1080 | 否 |
| hy2 | Hysteria2 | sing-box | 8444 (UDP) | 否(无证书时自签,链接自带 insecure=1) |
| tuic | Tuic | sing-box | 8445 (UDP) | 否(同上) |
| anytls | AnyTLS | sing-box | 8446 | 否(同上) |
| naive | Naiveproxy | sing-box | 8447 | 是 |
| anyreality | Any reality | sing-box | 8451 | 否 |
| sssb | Shadowsocks-2022(sing-box) | sing-box | 8452 | 否 |

网关客户端支持粘贴同样的链接导入;hy2/tuic/anytls/naive 等 sing-box 协议节点会自动安装 sing-box 桥接(本地 socks),分流/TPROXY 逻辑不变。


## 重制版相比原版的改进

| 类别 | 原版 | 重制版 |
|---|---|---|
| 二进制来源 | 作者预编译 nginx/doh/xray,存放在仓库里 | **全部官方上游**:Xray 官方安装器、nginx.org 官方源(缺失时回退 Debian 包)、dnsproxy(AdGuard)、Loyalsoldier 规则、felixonmars 域名表 |
| 协议 | 仅 vmess+WS+TLS | **19 种协议**:Xray 侧 13 种(vmess/vless/trojan 系列、VLESS 加密、Reality、XHTTP 系列、Shadowsocks-2022、SOCKS5)+ sing-box 侧 6 种(Hysteria2、TUIC、AnyTLS、NaiveProxy、any reality、SS2022),菜单与 Web 面板随时开关 |
| 分享链接 | 非标准 vmess URI,部分客户端无法导入 | **19 种协议标准链接 + 订阅服务(/sub)+ 二维码**,v2rayN 7.x 实测格式 |
| 管理界面 | 仅 PHP 面板(1600+ 文件) | **单文件 Web 控制面板**(Python3 标准库,无 pip)+ 完整 CLI 菜单,浏览器勾选协议即可生效 |
| 客户端节点 | 仅手填 vmess | **粘贴分享链接导入**,hy2/tuic/anytls/naive 自动 sing-box 桥接 |
| 证书 | 私钥 chmod 644,TLS1.3 0-RTT 开启 | 私钥 **0600**,0-RTT 关闭(防重放) |
| 防火墙 | tcp_syncookies=0 | syncookies 开启,保留坏标志包防御 |
| HAProxy 转发 | 每次整体覆写,只能存一条 | **多条转发**,菜单增删 |
| WARP | 出口 IP 判断有缺陷 | 前后对比修正,注册文件不再落当前目录 |
| 自动更新 | 版本相等也会触发重装 | 仅当远端更新时拉取,更新源可在脚本头部自行配置 |
| 容器模式 | upstream 端口错配(9890/9896) | 容器内跳过 sysctl/tc/nft,其余功能与 VM 一致 |
| 客户端 DNS | pihole(docker)→mosdns→smartdns→coredns 四级链 | **smartdns 单组件分流**(国内组/全球DoH组,first-ping 选优),可选 AdGuard Home 前置拦截,排障容易得多 |
| block53 | INPUT 链 drop 53,会误伤本机 DNS | **nft redirect 劫持**:LAN 查外部 DNS 一律重定向到网关,真正防绕过 |
| 运维 | 大量 sed 打补丁,半装状态难恢复 | 模板整文件幂等重生成,nginx 自定义段保留;状态统一存 `/opt/de_GWD/conf.json`(0600) |

## 功能对照

### server 菜单

| 项 | 功能 |
|---|---|
| 1 | 安装(协议勾选,回车=全部) |
| 2 | 安装 Zabbly 内核并重启 |
| 3 | 更换域名并重新签发证书(443 走 webroot,非 443 走 Cloudflare DNS API) |
| 4 | 更换 UUID 与 WS path(所有协议同步生效) |
| 5 | Reality 开关/重新生成密钥 |
| 6 | 协议开关(随时启停任意协议,自动重生成配置与订阅) |
| 7 | 安装/重装 Web 控制面板 |
| 0 / 00 | 更新 / 自动更新开关(每日 04:30) |
| 11 | 打印全部协议分享链接 + 二维码 + 订阅地址 + v2rayN 导入示例 |
| 12 | 本机 Cloudflare 测速(cfspeed) |
| 33 | Cloudflare WARP 出站(本机服务不受影响:公网 IP 与 DNS 查询仍走直连) |
| 44 | HAProxy TCP 端口转发(多条) |

服务端端口:80(301)/443 或自定义(nginx TLS+QUIC)、8442(trojan-tcp)、8443(Reality)、8448/8449/8450(XHTTP 系列)、8388(SS)、1080(SOCKS5)、8444/8445(hy2/tuic,UDP)、8446(AnyTLS)、8447(NaiveProxy)、8451(any reality)、8452(SS2022 sing-box);本机内部:127.0.0.1:9890/9891/9892/9893/9894(Xray vmess/vless/trojan-ws/trojan-ws2/vless-ws-enc)、127.0.0.1:9853(DoH)、127.0.0.1:53(unbound)、127.0.0.1:3000(Web 面板)。
伪装站默认自带(轻量自绘),`/var/www/html/spt` 为 100MB 供客户端测速;`https://域名/dns-query` 为 DoH 入口,`https://域名/sub/<token>` 为订阅地址。

### client 菜单

| 项 | 功能 |
|---|---|
| 1 | 安装(自动检测网卡,静态 IP,分流规则下载) |
| 2 | 节点管理:粘贴分享链接导入(vmess/vless/trojan/ss/hy2/tuic/anytls)、增/删/切换/测延迟/测速(1-based 序号) |
| 3 | 分流规则:流媒体预设(YouTube/Netflix/HBO/TVB/巴哈/OpenAI/Apple/Steam,按 geosite)、自定义域名黑白名单、源 IP 分流(指定设备强制代理/直连) |
| 4 | DNS 设置:全球 DoH、国内 DNS 列表、自定义 hosts |
| 5 | AdGuard Home 安装/移除(53 前置,广告拦截) |
| 6 | WireGuard 服务端(出门在外连回家用网关分流,客户端配置二维码) |
| 7 | Cloudflare DDNS(API Token,每 5 分钟) |
| 8 | block53(DNS 劫持开关,防局域网设备绕过网关 DNS) |
| 9 | 代理开/关(一键全直连) |
| 10 | 对外中转线(额外 vmess 端口,可串联指定节点) |
| 12 | Zabbly 内核 |
| 0 / 00 / 11 | 更新 / 自动更新(每日 05:00)/ 节点信息 |

客户端实现:nftables **TPROXY**(mark 0x9,table 220)→ Xray dokodemo-door 127.0.0.1:9896;chnroute IP 在 **nft 内核层直连**(不过代理栈,性能同原版);geosite:cn 在 Xray 路由层双保险;防回环三板斧(节点 IP 进 V2NODE 集合直连 + Xray 出站 mark 255 豁免 + 节点域名钉死 IP)。

## 与原版的功能差异(未实现部分)

- 客户端 **Web UI**(原版 1600+ 文件的 PHP 面板)与 ttyd 终端 —— 全部功能已收入 CLI 菜单;服务端侧的 Web 控制面板已用单文件 `panel.py` 实现
- 家庭服务器应用安装器:Docker/Jellyfin/Bitwarden/FileRun/MariaDB/NFS
- DNS over gRPC(DoG)服务与 3322 DDNS(服务已死);如需 DoG/3322 请用原版

其余网关核心功能(透明代理、分流、整形、WG、DDNS、中转)与原版对齐,行为一致处不一一列举。

## 文件布局(两端通用)

```
/opt/de_GWD/
  conf.json          状态中心(0600, jq 可直接读写;含 .panel.token/.panel.path)
  server / client    主脚本(菜单 / --cli 单一入口)
  panel.py           Web 控制面板(单文件,Python3 标准库,由 degwd-panel.service 托管)
  xray/config.json   Xray 配置(菜单/面板操作后自动重生成)
  singbox/config.json sing-box 配置(hy2/tuic/anytls/naive/anyreality/sssb)
  smartdns/          客户端 DNS 配置与缓存
  nftables/          规则与 IP 集合文本、flowtable 设备生成器
  autoUpdate / updateLists / ddns   cron 脚本
/etc/rc_online.local CAKE+ifb 双向整形(networking/nftables/wg-quick 启动时自动重跑)
```

## 依赖

Debian 12 (bookworm) / 13 (trixie) 或 Ubuntu 22.04 / 24.04,amd64 或 arm64;root 权限。服务端需要域名才能使用 nginx 类协议;Reality / XHTTP-Reality / SS / SOCKS5 / Hysteria2 / TUIC / AnyTLS / SS2022(sing-box) 无需域名。客户端建议物理设备或 KVM 虚机(容器内无 TPROXY/CAKE);OpenWrt 客户端由 install.sh 自动识别并安装。

Web 控制面板需要 `python3`(标准库即可,无需 pip);面板由 nginx 反代到随机路径,也可 SSH 隧道直连 `127.0.0.1:3000`。

## 目录说明

- `install.sh`:一键安装引导(自动识别 Debian/Ubuntu 或 OpenWrt → 下载主脚本 → 选角色 → 安装 → 打印节点地址)
- `server` / `client`:服务端 / 旁路网关客户端主脚本(Debian / Ubuntu)
- `client-openwrt`:OpenWrt / Kwrt 客户端主脚本(procd + uci + opkg + nft TPROXY)
- `panel.py`:Web 控制面板(单文件,随 install.sh 一并下载到 `/opt/de_GWD/`)
- `version`:版本文件(自动更新比对他源)
- `_original/`:原版仓库完整克隆,仅作对照参考,可删除
- `LICENSE.md`:EPL-2.0 说明与原版出处
