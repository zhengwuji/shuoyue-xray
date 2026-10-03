# 朔月 Shuoyue v1.2.0 — 代码审查与优化建议

审查范围：`server`（1923 行）、`client`（1883 行）、`install.sh`（90 行）。
每条均带行号与可替换代码。优先级按「影响面 ÷ 改动量」排序。

---

## 0. 先修这 12 条（P0：会直接导致功能不可用或数据损坏）

| # | 位置 | 问题 | 修复要点 |
|---|------|------|----------|
| 1 | [client:367](client#L367) | `ExecStart=/usr/bin/smartdns`，而 Debian 包把守护进程装在 `/usr/sbin/smartdns` → smartdns 起不来，DNS 全挂 | 用 `command -v smartdns` 动态取路径；enable 前补 `daemon-reload` |
| 2 | [server:1690](server#L1690) | Zabbly 源写成 `URIs: https://zabbly.com/kernel/stable`，官方仓库实际在 `pkgs.zabbly.com`（实测前者 404/502，后者 200） | 改为 `https://pkgs.zabbly.com/kernel/stable` |
| 3 | [server:181](server#L181) | 依赖硬编码 `libmimalloc2.0`，Debian trixie 已改为 `libmimalloc3` | 按 codename 分支或直接删除该依赖 |
| 4 | [client:319-322](client#L319-L322) + [client:423](client#L423) | `smartdns_conf` 整文件重写把 bind 改回 `[::]:53`，AGH 让出的 53 被抢回，且 AGH 上游 `127.0.0.1:5330` 无人监听 | 端口决策移入生成器，删掉事后 sed |
| 5 | [server:503](server#L503)、[client:672](client#L672)、[client:1514](client#L1514)、[server:1758](server#L1758) | `nft flush ruleset` 清空**整机**所有 nft 表（Docker / firewalld / 用户规则全丢） | 只 `nft delete table` 自建表；表名加前缀避免撞名 |
| 6 | [server:1128-1146](server#L1128-L1146) | `xray_gen_config` 用 `>` 直写 `config.json`，jq 失败即留空文件，Xray 起不来且无提示 | 原子写 + `jq -e` 校验后再 `mv` |
| 7 | [client:571](client#L571) | prerouting 最后一条 `tproxy to 127.0.0.1:9896` 无端口豁免，中转线入站与 WG UDP 51820 被劫持 | 本机 IP 并入 `RESERVED_IP` + 入口端口豁免 |
| 8 | [client:1602](client#L1602) | `wan_ip()` 走代理出口，返回的是 VPS IP → DDNS 写错、WG 客户端 EndPoint 指向 VPS | IP 回显域名建直连集并在 output 链豁免 + IP 正则校验 |
| 9 | [client:1504-1505](client#L1504-L1505)、[client:1478](client#L1478) | 重建 nftables 表后 CHNROUTE / V2NODE / GLOBALDNS / LISTBLAN / LISTWLAN 全空，直到次日 04:00 cron | 抽 `nftables_apply(){ nftables_conf; svc_restart nftables && refresh_nft_sets; }` |
| 10 | [client:71](client#L71)、[client:77](client#L77) | `conf.json` 无锁 + 固定临时名 `${CONF}.tmp`，3 个 cron 与菜单并发时可交错写坏 | `flock` + `mktemp` |
| 11 | [client:1115](client#L1115)、[client:113](client#L113)、[client:178](client#L178)、[client:289](client#L289) | 重跑菜单 1 会整体替换 `.nodes`（手拼 JSON）、`full-upgrade`、重写 `/etc/sysctl.conf`、`/etc/network/interfaces` | 安装前备份 + 节点改追加 + jq 构造 + full-upgrade 询问 |
| 12 | [client:1068-1069](client#L1068-L1069)、[client:1172-1178](client#L1172-L1178) | `|| true` / `2>/dev/null` 吞掉致命错误：geosite.dat 缺失 → Xray 起不来却毫无提示 | 关键调用显式判断 + `die`，日志落盘 |

---

## 1. 安全

### 1.1 密钥经 argv 泄漏到 `ps`（[client:71](client#L71)）
`jq --argjson v "$(printf '%s' "$2" | jq -Rs .)" "$1 = \$v" "$CONF"` —— 值出现在 `jq` 命令行里，`ps aux` 可见。
触发点：`conf_set '.wg.serverPriv'`（[client:1535](client#L1535)）、`conf_set '.ddns.cfToken'`（[client:1613](client#L1613)）、含 uuid/password 的 `.nodes`（[client:1321](client#L1321)）、`curl -H "Authorization: Bearer $token"`（[client:1636-1646](client#L1636-L1646)）。

```bash
conf_set() {
  local t valf; valf=$(mktemp "$BASE/.val.XXXXXX") || return 1
  printf '%s' "$2" > "$valf"; chmod 600 "$valf"
  t=$(mktemp "${CONF}.XXXXXX") || { rm -f "$valf"; return 1; }
  jq --rawfile v "$valf" "$1 = \$v" "$CONF" > "$t" \
    && mv -f "$t" "$CONF" && chmod 600 "$CONF"
  rm -f "$valf"
}
```
`conf_raw` 同理改用 `--slurpfile v <文件>`。

### 1.2 AGH 管理页无口令且对全网开放（[client:390-392](client#L390-L392)）
`address: 0.0.0.0:3000`，yaml 无 `users:` 段，heredoc 落盘默认 644。局域网任何人可抢先注册管理账号并改 DNS/过滤规则；INPUT 策略为 `policy accept`（[client:587-609](client#L587-L609)）无主机防火墙。
- 生成时写入 `users:` 口令哈希，或 `address: 127.0.0.1:3000` + SSH 隧道；
- `chmod 600 "$BASE/agh/AdGuardHome.yaml"`。

### 1.3 `wg_menu` 序号未校验 → 路径穿越读任意文件（[client:1589-1591](client#L1589-L1591)）
`[[ ! -f /etc/wireguard/client$i.conf ]]` 后直接 `qrencode < "/etc/wireguard/client$i.conf"`；输入 `../../etc/shadow` 可把任意文件渲染成二维码。
```bash
[[ "$i" =~ ^[0-9]+$ ]] || die "序号错误"
```

### 1.4 供应链：`curl | bash` 无锁版本、无校验
- [server:514](server#L514)、[client:712](client#L712)：`bash -c "$(curl -fsSL .../Xray-install/raw/main/install-release.sh)" @ install` → 锁版本 + 记录安装前后 `xray version` 对比。
- [server:1691](server#L1691) 附近 Zabbly key 无指纹校验 → 比对 `4EFC 5906 96CB 15B8 7C73 A3AD 82CC 8797 C838 DCFD`。
- [install.sh:57](install.sh#L57) 完整性检查是 `grep -q '朔月\|Shuoyue\|xray'`，任何含 "xray" 的页面都能通过 → 加 sha256 清单。

### 1.5 越权改动系统
- [server:198-200](server#L198-L200) `apt-get remove --purge systemd-timesyncd`（用户机器可能有别的用途）。
- [server:217-233](server#L217-L233) 写 `/etc/apt/apt.conf.d/01deGWD` 持久化 `APT::Get::Assume-Yes "true"` → 此后管理员**所有** apt 操作（含 autoremove）被静默确认。改为仅本次调用 `-y`。
- [server:963](server#L963) `rm -f "$SSLDIR"/*.key` 会连自签证书一起删。
- [server:642](server#L642) `ssl_conf_command Options KTLS;` 仅 nginx ≥1.21.4 + OpenSSL 3 支持，旧 nginx 配置直接报错。

---

## 2. 功能缺陷

| 位置 | 问题 | 修复 |
|------|------|------|
| [client:1229-1230](client#L1229-L1230) + [client:880-888](client#L880-L888) | vless 非 reality 一律生成 ws，`path` 为空时节点不可用（vmess 分支 [client:848](client#L848) 有正确分支） | 照 vmess 拆两支：path 空 → `network:"tcp"` |
| [client:1207-1214](client#L1207-L1214) | vmess 分享链接忽略 `net/type/tls/host/scy/alpn/fp`，grpc/h2 节点被静默生成为明文 tcp/ws | 解析 `.net/.tls` 落到 `type`，未知 type 直接拒绝 |
| [client:854](client#L854)/[886](client#L886)/[898](client#L898)/[907](client#L907) | `allowInsecure` 写死 false，自签证书场景不可用（仅 hy2/tuic/anytls 支持） | 三协议透传 `allowInsecure`，或文档明确声明 |
| [client:1659](client#L1659)、[server:1588](server#L1588) | 中转线端口只校验数字，可填 0/99999/53/9896/3000 | `-ge 1 && -le 65535` + 拒绝保留端口表 |
| [client:1375-1376](client#L1375-L1376) | 删除任意节点都把 `nodeActive` 重置为 0，且无二次确认 | 按 `act` 与 `idx` 关系调整索引 |
| [client:1356-1357](client#L1356-L1357) | curl 失败仍输出 `time_connect=0` → 打印「0ms」 | 判 `$?` 与 `-n $ms`，失败报「测不通」 |
| [client:1364-1368](client#L1364-L1368) | `nodes_speed` 无超时、无 `--no-check-certificate`、`port` 未 `local`、解析 `tail -n2` 极脆弱 | `local addr host port`；`curl -w '%{speed_download}'` |
| [client:640](client#L640) | block53 只劫持明文 53，DoT/DoH 完全绕过 | 加 `th dport 853 reject` + DoH IP 集，或文档声明 |
| [client:1635](client#L1635) | DDNS zone 推导只取后两段：`home.example.co.uk` → `co.uk` | 用 CF `GET /zones?name=` 后缀匹配 |
| [client:1636-1648](client#L1636-L1648) | DDNS 不检查 `.success`，失败也 `ok`；curl 无 `--max-time`，cron 可能永久挂住 | 加超时 + 校验 + 非 0 返回 |
| [client:1431](client#L1431)、[client:1483-1490](client#L1483-L1490) | 规则/hosts 菜单是整体替换，误回车即清空 | 基于现值追加，或提供追加/覆盖选择 |
| [client:1438-1442](client#L1438-L1442) | `split_ips` 不校验 IP/CIDR，坏值使 `nft add element` 整条失败且被吞 | 加 IPv4/CIDR 正则 |
| [client:1785](client#L1785)、[client:1792](client#L1792) | 输出 `hy2://` / `anytls://`，v2rayN 兼容性差 | 统一输出 `hysteria2://` |
| [client:624-635](client#L624-L635) | flowtable `bypassflow` 匹配 172.16.66.0/24 与 172.17.0.0/16，但 `devices` 只含物理网卡 → 死配置 | 删除该表或把 wg0/docker0 加入 devices |
| [client:1141-1146](client#L1141-L1146) | 先写 cron 后写脚本，且不检查 cron 是否存在（最小安装无 cron） | 先写脚本；`command -v crontab \|\| apt-get install -y cron` |
| [server:705-861](server#L705-L861) | 回退到发行版 nginx 包时未清理 `/etc/nginx/sites-enabled/default`，与之 `default_server` 冲突 → `nginx -t` 报 duplicate default server | 安装时清理；`uninstallGWD` 一并删除 |
| [server:935-936](server#L935-L936) | unbound DNSSEC 判断是空操作（`grep -q ... \|\| true` 无副作用） | 补 `unbound-control` 或直接删 |
| 全文 | client 无卸载路径（nft 表、6 个单元、ifb、cron、被 mask 的 systemd-resolved 全残留） | 加菜单项 `99. Uninstall` |
| [client:1728-1731](client#L1728-L1731) | autoUpdate 下载新脚本后只 `bash --update` 再 `rm`，**从未落盘覆盖自身** → 每天 05:00 空转，`VERSION` 永不变 | 校验 sha256 + `install -m 755` 覆盖 + `exec` |

---

## 3. 健壮性与幂等

### 3.1 全局错误处理
两个脚本都没有 `set -euo pipefail`，且大量 `2>/dev/null`。建议脚本头 `set -uo pipefail`（交互式脚本保留不启 `-e`），「必须成功」的调用显式判断 + `die`，统一日志 `/var/log/de_GWD.log`。

### 3.2 配置原子写（[client:319](client#L319)/[1046](client#L1046)/[1058](client#L1058)/[1063](client#L1063)/[808](client#L808)，[server:1128](server#L1128)）
```bash
write_atomic() {   # $1=dest $2=mode 从 stdin 读
  local t; t=$(mktemp "$1.XXXXXX") || return 1
  cat > "$t" || { rm -f "$t"; return 1; }
  chmod "$2" "$t" && mv -f "$t" "$1"
}
```
JSON 生成统一 `jq -e .` 校验通过再 `mv`。

### 3.3 清单下载加条数校验（[client:1055-1058](client#L1055-L1058)、[client:1063](client#L1063)）
`[[ -s file ]]` 对半截文件也成立 → 国内直连集被截断（国内流量绕代理）。
```bash
n=$(grep -cE '^[0-9]+\.' /tmp/chnroute.txt || echo 0)
if [[ $n -ge 3000 ]]; then
  grep -E '^[0-9]+\.' /tmp/chnroute.txt | sed 's/;.*//' | sort -u > "$BASE/nftables/IP_CHNROUTE.new" \
    && mv -f "$BASE/nftables/IP_CHNROUTE.new" "$BASE/nftables/IP_CHNROUTE"
else warn "chnroute 条数异常($n)，保留旧表"; fi
```

### 3.4 并发与临时文件
- [client:529](client#L529)/[539](client#L539) `/tmp/nft_elements.tmp` 固定名，cron 与菜单并发互踩 → `mktemp`；表不存在时先 `nft list table ip de_GWD` 判断并报错。
- [server:1496](server#L1496) `/tmp/gwd_links.$$`、[client:90](client#L90) `/tmp/$name`（用 GitHub 返回的文件名拼路径，含 `/` 或 `..` 会越界写）→ `mktemp` + `trap 'rm -f ...' EXIT`。
- [client:46-49](client#L46-L49)、[server:59](server#L59) `svc_restart` 里 `sed -i '/^Nice=/d'` 会**永久**删掉单元的 `Nice=-9` 且不可恢复 → 改用 `systemctl set-property` 或临时 drop-in。

### 3.5 动作反向的 `&&`/`||`（[client:1859](client#L1859)、[client:1868](client#L1868)）
`[[ ... == true ]] && agh_remove || agh_install`：`agh_remove` 返回非 0 时立刻重装。改显式 `if/else`。

### 3.6 状态残留
- [client:1511-1515](client#L1511-L1515) `proxy_toggle` 用「服务是否在跑」判断方向（xray 崩溃时会走「恢复」分支）；关闭时不删 `ip route add local default dev lo table 220`（[client:671](client#L671) 加的）→ 用 conf 的 `.proxyOn` 记录状态并在关闭时删除路由。
- [client:242-301](client#L242-L301) `net_static` 无确认无回滚，改错 CIDR 即失联 → 写入前备份，apply 后 60 秒自检并回滚。
- [client:1154-1162](client#L1154-L1162) `resolv_setup` 直接 mask `systemd-resolved` 并硬写 `/etc/resolv.conf`，与 [client:249](client#L249) 的 nmcli 分支矛盾（NM 会覆盖手写内容）→ 统一走 NM 或加 `dns=none`。

### 3.7 其他
- [client:550](client#L550) `include "/opt/de_GWD/nftables/flowtable.eth"` 硬编码，该文件只由 nftables.service 的 ExecStart 生成；生成失败则整个 `nft -f` 报错 → 无 TPROXY/NAT/过滤。改为生成器内直接产出或先写空占位。
- [client:654](client#L654) 覆盖发行版 `/etc/systemd/system/nftables.service`（用户 `/etc/nftables.conf` 永不生效），且 `Before=network-pre.target` 早于 `rc_online.local` 需要的网卡 up → 单元改名 `degwd-nftables.service`，整形拆到 `After=network-online.target` 的 `degwd-shaping.service`。
- [server:401-405](server#L401-L405)、[client:516-520](client#L516-L520) 用 `networking.service.d/override.conf` 挂整形，在 NetworkManager / systemd-networkd 系统上该单元不存在 → 永不执行，且缺 `daemon-reload`。
- [server:96-119](server#L96-L119)、[client:81](client#L81) `fetch_release` 用 `index($0,n)` 模糊匹配校验和，可能取到别的文件名；无 checksums 资产时静默跳过校验 → 只接受精确 `$2==n`。
- [server:1538](server#L1538) WARP 内核版本比较 `printf '%s\n5.6\n' "$(uname -r)" | sort -rV`，`uname -r` 形如 `6.1.0-13-amd64`，比较结果不可靠。
- [server:1282](server#L1282) `gen_sub_all` 用 `>` 直写订阅文件；[server:1503](server#L1503) 临时文件无 trap 清理。
- [client:33](client#L33) `ask()` 缺 `-r`，含 `\` 的 UUID/口令/路径会被 read 解释转义。
- [client:119-120](client#L119-L120) `pkg_dep` 装了全文未使用的 `socat`/`screen`，`resolvconf` 还会与手写 `/etc/resolv.conf` 冲突。
- [client:1867](client#L1867) 菜单 00 的 `svc_ok cron >/dev/null 2>&1 || true` 是死代码，且部分发行版单元名是 `crond.service`。

---

## 4. 性能

1. **关掉 GRO/GSO/TSO/LRO 是主要瓶颈**（[server:391-393](server#L391-L393)、[client:508-509](client#L508-L509)）。`ethtool -K ... gro off gso off tso off` 让 CAKE 走逐包路径，吞吐显著下降 —— 而 `no-split-gso` 参数本意正是配合 GSO 存在。建议只保留 `gro on gso on tso on`；删掉 `ethtool -s duplex full`（2.5G/10G 网卡可能掉链路）与 `ufo`（5.x 内核已移除）。
2. **对 `lo` 做 ingress 整形并 mirred 到 `ifb4lo`**（[client:472-479](client#L472-L479)）：TPROXY 把 LAN 流量交付到 `127.0.0.1:9896`，整条链路都走 lo，再叠加 lo 双向 CAKE 纯属自伤 → 删除。
3. **虚拟网卡一网打尽**（[client:481-494](client#L481-L494)）：`grep 'virtual'` 把 veth/br-* 也整形；`ifb4$(cut -c1-11)` 截断导致 `veth1234567`/`veth1234568` 复用同一 ifb 互相串流 → 只整形物理/WAN/LAN，ifb 名用哈希。
4. **循环内重复调 jq**（[client:352](client#L352)、[699](client#L699)、[939](client#L939)、[1295](client#L1295)、[1546](client#L1546)、[1675](client#L1675)）：`while [[ $i -lt $(echo "$nodes" | jq 'length') ]]` 每轮 fork 一次 jq → 循环前取一次长度。
5. **菜单每轮跑外网请求**（[client:1688-1698](client#L1688-L1698) 被 [client:1835](client#L1835) 主菜单 while 每轮调用，且只在进入时 `clear`）→ 改惰性/手动触发，循环内 `clear`。
6. **改国内 DNS 会重写整个 default.nft 并重启 nftables**（[client:1478](client#L1478)）→ 拆出 `nft_reserved_only()` 只改 `RESERVED_IP`。

---

## 5. 可维护性

- **硬编码集中化**：`REMOTE_BASE`、`BASE`（[client:18](client#L18) 定义了但 [client:367](client#L367)/[372](client#L372)/[413](client#L413) 又写死 `/opt/de_GWD`）、`223.5.5.5`/`119.29.29.29`（10 处）、保留网段、`172.16.66.0/24`、geosite 分类表、规则 URL 全部散落 → 收敛到顶部常量区 + `conf.json` 默认值。
- **模板抽离**：5 份 systemd unit heredoc（[client:361](client#L361)/[407](client#L407)/[654](client#L654)/[715](client#L715)/[756](client#L756)）+ nft 模板（[client:549](client#L549)）→ `templates/` + `envsubst`。
- **JSON 构造**：手拼 `"[{\"name\":\"$(echo $tls | cut -d. -f1)\",...}]"`（[client:1115](client#L1115)）与 `'. + {'\"$cat\"':$v}'`（[client:1413](client#L1413)）→ 一律 `jq -n --arg/--argjson`。
- **变量引用**：`grep -v de_GWD/xxx` 未加引号且非 `-F`，路径含 `.` 会误匹配（[client:1141](client#L1141)/[1614](client#L1614)/[1721](client#L1721)）→ `grep -F -v -- "$BASE/updateLists"`。
- **全局变量污染**：`port`（[client:1365](client#L1365)）、`wgport`、`n`/`idx` 未 `local`；`tls=${addr%%:*}`（[client:1349](client#L1349)）实为 host，命名误导且全脚本沿用。
- **接口不全**：只有 `--update/--install/--lists/--ddns/--version`（[client:1876-1882](client#L1876-L1882)）→ 补 `--uninstall/--status/--node-switch N/--regen` 与 `--help`。
- **菜单编号错乱**：[client:1847-1850](client#L1847-L1850) `12. Install new kernel` 排在 `0. Update` 前，`00. AutoUpdate` 排在 `11. Print node` 前。
- **IPv6 不一致**：既关闭 IPv6（[client:235-237](client#L235-L237)），又 `bind [::]:53`（[client:321](client#L321)）、`AllowedIPs = ::/0`（[client:1581](client#L1581)）、`host=${hostport%%:*}` 解析不了 `[2001:db8::1]:443`（[client:1219](client#L1219)）→ 二选一：彻底 IPv4-only 或补 `table ip6` 与解析分支。
- **`net.ipv4.ip_local_reserved_ports` 语义**（[client:200](client#L200)）：把 53/5330/3000/9896 列为保留端口，但 3000 是 AGH 管理页、53 由 AGH/smartdns 显式绑定 → 补注释说明并加入 10808、51820。

---

## 6. 建议的实施顺序

1. **第一批（1 天内，纯 bugfix）**：#1–#9，逐条 2–20 行改动，不涉及架构。
2. **第二批（安全）**：conf_set 去 argv、AGH 口令与权限、wg_menu 校验、install.sh sha256、Assume-Yes 收敛。
3. **第三批（健壮性）**：`write_atomic` + `flock` + 清单条数校验 + `set -uo pipefail` + 日志。
4. **第四批（性能）**：ethtool 反转、删 lo 整形、ifb 命名、jq 循环外提。
5. **第五批（架构）**：模板抽离、常量收敛、子命令与卸载路径补齐。
