#!/bin/bash
# =============================================================================
#  朔月 Shuoyue — 一键安装引导脚本
#  用法(一键):
#    bash <(curl -fsSL https://raw.githubusercontent.com/zhengwuji/shuoyue-xray/main/install.sh)
#  Debian / Ubuntu 支持服务端 + 客户端;OpenWrt / Kwrt 支持客户端。
#  安装完成后自动打印节点地址、订阅地址与 v2rayN 导入二维码。
# =============================================================================
RED='\E[1;31m'; GREEN='\E[1;32m'; YELLOW='\E[1;33m'; CYAN='\E[1;36m'; WHITE='\E[1;37m'; cRES='\E[0m'
REPO="zhengwuji/shuoyue-xray"
BRANCH="main"
# 下载基址。可用 DEGWD_RAW 覆盖(自建镜像 / 内网分发 / 离线测试):
#   DEGWD_RAW=http://192.168.1.10/shuoyue bash install.sh
# 覆盖后不再走 ghproxy / jsdelivr 镜像(那些是给 GitHub raw 用的加速通道)。
RAW="${DEGWD_RAW:-https://raw.githubusercontent.com/$REPO/$BRANCH}"
RAW_OVERRIDDEN=0
[[ -n ${DEGWD_RAW:-} ]] && RAW_OVERRIDDEN=1
# BASE / 命令落点都可用环境变量覆盖: 与 server / client / client-openwrt / panel.py
# 的 DEGWD_BASE 保持一致(便于把整套装到自定义路径, 也便于端到端测试时隔离)。
BASE="${DEGWD_BASE:-/opt/de_GWD}"
BINDIR_OVERRIDE="${DEGWD_BINDIR:-}"

ok()   { echo -e "${WHITE}[ ${GREEN}✓${WHITE} ]${cRES} $*"; }
warn() { echo -e "${WHITE}[ ${YELLOW}!${WHITE} ]${cRES} $*"; }
die()  { echo -e "${WHITE}[ ${RED}✕${WHITE} ]${cRES} $*"; exit 1; }

# 本脚本与 server/client 都依赖 bash 语法([[ ]]、数组、read -rp)。
# 精简版 OpenWrt 默认只有 ash, 直接用 sh 执行会在一堆语法错误里迷路,
# 故这里先确认 shell, 能换就换, 换不了给一句可操作的提示。
if [ -z "${BASH_VERSION:-}" ]; then
  # 仅当 $0 是可读的普通文件时才能安全 re-exec(curl | sh 时 $0 是 stdin, 重跑会读到空)
  if command -v bash >/dev/null 2>&1 && [ -f "$0" ] && [ -r "$0" ]; then
    exec bash "$0" "$@"
  fi
  echo "本脚本需要 bash,当前是 $(readlink -f /proc/$$/exe 2>/dev/null || echo 未知 shell)。"
  echo "OpenWrt 请先执行: opkg update && opkg install bash"
  echo "Debian/Ubuntu 请执行: apt-get update && apt-get install -y bash"
  echo "然后用 bash 运行本脚本。"
  exit 1
fi

[[ $(id -u) -ne 0 ]] && die "请以 root 运行(VPS 默认就是 root;sudo 用户先 sudo -i)"

# 命令落点: OpenWrt 上 /usr/local/bin 不存在,统一探测可写目录
BINDIR=""
pick_bindir() {
  local d
  if [[ -n $BINDIR_OVERRIDE ]]; then
    [[ -d $BINDIR_OVERRIDE && -w $BINDIR_OVERRIDE ]] || return 1
    BINDIR=$BINDIR_OVERRIDE; return 0
  fi
  for d in /usr/local/bin /usr/bin; do
    [[ -d $d && -w $d ]] && { BINDIR=$d; return 0; }
  done
  return 1
}

# 发行版判定。可用 DEGWD_FORCE_OS=debian|openwrt 强制指定分支:
#   - 少数系统两类特征同时存在(Kwrt 上跑 Debian chroot、OpenWrt 里装了 apt 的
#     旁路环境), 自动判定会走错分支, 此时手动指定即可;
#   - 端到端测试也依赖它 —— 否则测试机自身的特征会决定走哪条分支, 在 OpenWrt
#     上就永远测不到 Debian 分支。
is_openwrt() {
  case "${DEGWD_FORCE_OS:-}" in
    openwrt)      return 0 ;;
    debian|ubuntu) return 1 ;;
  esac
  [[ -f /etc/openwrt_release ]] || command -v opkg >/dev/null 2>&1
}

# OpenWrt 架构 → 统一标签(供 xray / sing-box 下载使用)
owrt_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   echo amd64 ;;
    aarch64|arm64)  echo arm64 ;;
    armv7l|armv7)   echo armv7 ;;
    armv6l)         echo armv6 ;;
    mips64*)        echo mips64 ;;
    mips*)          echo mips32 ;;
    *)              echo "" ;;
  esac
}

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  if is_openwrt; then
    echo -e "${CYAN}安装下载工具...${cRES}"
    opkg update >/dev/null 2>&1
    opkg install curl ca-bundle >/dev/null 2>&1 || die "curl 安装失败,请检查软件源"
  else
    command -v apt-get >/dev/null 2>&1 || die "未检测到 apt,本脚本仅支持 Debian / Ubuntu"
    echo -e "${CYAN}安装下载工具...${cRES}"
    apt-get update -qq
    apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || die "curl 安装失败,请检查软件源"
  fi
fi

# 多源下载: 官方 raw → ghproxy → jsdelivr (任一成功即可)
# DEGWD_RAW 被显式指定时只走该基址 —— 否则会绕过自建镜像去打 GitHub。
dl() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 60 -o "$out" "$url" 2>/dev/null && [[ -s $out ]] && return 0
    [[ $RAW_OVERRIDDEN -eq 1 ]] && return 1
    curl -fsSL --max-time 60 -o "$out" "https://ghproxy.net/$url" 2>/dev/null && [[ -s $out ]] && return 0
    curl -fsSL --max-time 60 -o "$out" "https://cdn.jsdelivr.net/gh/$REPO@$BRANCH/${url##*/}" 2>/dev/null && [[ -s $out ]] && return 0
  else
    wget -qO "$out" "$url" 2>/dev/null && [[ -s $out ]] && return 0
    [[ $RAW_OVERRIDDEN -eq 1 ]] && return 1
    wget -qO "$out" "https://ghproxy.net/$url" 2>/dev/null && [[ -s $out ]] && return 0
    wget -qO "$out" "https://cdn.jsdelivr.net/gh/$REPO@$BRANCH/${url##*/}" 2>/dev/null && [[ -s $out ]] && return 0
  fi
  return 1
}

# 下载并做完整性 + 内容校验
# 校验顺序: sha256 清单(强) → 体积下限 + 特征串(弱兜底)。
# 原实现只有 `grep -q '朔月\|Shuoyue\|xray'`, 任何含 "xray" 的页面(CDN 错误页、
# 被替换的中间人响应)都能通过; 清单由仓库内 SHA256SUMS 提供, 取不到时才降级。
SUMS=""
fetch_sums() {
  [[ -n $SUMS ]] && return 0
  local t; t=$(mktemp) || return 1
  if dl "$RAW/SHA256SUMS" "$t" && [[ -s $t ]]; then SUMS=$t; return 0; fi
  rm -f "$t"; return 1
}
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print$1}'
  elif command -v busybox >/dev/null 2>&1; then busybox sha256sum "$1" | awk '{print$1}'
  else openssl dgst -sha256 "$1" | awk '{print$NF}'; fi
}
dl_checked() {
  local name="$1" dest="$2" min="$3"
  dl "$RAW/$name" "$dest" || die "$name 下载失败(检查网络或稍后重试)"
  [[ $(du -sk "$dest" 2>/dev/null | awk '{print$1}') -ge "$min" ]] || die "$name 下载不完整"

  local want got
  if fetch_sums; then
    # 清单行格式: "<sha256>  <文件名>"; 只认精确文件名匹配(避免 index 式模糊命中)
    want=$(awk -v n="$name" '$2==n {print $1; exit}' "$SUMS")
    if [[ -n $want ]]; then
      got=$(sha256_of "$dest")
      if [[ "$got" != "$want" ]]; then
        die "$name sha256 校验失败(期望 ${want:0:16}..., 实际 ${got:0:16}...), 已中止"
      fi
      ok "$name sha256 校验通过 (${got:0:16}...)"
      return 0
    fi
    warn "$name 不在 SHA256SUMS 清单中, 退回特征串校验"
  else
    warn "SHA256SUMS 获取失败, 退回特征串校验(弱校验)"
  fi
  grep -q '朔月\|Shuoyue\|de_GWD' "$dest" || die "$name 下载内容校验失败,已中止"
}

# =============================================================================
#  OpenWrt / Kwrt 分支 —— 只提供客户端(旁路网关)
# =============================================================================
if is_openwrt; then
  OWARCH=$(owrt_arch)
  echo
  echo -e "${CYAN}=============================================${cRES}"
  echo -e "${WHITE}   朔月 Shuoyue — OpenWrt 旁路网关客户端${cRES}"
  echo -e "${CYAN}=============================================${cRES}"
  echo "  已检测到 OpenWrt / Kwrt (架构: ${OWARCH:-未知})"
  echo "  将安装客户端(procd 服务 + uci/dnsmasq 集成 + nft TPROXY)"
  echo "  服务端不适用于 OpenWrt,如需节点请另备一台 Debian/Ubuntu VPS"
  echo

  mkdir -p "$BASE"
  # client-openwrt 需要 bash(数组、[[ ]]、read -rp), 精简版 OpenWrt 只有 ash
  if ! command -v bash >/dev/null 2>&1; then
    echo -e "${CYAN}安装 bash (OpenWrt 精简版默认只有 ash)...${cRES}"
    opkg update >/dev/null 2>&1
    opkg install bash >/dev/null 2>&1 || die "bash 安装失败,请检查软件源(或手动 opkg install bash)"
  fi
  echo -n "下载客户端脚本... "
  dl_checked client-openwrt "$BASE/client-openwrt" 30
  chmod +x "$BASE/client-openwrt"
  echo -e "${GREEN}OK${cRES} ($(du -sk "$BASE/client-openwrt" | awk '{print$1}') KB)"
  dl "$RAW/version" "$BASE/version" 2>/dev/null

  pick_bindir || die "/usr/bin 不可写,无法创建命令"
  ln -sf "$BASE/client-openwrt" "$BINDIR/shuoyue-gw"
  ok "已安装命令: shuoyue-gw ($BINDIR/shuoyue-gw)"
  warn "OpenWrt 的 /opt 位于 overlayfs,sysupgrade 前请执行 sysupgrade -b 备份"

  echo
  read -rp "现在开始安装并初始化? [Y/n]: " a; a=${a:-y}
  [[ $a == [Yy] ]] || { ok "完成。以后输入 shuoyue-gw 打开菜单。"; exit 0; }
  exec bash "$BASE/client-openwrt" --install
fi

# =============================================================================
#  Debian / Ubuntu 分支 —— 服务端 + 客户端
# =============================================================================
command -v apt-get >/dev/null 2>&1 || die "未检测到 apt,本脚本仅支持 Debian / Ubuntu 与 OpenWrt"
ARCH=$(dpkg --print-architecture 2>/dev/null)
[[ "$ARCH" != "amd64" && "$ARCH" != "arm64" ]] && die "不支持的架构: ${ARCH:-未知}(仅 amd64/arm64)"

# 快速卸载入口：若传入 del / uninstall / --uninstall 直接执行彻底清理
if [[ "${1:-}" =~ ^(--uninstall|uninstall|del)$ ]]; then
  if [[ -x "$BASE/server" ]]; then
    shift
    exec bash "$BASE/server" --uninstall "$@"
  elif [[ -x "$BASE/client" ]]; then
    shift
    exec bash "$BASE/client" --uninstall "$@"
  else
    mkdir -p "$BASE"
    echo -n "下载卸载脚本... "
    dl_checked server "$BASE/server" 30
    chmod +x "$BASE/server"
    echo -e "${GREEN}OK${cRES}"
    shift
    exec bash "$BASE/server" --uninstall "$@"
  fi
fi

echo
echo -e "${CYAN}=============================================${cRES}"
echo -e "${WHITE}   朔月 Shuoyue — Debian 多协议旁路网关${cRES}"
echo -e "${CYAN}=============================================${cRES}"
echo "  服务端: vmess / vless / trojan / Reality / SS / Hysteria2 / TUIC / AnyTLS"
echo "          + DoH + 订阅 + WARP + CAKE 流量整形, 分享链接兼容 v2rayN 7.x"
echo

mkdir -p "$BASE"
echo -n "下载主脚本... "
dl_checked server "$BASE/server" 30
chmod +x "$BASE/server"
echo -e "${GREEN}OK${cRES} ($(du -sk "$BASE/server" | awk '{print$1}') KB)"
dl "$RAW/version" "$BASE/version" 2>/dev/null
# panel.py 也在 SHA256SUMS 清单里, 同样走强校验(原来是裸 dl, 唯一漏检的产物)
echo -n "下载 Web 面板... "
dl_checked panel.py "$BASE/panel.py" 10
chmod 755 "$BASE/panel.py"
echo -e "${GREEN}OK${cRES} ($(du -sk "$BASE/panel.py" | awk '{print$1}') KB)"

pick_bindir || die "/usr/bin 不可写,无法创建命令"
ln -sf "$BASE/server" "$BINDIR/shuoyue"
ok "已安装命令: shuoyue (以后随时输入即可打开管理菜单)"

has_installed=0
cur_ver=""
if [[ -f "$BASE/conf.json" || -f "$BASE/server" ]]; then
  has_installed=1
  [[ -f "$BASE/version" ]] && cur_ver=$(head -n1 "$BASE/version" 2>/dev/null)
fi

if [[ "${1:-}" == "--update" || "${1:-}" == "-u" ]]; then
  c=4
else
  echo
  if [[ $has_installed -eq 1 ]]; then
    echo -e "${GREEN}★ 检测到本机已安装 朔月 Shuoyue${cur_ver:+ ($cur_ver)}${cRES}"
    echo "  已安装环境推荐选择 [4] 直接升级，将无损保留您的所有节点与配置。"
    echo
  fi
  echo "请选择操作目标:"
  echo "  [1] 服务端全新安装 — 部署 Web 控制面板，通过网页 GUI 勾选并安装 19 种协议"
  echo "  [2] 客户端 — 家里闲置设备做旁路网关,其他设备把网关指向它"
  echo "  [3] 退出(以后输入 shuoyue 打开菜单)"
  echo "  [4] 升级更新 — 直接升级服务端核心、Web 控制面板及后续新增功能与修复补丁"
  echo "  [5] 彻底卸载 — 清理所有协议服务、证书、自建防火墙规则、Web 面板及配置文件"
  if [[ $has_installed -eq 1 ]]; then
    read -rp "选择 [1/2/3/4/5, 已安装推荐 4, 回车=4]: " c; c=${c:-4}
  else
    read -rp "选择 [1/2/3/4/5, 回车=1]: " c; c=${c:-1}
  fi
fi

case $c in
  2)
    echo -n "下载客户端脚本... "
    dl_checked client "$BASE/client" 30
    chmod +x "$BASE/client"
    ln -sf "$BASE/client" "$BINDIR/shuoyue-gw"
    ok "已安装命令: shuoyue-gw"
    clear
    exec bash "$BASE/client" --install
    ;;
  3)
    ok "完成。输入 shuoyue 打开菜单。"
    exit 0
    ;;
  4|[Uu]|[Uu][Pp][Dd][Aa][Tt][Ee])
    clear
    exec bash "$BASE/server" --update
    ;;
  5|[Uu][Nn][Ii][Nn][Ss][Tt][Aa][Ll][Ll]|[Dd][Ee][Ll])
    clear
    exec bash "$BASE/server" --uninstall
    ;;
  *)
    clear
    exec bash "$BASE/server" --install
    ;;
esac
