#!/bin/bash
# =============================================================================
#  朔月 Shuoyue — 一键安装引导脚本
#  用法(一键):
#    bash <(curl -fsSL https://raw.githubusercontent.com/zhengwuji/shuoyue-xray/main/install.sh)
#  仅支持 Debian / Ubuntu (amd64/arm64)。
#  安装完成后自动打印节点地址、订阅地址与 v2rayN 导入二维码。
# =============================================================================
RED='\E[1;31m'; GREEN='\E[1;32m'; YELLOW='\E[1;33m'; CYAN='\E[1;36m'; WHITE='\E[1;37m'; cRES='\E[0m'
REPO="zhengwuji/shuoyue-xray"
BRANCH="main"
RAW="https://raw.githubusercontent.com/$REPO/$BRANCH"
BASE=/opt/de_GWD

ok()   { echo -e "${WHITE}[ ${GREEN}✓${WHITE} ]${cRES} $*"; }
warn() { echo -e "${WHITE}[ ${YELLOW}!${WHITE} ]${cRES} $*"; }
die()  { echo -e "${WHITE}[ ${RED}✕${WHITE} ]${cRES} $*"; exit 1; }

[[ $(id -u) -ne 0 ]] && die "请以 root 运行(VPS 默认就是 root;sudo 用户先 sudo -i)"
command -v apt-get >/dev/null 2>&1 || die "未检测到 apt,本脚本仅支持 Debian / Ubuntu"
ARCH=$(dpkg --print-architecture 2>/dev/null)
[[ "$ARCH" != "amd64" && "$ARCH" != "arm64" ]] && die "不支持的架构: ${ARCH:-未知}(仅 amd64/arm64)"

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
  echo -e "${CYAN}安装下载工具...${cRES}"
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || die "curl 安装失败,请检查软件源"
fi

# 多源下载: 官方 raw → ghproxy → jsdelivr (任一成功即可)
dl() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 60 -o "$out" "$url" 2>/dev/null && [[ -s $out ]] && return 0
    curl -fsSL --max-time 60 -o "$out" "https://ghproxy.net/$url" 2>/dev/null && [[ -s $out ]] && return 0
    curl -fsSL --max-time 60 -o "$out" "https://cdn.jsdelivr.net/gh/$REPO@$BRANCH/${url##*/}" 2>/dev/null && [[ -s $out ]] && return 0
  else
    wget -qO "$out" "$url" 2>/dev/null && [[ -s $out ]] && return 0
    wget -qO "$out" "https://ghproxy.net/$url" 2>/dev/null && [[ -s $out ]] && return 0
    wget -qO "$out" "https://cdn.jsdelivr.net/gh/$REPO@$BRANCH/${url##*/}" 2>/dev/null && [[ -s $out ]] && return 0
  fi
  return 1
}

echo
echo -e "${CYAN}=============================================${cRES}"
echo -e "${WHITE}   朔月 Shuoyue — Debian 多协议旁路网关${cRES}"
echo -e "${CYAN}=============================================${cRES}"
echo "  服务端: vmess / vless / trojan / Reality / SS / Hysteria2 / TUIC / AnyTLS"
echo "          + DoH + 订阅 + WARP + CAKE 流量整形, 分享链接兼容 v2rayN 7.x"
echo

mkdir -p "$BASE"
echo -n "下载主脚本... "
dl "$RAW/server" "$BASE/server" || die "server 下载失败(检查网络或稍后重试)"
[[ $(du -sk "$BASE/server" | awk '{print$1}') -ge 30 ]] || die "server 下载不完整"
grep -q '朔月\|Shuoyue\|xray' "$BASE/server" || die "下载内容校验失败,已中止"
chmod +x "$BASE/server"
echo -e "${GREEN}OK${cRES} ($(du -sk "$BASE/server" | awk '{print$1}') KB)"
dl "$RAW/version" "$BASE/version" 2>/dev/null

ln -sf "$BASE/server" /usr/local/bin/shuoyue
ok "已安装命令: shuoyue (以后随时输入即可打开管理菜单)"

echo
echo "请选择安装目标:"
echo "  [1] 服务端 — VPS 出口节点,装完直接打印 节点地址/订阅/二维码  ← 推荐"
echo "  [2] 客户端 — 家里闲置设备做旁路网关,其他设备把网关指向它"
echo "  [3] 退出(以后输入 shuoyue 打开菜单)"
read -rp "选择 [1/2/3, 回车=1]: " c; c=${c:-1}
case $c in
  2)
    echo -n "下载客户端脚本... "
    dl "$RAW/client" "$BASE/client" || die "client 下载失败"
    [[ $(du -sk "$BASE/client" | awk '{print$1}') -ge 30 ]] || die "client 下载不完整"
    chmod +x "$BASE/client"
    ln -sf "$BASE/client" /usr/local/bin/shuoyue-gw
    ok "已安装命令: shuoyue-gw"
    clear
    exec bash "$BASE/client" --install
    ;;
  3)
    ok "完成。输入 shuoyue 打开菜单。"
    exit 0
    ;;
  *)
    clear
    exec bash "$BASE/server" --install
    ;;
esac
