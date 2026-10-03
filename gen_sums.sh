#!/bin/bash
# 生成仓库根目录的 SHA256SUMS(供 install.sh 强校验下载内容)。
# 只登记"会被 install.sh 下载并执行"的产物; install.sh 自身与 version 不登记
# (自校验无意义, version 只有几个字节)。
# 注意: 必须在 LF 工作区生成 —— Git 的 text=auto 会把文件规范化成 LF,
# raw.githubusercontent 提供的正是规范化后的内容, 与本地 LF 文件一致。
# 放在仓库根(而非 .probe/, 那个目录被 .gitignore 忽略)是为了让它随仓库分发。
# 兼容性: 只用 POSIX 工具, 不用 GNU 专有选项(真机可能是 BusyBox)。
set -uo pipefail
cd "$(dirname "$0")" || exit 1

FILES=(server client client-openwrt panel.py)

# 计算单个文件的 sha256; 三级兜底, 与 install.sh 的 sha256_of() 保持同序
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    # 不用 `--text`: BusyBox 的 sha256sum 没有该选项(GNU 专有), 会直接报错。
    # 改用 sed 去掉 Windows sha256sum 的二进制标记 "*file" —— 它会破坏
    # install.sh 里 `$2==n` 的精确文件名匹配。
    sha256sum "$1" | sed 's/\*\(.*\)$/ \1/' | awk '{print$1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print$NF}'
  else
    echo "错误: 缺少 sha256sum 与 openssl" >&2; return 1
  fi
}

# 统计 CR 字节数(比 `grep -qU $'\r'` 可移植: BusyBox grep 不保证有 -U)
has_cr() { [[ $(tr -cd '\r' < "$1" | wc -c | tr -d ' ') -gt 0 ]]; }

tmp=$(mktemp) || exit 1
for f in "${FILES[@]}"; do
  [[ -f $f ]] || { echo "缺少文件: $f" >&2; rm -f "$tmp"; exit 1; }
  # 拒绝 CRLF: 会让 Linux 端 sha256 与清单不符
  if has_cr "$f"; then
    echo "错误: $f 含 CRLF 行尾, 请先转成 LF" >&2; rm -f "$tmp"; exit 1
  fi
  h=$(sha256_of "$f") || { rm -f "$tmp"; exit 1; }
  printf '%s  %s\n' "$h" "$f"
done > "$tmp" || { rm -f "$tmp"; exit 1; }

# 排序保证幂等(避免因数组顺序调整产生无意义 diff)
sort -k2 "$tmp" -o SHA256SUMS
rm -f "$tmp"
echo "已生成 SHA256SUMS:"
cat SHA256SUMS
