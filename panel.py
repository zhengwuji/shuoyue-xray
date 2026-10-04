#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""朔月 Shuoyue / de_GWD —— 单文件标准库 Web 面板。

只依赖 Python3 标准库，由 systemd 以 root 运行，默认监听 0.0.0.0:3000，
由 nginx 反向代理暴露在 https://<域名>/<随机路径段>/ 之下。

面板本身不实现任何代理逻辑，只通过 subprocess 调用
``bash <BASE>/server --cli <子命令>`` 并解析其 stdout。

CLI 契约（由主脚本 server 提供，本文件只消费）::

    --cli status              输出 status JSON
    --cli protos "a b c"      设置协议集合，输出 status JSON
    --cli links               每行一条纯文本分享链接
    --cli regen               重建配置 + 订阅，输出 status JSON
    --cli reset               重置 UUID/Path/token，输出 status JSON
    --cli cfg '<json>'        局部更新配置，输出 status JSON

命令行::

    python3 panel.py                 前台运行
    python3 panel.py --print-config  打印 PANEL_TOKEN/PANEL_PATH/PANEL_BIND/PANEL_PORT
    python3 panel.py --check         自检：读 conf.json + 调一次 --cli status
"""

import argparse
import base64
import glob
import gzip
import hmac
import http.cookies
import http.server
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

# --------------------------------------------------------------------- 常量 ---
# 基础目录不写死，便于本地调试；部署时保持默认 /opt/de_GWD
BASE = os.environ.get("DEGWD_BASE", "/opt/de_GWD")
SERVER = os.path.join(BASE, "server")
CONF = os.path.join(BASE, "conf.json")

# 调用 server 的超时（秒），regen/protos/cfg 可能较慢
CLI_TIMEOUT = int(os.environ.get("DEGWD_PANEL_TIMEOUT", "180"))
# 请求体上限 256 KiB
MAX_BODY = 256 * 1024
# 提前报错时最多再读这么多字节以保持 keep-alive 连接对齐，超过则直接断连
MAX_DRAIN = 64 * 1024
# stdout/stderr 回传前端的截断长度
CLIP = 8000
# 所有对 server 的调用串行化，避免并发重建配置
CLI_LOCK = threading.Lock()
# 合法的协议 id 字符集
PROTO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# 域名 / 主机:端口
HOSTPORT_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}(?::[0-9]{1,5})?$")
# 纯主机名（Reality SNI，不带端口）
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
# CDN 优选 IP / 落地域名（与 server cli_cfg 的 upip 校验保持一致）
UPIP_RE = re.compile(r"^[A-Za-z0-9.:\-]{1,253}$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# 节点名前缀：允许中文等可见字符，仅拒绝控制字符，长度上限 32
PREFIX_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,32}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
# ANSI 颜色码
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# 协议清单：必须与 server 的 PROTO_TABLE 完全一致（id/名称/内核/端口/是否需域名）
# 运行时若 server --cli status 返回 protolist，则以其为准覆盖本表。
PROTOCOLS = [
    # ---- Xray 内核 ----
    {"id": "vmess", "name": "Vmess-ws", "group": "xray", "port": "443(nginx)", "needs_domain": True},
    {"id": "vless", "name": "Vless-ws-tls", "group": "xray", "port": "443(nginx)", "needs_domain": True},
    {"id": "trojan", "name": "Trojan-ws-tls", "group": "xray", "port": "443(nginx)", "needs_domain": True},
    {"id": "wsenc", "name": "Vless-ws-enc", "group": "xray", "port": "443(nginx)", "needs_domain": True},
    {"id": "trojanws", "name": "Trojan-ws", "group": "xray", "port": "443(nginx)", "needs_domain": True},
    {"id": "trojantcp", "name": "Trojan-tcp-tls", "group": "xray", "port": "8442", "needs_domain": True},
    {"id": "reality", "name": "Vless-tcp-reality-vision", "group": "xray", "port": "8443", "needs_domain": False},
    {"id": "xhttptls", "name": "Vless-xhttp-tls-TCP/UDP", "group": "xray", "port": "8448", "needs_domain": True},
    {"id": "xhttpupip", "name": "Vless-xhttp-tls-UpIP", "group": "xray", "port": "8448", "needs_domain": True},
    {"id": "xhttpenc", "name": "Vless-xhttp-enc", "group": "xray", "port": "8449", "needs_domain": True},
    {"id": "realityxhttp", "name": "Vless-xhttp-reality-enc", "group": "xray", "port": "8450", "needs_domain": False},
    {"id": "ss", "name": "Shadowsocks-2022(xray)", "group": "xray", "port": "8388", "needs_domain": False},
    {"id": "socks5", "name": "Socks5", "group": "xray", "port": "1080", "needs_domain": False},
    # ---- Sing-box 内核 ----
    {"id": "hy2", "name": "Hysteria2", "group": "singbox", "port": "8444/udp", "needs_domain": False},
    {"id": "tuic", "name": "Tuic", "group": "singbox", "port": "8445/udp", "needs_domain": False},
    {"id": "anytls", "name": "AnyTLS", "group": "singbox", "port": "8446", "needs_domain": False},
    {"id": "naive", "name": "Naiveproxy", "group": "singbox", "port": "8447", "needs_domain": True},
    {"id": "anyreality", "name": "Any reality", "group": "singbox", "port": "8451", "needs_domain": False},
    {"id": "sssb", "name": "Shadowsocks-2022(sing-box)", "group": "singbox", "port": "8452", "needs_domain": False},
]
PROTO_IDS = {p["id"] for p in PROTOCOLS}


def merge_protolist(protolist):
    """用 server 返回的 protolist 覆盖本地清单（server 是单一事实来源）。"""
    global PROTOCOLS, PROTO_IDS
    if not isinstance(protolist, list):
        return
    items = []
    for p in protolist:
        if not isinstance(p, dict) or not p.get("id"):
            continue
        pid = str(p["id"])
        if not PROTO_ID_RE.match(pid):
            continue
        items.append({
            "id": pid,
            "name": str(p.get("name") or pid),
            "group": "xray" if p.get("kernel") == "xray" else "singbox",
            "port": str(p.get("port") or ""),
            "needs_domain": bool(p.get("needs_domain")),
            "desc": str(p.get("desc") or ""),
        })
    if items:
        PROTOCOLS = items
        PROTO_IDS = {p["id"] for p in items}


# ------------------------------------------------------------------ 日志工具 ---
def _log(msg):
    """把日志写到 stderr（systemd journal）。"""
    sys.stderr.write("%s %s\n" % (time.strftime("[%Y-%m-%d %H:%M:%S]"), msg))
    sys.stderr.flush()


def _clip(text, limit=CLIP):
    """截断过长文本，保留首尾以便定位错误。"""
    if not text:
        return ""
    if len(text) <= limit:
        return text
    half = limit // 2
    return "%s\n…（中间省略 %d 字符）…\n%s" % (text[:half], len(text) - limit, text[-half:])


def _strip_ansi(text):
    """去掉 ANSI 颜色码。"""
    return ANSI_RE.sub("", text or "")


# -------------------------------------------------------- 外部代理链接提取 ---
def _get_wan_ip():
    """获取本机出口公网 IP，用于逆向构造第三方代理分享链接。"""
    try:
        req = urllib.request.Request(
            "https://api.ipify.org", headers={"User-Agent": "curl/7.88.1"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            ip = resp.read().decode("utf-8").strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "1.1.1.1"], text=True, stderr=subprocess.DEVNULL
        )
        m = re.search(r"src\s+([0-9.]+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "127.0.0.1"


def extract_third_party_links(conf_path="", exe_path="", pid=None):
    """提取检测到的第三方代理服务端原始 v2rayN 节点分享链接。

    策略：
    1. 优先在进程运行目录、配置文件所在目录检索已导出的节点文本文件（如 jhsub.txt / sub.txt / links.txt 等）；
    2. 若未找到文本链接文件，则解析其 JSON 配置文件（如 xr.json / config.json），
       逆向提取 Reality / SS / Trojan / VMess 等入站配置并计算 X25519 公钥还原标准 v2rayN 链接。
    """
    links = []
    seen = set()

    def add_link(l):
        l = l.strip()
        if l and l not in seen and re.match(r"^[a-zA-Z0-9]+://", l):
            seen.add(l)
            links.append(l)

    # 1. 搜集候选目录
    candidate_dirs = []
    if conf_path and os.path.exists(conf_path):
        candidate_dirs.append(os.path.dirname(os.path.abspath(conf_path)))
    if exe_path and os.path.exists(exe_path):
        candidate_dirs.append(os.path.dirname(os.path.abspath(exe_path)))
    if pid:
        try:
            cwd = os.readlink("/proc/%s/cwd" % pid)
            if os.path.isdir(cwd):
                candidate_dirs.append(cwd)
        except Exception:
            pass

    # 常见外部代理常用部署目录
    candidate_dirs.extend(["/root/agsbx", "/root", "/etc/xray", "/etc/v2ray", "/etc/sing-box"])

    unique_dirs = []
    for d in candidate_dirs:
        if d and os.path.isdir(d) and d not in unique_dirs:
            unique_dirs.append(d)

    # 2. 检索已知文本链接文件
    known_filenames = [
        "jhsub.txt", "sub.txt", "links.txt", "link.txt", "v2ray.txt", "nodes.txt",
        "subscribe.txt", "sub_list.txt", "url.txt", "urls.txt", "xray.txt"
    ]
    for d in unique_dirs:
        for fname in known_filenames:
            fpath = os.path.join(d, fname)
            if os.path.isfile(fpath) and os.path.getsize(fpath) < 2 * 1024 * 1024:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                        for line in fp:
                            line = line.strip()
                            if re.match(r"^(vless|vmess|trojan|ss|hy2|hysteria2|tuic)://", line, re.I):
                                add_link(line)
                except Exception:
                    pass

        if not links:
            for fpath in glob.glob(os.path.join(d, "*.txt")):
                if os.path.getsize(fpath) < 1024 * 1024:
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                            for line in fp:
                                line = line.strip()
                                if re.match(r"^(vless|vmess|trojan|ss|hy2|hysteria2|tuic)://", line, re.I):
                                    add_link(line)
                    except Exception:
                        pass
        if links:
            break

    # 3. 若无文本文件，尝试从配置文件逆向还原
    if not links and conf_path and os.path.isfile(conf_path):
        try:
            with open(conf_path, "r", encoding="utf-8", errors="ignore") as fp:
                cdata = json.load(fp)
            wan_ip = _get_wan_ip()
            inbounds = cdata.get("inbounds", [])
            if isinstance(cdata.get("inbound"), dict):
                inbounds.append(cdata["inbound"])

            for inb in inbounds:
                proto = (inb.get("protocol") or inb.get("type") or "").lower()
                port = inb.get("port") or inb.get("listen_port")
                tag = inb.get("tag") or proto
                stream = inb.get("streamSettings") or inb.get("tls") or {}
                sec = stream.get("security", "")

                if proto == "vless" and (sec == "reality" or "reality" in inb):
                    r_settings = stream.get("realitySettings") or inb.get("reality", {})
                    priv_key = r_settings.get("privateKey", "")
                    pbk = ""
                    if priv_key:
                        candidates = [exe_path, "xray", "/usr/local/bin/xray", "/usr/bin/xray", "/root/agsbx/xray"]
                        for xc in candidates:
                            if xc and (os.path.exists(xc) or shutil.which(xc)):
                                try:
                                    out = subprocess.check_output(
                                        [xc, "x25519", "-i", priv_key], text=True, stderr=subprocess.DEVNULL
                                    )
                                    m = re.search(r"(?:Public key|PublicKey|Password \(PublicKey\)):\s*([^\s]+)", out, re.I)
                                    if m:
                                        pbk = m.group(1).strip()
                                        break
                                except Exception:
                                    pass

                    clients = inb.get("settings", {}).get("clients", [])
                    uuid_str = clients[0].get("id", "") if clients else ""
                    flow = clients[0].get("flow", "") if clients else ""
                    snis = r_settings.get("serverNames", [""])
                    sni = snis[0] if snis else ""
                    sids = r_settings.get("shortIds", [""])
                    sid = sids[0] if sids else ""
                    net = stream.get("network", "tcp")
                    if uuid_str and port and pbk:
                        flow_str = ("&flow=%s" % flow) if flow else ""
                        link = ("vless://%s@%s:%s?security=reality&encryption=none&pbk=%s&headerType=none"
                                "&fp=chrome&type=%s%s&sni=%s&sid=%s#%s" %
                                (uuid_str, wan_ip, port, pbk, net, flow_str, sni, sid, tag))
                        add_link(link)
                elif proto in ("shadowsocks", "ss"):
                    settings = inb.get("settings", inb)
                    method = settings.get("method", "")
                    pwd = settings.get("password", "")
                    if method and pwd and port:
                        b64_cred = base64.b64encode(("%s:%s" % (method, pwd)).encode()).decode()
                        link = "ss://%s@%s:%s#%s" % (b64_cred, wan_ip, port, tag)
                        add_link(link)
                elif proto == "trojan":
                    clients = inb.get("settings", {}).get("clients", [])
                    pwd = clients[0].get("password", "") if clients else inb.get("password", "")
                    if pwd and port:
                        link = "trojan://%s@%s:%s#%s" % (pwd, wan_ip, port, tag)
                        add_link(link)
        except Exception:
            pass

    return links


# -------------------------------------------------------------- conf.json IO ---
def _read_conf():
    """读取 conf.json；不存在或损坏时返回空字典。"""
    try:
        with open(CONF, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # 损坏的 JSON 不致命，退化为空字典
        _log("读取 %s 失败: %s" % (CONF, exc))
        return {}


def _write_conf_atomic(data):
    """读-改-写：先写同目录临时文件再原子替换，保持 600 权限。"""
    directory = os.path.dirname(CONF) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, ".conf.json.tmp.%d" % os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False, indent=2)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, CONF)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        os.chmod(CONF, 0o600)
    except OSError:
        pass


def _rand_path():
    """生成随机路径段（小写字母 + 数字，10 位）。"""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(10))


def ensure_panel_secrets():
    """确保 conf.json 中有 .panel.token / .panel.path / .panel.port，返回 (token, path, port)。

    环境变量 DEGWD_PANEL_TOKEN 存在时覆盖 token（此时不把环境变量写回 conf.json）。
    """
    conf = _read_conf()
    panel = conf.get("panel")
    if not isinstance(panel, dict):
        panel = {}
    dirty = False

    token = str(panel.get("token") or "").strip()
    if not TOKEN_RE.match(token):
        token = secrets.token_urlsafe(24)
        panel["token"] = token
        dirty = True

    path = str(panel.get("path") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", path or ""):
        path = _rand_path()
        panel["path"] = path
        dirty = True

    port_val = panel.get("port")
    valid_port = False
    if port_val is not None:
        try:
            p_int = int(port_val)
            if 1 <= p_int <= 65535:
                valid_port = True
        except (ValueError, TypeError):
            valid_port = False

    if not valid_port:
        import random, socket
        reserved = {53, 80, 443, 1080, 3000, 8388, 8442, 8443, 8444, 8445, 8446, 8447, 8448, 8449, 8450, 8451, 8452, 9853, 9890, 9891, 9892, 9893, 9894, 9895, 9896, 51820}
        found = None
        for _ in range(100):
            cand = random.randint(10000, 60000)
            if cand in reserved:
                continue
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", cand))
                    found = cand
                    break
            except Exception:
                continue
        panel["port"] = found or random.randint(20000, 50000)
        dirty = True

    if dirty:
        conf["panel"] = panel
        try:
            _write_conf_atomic(conf)
        except Exception as exc:
            _log("写入 %s 失败（面板仍可运行，但重启后 token/port 会变化）: %s" % (CONF, exc))

    env_token = (os.environ.get("DEGWD_PANEL_TOKEN") or "").strip()
    if env_token:
        token = env_token
    return token, path, panel.get("port")


# --------------------------------------------------------------- server 调用 ---
def _extract_json(text):
    """从可能夹杂日志行的 stdout 中提取完整 JSON 对象。

    注意不能简单「从后往前找第一个可解析的 ``{``」——那样会命中嵌套的
    内层对象（例如 ``{...,"svc":{"xray":"active"}}`` 会只取到 ``svc``）。
    这里复用 ``_extract_json_any`` 的「结束位置最靠后」策略：外层对象
    总是最晚结束，因此会被优先选中。
    """
    value = _extract_json_any(text)
    return value if isinstance(value, dict) else None


def _extract_json_any(text):
    """从混杂日志的 stdout 中提取最后一个完整 JSON 值（对象或数组）。

    与 _extract_json 的区别：本函数同时接受数组（例如新版 ``--cli links``
    直接输出 ``[{...},{...}]``）。策略是扫描所有 ``{`` / ``[`` 起点做
    raw_decode，取「结束位置最靠后」的那个成功结果。
    """
    if not text:
        return None
    decoder = json.JSONDecoder()
    best = None
    best_end = -1
    for idx, ch in enumerate(text):
        if ch not in "{[":
            continue
        try:
            value, end = decoder.raw_decode(text, idx)
        except Exception:
            continue
        if end > best_end:
            best, best_end = value, end
    return best


def _quote(arg):
    """把参数渲染成可读的命令行片段（仅用于展示）。"""
    if arg == "" or re.search(r"[\s'\"$`\\|&;<>()*?]", arg):
        return "'" + arg.replace("'", "'\\''") + "'"
    return arg


def run_cli(args, timeout=None, stdin_data=None):
    """串行化执行 server 的 --cli 子命令，返回统一结果字典。

    stdin_data 非空时通过标准输入传递，用于承载 JSON 之类的复杂参数：
    某些环境（如 Windows 上的 MSYS/Git Bash）会改写命令行里不含空格的
    ``{"k":"v"}`` 这类参数，走 stdin 可以彻底绕开命令行转义问题。
    """
    timeout = timeout or CLI_TIMEOUT
    argv = ["bash", SERVER, "--cli"] + [str(a) for a in args]
    result = {
        "ok": False,
        "code": None,
        "cmd": " ".join(_quote(a) for a in argv),
        "stdout": "",
        "stderr": "",
        "data": None,
        "ms": 0,
        "timeout": False,
    }
    if not os.path.exists(SERVER):
        result["code"] = 127
        result["stderr"] = "找不到主脚本: %s" % SERVER
        return result

    started = time.time()
    with CLI_LOCK:  # 一把锁：任何时刻只允许一个重建配置的进程
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=BASE if os.path.isdir(BASE) else None,
                input=stdin_data,
            )
            result["code"] = proc.returncode
            result["stdout"] = proc.stdout or ""
            result["stderr"] = proc.stderr or ""
            result["ok"] = proc.returncode == 0
        except subprocess.TimeoutExpired:
            result["code"] = 124
            result["timeout"] = True
            result["stderr"] = "执行超时（超过 %d 秒），操作可能仍在后台进行" % timeout
        except Exception as exc:
            result["code"] = 1
            result["stderr"] = "执行异常: %s: %s" % (type(exc).__name__, exc)
    result["ms"] = int((time.time() - started) * 1000)
    result["data"] = _extract_json(result["stdout"])
    return result


def cli_payload(result, extra=None):
    """把 run_cli 结果包装成前端统一消费的 JSON 响应体。"""
    payload = {
        "ok": bool(result["ok"]),
        "code": result["code"],
        "cmd": result["cmd"],
        "ms": result["ms"],
        "timeout": result["timeout"],
        "stdout": _clip(result["stdout"]),
        "stderr": _clip(result["stderr"]),
        "data": result["data"],
    }
    if isinstance(result["data"], dict):
        # 兼容：同时把 status 字段平铺到顶层（installed/links/protos/...）
        for key, value in result["data"].items():
            payload.setdefault(key, value)
    if extra:
        payload.update(extra)
    return payload


def error_payload(message, stderr=""):
    """构造统一的失败响应体。"""
    return {"ok": False, "error": message, "stderr": _clip(stderr)}


def _normalize_links(items):
    """把 status 里的 links 数组规整为前端统一的字段集合。"""
    links = []
    for item in items or []:
        if not isinstance(item, dict) or not item.get("link"):
            continue
        links.append({
            "id": str(item.get("id") or ""),
            "name": str(item.get("name") or ""),
            "link": str(item.get("link")),
            "port": item.get("port", ""),
            "needs_domain": bool(item.get("needs_domain", False)),
        })
    return links


def _parse_links_output(stdout):
    """解析 ``--cli links`` 的输出，兼容 JSON 数组与逐行纯文本两种格式。"""
    text = _strip_ansi(stdout or "")
    if not text.strip():
        return []
    # 新版 server 直接输出 JSON 数组（元素含 id/name/link/port/needs_domain）
    data = _extract_json_any(text)
    if isinstance(data, list):
        return _normalize_links(data)
    if isinstance(data, dict) and isinstance(data.get("links"), list):
        return _normalize_links(data["links"])
    # 旧版 / 兜底：每行一条纯文本分享链接
    links = []
    for line in text.splitlines():
        line = line.strip()
        if "://" in line:
            links.append({"id": "", "name": "", "link": line,
                          "port": "", "needs_domain": False})
    return links


# -------------------------------------------------------------------- HTML ---
PAGE_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>朔月 de_GWD 控制面板</title>
<style>
*{box-sizing:border-box}
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1b2230;--fg:#e6edf3;--dim:#8b949e;
--acc:#4c8dff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--bd:#2d333b;--r:10px}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);padding:16px;
font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans CJK SC","Microsoft YaHei",sans-serif;
-webkit-text-size-adjust:100%}
header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;
max-width:1280px;margin:0 auto 16px}
h1{font-size:18px;margin:0;display:flex;align-items:center;gap:8px}
h2{font-size:15px;margin:0 0 12px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
h3{font-size:13px;color:var(--dim);margin:14px 0 8px;display:flex;gap:8px;align-items:center}
main{max-width:1280px;margin:0 auto;display:flex;flex-direction:column;gap:16px}
section{background:var(--panel);border:1px solid var(--bd);border-radius:var(--r);padding:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}
.card{border:1px solid var(--bd);border-radius:8px;padding:10px;background:var(--panel2)}
.proto{display:flex;gap:10px;align-items:flex-start;cursor:pointer;user-select:none;transition:border-color .15s,box-shadow .15s,background .15s}
.proto:hover{border-color:var(--acc)}
.proto.on{border-color:var(--acc);box-shadow:inset 0 0 0 1px rgba(76,141,255,.25)}
.proto.installed{border-color:rgba(46,160,67,0.7);background:linear-gradient(135deg,rgba(46,160,67,0.12) 0%,rgba(22,27,34,0.95) 100%);box-shadow:0 0 10px rgba(46,160,67,0.2)}
.proto.installed:hover{border-color:#3fb950;box-shadow:0 0 14px rgba(46,160,67,0.35)}
.proto.installed.on{border-color:#3fb950;box-shadow:0 0 16px rgba(46,160,67,0.35),inset 0 0 0 1px rgba(46,160,67,0.5)}
.proto.installed input{accent-color:#3fb950}
.tag.installed-badge{background:rgba(46,160,67,0.18);border-color:#2ea043;color:#3fb950;font-weight:600;display:inline-flex;align-items:center;gap:4px}
.pname{font-weight:600;word-break:break-word}
.pid{display:block;color:var(--dim);font-size:12px;margin:2px 0 6px;word-break:break-all}
.meta{display:flex;flex-wrap:wrap;gap:6px}
.tag{font-size:11px;padding:1px 7px;border-radius:20px;background:#21262d;color:var(--dim);
border:1px solid var(--bd);white-space:nowrap}
.tag.ok{color:var(--ok);border-color:#1f4527}
.tag.warn{color:var(--warn);border-color:#4a3a12}
.tag.err{color:var(--err);border-color:#5a1f1c}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
button{font:inherit;color:var(--fg);background:#21262d;border:1px solid var(--bd);
border-radius:8px;padding:7px 12px;cursor:pointer}
button:hover:not(:disabled){border-color:var(--acc)}
button:disabled{opacity:.5;cursor:not-allowed}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff}
button.ok{background:#1f6f36;border-color:#1f6f36;color:#fff}
button.danger{background:#da3633;border-color:#f85149;color:#fff}
button.danger:hover:not(:disabled){background:#b62324;border-color:#ff7b72}
button.mini{padding:2px 9px;font-size:12px;border-radius:6px}
.proto-actions-bar{margin-top:14px;padding:12px 14px;background:rgba(255,255,255,0.02);border:1px solid var(--bd);border-radius:8px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.form{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.field{display:flex;flex-direction:column;gap:5px}
.field>label{font-size:12px;color:var(--dim)}
.row{display:flex;gap:8px}
input[type=text]{flex:1;min-width:0;background:#0d1117;border:1px solid var(--bd);border-radius:8px;
color:var(--fg);padding:8px 10px;font:inherit}
input[type=text]:focus{outline:none;border-color:var(--acc)}
textarea{width:100%;background:#0d1117;border:1px solid var(--bd);border-radius:8px;color:var(--fg);
font:12px/1.5 ui-monospace,Consolas,"Courier New",monospace;padding:8px;resize:vertical}
#links-text{min-height:120px}
.linkcard{border:1px solid var(--bd);border-radius:8px;padding:8px;background:var(--panel2);margin-bottom:8px}
.lhead{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:6px}
.lname{font-weight:600}
.subrow{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:10px 0}
.subrow input{flex:1;min-width:200px}
.dim{color:var(--dim)}
.badge{display:flex;gap:6px;align-items:center;border:1px solid var(--bd);border-radius:20px;
padding:4px 12px;background:var(--panel);white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);display:inline-block}
.dot.ok{background:var(--ok)}
.dot.err{background:var(--err)}
#info{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;margin-top:4px}
.kv{border:1px solid var(--bd);border-radius:8px;padding:7px 10px;background:var(--panel2)}
.kv b{display:block;color:var(--dim);font-weight:400;font-size:12px}
.kv span{word-break:break-all;font-family:ui-monospace,Consolas,monospace;font-size:12px}
#log{display:flex;flex-direction:column;gap:10px;max-height:480px;overflow:auto}
.logentry{border:1px solid var(--bd);border-left:3px solid var(--ok);border-radius:8px;
padding:10px;background:var(--panel2)}
.logentry.err{border-left-color:var(--err)}
pre{white-space:pre-wrap;word-break:break-all;background:#0d1117;border:1px solid var(--bd);
border-radius:6px;padding:8px;margin:6px 0 0;font-size:12px;max-height:220px;overflow:auto;
font-family:ui-monospace,Consolas,"Courier New",monospace}
pre.sterr{color:#ffb3ae}
.cmd{font-family:ui-monospace,Consolas,monospace;color:var(--dim);font-size:12px;
margin-top:6px;word-break:break-all}
.note{border:1px dashed var(--bd);border-radius:8px;padding:8px 10px;color:var(--dim);
font-size:12px;margin-top:10px}
#toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:#21262d;
border:1px solid var(--acc);border-radius:8px;padding:8px 16px;opacity:0;pointer-events:none;
transition:opacity .2s;z-index:9;max-width:90vw}
#toast.show{opacity:1}
@media(max-width:640px){body{padding:10px}section{padding:11px}.grid{grid-template-columns:1fr}}
.alert-box{border:1px solid #d29922;background:rgba(210,153,34,.12);border-radius:8px;padding:10px 12px;font-size:13px;color:#e3b341;margin-bottom:12px;line-height:1.5}
.core-card{border:1px solid var(--bd);border-radius:8px;padding:8px 10px;background:var(--panel2);display:flex;flex-direction:column;gap:3px}
.core-card .chead{display:flex;justify-content:space-between;align-items:center}
.core-card .cname{font-weight:600;font-size:13px}
.core-card .cpath{font-family:ui-monospace,Consolas,monospace;font-size:11px;color:var(--dim);word-break:break-all}
.core-card .cver{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--fg)}
.proc-card{border:1px solid var(--bd);border-radius:8px;padding:10px;background:var(--panel2);margin-bottom:8px;font-size:12px}
.proc-card.third-party{border-color:rgba(210,153,34,.45);background:rgba(210,153,34,.06)}
.phead{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:6px}
.phead .p-title{font-weight:600;font-size:13px}
.ports-tag{font-family:ui-monospace,Consolas,monospace;background:#162436;color:#58a6ff;border:1px solid #388bfd44;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:600}
.cmd-box{background:#0d1117;border:1px solid var(--bd);border-radius:6px;padding:6px 8px;margin-top:6px;font-family:ui-monospace,Consolas,monospace;font-size:11px;word-break:break-all;color:#8b949e}
.tp-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.tp-links-box{margin-top:8px;padding:8px;background:#0d1117;border:1px solid #30363d;border-radius:6px}
.tp-link-row{display:flex;align-items:center;gap:6px;margin-bottom:6px;font-size:11px}
.tp-link-row:last-child{margin-bottom:0}
.tp-link-input{flex:1;background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:4px 8px;border-radius:4px;font-family:ui-monospace,Consolas,monospace;font-size:11px}
.mini-btn{padding:3px 8px;font-size:11px;border-radius:4px;cursor:pointer;border:1px solid var(--bd);background:var(--panel2);color:var(--fg)}
.mini-btn:hover{border-color:var(--acc);color:var(--acc)}
.mini-btn.stop{border-color:rgba(210,153,34,.5);color:#e3b341}
.mini-btn.stop:hover{background:rgba(210,153,34,.15)}
.mini-btn.uninstall{border-color:rgba(248,81,73,.5);color:#f85149}
.mini-btn.uninstall:hover{background:rgba(248,81,73,.15)}
.test-card{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:#0d1117;border:1px solid #30363d;border-radius:6px}
.test-card.ok{border-color:rgba(46,160,67,.4)}
.test-card.fail{border-color:rgba(248,81,73,.4)}
.test-status.ok{color:#3fb950;font-weight:600;font-size:11px}
.test-status.fail{color:#f85149;font-weight:600;font-size:11px}
.port-tag{cursor:pointer;transition:all .15s}
.port-tag:hover{border-color:var(--acc);color:var(--acc)}
.port-row{display:flex;align-items:center;justify-content:space-between;gap:6px;padding:6px 8px;background:#0d1117;border:1px solid #30363d;border-radius:4px;font-size:12px}
.port-row input{width:75px;padding:2px 6px;font-size:12px;text-align:center;background:#161b22;border:1px solid #30363d;color:#c9d1d9;border-radius:4px}
</style>
</head>
<body>
<header>
  <h1>
    <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9z" fill="#4c8dff"></path>
    </svg>
    朔月 de_GWD 控制面板
  </h1>
  <div id="badge" class="badge"><span class="dot"></span>加载中…</div>
</header>
<main>
  <section>
    <h2>当前状态 <button class="mini" id="btn-refresh">刷新状态</button></h2>
    <div id="info"><div class="kv"><b>提示</b><span>尚未获取状态</span></div></div>
  </section>

  <section id="sec-detect">
    <h2>
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px">
        <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      </svg>
      服务端组件与进程检测
      <button class="mini" id="btn-detect-refresh">重新探测</button>
    </h2>
    <div id="detect-alert"></div>
    <div id="detect-summary" class="toolbar" style="margin-bottom:10px"></div>
    <h3 style="font-size:13px;color:var(--dim);margin:10px 0 6px">已安装服务端核心 / 工具</h3>
    <div id="detect-bins" class="grid" style="grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px;margin-bottom:14px">
      <div class="dim">正在检测服务端核心组件…</div>
    </div>
    <h3 style="font-size:13px;color:var(--dim);margin:10px 0 6px">运行中的代理进程与监听端口</h3>
    <div id="detect-procs">
      <div class="dim">正在探测运行中的代理进程…</div>
    </div>
  </section>

  <section>
    <h2>协议选择</h2>
    <div class="toolbar" style="flex-wrap:wrap;gap:8px">
      <button class="mini" data-quick="all">全选</button>
      <button class="mini" data-quick="none">全不选</button>
      <button class="mini" data-quick="xray">仅 Xray</button>
      <button class="mini" data-quick="singbox">仅 Sing-box（含 Naive）</button>
      <span class="dim" id="pick-count"></span>
      <div style="margin-left:auto;display:flex;gap:6px;flex-wrap:wrap">
        <button class="mini" id="btn-rand-ports" style="background:rgba(88,166,255,0.15);border-color:#58a6ff;color:#58a6ff;font-weight:600" title="为所有协议分配互不相同的独立高位随机端口（10000~60000）">🎲 一键随机所有端口</button>
        <button class="mini" id="btn-reset-ports" title="将所有协议端口恢复为默认初始端口">🔄 恢复默认端口</button>
        <button class="mini" id="btn-toggle-port-mgr" title="展开/收起各协议独立端口详细配置">⚙️ 独立端口配置</button>
      </div>
    </div>
    <div id="port-mgr-panel" style="display:none;margin-top:10px;padding:12px;background:var(--panel2);border:1px solid var(--bd);border-radius:6px">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:8px">
        <span style="font-weight:600;font-size:13px">🔌 协议独立端口详细配置（支持单独修改任意协议端口或一键随机）</span>
        <button class="mini primary" id="btn-save-custom-ports">保存独立端口修改</button>
      </div>
      <div id="port-mgr-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px"></div>
    </div>
    <div id="proto-groups"></div>
    <div class="proto-actions-bar">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <button class="primary" id="btn-proto-install" style="padding:8px 18px;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px" title="将上方勾选的所有协议立即保存并安装部署，启动代理服务">
          <span>🚀 安装所选协议</span>
        </button>
        <button id="btn-proto-reinstall" style="padding:8px 16px;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px" title="根据当前勾选的协议重新生成底层 Xray / Sing-box / Nginx 配置并重启全部服务">
          <span>🔄 重新安装</span>
        </button>
        <button class="danger" id="btn-proto-uninstall" style="padding:8px 16px;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:6px" title="卸载并停用勾选的协议，释放端口">
          <span>🗑️ 卸载协议</span>
        </button>
      </div>
      <div class="dim" style="font-size:12px">
        <span>💡 勾选上方协议后点击「安装」生效；「重新安装」重建底层配置；「卸载」停用所选协议并释放端口</span>
      </div>
    </div>
  </section>

  <section>
    <h2>全局配置</h2>
    <div class="form">
      <div class="field">
        <label for="f-domain">域名（可含端口，如 a.example.com:8443）</label>
        <input type="text" id="f-domain" placeholder="a.example.com" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-port">服务端口（nginx 类协议，默认 443）</label>
        <input type="text" id="f-port" placeholder="443" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-uuid">UUID（所有协议共用）</label>
        <div class="row">
          <input type="text" id="f-uuid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" autocomplete="off">
          <button class="mini" id="btn-genuuid">生成</button>
        </div>
      </div>
      <div class="field">
        <label for="f-subtoken">订阅路径密码（sub token）</label>
        <input type="text" id="f-subtoken" placeholder="1a2b3c4d5e6f7a8b" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-upip">CDN 优选 IP / 落地域名（xhttp-tls-UpIP 用）</label>
        <input type="text" id="f-upip" placeholder="1.2.3.4 或 up.example.com" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-prefix">节点名称前缀（写进分享链接的 # 片段）</label>
        <input type="text" id="f-prefix" placeholder="朔月" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-rsni">Reality 伪装域名（SNI，默认 www.microsoft.com）</label>
        <input type="text" id="f-rsni" placeholder="www.microsoft.com" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-rdest">Reality 回落目标（host:port，默认 www.microsoft.com:443）</label>
        <input type="text" id="f-rdest" placeholder="www.microsoft.com:443" autocomplete="off">
      </div>
      <div class="field">
        <label for="f-rport">Reality 端口（默认 8443）</label>
        <input type="text" id="f-rport" placeholder="8443" autocomplete="off">
      </div>
    </div>
    <div class="toolbar" style="margin-top:12px">
      <button class="primary" id="btn-cfg">保存全局配置</button>
      <span class="dim">只提交填写了内容的字段；会重建配置并重启内核</span>
    </div>
  </section>

  <section id="sec-cloudflare">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <h2 style="margin:0">🌐 Cloudflare &amp; 出口代理设置 (解锁 Gemini / 谷歌全家桶)</h2>
      <div style="display:flex;gap:6px;align-items:center">
        <span id="sw-warp-mode" class="tag">模式: 未知</span>
        <span id="sw-warp-ip" class="tag dim">出口: 未知</span>
      </div>
    </div>

    <div class="note" style="margin-bottom:12px">
      💡 <b>出口代理原理</b>：通过 Cloudflare WARP 出口为代理流量提供干净解锁 IP。支持<b>智能分流</b>（仅将 Gemini / Google / OpenAI 等需要解锁的流量路由至 WARP 出口，国内与普通流量保持 VPS 原生直连，兼顾极速与解锁）。
    </div>

    <div class="form">
      <div class="field" style="grid-column: 1 / -1">
        <label for="f-warp-mode">选择出口代理模式</label>
        <select id="f-warp-mode" style="font-weight:600">
          <option value="direct">🌐 原生 IP 直连（关闭 WARP 出口代理）</option>
          <option value="warp_google" selected>⚡ 仅解锁 Gemini &amp; 谷歌全家桶（推荐：Google/Gemini 走 WARP，其余原生直连）</option>
          <option value="warp_ai">🤖 解锁全套 AI（Gemini + OpenAI/ChatGPT + Claude + Perplexity，其余直连）</option>
          <option value="warp_media_ai">🎬 解锁 AI 与流媒体（Gemini + Google + OpenAI + Netflix + Disney+）</option>
          <option value="warp_all">🌍 全局 WARP 出站（全部流量经由 Cloudflare WARP 出口）</option>
        </select>
      </div>
    </div>

    <div class="toolbar" style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <button class="primary" id="btn-save-warp">应用出口代理模式</button>
      <button class="mini-btn" id="btn-test-warp">🧪 一键测试 Gemini / 谷歌 / AI 解锁</button>
      <button class="mini-btn" id="btn-regen-warp">🔄 刷新 WARP 账号与干净密钥</button>
    </div>

    <div id="warp-test-result" style="display:none;margin-top:12px;padding:12px;background:#161b22;border:1px solid #30363d;border-radius:6px;font-size:12px">
      <div style="font-weight:600;margin-bottom:8px;color:#58a6ff">🧪 解锁连通性测试报告：</div>
      <div id="warp-test-details" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px"></div>
    </div>

    <details style="margin-top:16px;background:var(--panel2);border:1px solid var(--bd);border-radius:6px;padding:10px 14px">
      <summary style="cursor:pointer;font-weight:600;color:var(--fg);display:flex;align-items:center;justify-content:space-between">
        <span>🚇 Cloudflare Tunnel (cloudflared 穿透隧道设置)</span>
        <span id="sw-cf-tunnel" class="tag dim">未安装</span>
      </summary>
      <div style="margin-top:10px;font-size:12px;color:var(--dim)">
        无需公网 IP 与开放端口，通过 Cloudflare Zero Trust 隧道将 Web 控制面板或代理服务穿透发布，自带 Cloudflare CDN 加速与 WAF 防护。
      </div>
      <div class="form" style="margin-top:10px">
        <div class="field" style="grid-column: 1 / -1">
          <label for="f-cf-token">Cloudflare Tunnel Token (从 Cloudflare Zero Trust 复制)</label>
          <input type="password" id="f-cf-token" placeholder="eyJhIjoi... (留空保持不变)">
        </div>
      </div>
      <div class="toolbar" style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
        <button class="mini-btn" id="btn-cf-start">🚀 启动隧道服务</button>
        <button class="mini-btn stop" id="btn-cf-stop">🛑 停止隧道服务</button>
        <button class="mini-btn" id="btn-cf-quick">⚡ 临时快速隧道 (trycloudflare.com)</button>
        <button class="mini-btn" id="btn-cf-install">📥 一键安装/更新 cloudflared</button>
      </div>
      <div id="cf-tunnel-msg" style="margin-top:8px;font-size:11px;font-family:monospace;color:#8b949e"></div>
    </details>
  </section>

  <section>
    <h2>订阅服务开关</h2>
    <div class="form">
      <div class="field">
        <label for="f-subon">订阅服务开关（/sub/&lt;token&gt; 可访问） <span id="sw-sub" class="tag">未知</span></label>
        <select id="f-subon">
          <option value="">保持不变</option>
          <option value="on">启用</option>
          <option value="off">关闭</option>
        </select>
      </div>
    </div>
    <div class="toolbar" style="margin-top:12px">
      <button class="primary" id="btn-sub-switch">应用订阅开关</button>
    </div>
  </section>

  <section>
    <h2>订阅</h2>
    <div class="subrow">
      <span class="dim">订阅地址（base64，v2rayN / Clash / sing-box 通用）</span>
      <input type="text" id="suburl" readonly placeholder="—">
      <button class="mini" id="btn-copysub">复制订阅</button>
    </div>
    <div class="note">把订阅地址填入 v2rayN → 订阅分组 → 添加，更新订阅即可拉到全部已启用协议节点。面板不内置二维码编码器。</div>
  </section>

  <section>
    <h2>操作</h2>
    <div class="toolbar">
      <button class="primary" id="btn-save">保存并应用（勾选的协议）</button>
      <button id="btn-reset">重新生成 UUID/Path</button>
      <button id="btn-regen">重建配置</button>
      <button id="btn-links">重新拉取链接</button>
    </div>
    <div class="note">重建配置 / 切换协议 / 重置凭据都会在服务端重写 Xray / sing-box / nginx 配置并重启服务，耗时较长，请勿连续点击。</div>
  </section>

  <section>
    <h2>分享链接</h2>
    <div class="toolbar">
      <button class="mini" id="btn-copyall">复制全部</button>
      <span class="dim" id="link-count"></span>
    </div>
    <textarea id="links-text" readonly placeholder="暂无链接"></textarea>
    <div id="links"></div>
  </section>

  <section>
    <h2>日志 / 结果</h2>
    <div class="toolbar"><button class="mini" id="btn-clearlog">清空</button></div>
    <div id="log"><div class="dim">暂无操作记录。</div></div>
  </section>
</main>
<div id="toast"></div>
<script>
"use strict";
var PROTOS = /*__PROTOS__*/[];
var SERVER_PROTOS = null;
var PROTOLIST_SIG = "";
var TOKEN = new URLSearchParams(location.search).get("t") || "";
var LINKS = [];

function $(sel, root) { return (root || document).querySelector(sel); }
function $$(sel, root) {
  return Array.prototype.slice.call((root || document).querySelectorAll(sel));
}
function esc(v) {
  return String(v === null || v === undefined ? "" : v).replace(/[&<>"']/g, function (c) {
    return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
  });
}
function toast(msg) {
  var el = $("#toast");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(function () { el.classList.remove("show"); }, 2200);
}
function truncate(text, n) {
  text = String(text || "");
  if (text.length <= n) { return text; }
  return text.slice(0, n) + "\n…（已截断，共 " + text.length + " 字符）";
}

/* ------------------------------------------------------------ 协议卡片渲染 */
function protoList() {
  // 优先用 server --cli status 返回的 protolist（单一事实来源），否则用内嵌清单
  if (Array.isArray(SERVER_PROTOS) && SERVER_PROTOS.length) {
    return SERVER_PROTOS.map(function (p) {
      return {
        id: p.id, name: p.name || p.id,
        group: p.kernel === "xray" ? "xray" : "singbox",
        port: String(p.port || ""),
        needs_domain: !!p.needs_domain,
        desc: p.desc || ""
      };
    });
  }
  return PROTOS;
}
var INSTALLED_PROTOS = {};
function renderProtos() {
  var list = protoList();
  var groups = [["xray", "Xray 内核"], ["singbox", "Sing-box 内核"]];
  var host = $("#proto-groups");
  host.innerHTML = groups.map(function (g) {
    var items = list.filter(function (p) { return p.group === g[0]; });
    if (!items.length) { return ""; }
    var cards = items.map(function (p) {
      var isInst = !!INSTALLED_PROTOS[p.id];
      var instBadge = isInst ? '<span class="tag installed-badge"><span class="dot ok" style="width:6px;height:6px;margin:0"></span>已安装</span>' : '';
      return '<label class="card proto' + (isInst ? ' installed' : '') + '" data-group="' + p.group + '" data-pid="' + esc(p.id) + '" title="' + esc(p.desc || "") + '">' +
        '<input type="checkbox" class="pk" value="' + esc(p.id) + '">' +
        '<div><div class="pname">' + esc(p.name) + "</div>" +
        '<code class="pid">' + esc(p.id) + "</code>" +
        '<div class="meta">' +
        instBadge +
        '<span class="tag port-tag" data-pid="' + esc(p.id) + '" title="点击快捷修改此协议端口">' + esc(p.port) + ' ✏️</span>' +
        (p.needs_domain ? '<span class="tag warn">需域名</span>' : '<span class="tag ok">免域名</span>') +
        "</div></div></label>";
    }).join("");
    return '<div><h3>' + esc(g[1]) + '<span class="tag">' + items.length + "</span></h3>" +
      '<div class="grid">' + cards + "</div></div>";
  }).join("");
  $$(".pk").forEach(function (cb) {
    cb.addEventListener("change", function () {
      cb.closest(".proto").classList.toggle("on", cb.checked);
      updateCount();
    });
  });
  $$(".port-tag").forEach(function (el) {
    el.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      var pid = el.getAttribute("data-pid");
      var cur = el.textContent.replace(/[^0-9]/g, "");
      var np = prompt("修改协议 [" + pid + "] 的端口\n(当前: " + cur + "，范围 1024-65535，留空回车则随机生成):", cur);
      if (np === null) { return; }
      np = np.trim();
      if (!np) {
        np = Math.floor(10000 + Math.random() * 50000);
      }
      var portNum = parseInt(np, 10);
      if (isNaN(portNum) || portNum < 1024 || portNum > 65535) {
        alert("端口必须在 1024-65535 之间");
        return;
      }
      api("/api/ports", "POST", { action: "set", id: pid, port: String(portNum) }, function (err, res) {
        if (err) { alert("修改端口失败: " + err); return; }
        if (res && res.protolist) {
          updateProtoList(res.protolist);
        }
        loadStatus();
        toast("协议 " + pid + " 端口已更新为 " + portNum);
      });
    });
  });
  updateCount();
}
function updateProtoList(newlist) {
  if (Array.isArray(newlist) && newlist.length) {
    SERVER_PROTOS = newlist;
    PROTOS = newlist.map(function (p) {
      return {
        id: p.id,
        name: p.name || p.id,
        group: p.kernel === "xray" ? "xray" : "singbox",
        port: String(p.port || ""),
        needs_domain: !!p.needs_domain,
        desc: p.desc || ""
      };
    });
    renderProtos();
    renderPortMgrGrid();
  }
}
window.updateProtoList = updateProtoList;

function renderPortMgrGrid() {
  var grid = $("#port-mgr-grid");
  if (!grid) { return; }
  var list = protoList();
  grid.innerHTML = list.map(function (p) {
    var numPort = p.port.replace(/[^0-9]/g, "");
    return '<div class="port-row">' +
      '<span style="font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(p.name) + '">' + esc(p.name) + '</span>' +
      '<input type="text" class="custom-port-inp" data-pid="' + esc(p.id) + '" value="' + esc(numPort) + '" maxlength="5">' +
      '<button class="mini btn-rand-single" data-pid="' + esc(p.id) + '" title="为该协议单独随机端口">🎲</button>' +
    '</div>';
  }).join("");
  $$(".btn-rand-single").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var pid = btn.getAttribute("data-pid");
      var inp = grid.querySelector('.custom-port-inp[data-pid="' + pid + '"]');
      if (inp) {
        inp.value = Math.floor(10000 + Math.random() * 50000);
      }
    });
  });
}
function checkedIds() {
  return $$(".pk").filter(function (cb) { return cb.checked; }).map(function (cb) { return cb.value; });
}
function updateCount() {
  $("#pick-count").textContent = "已选 " + checkedIds().length + " / " + protoList().length + " 个协议";
}
function setChecks(src) {
  // server 的 protos 是「已启用 id 的数组」，但历史/其他调用方可能传对象映射，两种都支持
  var map = {};
  if (Array.isArray(src)) {
    src.forEach(function (id) { map[String(id)] = true; });
  } else if (src && typeof src === "object") {
    map = src;
  }
  $$(".pk").forEach(function (cb) {
    cb.checked = !!map[cb.value];
    cb.closest(".proto").classList.toggle("on", cb.checked);
  });
  updateCount();
}
function updateInstalledStatus(src) {
  var map = {};
  if (Array.isArray(src)) {
    src.forEach(function (id) { map[String(id)] = true; });
  } else if (src && typeof src === "object") {
    map = src;
  }
  INSTALLED_PROTOS = map;
  $$(".proto").forEach(function (card) {
    var cb = card.querySelector ? card.querySelector(".pk") : null;
    if (!cb) { return; }
    var pid = cb.value;
    var isInst = !!map[pid];
    if (card.classList && card.classList.toggle) {
      card.classList.toggle("installed", isInst);
    }
    var meta = card.querySelector ? card.querySelector(".meta") : null;
    if (!meta) { return; }
    var badge = card.querySelector ? card.querySelector(".installed-badge") : null;
    if (isInst) {
      if (!badge) {
        var b = document.createElement("span");
        b.className = "tag installed-badge";
        b.innerHTML = '<span class="dot ok" style="width:6px;height:6px;margin:0"></span>已安装';
        if (meta.firstChild) {
          meta.insertBefore(b, meta.firstChild);
        } else {
          meta.appendChild(b);
        }
      }
    } else {
      if (badge && badge.parentNode) {
        badge.parentNode.removeChild(badge);
      }
    }
  });
}
window.updateInstalledStatus = updateInstalledStatus;
$$("[data-quick]").forEach(function (btn) {
  btn.addEventListener("click", function () {
    var mode = btn.getAttribute("data-quick");
    var map = {};
    protoList().forEach(function (p) {
      if (mode === "all") { map[p.id] = true; }
      else if (mode === "none") { map[p.id] = false; }
      else if (mode === "xray") { map[p.id] = p.group === "xray"; }
      else if (mode === "singbox") { map[p.id] = p.group !== "xray"; }
    });
    setChecks(map);
  });
});

/* -------------------------------------------------------------- 状态与链接 */
var LAST_STATUS = null;
function applyStatus(d) {
  if (!d || typeof d !== "object") { return; }
  LAST_STATUS = d;
  var installed = !!d.installed;
  var badge = $("#badge");
  badge.innerHTML = '<span class="dot ' + (installed ? "ok" : "err") + '"></span>' +
    (installed ? "已安装" : "未安装");
  var rows = [
    ["域名", d.domain || "—"],
    ["服务端口", d.port || "—"],
    ["面板端口", d.panel_port || "—"],
    ["UUID", d.uuid || "—"],
    ["订阅 token", d.subtoken || "—"],
    ["面板路径", d.panel_path || "—"],
    ["内核", "xray " + (d.svc && d.svc.xray ? "✓" : "✕") +
             "  nginx " + (d.svc && d.svc.nginx ? "✓" : "✕") +
             "  sing-box " + (d.svc && d.svc.singbox ? "✓" : "✕")]
  ];
  $("#info").innerHTML = rows.map(function (r) {
    return '<div class="kv"><b>' + esc(r[0]) + "</b><span>" + esc(r[1]) + "</span></div>";
  }).join("");

  // server 返回的 protolist 是权威清单；只有内容变化时才重绘，避免清掉用户正在勾选的状态
  if (Array.isArray(d.protolist) && d.protolist.length) {
    var sig = JSON.stringify(d.protolist);
    if (sig !== PROTOLIST_SIG) {
      PROTOLIST_SIG = sig;
      SERVER_PROTOS = d.protolist;
      renderProtos();
    }
  }
  if (d.protos) {
    setChecks(d.protos);
    updateInstalledStatus(d.protos);
  }
  if (d.domain) { $("#f-domain").value = d.domain; }
  if (d.uuid) { $("#f-uuid").value = d.uuid; }
  if (d.subtoken) { $("#f-subtoken").value = d.subtoken; }
  var cfg = d.cfg || {};
  if (cfg.port) { $("#f-port").value = String(cfg.port); }
  if (cfg.upip) { $("#f-upip").value = cfg.upip; }
  if (cfg.prefix) { $("#f-prefix").value = cfg.prefix; }
  if (cfg.reality_sni) { $("#f-rsni").value = cfg.reality_sni; }
  if (cfg.reality_dest) { $("#f-rdest").value = cfg.reality_dest; }
  var warpObj = (typeof d.warp === "object" && d.warp !== null) ? d.warp : { enabled: !(!d.warp), mode: (d.warp ? "warp_google" : "direct"), v4: "" };
  var isWarpOn = !(!warpObj.enabled);
  var warpMode = warpObj.mode || (isWarpOn ? "warp_google" : "direct");
  var modeSel = $("#f-warp-mode");
  if (modeSel) { modeSel.value = isWarpOn ? warpMode : "direct"; }

  var modeTag = $("#sw-warp-mode");
  if (modeTag) {
    var modeNames = {
      direct: "原生直连",
      warp_google: "⚡ 仅解锁 Gemini & 谷歌",
      warp_ai: "🤖 解锁全套 AI",
      warp_media_ai: "🎬 解锁 AI 与流媒体",
      warp_all: "🌍 全局 WARP"
    };
    modeTag.textContent = modeNames[warpMode] || warpMode;
    modeTag.className = "tag " + (isWarpOn ? "ok" : "warn");
  }

  var ipTag = $("#sw-warp-ip");
  if (ipTag) {
    if (isWarpOn && warpObj.v4) {
      ipTag.textContent = "WARP: " + warpObj.v4;
      ipTag.className = "tag";
    } else if (isWarpOn) {
      ipTag.textContent = "WARP 出口生效中";
      ipTag.className = "tag ok";
    } else {
      ipTag.textContent = "未启用 WARP 出站";
      ipTag.className = "tag dim";
    }
  }

  var cfObj = d.cloudflared || {};
  var cfTag = $("#sw-cf-tunnel");
  if (cfTag) {
    if (cfObj.running) {
      cfTag.textContent = "运行中";
      cfTag.className = "tag ok";
    } else if (cfObj.installed) {
      cfTag.textContent = "已安装 (未运行)";
      cfTag.className = "tag";
    } else {
      cfTag.textContent = "未安装";
      cfTag.className = "tag dim";
    }
  }

  var swWarp = $("#sw-warp");
  if (swWarp) {
    swWarp.textContent = isWarpOn ? "已启用" : "未启用";
    swWarp.className = "tag " + (isWarpOn ? "" : "warn");
  }
  var swSub = $("#sw-sub");
  if (swSub) {
    swSub.textContent = d.sub_on === false ? "已关闭" : "已启用";
    swSub.className = "tag " + (d.sub_on === false ? "warn" : "");
  }
  setSub(d.suburl);
  if (Array.isArray(d.links)) { renderLinks(d.links); }
  if (d.proxy_env) { renderDetection(d.proxy_env); }
}
function renderDetection(env) {
  if (!env || typeof env !== "object") { return; }
  var bins = Array.isArray(env.binaries) ? env.binaries : [];
  var procs = Array.isArray(env.running) ? env.running : [];
  var sum = env.summary || {};

  var sHost = $("#detect-summary");
  if (sHost) {
    sHost.innerHTML =
      '<span class="tag ok">已检出核心: ' + (sum.total_installed || bins.length) + ' 个</span>' +
      '<span class="tag">运行中进程: ' + (sum.total_running || procs.length) + ' 个</span>' +
      '<span class="tag">本系统托管: ' + (sum.degwd_running || 0) + ' 个</span>' +
      ((sum.third_party_running || 0) > 0 ?
        '<span class="tag warn">⚠️ 外部/第三方进程: ' + sum.third_party_running + ' 个</span>' :
        '<span class="tag ok">无第三方冲突</span>');
  }

  var aHost = $("#detect-alert");
  if (aHost) {
    if (sum.has_third_party) {
      var thirdProcs = procs.filter(function (p) { return !p.is_degwd; });
      var thirdPorts = [];
      thirdProcs.forEach(function (p) {
        if (p.ports) {
          p.ports.split(",").forEach(function (pt) {
            pt = pt.trim();
            if (pt && thirdPorts.indexOf(pt) < 0) { thirdPorts.push(pt); }
          });
        }
      });
      aHost.innerHTML =
        '<div class="alert-box"><strong>⚠️ 检测到服务器上运行有外部/第三方代理进程：</strong>共发现 ' +
        thirdProcs.length + ' 个非本系统托管的服务实例' +
        (thirdPorts.length ? '，已占用端口：<code>' + esc(thirdPorts.join(", ")) + '</code>' : '') +
        '。配置或修改本系统协议服务端口时，请避免使用已被占用的端口，以防冲突启动失败。</div>';
    } else {
      aHost.innerHTML = '';
    }
  }

  var bHost = $("#detect-bins");
  if (bHost) {
    if (!bins.length) {
      bHost.innerHTML = '<div class="dim">暂未检出标准代理核心程序（勾选协议并保存后系统将按需自动安装）。</div>';
    } else {
      bHost.innerHTML = bins.map(function (b) {
        var isRun = procs.some(function (p) { return p.name === b.name; });
        return '<div class="core-card">' +
          '<div class="chead"><span class="cname">' + esc(b.name) + '</span>' +
          (isRun ? '<span class="tag ok">运行中</span>' : '<span class="tag">未运行</span>') +
          '</div>' +
          '<div class="cver">版本: ' + esc(b.version || "已安装") + '</div>' +
          '<div class="cpath" title="' + esc(b.path) + '">路径: ' + esc(b.path) + '</div>' +
          '</div>';
      }).join("");
    }
  }

  var pHost = $("#detect-procs");
  if (pHost) {
    if (!procs.length) {
      pHost.innerHTML = '<div class="dim">当前无运行中的代理服务进程。</div>';
    } else {
      pHost.innerHTML = procs.map(function (p, idx) {
        var linksHtml = '';
        if (!p.is_degwd && Array.isArray(p.links) && p.links.length > 0) {
          linksHtml = '<div class="tp-links-box">' +
            '<div style="font-weight:600;color:#58a6ff;margin-bottom:6px">📋 提取到的原 v2rayN 节点链接 (' + p.links.length + ' 个)：</div>' +
            p.links.map(function (lk) {
              return '<div class="tp-link-row">' +
                '<input type="text" readonly class="tp-link-input" value="' + esc(lk) + '">' +
                '<button type="button" class="mini-btn copy-tp-link" data-link="' + esc(lk) + '">复制</button>' +
              '</div>';
            }).join('') +
          '</div>';
        }
        var actHtml = '';
        if (!p.is_degwd) {
          actHtml = '<div class="tp-actions">' +
            '<button type="button" class="mini-btn stop" data-kill-action="stop" data-pid="' + esc(p.pid) + '" data-name="' + esc(p.name) + '" data-exe="' + esc(p.exe || '') + '" data-config="' + esc(p.config || '') + '">🛑 一键停止进程 (释放端口)</button>' +
            '<button type="button" class="mini-btn uninstall" data-kill-action="uninstall" data-pid="' + esc(p.pid) + '" data-name="' + esc(p.name) + '" data-exe="' + esc(p.exe || '') + '" data-config="' + esc(p.config || '') + '">🗑️ 一键彻底卸载清理</button>' +
          '</div>';
        }
        return '<div class="proc-card ' + (p.is_degwd ? '' : 'third-party') + '">' +
          '<div class="phead">' +
            '<span class="p-title">#' + (idx + 1) + ' ' + esc(p.name) + '</span>' +
            '<span class="tag">PID: ' + esc(p.pid) + '</span>' +
            '<span class="tag">用户: ' + esc(p.user) + '</span>' +
            (p.is_degwd ? '<span class="tag ok">本系统托管</span>' : '<span class="tag warn">⚠️ 第三方/已有脚本</span>') +
            (p.ports ? '<span class="ports-tag">监听: ' + esc(p.ports) + '</span>' : '<span class="tag">无外部监听</span>') +
          '</div>' +
          (p.config ? '<div style="margin:2px 0"><span class="dim">配置文件: </span><code>' + esc(p.config) + '</code></div>' : '') +
          '<div class="cmd-box">' + esc(p.cmd || p.exe || '') + '</div>' +
          linksHtml +
          actHtml +
          '</div>';
      }).join("");
    }
  }
}
function setSub(url) {
  $("#suburl").value = url || "";
}
function renderLinks(list) {
  LINKS = Array.isArray(list) ? list : [];
  $("#links-text").value = LINKS.map(function (x) { return x.link || ""; })
    .filter(function (s) { return s; }).join("\n");
  $("#link-count").textContent = LINKS.length ? ("共 " + LINKS.length + " 条") : "";
  var box = $("#links");
  if (!LINKS.length) {
    box.innerHTML = '<p class="dim">暂无链接：请勾选协议后点「保存并应用」，或点「重建配置」。</p>';
    return;
  }
  box.innerHTML = LINKS.map(function (x, i) {
    return '<div class="linkcard"><div class="lhead"><span class="lname">' +
      esc(x.name || x.id || ("节点 " + (i + 1))) + "</span>" +
      (x.port ? '<span class="tag">' + esc(x.port) + "</span>" : "") +
      (x.needs_domain ? '<span class="tag warn">需域名</span>' : "") +
      '<button class="mini" data-copy="' + i + '">复制</button></div>' +
      '<textarea readonly rows="2">' + esc(x.link || "") + "</textarea></div>";
  }).join("");
}

/* ------------------------------------------------------------------ 复制 */
function copyText(text, btn) {
  function done() {
    if (!btn) { toast("已复制"); return; }
    var old = btn.textContent;
    btn.textContent = "已复制";
    btn.classList.add("ok");
    setTimeout(function () { btn.textContent = old; btn.classList.remove("ok"); }, 1200);
  }
  function fallback() {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      if (ok) { done(); } else { toast("复制失败，请手动选择文本"); }
    } catch (e) { toast("复制失败：" + e.message); }
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(fallback);
  } else { fallback(); }
}
$("#btn-copyall").addEventListener("click", function () {
  var v = $("#links-text").value;
  if (!v) { toast("暂无链接"); return; }
  copyText(v, this);
});
$("#btn-copysub").addEventListener("click", function () {
  var v = $("#suburl").value;
  if (!v) { toast("暂无订阅地址"); return; }
  copyText(v, this);
});
$("#links").addEventListener("click", function (ev) {
  var btn = ev.target.closest("[data-copy]");
  if (!btn) { return; }
  var item = LINKS[parseInt(btn.getAttribute("data-copy"), 10)];
  if (item && item.link) { copyText(item.link, btn); }
});

/* ---------------------------------------------------------------- 日志区 */
function logOp(title, r) {
  var box = $("#log");
  if (box.firstChild && box.firstChild.className === "dim") { box.innerHTML = ""; }
  var d = (r && r.data) || {};
  var code = (d.code === null || d.code === undefined) ? r.status : d.code;
  var ok = r.ok && d.ok !== false;
  var head = ["<b>" + esc(title) + "</b>",
    '<span class="dim">' + new Date().toLocaleTimeString() + "</span>",
    '<span class="tag">' + esc(r.method) + " " + esc(r.path) + "</span>",
    '<span class="tag">HTTP ' + esc(r.status) + "</span>",
    '<span class="tag">exit ' + esc(code) + "</span>",
    '<span class="tag">' + r.ms + "ms</span>"].join(" ");
  var body = "";
  if (d.cmd) { body += '<div class="cmd">$ ' + esc(d.cmd) + "</div>"; }
  if (d.error) { body += '<pre class="sterr">' + esc(d.error) + "</pre>"; }
  if (d.stdout) { body += "<pre>" + esc(truncate(d.stdout, 4000)) + "</pre>"; }
  if (d.stderr) { body += '<pre class="sterr">' + esc(truncate(d.stderr, 4000)) + "</pre>"; }
  var entry = document.createElement("div");
  entry.className = "logentry" + (ok ? "" : " err");
  entry.innerHTML = '<div class="lhead">' + head + "</div>" + body;
  box.insertBefore(entry, box.firstChild);
  while (box.children.length > 40) { box.removeChild(box.lastChild); }
}
$("#btn-clearlog").addEventListener("click", function () {
  $("#log").innerHTML = '<div class="dim">暂无操作记录。</div>';
});

/* -------------------------------------------------------------- 请求封装 */
function api(path, method, body) {
  var url = path;
  if (TOKEN) { url += (path.indexOf("?") >= 0 ? "&" : "?") + "t=" + encodeURIComponent(TOKEN); }
  var opt = { method: method || "GET", credentials: "same-origin", cache: "no-store", headers: {} };
  if (body !== undefined && body !== null) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  var t0 = (window.performance && performance.now) ? performance.now() : Date.now();
  return fetch(url, opt).then(function (resp) {
    return resp.text().then(function (text) {
      var js = null;
      try { js = JSON.parse(text); } catch (e) { js = null; }
      var ms = ((window.performance && performance.now) ? performance.now() : Date.now()) - t0;
      return {
        ok: resp.ok, status: resp.status, data: js, raw: text,
        ms: Math.round(ms), path: path, method: method || "GET"
      };
    });
  }).catch(function (err) {
    return {
      ok: false, status: 0, data: { ok: false, error: "网络请求失败：" + err.message },
      raw: "", ms: 0, path: path, method: method || "GET"
    };
  });
}
function busy(btn, promise, title) {
  if (btn) { btn.disabled = true; }
  return promise.then(function (r) {
    if (btn) { btn.disabled = false; }
    logOp(title, r);
    if (r && r.ok && (!r.data || r.data.ok !== false)) {
      toast(title + " 完成");
    } else {
      var err = (r && r.data && (r.data.error || (r.data.data && r.data.data.error))) || "";
      toast(title + (err ? (" 失败: " + err) : " 失败，见日志"));
    }
    return r;
  }, function (err) {
    if (btn) { btn.disabled = false; }
    logOp(title, { ok: false, status: 0, ms: 0, method: "?", path: "?", data: { error: String(err) } });
    toast(title + " 出错: " + String(err));
    return null;
  });
}

/* ---------------------------------------------------------------- 各操作 */
function loadStatus(btn) {
  return busy(btn, api("/api/status"), "刷新状态").then(function (r) {
    if (r && r.ok && r.data) { applyStatus(r.data.data || r.data); }
    return r;
  });
}
$("#btn-refresh").addEventListener("click", function () { loadStatus(this); });
var btnDetect = $("#btn-detect-refresh");
if (btnDetect) {
  btnDetect.addEventListener("click", function () {
    busy(this, api("/api/detect"), "探测代理环境").then(function (r) {
      if (r && r.ok && r.data) {
        renderDetection(r.data.data || r.data);
        toast("探测完成");
      }
    });
  });
}

function handleInstallProtos(triggerBtn) {
  var ids = checkedIds();
  if (!ids.length) { toast("请至少勾选一个协议"); return; }
  var needDomain = false;
  var protos = SERVER_PROTOS || PROTOCOLS;
  for (var i = 0; i < protos.length; i++) {
    if (protos[i].needs_domain && ids.indexOf(protos[i].id) >= 0) {
      needDomain = true;
      break;
    }
  }
  var domainVal = ($("#f-domain").value || "").trim();
  if (needDomain && !domainVal) {
    toast("所选协议需要域名，请先在全局配置中填入域名");
    $("#f-domain").focus();
    return;
  }
  var prepJob = Promise.resolve();
  if (domainVal) {
    prepJob = api("/api/cfg", "POST", { domain: domainVal });
  }
  busy(triggerBtn, prepJob.then(function () {
    return api("/api/protos", "POST", { protos: ids });
  }), "正在安装并应用协议…").then(function (r) {
    if (r && r.ok && r.data) {
      applyStatus(r.data.data || r.data);
      updateInstalledStatus(ids);
      toast("✅ 所选协议已成功安装并启动！");
      loadStatus();
    }
  });
}

var btnSave = $("#btn-save");
if (btnSave) {
  btnSave.addEventListener("click", function () { handleInstallProtos(this); });
}

var btnProtoInstall = $("#btn-proto-install");
if (btnProtoInstall) {
  btnProtoInstall.addEventListener("click", function () { handleInstallProtos(this); });
}

var btnProtoReinstall = $("#btn-proto-reinstall");
if (btnProtoReinstall) {
  btnProtoReinstall.addEventListener("click", function () {
    var ids = checkedIds();
    if (!ids.length) {
      if (!confirm("当前未勾选任何协议，重新安装将重新构建底层配置并重启服务，继续？")) { return; }
      busy(this, api("/api/regen", "POST", {}), "正在重新安装…").then(function (r) {
        if (r && r.ok && r.data) {
          applyStatus(r.data.data || r.data);
          toast("✅ 底层服务配置已重建并重启！");
          loadStatus();
        }
      });
      return;
    }
    if (!confirm("确认重新安装所选协议（共 " + ids.length + " 个）？\n将应用勾选的协议并彻底重新生成 Xray / Sing-box / Nginx 配置。")) {
      return;
    }
    var trigger = this;
    busy(trigger, api("/api/protos", "POST", { protos: ids }).then(function () {
      return api("/api/regen", "POST", {});
    }), "正在重新安装协议…").then(function (r) {
      if (r && r.ok && r.data) {
        applyStatus(r.data.data || r.data);
        updateInstalledStatus(ids);
        toast("✅ 所选协议已重新安装，底层配置已彻底重建！");
        loadStatus();
      }
    });
  });
}

var btnProtoUninstall = $("#btn-proto-uninstall");
if (btnProtoUninstall) {
  btnProtoUninstall.addEventListener("click", function () {
    var ids = checkedIds();
    var curProtos = (LAST_STATUS && LAST_STATUS.protos) ? LAST_STATUS.protos : {};
    var activeIds = [];
    if (Array.isArray(curProtos)) {
      activeIds = curProtos.slice();
    } else if (curProtos && typeof curProtos === "object") {
      for (var k in curProtos) {
        if (curProtos[k]) { activeIds.push(k); }
      }
    }
    if (!ids.length) {
      if (!activeIds.length) {
        toast("当前未启用任何代理协议，无需卸载");
        return;
      }
      if (!confirm("当前未勾选特定协议，确认卸载并停用所有已启用的代理协议（共 " + activeIds.length + " 个）？\n将关闭各协议代理服务并释放端口。")) {
        return;
      }
      busy(this, api("/api/protos", "POST", { protos: [] }), "正在卸载所有协议…").then(function (r) {
        if (r && r.ok && r.data) {
          applyStatus(r.data.data || r.data);
          setChecks([]);
          updateInstalledStatus([]);
          toast("✅ 已卸载并停用所有代理协议服务");
          loadStatus();
        }
      });
      return;
    }
    if (!confirm("确认卸载并停用勾选的 " + ids.length + " 个协议？\n将从服务中移除这些协议并释放对应端口。")) {
      return;
    }
    var remaining = activeIds.filter(function (id) { return ids.indexOf(id) < 0; });
    busy(this, api("/api/protos", "POST", { protos: remaining }), "正在卸载协议…").then(function (r) {
      if (r && r.ok && r.data) {
        applyStatus(r.data.data || r.data);
        updateInstalledStatus(remaining);
        ids.forEach(function (id) {
          var cb = $('.pk[value="' + id + '"]');
          if (cb) {
            cb.checked = false;
            if (cb.closest(".proto")) { cb.closest(".proto").classList.remove("on"); }
          }
        });
        updateCount();
        toast("✅ 所选协议已成功卸载并停用！");
        loadStatus();
      }
    });
  });
}
$("#btn-regen").addEventListener("click", function () {
  if (!confirm("重建配置会重写 Xray / sing-box / nginx 配置并重启服务，继续？")) { return; }
  busy(this, api("/api/regen", "POST", {}), "重建配置").then(function (r) {
    if (r && r.ok && r.data) { applyStatus(r.data.data || r.data); }
  });
});
$("#btn-reset").addEventListener("click", function () {
  if (!confirm("将重新生成 UUID / WS path / 订阅 token，旧链接立即失效，继续？")) { return; }
  busy(this, api("/api/reset", "POST", {}), "重置凭据").then(function (r) {
    if (r && r.ok && r.data) { applyStatus(r.data.data || r.data); }
  });
});
$("#btn-links").addEventListener("click", function () {
  busy(this, api("/api/links"), "拉取链接").then(function (r) {
    if (r && r.ok && r.data) {
      var d = r.data;
      setSub(d.suburl);
      renderLinks(d.links || []);
    }
  });
});
var btnSaveWarp = $("#btn-save-warp");
if (btnSaveWarp) {
  btnSaveWarp.addEventListener("click", function () {
    var mode = $("#f-warp-mode").value;
    busy(this, api("/api/warp", "POST", { action: "set_mode", mode: mode }), "应用出口代理模式").then(function (r) {
      if (r && r.ok) {
        toast(r.data && r.data.message ? r.data.message : "出口代理配置已更新生效");
        loadStatus();
      }
    });
  });
}

var btnTestWarp = $("#btn-test-warp");
if (btnTestWarp) {
  btnTestWarp.addEventListener("click", function () {
    var box = $("#warp-test-result");
    var details = $("#warp-test-details");
    if (box) { box.style.display = "block"; }
    if (details) { details.innerHTML = '<div style="color:var(--dim)">正在测试 Gemini / 谷歌 / AI 连通性，请稍候（约需 3-5 秒）…</div>'; }
    busy(this, api("/api/warp/test"), "测试解锁中…").then(function (r) {
      if (r && r.ok && r.data) {
        var d = r.data;
        var items = [
          { name: "Gemini AI", res: d.gemini, target: "gemini.google.com" },
          { name: "Google 搜索/服务", res: d.google, target: "google.com" },
          { name: "YouTube", res: d.youtube, target: "youtube.com" },
          { name: "ChatGPT / OpenAI", res: d.chatgpt, target: "chatgpt.com" }
        ];
        var cards = items.map(function (it) {
          var pass = it.res && it.res.ok;
          return '<div class="test-card ' + (pass ? "ok" : "fail") + '">' +
            '<div><div style="font-weight:600">' + esc(it.name) + '</div><div class="dim" style="font-size:11px">' + esc(it.target) + '</div></div>' +
            '<div class="test-status ' + (pass ? "ok" : "fail") + '">' + (pass ? "✅ 已解锁" : "⚠️ " + esc(it.res ? it.res.status : "未解锁")) + '</div>' +
          '</div>';
        }).join("");

        var traceCard = '<div class="test-card ok" style="grid-column: 1 / -1">' +
          '<div><div style="font-weight:600">Cloudflare 出口 IP &amp; 地区</div><div class="dim" style="font-size:11px">WARP 状态: ' + (d.warp_on ? "已开启 (WARP ON)" : "未开启 (直连)") + '</div></div>' +
          '<div style="font-family:monospace;font-weight:600;color:#58a6ff">' + esc(d.warp_ip || "原生 IP") + (d.warp_loc ? " [" + esc(d.warp_loc) + "]" : "") + '</div>' +
        '</div>';

        if (details) { details.innerHTML = cards + traceCard; }
        toast("解锁连通性测试完成");
      }
    });
  });
}

var btnRegenWarp = $("#btn-regen-warp");
if (btnRegenWarp) {
  btnRegenWarp.addEventListener("click", function () {
    if (!confirm("确定要重新向 Cloudflare 注册并获取全新的 WARP 账号与密钥吗？")) { return; }
    busy(this, api("/api/warp", "POST", { action: "regen" }), "正在注册新账号…").then(function (r) {
      if (r && r.ok) {
        toast("WARP 账号已刷新并重载服务");
        loadStatus();
      }
    });
  });
}

var btnSubSw = $("#btn-sub-switch");
if (btnSubSw) {
  btnSubSw.addEventListener("click", function () {
    var sub = $("#f-subon").value;
    if (!sub) { toast("请选择订阅服务开关状态"); return; }
    busy(this, api("/api/sub", "POST", { action: sub }), "保存订阅设置").then(function (r) {
      if (r && r.ok) {
        toast("订阅服务设置已更新");
        loadStatus();
      }
    });
  });
}

var btnCfStart = $("#btn-cf-start");
if (btnCfStart) {
  btnCfStart.addEventListener("click", function () {
    var tok = ($("#f-cf-token").value || "").trim();
    if (!tok) { toast("请输入 Cloudflare Tunnel Token"); return; }
    busy(this, api("/api/cloudflared", "POST", { action: "set_token", token: tok }), "启动隧道中…").then(function (r) {
      if (r && r.ok) {
        toast("Cloudflare Tunnel 已成功启动");
        loadStatus();
      }
    });
  });
}
var btnCfStop = $("#btn-cf-stop");
if (btnCfStop) {
  btnCfStop.addEventListener("click", function () {
    busy(this, api("/api/cloudflared", "POST", { action: "stop" }), "停止隧道中…").then(function (r) {
      if (r && r.ok) {
        toast("Cloudflare Tunnel 已停止");
        loadStatus();
      }
    });
  });
}
var btnCfInstall = $("#btn-cf-install");
if (btnCfInstall) {
  btnCfInstall.addEventListener("click", function () {
    busy(this, api("/api/cloudflared", "POST", { action: "install" }), "下载安装中…").then(function (r) {
      if (r && r.ok) {
        toast("cloudflared 安装成功");
        loadStatus();
      }
    });
  });
}
var btnCfQuick = $("#btn-cf-quick");
if (btnCfQuick) {
  btnCfQuick.addEventListener("click", function () {
    var msg = $("#cf-tunnel-msg");
    if (msg) { msg.textContent = "正在启动临时快速隧道并申请域名，请稍候（约需 5 秒）…"; }
    busy(this, api("/api/cloudflared", "POST", { action: "quick" }), "创建快速隧道…").then(function (r) {
      if (r && r.ok && r.data && r.data.url) {
        if (msg) {
          msg.innerHTML = '✅ 临时访问地址: <a href="' + esc(r.data.url) + '" target="_blank" style="color:#58a6ff;text-decoration:underline">' + esc(r.data.url) + '</a> (外网直接免端口免证书访问)';
        }
        toast("快速隧道已就绪");
      }
    });
  });
}

var btnRandPorts = $("#btn-rand-ports");
if (btnRandPorts) {
  btnRandPorts.addEventListener("click", function () {
    if (!confirm("确认将全部协议分配互不相同的独立高位随机端口（10000~60000）？\n每个协议将拥有完全不同的端口，自动避开系统保留端口，并自动重启内核与更新订阅！")) {
      return;
    }
    busy(btnRandPorts, api("/api/ports", "POST", { action: "randomize" }), "正在随机端口…").then(function (r) {
      if (r && r.ok) {
        if (r.data && r.data.protolist) {
          updateProtoList(r.data.protolist);
        }
        toast("✅ 全部协议独立随机端口已分配并生效！");
        loadStatus();
      }
    });
  });
}
var btnResetPorts = $("#btn-reset-ports");
if (btnResetPorts) {
  btnResetPorts.addEventListener("click", function () {
    if (!confirm("确认将所有协议恢复为默认预设端口？")) {
      return;
    }
    busy(btnResetPorts, api("/api/ports", "POST", { action: "reset" }), "正在重置…").then(function (r) {
      if (r && r.ok) {
        if (r.data && r.data.protolist) {
          updateProtoList(r.data.protolist);
        }
        toast("✅ 已恢复所有协议为默认端口！");
        loadStatus();
      }
    });
  });
}
var btnTogglePortMgr = $("#btn-toggle-port-mgr");
if (btnTogglePortMgr) {
  btnTogglePortMgr.addEventListener("click", function () {
    var p = $("#port-mgr-panel");
    if (p) {
      if (p.style.display === "none") {
        p.style.display = "block";
        renderPortMgrGrid();
      } else {
        p.style.display = "none";
      }
    }
  });
}
var btnSavePorts = $("#btn-save-custom-ports");
if (btnSavePorts) {
  btnSavePorts.addEventListener("click", function () {
    var inputs = $$(".custom-port-inp");
    var pports = {};
    for (var i = 0; i < inputs.length; i++) {
      var pid = inputs[i].getAttribute("data-pid");
      var val = parseInt(inputs[i].value.trim(), 10);
      if (!isNaN(val) && val >= 1024 && val <= 65535) {
        pports[pid] = val;
      }
    }
    busy(btnSavePorts, api("/api/ports", "POST", { action: "batch", proto_ports: pports }), "正在保存…").then(function (r) {
      if (r && r.ok) {
        toast("独立端口配置已保存并重载内核");
        loadStatus();
      }
    });
  });
}

$("#btn-cfg").addEventListener("click", function () {
  var payload = {};
  var map = {
    domain: "#f-domain", uuid: "#f-uuid", port: "#f-port",
    upip: "#f-upip", subtoken: "#f-subtoken", prefix: "#f-prefix",
    reality_sni: "#f-rsni", reality_dest: "#f-rdest", reality_port: "#f-rport"
  };
  Object.keys(map).forEach(function (key) {
    var v = $(map[key]).value.trim();
    if (v) { payload[key] = v; }
  });
  if (!Object.keys(payload).length) { toast("没有可提交的字段"); return; }
  busy(this, api("/api/cfg", "POST", payload), "保存全局配置").then(function (r) {
    if (r && r.ok && r.data) { applyStatus(r.data.data || r.data); }
  });
});
$("#btn-genuuid").addEventListener("click", function () {
  var buf = new Uint8Array(16);
  if (window.crypto && crypto.getRandomValues) { crypto.getRandomValues(buf); }
  else { for (var i = 0; i < 16; i++) { buf[i] = Math.floor(Math.random() * 256); } }
  buf[6] = (buf[6] & 0x0f) | 0x40;
  buf[8] = (buf[8] & 0x3f) | 0x80;
  var hex = Array.prototype.map.call(buf, function (b) {
    return ("0" + b.toString(16)).slice(-2);
  }).join("");
  $("#f-uuid").value = hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) +
    "-" + hex.slice(16, 20) + "-" + hex.slice(20);
  toast("已生成新 UUID（记得点「保存全局配置」）");
});

var dProcs = $("#detect-procs");
if (dProcs) {
  dProcs.addEventListener("click", function (e) {
    var copyBtn = e.target.closest(".copy-tp-link");
    if (copyBtn) {
      var lk = copyBtn.getAttribute("data-link");
      if (lk) { copyText(lk, copyBtn); }
      return;
    }
    var actBtn = e.target.closest("[data-kill-action]");
    if (actBtn) {
      var action = actBtn.getAttribute("data-kill-action");
      var pid = actBtn.getAttribute("data-pid");
      var name = actBtn.getAttribute("data-name") || "外部代理服务";
      var exe = actBtn.getAttribute("data-exe") || "";
      var cfg = actBtn.getAttribute("data-config") || "";
      var tip = action === "uninstall" ?
        "【警告】确定要彻底卸载外部代理组件「" + name + "」(PID: " + pid + ") 吗？\n将停止运行并安全清理其配置文件，释放占用端口。" :
        "确定要停止外部代理进程「" + name + "」(PID: " + pid + ") 并立即释放其占用的端口吗？";
      if (!confirm(tip)) { return; }
      busy(actBtn, api("/api/kill_third_party", "POST", {
        action: action, pid: pid, name: name, exe: exe, config: cfg
      }), action === "uninstall" ? "正在卸载…" : "正在停止…").then(function (r) {
        if (r && r.ok) {
          toast(r.data && r.data.message ? r.data.message : "操作成功");
          loadStatus();
        }
      });
    }
  });
}

/* --------------------------------------------------------------- 初始化 */
renderProtos();
loadStatus(null);
</script>
</body>
</html>
"""


def build_page():
    """渲染单页 HTML（注入协议清单 JSON）。"""
    proto_json = json.dumps(PROTOCOLS, ensure_ascii=False, separators=(",", ":"))
    return PAGE_TEMPLATE.replace("/*__PROTOS__*/[]", proto_json).encode("utf-8")


# ------------------------------------------------------------ HTTP 处理器 ---
class PanelHandler(http.server.BaseHTTPRequestHandler):
    """单文件面板的 HTTP 处理器：路由 / 鉴权 / CSRF / 请求体限制。"""

    server_version = ""
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 300  # 单连接空闲超时（秒）

    # ---- 基础设施 ----
    def log_message(self, fmt, *args):
        """屏蔽默认访问日志（本类自己按统一格式记录）。"""
        return

    def send_response(self, code, message=None):
        """覆盖父类实现，不发送 Server 版本头。"""
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def _send(self, status, payload, raw=None, ctype="application/json; charset=utf-8", extra=None):
        """统一发送响应，始终带 Content-Length，支持 gzip 压缩。"""
        body = raw if raw is not None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = list(extra or [])
        accept_enc = self.headers.get("Accept-Encoding", "")
        if "gzip" in accept_enc and len(body) > 256:
            try:
                compressed = gzip.compress(body, compresslevel=6)
                if len(compressed) < len(body):
                    body = compressed
                    headers.append(("Content-Encoding", "gzip"))
            except Exception:
                pass
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in headers:
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            try:
                self.wfile.flush()
            except Exception:
                pass
        except (BrokenPipeError, ConnectionResetError):
            pass
        return status

    def _send_error_json(self, status, message, stderr=""):
        """发送统一格式的失败响应。"""
        return self._send(status, error_payload(message, stderr))

    def _request_path(self):
        """取出请求路径，并剥离 nginx 注入的面板随机路径前缀。"""
        path = urllib.parse.urlparse(self.path).path or "/"
        prefix = "/" + self.server.panel_path
        if path == prefix:
            path = "/"
        elif path.startswith(prefix + "/"):
            path = path[len(prefix):]
        return path or "/"

    def _remote(self):
        """返回客户端地址（nginx 反代时优先 X-Forwarded-For 首段）。"""
        fwd = self.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "-"

    # ---- 鉴权 / CSRF ----
    def _auth_token(self):
        """从查询参数 / 请求头 / Cookie 中提取候选 token。"""
        candidates = []
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if query.get("t"):
            candidates.append(query["t"][0])
        header = self.headers.get("X-Panel-Token")
        if header:
            candidates.append(header.strip())
        try:
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            if "degwd_panel" in jar:
                candidates.append(jar["degwd_panel"].value)
        except Exception:
            pass
        return candidates

    def _authed(self):
        """常量时间比较鉴权 token。"""
        expected = self.server.panel_token or ""
        if not expected:
            return False
        for candidate in self._auth_token():
            try:
                if hmac.compare_digest(str(candidate), expected):
                    return True
            except Exception:
                continue
        return False

    def _check_csrf(self):
        """校验 Origin/Referer 的 host 与 Host 头一致，返回 (是否通过, 原因)。"""
        host = (self.headers.get("Host") or "").strip().lower()
        source = self.headers.get("Origin") or self.headers.get("Referer") or ""
        source = source.strip()
        if not host:
            return False, "缺少 Host 头"
        if not source:
            return False, "缺少 Origin/Referer 头"
        match = re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://([^/?#]+)", source)
        if not match:
            return False, "Origin/Referer 格式非法"
        origin_netloc = match.group(1).lower()
        if origin_netloc == host:
            return True, ""
        # 容忍默认端口写法差异（https://a.com 与 a.com:443）
        def split(netloc):
            if netloc.startswith("["):
                idx = netloc.find("]")
                return netloc[:idx + 1], netloc[idx + 2:] or ""
            if ":" in netloc:
                head, _, tail = netloc.rpartition(":")
                return head, tail
            return netloc, ""
        oh, op = split(origin_netloc)
        hh, hp = split(host)
        if oh != hh:
            return False, "Origin/Referer 与 Host 不一致"
        if op and hp and op != hp:
            return False, "Origin/Referer 与 Host 端口不一致"
        return True, ""

    def _set_auth_cookie(self):
        """鉴权通过后下发 HttpOnly Cookie。"""
        value = self.server.panel_token
        return ("Set-Cookie",
                "degwd_panel=%s; HttpOnly; SameSite=Strict; Path=/" % value)

    def _log_request(self, started, path, status):
        """按统一格式把访问日志写到 stderr（systemd journal）。"""
        _log("%s %s %s %s %dms" % (self._remote(), self.command, path, status,
                                   int((time.time() - started) * 1000)))

    def _drain_body(self, limit=MAX_DRAIN):
        """在提前返回错误响应前读完请求体，避免 keep-alive 连接错位。

        返回 True 表示请求体超过 limit、仍有残留字节未读，调用方应关闭连接。
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            return False
        if length <= 0:
            return False
        remaining = min(length, limit)
        while remaining > 0:
            try:
                chunk = self.rfile.read(min(65536, remaining))
            except Exception:
                return True
            if not chunk:
                break
            remaining -= len(chunk)
        if length > limit:
            self.close_connection = True
            return True
        return False

    # ---- 请求体 ----
    def _read_body(self):
        """读取并解析请求体，返回 (字典, 错误响应状态或 None)。"""
        ctype = (self.headers.get("Content-Type") or "").strip().lower()
        if not ctype:
            self._drain_body()
            return None, self._send_error_json(415, "缺少 Content-Type 头")
        length = self.headers.get("Content-Length")
        if length is None:
            return None, self._send_error_json(413, "缺少 Content-Length")
        try:
            size = int(length)
        except ValueError:
            return None, self._send_error_json(400, "Content-Length 非法")
        if size < 0:
            return None, self._send_error_json(400, "Content-Length 非法")
        if size > MAX_BODY:
            # 超大请求体不读取（避免被慢速客户端拖住线程），直接断连返回 413
            self.close_connection = True
            return None, self._send_error_json(413, "请求体超过 %d 字节上限" % MAX_BODY)
        raw = self.rfile.read(size) if size else b""
        text = raw.decode("utf-8", errors="replace")
        if ctype.startswith("application/json"):
            try:
                data = json.loads(text) if text.strip() else {}
            except Exception as exc:
                return None, self._send_error_json(400, "JSON 解析失败: %s" % exc)
        elif ctype.startswith("application/x-www-form-urlencoded"):
            parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
            data = {k: v[0] for k, v in parsed.items()}
        else:
            self._drain_body()
            return None, self._send_error_json(415, "不支持的 Content-Type: %s" % ctype)
        if not isinstance(data, dict):
            return None, self._send_error_json(400, "请求体必须是 JSON 对象")
        return data, None

    # ---- 路由 ----
    def do_GET(self):
        """处理 GET：页面 / 状态 / 链接。"""
        started = time.time()
        status = 500
        path = self._request_path()
        try:
            if not self._authed():
                status = self._send_error_json(401, "未授权")
                return
            if path == "/":
                status = self._send(200, None, raw=build_page(),
                                    ctype="text/html; charset=utf-8",
                                    extra=[self._set_auth_cookie(),
                                           ("Content-Security-Policy",
                                            "default-src 'none'; script-src 'unsafe-inline'; "
                                            "style-src 'unsafe-inline'; connect-src 'self'; "
                                            "img-src 'self' data:; base-uri 'none'; form-action 'none'")])
            elif path == "/api/status":
                status = self._handle_status()
            elif path == "/api/detect":
                status = self._handle_detect()
            elif path == "/api/links":
                status = self._handle_links()
            elif path == "/api/warp/test":
                status = self._finish_cli(run_cli(["warp", "test"]))
            elif path == "/api/cloudflared":
                status = self._finish_cli(run_cli(["cf_tunnel", "status"]))
            elif path == "/api/ports":
                status = self._finish_cli(run_cli(["ports", "list"]))
            else:
                status = self._send_error_json(404, "路径不存在")
        except Exception as exc:  # 任何异常都不能让进程崩溃
            _log("GET %s 异常: %s: %s" % (path, type(exc).__name__, exc))
            status = self._send_error_json(500, "内部错误: %s" % type(exc).__name__)
        finally:
            self._log_request(started, path, status)

    def do_POST(self):
        """处理 POST：协议 / 配置 / 重建 / 重置。"""
        started = time.time()
        status = 500
        path = self._request_path()
        try:
            if not self._authed():
                self._drain_body()
                status = self._send_error_json(401, "未授权")
                return
            ok, reason = self._check_csrf()
            if not ok:
                self._drain_body()
                status = self._send_error_json(403, "CSRF 校验失败: %s" % reason)
                return
            if path not in ("/api/protos", "/api/cfg", "/api/regen", "/api/reset",
                            "/api/warp", "/api/sub", "/api/kill_third_party", "/api/cloudflared", "/api/ports"):
                self._drain_body()
                status = self._send_error_json(404, "路径不存在")
                return
            body, early = self._read_body()
            if early is not None:
                status = early
                return
            if path == "/api/protos":
                status = self._handle_protos(body)
            elif path == "/api/cfg":
                status = self._handle_cfg(body)
            elif path == "/api/warp":
                status = self._handle_warp(body)
            elif path == "/api/cloudflared":
                status = self._handle_cloudflared(body)
            elif path == "/api/ports":
                status = self._handle_ports(body)
            elif path == "/api/sub":
                status = self._handle_switch(body, "sub")
            elif path == "/api/regen":
                status = self._handle_simple(["regen"])
            elif path == "/api/kill_third_party":
                status = self._handle_kill_third_party(body)
            else:
                status = self._handle_simple(["reset"])
        except Exception as exc:
            _log("POST %s 异常: %s: %s" % (path, type(exc).__name__, exc))
            status = self._send_error_json(500, "内部错误: %s" % type(exc).__name__)
        finally:
            self._log_request(started, path, status)

    # ---- HEAD 请求按 GET 逻辑处理 (报头一致, _send 内部根据 command != 'HEAD' 跳过响应体) ----
    do_HEAD = do_GET

    def _method_not_allowed(self):
        self._drain_body()
        self._send_error_json(405, "方法不允许")

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _method_not_allowed

    # ---- 业务处理 ----
    def _finish_cli(self, result):
        """把 CLI 结果映射为 HTTP 状态码并返回。"""
        if result["ok"]:
            return self._send(200, cli_payload(result))
        if result["timeout"]:
            return self._send(504, cli_payload(result))
        return self._send(502, cli_payload(result))

    def _handle_status(self):
        """GET /api/status —— 透传 --cli status。"""
        return self._finish_cli(run_cli(["status"]))

    def _handle_detect(self):
        """GET /api/detect —— 探测服务端已有代理组件与进程。"""
        return self._finish_cli(run_cli(["detect"]))

    def _handle_links(self):
        """GET /api/links —— 优先用 status 的结构化 links，否则调 --cli links 解析。"""
        status_res = run_cli(["status"])
        meta = status_res["data"] if isinstance(status_res["data"], dict) else {}
        structured = meta.get("links") if isinstance(meta.get("links"), list) else []
        suburl = meta.get("suburl", "")
        links = []
        if structured:
            # status 已带结构化链接（含 port / needs_domain），无需再跑一次 --cli links
            links = _normalize_links(structured)
            source = status_res
        else:
            source = run_cli(["links"])
            links = _parse_links_output(source["stdout"])
        payload = {
            "ok": bool(source["ok"]),
            "code": source["code"],
            "cmd": source["cmd"],
            "ms": source["ms"],
            "timeout": source["timeout"],
            "stdout": _clip(source["stdout"]),
            "stderr": _clip(source["stderr"]),
            "links": links,
            "suburl": suburl,
            "data": {"links": links, "suburl": suburl},
        }
        if not payload["ok"]:
            payload["error"] = "获取链接失败"
            return self._send(502, payload)
        return self._send(200, payload)

    def _handle_protos(self, body):
        """POST /api/protos —— 设置协议集合并立即生效。"""
        raw_ids = body.get("protos")
        if isinstance(raw_ids, str):
            raw_ids = re.split(r"[\s,]+", raw_ids.strip())
        if not isinstance(raw_ids, list):
            return self._send_error_json(400, "protos 必须是字符串数组")
        ids = []
        for item in raw_ids:
            if not isinstance(item, str):
                return self._send_error_json(400, "protos 元素必须是字符串")
            item = item.strip()
            if not item:
                continue
            if not PROTO_ID_RE.match(item):
                return self._send_error_json(400, "协议 id 非法: %s" % item[:64])
            if item not in PROTO_IDS:
                return self._send_error_json(400, "未知协议 id: %s" % item[:64])
            if item not in ids:
                ids.append(item)
        if not ids:
            return self._send_error_json(400, "至少需要勾选一个协议")
        return self._finish_cli(run_cli(["protos", " ".join(ids)]))

    def _handle_cfg(self, body):
        """POST /api/cfg —— 局部更新配置（只提交给出的字段）。"""
        # 与 server cli_cfg 支持的键保持一致（多出的键会被 server 忽略）
        allowed = ("domain", "port", "uuid", "subtoken", "prefix",
                   "reality_sni", "reality_dest", "reality_port", "upip", "cdn")
        payload = {}
        for key in allowed:
            if key not in body:
                continue
            value = body[key]
            if value is None:
                continue
            value = str(value).strip()
            if value == "":
                continue
            if key in ("domain", "reality_dest"):
                if not HOSTPORT_RE.match(value):
                    return self._send_error_json(400, "%s 格式非法（应为 host 或 host:port）" % key)
            elif key == "reality_sni":
                if not HOST_RE.match(value):
                    return self._send_error_json(400, "reality_sni 格式非法")
            elif key == "uuid":
                if not UUID_RE.match(value):
                    return self._send_error_json(400, "uuid 格式非法")
            elif key == "subtoken":
                if not TOKEN_RE.match(value):
                    return self._send_error_json(400, "subtoken 含非法字符")
            elif key == "prefix":
                if not PREFIX_RE.match(value):
                    return self._send_error_json(400, "prefix 含非法字符或过长")
            elif key in ("port", "reality_port"):
                if not re.fullmatch(r"[0-9]{1,5}", value) or not (1 <= int(value) <= 65535):
                    return self._send_error_json(400, "%s 必须是 1-65535" % key)
            elif key == "upip":
                if not UPIP_RE.match(value):
                    return self._send_error_json(400, "upip 只能包含字母、数字、点、冒号、连字符")
            payload[key] = value
        if not payload:
            return self._send_error_json(400, "没有可更新的字段")
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        # 走 stdin 传 JSON（server 端以 "-" 识别），避免命令行参数被环境改写
        return self._finish_cli(run_cli(["cfg", "-"], stdin_data=encoded))

    def _handle_simple(self, args):
        """POST /api/regen 与 /api/reset 的共用处理。"""
        return self._finish_cli(run_cli(args))

    def _handle_warp(self, body):
        """POST /api/warp —— 出口代理模式、刷新账号或启停。"""
        if not isinstance(body, dict):
            return self._send_error_json(400, "请求体必须是 JSON 对象")
        action = str(body.get("action") or "set_mode").strip().lower()
        mode = str(body.get("mode") or "").strip()
        if action in ("set_mode", "mode"):
            return self._finish_cli(run_cli(["warp", "set", mode or "warp_google"]))
        elif action == "on":
            return self._finish_cli(run_cli(["warp", "on", mode or "warp_google"]))
        elif action == "off":
            return self._finish_cli(run_cli(["warp", "off"]))
        elif action == "regen":
            return self._finish_cli(run_cli(["warp", "regen"]))
        elif action == "test":
            return self._finish_cli(run_cli(["warp", "test"]))
        return self._send_error_json(400, "未知动作: %s" % action)

    def _handle_cloudflared(self, body):
        """POST /api/cloudflared —— 管理 cloudflared 穿透隧道。"""
        if not isinstance(body, dict):
            return self._send_error_json(400, "请求体必须是 JSON 对象")
        action = str(body.get("action") or "").strip().lower()
        if action == "install":
            return self._finish_cli(run_cli(["cf_tunnel", "install"]))
        elif action in ("set_token", "token"):
            tok = str(body.get("token") or "").strip()
            if not tok:
                return self._send_error_json(400, "Token 不能为空")
            return self._finish_cli(run_cli(["cf_tunnel", "token", tok]))
        elif action == "stop":
            return self._finish_cli(run_cli(["cf_tunnel", "stop"]))
        elif action == "start":
            return self._finish_cli(run_cli(["cf_tunnel", "start"]))
        elif action == "quick":
            port = str(body.get("port") or "").strip()
            args = ["cf_tunnel", "quick"]
            if port and port.isdigit():
                args.append(port)
            return self._finish_cli(run_cli(args))
        return self._send_error_json(400, "未知动作: %s" % action)

    def _handle_switch(self, body, kind):
        """POST /api/sub —— 订阅服务开关。"""
        action = body.get("action")
        if isinstance(action, str):
            action = action.strip().lower()
        if action not in ("on", "off"):
            return self._send_error_json(400, "action 必须是 on 或 off")
        return self._finish_cli(run_cli(["sub", action]))

    def _handle_kill_third_party(self, body):
        """POST /api/kill_third_party —— 一键停止或卸载外部第三方代理进程。"""
        if not isinstance(body, dict):
            return self._send_error_json(400, "请求体必须是 JSON 对象")
        action = str(body.get("action") or "stop").strip().lower()
        if action not in ("stop", "uninstall"):
            return self._send_error_json(400, "无效的操作类型: %s" % action)
        pid = body.get("pid")
        if not pid or not str(pid).isdigit():
            return self._send_error_json(400, "无效的 PID")

        payload = json.dumps({
            "action": action,
            "pid": int(pid),
            "name": str(body.get("name") or ""),
            "exe": str(body.get("exe") or ""),
            "config": str(body.get("config") or ""),
        })
        return self._finish_cli(run_cli(["kill_tp", payload]))

    def _handle_ports(self, body):
        """POST /api/ports —— 随机端口 / 重置端口 / 单独修改指定协议端口。"""
        if not isinstance(body, dict):
            return self._send_error_json(400, "请求体必须是 JSON 对象")
        action = str(body.get("action") or "").strip().lower()
        if action in ("randomize", "rand"):
            return self._finish_cli(run_cli(["ports", "randomize"]))
        elif action == "reset":
            return self._finish_cli(run_cli(["ports", "reset"]))
        elif action == "set":
            pid = str(body.get("id") or "").strip()
            port = str(body.get("port") or "").strip()
            if not PROTO_ID_RE.match(pid):
                return self._send_error_json(400, "非法协议 ID")
            if not re.match(r"^[0-9]+$", port) or not (1024 <= int(port) <= 65535):
                return self._send_error_json(400, "端口必须在 1024-65535 之间")
            return self._finish_cli(run_cli(["ports", "set", pid, port]))
        elif action == "batch":
            pports = body.get("proto_ports")
            if not isinstance(pports, dict):
                return self._send_error_json(400, "proto_ports 必须为键值对对象")
            clean_ports = {}
            for k, v in pports.items():
                if PROTO_ID_RE.match(str(k)):
                    try:
                        pv = int(v)
                        if 1024 <= pv <= 65535:
                            clean_ports[str(k)] = pv
                    except (ValueError, TypeError):
                        continue
            return self._finish_cli(run_cli(["cfg", "-"], stdin_data=json.dumps({"proto_ports": clean_ports})))
        return self._send_error_json(400, "未知动作: %s，支持 randomize|reset|set|batch" % action)


# ------------------------------------------------------------------- 启动 ---
def serve(bind, port, token, path):
    """启动 ThreadingHTTPServer（阻塞直到 Ctrl+C）。"""
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    server = http.server.ThreadingHTTPServer((bind, port), PanelHandler)
    server.daemon_threads = True
    server.panel_token = token
    server.panel_path = path
    _log("面板已启动 http://%s:%d/  随机路径段=/%s  token 长度=%d  BASE=%s"
         % (bind, port, path, len(token), BASE))
    if not os.path.exists(SERVER):
        _log("警告：主脚本不存在（%s），所有操作将返回 502" % SERVER)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        _log("收到中断信号，正在退出")
    finally:
        server.server_close()
    return 0


def _print_config(token, path, bind, port):
    """以可 eval 的 shell 变量形式输出配置。"""
    safe = lambda s: str(s).replace("'", "")
    print("PANEL_TOKEN='%s'" % safe(token))
    print("PANEL_PATH='%s'" % safe(path))
    print("PANEL_BIND='%s'" % safe(bind))
    print("PANEL_PORT='%s'" % safe(port))


def _self_check():
    """自检：读取 conf.json 并调用一次 --cli status。"""
    print("== 面板自检 ==")
    print("BASE       : %s" % BASE)
    print("SERVER     : %s (%s)" % (SERVER, "存在" if os.path.exists(SERVER) else "缺失"))
    print("CONF       : %s (%s)" % (CONF, "存在" if os.path.exists(CONF) else "缺失"))
    conf = _read_conf()
    panel = conf.get("panel") if isinstance(conf.get("panel"), dict) else {}
    print("conf 顶层键 : %s" % ", ".join(sorted(conf.keys())) or "(空)")
    print("panel.token: %s" % ("已设置(%d 位)" % len(str(panel.get("token") or ""))
                               if panel.get("token") else "未设置"))
    print("panel.path : %s" % (panel.get("path") or "未设置"))
    print("协议清单   : %d 个" % len(PROTOCOLS))
    print("-- 调用 --cli status --")
    result = run_cli(["status"])
    print("退出码     : %s" % result["code"])
    print("耗时       : %dms" % result["ms"])
    print("stdout     :\n%s" % _clip(result["stdout"], 2000))
    if result["stderr"]:
        print("stderr     :\n%s" % _clip(result["stderr"], 2000))
    print("解析结果   : %s" % json.dumps(result["data"], ensure_ascii=False))
    return 0 if result["ok"] else 1


def main(argv=None):
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        description="朔月 Shuoyue / de_GWD 单文件 Web 面板（仅标准库）")
    parser.add_argument("--print-config", action="store_true",
                        help="打印 PANEL_TOKEN/PANEL_PATH/PANEL_BIND/PANEL_PORT 后退出")
    parser.add_argument("--check", action="store_true",
                        help="自检：读取 conf.json 并调用一次 --cli status")
    parser.add_argument("--extract-links", nargs="*", default=None,
                        help="提取第三方代理的原始 v2rayN 分享链接")
    parser.add_argument("--bind", default=None, help="监听地址（默认 0.0.0.0）")
    parser.add_argument("--port", type=int, default=None, help="监听端口（默认 3000）")
    args = parser.parse_args(argv)

    if args.extract_links is not None:
        conf_p = args.extract_links[0] if len(args.extract_links) > 0 else ""
        exe_p = args.extract_links[1] if len(args.extract_links) > 1 else ""
        pid_val = args.extract_links[2] if len(args.extract_links) > 2 else None
        links = extract_third_party_links(conf_p, exe_p, pid_val)
        print(json.dumps(links, ensure_ascii=False))
        return 0

    try:
        token, path, default_port = ensure_panel_secrets()
    except Exception as exc:
        _log("初始化面板凭据失败: %s: %s" % (type(exc).__name__, exc))
        return 2

    bind = args.bind or os.environ.get("DEGWD_PANEL_BIND", "0.0.0.0")
    try:
        env_port = os.environ.get("DEGWD_PANEL_PORT")
        port = args.port or (int(env_port) if env_port else None) or (int(default_port) if default_port else 3000)
    except ValueError:
        port = int(default_port) if default_port else 3000

    if args.print_config:
        _print_config(token, path, bind, port)
        return 0
    if args.check:
        return _self_check()
    return serve(bind, port, token, path)


if __name__ == "__main__":
    sys.exit(main())
