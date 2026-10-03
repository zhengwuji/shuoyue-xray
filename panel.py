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
import gzip
import hmac
import http.cookies
import http.server
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse

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
.proto{display:flex;gap:10px;align-items:flex-start;cursor:pointer;user-select:none}
.proto:hover{border-color:var(--acc)}
.proto.on{border-color:var(--acc);box-shadow:inset 0 0 0 1px rgba(76,141,255,.25)}
.proto input{margin:3px 0 0;width:16px;height:16px;accent-color:var(--acc);flex:0 0 auto}
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
button.mini{padding:2px 9px;font-size:12px;border-radius:6px}
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

  <section>
    <h2>协议选择</h2>
    <div class="toolbar">
      <button class="mini" data-quick="all">全选</button>
      <button class="mini" data-quick="none">全不选</button>
      <button class="mini" data-quick="xray">仅 Xray</button>
      <button class="mini" data-quick="singbox">仅 Sing-box（含 Naive）</button>
      <span class="dim" id="pick-count"></span>
    </div>
    <div id="proto-groups"></div>
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

  <section>
    <h2>出口 / 订阅开关</h2>
    <div class="form">
      <div class="field">
        <label for="f-warp">Cloudflare WARP 出站（出口 IP 走 WARP） <span id="sw-warp" class="tag warn">未知</span></label>
        <select id="f-warp">
          <option value="">保持不变</option>
          <option value="on">启用</option>
          <option value="off">关闭并删除</option>
        </select>
      </div>
      <div class="field">
        <label for="f-subon">订阅服务（/sub/&lt;token&gt; 可访问） <span id="sw-sub" class="tag">未知</span></label>
        <select id="f-subon">
          <option value="">保持不变</option>
          <option value="on">启用</option>
          <option value="off">关闭</option>
        </select>
      </div>
    </div>
    <div class="toolbar" style="margin-top:12px">
      <button class="primary" id="btn-switch">应用开关</button>
      <span class="dim">WARP 首次启用需下载 wgcf 并注册，耗时较长（可能 1-2 分钟）</span>
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
function renderProtos() {
  var list = protoList();
  var groups = [["xray", "Xray 内核"], ["singbox", "Sing-box 内核"]];
  var host = $("#proto-groups");
  host.innerHTML = groups.map(function (g) {
    var items = list.filter(function (p) { return p.group === g[0]; });
    if (!items.length) { return ""; }
    var cards = items.map(function (p) {
      return '<label class="card proto" data-group="' + p.group + '" title="' + esc(p.desc || "") + '">' +
        '<input type="checkbox" class="pk" value="' + esc(p.id) + '">' +
        '<div><div class="pname">' + esc(p.name) + "</div>" +
        '<code class="pid">' + esc(p.id) + "</code>" +
        '<div class="meta"><span class="tag">' + esc(p.port) + "</span>" +
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
  updateCount();
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
function applyStatus(d) {
  if (!d || typeof d !== "object") { return; }
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
  if (d.protos) { setChecks(d.protos); }
  if (d.domain) { $("#f-domain").value = d.domain; }
  if (d.uuid) { $("#f-uuid").value = d.uuid; }
  if (d.subtoken) { $("#f-subtoken").value = d.subtoken; }
  var cfg = d.cfg || {};
  if (cfg.port) { $("#f-port").value = String(cfg.port); }
  if (cfg.upip) { $("#f-upip").value = cfg.upip; }
  if (cfg.prefix) { $("#f-prefix").value = cfg.prefix; }
  if (cfg.reality_sni) { $("#f-rsni").value = cfg.reality_sni; }
  if (cfg.reality_dest) { $("#f-rdest").value = cfg.reality_dest; }
  if (cfg.reality_port) { $("#f-rport").value = String(cfg.reality_port); }
  $("#sw-warp").textContent = d.warp ? "已启用" : "未启用";
  $("#sw-warp").className = "tag " + (d.warp ? "" : "warn");
  $("#sw-sub").textContent = d.sub_on === false ? "已关闭" : "已启用";
  $("#sw-sub").className = "tag " + (d.sub_on === false ? "warn" : "");
  setSub(d.suburl);
  if (Array.isArray(d.links)) { renderLinks(d.links); }
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

$("#btn-save").addEventListener("click", function () {
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
  busy(this, prepJob.then(function () {
    return api("/api/protos", "POST", { protos: ids });
  }), "保存并应用协议").then(function (r) {
    if (r && r.ok && r.data) { applyStatus(r.data.data || r.data); }
  });
});
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
$("#btn-switch").addEventListener("click", function () {
  var self = this;
  var warp = $("#f-warp").value;
  var sub = $("#f-subon").value;
  if (!warp && !sub) { toast("请至少选择一项开关"); return; }
  var jobs = [];
  if (warp) { jobs.push(api("/api/warp", "POST", { action: warp })); }
  if (sub) { jobs.push(api("/api/sub", "POST", { action: sub })); }
  busy(self, Promise.all(jobs), "应用开关").then(function (list) {
    var okAll = list.every(function (r) { return r && r.ok; });
    if (okAll) { loadStatus(); }
  });
});

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
            elif path == "/api/links":
                status = self._handle_links()
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
                            "/api/warp", "/api/sub"):
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
                status = self._handle_switch(body, "warp")
            elif path == "/api/sub":
                status = self._handle_switch(body, "sub")
            elif path == "/api/regen":
                status = self._handle_simple(["regen"])
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

    def _handle_switch(self, body, kind):
        """POST /api/warp 与 /api/sub —— 只接受 on / off 两种动作。"""
        action = body.get("action")
        if isinstance(action, str):
            action = action.strip().lower()
        if action not in ("on", "off"):
            return self._send_error_json(400, "action 必须是 on 或 off")
        if kind == "warp":
            return self._finish_cli(run_cli(["warp", action]))
        return self._finish_cli(run_cli(["sub", action]))


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
    parser.add_argument("--bind", default=None, help="监听地址（默认 0.0.0.0）")
    parser.add_argument("--port", type=int, default=None, help="监听端口（默认 3000）")
    args = parser.parse_args(argv)

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
