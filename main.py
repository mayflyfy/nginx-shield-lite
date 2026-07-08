from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import hashlib
import glob
import json
import mimetypes
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import parse_qs, urlsplit

# ========== Config ==========
BASE_DIR = Path(__file__).resolve().parent
WEB_ROOT = BASE_DIR / "web"
DLC_ROOT = BASE_DIR / "dlc"


def _safe_child(root, relative):
    """Resolve an untrusted relative path without allowing directory escape."""
    target = (root / relative).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    return target


def _load_dlc_plugins():
    """Discover optional DLCs without making them a core dependency."""
    disabled = {
        item.strip()
        for item in os.environ.get("NSL_DISABLED_DLC", "").split(",")
        if item.strip()
    }
    plugins = []
    claimed_routes = set()
    if not DLC_ROOT.is_dir():
        return plugins

    for manifest_path in sorted(DLC_ROOT.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            plugin_id = manifest["id"]
            if not re.fullmatch(r"[a-z][a-z0-9_]*", plugin_id):
                raise ValueError("id 必须使用 snake_case")
            if plugin_id in disabled or not manifest.get("enabled_by_default", True):
                continue
            root = manifest_path.parent.resolve()
            routes = {}
            for route, relative in manifest.get("routes", {}).items():
                route = "/" + route.strip("/")
                if route == "/" or route.startswith(("/api/", "/static/", "/dlc/")):
                    raise ValueError(f"扩展路由使用了核心保留路径: {route}")
                if route in claimed_routes:
                    raise ValueError(f"扩展路由冲突: {route}")
                target = _safe_child(root, relative)
                if target is None or not target.is_file():
                    raise ValueError(f"路由文件不存在: {relative}")
                routes[route] = target
            claimed_routes.update(routes)
            plugins.append({
                "id": plugin_id,
                "name": manifest.get("name", plugin_id),
                "version": manifest.get("version", "0"),
                "root": root,
                "routes": routes,
                "nav": manifest.get("nav"),
            })
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            print(f"[DLC] 跳过 {manifest_path}: {exc}")
    return plugins


DLC_PLUGINS = _load_dlc_plugins()
DLC_ROUTES = {
    route: (plugin, target)
    for plugin in DLC_PLUGINS
    for route, target in plugin["routes"].items()
}


def _configured_log_paths():
    configured = os.environ.get("NSL_LOG_PATHS", "/var/log/nginx/access.log*")
    paths = []
    for entry in configured.split(","):
        entry = entry.strip()
        if not entry:
            continue
        matches = glob.glob(entry) if any(char in entry for char in "*?[") else [entry]
        paths.extend(matches)

    def rotation_key(path):
        name = os.path.basename(path)
        if name == "access.log":
            return (0, 0, name)
        match = re.search(r"\.(\d+)(?:\.gz)?$", name)
        return (1, int(match.group(1)) if match else 10**9, name)

    return sorted(dict.fromkeys(paths), key=rotation_key)


LOG_PATHS = _configured_log_paths()
BLACKLIST_PATH = os.environ.get(
    "NSL_BLACKLIST_PATH", "/etc/nginx/conf.d/black_ip.conf"
)
TRUSTEDLIST_PATH = os.environ.get(
    "NSL_TRUSTEDLIST_PATH", "/etc/nginx/conf.d/trusted_ip.conf"
)
PORT = int(os.environ.get("NSL_PORT", "9999"))
LOG_CHUNK_SIZE = 8 * 1024 * 1024
LIST_PATHS = {
    "black": BLACKLIST_PATH,
    "trusted": TRUSTEDLIST_PATH,
}


def normalize_app_path(path):
    """Accept direct routes and routes mounted below an Nginx subpath.

    Examples:
      /static/app.js        -> /static/app.js
      /cstat/static/app.js  -> /static/app.js
      /cstat/api/config     -> /api/config
      /cstat/blocked        -> /blocked（由可选 DLC 提供）
    """
    for marker in ("/api/", "/static/", "/dlc/"):
        position = path.find(marker)
        if position >= 0:
            return path[position:]
    trimmed = path.rstrip("/")
    for route in DLC_ROUTES:
        if trimmed == route or trimmed.endswith(route):
            return route
    if trimmed.endswith("/index.html"):
        return "/"
    segments = [segment for segment in trimmed.split("/") if segment]
    if not segments or (len(segments) == 1 and path.endswith("/")):
        return "/"
    return trimmed or "/"

BOTS = [
    ("Bingbot",       "必应", re.compile(r"bingbot", re.I)),
    ("Googlebot",     "谷歌", re.compile(r"googlebot", re.I)),
    ("BaiduSpider",   "百度", re.compile(r"baiduspider", re.I)),
    ("DuckDuckBot",   "DuckDuckGo", re.compile(r"duckduckbot", re.I)),
    ("YandexBot",     "Yandex", re.compile(r"yandexbot", re.I)),
    ("SogouSpider",   "搜狗", re.compile(r"sogou.*(?:spider|web)", re.I)),
    ("360Spider",     "360", re.compile(r"360spider|haosouspider", re.I)),
    ("Bytespider",    "字节", re.compile(r"bytespider", re.I)),
    ("PetalBot",      "华为花瓣", re.compile(r"petalbot", re.I)),
    ("YisouSpider",   "神马", re.compile(r"yisouspider|shenmaspider", re.I)),
    ("OAI-SearchBot", "OpenAI", re.compile(r"oai-searchbot", re.I)),
    ("ChatGPT-User",  "OpenAI 用户访问", re.compile(r"chatgpt-user", re.I)),
    ("GPTBot",        "OpenAI GPTBot", re.compile(r"gptbot", re.I)),
    ("Doubao-User",   "豆包用户访问", re.compile(r"samanthadoubao|appname/doubao", re.I)),
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
STATUS_PATTERN = re.compile(r"\" (\d{3}) ")

# ========== Core analysis ==========
def analyze_logs(paths=None, success_only=False):
    if paths is None:
        paths = LOG_PATHS
    bot_counts = {name: 0 for name, _, _ in BOTS}
    bot_counts["total"] = 0
    ip_counts = {}
    bot_ips = {}

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if success_only:
                        m_status = STATUS_PATTERN.search(line)
                        if m_status and m_status.group(1).startswith("4"):
                            continue
                    bot_counts["total"] += 1
                    matched_bot = None
                    for name, label, pat in BOTS:
                        if pat.search(line):
                            bot_counts[name] += 1
                            matched_bot = label
                            break
                    m = IP_PATTERN.match(line)
                    if m:
                        ip = m.group(1)
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
                        if matched_bot:
                            bot_ips[ip] = matched_bot
        except FileNotFoundError:
            pass

    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return bot_counts, sorted_ips, bot_ips


def _format_network(network):
    if network.prefixlen == 32:
        return str(network.network_address)
    return str(network)


def parse_blacklist(content):
    rules = []
    invalid = []
    for line_no, original in enumerate(content.splitlines(), 1):
        body = original.split("#", 1)[0].strip()
        if not body:
            continue
        parts = body.split()
        key = parts[0].rstrip(";")
        if not key or not key[0].isdigit():
            continue
        value = parts[1].rstrip(";") if len(parts) > 1 else ""
        try:
            network = ipaddress.ip_network(key, strict=False)
            if network.version != 4:
                raise ValueError("only IPv4 is supported")
        except ValueError:
            invalid.append({"line": line_no, "rule": key})
            continue
        if value not in ("0", "1"):
            continue
        rules.append({
            "line": line_no,
            "rule": key,
            "network": network,
            "value": int(value),
        })
    return rules, invalid


def _effective_blocked_ip_count(rules):
    root = {"value": None, "children": {}}
    for rule in rules:
        network = rule["network"]
        address = int(network.network_address)
        node = root
        for depth in range(network.prefixlen):
            bit = (address >> (31 - depth)) & 1
            node = node["children"].setdefault(bit, {"value": None, "children": {}})
        node["value"] = rule["value"]

    def count(node, depth, inherited):
        value = inherited if node["value"] is None else node["value"]
        size = 1 << (32 - depth)
        if not node["children"]:
            return size if value == 1 else 0
        half = size // 2
        return sum(
            count(node["children"][bit], depth + 1, value)
            if bit in node["children"] else (half if value == 1 else 0)
            for bit in (0, 1)
        )

    return count(root, 0, 0)


def _merge_sibling_networks(networks):
    sources = {network: {network} for network in networks}
    changed = True
    while changed:
        changed = False
        for network in sorted(list(sources), key=lambda item: item.prefixlen, reverse=True):
            if network.prefixlen == 0 or network not in sources:
                continue
            parent = network.supernet()
            children = list(parent.subnets(new_prefix=network.prefixlen))
            sibling = children[1] if network == children[0] else children[0]
            if sibling not in sources:
                continue
            merged_sources = sources.pop(network) | sources.pop(sibling)
            if parent in sources:
                sources[parent] |= merged_sources
            else:
                sources[parent] = merged_sources
            changed = True
            break
    return sources


def analyze_blacklist(content):
    rules, invalid = parse_blacklist(content)
    block_rules = [rule for rule in rules if rule["value"] == 1]
    networks = [rule["network"] for rule in block_rules]
    raw_ip_count = sum(network.num_addresses for network in networks)
    unique_ip_count = _effective_blocked_ip_count(rules)

    prefix_counts = {}
    for network in networks:
        prefix_counts[network.prefixlen] = prefix_counts.get(network.prefixlen, 0) + 1
    prefix_stats = [{
        "prefix": prefix,
        "label": "单IP" if prefix == 32 else f"/{prefix}",
        "rule_count": count,
        "ip_count": count * (1 << (32 - prefix)),
    } for prefix, count in sorted(prefix_counts.items())]

    redundant = []
    seen = {}
    rules_by_network = {}
    for rule in rules:
        rules_by_network.setdefault(rule["network"], rule)
    for rule in block_rules:
        network = rule["network"]
        if network in seen:
            redundant.append({
                "line": rule["line"],
                "rule": rule["rule"],
                "reason": f"与第{seen[network]['line']}行完全重复",
            })
            continue
        seen[network] = rule
        container = None
        for prefix in range(network.prefixlen - 1, -1, -1):
            candidate = network.supernet(new_prefix=prefix)
            if candidate in rules_by_network:
                container = rules_by_network[candidate]
                break
        if container:
            if container["value"] == 1:
                redundant.append({
                    "line": rule["line"],
                    "rule": rule["rule"],
                    "reason": f"已被第{container['line']}行 {_format_network(container['network'])} 包含",
                })

    redundant_lines = {item["line"] for item in redundant}
    essential_rules = [rule for rule in block_rules if rule["line"] not in redundant_lines]
    essential = {rule["network"] for rule in essential_rules}
    merged_networks = _merge_sibling_networks(essential)
    merge_suggestions = []
    for target, source_set in sorted(
        merged_networks.items(), key=lambda item: (int(item[0].network_address), item[0].prefixlen)
    ):
        sources = sorted(source_set, key=lambda network: (int(network.network_address), network.prefixlen))
        if len(sources) > 1:
            merge_suggestions.append({
                "sources": [_format_network(network) for network in sources],
                "target": _format_network(target),
            })

    redundant_by_line = {item["line"]: item["reason"] for item in redundant}
    merge_sources = {
        source
        for suggestion in merge_suggestions
        for source in suggestion["sources"]
    }
    rule_rows = []
    for rule in rules:
        network = rule["network"]
        canonical = _format_network(network)
        rule_rows.append({
            "line": rule["line"],
            "rule": rule["rule"],
            "canonical": canonical,
            "value": rule["value"],
            "prefix": network.prefixlen,
            "type": "single" if network.prefixlen == 32 else "cidr",
            "ip_count": network.num_addresses,
            "redundant": rule["line"] in redundant_by_line,
            "redundant_reason": redundant_by_line.get(rule["line"], ""),
            "merge_candidate": canonical in merge_sources,
        })

    source_lines = content.splitlines()
    valid_lines = {rule["line"] for rule in block_rules}
    placements = {}
    for target, source_set in merged_networks.items():
        matching_lines = [
            rule["line"] for rule in essential_rules
            if rule["network"] in source_set
        ]
        if matching_lines:
            placements[min(matching_lines)] = target
    optimized_lines = []
    for line_no, original in enumerate(source_lines, 1):
        if line_no in placements:
            optimized_lines.append(f"{_format_network(placements[line_no])} 1;")
        elif line_no not in valid_lines:
            optimized_lines.append(original)
    optimized_content = "\n".join(optimized_lines)
    if content.endswith(("\n", "\r")):
        optimized_content += "\n"

    return {
        "rule_count": len(block_rules),
        "raw_ip_count": raw_ip_count,
        "unique_ip_count": unique_ip_count,
        "prefix_stats": prefix_stats,
        "rules": rule_rows,
        "allow_rule_count": sum(rule["value"] == 0 for rule in rules),
        "redundant": redundant,
        "merge_suggestions": merge_suggestions,
        "invalid": invalid,
        "optimized_content": optimized_content,
        "changed": optimized_content != content,
    }


def read_list(name):
    path = LIST_PATHS.get(name)
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""
    except Exception:
        return None


def list_etag(name):
    path = LIST_PATHS.get(name)
    if not path:
        return None
    try:
        stat = os.stat(path)
        seed = f"{name}:{stat.st_size}:{stat.st_mtime_ns}".encode("ascii")
    except FileNotFoundError:
        seed = f"{name}:missing".encode("ascii")
    return '"' + hashlib.sha256(seed).hexdigest()[:24] + '"'


def write_list(name, content):
    path = LIST_PATHS.get(name)
    if not path:
        return False
    try:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}.",
            delete=False,
        ) as temp:
            temp.write(content)
            temp_path = temp.name
        os.replace(temp_path, target)
        return True
    except Exception:
        try:
            if "temp_path" in locals():
                os.unlink(temp_path)
        except OSError:
            pass
        return False


def read_blacklist():
    return read_list("black")


def write_blacklist(content):
    return write_list("black", content)


def log_manifest():
    result = []
    for index, path in enumerate(LOG_PATHS):
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            continue
        identity = hashlib.sha256(
            f"{path}:{stat.st_dev}:{stat.st_ino}".encode("utf-8")
        ).hexdigest()[:24]
        result.append({
            "index": index,
            "id": identity,
            "name": os.path.basename(path),
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "gzip": path.lower().endswith(".gz"),
        })
    return result


def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        output = (r.stdout + r.stderr).strip()
        return r.returncode == 0, output
    except Exception as e:
        return False, str(e)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = normalize_app_path(parsed.path)
        query = parse_qs(parsed.query)
        if path == "/":
            self._static("index.html")
        elif path in DLC_ROUTES:
            _, target = DLC_ROUTES[path]
            self._serve_file(target)
        elif path.startswith("/static/"):
            self._static(path.removeprefix("/static/"))
        elif path.startswith("/dlc/"):
            self._dlc_static(path)
        elif path == "/api/dlc":
            self._json({
                "plugins": [
                    {
                        "id": plugin["id"],
                        "name": plugin["name"],
                        "version": plugin["version"],
                        "nav": plugin["nav"],
                    }
                    for plugin in DLC_PLUGINS
                ]
            })
        elif path == "/api/logs/manifest":
            self._json({"files": log_manifest()})
        elif path == "/api/logs/chunk":
            self._log_chunk(query)
        elif path == "/api/stats":
            # Backwards-compatible endpoint. The new UI uses raw chunks and
            # computes aggregates in the browser.
            today = query.get("today") == ["1"]
            success = query.get("success") == ["1"]
            paths = [LOG_PATHS[0]] if today else LOG_PATHS
            bot_counts, sorted_ips, bot_ips = analyze_logs(paths, success_only=success)
            data = {"bots": bot_counts, "ips": sorted_ips, "bot_ips": bot_ips}
            self._json(data)
        elif path in ("/api/config", "/api/blacklist"):
            name = "black" if path == "/api/blacklist" else query.get("name", [""])[0]
            if name not in LIST_PATHS:
                self._json({"error": "未知名单"}, 400)
                return
            etag = list_etag(name)
            if etag and self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                return
            content = read_list(name)
            if content is None:
                self._json({"error": "读取失败"}, 500)
            else:
                self._json(
                    {"name": name, "content": content, "etag": etag},
                    extra_headers={"ETag": etag, "Cache-Control": "no-cache"},
                )
        elif path == "/api/nginx_test":
            ok, output = run_cmd("nginx -t 2>&1")
            self._json({"ok": ok, "output": output})
        elif path == "/api/nginx_reload":
            ok, output = run_cmd("nginx -s reload 2>&1")
            self._json({"ok": ok, "output": output})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = normalize_app_path(parsed.path)
        query = parse_qs(parsed.query)
        if path in ("/api/config", "/api/blacklist", "/api/blacklist/analyze"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                data = json.loads(body)
                content = data.get("content", "")
            except Exception:
                self._json({"error": "无效请求"}, 400)
                return
            if path == "/api/blacklist/analyze":
                self._json(analyze_blacklist(content))
            else:
                name = (
                    "black"
                    if path == "/api/blacklist"
                    else query.get("name", [""])[0]
                )
                if name not in LIST_PATHS:
                    self._json({"error": "未知名单"}, 400)
                elif write_list(name, content):
                    self._json({"ok": True, "etag": list_etag(name)})
                else:
                    self._json({"error": "写入失败"}, 500)
        else:
            self.send_response(404)
            self.end_headers()

    def _static(self, relative):
        target = _safe_child(WEB_ROOT, relative)
        if target is None:
            self.send_response(403)
            self.end_headers()
            return
        self._serve_file(target)

    def _dlc_static(self, path):
        parts = path.removeprefix("/dlc/").split("/", 1)
        if len(parts) != 2:
            self.send_response(404)
            self.end_headers()
            return
        plugin = next(
            (item for item in DLC_PLUGINS if item["id"] == parts[0]),
            None,
        )
        target = _safe_child(plugin["root"], parts[1]) if plugin else None
        if target is None:
            self.send_response(403 if plugin else 404)
            self.end_headers()
            return
        self._serve_file(target)

    def _serve_file(self, target):
        if not target.is_file():
            self.send_response(404)
            self.end_headers()
            return
        content = target.read_bytes()
        mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in ("application/javascript", "application/json"):
            mime += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _log_chunk(self, query):
        try:
            index = int(query.get("index", ["-1"])[0])
            offset = max(0, int(query.get("offset", ["0"])[0]))
        except ValueError:
            self._json({"error": "无效参数"}, 400)
            return
        if index < 0 or index >= len(LOG_PATHS):
            self._json({"error": "日志不存在"}, 404)
            return
        path = LOG_PATHS[index]
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            self._json({"error": "日志不存在"}, 404)
            return
        identity = hashlib.sha256(
            f"{path}:{stat.st_dev}:{stat.st_ino}".encode("utf-8")
        ).hexdigest()[:24]
        expected = query.get("id", [identity])[0]
        if expected != identity:
            self._json({"error": "日志已轮转，请刷新清单"}, 409)
            return
        if offset > stat.st_size:
            self._json({"error": "偏移量超过文件大小，请重建浏览器缓存"}, 416)
            return
        compressed = path.lower().endswith(".gz")
        if compressed and offset not in (0, stat.st_size):
            self._json({"error": "压缩日志只能整文件读取"}, 416)
            return
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                data = fh.read() if compressed else fh.read(LOG_CHUNK_SIZE)
                if not compressed and data and offset + len(data) < stat.st_size:
                    data += fh.readline()
                next_offset = offset + len(data)
        except OSError as exc:
            self._json({"error": str(exc)}, 500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Log-Id", identity)
        self.send_header("X-Next-Offset", str(next_offset))
        self.send_header("X-File-Size", str(stat.st_size))
        self.send_header("Cache-Control", "no-store")
        if compressed:
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, data, code=200, extra_headers=None):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or {}).items():
            if value is not None:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Server started at: http://0.0.0.0:{PORT}")
    if DLC_PLUGINS:
        print("DLC enabled: " + ", ".join(item["id"] for item in DLC_PLUGINS))
    server.serve_forever()
