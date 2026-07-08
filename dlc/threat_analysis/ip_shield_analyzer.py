#!/usr/bin/env python3
"""Nginx access-log threat analysis with conservative block recommendations.

Designed for unattended, repeatable analysis:
  * reads plain and .gz rotated logs;
  * refreshes official crawler ranges and a local DB-IP country/ASN database;
  * verifies selected crawlers with forward-confirmed reverse DNS;
  * scores IPs and /24 networks from behavior, not geography alone;
  * audits an existing Nginx geo blacklist;
  * writes a self-contained Chinese HTML report and reviewable config files.

The script never modifies the active blacklist.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import gzip
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import socket
import statistics
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import requests

try:
    from .paths import ALLOWLIST_FILE, BLACKLIST_FILE, DATA_DIR, LOG_DIR, OUTPUT_DIR
except ImportError:
    from paths import ALLOWLIST_FILE, BLACKLIST_FILE, DATA_DIR, LOG_DIR, OUTPUT_DIR


VERSION = "1.0.0"
UA = "nginx-shield-lite-analyzer/1.0 (+local security analysis)"

OFFICIAL_RANGE_URLS = {
    "Google common crawler": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    "Google special crawler": "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    "Google user-triggered": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    "Google user-triggered (Google)": "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
    "OpenAI SearchBot": "https://openai.com/searchbot.json",
    "OpenAI ChatGPT-User": "https://openai.com/chatgpt-user.json",
    "OpenAI GPTBot": "https://openai.com/gptbot.json",
}

BOT_PATTERNS = [
    ("OpenAI ChatGPT-User", "ai_user", re.compile(r"chatgpt-user", re.I)),
    ("OpenAI SearchBot", "search", re.compile(r"oai-searchbot", re.I)),
    ("OpenAI GPTBot", "ai_training", re.compile(r"\bgptbot\b", re.I)),
    ("Google", "search", re.compile(r"googlebot|googleother|google-inspectiontool|adsbot-google|storebot-google", re.I)),
    ("Bing", "search", re.compile(r"bingbot|adidxbot|microsoftpreview", re.I)),
    ("Baidu", "search", re.compile(r"baiduspider", re.I)),
    ("Yandex", "search", re.compile(r"yandex(?:bot|images|mobile|accessibility|renderresources|video)", re.I)),
    ("Sogou", "search", re.compile(r"sogou.*(?:spider|web)", re.I)),
    ("360", "search", re.compile(r"360spider|haosouspider", re.I)),
    ("Shenma/Yisou", "search", re.compile(r"yisouspider|shenmaspider", re.I)),
    ("DuckDuckGo", "search", re.compile(r"duckduckbot", re.I)),
    ("Applebot", "search", re.compile(r"applebot", re.I)),
    ("PetalBot", "search", re.compile(r"petalbot", re.I)),
    ("Bytespider", "ai_training", re.compile(r"bytespider", re.I)),
    ("ByteDance crawler", "ai_search", re.compile(r"toutiaospider|doubaobot", re.I)),
    (
        "Doubao user",
        "ai_user",
        re.compile(r"samanthadoubao|appname/doubao|(?:^|[;\s])doubao(?:[;/\s]|$)", re.I),
    ),
    ("Anthropic user", "ai_user", re.compile(r"claude-user", re.I)),
    ("Anthropic", "ai_search", re.compile(r"claude(?:bot|-searchbot)", re.I)),
    ("Perplexity user", "ai_user", re.compile(r"perplexity-user", re.I)),
    ("Perplexity", "ai_search", re.compile(r"perplexitybot", re.I)),
    ("Meta external", "ai_training", re.compile(r"meta-externalagent|facebookexternalhit", re.I)),
    ("Amazonbot", "search", re.compile(r"amazonbot", re.I)),
]

UNWANTED_BOT_RE = re.compile(
    r"ahrefs|semrush|mj12bot|dotbot|dataforseo|serpstat|blexbot|"
    r"megaindex|seekport|barkrowler|bbytespider|turnitinbot|"
    r"zgrab|masscan|nmap|nuclei|sqlmap|nikto|acunetix|censys|"
    r"claudebot-fake|python-requests|go-http-client|curl/|wget/|"
    r"api-config-collector|tlm-audit-scanner|expanse|internetmeasurement",
    re.I,
)

PROBE_RE = re.compile(
    r"(?:^|/)(?:\.env|\.git|\.svn|wp-config(?:\.php)?|phpmyadmin|"
    r"server-status|actuator|vendor/phpunit|cgi-bin|HNAP1|"
    r"boaform|manager/html|solr/admin|console|autodiscover\.xml|"
    r"_ignition|_cluster|remote/login|livewire/(?:update|livewire)|"
    r"api/v\d|rest/login|@vite|SDK/webLanguage|this_is_a_new_hello_world\.php)"
    r"|(?:\.\./|%2e%2e|/etc/passwd|/proc/self|union\s+select|"
    r"<script|%3cscript|jndi:|/\.well-known/acme-challenge/\.\.)",
    re.I,
)

MALFORMED_RE = re.compile(r"\\x[0-9a-f]{2}|^\s*$", re.I)
CONTENT_RE = re.compile(r"^/(?:archives/\d+|category/|tag/|page/\d+|$)", re.I)
ARCHIVE_RE = re.compile(r"^/archives/\d+/?(?:\?.*)?$", re.I)
HUMAN_EVENT_RE = re.compile(r"^/wp-json/wp-statistics/v2/hit(?:\?|$)", re.I)
ADMIN_RE = re.compile(r"^/wp-admin/(?!admin-ajax\.php)", re.I)
AUTH_RE = re.compile(r"^/(?:api/user/login|wp-login\.php|xmlrpc\.php)(?:\?|$)", re.I)
PHP_RE = re.compile(r"^/[^?\s]+\.php(?:\?|$)", re.I)
KNOWN_PHP_RE = re.compile(
    r"^/(?:index|wp-cron|wp-login|xmlrpc)\.php(?:\?|$)|"
    r"^/wp-(?:admin|content|includes)/.+\.php(?:\?|$)",
    re.I,
)

GOOD_REFERRER_DOMAINS = (
    # Search engines.
    "bing.com", "baidu.com", "sogou.com", "so.com", "sm.cn",
    "duckduckgo.com", "yandex.ru", "yandex.com", "yandex.net",
    # AI assistants and AI search products. This protects the referred human,
    # not a bot merely claiming one of these names in its User-Agent.
    "chatgpt.com", "openai.com", "perplexity.ai", "claude.ai",
    "copilot.microsoft.com", "gemini.google.com", "poe.com",
    "doubao.com", "toutiao.com", "yuanbao.tencent.com",
    "kimi.com", "moonshot.cn", "deepseek.com", "qianwen.com",
    "tongyi.com", "chatglm.cn", "zhipuai.cn", "metaso.cn", "quark.cn",
)
GOOGLE_REFERRER_RE = re.compile(r"(?:^|\.)google\.[a-z.]{2,}$", re.I)

PTR_SUFFIXES = {
    "Bing": (".search.msn.com",),
    "Baidu": (".baidu.com", ".baidu.jp"),
    "Yandex": (".yandex.ru", ".yandex.net", ".yandex.com"),
}

# 站点主要面向中文用户；Yandex 抓取频率过高，属于明确业务封禁对象。
POLICY_BLOCKED_TRUSTED_BOTS = {"Yandex"}

LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>.*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>.*)"\s+"(?P<ua>.*)"\s*$'
)

BLACKLIST_RE = re.compile(r"^\s*([0-9a-fA-F:.]+(?:/\d{1,3})?)\s+1\s*;\s*(?:#.*)?$")


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def open_text(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def iter_log_files(log_dir: Path) -> list[Path]:
    files = [
        p for p in log_dir.iterdir()
        if p.is_file() and (p.name.startswith("access.log") or p.name.endswith(".access.log"))
    ]
    return sorted(files, key=lambda p: (p.stat().st_mtime, p.name))


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")


def referrer_host(value: str) -> str:
    if not value or value == "-":
        return ""
    try:
        return (urlsplit(value).hostname or "").lower()
    except ValueError:
        return ""


def is_good_referrer(host: str) -> bool:
    if not host:
        return False
    if GOOGLE_REFERRER_RE.search(host):
        return True
    return any(host == domain or host.endswith("." + domain) for domain in GOOD_REFERRER_DOMAINS)


def identify_bot(ua: str) -> tuple[str, str] | None:
    for name, kind, pattern in BOT_PATTERNS:
        if pattern.search(ua):
            return name, kind
    return None


@dataclass
class IPStats:
    ip: str
    requests: int = 0
    bytes_sent: int = 0
    status: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    days: set[str] = field(default_factory=set)
    hours: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    archive_paths: set[str] = field(default_factory=set)
    uas: Counter = field(default_factory=Counter)
    bot_claims: Counter = field(default_factory=Counter)
    bot_kinds: Counter = field(default_factory=Counter)
    good_referrers: Counter = field(default_factory=Counter)
    direct: int = 0
    probes: int = 0
    malformed: int = 0
    unwanted_bot: int = 0
    human_events: int = 0
    admin_events: int = 0
    auth_attempts: int = 0
    php_paths: set[str] = field(default_factory=set)
    robots: int = 0
    samples: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    max_day_requests: int = 0
    _per_day: Counter = field(default_factory=Counter)

    def add(
        self, dt: datetime, method: str, target: str, status: int, size: int,
        referrer: str, ua: str, malformed: bool
    ) -> None:
        self.requests += 1
        self.bytes_sent += size
        self.status[status] += 1
        self.methods[method] += 1
        day = dt.date().isoformat()
        self.days.add(day)
        self.hours.add(dt.strftime("%Y-%m-%d %H"))
        self._per_day[day] += 1
        self.max_day_requests = max(self.max_day_requests, self._per_day[day])
        self.first_seen = min(self.first_seen, dt) if self.first_seen else dt
        self.last_seen = max(self.last_seen, dt) if self.last_seen else dt
        if len(self.paths) < 5000:
            self.paths.add(target)
        if ARCHIVE_RE.match(target) and len(self.archive_paths) < 5000:
            self.archive_paths.add(target)
        self.uas[ua[:300]] += 1
        bot = identify_bot(ua)
        if bot:
            self.bot_claims[bot[0]] += 1
            self.bot_kinds[bot[1]] += 1
        host = referrer_host(referrer)
        if is_good_referrer(host):
            self.good_referrers[host] += 1
        if not host:
            self.direct += 1
        if PROBE_RE.search(target):
            self.probes += 1
            if len(self.samples) < 8:
                self.samples.append(target[:180])
        if malformed:
            self.malformed += 1
            if len(self.samples) < 8:
                self.samples.append(f"[畸形请求] {target[:160]}")
        if UNWANTED_BOT_RE.search(ua):
            self.unwanted_bot += 1
        if HUMAN_EVENT_RE.match(target):
            self.human_events += 1
        if ADMIN_RE.match(target) and status in (200, 302):
            self.admin_events += 1
        if AUTH_RE.match(target):
            self.auth_attempts += 1
        if PHP_RE.match(target) and not KNOWN_PHP_RE.match(target) and len(self.php_paths) < 1000:
            self.php_paths.add(target.split("?", 1)[0])
        if target.split("?", 1)[0] == "/robots.txt":
            self.robots += 1


@dataclass
class GeoRecord:
    country: str = ""
    asn: int | None = None
    as_name: str = ""


class RangeTable:
    """Memory-efficient IPv4 range lookup loaded from DB-IP CSV.gz."""

    def __init__(self) -> None:
        self.starts: list[int] = []
        self.ends: list[int] = []
        self.values: list[tuple] = []

    def load(self, path: Path, value_columns: tuple[int, ...]) -> None:
        starts, ends, values = [], [], []
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                try:
                    if ":" in row[0]:
                        continue
                    starts.append(int(ipaddress.IPv4Address(row[0])))
                    ends.append(int(ipaddress.IPv4Address(row[1])))
                    values.append(tuple(row[i] for i in value_columns))
                except (ValueError, IndexError):
                    continue
        order = sorted(range(len(starts)), key=starts.__getitem__)
        self.starts = [starts[i] for i in order]
        self.ends = [ends[i] for i in order]
        self.values = [values[i] for i in order]

    def get(self, ip: str) -> tuple | None:
        try:
            value = int(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError:
            return None
        idx = bisect.bisect_right(self.starts, value) - 1
        if idx >= 0 and value <= self.ends[idx]:
            return self.values[idx]
        return None


class Intelligence:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.official: dict[str, list[ipaddress._BaseNetwork]] = {}
        self.country = RangeTable()
        self.asn = RangeTable()
        self.geo_cache: dict[str, GeoRecord] = {}
        self.ptr_cache: dict[str, dict] = {}
        self.sources: dict[str, dict] = {}

    @staticmethod
    def _get(url: str, *, binary: bool = False, retries: int = 4):
        last_error = None
        for attempt in range(retries):
            try:
                response = requests.get(
                    url, timeout=(15, 90), headers={"User-Agent": UA}
                )
                response.raise_for_status()
                return response.content if binary else response.json()
            except Exception as exc:  # network errors vary by platform
                last_error = exc
                if attempt + 1 < retries:
                    time.sleep(1.5 * (attempt + 1))
        raise RuntimeError(f"下载失败 {url}: {last_error}")

    def refresh_official_ranges(self, online: bool) -> None:
        cache_path = self.data_dir / "official_crawler_ranges.json"
        payload: dict[str, dict] = {}
        if cache_path.exists():
            try:
                payload = json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
        changed = False
        for name, url in OFFICIAL_RANGE_URLS.items():
            item = payload.get(name)
            stale = not item or time.time() - item.get("fetched_at", 0) > 86400
            if online and stale:
                try:
                    doc = self._get(url)
                    prefixes = []
                    for row in doc.get("prefixes", []):
                        prefix = row.get("ipv4Prefix") or row.get("ipv6Prefix")
                        if prefix:
                            prefixes.append(prefix)
                    item = {
                        "url": url,
                        "fetched_at": time.time(),
                        "creation_time": doc.get("creationTime", ""),
                        "prefixes": prefixes,
                    }
                    payload[name] = item
                    changed = True
                except RuntimeError as exc:
                    eprint(f"警告: {exc}")
            if item:
                networks = []
                for prefix in item.get("prefixes", []):
                    try:
                        networks.append(ipaddress.ip_network(prefix, strict=False))
                    except ValueError:
                        pass
                self.official[name] = networks
                self.sources[name] = {
                    "url": item.get("url", url),
                    "fetched_at": item.get("fetched_at", 0),
                    "creation_time": item.get("creation_time", ""),
                    "records": len(networks),
                }
        if changed:
            cache_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def refresh_dbip(self, online: bool) -> None:
        now = datetime.now(timezone.utc)
        candidates = []
        year, month = now.year, now.month
        for _ in range(3):
            candidates.append(f"{year:04d}-{month:02d}")
            month -= 1
            if month == 0:
                month, year = 12, year - 1
        paths = {}
        for kind in ("country", "asn"):
            existing = sorted(self.data_dir.glob(f"dbip-{kind}-lite-*.csv.gz"), reverse=True)
            chosen = existing[0] if existing else None
            if online and (not chosen or candidates[0] not in chosen.name):
                for stamp in candidates:
                    url = f"https://download.db-ip.com/free/dbip-{kind}-lite-{stamp}.csv.gz"
                    target = self.data_dir / f"dbip-{kind}-lite-{stamp}.csv.gz"
                    try:
                        content = self._get(url, binary=True)
                        target.write_bytes(content)
                        chosen = target
                        break
                    except RuntimeError:
                        continue
            if chosen:
                paths[kind] = chosen
                self.sources[f"DB-IP {kind}"] = {
                    "url": "https://db-ip.com/db/lite.php",
                    "fetched_at": chosen.stat().st_mtime,
                    "creation_time": chosen.stem.replace(".csv", ""),
                    "records": 0,
                }
        if "country" in paths:
            self.country.load(paths["country"], (2,))
            self.sources["DB-IP country"]["records"] = len(self.country.starts)
        if "asn" in paths:
            self.asn.load(paths["asn"], (2, 3))
            self.sources["DB-IP asn"]["records"] = len(self.asn.starts)

    def lookup(self, ip: str) -> GeoRecord:
        cached = self.geo_cache.get(ip)
        if cached:
            return cached
        result = GeoRecord()
        country = self.country.get(ip)
        asn = self.asn.get(ip)
        if country:
            result.country = country[0]
        if asn:
            try:
                result.asn = int(asn[0])
            except ValueError:
                pass
            result.as_name = asn[1]
        self.geo_cache[ip] = result
        return result

    def official_matches(self, ip: str) -> list[str]:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return []
        return [
            name for name, networks in self.official.items()
            if any(address.version == net.version and address in net for net in networks)
        ]

    def load_ptr_cache(self) -> None:
        path = self.data_dir / "ptr_cache.json"
        if path.exists():
            try:
                self.ptr_cache = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.ptr_cache = {}

    def save_ptr_cache(self) -> None:
        path = self.data_dir / "ptr_cache.json"
        path.write_text(json.dumps(self.ptr_cache, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _verify_ptr(ip: str, suffixes: tuple[str, ...]) -> dict:
        result = {"verified": False, "host": "", "checked_at": time.time(), "error": ""}
        try:
            host = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
            result["host"] = host
            if not any(host.endswith(suffix) for suffix in suffixes):
                result["error"] = "PTR 域名后缀不匹配"
                return result
            addresses = {
                item[4][0] for item in socket.getaddrinfo(host, None)
                if item and item[4]
            }
            result["verified"] = ip in addresses
            if not result["verified"]:
                result["error"] = "正向 DNS 未返回原 IP"
        except Exception as exc:
            result["error"] = str(exc)[:180]
        return result

    def verify_ptr_claims(self, jobs: dict[str, tuple[str, ...]], online: bool) -> None:
        self.load_ptr_cache()
        now = time.time()
        pending = {}
        for ip, suffixes in jobs.items():
            cached = self.ptr_cache.get(ip)
            if cached and now - cached.get("checked_at", 0) < 7 * 86400:
                continue
            if online:
                pending[ip] = suffixes
        if pending:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(5)
            try:
                with ThreadPoolExecutor(max_workers=24) as pool:
                    futures = {
                        pool.submit(self._verify_ptr, ip, suffixes): ip
                        for ip, suffixes in pending.items()
                    }
                    for future in as_completed(futures):
                        self.ptr_cache[futures[future]] = future.result()
            finally:
                socket.setdefaulttimeout(old_timeout)
            self.save_ptr_cache()


@dataclass
class Verdict:
    score: int
    level: str
    protected: bool
    trusted_bot: str
    reasons: list[str]
    geo: GeoRecord
    blacklisted: bool = False


def bot_verification(stats: IPStats, intel: Intelligence) -> tuple[str, str]:
    """Return (trusted identity, verification note)."""
    matches = intel.official_matches(stats.ip)
    claims = set(stats.bot_claims)
    if "Google" in claims:
        hit = next((m for m in matches if m.startswith("Google ")), "")
        if hit:
            return f"Google（{hit.replace('Google ', '')}）", "官方 IP 网段"
    openai_map = {
        "OpenAI SearchBot": "OpenAI SearchBot",
        "OpenAI ChatGPT-User": "OpenAI ChatGPT-User",
        "OpenAI GPTBot": "OpenAI GPTBot",
    }
    for claim, source in openai_map.items():
        if claim in claims and source in matches:
            return claim, "官方 IP 网段"
    for claim, suffixes in PTR_SUFFIXES.items():
        if claim in claims:
            cached = intel.ptr_cache.get(stats.ip, {})
            if cached.get("verified"):
                return claim, f"FCrDNS: {cached.get('host', '')}"
    return "", ""


def score_ip(
    stats: IPStats, intel: Intelligence, total_days: int,
    blacklist_networks: list[ipaddress._BaseNetwork],
    allow_networks: list[ipaddress._BaseNetwork] | None = None,
) -> Verdict:
    geo = intel.lookup(stats.ip)
    trusted, _ = bot_verification(stats, intel)
    claimed = bool(stats.bot_claims)
    ai_or_search_ref = bool(stats.good_referrers)
    allow_networks = allow_networks or []
    try:
        address = ipaddress.ip_address(stats.ip)
        explicit_allow = any(
            address.version == network.version and address in network
            for network in allow_networks
        )
    except ValueError:
        address = None
        explicit_allow = False
    score = 0
    reasons = []
    if explicit_allow:
        reasons.append("命中站点显式白名单")
    if trusted:
        reasons.append(f"已验证可信：{trusted}")
    elif claimed:
        reasons.append("自称搜索/AI 爬虫，身份未由官方网段或 FCrDNS 证实")
    if ai_or_search_ref:
        names = ", ".join(host for host, _ in stats.good_referrers.most_common(2))
        reasons.append(f"存在搜索/AI 引荐：{names}")
    if stats.human_events:
        reasons.append(f"执行站内统计请求 {stats.human_events} 次（真人/JS 信号）")
    if stats.probes:
        points = min(9, 5 + stats.probes // 2)
        score += points
        reasons.append(f"命中敏感路径/漏洞探测 {stats.probes} 次")
    if stats.malformed:
        points = min(8, 5 + stats.malformed // 2)
        score += points
        reasons.append(f"非 HTTP/畸形请求 {stats.malformed} 次")
    if stats.unwanted_bot:
        score += min(6, 3 + stats.unwanted_bot // 10)
        reasons.append(f"命中扫描器/商业采集 UA {stats.unwanted_bot} 次")
    if stats.auth_attempts >= 10:
        score += min(9, 5 + stats.auth_attempts // 100)
        reasons.append(f"登录/XML-RPC 接口高频尝试 {stats.auth_attempts} 次")
    if len(stats.php_paths) >= 8:
        score += min(9, 5 + len(stats.php_paths) // 20)
        reasons.append(f"枚举 {len(stats.php_paths)} 个非常规 PHP/木马路径")
    unique_content = sum(1 for path in stats.paths if CONTENT_RE.match(path))
    direct_ratio = stats.direct / max(1, stats.requests)
    if stats.max_day_requests >= 80 and unique_content >= 45:
        score += 5
        reasons.append(f"单日最高 {stats.max_day_requests} 次、批量遍历 {unique_content} 个内容页")
    elif stats.max_day_requests >= 35 and unique_content >= 25:
        score += 3
        reasons.append(f"单日最高 {stats.max_day_requests} 次、遍历 {unique_content} 个内容页")
    repeat_cutoff = max(4, math.ceil(total_days * 0.45))
    if len(stats.days) >= repeat_cutoff and len(stats.archive_paths) >= 20:
        score += 3
        reasons.append(f"{len(stats.days)}/{total_days} 天持续抓取文章")
    if stats.requests >= 30 and direct_ratio >= 0.97 and not stats.good_referrers:
        score += 1
        reasons.append("高频访问几乎全部无外部来源")
    if stats.robots and len(stats.archive_paths) >= 30:
        score += 1
        reasons.append("读取 robots.txt 后继续批量抓取")
    if geo.as_name and re.search(r"cloud|hosting|server|data ?center|vps", geo.as_name, re.I):
        score += 1
        reasons.append("ASN 名称显示为云/托管网络（仅弱证据）")
    hard_bad = bool(
        stats.probes or stats.malformed or stats.auth_attempts >= 10
        or len(stats.php_paths) >= 8
    )
    soft_claim = claimed and not hard_bad
    human_signal = (
        (stats.human_events >= 1 or stats.admin_events >= 2 or ai_or_search_ref)
        and not hard_bad and stats.unwanted_bot == 0
    )
    protected = bool(explicit_allow or trusted or soft_claim or human_signal)
    if protected:
        score = min(score, 3)
    if protected:
        level = "保护"
    elif score >= 7:
        level = "建议封禁"
    elif score >= 4:
        level = "观察"
    else:
        level = "低风险"
    try:
        address = ipaddress.ip_address(stats.ip)
        blacklisted = any(address.version == n.version and address in n for n in blacklist_networks)
    except ValueError:
        blacklisted = False
    return Verdict(score, level, protected, trusted, reasons, geo, blacklisted)


def parse_logs(paths: Iterable[Path]) -> tuple[dict[str, IPStats], dict, list[str]]:
    stats: dict[str, IPStats] = {}
    daily = defaultdict(lambda: Counter(requests=0, ips=0, blocked=0, probes=0))
    daily_ips = defaultdict(set)
    errors = []
    parsed = 0
    skipped = 0
    first = last = None
    for path in paths:
        with open_text(path) as fh:
            for line_no, line in enumerate(fh, 1):
                match = LOG_RE.match(line.rstrip("\r\n"))
                if not match:
                    skipped += 1
                    if len(errors) < 20:
                        errors.append(f"{path.name}:{line_no}: {line[:180].rstrip()}")
                    continue
                try:
                    ip_obj = ipaddress.ip_address(match.group("ip"))
                    ip = str(ip_obj)
                    dt = parse_time(match.group("time"))
                    status = int(match.group("status"))
                    size_text = match.group("size")
                    size = int(size_text) if size_text.isdigit() else 0
                except (ValueError, OverflowError):
                    skipped += 1
                    continue
                request = match.group("request")
                parts = request.split()
                malformed = bool(MALFORMED_RE.search(request)) or len(parts) < 2
                method = parts[0] if parts else "MALFORMED"
                target = parts[1] if len(parts) >= 2 else request
                item = stats.setdefault(ip, IPStats(ip))
                item.add(
                    dt, method, target, status, size,
                    match.group("referrer"), match.group("ua"), malformed
                )
                day = dt.date().isoformat()
                daily[day]["requests"] += 1
                daily_ips[day].add(ip)
                if status == 444:
                    daily[day]["blocked"] += 1
                if PROBE_RE.search(target) or malformed:
                    daily[day]["probes"] += 1
                parsed += 1
                first = min(first, dt) if first else dt
                last = max(last, dt) if last else dt
    for day, ips in daily_ips.items():
        daily[day]["ips"] = len(ips)
    for item in stats.values():
        if item.first_seen:
            daily[item.first_seen.date().isoformat()]["new_ips"] += 1
    for day in daily:
        daily[day]["returning_ips"] = daily[day]["ips"] - daily[day]["new_ips"]
    meta = {
        "parsed": parsed,
        "skipped": skipped,
        "first": first,
        "last": last,
        "daily": dict(sorted(daily.items())),
    }
    return stats, meta, errors


def parse_blacklist(path: Path) -> tuple[list[tuple[str, ipaddress._BaseNetwork]], list[str]]:
    rules, invalid = [], []
    if not path.exists():
        return rules, invalid
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = BLACKLIST_RE.match(line)
        if not match:
            invalid.append(f"第 {line_no} 行: {stripped}")
            continue
        try:
            net = ipaddress.ip_network(match.group(1), strict=False)
            rules.append((match.group(1), net))
        except ValueError:
            invalid.append(f"第 {line_no} 行: {stripped}")
    return rules, invalid


def parse_allowlist(path: Path) -> tuple[list[ipaddress._BaseNetwork], list[str]]:
    networks, invalid = [], []
    if not path.exists():
        return networks, invalid
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            invalid.append(f"第 {line_no} 行: {value}")
    return networks, invalid


def ptr_jobs(stats: dict[str, IPStats]) -> dict[str, tuple[str, ...]]:
    jobs = {}
    for ip, item in stats.items():
        for claim, suffixes in PTR_SUFFIXES.items():
            if claim in item.bot_claims:
                jobs[ip] = suffixes
                break
    return jobs


def aggregate_networks(
    stats: dict[str, IPStats], verdicts: dict[str, Verdict],
    blacklist_networks: list[ipaddress._BaseNetwork] | None = None,
) -> list[dict]:
    blacklist_networks = blacklist_networks or []
    groups = defaultdict(list)
    for ip, item in stats.items():
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        prefix = 24 if address.version == 4 else 64
        groups[str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))].append(item)
    result = []
    for network, items in groups.items():
        requests = sum(x.requests for x in items)
        bad = [x for x in items if verdicts[x.ip].level == "建议封禁"]
        observe = [x for x in items if verdicts[x.ip].level == "观察"]
        protected = [x for x in items if verdicts[x.ip].protected]
        direct = sum(x.direct for x in items)
        archive = sum(len(x.archive_paths) for x in items)
        probes = sum(x.probes + x.malformed for x in items)
        bad_ratio = len(bad) / max(1, len(items))
        rotating_pattern = (
            len(items) >= 4 and requests >= 20 and archive >= 15
            and direct / max(1, requests) >= 0.95
            and not protected
        )
        network_obj = ipaddress.ip_network(network)
        already_blacklisted = any(
            network_obj.version == existing.version and network_obj.subnet_of(existing)
            for existing in blacklist_networks
        )
        auto = (
            not protected and not already_blacklisted and (
                (len(bad) >= 3 and bad_ratio >= 0.70 and requests >= 40)
                or (probes >= 8 and len(items) >= 3)
            )
        )
        sample_geo = verdicts[items[0].ip].geo
        reasons = []
        if len(bad) >= 3:
            reasons.append(f"{len(bad)}/{len(items)} 个活跃 IP 达到高风险")
        if probes:
            reasons.append(f"探测/畸形请求 {probes} 次")
        if rotating_pattern:
            reasons.append("多 IP 轮换、无来源地遍历文章")
        if protected:
            reasons.append(f"含 {len(protected)} 个保护 IP，禁止整段封禁")
        if already_blacklisted:
            reasons.append("已被现有黑名单完整覆盖，不重复输出")
        result.append({
            "network": network,
            "ips": len(items),
            "requests": requests,
            "bad_ips": len(bad),
            "observe_ips": len(observe),
            "protected_ips": len(protected),
            "probes": probes,
            "auto": auto,
            "already_blacklisted": already_blacklisted,
            "reasons": reasons,
            "country": sample_geo.country,
            "asn": sample_geo.asn,
            "as_name": sample_geo.as_name,
        })
    return sorted(result, key=lambda x: (x["auto"], x["bad_ips"], x["requests"]), reverse=True)


def aggregate_asns(stats: dict[str, IPStats], verdicts: dict[str, Verdict]) -> list[dict]:
    groups = defaultdict(list)
    for ip, item in stats.items():
        geo = verdicts[ip].geo
        key = (geo.asn, geo.as_name, geo.country)
        groups[key].append(item)
    result = []
    for (asn, name, country), items in groups.items():
        requests = sum(x.requests for x in items)
        bad = sum(verdicts[x.ip].level == "建议封禁" for x in items)
        protected = sum(verdicts[x.ip].protected for x in items)
        result.append({
            "asn": asn or "",
            "name": name or "未知",
            "country": country or "",
            "ips": len(items),
            "requests": requests,
            "bad_ips": bad,
            "protected_ips": protected,
            "bad_ratio": bad / max(1, len(items)),
        })
    return sorted(result, key=lambda x: (x["bad_ips"], x["requests"]), reverse=True)


def aggregate_countries(stats: dict[str, IPStats], verdicts: dict[str, Verdict]) -> list[dict]:
    groups = defaultdict(list)
    for ip, item in stats.items():
        groups[verdicts[ip].geo.country or "未知"].append(item)
    result = []
    for country, items in groups.items():
        requests = sum(x.requests for x in items)
        bad = sum(verdicts[x.ip].level == "建议封禁" for x in items)
        protected = sum(verdicts[x.ip].protected for x in items)
        blocked_requests = sum(x.status[444] for x in items)
        result.append({
            "country": country,
            "ips": len(items),
            "requests": requests,
            "bad_ips": bad,
            "protected_ips": protected,
            "blocked_requests": blocked_requests,
        })
    return sorted(result, key=lambda x: x["requests"], reverse=True)


def aggregate_user_agents(stats: dict[str, IPStats], verdicts: dict[str, Verdict]) -> list[dict]:
    groups = {}
    for ip, item in stats.items():
        if not item.uas:
            continue
        ua, ua_requests = item.uas.most_common(1)[0]
        group = groups.setdefault(ua, {
            "ua": ua, "ips": 0, "requests": 0, "days": set(), "bad_ips": 0,
            "protected_ips": 0, "direct_estimate": 0.0, "archive_ips": 0,
            "countries": Counter(),
        })
        group["ips"] += 1
        group["requests"] += ua_requests
        group["days"].update(item.days)
        group["bad_ips"] += verdicts[ip].level == "建议封禁"
        group["protected_ips"] += verdicts[ip].protected
        group["direct_estimate"] += ua_requests * item.direct / max(1, item.requests)
        group["archive_ips"] += bool(item.archive_paths)
        group["countries"][verdicts[ip].geo.country or "未知"] += 1
    result = []
    for group in groups.values():
        direct_ratio = group["direct_estimate"] / max(1, group["requests"])
        rotating = (
            group["ips"] >= 20
            and group["archive_ips"] >= math.ceil(group["ips"] * 0.5)
            and direct_ratio >= 0.90
            and group["protected_ips"] == 0
        )
        result.append({
            **group,
            "days_count": len(group["days"]),
            "direct_ratio": direct_ratio,
            "rotating": rotating,
            "top_countries": ", ".join(
                f"{country}:{count}" for country, count in group["countries"].most_common(4)
            ),
        })
    return sorted(
        result,
        key=lambda x: (x["rotating"], x["ips"], x["requests"]),
        reverse=True,
    )


def audit_blacklist(
    rules: list[tuple[str, ipaddress._BaseNetwork]],
    stats: dict[str, IPStats],
    verdicts: dict[str, Verdict],
    intel: Intelligence,
) -> list[dict]:
    result = []
    for raw, net in rules:
        active = []
        for ip in stats:
            try:
                address = ipaddress.ip_address(ip)
                if address.version == net.version and address in net:
                    active.append(ip)
            except ValueError:
                pass
        protected = [ip for ip in active if verdicts[ip].protected]
        trusted = [ip for ip in active if verdicts[ip].trusted_bot]
        intentional_trusted = [
            ip for ip in trusted
            if verdicts[ip].trusted_bot in POLICY_BLOCKED_TRUSTED_BOTS
        ]
        allowed_trusted = [ip for ip in trusted if ip not in intentional_trusted]
        official_overlaps = []
        for source, networks in intel.official.items():
            if any(net.version == other.version and net.overlaps(other) for other in networks):
                official_overlaps.append(source)
        bad = [ip for ip in active if verdicts[ip].level == "建议封禁"]
        if allowed_trusted:
            action = "建议解封"
            reason = f"实际拦截了 {len(allowed_trusted)} 个应保留的已验证搜索/AI IP"
        elif intentional_trusted:
            action = "业务保留"
            reason = f"覆盖 {len(intentional_trusted)} 个已验证 Yandex IP，但本站明确不需要俄语区抓取"
        elif protected:
            action = "复核解封"
            reason = f"覆盖 {len(protected)} 个具有人类/AI 引荐信号的活跃 IP"
        elif official_overlaps:
            action = "复核解封"
            reason = "与官方爬虫网段重叠：" + "、".join(official_overlaps)
        elif active and len(bad) == 0 and net.prefixlen <= (16 if net.version == 4 else 48):
            action = "复核"
            reason = "大网段有活跃 IP，但样本内未发现高风险证据"
        elif active:
            action = "保留"
            reason = f"活跃 {len(active)} IP，其中高风险 {len(bad)}"
        else:
            action = "无近期样本"
            reason = "日志窗口内未再出现，不能据此判断安全或恶意"
        result.append({
            "rule": raw,
            "prefix": net.prefixlen,
            "active": len(active),
            "bad": len(bad),
            "protected": len(protected),
            "trusted": len(trusted),
            "intentional_trusted": len(intentional_trusted),
            "official": official_overlaps,
            "action": action,
            "reason": reason,
            "examples": protected[:5] or active[:5],
        })
    priority = {
        "建议解封": 6, "复核解封": 5, "复核": 4,
        "业务保留": 3, "保留": 2, "无近期样本": 1,
    }
    return sorted(result, key=lambda x: (priority[x["action"]], x["protected"], x["active"]), reverse=True)


def audit_redundancy(rules: list[tuple[str, ipaddress._BaseNetwork]]) -> list[dict]:
    result = []
    for idx, (raw, net) in enumerate(rules):
        parents = [
            other_raw for j, (other_raw, other) in enumerate(rules)
            if j != idx and net.version == other.version and net.subnet_of(other) and net != other
        ]
        duplicates = sum(net == other for j, (_, other) in enumerate(rules) if j != idx)
        if parents or duplicates:
            result.append({
                "rule": raw,
                "parents": parents[:5],
                "duplicates": duplicates,
            })
    return result


def fmt_int(value: int | float) -> str:
    return f"{int(value):,}"


def fmt_pct(num: int | float, den: int | float) -> str:
    return f"{(num / den * 100 if den else 0):.1f}%"


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def table(headers: list[str], rows: list[list[object]], classes: str = "") -> str:
    if not rows:
        return '<p class="muted">无数据</p>'
    head = "".join(f"<th>{esc(x)}</th>" for x in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f'<div class="table-wrap"><table class="{classes}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def badge(text: str, kind: str) -> str:
    return f'<span class="badge {esc(kind)}">{esc(text)}</span>'


def generate_report(
    output: Path, stats: dict[str, IPStats], verdicts: dict[str, Verdict],
    networks: list[dict], asns: list[dict], countries: list[dict],
    campaigns: list[dict], blacklist_audit: list[dict],
    redundancy: list[dict], invalid_rules: list[str], meta: dict,
    parse_errors: list[str], intel: Intelligence, files: list[Path],
) -> None:
    total_requests = meta["parsed"]
    total_ips = len(stats)
    total_days = len(meta["daily"])
    blocked = sum(x.status[444] for x in stats.values())
    high = [ip for ip, v in verdicts.items() if v.level == "建议封禁"]
    observe = [ip for ip, v in verdicts.items() if v.level == "观察"]
    protected = [ip for ip, v in verdicts.items() if v.protected]
    bot_requests = sum(sum(x.bot_claims.values()) for x in stats.values())
    verified_bot_requests = sum(
        stats[ip].requests for ip, v in verdicts.items() if v.trusted_bot
    )
    auto_networks = [n for n in networks if n["auto"]]
    definite_unblock = sum(x["action"] == "建议解封" for x in blacklist_audit)
    unblock_advice = (
        f"先人工确认并移除报告中 {definite_unblock} 条“建议解封”规则；其余“复核解封”不要批量操作。"
        if definite_unblock
        else "当前没有必须解封的规则；Yandex 网段按中文站业务策略继续保留。"
    )
    audit_networks = []
    for item in blacklist_audit:
        try:
            audit_networks.append(ipaddress.ip_network(item["rule"], strict=False))
        except ValueError:
            pass
    collapsed_v4 = list(ipaddress.collapse_addresses(n for n in audit_networks if n.version == 4))
    blacklist_v4_coverage = sum(n.num_addresses for n in collapsed_v4)

    daily_rows = []
    max_daily = max((x["requests"] for x in meta["daily"].values()), default=1)
    for day, item in meta["daily"].items():
        width = max(2, int(item["requests"] / max_daily * 100))
        daily_rows.append([
            esc(day),
            f'<div class="bar" style="width:{width}%"></div><span>{fmt_int(item["requests"])}</span>',
            fmt_int(item["ips"]),
            fmt_int(item["new_ips"]),
            fmt_int(item["returning_ips"]),
            f'{fmt_int(item["blocked"])} ({fmt_pct(item["blocked"], item["requests"])})',
            fmt_int(item["probes"]),
        ])

    top_ips = sorted(stats, key=lambda ip: stats[ip].requests, reverse=True)[:100]
    ip_rows = []
    for ip in top_ips:
        s, v = stats[ip], verdicts[ip]
        reasons = "；".join(v.reasons[:4]) or "未发现强风险信号"
        label_kind = {"建议封禁": "danger", "观察": "warn", "保护": "good", "低风险": "muted"}[v.level]
        ua = s.uas.most_common(1)[0][0] if s.uas else ""
        ip_rows.append([
            f"<code>{esc(ip)}</code>",
            fmt_int(s.requests),
            len(s.days),
            len(s.archive_paths),
            f"{esc(v.geo.country)} / AS{esc(v.geo.asn or '')}<br><small>{esc(v.geo.as_name[:48])}</small>",
            badge(v.level, label_kind) + (" " + badge("已在黑名单", "dark") if v.blacklisted else ""),
            f'<span title="{esc(ua)}">{esc(reasons)}</span>',
        ])

    high_rows = []
    for ip in sorted(high, key=lambda x: (verdicts[x].score, stats[x].requests), reverse=True)[:250]:
        s, v = stats[ip], verdicts[ip]
        high_rows.append([
            f"<code>{esc(ip)}</code>",
            v.score,
            fmt_int(s.requests),
            len(s.days),
            len(s.archive_paths),
            f"{esc(v.geo.country)} / AS{esc(v.geo.asn or '')}<br><small>{esc(v.geo.as_name[:55])}</small>",
            esc("；".join(v.reasons)),
            "<br>".join(f"<code>{esc(x)}</code>" for x in s.samples[:3]),
        ])

    network_rows = []
    for n in networks[:150]:
        if not (n["auto"] or n["bad_ips"] or n["observe_ips"] >= 2):
            continue
        state = badge("可生成规则", "danger") if n["auto"] else badge("仅观察", "warn")
        if n["already_blacklisted"]:
            state = badge("已在黑名单", "dark")
        if n["protected_ips"]:
            state = badge("禁止整段封禁", "good")
        network_rows.append([
            f"<code>{esc(n['network'])}</code>",
            fmt_int(n["requests"]),
            n["ips"],
            n["bad_ips"],
            n["protected_ips"],
            f"{esc(n['country'])} / AS{esc(n['asn'] or '')}<br><small>{esc(n['as_name'][:52])}</small>",
            state,
            esc("；".join(n["reasons"])),
        ])

    asn_rows = []
    for a in asns[:100]:
        asn_rows.append([
            f"AS{esc(a['asn'])}" if a["asn"] else "未知",
            esc(a["name"][:75]),
            esc(a["country"]),
            fmt_int(a["ips"]),
            fmt_int(a["requests"]),
            f"{a['bad_ips']} ({fmt_pct(a['bad_ips'], a['ips'])})",
            a["protected_ips"],
        ])

    country_rows = []
    for item in countries:
        country_rows.append([
            esc(item["country"]),
            fmt_int(item["ips"]),
            fmt_int(item["requests"]),
            f'{item["bad_ips"]} ({fmt_pct(item["bad_ips"], item["ips"])})',
            item["protected_ips"],
            f'{fmt_int(item["blocked_requests"])} ({fmt_pct(item["blocked_requests"], item["requests"])})',
        ])

    campaign_rows = []
    for item in campaigns:
        if item["ips"] < 5 and item["requests"] < 100:
            continue
        state = badge("疑似代理池爬虫", "warn") if item["rotating"] else badge("统计观察", "muted")
        campaign_rows.append([
            f'<span title="{esc(item["ua"])}">{esc(item["ua"][:115])}</span>',
            fmt_int(item["ips"]),
            fmt_int(item["requests"]),
            item["days_count"],
            item["archive_ips"],
            item["bad_ips"],
            item["protected_ips"],
            f'{item["direct_ratio"]*100:.1f}%',
            esc(item["top_countries"]),
            state,
        ])
        if len(campaign_rows) >= 120:
            break

    persistent_rows = []
    persistent = sorted(
        (ip for ip in stats if len(stats[ip].days) >= max(5, math.ceil(total_days * 0.45))),
        key=lambda ip: (len(stats[ip].days), stats[ip].requests),
        reverse=True,
    )
    for ip in persistent[:160]:
        item, verdict = stats[ip], verdicts[ip]
        persistent_rows.append([
            f"<code>{esc(ip)}</code>",
            len(item.days),
            fmt_int(item.requests),
            len(item.archive_paths),
            badge(verdict.level, {
                "建议封禁": "danger", "观察": "warn", "保护": "good", "低风险": "muted",
            }[verdict.level]),
            esc(verdict.trusted_bot or ", ".join(item.bot_claims)),
            f"{esc(verdict.geo.country)} / AS{esc(verdict.geo.asn or '')} {esc(verdict.geo.as_name[:42])}",
            esc("；".join(verdict.reasons[:4])),
        ])

    protected_rows = []
    for ip in sorted(protected, key=lambda x: stats[x].requests, reverse=True)[:150]:
        s, v = stats[ip], verdicts[ip]
        protected_rows.append([
            f"<code>{esc(ip)}</code>",
            fmt_int(s.requests),
            esc(v.trusted_bot or "行为/引荐保护"),
            esc(", ".join(s.bot_claims)),
            esc(", ".join(s.good_referrers)),
            f"{esc(v.geo.country)} / AS{esc(v.geo.asn or '')} {esc(v.geo.as_name[:40])}",
            badge("黑名单覆盖", "danger") if v.blacklisted else badge("未封", "good"),
        ])

    audit_rows = []
    for item in blacklist_audit:
        kind = {
            "建议解封": "danger", "复核解封": "warn", "复核": "warn",
            "业务保留": "dark", "保留": "dark", "无近期样本": "muted",
        }[item["action"]]
        audit_rows.append([
            f"<code>{esc(item['rule'])}</code>",
            badge(item["action"], kind),
            item["active"],
            item["bad"],
            item["protected"],
            esc(item["reason"]),
            "<br>".join(f"<code>{esc(x)}</code>" for x in item["examples"]),
        ])

    source_rows = []
    for name, item in intel.sources.items():
        fetched = datetime.fromtimestamp(item["fetched_at"]).astimezone().strftime("%Y-%m-%d %H:%M") if item["fetched_at"] else ""
        source_rows.append([
            esc(name), fmt_int(item["records"]), esc(item["creation_time"]),
            esc(fetched), f'<a href="{esc(item["url"])}" target="_blank" rel="noreferrer">来源</a>',
        ])

    period = ""
    if meta["first"] and meta["last"]:
        period = f"{meta['first'].strftime('%Y-%m-%d %H:%M')} 至 {meta['last'].strftime('%Y-%m-%d %H:%M')}"
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    cards = [
        ("请求", fmt_int(total_requests), period),
        ("独立 IP", fmt_int(total_ips), f"{total_days} 个自然日"),
        ("已返回 444", fmt_int(blocked), fmt_pct(blocked, total_requests)),
        ("高风险 IP", fmt_int(len(high)), "满足多重行为证据"),
        ("观察 IP", fmt_int(len(observe)), "不自动封"),
        ("保护 IP", fmt_int(len(protected)), "搜索 / AI / 真人信号"),
        ("声明爬虫请求", fmt_int(bot_requests), f"已验证来源约 {fmt_int(verified_bot_requests)} 请求"),
        ("高置信 /24", fmt_int(len(auto_networks)), "输出前仍建议人工复核"),
    ]
    card_html = "".join(
        f'<div class="card"><div class="label">{esc(a)}</div><div class="value">{esc(b)}</div><div class="sub">{esc(c)}</div></div>'
        for a, b, c in cards
    )

    methodology = """
    <ol>
      <li><strong>保护层先行：</strong>官方 IP 网段或 FCrDNS 验证的搜索引擎；ChatGPT/Claude/Perplexity 用户触发 UA；搜索/AI 引荐；执行站内 JS 统计请求的访问，均不进入自动封禁。</li>
      <li><strong>行为评分：</strong>漏洞路径、非 HTTP 探测、扫描器 UA、单日批量遍历、跨日持续抓取、近乎全无来源等叠加计分。云厂商 ASN 只加 1 分，国家不加分。</li>
      <li><strong>网段升级：</strong>只有同一 /24 内至少多个高风险 IP、占比足够高且没有保护 IP，才输出网段候选；/16、ASN 和国家永不自动封禁。</li>
      <li><strong>黑名单审计：</strong>优先找出实际覆盖可信爬虫/AI/真人信号的规则；“最近没出现”不等于安全，也不作为自动解封依据。</li>
      <li><strong>部署原则：</strong>候选名单先观察 3–7 天，再手工合并进生产配置；先单 IP、后 /24，避免 /16、国家和整个云厂商的一刀切。</li>
    </ol>
    """

    caveats = """
    <ul>
      <li>Access log 看不到 Cookie、JS 挑战结果和完整会话，无法证明每个普通 Chrome UA 都是真人。</li>
      <li>住宅代理僵尸网络通常“一 IP 一请求”，靠永久 IP 黑名单会持续追新 IP；更有效的是速率限制、缓存、挑战和路径级规则。</li>
      <li>ASN/国家归属会变化；DB-IP Lite 为月更免费库，位置和组织名可能有误差。报告已按 CC BY 4.0 要求注明来源。</li>
      <li>当前日志窗口只有约两周，“每天都来”仅指该窗口内重复出现，不能外推到半年。</li>
    </ul>
    """

    style = """
    :root{--bg:#f5f7fb;--panel:#fff;--text:#172033;--muted:#667085;--line:#e5e9f0;--blue:#2563eb;--red:#b42318;--amber:#b54708;--green:#067647}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
    main{max-width:1500px;margin:auto;padding:26px}.hero{background:linear-gradient(135deg,#172554,#1d4ed8);color:white;border-radius:16px;padding:28px;margin-bottom:18px}
    h1{margin:0 0 6px;font-size:28px}h2{margin:0 0 14px;font-size:19px}h3{font-size:15px}.hero p{opacity:.85;margin:0}
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 8px #1018280a}
    .card{padding:15px}.card .label{color:var(--muted);font-size:12px}.card .value{font-size:25px;font-weight:700;margin:2px 0}.card .sub{font-size:11px;color:var(--muted)}
    .panel{padding:18px;margin:14px 0}.muted,small{color:var(--muted)}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}
    .table-wrap{overflow:auto;border:1px solid var(--line);border-radius:9px}table{width:100%;border-collapse:collapse;background:white}th,td{padding:9px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}td:last-child{white-space:normal;min-width:220px}
    th{position:sticky;top:0;background:#f8fafc;z-index:1;font-size:12px;color:#475467}tr:hover td{background:#f9fbff}
    .badge{display:inline-block;border-radius:99px;padding:2px 7px;font-size:11px;font-weight:650}.danger{background:#fee4e2;color:var(--red)}.warn{background:#fef0c7;color:var(--amber)}.good{background:#dcfae6;color:var(--green)}.dark{background:#e4e7ec;color:#344054}.badge.muted{background:#f2f4f7;color:#667085}
    .bar{height:7px;background:#60a5fa;border-radius:9px;display:inline-block;margin-right:7px;min-width:2px}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
    details{border-top:1px solid var(--line);padding-top:10px;margin-top:10px}summary{cursor:pointer;font-weight:650}.two{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    .callout{border-left:4px solid var(--amber);background:#fffaeb;padding:10px 14px;border-radius:7px}.ok{border-color:var(--green);background:#ecfdf3}
    a{color:var(--blue)}@media(max-width:900px){main{padding:12px}.two{grid-template-columns:1fr}.hero{padding:20px}th,td{padding:7px}}
    @media print{body{background:#fff}.panel,.card{box-shadow:none}main{max-width:none}.table-wrap{overflow:visible}th{position:static}}
    """

    doc = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nginx Shield IP 流量分析报告</title><style>{style}</style></head>
<body><main>
<section class="hero"><h1>Nginx Shield IP 流量分析报告</h1><p>生成于 {esc(generated)} · 分析器 v{VERSION} · 只生成建议，未修改生产黑名单</p></section>
<section class="cards">{card_html}</section>
<section class="panel"><h2>先说结论</h2>
<div class="callout"><strong>不建议继续按国家、整个云厂商或 /16 批量封禁。</strong>这会误伤搜索引擎、ChatGPT 用户取页、VPN 真人和 IP 重新分配后的新用户。报告只把 {fmt_int(len(high))} 个 IP 与 {fmt_int(len(auto_networks))} 个 /24 列为高置信候选；其余进入观察层。</div>
<p>当前 444 占全部请求的 <strong>{fmt_pct(blocked,total_requests)}</strong>。声明搜索/AI 爬虫的请求为 {fmt_int(bot_requests)}；其中只有通过官方网段或 FCrDNS 的来源显示为“已验证”。</p>
</section>
<section class="panel"><h2>建议的落地顺序</h2>
<ol>
<li>{unblock_advice}</li>
<li>先应用 <code>candidate_block_ips.conf</code> 的单 IP，再观察错误率和搜索抓取 1–3 天。</li>
<li><code>candidate_bad_ua_map.conf</code> 针对跨国家住宅代理池的精确伪装 UA；它比追逐上千个一次性 IP 更有效，但仍应先灰度。</li>
<li><code>candidate_block_networks.conf</code> 的 /24 风险最高，最后应用；任何出现保护 IP 的段都没有写入。</li>
</ol>
</section>
<section class="panel"><h2>每日流量</h2>
<p class="muted">“新 IP”指在当前 15 天日志窗口内第一次出现，并不代表该 IP 在更早历史中从未访问。</p>
{table(["日期","请求","IP","窗口内新IP","回访IP","444","探测"],daily_rows)}</section>
<section class="panel"><h2>高风险 IP（建议先封单 IP）</h2>
<p class="muted">需要风险分 ≥ 7，且未命中保护层。输出文件中的规则与本表一致。</p>
{table(["IP","分数","请求","天数","文章","国家 / ASN","证据","样本"],high_rows)}</section>
<section class="panel"><h2>/24 网段候选</h2>
<p class="muted">只有同段多个 IP 呈现一致恶意行为且没有保护 IP 才生成规则；包含保护 IP 的网段会明确禁止整段封禁。</p>
{table(["网段","请求","IP","高风险IP","保护IP","国家 / ASN","结论","证据"],network_rows)}</section>
<section class="panel"><h2>访问最多的 IP</h2>{table(["IP","请求","天数","文章","国家 / ASN","结论","摘要"],ip_rows)}</section>
<section class="panel"><h2>持续多日来访 IP</h2>
<p class="muted">持续出现本身不是封禁理由；Google、OpenAI、服务器定时任务也会每天来。结论列已结合身份与行为。</p>
{table(["IP","活跃天","请求","文章","结论","身份声明","国家 / ASN","证据"],persistent_rows)}</section>
<section class="panel"><h2>多 IP 同 User-Agent 行为簇</h2>
<p class="muted">这张表用于发现住宅代理池/轮换爬虫。“疑似”不会自动生成网段规则，因为 IP 可能横跨真实用户网络。</p>
{table(["主 UA","IP","请求","天数","抓文章IP","高风险IP","保护IP","估算无来源","主要国家","判断"],campaign_rows)}</section>
<section class="panel"><h2>搜索引擎、AI 与真人保护层</h2>
<p class="muted">“行为/引荐保护”不是身份认证，只表示为了降低误伤，不自动封禁；是否真实仍可继续复核。</p>
{table(["IP","请求","身份","声明UA","引荐","国家 / ASN","黑名单"],protected_rows)}</section>
<section class="panel"><h2>现有黑名单审计</h2>
<p class="muted">当前共 {len(blacklist_audit)} 条有效规则，IPv4 去重后覆盖约 {fmt_int(blacklist_v4_coverage)} 个地址。“建议解封”只用于已实际拦截可信来源；“复核解封”需要你确认。没有近期样本的规则不会自动删除。</p>
{table(["规则","动作","活跃IP","高风险","保护IP","原因","示例"],audit_rows)}
<details><summary>冗余与无效规则</summary>
<p>冗余规则 {len(redundancy)} 条；无效行 {len(invalid_rules)} 条。</p>
{table(["规则","被这些大网段包含","重复次数"],[[f"<code>{esc(x['rule'])}</code>",esc(", ".join(x["parents"])),x["duplicates"]] for x in redundancy])}
{"<pre>"+esc(chr(10).join(invalid_rules))+"</pre>" if invalid_rules else ""}
</details></section>
<section class="panel"><h2>ASN 风险排行（只用于观察，绝不自动整 ASN 封禁）</h2>
{table(["ASN","组织","国家","活跃IP","请求","高风险IP","保护IP"],asn_rows)}</section>
<section class="panel"><h2>国家 / 地区分布（只用于观察）</h2>
<p class="muted">国家不参与风险评分。新加坡等 VPN/云节点集中地区仍可能有真人和 AI 用户，不能据此整国封禁。</p>
{table(["国家","活跃IP","请求","高风险IP","保护IP","444"],country_rows)}</section>
<div class="two"><section class="panel"><h2>方法论</h2>{methodology}</section>
<section class="panel"><h2>边界与限制</h2>{caveats}</section></div>
<section class="panel"><h2>数据来源与可复现性</h2>
{table(["数据源","记录数","源版本","本地获取时间","链接"],source_rows)}
<p>日志文件：{esc(", ".join(p.name for p in files))}</p>
<p>成功解析 {fmt_int(meta["parsed"])} 行，跳过 {fmt_int(meta["skipped"])} 行。</p>
<details><summary>解析失败样本</summary><pre>{esc(chr(10).join(parse_errors))}</pre></details>
<p class="muted">IP 归属数据：<a href="https://db-ip.com" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</a>（DB-IP Lite，CC BY 4.0）。</p>
<p class="muted">身份验证依据：
<a href="https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests" target="_blank" rel="noreferrer">Google 官方验证说明</a> ·
<a href="https://blogs.bing.com/webmaster/August-2012/How-to-Verify-that-Bingbot-is-Bingbot" target="_blank" rel="noreferrer">Bing FCrDNS</a> ·
<a href="https://yandex.com/support/webmaster/en/robot-workings/check-yandex-robots" target="_blank" rel="noreferrer">Yandex FCrDNS</a> ·
<a href="https://openai.com/searchbot.json" target="_blank" rel="noreferrer">OpenAI SearchBot 网段</a>。
</p>
</section>
</main></body></html>"""
    output.write_text(doc, encoding="utf-8")


def write_outputs(
    output_dir: Path, stats: dict[str, IPStats], verdicts: dict[str, Verdict],
    networks: list[dict], asns: list[dict], countries: list[dict],
    campaigns: list[dict], audit: list[dict], meta: dict,
) -> None:
    high = sorted(
        (ip for ip, v in verdicts.items() if v.level == "建议封禁" and not v.blacklisted),
        key=lambda ip: (verdicts[ip].score, stats[ip].requests), reverse=True,
    )
    lines = [
        "# 自动生成的高置信单 IP 候选；请先复核，勿直接覆盖生产黑名单",
        f"# generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
    ]
    for ip in high:
        reason = "；".join(verdicts[ip].reasons).replace("\n", " ")
        lines.append(f"{ip} 1; # score={verdicts[ip].score} {reason}")
    (output_dir / "candidate_block_ips.conf").write_text("\n".join(lines) + "\n", encoding="utf-8")

    network_lines = [
        "# 自动生成的 /24 高置信候选；风险高于单 IP，必须人工复核后再使用",
        f"# generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
    ]
    for item in networks:
        if item["auto"]:
            network_lines.append(
                f"{item['network']} 1; # bad_ips={item['bad_ips']} requests={item['requests']} "
                + "；".join(item["reasons"])
            )
    (output_dir / "candidate_block_networks.conf").write_text(
        "\n".join(network_lines) + "\n", encoding="utf-8"
    )

    unblock = [
        "# 现有黑名单疑似误伤；此文件不是可直接 include 的配置，请逐条核验后从原名单删除",
        f"# generated: {datetime.now().astimezone().isoformat(timespec='seconds')}",
    ]
    for item in audit:
        if item["action"] in ("建议解封", "复核解封"):
            unblock.append(f"# {item['action']}: {item['rule']} -- {item['reason']}")
    (output_dir / "candidate_unblock_review.txt").write_text(
        "\n".join(unblock) + "\n", encoding="utf-8"
    )

    protected_lines = [
        "# 分析窗口内的保护 IP，仅用于审计，不建议长期硬编码为 allowlist",
    ]
    for ip, verdict in sorted(verdicts.items()):
        if verdict.protected:
            protected_lines.append(
                f"{ip}\t{verdict.trusted_bot or 'behavior/referrer'}\t"
                + "；".join(verdict.reasons)
            )
    (output_dir / "protected_ips.tsv").write_text("\n".join(protected_lines) + "\n", encoding="utf-8")

    ua_candidates = [
        x for x in campaigns
        if x["rotating"] and x["ips"] >= 50 and x["direct_ratio"] >= 0.98
        and x["archive_ips"] >= math.ceil(x["ips"] * 0.8)
    ]
    ua_lines = [
        "# 在 nginx.conf 的 http {} 中 include 本文件；不要放入 server {}",
        "# 精确 UA 仅来自“至少 50 IP、>=98% 无来源、>=80% IP 抓文章、无保护 IP”的行为簇",
        "map $http_user_agent $shield_bad_ua {",
        "    default 0;",
    ]
    for item in ua_candidates:
        quoted = item["ua"].replace("\\", "\\\\").replace('"', '\\"')
        ua_lines.append(
            f'    "{quoted}" 1; # ips={item["ips"]} requests={item["requests"]}'
        )
    ua_lines.extend([
        "}",
        "",
        "# 然后在需要保护的 server {} 中加入：",
        "# if ($shield_bad_ua) { return 444; }",
    ])
    (output_dir / "candidate_bad_ua_map.conf").write_text(
        "\n".join(ua_lines) + "\n", encoding="utf-8"
    )

    def write_csv(name: str, headers: list[str], rows: Iterable[Iterable[object]]) -> None:
        with (output_dir / name).open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            writer.writerows(rows)

    write_csv(
        "ip_details.csv",
        ["ip", "requests", "active_days", "max_day_requests", "unique_paths",
         "archive_paths", "status_444", "probes", "malformed", "auth_attempts",
         "php_scan_paths", "human_events", "country", "asn", "as_name", "score",
         "verdict", "protected", "trusted_bot", "blacklisted", "reasons", "top_ua"],
        (
            [
                ip, item.requests, len(item.days), item.max_day_requests, len(item.paths),
                len(item.archive_paths), item.status[444], item.probes, item.malformed,
                item.auth_attempts, len(item.php_paths), item.human_events,
                verdicts[ip].geo.country, verdicts[ip].geo.asn or "",
                verdicts[ip].geo.as_name, verdicts[ip].score, verdicts[ip].level,
                verdicts[ip].protected, verdicts[ip].trusted_bot,
                verdicts[ip].blacklisted, "；".join(verdicts[ip].reasons),
                item.uas.most_common(1)[0][0] if item.uas else "",
            ]
            for ip, item in sorted(stats.items(), key=lambda pair: pair[1].requests, reverse=True)
        ),
    )
    write_csv(
        "network_details.csv",
        ["network", "ips", "requests", "bad_ips", "observe_ips", "protected_ips",
         "probes", "auto_candidate", "already_blacklisted", "country", "asn", "as_name", "reasons"],
        (
            [n["network"], n["ips"], n["requests"], n["bad_ips"], n["observe_ips"],
             n["protected_ips"], n["probes"], n["auto"], n["already_blacklisted"],
             n["country"], n["asn"] or "",
             n["as_name"], "；".join(n["reasons"])]
            for n in networks
        ),
    )
    write_csv(
        "asn_details.csv",
        ["asn", "name", "country", "ips", "requests", "bad_ips", "protected_ips", "bad_ratio"],
        (
            [a["asn"], a["name"], a["country"], a["ips"], a["requests"],
             a["bad_ips"], a["protected_ips"], f'{a["bad_ratio"]:.6f}']
            for a in asns
        ),
    )
    write_csv(
        "country_details.csv",
        ["country", "ips", "requests", "bad_ips", "protected_ips", "blocked_requests"],
        (
            [x["country"], x["ips"], x["requests"], x["bad_ips"],
             x["protected_ips"], x["blocked_requests"]]
            for x in countries
        ),
    )
    write_csv(
        "ua_campaigns.csv",
        ["user_agent", "ips", "requests", "days", "archive_ips", "bad_ips",
         "protected_ips", "direct_ratio", "top_countries", "rotating_suspect"],
        (
            [x["ua"], x["ips"], x["requests"], x["days_count"], x["archive_ips"],
             x["bad_ips"], x["protected_ips"], f'{x["direct_ratio"]:.6f}',
             x["top_countries"], x["rotating"]]
            for x in campaigns
        ),
    )
    write_csv(
        "blacklist_audit.csv",
        ["rule", "action", "active_ips", "bad_ips", "protected_ips", "trusted_ips",
         "official_overlap", "reason", "examples"],
        (
            [x["rule"], x["action"], x["active"], x["bad"], x["protected"],
             x["trusted"], "；".join(x["official"]), x["reason"], "；".join(x["examples"])]
            for x in audit
        ),
    )
    write_csv(
        "daily_details.csv",
        ["date", "requests", "unique_ips", "new_ips_in_window", "returning_ips",
         "status_444", "probes"],
        (
            [day, x["requests"], x["ips"], x["new_ips"], x["returning_ips"],
             x["blocked"], x["probes"]]
            for day, x in meta["daily"].items()
        ),
    )


def build_summary(
    stats: dict[str, IPStats], verdicts: dict[str, Verdict], networks: list[dict],
    campaigns: list[dict], audit: list[dict], redundancy: list[dict],
    invalid_rules: list[str], meta: dict,
) -> dict:
    candidates = [
        ip for ip, verdict in verdicts.items()
        if verdict.level == "建议封禁" and not verdict.blacklisted
    ]
    ua_candidates = [
        x for x in campaigns
        if x["rotating"] and x["ips"] >= 50 and x["direct_ratio"] >= 0.98
        and x["archive_ips"] >= math.ceil(x["ips"] * 0.8)
    ]
    return {
        "version": VERSION,
        "generated_at": datetime.now().astimezone().isoformat(),
        "period": {
            "first": meta["first"].isoformat() if meta["first"] else None,
            "last": meta["last"].isoformat() if meta["last"] else None,
            "days": len(meta["daily"]),
        },
        "requests": meta["parsed"],
        "unique_ips": len(stats),
        "status_444": sum(x.status[444] for x in stats.values()),
        "verdicts": dict(Counter(v.level for v in verdicts.values())),
        "candidate_ip_count": len(candidates),
        "candidate_ip_requests": sum(stats[ip].requests for ip in candidates),
        "candidate_network_count": sum(n["auto"] for n in networks),
        "candidate_ua_count": len(ua_candidates),
        "candidate_ua_requests": sum(x["requests"] for x in ua_candidates),
        "blacklist_rules": len(audit),
        "blacklist_redundant_rules": len(redundancy),
        "blacklist_invalid_lines": len(invalid_rules),
        "blacklist_review": dict(Counter(x["action"] for x in audit)),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Nginx 日志 IP/爬虫分析与 HTML 报告")
    parser.add_argument("--log-dir", type=Path, default=LOG_DIR)
    parser.add_argument("--blacklist", type=Path, default=BLACKLIST_FILE)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    parser.add_argument("--allowlist", type=Path, default=ALLOWLIST_FILE)
    parser.add_argument("--offline", action="store_true", help="不联网更新数据库或验证 PTR")
    args = parser.parse_args(argv)

    if not args.log_dir.is_dir():
        parser.error(f"日志目录不存在: {args.log_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.data_dir.mkdir(parents=True, exist_ok=True)
    files = iter_log_files(args.log_dir)
    if not files:
        parser.error(f"没有找到 access.log*: {args.log_dir}")

    print(f"[1/6] 读取 {len(files)} 个日志文件...")
    stats, meta, parse_errors = parse_logs(files)
    print(f"      {meta['parsed']:,} 请求，{len(stats):,} 个 IP，跳过 {meta['skipped']:,} 行")

    print("[2/6] 加载官方爬虫网段与 DB-IP Lite...")
    intel = Intelligence(args.data_dir)
    intel.refresh_official_ranges(not args.offline)
    intel.refresh_dbip(not args.offline)

    print("[3/6] 验证 Bing / Baidu / Yandex 的 FCrDNS...")
    intel.verify_ptr_claims(ptr_jobs(stats), not args.offline)

    print("[4/6] 行为评分、网段与 ASN 聚合...")
    rules, invalid_rules = parse_blacklist(args.blacklist)
    blacklist_networks = [net for _, net in rules]
    allow_networks, invalid_allow = parse_allowlist(args.allowlist)
    if invalid_allow:
        eprint("警告: 白名单存在无效行:", *invalid_allow, sep="\n  ")
    total_days = max(1, len(meta["daily"]))
    verdicts = {
        ip: score_ip(item, intel, total_days, blacklist_networks, allow_networks)
        for ip, item in stats.items()
    }
    networks = aggregate_networks(stats, verdicts, blacklist_networks)
    asns = aggregate_asns(stats, verdicts)
    countries = aggregate_countries(stats, verdicts)
    campaigns = aggregate_user_agents(stats, verdicts)

    print("[5/6] 审计现有黑名单...")
    audit = audit_blacklist(rules, stats, verdicts, intel)
    redundancy = audit_redundancy(rules)

    print("[6/6] 生成报告与候选配置...")
    report_path = args.output_dir / "ip_analysis_report.html"
    generate_report(
        report_path, stats, verdicts, networks, asns, countries, campaigns, audit, redundancy,
        invalid_rules, meta, parse_errors, intel, files,
    )
    write_outputs(
        args.output_dir, stats, verdicts, networks, asns, countries,
        campaigns, audit, meta,
    )
    summary = build_summary(
        stats, verdicts, networks, campaigns, audit, redundancy, invalid_rules, meta
    )
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"完成: {report_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
