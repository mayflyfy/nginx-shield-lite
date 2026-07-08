#!/usr/bin/env python3
"""Build an aggressive, deployable Nginx policy from the analysis results.

Outputs a scoped deployment bundle under analysis_output/deploy:
  nginx.conf, black_ip.conf, trusted_ip.conf and reports.

The active files in the repository root are never modified.
"""

from __future__ import annotations

import bisect
import csv
import gzip
import html
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    from . import ip_shield_analyzer as analyzer
    from .paths import (
        ALLOWLIST_FILE,
        BLACKLIST_FILE,
        DATA_DIR,
        LOG_DIR,
        NGINX_SOURCE,
        OUTPUT_DIR,
    )
except ImportError:
    import ip_shield_analyzer as analyzer
    from paths import (
        ALLOWLIST_FILE,
        BLACKLIST_FILE,
        DATA_DIR,
        LOG_DIR,
        NGINX_SOURCE,
        OUTPUT_DIR,
    )


BLOCK_COUNTRIES = {
    "SG": "新加坡：日志中代理、云主机和一次性抓取 IP 高度集中",
    "RU": "俄罗斯：非目标用户区域，且 Yandex 抓取频率过高",
}

# Deliberately excludes Microsoft/Azure, Google, AWS, Cloudflare and Akamai:
# they had substantial verified search/AI/user-triggered traffic in this sample.
# GTT AS3257 is also excluded from ASN-wide blocking because it is a Tier-1
# transit carrier; block only observed customer prefixes if needed.
BLOCK_ASNS = {
    132203: "腾讯云国际",
    45090: "腾讯云中国",
    55990: "华为云中国",
    45102: "阿里云国际",
    37963: "阿里云中国",
    135377: "UCloud",
    211590: "Bucklog 扫描网络",
    48090: "TECHOFF 扫描网络",
    142430: "DIGI VPS",
    204770: "Cherry Servers",
    18450: "WebNX",
    14061: "DigitalOcean",
    48721: "Flyservers",
    267784: "Flyservers",
    398324: "Censys",
    398722: "Censys",
    398705: "Censys",
    209699: "Coaxial Cable 扫描网络",
    31898: "Oracle Cloud",
    206264: "Amarutu Hosting",
    # Aggressive 2026-07-08 policy: hosting, VPN/proxy, SEO collection,
    # and low-relevance overseas infrastructure seen in the latest allowed-IP CSV.
    9009: "M247 Europe：机房/VPN/代理出口",
    212238: "Datacamp：CDN/机房/VPN/代理出口",
    200373: "3xK Tech：代理/分散出口",
    26658: "HT：香港/美国机房出口",
    152330: "Alllan Communications：香港机房出口",
    12876: "Scaleway：法国云服务器",
    209366: "SEMrush：SEO 商业采集",
    396319: "Oxylabs：代理/数据采集",
    7979: "Servers.com：服务器托管",
    396356: "Latitude.sh：云/裸金属服务器",
    399073: "Bunny Technology：CDN/边缘/代理网络",
    5065: "Bunny Communications：网络/CDN/边缘出口",
    45753: "Netsec Limited：香港机房出口",
    63199: "CDS Global Cloud：云服务器网络",
    16276: "OVH：欧洲云服务器",
    11798: "Ace Data Centers：服务器托管",
    401152: "Ace Data Centers II：服务器托管",
    62874: "Web2Objects：服务器/代理出口",
    210906: "Bite Lietuva：分散代理/出口网络",
}

POLICY_CLOUD_ASNS = {
    132203, 45090, 55990, 45102, 37963, 135377,
    9009, 212238, 200373, 26658, 152330, 12876, 7979,
    396356, 399073, 5065, 45753, 63199, 16276, 11798,
    401152, 62874, 210906,
}

# Fixed user-owned infrastructure. Keep exact /32, even when its Tencent Cloud
# parent ranges are blocked. Do not widen these to /24.
SELF_HOST_IPS = {"43.155.248.119"}

# 360 Search publishes these crawler ranges on its official help page.
OFFICIAL_360_NETWORKS = [
    ipaddress.ip_network(value)
    for value in (
        "42.236.10.0/24",
        "42.236.12.0/24",
        "42.236.17.0/24",
        "42.236.101.0/24",
        "180.153.236.0/24",
        "180.163.220.0/24",
    )
]

# These services matter to a Chinese-language site but do not all publish a
# stable, official IP list. Observed, non-malicious claims get a narrow /32
# exception from broad country/ASN blocks; they do not bypass path/UA checks.
CLAIM_PROTECTED_BOTS = {
    "Baidu",
    "360",
    "Sogou",
    "Shenma/Yisou",
    "PetalBot",
    "Bytespider",
    "ByteDance crawler",
    "Doubao user",
}

# Yandex 与俄罗斯区是明确的业务封禁策略，不删除原有 Yandex 网段。
REMOVE_RULES: set[str] = set()

BAD_UA_PATTERN = (
    r"spbot|CensysInspect|Infrawatch|DnyzBot|Researchscan|semrushbot|"
    r"AhrefsBot|DotBot|Uptimebot|MJ12bot|MegaIndex|ZoominfoBot|"
    r"BLEXBot|ExtLinksBot|aiHitBot|Barkrowler|Yandex|"
    r"python-requests|Go-http-client|masscan|zgrab|nuclei|sqlmap|nikto|"
    r"curl/|wget/|TLM-Audit-Scanner|api-config-collector"
)

BAD_PATH_PATTERN = (
    r"(?:^|/)\.(?:env|git|svn)(?:/|$)|"
    r"wp-config|phpmyadmin|vendor/phpunit|cgi-bin|server-status|"
    r"actuator|HNAP1|boaform|SDK/webLanguage|_ignition|_cluster|"
    r"solr/admin|manager/html|/etc/passwd|(?:\.\./|%2e%2e)|jndi:"
)


class IPv4Matcher:
    def __init__(self, networks):
        ranges = sorted(
            (int(n.network_address), int(n.broadcast_address))
            for n in networks if n.version == 4
        )
        merged = []
        for start, end in ranges:
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        self.starts = [x[0] for x in merged]
        self.ends = [x[1] for x in merged]

    def contains(self, ip: str) -> bool:
        try:
            value = int(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError:
            return False
        idx = bisect.bisect_right(self.starts, value) - 1
        return idx >= 0 and value <= self.ends[idx]

    def overlaps(self, network: ipaddress._BaseNetwork) -> bool:
        if network.version != 4:
            return False
        start = int(network.network_address)
        end = int(network.broadcast_address)
        idx = bisect.bisect_right(self.starts, end) - 1
        return idx >= 0 and self.ends[idx] >= start


def collapse_mixed(networks):
    networks = list(networks)
    return (
        list(ipaddress.collapse_addresses(x for x in networks if x.version == 4))
        + list(ipaddress.collapse_addresses(x for x in networks if x.version == 6))
    )


def widen_ipv4_to_slash24(networks):
    """Use /24 as the finest IPv4 policy granularity, then collapse again."""
    return collapse_mixed(
        network.supernet(new_prefix=24)
        if network.version == 4 and network.prefixlen > 24
        else network
        for network in networks
    )


def range_to_cidrs(start: int, end: int):
    return list(ipaddress.summarize_address_range(
        ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
    ))


def db_networks(table: analyzer.RangeTable, wanted: set[str]) -> list[ipaddress.IPv4Network]:
    result = []
    for start, end, values in zip(table.starts, table.ends, table.values):
        if values and values[0] in wanted:
            result.extend(range_to_cidrs(start, end))
    return result


def subtract_networks(blocks, exclusions):
    by_version = {
        4: sorted((x for x in exclusions if x.version == 4), key=lambda n: (int(n.network_address), n.prefixlen)),
        6: sorted((x for x in exclusions if x.version == 6), key=lambda n: (int(n.network_address), n.prefixlen)),
    }
    output = []
    for block in blocks:
        pieces = [block]
        for exc in by_version[block.version]:
            if int(exc.network_address) > int(block.broadcast_address):
                break
            if int(exc.broadcast_address) < int(block.network_address):
                continue
            next_pieces = []
            for piece in pieces:
                if not piece.overlaps(exc):
                    next_pieces.append(piece)
                elif piece.subnet_of(exc):
                    continue
                elif exc.subnet_of(piece):
                    next_pieces.extend(piece.address_exclude(exc))
            pieces = next_pieces
            if not pieces:
                break
        output.extend(pieces)
    return collapse_mixed(output)


def build_final_blocks(raw_blocks, trusted_networks):
    """Keep /24-or-broader blocks intact; trusted_ip.conf wins on overlap."""
    return widen_ipv4_to_slash24(raw_blocks)


def hard_bad(item: analyzer.IPStats) -> bool:
    return bool(
        item.probes or item.malformed or item.auth_attempts >= 10
        or len(item.php_paths) >= 8
    )


def strong_human_or_ai(item: analyzer.IPStats) -> bool:
    return bool(
        item.human_events
        or item.admin_events >= 2
        or item.good_referrers
        or "ai_user" in item.bot_kinds
    ) and not hard_bad(item)


def intentionally_blocked_bot(verdict: analyzer.Verdict) -> bool:
    return verdict.trusted_bot == "Yandex"


def write_network_file(path: Path, networks, value: int, heading: list[str]):
    lines = [f"# {x}" for x in heading]
    lines.append(f"# generated: {datetime.now().astimezone().isoformat(timespec='seconds')}")
    for network in sorted(
        networks, key=lambda n: (n.version, int(n.network_address), n.prefixlen)
    ):
        lines.append(f"{network} {value};")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def iter_requests(paths):
    for path in paths:
        opener = gzip.open if path.suffix.lower() == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                match = analyzer.LOG_RE.match(line.rstrip("\r\n"))
                if not match:
                    continue
                request = match.group("request")
                parts = request.split()
                yield {
                    "ip": match.group("ip"),
                    "time": analyzer.parse_time(match.group("time")),
                    "target": parts[1] if len(parts) >= 2 else request,
                    "status": int(match.group("status")),
                    "referrer": match.group("referrer"),
                    "ua": match.group("ua"),
                }


def generate_nginx(source: Path, target: Path, exact_uas: list[str]):
    text = source.read_text(encoding="utf-8")
    geo_re = re.compile(r"\s*geo \$blacklisted_ip\s*\{.*?\n\s*\}", re.S)
    extension = """

    geo $trusted_ip {
        default 0;
        include conf.d/trusted_ip.conf;
    }

    # 精确 UA 很长，需要显式提高 map 哈希桶；否则 nginx -t 会报 map_hash 错误
    map_hash_bucket_size 256;
    map_hash_max_size 4096;

    # 所有原来使用 $blacklisted_ip 的应用统一遵守 trusted_ip.conf。
    map "$trusted_ip:$blacklisted_ip" $ip_blocked {
        default 0;
        "0:1" 1;
    }

    # 已知商业采集器、扫描器及脚本客户端
    map $http_user_agent $shield_known_bad_ua {
        default 0;
        ~*(spbot|CensysInspect|Infrawatch|DnyzBot|Researchscan|semrushbot|AhrefsBot|DotBot|Uptimebot|MJ12bot|MegaIndex|ZoominfoBot|BLEXBot|ExtLinksBot|aiHitBot|Barkrowler|Yandex|python-requests|Go-http-client|masscan|zgrab|nuclei|sqlmap|nikto|curl/|wget/|TLM-Audit-Scanner|api-config-collector) 1;
    }

    # 从本批日志中识别出的跨国家住宅代理池精确 UA
    map $http_user_agent $shield_proxy_pool_ua {
        default 0;
__EXACT_UA_RULES__
    }

    map $request_uri $shield_bad_path {
        default 0;
        ~*(?:^|/)\\.(?:env|git|svn)(?:/|$) 1;
        ~*(wp-config|phpmyadmin|vendor/phpunit|cgi-bin|server-status|actuator|HNAP1|boaform|SDK/webLanguage|_ignition|_cluster|solr/admin|manager/html|/etc/passwd|(?:\\.\\./|%2e%2e)|jndi:) 1;
    }

    # 搜索/大模型引荐只保护真实浏览器式入口；它不覆盖恶意路径或明确扫描 UA。
    map $http_referer $shield_good_referrer {
        default 0;
        ~*^https?://(?:[^./]+\\.)*(?:baidu\\.com|sogou\\.com|so\\.com|sm\\.cn|bing\\.com|duckduckgo\\.com|chatgpt\\.com|openai\\.com|perplexity\\.ai|claude\\.ai|copilot\\.microsoft\\.com|gemini\\.google\\.com|poe\\.com|doubao\\.com|toutiao\\.com|yuanbao\\.tencent\\.com|kimi\\.com|moonshot\\.cn|deepseek\\.com|qianwen\\.com|tongyi\\.com|chatglm\\.cn|zhipuai\\.cn|metaso\\.cn|quark\\.cn)(?::[0-9]+)?(?:/|$) 1;
        ~*^https?://(?:[^./]+\\.)*google\\.[a-z.]+(?::[0-9]+)?(?:/|$) 1;
    }

    map $http_user_agent $shield_browser_like {
        default 0;
        ~*(Mozilla/5\\.0|SamanthaDoubao|BytedanceWebview|MicroMessenger|Quark) 1;
    }

    map "$shield_good_referrer:$shield_browser_like" $shield_referred_human {
        default 0;
        "1:1" 1;
    }

    # 中文搜索和用户指定保留的 AI 抓取只跳过大段 IP 黑名单，仍受恶意
    # 路径、明确坏 UA 和限速保护；Yandex 不在此列表。
    map $http_user_agent $shield_preserved_bot {
        default 0;
        ~*(Baiduspider|360Spider|HaosouSpider|Sogou.*(?:spider|web)|YisouSpider|ShenmaSpider|PetalBot|Bytespider|ToutiaoSpider|DoubaoBot|SamanthaDoubao|AppName/doubao) 1;
    }

    map "$shield_referred_human:$shield_preserved_bot" $shield_ip_exception {
        default 0;
        ~^1: 1;
        ~^[01]:1$ 1;
    }

    # 可信官方爬虫跳过 Shield；引荐真人和保留爬虫只跳过大段 IP 黑名单。
    map "$trusted_ip:$blacklisted_ip:$shield_known_bad_ua:$shield_proxy_pool_ua:$shield_bad_path:$shield_ip_exception" $shield_block_request {
        default 0;
        ~^0:1:0:0:0:0$ 1;
        ~^0:[01]:1: 1;
        ~^0:[01]:[01]:1: 1;
        ~^0:[01]:[01]:[01]:1: 1;
    }

    # 只对非可信 IP 计速；空 key 不进入限速状态
    map $trusted_ip $shield_rate_key {
        0 $binary_remote_addr;
        1 "";
    }
    limit_req_zone $shield_rate_key zone=shield_page_rate:10m rate=3r/s;
    limit_conn_zone $shield_rate_key zone=shield_conn:10m;
"""
    ua_lines = []
    for ua in exact_uas:
        safe = ua.replace("\\", "\\\\").replace('"', '\\"')
        ua_lines.append(f'        "{safe}" 1;')
    extension = extension.replace("__EXACT_UA_RULES__", "\n".join(ua_lines))
    geo_match = geo_re.search(text)
    if not geo_match:
        raise RuntimeError("无法定位 nginx.conf 中的 geo $blacklisted_ip")
    text = text[:geo_match.end()] + extension.rstrip() + text[geo_match.end():]

    server_start_re = re.compile(r"(?m)^\s*server\s*\{")
    spans = []
    for match in server_start_re.finditer(text):
        depth = 0
        end = None
        for pos in range(match.start(), len(text)):
            if text[pos] == "{":
                depth += 1
            elif text[pos] == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        if end is None:
            raise RuntimeError("nginx.conf server 块括号不完整")
        spans.append((match.start(), end))

    main_servers = 0
    for start, end in reversed(spans):
        block = text[start:end]
        if not re.search(
            r"(?m)^\s*server_name\s+manbohub\.com\s+www\.manbohub\.com\s*;",
            block,
        ):
            continue
        main_servers += 1
        block = re.sub(
            r"\n\s*if\s*\(\$blacklisted_ip\)\s*\{\s*return 444;\s*\}",
            "", block, flags=re.S,
        )
        block = re.sub(
            r"\n\s*if\s*\(\$http_user_agent\s+~\*.*?\)\s*\{\s*return 444;\s*\}",
            "", block, flags=re.S,
        )
        block = re.sub(
            r"(?m)^(\s*server\s*\{\s*)$",
            r"\1\n        if ($shield_block_request) {\n"
            r"            return 444;\n        }",
            block, count=1,
        )
        block = re.sub(
            r"(?m)^(\s*location\s+/\s*\{\s*)$",
            r"\1\n            limit_req_status 444;\n"
            r"            limit_conn_status 444;\n"
            r"            limit_req zone=shield_page_rate burst=20 nodelay;\n"
            r"            limit_conn shield_conn 20;",
            block,
        )
        text = text[:start] + block + text[end:]
    if main_servers != 2:
        raise RuntimeError(f"预期找到 2 个 manbohub.com server，实际 {main_servers}")
    text = re.sub(
        r"if\s*\(\$blacklisted_ip\)",
        "if ($ip_blocked)",
        text,
    )
    target.write_text(text, encoding="utf-8")


def generate_local_nginx_syntax_test(
    generated_nginx: Path, deploy_dir: Path, target: Path
):
    """Write a minimal local-only config that exercises every new Shield directive."""
    text = generated_nginx.read_text(encoding="utf-8")
    start = text.index("    geo $blacklisted_ip")
    marker = "    limit_conn_zone $shield_rate_key zone=shield_conn:10m;"
    end = text.index(marker, start) + len(marker)
    shield = text[start:end]

    def wsl_path(path: Path) -> str:
        resolved = path.resolve().as_posix()
        drive, remainder = resolved[0].lower(), resolved[2:]
        return f"/mnt/{drive}{remainder}"

    shield = shield.replace(
        "include conf.d/black_ip.conf;",
        f"include {wsl_path(deploy_dir / 'black_ip.conf')};",
    ).replace(
        "include conf.d/trusted_ip.conf;",
        f"include {wsl_path(deploy_dir / 'trusted_ip.conf')};",
    )
    config = f"""# 仅供本机自动执行 nginx -t，不要部署到服务器
pid /tmp/nginx-shield-syntax-test.pid;
error_log stderr notice;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path /tmp/nginx-shield-body;
    proxy_temp_path /tmp/nginx-shield-proxy;
    fastcgi_temp_path /tmp/nginx-shield-fastcgi;
    uwsgi_temp_path /tmp/nginx-shield-uwsgi;
    scgi_temp_path /tmp/nginx-shield-scgi;
{shield}
    server {{
        listen 18080;
        server_name manbohub-syntax-test.invalid;
        if ($shield_block_request) {{ return 444; }}
        location / {{
            limit_req_status 444;
            limit_conn_status 444;
            limit_req zone=shield_page_rate burst=20 nodelay;
            limit_conn shield_conn 20;
            return 200 "ok";
        }}
    }}
}}
"""
    target.write_text(config, encoding="utf-8", newline="\n")


def pct(num, den):
    return f"{num / den * 100:.1f}%" if den else "0.0%"


def html_table(headers, rows):
    head = "".join(f"<th>{html.escape(str(x))}</th>" for x in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{x}</td>" for x in row) + "</tr>" for row in rows
    )
    return f"<div class=scroll><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def main():
    data_dir = DATA_DIR
    output_dir = OUTPUT_DIR
    deploy_dir = output_dir / "deploy"
    deploy_dir.mkdir(parents=True, exist_ok=True)
    for obsolete in ("manbohub_black_ip.conf", "manbohub_trusted_ip.conf"):
        obsolete_path = deploy_dir / obsolete
        if obsolete_path.exists():
            obsolete_path.unlink()

    logs = analyzer.iter_log_files(LOG_DIR)
    stats, meta, _ = analyzer.parse_logs(logs)
    intel = analyzer.Intelligence(data_dir)
    intel.refresh_official_ranges(False)
    intel.refresh_dbip(False)
    intel.verify_ptr_claims(analyzer.ptr_jobs(stats), False)
    old_rules, invalid = analyzer.parse_blacklist(BLACKLIST_FILE)
    if invalid:
        raise RuntimeError("原黑名单存在无效行，停止生成")
    old_networks = [network for _, network in old_rules]
    allow_networks, _ = analyzer.parse_allowlist(ALLOWLIST_FILE)
    verdicts = {
        ip: analyzer.score_ip(item, intel, len(meta["daily"]), old_networks, allow_networks)
        for ip, item in stats.items()
    }
    network_rows = analyzer.aggregate_networks(stats, verdicts, old_networks)
    campaigns = analyzer.aggregate_user_agents(stats, verdicts)

    exact_uas = [
        x["ua"] for x in campaigns
        if x["rotating"] and x["ips"] >= 50 and x["direct_ratio"] >= 0.98
        and x["archive_ips"] >= math.ceil(x["ips"] * 0.8)
        # Generic browser strings are not safe global blocking keys.
        and not re.search(r"mozilla/5\.0", x["ua"], re.I)
    ]

    source_networks = defaultdict(list)
    range_catalog = {}
    for raw, network in old_rules:
        if str(network) not in REMOVE_RULES:
            source_networks["保留的原黑名单"].append(network)
    for ip, verdict in verdicts.items():
        if verdict.level == "建议封禁" and not verdict.blacklisted:
            source_networks["新增高风险单 IP"].append(ipaddress.ip_network(ip))
    for row in network_rows:
        if row["auto"]:
            source_networks["新增高风险 /24"].append(ipaddress.ip_network(row["network"]))
    source_networks["已验证 Yandex IP"].extend(
        ipaddress.ip_network(ip)
        for ip, verdict in verdicts.items()
        if intentionally_blocked_bot(verdict)
    )
    for country, reason in BLOCK_COUNTRIES.items():
        name = f"国家 {country}：{reason}"
        source_networks[name].extend(db_networks(intel.country, {country}))
        range_catalog[("country", country, reason)] = source_networks[name]
    for asn, label in BLOCK_ASNS.items():
        name = f"ASN AS{asn}：{label}"
        source_networks[name].extend(db_networks(intel.asn, {str(asn)}))
        range_catalog[("asn", str(asn), label)] = source_networks[name]
    for name in list(source_networks):
        source_networks[name] = collapse_mixed(source_networks[name])
    for key in list(range_catalog):
        kind, ident, label = key
        lookup_name = (
            f"国家 {ident}：{label}" if kind == "country"
            else f"ASN AS{ident}：{label}"
        )
        range_catalog[key] = source_networks[lookup_name]

    raw_blocks = collapse_mixed(
        network for rows in source_networks.values() for network in rows
    )

    trusted_networks = [
        network for rows in intel.official.values() for network in rows
    ]
    trusted_networks.extend(OFFICIAL_360_NETWORKS)
    trusted_ips = set()
    soft_human_ips = set()
    claimed_bot_ip_holes = set()
    for ip, item in stats.items():
        verdict = verdicts[ip]
        if (verdict.trusted_bot and not intentionally_blocked_bot(verdict)) or any(
            ipaddress.ip_address(ip) in net
            for net in allow_networks if net.version == ipaddress.ip_address(ip).version
        ):
            trusted_ips.add(ip)
        elif (
            set(item.bot_claims).intersection(CLAIM_PROTECTED_BOTS)
            and not hard_bad(item)
            and not intentionally_blocked_bot(verdict)
        ):
            soft_human_ips.add(ip)
            claimed_bot_ip_holes.add(ip)
        elif strong_human_or_ai(item) and not intentionally_blocked_bot(verdict):
            soft_human_ips.add(ip)
    self_host_networks = [ipaddress.ip_network(f"{ip}/32") for ip in SELF_HOST_IPS]
    trusted_networks.extend(
        ipaddress.ip_network(ip) for ip in trusted_ips if ip not in SELF_HOST_IPS
    )
    trusted_networks.extend(
        network for network in allow_networks
        if str(network.network_address) not in SELF_HOST_IPS
    )
    trusted_networks = widen_ipv4_to_slash24(trusted_networks)
    trusted_networks = collapse_mixed(trusted_networks + self_host_networks)

    # Do not subtract trusted ranges from black ranges: subtraction would
    # recreate /25-/32 fragments. Nginx gives trusted_ip.conf priority where
    # widened /24 networks overlap.
    final_blocks = build_final_blocks(raw_blocks, trusted_networks)

    write_network_file(
        deploy_dir / "black_ip.conf", final_blocks, 1,
        [
            "最终统一黑名单：保留原规则，再加入 SG、RU、选定云 ASN、行为候选",
            "IPv4 最细统一为 /24；黑白重叠由 trusted_ip.conf 优先放行",
            "复制到 /etc/nginx/conf.d/black_ip.conf",
        ],
    )
    write_network_file(
        deploy_dir / "trusted_ip.conf", trusted_networks, 1,
        [
            "可信基础设施：IPv4 最细统一为 /24；Google/OpenAI、Bing/Baidu、服务器自身（不含 Yandex）",
            "由 Shield 可信变量使用；可信 IP 绕过 IP、UA、路径和限速规则",
            "复制到 /etc/nginx/conf.d/trusted_ip.conf",
        ],
    )
    generate_nginx(NGINX_SOURCE, deploy_dir / "nginx.conf", exact_uas)
    generate_local_nginx_syntax_test(
        deploy_dir / "nginx.conf", deploy_dir,
        output_dir / "nginx_shield_syntax_test.conf",
    )

    old_match = IPv4Matcher(old_networks)
    final_match = IPv4Matcher(final_blocks)
    trusted_match = IPv4Matcher(trusted_networks)
    ua_re = re.compile(BAD_UA_PATTERN, re.I)
    path_re = re.compile(BAD_PATH_PATTERN, re.I)
    exact_ua_set = set(exact_uas)

    metrics = Counter()
    matched_ips = defaultdict(set)
    per_source = {}
    source_matchers = {
        name: IPv4Matcher(networks) for name, networks in source_networks.items()
    }
    for name in source_matchers:
        per_source[name] = Counter()
    rate_buckets = Counter()
    strong_block_uas = Counter()
    strong_block_paths = Counter()
    strong_block_ips = set()

    for req in iter_requests(logs):
        ip = req["ip"]
        item = stats[ip]
        trusted = trusted_match.contains(ip)
        old = old_match.contains(ip)
        ip_block = final_match.contains(ip)
        ua_block = not trusted and (bool(ua_re.search(req["ua"])) or req["ua"] in exact_ua_set)
        path_block = not trusted and bool(path_re.search(req["target"]))
        good_referrer = analyzer.is_good_referrer(
            analyzer.referrer_host(req["referrer"])
        )
        browser_like = bool(
            re.search(
                r"Mozilla/5\.0|SamanthaDoubao|BytedanceWebview|MicroMessenger|Quark",
                req["ua"],
                re.I,
            )
        )
        referred_human = good_referrer and browser_like
        bot = analyzer.identify_bot(req["ua"])
        preserved_bot = bool(bot and bot[0] in CLAIM_PROTECTED_BOTS)
        ip_exception = referred_human or preserved_bot
        effective_ip_block = ip_block and not ip_exception
        combined = not trusted and (effective_ip_block or ua_block or path_block)
        trusted_and_allowed = bool(
            verdicts[ip].trusted_bot and not intentionally_blocked_bot(verdicts[ip])
        )
        strong_ip = strong_human_or_ai(item) or trusted_and_allowed
        request_human_signal = bool(
            trusted_and_allowed
            or good_referrer
            or analyzer.HUMAN_EVENT_RE.match(req["target"])
            or (analyzer.ADMIN_RE.match(req["target"]) and req["status"] in (200, 302))
            or (bot and bot[1] == "ai_user")
        )
        suspicious = (
            verdicts[ip].level == "建议封禁"
            or item.probes or item.malformed or item.auth_attempts >= 10
            or len(item.php_paths) >= 8
            or ua_block or path_block
        )
        browser_uncertain = (
            combined and not suspicious and not strong_ip
            and bool(re.search(r"mozilla/5\.0", req["ua"], re.I))
        )

        metrics["requests"] += 1
        metrics["actual_444"] += req["status"] == 444
        metrics["old"] += old
        metrics["final_ip"] += effective_ip_block and not trusted
        metrics["referred_human_ip_bypass"] += (
            ip_block and referred_human and not ua_block and not path_block and not trusted
        )
        metrics["preserved_bot_ip_bypass"] += (
            ip_block and preserved_bot and not ua_block and not path_block and not trusted
        )
        metrics["ua"] += ua_block
        metrics["path"] += path_block
        metrics["combined"] += combined
        metrics["incremental"] += combined and not old
        metrics["newly_blocked_success"] += combined and not old and req["status"] != 444
        metrics["released"] += old and not combined
        metrics["trusted_blocked"] += combined and trusted_and_allowed
        metrics["yandex_blocked"] += combined and bool(bot and bot[0] == "Yandex")
        metrics["yandex_verified_blocked"] += (
            combined and bool(bot and bot[0] == "Yandex")
            and intentionally_blocked_bot(verdicts[ip])
        )
        clean_human_signal = request_human_signal and not suspicious
        metrics["clean_human_blocked"] += combined and clean_human_signal and not trusted_and_allowed
        metrics["human_signal_conflict_blocked"] += (
            combined and request_human_signal and suspicious and not trusted_and_allowed
        )
        metrics["uncertain_browser"] += browser_uncertain
        if combined:
            matched_ips["combined"].add(ip)
        if old:
            matched_ips["old"].add(ip)
        if browser_uncertain:
            matched_ips["uncertain"].add(ip)
        if combined and request_human_signal and suspicious and not trusted_and_allowed:
            strong_block_ips.add(ip)
            strong_block_uas[req["ua"]] += 1
            strong_block_paths[req["target"]] += 1
        if not trusted and not item.status[444]:
            rate_buckets[(ip, req["time"].replace(microsecond=0))] += 1
        for name, matcher in source_matchers.items():
            if matcher.contains(ip):
                per_source[name]["requests"] += 1
                per_source[name]["ips_set"] = 0

    # Approximation only: requests over a 20-request one-second burst.
    metrics["rate_limit_upper"] = sum(max(0, count - 20) for count in rate_buckets.values())

    for name, matcher in source_matchers.items():
        ips = [ip for ip in stats if matcher.contains(ip)]
        per_source[name]["ips"] = len(ips)
        per_source[name]["protected_ips_before_exceptions"] = sum(
            verdicts[ip].protected for ip in ips
        )
        per_source[name]["trusted_ips_before_exceptions"] = sum(
            bool(verdicts[ip].trusted_bot and not intentionally_blocked_bot(verdicts[ip]))
            for ip in ips
        )
        per_source[name]["yandex_ips"] = sum(
            intentionally_blocked_bot(verdicts[ip]) for ip in ips
        )
        per_source[name].pop("ips_set", None)

    asn_observed = {}
    for asn, label in BLOCK_ASNS.items():
        ips = [
            ip for ip in stats
            if verdicts[ip].geo.asn == asn
        ]
        asn_observed[str(asn)] = {
            "label": label,
            "ips": len(ips),
            "requests": sum(stats[ip].requests for ip in ips),
            "high_risk_ips": sum(verdicts[ip].level == "建议封禁" for ip in ips),
            "protected_ips": sum(verdicts[ip].protected for ip in ips),
            "actual_444": sum(stats[ip].status[444] for ip in ips),
        }

    black_ipv4_coverage = sum(
        network.num_addresses for network in final_blocks if network.version == 4
    )

    range_dir = deploy_dir / "range_sources"
    range_dir.mkdir(parents=True, exist_ok=True)
    catalog_rows = []
    markdown_rows = []
    for (kind, ident, label), networks in sorted(
        range_catalog.items(), key=lambda item: (item[0][0], item[0][1])
    ):
        source_name = (
            f"国家 {ident}：{label}" if kind == "country"
            else f"ASN AS{ident}：{label}"
        )
        observed = per_source[source_name]
        coverage = sum(x.num_addresses for x in networks if x.version == 4)
        filename = (
            f"country_{ident}.cidr.txt" if kind == "country"
            else f"asn_{ident}.cidr.txt"
        )
        if kind == "country":
            decision_type = "业务地区策略"
            decision_reason = label
        elif int(ident) in POLICY_CLOUD_ASNS:
            decision_type = "云厂商整体策略"
            decision_reason = (
                f"{label}；用户明确接受整体封云，同时日志中保护 IP 占比较低"
            )
        else:
            decision_type = "高风险云/扫描网络"
            decision_reason = (
                f"{label}；日志中高风险扫描、登录爆破或测绘行为集中"
            )
        lines = [
            f"# 类型: {decision_type}",
            f"# 标识: {'国家 '+ident if kind == 'country' else 'AS'+ident}",
            f"# 名称/理由: {label}",
            f"# 选择依据: {decision_reason}",
            "# 数据来源: DB-IP Lite 2026-07（国家/ASN 归属，不是恶意信誉库）",
            f"# 原始 CIDR 数: {len(networks)}",
            f"# IPv4 地址数: {coverage}",
            f"# 日志活跃 IP: {observed['ips']}",
            f"# 日志请求: {observed['requests']}",
            f"# 分析保护 IP（打洞前）: {observed['protected_ips_before_exceptions']}",
            "",
        ]
        lines.extend(str(network) for network in networks)
        (range_dir / filename).write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
        )
        catalog_rows.append({
            "type": kind,
            "id": ident,
            "name_or_reason": label,
            "decision_type": decision_type,
            "decision_reason": decision_reason,
            "raw_cidr_count": len(networks),
            "ipv4_addresses": coverage,
            "observed_ips": observed["ips"],
            "observed_requests": observed["requests"],
            "protected_ips_before_exceptions": observed["protected_ips_before_exceptions"],
            "trusted_ips_before_exceptions": observed["trusted_ips_before_exceptions"],
            "yandex_ips": observed["yandex_ips"],
            "file": f"range_sources/{filename}",
        })
        markdown_rows.append(
            f"| {decision_type} | {'国家 '+ident if kind == 'country' else 'AS'+ident} "
            f"| {label} | {len(networks):,} | {coverage:,} | {observed['ips']:,} "
            f"| {observed['requests']:,} | [{filename}](range_sources/{filename}) |"
        )

    with (deploy_dir / "range_source_summary.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as fh:
        writer = csv.DictWriter(fh, fieldnames=list(catalog_rows[0]))
        writer.writeheader()
        writer.writerows(catalog_rows)

    attribution_rows = []
    for network in sorted(
        final_blocks, key=lambda n: (n.version, int(n.network_address), n.prefixlen)
    ):
        sources = [
            name for name, matcher in source_matchers.items()
            if matcher.overlaps(network)
        ]
        attribution_rows.append([
            str(network), network.num_addresses, "；".join(sources)
        ])
    with (deploy_dir / "final_rule_attribution.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as fh:
        writer = csv.writer(fh)
        writer.writerow(["final_cidr", "address_count", "source_reasons"])
        writer.writerows(attribution_rows)

    source_markdown = f"""# 最终大段封禁来源说明

生成时间：{datetime.now().astimezone().isoformat(timespec='seconds')}

## 怎么理解这些网段

- 国家和 ASN 地址归属来自 DB-IP Lite 2026-07。它只说明地址属于哪个国家或
  网络运营方，不表示其中每个 IP 都是恶意。
- “业务地区策略”是因为网站面向中文用户而主动屏蔽 SG/RU。
- “云厂商整体策略”是你明确接受的风险偏好；腾讯、华为、阿里、UCloud
  并非每个 IP 都在日志中完成了恶意举证。
- “高风险云/扫描网络”则有更强的扫描、爆破或批量探测证据。
- 最终黑白名单的 IPv4 最细统一为 `/24`，不保留 `/25` 至 `/32`。黑白名单
  重叠时由 `trusted_ip.conf` 优先放行，不再通过切割黑名单制造碎片。
- 近期真人信号由 Nginx 运行时 Referer/浏览器规则保护。
- `final_rule_attribution.csv` 可以反查 manbohub 最终黑名单每一条 CIDR 是由哪些策略产生。

| 类型 | 标识 | 名称/理由 | 原始CIDR数 | IPv4地址数 | 日志IP | 日志请求 | 完整清单 |
|---|---|---|---:|---:|---:|---:|---|
{chr(10).join(markdown_rows)}

## 重点云厂商

- AS132203：腾讯云国际。日志中 2,115 个 IP、7,927 次请求，只有 2 个保护 IP；
  大量地址呈一次性或低频轮换，且 3,145 次请求已被旧策略拦截。
- AS45090：腾讯云中国。854 个 IP、1,626 次请求；属于你明确要求整体屏蔽的
  中国大陆云服务器来源。
- AS55990：华为云中国。525 个 IP、873 次请求，其中 762 次已经返回 444；
  这是云厂商业务封禁，不是“525 个 IP 全部已证明恶意”。
- AS45102 / AS37963：阿里云国际和中国。合计 197 个活跃 IP、630 次请求，
  其中至少 15 个 IP 达到高风险。
- AS135377：UCloud。35 个活跃 IP 中 21 个达到高风险，是中国云厂商中
  行为证据最强的一组。
"""
    (deploy_dir / "RANGE_SOURCES.md").write_text(
        source_markdown, encoding="utf-8", newline="\n"
    )

    summary = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "policy": {
            "countries": BLOCK_COUNTRIES,
            "asns": {str(k): v for k, v in BLOCK_ASNS.items()},
            "removed_rules": sorted(REMOVE_RULES),
            "exact_proxy_uas": len(exact_uas),
        },
        "config": {
            "black_rules": len(final_blocks),
            "trusted_rules": len(trusted_networks),
            "runtime_human_exceptions": len(soft_human_ips),
            "runtime_claimed_bot_exceptions": len(claimed_bot_ip_holes),
            "official_360_ranges": len(OFFICIAL_360_NETWORKS),
            "black_ipv4_coverage": black_ipv4_coverage,
        },
        "replay": {
            **metrics,
            "old_unique_ips": len(matched_ips["old"]),
            "combined_unique_ips": len(matched_ips["combined"]),
            "uncertain_browser_unique_ips": len(matched_ips["uncertain"]),
            "human_signal_conflict_unique_ips": len(strong_block_ips),
            "human_signal_conflict_top_uas": strong_block_uas.most_common(10),
            "human_signal_conflict_top_paths": strong_block_paths.most_common(10),
        },
        "sources": {name: dict(values) for name, values in per_source.items()},
        "asn_observed": asn_observed,
    }
    (deploy_dir / "impact.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    install_script = """#!/bin/sh
set -eu

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/etc/nginx/shield-backup-$STAMP"

if [ "$(id -u)" -ne 0 ]; then
    echo "请用 root 运行：sudo sh $0" >&2
    exit 1
fi

mkdir -p "$BACKUP/conf.d"
cp -p /etc/nginx/nginx.conf "$BACKUP/nginx.conf"
if [ -f /etc/nginx/conf.d/black_ip.conf ]; then
    cp -p /etc/nginx/conf.d/black_ip.conf "$BACKUP/conf.d/black_ip.conf"
fi
if [ -f /etc/nginx/conf.d/trusted_ip.conf ]; then
    cp -p /etc/nginx/conf.d/trusted_ip.conf "$BACKUP/conf.d/trusted_ip.conf"
fi

install -m 0644 "$SRC_DIR/nginx.conf" /etc/nginx/nginx.conf
install -m 0644 "$SRC_DIR/black_ip.conf" /etc/nginx/conf.d/black_ip.conf
install -m 0644 "$SRC_DIR/trusted_ip.conf" /etc/nginx/conf.d/trusted_ip.conf

restore() {
    cp -p "$BACKUP/nginx.conf" /etc/nginx/nginx.conf
    if [ -f "$BACKUP/conf.d/black_ip.conf" ]; then
        cp -p "$BACKUP/conf.d/black_ip.conf" /etc/nginx/conf.d/black_ip.conf
    else
        rm -f /etc/nginx/conf.d/black_ip.conf
    fi
    if [ -f "$BACKUP/conf.d/trusted_ip.conf" ]; then
        cp -p "$BACKUP/conf.d/trusted_ip.conf" /etc/nginx/conf.d/trusted_ip.conf
    else
        rm -f /etc/nginx/conf.d/trusted_ip.conf
    fi
}

if ! nginx -t; then
    echo "新配置检查失败，正在恢复 $BACKUP" >&2
    restore
    nginx -t
    exit 1
fi

if ! systemctl reload nginx; then
    echo "reload 失败，正在恢复旧配置" >&2
    restore
    nginx -t
    systemctl reload nginx
    exit 1
fi

echo "部署成功；备份位于 $BACKUP"
"""
    (deploy_dir / "install.sh").write_text(install_script, encoding="utf-8", newline="\n")
    deploy_readme = f"""Nginx Shield 最终部署包
=======================

策略：
- 整体封禁 SG（新加坡）和 RU（俄罗斯）IPv4。
- 整体封禁 {len(BLOCK_ASNS)} 个选定云厂商/扫描 ASN。
- 保留原有 Yandex 网段，并在 UA 层主动封禁 Yandex。
- Google/OpenAI、Bing/Baidu、服务器自身和显式白名单 IPv4 最细统一为 `/24`，
  与黑名单重叠时白名单优先。
- 本日志窗口内的 {len(soft_human_ips)} 个强真人/AI 信号 IP 只作为运行时例外。
- 普通浏览器 UA 不单独封禁；仅封已知扫描 UA、高危路径，并采用 3r/s、burst=20 页面限速。

推荐部署：
1. 把整个 deploy 目录上传到服务器，例如 /root/shield-deploy
2. 执行：
   sudo sh /root/shield-deploy/install.sh
3. 脚本会先备份，再运行 nginx -t；失败会自动恢复，不会 reload 错误配置。

手工部署：
  deploy/nginx.conf                    -> /etc/nginx/nginx.conf
  deploy/black_ip.conf                 -> /etc/nginx/conf.d/black_ip.conf
  deploy/trusted_ip.conf               -> /etc/nginx/conf.d/trusted_ip.conf
  nginx -t && systemctl reload nginx

重要：
  /etc/nginx/conf.d/black_ip.conf 和 trusted_ip.conf 会被替换，但会先备份。
  IP 黑名单继续供原来引用 $blacklisted_ip 的域名使用；
  UA、Referer、路径和限速 Shield 规则仍只在 manbohub.com 两个 server 中引用。

网段来源说明：
  RANGE_SOURCES.md               国家/云厂商选择理由与汇总
  range_source_summary.csv       每个国家/ASN 的 CIDR 数、覆盖地址和日志证据
  range_sources/*.cidr.txt       腾讯、华为、阿里等各自完整原始 CIDR 清单
  final_rule_attribution.csv     manbohub 最终黑名单每条规则的来源反查表

本地日志回放：
- 最终组合命中：{metrics['combined']} / {metrics['requests']}（{pct(metrics['combined'], metrics['requests'])}）
- 相对原黑名单新增：{metrics['incremental']} 请求
- 已验证搜索/AI 误伤：{metrics['trusted_blocked']} 请求
- 主动封禁已验证 Yandex：{metrics['yandex_blocked']} 请求
- 无恶意证据冲突的强真人信号误伤：{metrics['clean_human_blocked']} 请求
- 普通浏览器但无充分行为证据的误伤上界：{metrics['uncertain_browser']} 请求 /
  {len(matched_ips['uncertain'])} IP（其中大量是代理池，不能理解为都是真人）

注意：国家/ASN 和动态 IP 会变化，建议每周重新运行分析器和 build_final_policy.py。
"""
    (deploy_dir / "README.txt").write_text(deploy_readme, encoding="utf-8", newline="\n")

    source_rows = []
    for name, values in per_source.items():
        source_rows.append([
            html.escape(name),
            f"{values['ips']:,}",
            f"{values['requests']:,}",
            f"{values['trusted_ips_before_exceptions']:,}",
            f"{values['yandex_ips']:,}",
            f"{values['protected_ips_before_exceptions']:,}",
        ])
    asn_rows = []
    for asn, label in BLOCK_ASNS.items():
        observed = asn_observed[str(asn)]
        asn_rows.append([
            f"AS{asn}", html.escape(label), f"{observed['ips']:,}",
            f"{observed['requests']:,}", f"{observed['high_risk_ips']:,}",
            f"{observed['protected_ips']:,}", f"{observed['actual_444']:,}",
        ])
    report = f"""<!doctype html><html lang=zh-CN><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>最终 Nginx Shield 部署方案</title>
<style>
body{{margin:0;background:#f5f7fb;color:#172033;font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif}}main{{max-width:1250px;margin:auto;padding:24px}}
.hero{{background:linear-gradient(135deg,#172554,#1d4ed8);color:white;padding:26px;border-radius:14px}}h1{{margin:0}}section{{background:white;border:1px solid #e5e9f0;border-radius:12px;padding:18px;margin:14px 0}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:10px}}.card{{background:white;border:1px solid #e5e9f0;border-radius:10px;padding:14px}}.v{{font-size:25px;font-weight:750}}
.muted{{color:#667085}}.warn{{border-left:4px solid #f79009;background:#fffaeb;padding:10px}}.good{{border-left:4px solid #12b76a;background:#ecfdf3;padding:10px}}
.scroll{{overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{padding:8px 10px;border-bottom:1px solid #e5e9f0;text-align:left;white-space:nowrap}}th{{background:#f8fafc}}
code{{font-family:Consolas,monospace}}@media(max-width:700px){{main{{padding:10px}}}}
</style></head><body><main>
<div class=hero><h1>最终 Nginx Shield 部署方案</h1><div>偏激进策略 · 已对 {meta['parsed']:,} 条请求进行日志回放</div></div>
<div class=cards>
<div class=card><div>现有规则命中</div><div class=v>{metrics['old']:,}</div><div>{pct(metrics['old'],metrics['requests'])}</div></div>
<div class=card><div>最终组合命中</div><div class=v>{metrics['combined']:,}</div><div>{pct(metrics['combined'],metrics['requests'])}</div></div>
<div class=card><div>新增拦截请求</div><div class=v>{metrics['incremental']:,}</div><div>相对原黑名单</div></div>
<div class=card><div>最终命中 IP</div><div class=v>{len(matched_ips['combined']):,}</div></div>
<div class=card><div>已验证爬虫误伤</div><div class=v>{metrics['trusted_blocked']:,}</div><div>回放结果</div></div>
<div class=card><div>无冲突真人信号误伤</div><div class=v>{metrics['clean_human_blocked']:,}</div><div>回放结果</div></div>
</div>
<section><h2>最终决定</h2>
<ul>
<li>保留原黑名单和 Yandex 网段；Yandex 是明确业务封禁对象，不计作误伤。</li>
<li>整体封禁新加坡、俄罗斯 IPv4，以及腾讯云、阿里云、华为云中国、UCloud、DigitalOcean、Oracle Cloud 和高危扫描 ASN。</li>
<li>IPv4 黑白名单最细统一为 `/24`；Google/OpenAI、Bing/Baidu、服务器自身和显式白名单与黑名单重叠时由白名单优先，不再切割黑名单；本窗口内有强真人/AI 信号的 {len(soft_human_ips):,} 个 IP 由运行时规则保护；Yandex 不进入白名单。</li>
<li>不凭普通 Chrome/Safari UA 全局封禁；仅封商业 SEO 爬虫、脚本客户端和高危探测路径。</li>
<li>WordPress 页面采用每 IP 3 请求/秒、burst 20 的宽松限速；可信 IP 不参与限速。</li>
</ul></section>
<section><h2>回放效果与误伤边界</h2>
<p class=good>本日志窗口中，最终组合规则命中 {metrics['combined']:,} / {metrics['requests']:,} 次请求（{pct(metrics['combined'],metrics['requests'])}），
比原黑名单多命中 {metrics['incremental']:,} 次；已验证搜索/AI 误伤 {metrics['trusted_blocked']} 次，无恶意证据冲突的真人信号误伤 {metrics['clean_human_blocked']} 次。</p>
<p>其中主动拦截已验证 Yandex 请求 {metrics['yandex_blocked']:,} 次；这是中文站的业务选择，不计入搜索引擎误伤。</p>
<p>另有 {metrics['human_signal_conflict_blocked']:,} 次请求虽然带引荐、后台或统计信号，但同一请求/IP 同时命中扫描 UA、高危路径或高风险行为，按“恶意证据优先”拦截；它们不计入干净真人误伤。</p>
<p class=warn>仍有 {metrics['uncertain_browser']:,} 次、涉及 {len(matched_ips['uncertain']):,} 个 IP 的普通浏览器 UA 请求缺少足够行为证据。
它们是“潜在真人误伤上界”，并不表示都是真人；其中大量来自新加坡、俄罗斯或云 ASN、每 IP 请求很少，形态更像代理池。未来新出现的直连云/VPN 真人仍可能被拦，但带可信搜索或大模型引荐的浏览器访问会实时绕过大段 IP 黑名单。</p>
<p>限速规则的粗略一秒突发上界为 {metrics['rate_limit_upper']:,} 次请求；它依赖 Nginx 漏桶状态，因此未计入上面的确定命中量。</p>
</section>
<section><h2>各来源在加白前的覆盖</h2>
{html_table(['来源','活跃IP','请求','保留可信IP','主动封Yandex IP','保护IP'],source_rows)}
</section>
<section><h2>整体封禁的 ASN</h2>{html_table(['ASN','理由','活跃IP','请求','高风险IP','保护IP','原444'],asn_rows)}</section>
<section><h2>部署文件</h2>
<ol><li><code>deploy/nginx.conf</code> → <code>/etc/nginx/nginx.conf</code></li>
<li><code>deploy/black_ip.conf</code> → <code>/etc/nginx/conf.d/black_ip.conf</code></li>
<li><code>deploy/trusted_ip.conf</code> → <code>/etc/nginx/conf.d/trusted_ip.conf</code></li>
<li>执行 <code>nginx -t</code>，成功后再执行 <code>nginx -s reload</code>。</li></ol>
<p><strong><code>black_ip.conf</code> 和 <code>trusted_ip.conf</code> 使用最终统一名称；
IP 黑名单会继续作用于原来引用 <code>$blacklisted_ip</code> 的域名，UA、Referer、路径和限速规则只作用于
<code>manbohub.com / www.manbohub.com</code>。</strong></p>
<p><code>RANGE_SOURCES.md</code> 说明腾讯、华为、阿里等每个来源；
<code>range_sources/</code> 保存各自完整 CIDR；
<code>final_rule_attribution.csv</code> 可反查最终每一条规则。</p>
<p class=muted>先备份服务器上的三个原文件。最终黑名单共 {len(final_blocks):,} 条，覆盖约 {black_ipv4_coverage:,} 个 IPv4；可信规则 {len(trusted_networks):,} 条。</p>
</section></main></body></html>"""
    (deploy_dir / "final_policy_report.html").write_text(report, encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"部署包: {deploy_dir}")


if __name__ == "__main__":
    main()
