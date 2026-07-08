#!/usr/bin/env python3
"""Evaluate regional blocking candidates against the site's finite log sample.

This script is deliberately advisory: it never adds a country, province or city
to the deployable blacklist. City data comes from DB-IP City Lite and is only an
approximate IP geolocation, especially for VPN, mobile and cloud traffic.
"""

from __future__ import annotations

import csv
import gzip
import html
import ipaddress
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from . import build_final_policy as policy
    from . import ip_shield_analyzer as analyzer
    from .paths import ALLOWLIST_FILE, BLACKLIST_FILE, DATA_DIR, LOG_DIR, OUTPUT_DIR
except ImportError:
    import build_final_policy as policy
    import ip_shield_analyzer as analyzer
    from paths import ALLOWLIST_FILE, BLACKLIST_FILE, DATA_DIR, LOG_DIR, OUTPUT_DIR


def locate_observed_ips(city_db: Path, ips: list[str]) -> dict[str, dict[str, str]]:
    wanted = sorted(
        (int(ipaddress.IPv4Address(ip)), ip)
        for ip in ips
        if ipaddress.ip_address(ip).version == 4
    )
    result: dict[str, dict[str, str]] = {}
    pos = 0
    with gzip.open(city_db, "rt", encoding="utf-8", newline="") as fh:
        for row in csv.reader(fh):
            if pos >= len(wanted):
                break
            if len(row) < 6:
                continue
            start = int(ipaddress.IPv4Address(row[0]))
            end = int(ipaddress.IPv4Address(row[1]))
            while pos < len(wanted) and wanted[pos][0] < start:
                pos += 1
            while pos < len(wanted) and wanted[pos][0] <= end:
                _, ip = wanted[pos]
                result[ip] = {
                    "continent": row[2],
                    "country": row[3],
                    "state": row[4],
                    "city": row[5],
                }
                pos += 1
    return result


def protected_signal(item: analyzer.IPStats, verdict: analyzer.Verdict) -> bool:
    return bool(
        (verdict.trusted_bot and not policy.intentionally_blocked_bot(verdict))
        or policy.strong_human_or_ai(item)
        or (
            set(item.bot_claims).intersection(policy.CLAIM_PROTECTED_BOTS)
            and not policy.hard_bad(item)
        )
    )


def summarize(
    ips: list[str],
    stats: dict[str, analyzer.IPStats],
    verdicts: dict[str, analyzer.Verdict],
) -> dict[str, int | float]:
    items = [stats[ip] for ip in ips]
    requests = sum(item.requests for item in items)
    direct = sum(item.direct for item in items)
    return {
        "ips": len(items),
        "requests": requests,
        "actual_444": sum(item.status[444] for item in items),
        "high_risk_ips": sum(verdicts[item.ip].level == "建议封禁" for item in items),
        "hard_bad_ips": sum(policy.hard_bad(item) for item in items),
        "protected_signal_ips": sum(
            protected_signal(item, verdicts[item.ip]) for item in items
        ),
        "search_claim_ips": sum("search" in item.bot_kinds for item in items),
        "ai_signal_ips": sum(
            any(kind.startswith("ai_") for kind in item.bot_kinds)
            or any(
                domain in host
                for host in item.good_referrers
                for domain in (
                    "doubao.com", "chatgpt.com", "deepseek.com", "kimi.com",
                    "yuanbao.tencent.com", "qianwen.com", "tongyi.com",
                    "perplexity.ai", "claude.ai", "gemini.google.com",
                )
            )
            for item in items
        ),
        "repeat_3day_ips": sum(len(item.days) >= 3 for item in items),
        "direct_ratio": round(direct / requests, 4) if requests else 0.0,
    }


def make_table(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join(f"<th>{html.escape(str(value))}</th>" for value in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<div class=scroll><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def main() -> None:
    data_dir = DATA_DIR
    output_dir = OUTPUT_DIR / "deploy"
    output_dir.mkdir(parents=True, exist_ok=True)
    city_databases = sorted(data_dir.glob("dbip-city-lite-*.csv.gz"))
    if not city_databases:
        raise FileNotFoundError(f"missing city database under: {data_dir}")
    city_db = city_databases[-1]

    logs = analyzer.iter_log_files(LOG_DIR)
    stats, meta, _ = analyzer.parse_logs(logs)
    intel = analyzer.Intelligence(data_dir)
    intel.refresh_official_ranges(False)
    intel.refresh_dbip(False)
    intel.verify_ptr_claims(analyzer.ptr_jobs(stats), False)
    old_rules, invalid = analyzer.parse_blacklist(BLACKLIST_FILE)
    if invalid:
        raise RuntimeError("existing blacklist contains invalid lines")
    old_networks = [network for _, network in old_rules]
    allow_networks, _ = analyzer.parse_allowlist(ALLOWLIST_FILE)
    verdicts = {
        ip: analyzer.score_ip(item, intel, len(meta["daily"]), old_networks, allow_networks)
        for ip, item in stats.items()
    }
    locations = locate_observed_ips(city_db, list(stats))

    region_members: dict[str, list[str]] = defaultdict(list)
    country_members: dict[str, list[str]] = defaultdict(list)
    for name in (
        "CN / Jiangsu",
        "CN / Jiangsu / Yancheng",
        "SG / whole country",
        "RU / whole country",
    ):
        region_members[name]
    for ip in stats:
        location = locations.get(ip, {})
        country = location.get("country") or verdicts[ip].geo.country or "ZZ"
        state = location.get("state", "")
        city = location.get("city", "")
        country_members[country].append(ip)
        if country == "CN" and state.lower() == "jiangsu":
            region_members["CN / Jiangsu"].append(ip)
        if (
            country == "CN"
            and state.lower() == "jiangsu"
            and city.lower().startswith("yancheng")
        ):
            region_members["CN / Jiangsu / Yancheng"].append(ip)
        if country == "SG":
            region_members["SG / whole country"].append(ip)
        if country == "RU":
            region_members["RU / whole country"].append(ip)

    regions = {
        name: summarize(ips, stats, verdicts)
        for name, ips in sorted(region_members.items())
    }
    countries = {
        country: summarize(ips, stats, verdicts)
        for country, ips in country_members.items()
    }

    # Log-derived candidates only. They are not global claims about a country.
    small_country_candidates = []
    for country, values in countries.items():
        if country in {"CN", "SG", "RU", "US", "ZZ"}:
            continue
        ips = int(values["ips"])
        high = int(values["high_risk_ips"])
        protected = int(values["protected_signal_ips"])
        if (
            ips >= 5
            and int(values["requests"]) >= 20
            and protected == 0
            and int(values["search_claim_ips"]) == 0
            and (high / ips >= 0.5 or int(values["actual_444"]) / int(values["requests"]) >= 0.5)
        ):
            small_country_candidates.append((country, values))
    small_country_candidates.sort(
        key=lambda row: (
            row[1]["high_risk_ips"] / row[1]["ips"],
            row[1]["requests"],
        ),
        reverse=True,
    )

    payload = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "sample": {
            "requests": meta["parsed"],
            "unique_ips": len(stats),
            "days": sorted(meta["daily"]),
            "warning": (
                "These are recent manbohub logs, not a representative sample of the "
                "global Internet. Geolocation is approximate and candidates require "
                "an explicit business decision."
            ),
        },
        "regions": regions,
        "small_country_candidates": [
            {"country": country, **values}
            for country, values in small_country_candidates
        ],
    }
    (output_dir / "region_candidate_analysis.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with (output_dir / "region_candidate_analysis.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "region", "ips", "requests", "actual_444", "high_risk_ips",
            "hard_bad_ips", "protected_signal_ips", "search_claim_ips",
            "ai_signal_ips", "repeat_3day_ips", "direct_ratio",
        ])
        for name, values in regions.items():
            writer.writerow([name, *values.values()])
        for country, values in small_country_candidates:
            writer.writerow([f"candidate country {country}", *values.values()])

    region_rows = [
        [
            name, values["ips"], values["requests"], values["actual_444"],
            values["high_risk_ips"], values["hard_bad_ips"],
            values["protected_signal_ips"], values["search_claim_ips"],
            values["ai_signal_ips"], values["repeat_3day_ips"],
            f"{values['direct_ratio']:.1%}",
        ]
        for name, values in regions.items()
    ]
    country_rows = [
        [
            country, values["ips"], values["requests"], values["actual_444"],
            values["high_risk_ips"], values["protected_signal_ips"],
            values["repeat_3day_ips"], f"{values['direct_ratio']:.1%}",
        ]
        for country, values in small_country_candidates
    ]
    report = f"""<!doctype html><html lang=zh-CN><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>地域整体封禁候选评估</title><style>
body{{margin:0;background:#f5f7fb;color:#172033;font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif}}
main{{max-width:1150px;margin:auto;padding:24px}}section{{background:white;border:1px solid #e5e9f0;border-radius:12px;padding:18px;margin:14px 0}}
h1{{margin-bottom:4px}}.warn{{border-left:4px solid #f79009;background:#fffaeb;padding:12px}}
.good{{border-left:4px solid #12b76a;background:#ecfdf3;padding:12px}}.scroll{{overflow:auto}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:8px 10px;border-bottom:1px solid #e5e9f0;text-align:left;white-space:nowrap}}
th{{background:#f8fafc}}code{{font-family:Consolas,monospace}}
</style></head><body><main><h1>地域整体封禁候选评估</h1>
<div>基于 {meta['parsed']:,} 条近期 manbohub 请求、{len(stats):,} 个 IP；生成于 {html.escape(payload['generated_at'])}</div>
<section><h2>先说边界</h2><p class=warn>这批日志只能证明“这些来源近期在你的网站上做了什么”，不能代表全网，也不能证明一个城市或国家的所有 IP 都是爬虫。DB-IP 城市定位同样存在 VPN、移动网络和云出口误差。因此本报告不自动生成任何新增地域封禁规则。</p></section>
<section><h2>指定地域</h2>
{make_table(['地域','IP','请求','已444','高风险IP','硬攻击IP','保护信号IP','搜索爬虫IP','AI信号IP','≥3天IP','直连占比'], region_rows)}
</section>
<section><h2>仅由本日志筛出的其他国家候选</h2>
<p>门槛：至少 5 个 IP、20 次请求、无搜索/AI/真人保护信号，并且高风险 IP ≥50% 或既有 444 请求 ≥50%。即使入选，也建议先观察或按 ASN 封禁，不直接解释成“全国都是垃圾”。</p>
{make_table(['国家代码','IP','请求','已444','高风险IP','保护信号IP','≥3天IP','直连占比'], country_rows)}
</section>
<section><h2>决策建议</h2><ul>
<li>盐城：只有在样本 IP 足够多、保护信号为 0、且风险跨多个 ASN 持续出现时，才考虑整市；否则优先封云 ASN 或明确网段。</li>
<li>新加坡：云主机和代理出口密度高，但也会承载 PetalBot、AI 抓取和真人 VPN。若接受这类误伤，可以整国；部署文件会对本窗口中已识别的搜索/AI IP 打洞。</li>
<li>小国：样本不足时不做整国结论。优先选择“跨日重复 + 高风险行为 + 云 ASN”组合。</li>
</ul></section></main></body></html>"""
    (output_dir / "regional_risk_report.html").write_text(report, encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
