#!/usr/bin/env python3
"""Build the final UTF-8 HTML handoff report from generated policy artifacts."""

from __future__ import annotations

import html
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

try:
    from . import build_final_policy as policy
    from . import ip_shield_analyzer as analyzer
    from .paths import LOG_DIR, OUTPUT_DIR
except ImportError:
    import build_final_policy as policy
    import ip_shield_analyzer as analyzer
    from paths import LOG_DIR, OUTPUT_DIR


BOT_NAMES = [
    "Baidu", "360", "Sogou", "Shenma/Yisou", "Bytespider",
    "ByteDance crawler", "Doubao user", "PetalBot", "Yandex",
]


def pct(value: int, total: int) -> str:
    return f"{value / total * 100:.1f}%" if total else "0.0%"


def table(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join(f"<th>{html.escape(str(value))}</th>" for value in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<div class=scroll><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def read_matcher(path: Path) -> policy.IPv4Matcher:
    networks = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"([^\s#]+)\s+1;", line)
        if match:
            networks.append(ipaddress.ip_network(match.group(1)))
    return policy.IPv4Matcher(networks)


def request_blocked(
    request: dict[str, object],
    black: policy.IPv4Matcher,
    trusted: policy.IPv4Matcher,
) -> bool:
    ip = str(request["ip"])
    if trusted.contains(ip):
        return False
    ua = str(request["ua"])
    target = str(request["target"])
    bot = analyzer.identify_bot(ua)
    preserved_bot = bool(bot and bot[0] in policy.CLAIM_PROTECTED_BOTS)
    good_referrer = analyzer.is_good_referrer(
        analyzer.referrer_host(str(request["referrer"]))
    )
    browser_like = bool(re.search(
        r"Mozilla/5\.0|SamanthaDoubao|BytedanceWebview|MicroMessenger|Quark",
        ua,
        re.I,
    ))
    ip_exception = preserved_bot or (good_referrer and browser_like)
    return bool(
        (black.contains(ip) and not ip_exception)
        or re.search(policy.BAD_UA_PATTERN, ua, re.I)
        or re.search(policy.BAD_PATH_PATTERN, target, re.I)
    )


def main() -> None:
    deploy = OUTPUT_DIR / "deploy"
    impact = json.loads((deploy / "impact.json").read_text(encoding="utf-8"))
    regional = json.loads(
        (deploy / "region_candidate_analysis.json").read_text(encoding="utf-8")
    )
    logs = analyzer.iter_log_files(LOG_DIR)
    stats, meta, _ = analyzer.parse_logs(logs)
    black = read_matcher(deploy / "black_ip.conf")
    trusted = read_matcher(deploy / "trusted_ip.conf")

    bot_counts = {
        name: {"ips": set(), "requests": 0, "blocked": 0}
        for name in BOT_NAMES
    }
    referrals = Counter()
    for request in policy.iter_requests(logs):
        bot = analyzer.identify_bot(str(request["ua"]))
        blocked = request_blocked(request, black, trusted)
        if bot and bot[0] in bot_counts:
            item = bot_counts[bot[0]]
            item["ips"].add(str(request["ip"]))
            item["requests"] += 1
            item["blocked"] += blocked
        host = analyzer.referrer_host(str(request["referrer"]))
        if analyzer.is_good_referrer(host):
            referrals[host] += 1

    bot_rows = []
    labels = {
        "Baidu": "百度",
        "360": "360",
        "Sogou": "搜狗",
        "Shenma/Yisou": "神马/Yisou",
        "Bytespider": "字节 Bytespider",
        "ByteDance crawler": "字节其他抓取",
        "Doubao user": "豆包用户访问",
        "PetalBot": "华为 PetalBot",
        "Yandex": "Yandex（主动封禁）",
    }
    for name in BOT_NAMES:
        item = bot_counts[name]
        bot_rows.append([
            labels[name], len(item["ips"]), item["requests"], item["blocked"],
            "业务主动封禁" if name == "Yandex" else (
                "无攻击证据时保留；仍限速" if name in policy.CLAIM_PROTECTED_BOTS
                else "观察"
            ),
        ])

    region_rows = []
    decisions = {
        "CN / Jiangsu": "不整省封：340 个搜索爬虫 IP，误伤明显",
        "CN / Jiangsu / Yancheng": "不封：本样本 0 个定位 IP，无证据",
        "SG / whole country": "当前启用整国封禁；搜索/AI与引荐入口例外",
        "RU / whole country": "启用：非目标地区，Yandex 也按业务要求封禁",
    }
    for name, values in regional["regions"].items():
        region_rows.append([
            name, values["ips"], values["requests"], values["actual_444"],
            values["high_risk_ips"], values["protected_signal_ips"],
            values["search_claim_ips"], values["ai_signal_ips"],
            decisions.get(name, "观察"),
        ])

    country_rows = [
        [
            row["country"], row["ips"], row["requests"], row["high_risk_ips"],
            row["hard_bad_ips"], row["actual_444"],
            "不整国封；优先封已识别的云/扫描 ASN",
        ]
        for row in regional["small_country_candidates"]
    ]
    asn_rows = []
    for asn, observed in impact["asn_observed"].items():
        if int(observed["requests"]) < 200:
            continue
        asn_rows.append([
            f"AS{asn}", observed["label"], observed["ips"], observed["requests"],
            observed["high_risk_ips"], observed["protected_ips"],
            observed["actual_444"],
        ])
    asn_rows.sort(key=lambda row: int(row[3]), reverse=True)

    replay = impact["replay"]
    config = impact["config"]
    report = f"""<!doctype html><html lang=zh-CN><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>manbohub Nginx Shield 最终分析与部署报告</title><style>
body{{margin:0;background:#f4f7fb;color:#172033;font:14px/1.65 system-ui,"Microsoft YaHei",sans-serif}}
main{{max-width:1240px;margin:auto;padding:24px}}.hero{{color:#fff;background:linear-gradient(135deg,#172554,#1d4ed8);border-radius:15px;padding:26px}}
h1{{margin:0 0 4px}}section{{background:#fff;border:1px solid #e4e9f1;border-radius:12px;padding:18px;margin:14px 0}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:14px 0}}
.card{{background:#fff;border:1px solid #e4e9f1;border-radius:11px;padding:14px}}.v{{font-size:25px;font-weight:760}}
.warn{{border-left:4px solid #f79009;background:#fffaeb;padding:11px}}.good{{border-left:4px solid #12b76a;background:#ecfdf3;padding:11px}}
.scroll{{overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{padding:8px 10px;border-bottom:1px solid #e4e9f1;text-align:left;white-space:nowrap}}th{{background:#f8fafc}}
code{{font-family:Consolas,monospace}}a{{color:#175cd3}}.muted{{color:#667085}}
</style></head><body><main>
<div class=hero><h1>manbohub Nginx Shield 最终分析与部署报告</h1>
<div>统一 black_ip.conf / trusted_ip.conf · {meta['parsed']:,} 条近期请求 · {len(stats):,} 个 IP · {len(meta['daily'])} 天</div></div>
<div class=cards>
<div class=card><div>预计组合拦截</div><div class=v>{replay['combined']:,}</div><div>{pct(replay['combined'], replay['requests'])}</div></div>
<div class=card><div>相对旧名单新增</div><div class=v>{replay['incremental']:,}</div></div>
<div class=card><div>最终 CIDR</div><div class=v>{config['black_rules']:,}</div></div>
<div class=card><div>搜索/AI引荐放行</div><div class=v>{replay['referred_human_ip_bypass']:,}</div></div>
<div class=card><div>确认强信号误拦</div><div class=v>{replay['clean_human_blocked']:,}</div></div>
</div>
<section><h2>最终结论</h2><ul>
<li>保留新加坡、俄罗斯整国策略和 20 个指定云/扫描 ASN；Yandex 明确封禁。</li>
<li>百度、360、搜狗、神马、PetalBot、Bytespider、豆包等不再因国家/云网段直接被拦；攻击路径和明确坏 UA 仍优先拦截，未强信任的爬虫仍受 3r/s、burst=20 限速。</li>
<li>百度/必应继续用 FCrDNS，Google/OpenAI 用官方网段，360 使用官方公布的 6 个 /24；缺少可靠官方 IP 清单的服务只做受限 UA 例外和本窗口 /32 打洞。</li>
<li>不再把普通 Chrome/Android UA 当作代理池全局封禁键；未来带可信搜索/大模型 Referer 的浏览器访问可实时绕过大段 IP 黑名单。</li>
<li>统一 IP 黑名单也供原来引用 <code>$blacklisted_ip</code> 的域名使用；UA、Referer、路径和限速规则仍只在 manbohub 两个 server 块引用。</li>
</ul></section>
<section><h2>中文搜索、AI 与引荐保护回放</h2>
{table(['来源','IP','请求','预计拦截','策略'], bot_rows)}
<p>可信引荐样本：{html.escape(', '.join(f'{host}={count}' for host, count in referrals.most_common(15)))}</p>
<p class=warn>UA 和 Referer 都可伪造，因此“保留爬虫/引荐”只绕过 IP 大段，不能绕过恶意路径、已知坏 UA 和限速。这是减少误伤与避免伪装通行之间的折中。</p>
</section>
<section><h2>地域候选：不把近期站内样本冒充全网结论</h2>
<p class=warn>DB-IP 城市定位对 VPN、移动网络和云出口并非绝对准确。盐城在本批日志中定位到 0 个 IP，无法确认“盐城整体都是垃圾”，所以未生成盐城封禁；江苏整体更不能封，因为 570 个 IP 中有 340 个搜索爬虫 IP。</p>
{table(['地域','IP','请求','已444','高风险IP','保护信号IP','搜索IP','AI信号IP','决定'], region_rows)}
<h3>小国候选</h3>{table(['国家','IP','请求','高风险IP','硬攻击IP','已444','决定'], country_rows)}
<p>AD 的高流量主要已归到 AS48090 TECHOFF 扫描网络，封 ASN 比封整个安道尔更有依据；HU 样本只有 6 个 IP，不做国家级结论。</p>
</section>
<section><h2>云厂商/扫描 ASN 的站内证据</h2>
{table(['ASN','名称','活跃IP','请求','高风险IP','保护信号IP','已444'], asn_rows)}
<p>这些大段的归属依据是 DB-IP Lite 2026-07 ASN 库；“整厂封禁”是你已接受的业务风险偏好，并不等于其中每个 IP 都被单独证明恶意。完整原始 CIDR、地址数量和最终规则归因见 <code>RANGE_SOURCES.md</code>、<code>range_sources/</code> 与 <code>final_rule_attribution.csv</code>。</p>
</section>
<section><h2>性能结论</h2>
<p class=good>用 Ubuntu Nginx 1.24.0 对最终配置和 {config['black_rules']:,} 条 CIDR 做了 5 次 <code>nginx -t</code>：每次 0.05–0.06 秒，最大常驻内存约 18.1 MB，语法检查通过。这个数量级不会成为请求性能瓶颈。</p>
<p>Nginx 的 <code>geo</code> 按 IP/CIDR 做查找，<code>map</code> 变量按需计算；真正更显眼的固定内存是两个限速共享区。本配置已从 20m+20m 收到 10m+10m，约可容纳至少约 8 万个限速状态和约 16 万个连接状态，远高于本样本 17,737 个 IP。</p>
<p class=muted>加载测试反映语法、构建数据结构和进程 RSS，不等于完整线上压测；但 WordPress/PHP、TLS 和网络时延通常远大于一次内存中的 IP 查找。</p>
</section>
<section><h2>误伤边界</h2>
<ul><li>本窗口中“确认的搜索/AI/真人强信号且无恶意证据”误拦：{replay['clean_human_blocked']:,} 次。</li>
<li>普通浏览器 UA、无充分行为标签的最坏上界：{replay['uncertain_browser']:,} 次（{pct(replay['uncertain_browser'], replay['requests'])}）。这不是估计真人数，其中大量是一请求代理池；没有可靠标签时不能把它包装成精确误伤率。</li>
<li>新加坡的直连真人/VPN、没有 Referer 的隐私浏览器仍可能被挡；这是整国封禁不可消除的代价。搜索/AI 引荐浏览器和本窗口识别的服务 IP 已例外。</li></ul>
</section>
<section><h2>部署与复核</h2><ol>
<li>上传整个 <code>analysis_output/deploy</code> 目录。</li>
<li>运行 <code>sudo sh install.sh</code>；脚本先备份，再执行 <code>nginx -t</code>，失败会恢复。</li>
<li>部署后一周检查 444/429、搜索站长平台抓取异常和来自 AI Referer 的访问；每周重跑分析，更新动态 IP。</li>
</ol><p><strong>正式部署文件为 <code>/etc/nginx/conf.d/black_ip.conf</code> 和 <code>/etc/nginx/conf.d/trusted_ip.conf</code>。</strong>安装脚本会先备份旧文件，测试失败自动恢复。</p>
</section>
<section><h2>主要官方依据</h2><ul>
<li><a href="https://nginx.org/en/docs/http/ngx_http_geo_module.html">Nginx geo 模块</a>、<a href="https://nginx.org/en/docs/http/ngx_http_map_module.html">map 模块</a>、<a href="https://nginx.org/en/docs/http/ngx_http_limit_req_module.html">limit_req 模块</a></li>
<li><a href="https://www.so.com/help/spider_ip.html">360 官方蜘蛛 UA 与 IP 段</a></li>
<li><a href="https://ziyuan.baidu.com/college/articleinfo?id=1295">百度官方蜘蛛 DNS 验证说明</a></li>
<li><a href="https://zhanzhang.sm.cn/">神马站长平台</a></li>
</ul></section>
</main></body></html>"""
    (deploy / "FINAL_REPORT.html").write_text(report, encoding="utf-8")
    print(deploy / "FINAL_REPORT.html")


if __name__ == "__main__":
    main()
