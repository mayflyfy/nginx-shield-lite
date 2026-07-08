# 离线威胁分析 DLC

该 DLC 根据本地 Nginx 日志生成审计报告、候选名单和部署包。分析器本身不修改
生产 `black_ip.conf`；生成策略也只写入 `var/analysis_output`。

## 数据位置

默认目录均位于 Git 忽略的 `var/`：

```text
var/logs/                       access.log*
var/black_ip.conf               当前真实黑名单
var/analysis_allowlist.txt      本地保护 IP/CIDR
var/nginx.conf                  生成部署包时使用的实际配置模板
var/analysis_data/              DB-IP、官方网段和 PTR 缓存
var/analysis_output/            HTML、CSV、候选和部署包
```

不要把服务器 IP、管理员出口 IP、日志、数据库或生产配置写进说明文件。
保护名单模板位于 `config/analysis_allowlist.example.txt`。

路径可以用 `NSL_VAR_DIR` 整体覆盖，也可以用
`NSL_ANALYSIS_LOG_DIR`、`NSL_ANALYSIS_DATA_DIR`、
`NSL_ANALYSIS_OUTPUT_DIR`、`NSL_ANALYSIS_BLACKLIST`、
`NSL_ANALYSIS_ALLOWLIST` 和 `NSL_ANALYSIS_NGINX` 分别覆盖。

## 运行

在项目根目录执行：

```powershell
python -m dlc.threat_analysis.ip_shield_analyzer
python -m dlc.threat_analysis.ip_shield_analyzer --offline
```

分析器需要 `requests`。首次联网运行会下载 DB-IP Lite 国家/ASN 数据并缓存官方
搜索/AI 网段；Bing、Baidu、Yandex 声明会进行 FCrDNS 验证。

主要输出包括：

- `ip_analysis_report.html`
- `candidate_block_ips.conf`
- `candidate_block_networks.conf`
- `candidate_unblock_review.txt`
- `protected_ips.tsv`
- `candidate_bad_ua_map.conf`
- `summary.json` 与明细 CSV

## 生成部署包

```powershell
python -m dlc.threat_analysis.build_final_policy
```

部署包位于 `var/analysis_output/deploy`。生成器会读取 `var/nginx.conf`，但不会
覆盖它。部署脚本先备份，运行 `nginx -t`，只有成功后才 reload，失败时恢复。

区域与国家候选默认只是人工复核材料，不被生成的 Nginx 配置自动 include：

```powershell
python -m dlc.threat_analysis.build_region_block_candidates
python -m dlc.threat_analysis.region_candidate_analysis
python -m dlc.threat_analysis.build_consolidated_report
```

## 安全顺序

1. 先核对搜索、AI、引荐和真人保护层。
2. 单 IP 候选观察 1–3 天；`/24` 至少观察 3–7 天。
3. 通用浏览器 UA 不得成为封禁键。
4. 国家、城市、云厂商和 ASN 必须有来源、数据日期、站内命中和误伤评估。
5. 候选确认后再生成正式策略，部署前用目标 Nginx 版本执行 `nginx -t`。

IP 国家和 ASN 数据来自 [DB-IP Lite](https://db-ip.com/db/lite.php)，采用
CC BY 4.0。免费地理库存在误差，归属信息不得单独作为“恶意”证明。
