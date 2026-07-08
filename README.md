# Nginx Shield Lite

轻量 Nginx 日志分析与 IP 黑白名单管理工具，适合放在低性能服务器上使用。主要计算负载在浏览器端完成，后端只提供日志、名单和 Nginx 操作接口。

![界面预览](preview.jpg)

## 功能

- 查看 Nginx access 日志里的 IP、状态码、访问次数和来源类型
- 识别常见搜索引擎、AI 访问和明显爬虫
- 在线管理共享黑白名单
- 白名单优先于黑名单，支持一键保存、导出和 `nginx -t`
- 可选扩展：444 拦截审核、离线 IP 风险分析

## 部署

### 1. 修改运行配置

打开 [main.py](main.py)，按服务器实际路径修改这几项：

```python
LOG_PATHS = _configured_log_paths()
BLACKLIST_PATH = os.environ.get(
    "NSL_BLACKLIST_PATH", "/etc/nginx/conf.d/black_ip.conf"
)
TRUSTEDLIST_PATH = os.environ.get(
    "NSL_TRUSTEDLIST_PATH", "/etc/nginx/conf.d/trusted_ip.conf"
)
PORT = int(os.environ.get("NSL_PORT", "9999"))
```

日志路径的默认值在 `_configured_log_paths()` 里：

```python
configured = os.environ.get("NSL_LOG_PATHS", "/var/log/nginx/access.log*")
```

也可以不改代码，直接用环境变量覆盖：

```bash
export NSL_PORT=9999
export NSL_LOG_PATHS="/var/log/nginx/access.log*"
export NSL_BLACKLIST_PATH="/etc/nginx/conf.d/black_ip.conf"
export NSL_TRUSTEDLIST_PATH="/etc/nginx/conf.d/trusted_ip.conf"
```

### 2. 准备黑白名单

```bash
sudo touch /etc/nginx/conf.d/black_ip.conf
sudo touch /etc/nginx/conf.d/trusted_ip.conf
```

`black_ip.conf` 示例：

```nginx
1.2.3.0/24 1;
1.2.3.4 1;
```

`trusted_ip.conf` 示例：

```nginx
5.6.7.0/24 1;
5.6.7.8 1;
```

### 3. 接入 Nginx

把这段放进 `nginx.conf` 的 `http {}` 内，并确保它位于第一个 `map` 指令之前：

```nginx
map_hash_bucket_size 128;

geo $blacklisted_ip {
    default 0;
    include conf.d/black_ip.conf;
}

geo $trusted_ip {
    default 0;
    include conf.d/trusted_ip.conf;
}

map "$trusted_ip:$blacklisted_ip" $ip_blocked {
    default 0;
    "0:1" 1;
}
```

然后在需要启用黑白名单的 `server {}` 里加入：

```nginx
if ($ip_blocked) {
    return 444;
}
```

检查并重载：

```bash
sudo nginx -t && sudo nginx -s reload
```

### 4. 启动

```bash
sh restart.sh
```

访问：

```text
http://服务器地址:9999/
```

## 可选：用 Nginx 代理管理页面

如需把管理页面挂到站点路径下，例如 `/cstat/`：

```nginx
location = /cstat {
    return 301 /cstat/;
}

location ^~ /cstat/ {
    proxy_pass http://127.0.0.1:9999;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

`^~` 用来避免站点已有的 `.js`、`.css` 静态规则抢走管理页面资源。

## 目录

```text
main.py       Python 启动入口
restart.sh    启动/重启脚本
web/          前端页面
dlc/          可选扩展
config/       示例配置
var/          本地运行数据和生成文件
```

## DLC

DLC 是可选扩展，不影响基础功能启动。项目自带两个 DLC：

- `blocked_review`：查看 444 拦截记录，辅助确认是否误拦。
- `threat_analysis`：离线分析日志、IP 情报、地区和 ASN 风险，并生成策略建议。

依赖说明：

- `blocked_review`：无额外依赖。
- `threat_analysis`：需要 `requests`；如果使用 Anaconda base，一般已包含。

### 安装 DLC

把 DLC 目录放到项目的 `dlc/` 下即可：

```text
dlc/
  blocked_review/
    manifest.json
  threat_analysis/
    manifest.json
```

每个 DLC 目录必须包含 `manifest.json`。重启后，带 Web 页面的 DLC 会自动出现在顶部导航；命令行 DLC 不会显示在页面导航里。

```bash
sh restart.sh
```

### 使用 blocked_review

启动后直接访问：

```text
http://服务器地址:9999/blocked
```

如果管理页面通过 `/cstat/` 代理访问，则对应路径是：

```text
https://域名/cstat/blocked
```

如果页面导航里没有出现“444 审核”，可以在服务器上检查：

```bash
ls dlc/blocked_review/manifest.json
curl http://127.0.0.1:9999/api/dlc
tail -n 50 var/main.log
```

### 使用 threat_analysis

`threat_analysis` 是离线分析工具，按需在项目根目录运行：

```bash
python -m dlc.threat_analysis.ip_shield_analyzer
python -m dlc.threat_analysis.build_final_policy
```

## 许可证

[MIT](LICENSE)
