# 444 误拦审核 DLC

该扩展读取核心前端已缓存在浏览器 IndexedDB 中的日志统计，按 IP 聚合
Nginx `444` 响应，支持任意数量的 IP 前缀排除规则及一键加入共享白名单。

- 页面：`/blocked` 或 `/444`
- 扩展 ID：`blocked_review`
- 禁用：启动前设置 `NSL_DISABLED_DLC=blocked_review`

扩展只提供浏览器页面，不增加 Python 第三方依赖。
