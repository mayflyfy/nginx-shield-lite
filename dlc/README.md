# DLC 扩展

DLC 是可选能力，不得成为 `main.py` 核心启动的前置条件。

每个 Web DLC 使用 `dlc/<snake_case_id>/manifest.json` 注册：

```json
{
  "id": "example_dlc",
  "name": "示例扩展",
  "version": "1.0.0",
  "enabled_by_default": true,
  "routes": {"/example": "web/index.html"},
  "nav": {"label": "示例", "path": "/example"}
}
```

约束：

- ID、目录和 Python 包使用 `snake_case`。
- 浏览器资源通过 `/dlc/<id>/...` 访问，不复制到核心 `web/`。
- DLC 只能调用稳定的核心 HTTP API，不能要求修改核心页面才能启动。
- `NSL_DISABLED_DLC=id1,id2` 可在启动时禁用扩展。
- 大数据库、日志、报告和真实策略只能写入 `var/`。
