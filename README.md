# CC Token Guard

监控 claude.ai 的 Claude Code OAuth token,自动撤销不在白名单里的 token,减少账号被他人蹭用的风险。

这是一个单文件脚本项目,入口固定为:

```bash
uv run python cc_token_guard.py ...
```

## 安全提醒

`config.toml` 里的 `session_key` 等同账号登录凭证。

- 不要把 `config.toml` 提交到 git。
- 不要把 `config.toml` 发给别人或上传到在线服务。
- 建议设置权限: `chmod 600 config.toml`。

## 安装

需要 Python 3.11+ 和 uv。

```bash
uv sync
```

## 配置

复制示例配置:

```bash
cp config.toml.example config.toml
chmod 600 config.toml
```

填写 `config.toml`:

```toml
poll_interval = 30
api_base = "https://claude.ai"
user_agent = "Mozilla/5.0 ..."
cleanup_web_sessions = false

[accounts.main]
org_id = "..."
session_key = "..."
```

字段说明:

- `poll_interval`: 监控轮询间隔,单位秒。
- `api_base`: claude.ai API 根地址,一般不用改。
- `user_agent`: 浏览器 User-Agent。
- `cleanup_web_sessions`: 是否同时清理 claude.ai Web 会话。
- `accounts.<name>.org_id`: claude.ai organization id。
- `accounts.<name>.session_key`: claude.ai 的 `sessionKey` cookie 值。

账号名只允许字母、数字、下划线和连字符,例如 `main`、`backup`。

## 获取 cookie

每个账号都需要获取一次:

1. 用该账号登录 `https://claude.ai`。
2. 打开浏览器 DevTools。
3. 进入 Application -> Cookies -> `https://claude.ai`。
4. 复制 `sessionKey` 的 Value,填入 `session_key`。
5. 复制 `lastActiveOrg` 的 Value,填入 `org_id`。

`session_key` 可以带或不带 `sessionKey=` 前缀。

## 使用

列出配置里的账号:

```bash
uv run python cc_token_guard.py accounts
```

初始化白名单:

```bash
uv run python cc_token_guard.py init main
```

这会把当前未撤销的 Claude Code token 写入 `data/main/whitelist.json`。运行前先确认 claude.ai 设置页里只剩你认可的 token。

查看状态:

```bash
uv run python cc_token_guard.py list
uv run python cc_token_guard.py list main
```

添加 token 到白名单:

```bash
uv run python cc_token_guard.py add main <token-uuid>
```

启动监控:

```bash
uv run python cc_token_guard.py monitor
```

无人值守运行时,如果确认允许缺白名单账号按空白名单处理,可以加 `--yes`:

```bash
uv run python cc_token_guard.py monitor --yes
```

主动登出某个账号:

```bash
uv run python cc_token_guard.py logout main
```

`logout` 会终止该账号的所有 Web session,并撤销所有非白名单 Claude Code token。执行后该账号当前 `session_key` 会失效,需要重新获取并更新 `config.toml`。

## 白名单

每个账号的白名单保存在:

```text
data/<account>/whitelist.json
```

监控逻辑:

- 白名单内的 Claude Code token 会保留。
- 白名单外的 Claude Code token 会被撤销。
- 已撤销 token 会忽略。
- 非 Claude Code 的 OAuth 应用不会处理。
- `cleanup_web_sessions = false` 时不会清理 Web 会话。

## 常用命令

```bash
uv run python cc_token_guard.py --help
uv run python cc_token_guard.py accounts
uv run python cc_token_guard.py init main
uv run python cc_token_guard.py list
uv run python cc_token_guard.py monitor
```
