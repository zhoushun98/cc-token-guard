from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
import structlog
from structlog.contextvars import bound_contextvars


# 项目目录就是当前工作目录
PROJECT_DIR = Path.cwd()
DATA_DIR = PROJECT_DIR / "data"

log = structlog.get_logger()

_VALID_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")


class ConfigError(Exception):
    """配置加载失败(文件缺失、字段不对等)。"""


class WhitelistError(Exception):
    """白名单文件缺失或损坏。"""


class CookieExpired(Exception):
    """sessionKey 已失效,需要重新抓 cookie。"""


class ClaudeAPIError(Exception):
    """claude.ai 返回非预期状态码。"""


@dataclass(frozen=True)
class GlobalConfig:
    poll_interval: int
    api_base: str
    user_agent: str
    cleanup_web_sessions: bool = False


@dataclass(frozen=True)
class Account:
    name: str
    org_id: str
    session_key: str

    def __repr__(self) -> str:
        # 防止 traceback / 日志意外打印 sessionKey
        return (
            f"Account(name={self.name!r}, org_id={self.org_id!r}, "
            f"session_key='<hidden>')"
        )


@dataclass(frozen=True)
class Token:
    id: str
    application_name: str
    scope: str
    is_revoked: bool
    created_at: str


@dataclass(frozen=True)
class WebSession:
    created_at: str
    application_slug: str
    is_current: bool
    browser: str
    os: str
    location: str


def _build_account(name: str, block: dict) -> Account:
    session_key = block["session_key"]
    if isinstance(session_key, str) and session_key.startswith("sessionKey="):
        session_key = session_key[len("sessionKey="):]
    return Account(
        name=name,
        org_id=block["org_id"],
        session_key=session_key,
    )


def load_config(project_dir: Path) -> tuple[GlobalConfig, list[Account]]:
    config_path = project_dir / "config.toml"
    if not config_path.exists():
        raise ConfigError(
            f"config.toml 不存在: {config_path}。"
            f"请复制 config.toml.example 为 config.toml 并填写。"
        )

    # 旧布局警告:存在 accounts/ 目录但已废弃
    if (project_dir / "accounts").is_dir():
        log.warning(
            "legacy_accounts_dir_detected",
            hint="accounts/<name>.toml 已废弃,请把字段移到 config.toml 的 [accounts.<name>] 块,然后删掉 accounts/ 目录",
        )

    with config_path.open("rb") as f:
        raw = tomllib.load(f)

    try:
        global_cfg = GlobalConfig(
            poll_interval=int(raw["poll_interval"]),
            api_base=raw["api_base"],
            user_agent=raw["user_agent"],
            cleanup_web_sessions=bool(raw.get("cleanup_web_sessions", False)),
        )
    except KeyError as exc:
        raise ConfigError(f"config.toml 缺少必填字段: {exc}") from exc

    accounts_raw = raw.get("accounts")
    if not isinstance(accounts_raw, dict) or not accounts_raw:
        raise ConfigError(
            "config.toml 中没有 [accounts.<name>] 块。"
            "至少需要一个,例如 [accounts.main] 含 org_id 和 session_key。"
        )

    accounts: list[Account] = []
    for name in sorted(accounts_raw.keys()):
        block = accounts_raw[name]
        if not _VALID_NAME.match(name):
            log.warning("invalid_account_name", name=name)
            continue
        if not isinstance(block, dict):
            log.warning("invalid_account_block", name=name)
            continue
        try:
            accounts.append(_build_account(name, block))
        except KeyError as exc:
            log.warning(
                "skip_invalid_account",
                name=name,
                error=str(exc),
                error_type="KeyError",
            )

    if not accounts:
        raise ConfigError(
            "config.toml 的 [accounts.<name>] 块中没有可用账号。"
            "请确保至少一个账号包含 org_id 和 session_key,且名字符合 [a-zA-Z0-9_-]+。"
        )
    return global_cfg, accounts


def write_whitelist(path: Path, token_ids: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "token_ids": sorted(set(token_ids)),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_whitelist(path: Path) -> set[str]:
    if not path.exists():
        raise WhitelistError(
            f"白名单未初始化: {path}。请先运行 `uv run python cc_token_guard.py init <account>`。"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        token_ids = data.get("token_ids", [])
        if not isinstance(token_ids, list):
            raise TypeError(f"token_ids 应为列表，实际为 {type(token_ids).__name__}")
        return set(token_ids)
    except (json.JSONDecodeError, TypeError) as exc:
        raise WhitelistError(f"白名单文件损坏: {path}") from exc


def add_token(path: Path, token_id: str) -> None:
    existing = load_whitelist(path) if path.exists() else set()
    existing.add(token_id)
    write_whitelist(path, list(existing))


def _parse_session(item: dict) -> WebSession:
    ua = item.get("user_agent") or {}
    loc = item.get("location_info") or {}
    browser = " ".join(filter(None, [ua.get("browser_family"), ua.get("browser_version")])) or "Unknown"
    os_str = " ".join(filter(None, [ua.get("os_family"), ua.get("os_version")])) or "Unknown"
    location = ", ".join(filter(None, [loc.get("city"), loc.get("region"), loc.get("country")])) or "Unknown"
    try:
        return WebSession(
            created_at=item["created_at"],
            application_slug=item["application_slug"],
            is_current=item["is_current"],
            browser=browser,
            os=os_str,
            location=location,
        )
    except KeyError as exc:
        raise ClaudeAPIError(f"session 数据缺少字段: {exc}") from exc


class ClaudeClient:
    def __init__(
        self,
        global_cfg: GlobalConfig,
        account: Account,
        *,
        timeout: float = 15.0,
    ) -> None:
        self._global_cfg = global_cfg
        self._account = account
        self._http = httpx.Client(
            timeout=timeout,
            headers={
                "cookie": f"sessionKey={account.session_key}",
                "anthropic-client-platform": "web_claude_ai",
                "anthropic-client-version": "1.0.0",
                "content-type": "application/json",
                "user-agent": global_cfg.user_agent,
                "accept": "*/*",
                "referer": "https://claude.ai/settings/claude-code",
            },
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ClaudeClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def list_tokens(self) -> list[Token]:
        url = (
            f"{self._global_cfg.api_base}"
            f"/api/oauth/organizations/{self._account.org_id}/oauth_tokens"
        )
        resp = self._http.get(url, params={"application_slug": "claude-code"})
        if resp.status_code in (401, 403):
            raise CookieExpired(f"list_tokens 返回 {resp.status_code}")
        if resp.status_code != 200:
            raise ClaudeAPIError(f"list_tokens 返回 {resp.status_code}: {resp.text}")
        return [
            Token(
                id=item["id"],
                application_name=item["application_name"],
                scope=item["scope"],
                is_revoked=item["is_revoked"],
                created_at=item["created_at"],
            )
            for item in resp.json()
        ]

    def revoke_token(self, token_id: str) -> None:
        url = (
            f"{self._global_cfg.api_base}"
            f"/api/oauth/organizations/{self._account.org_id}"
            f"/oauth_tokens/{token_id}/revoke"
        )
        # 关键:body 是 JSON 字符串字面量(带引号的 token_id),不是对象
        resp = self._http.post(url, content=json.dumps(token_id).encode("utf-8"))
        if resp.status_code in (401, 403):
            raise CookieExpired(f"revoke 返回 {resp.status_code}")
        if resp.status_code != 204:
            raise ClaudeAPIError(f"revoke 返回 {resp.status_code}: {resp.text}")

    def list_sessions(self) -> list[WebSession]:
        url = f"{self._global_cfg.api_base}/api/auth/sessions/list-active"
        resp = self._http.get(
            url,
            params={"per_page": 100, "application_slug": "claude-ai"},
        )
        if resp.status_code in (401, 403):
            raise CookieExpired(f"list_sessions 返回 {resp.status_code}")
        if resp.status_code != 200:
            raise ClaudeAPIError(f"list_sessions 返回 {resp.status_code}: {resp.text}")
        return [_parse_session(item) for item in resp.json().get("data", [])]

    def terminate_session(self, created_at: str, application_slug: str) -> None:
        url = f"{self._global_cfg.api_base}/api/auth/logout/session"
        resp = self._http.post(
            url,
            json={"created_at": created_at, "application_slug": application_slug},
        )
        if resp.status_code in (401, 403):
            raise CookieExpired(f"terminate_session 返回 {resp.status_code}")
        if resp.status_code != 200:
            raise ClaudeAPIError(f"terminate_session 返回 {resp.status_code}: {resp.text}")


def run_once(
    client: ClaudeClient,
    whitelist_path: Path,
    *,
    cleanup_sessions: bool = True,
) -> None:
    # 注意:CookieExpired 不在此处捕获,向上传播给 run_loop 统一处理(per-account 隔离,进程不退出)
    try:
        whitelist = load_whitelist(whitelist_path)
    except WhitelistError:
        # 白名单缺失 → 退化为空集合(= "全踢"语义);_cmd_monitor 启动时已二次确认
        log.warning("whitelist_missing_treating_as_empty", path=str(whitelist_path))
        whitelist = set()
    tokens = client.list_tokens()

    for token in tokens:
        if token.application_name != "Claude Code":
            continue
        if token.is_revoked:
            continue
        if token.id in whitelist:
            continue

        try:
            client.revoke_token(token.id)
            log.info(
                "kicked",
                token_id=token.id,
                created_at=token.created_at,
                scope=token.scope,
            )
        except ClaudeAPIError as e:
            log.error("revoke_failed", token_id=token.id, error=str(e))
            # 继续处理下一个,不退出

    if not cleanup_sessions:
        return

    # Web session 清理
    sessions = client.list_sessions()
    if not sessions:
        return
    if not any(s.is_current for s in sessions):
        # 防御:列表里没有任何 current session,异常情况,跳过避免误删
        log.warning("no_current_session_skip_session_cleanup", count=len(sessions))
        return

    for session in sessions:
        if session.is_current:
            continue
        try:
            client.terminate_session(session.created_at, session.application_slug)
            log.info(
                "session_terminated",
                created_at=session.created_at,
                browser=session.browser,
                os=session.os,
                location=session.location,
            )
        except ClaudeAPIError as e:
            log.error(
                "session_terminate_failed",
                created_at=session.created_at,
                error=str(e),
            )


def logout_account(
    client: ClaudeClient,
    whitelist_path: Path,
) -> None:
    """主动登出账号:撤销非白名单 Claude Code token + 终止所有 web session(self 放最后)。

    self session 一旦终止,sessionKey 立即失效;调用者需要重抓 cookie 更新 config.toml。
    """
    try:
        whitelist = load_whitelist(whitelist_path)
    except WhitelistError:
        log.warning("whitelist_missing_treating_as_empty", path=str(whitelist_path))
        whitelist = set()

    for token in client.list_tokens():
        if token.application_name != "Claude Code":
            continue
        if token.is_revoked:
            continue
        if token.id in whitelist:
            continue
        try:
            client.revoke_token(token.id)
            log.info(
                "kicked",
                token_id=token.id,
                created_at=token.created_at,
                scope=token.scope,
            )
        except ClaudeAPIError as e:
            log.error("revoke_failed", token_id=token.id, error=str(e))

    sessions = client.list_sessions()
    # is_current=True 的放最后:终止 self 后 sessionKey 失效,后续请求会 401
    ordered = sorted(sessions, key=lambda s: s.is_current)
    for session in ordered:
        try:
            client.terminate_session(session.created_at, session.application_slug)
            log.info(
                "session_terminated",
                created_at=session.created_at,
                browser=session.browser,
                os=session.os,
                location=session.location,
                is_self=session.is_current,
            )
        except ClaudeAPIError as e:
            log.error(
                "session_terminate_failed",
                created_at=session.created_at,
                error=str(e),
            )
        except CookieExpired:
            # 防御:self 已终止后还想继续,sessionKey 已死,直接停
            log.info("cookie_expired_after_self_logout")
            break


def run_loop(
    global_cfg: GlobalConfig,
    accounts: list[Account],
    data_dir: Path,
) -> None:
    log.info(
        "monitor_started",
        interval=global_cfg.poll_interval,
        accounts=len(accounts),
    )
    while True:
        for account in accounts:
            whitelist_path = data_dir / account.name / "whitelist.json"
            with bound_contextvars(name=account.name):
                try:
                    with ClaudeClient(global_cfg, account) as client:
                        run_once(
                            client,
                            whitelist_path,
                            cleanup_sessions=global_cfg.cleanup_web_sessions,
                        )
                except CookieExpired as e:
                    # 单账号 cookie 失效,记日志继续下一账号(进程不退出)
                    log.error("account_offline", error=str(e))
                except Exception as e:
                    log.warning(
                        "account_poll_error",
                        error=str(e),
                        error_type=type(e).__name__,
                    )

        time.sleep(global_cfg.poll_interval)


def _whitelist_path(account_name: str) -> Path:
    return DATA_DIR / account_name / "whitelist.json"


def _setup_logging() -> None:
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,  # 必须排第一:把 bound_contextvars 注入到 log record
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
    )


def _find_account(accounts: list[Account], name: str) -> Account:
    for acc in accounts:
        if acc.name == name:
            return acc
    available = ", ".join(a.name for a in accounts) or "(none)"
    raise ConfigError(f"账号 {name!r} 不存在。可用: {available}")


def _print_account_section(client: ClaudeClient, account: Account) -> None:
    """打印单个账号的 OAuth tokens + Web sessions 状态。"""
    try:
        whitelist = load_whitelist(_whitelist_path(account.name))
    except WhitelistError:
        whitelist = set()
        print(f"  (账号 {account.name} 白名单未初始化,所有 token 都会被标记为「将被撤销」)")

    print("  -- OAuth tokens (Claude Code) --")
    for t in client.list_tokens():
        if t.application_name != "Claude Code":
            continue
        if t.is_revoked:
            mark = "[已撤销]"
        elif t.id in whitelist:
            mark = "[✓ 白名单]"
        else:
            mark = "[✗ 将被撤销]"
        print(f"  {mark}  {t.id}  created {t.created_at}")

    print("  -- Web sessions --")
    for s in client.list_sessions():
        mark = "[← Current]   " if s.is_current else "[✗ 将被终止] "
        print(f"  {mark} {s.browser} / {s.os} / {s.location}  created {s.created_at}")


def _cmd_accounts(_: argparse.Namespace) -> int:
    _, accounts = load_config(PROJECT_DIR)
    print(f"已配置 {len(accounts)} 个账号:")
    for acc in accounts:
        print(f"  {acc.name}  (org_id={acc.org_id})")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    global_cfg, accounts = load_config(PROJECT_DIR)
    account = _find_account(accounts, args.account)
    wl_path = _whitelist_path(account.name)

    if wl_path.exists() and not args.force:
        print(f"账号 {account.name} 的白名单已存在: {wl_path}")
        print("加 --force 覆盖,或先备份。")
        return 1

    with ClaudeClient(global_cfg, account) as client:
        tokens = client.list_tokens()

    active_tokens = [
        t for t in tokens
        if t.application_name == "Claude Code" and not t.is_revoked
    ]

    write_whitelist(wl_path, [t.id for t in active_tokens])
    print(f"账号 {account.name}: 已写入 {len(active_tokens)} 个 token 到 {wl_path}:")
    for t in active_tokens:
        print(f"  ✓ {t.id}  (created at {t.created_at})")
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    global_cfg, accounts = load_config(PROJECT_DIR)
    if args.account is not None:
        targets = [_find_account(accounts, args.account)]
    else:
        targets = accounts

    for acc in targets:
        print(f"== 账号: {acc.name} ==")
        with ClaudeClient(global_cfg, acc) as client:
            _print_account_section(client, acc)
        print()
    return 0


def _cmd_add(args: argparse.Namespace) -> int:
    _, accounts = load_config(PROJECT_DIR)
    account = _find_account(accounts, args.account)
    add_token(_whitelist_path(account.name), args.token_id)
    print(f"账号 {account.name}: 已加入白名单 {args.token_id}")
    return 0


def _cmd_logout(args: argparse.Namespace) -> int:
    global_cfg, accounts = load_config(PROJECT_DIR)
    account = _find_account(accounts, args.account)
    _setup_logging()
    with ClaudeClient(global_cfg, account) as client:
        try:
            logout_account(client, _whitelist_path(account.name))
        except CookieExpired as e:
            print(f"账号 {account.name} 的 sessionKey 已失效: {e}", file=sys.stderr)
            return 2
    print(
        f"账号 {account.name}: 登出完成。当前 sessionKey 已作废,"
        f"重抓 cookie 后更新 config.toml 再启动 monitor。"
    )
    return 0


def _cmd_monitor(args: argparse.Namespace) -> int:
    global_cfg, accounts = load_config(PROJECT_DIR)
    missing = [a.name for a in accounts if not _whitelist_path(a.name).exists()]
    if missing and not args.yes:
        print(f"⚠️  以下账号尚未 init 白名单: {missing}", file=sys.stderr)
        print(
            f"   这些账号上的所有非撤销 Claude Code OAuth token 都会被立即撤销",
            file=sys.stderr,
        )
        print(f'   (相当于该账号的"白名单 = 空集合")', file=sys.stderr)
        print("", file=sys.stderr)
        if not sys.stdin.isatty():
            print(
                "错误: 非交互式环境(无 tty),无法二次确认。"
                "请加 --yes 跳过,或先跑 `uv run python cc_token_guard.py init <account>`。",
                file=sys.stderr,
            )
            return 2
        try:
            ans = input("确认继续吗? [y/N]: ").strip().lower()
        except EOFError:
            print("已取消(无输入)", file=sys.stderr)
            return 2
        if ans not in ("y", "yes"):
            print("已取消", file=sys.stderr)
            return 2

    _setup_logging()
    try:
        run_loop(global_cfg, accounts, DATA_DIR)
    except KeyboardInterrupt:
        # Ctrl+C 干净退出,不打 traceback
        pass
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="cc_token_guard.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_accounts = sub.add_parser("accounts", help="列出所有已配置账号")
    p_accounts.set_defaults(func=_cmd_accounts)

    p_init = sub.add_parser("init", help="给指定账号建白名单")
    p_init.add_argument("account", help="账号名")
    p_init.add_argument("--force", action="store_true", help="覆盖已存在的白名单")
    p_init.set_defaults(func=_cmd_init)

    p_list = sub.add_parser("list", help="显示账号 token + session 状态")
    p_list.add_argument("account", nargs="?", default=None, help="账号名(省略 = 所有)")
    p_list.set_defaults(func=_cmd_list)

    p_add = sub.add_parser("add", help="把指定 token id 加入账号白名单")
    p_add.add_argument("account", help="账号名")
    p_add.add_argument("token_id", help="要加入白名单的 token UUID")
    p_add.set_defaults(func=_cmd_add)

    p_logout = sub.add_parser(
        "logout",
        help="主动登出账号:撤销非白名单 token + 终止所有 web session(含自己)",
    )
    p_logout.add_argument("account", help="账号名")
    p_logout.set_defaults(func=_cmd_logout)

    p_monitor = sub.add_parser("monitor", help="常驻轮询所有账号")
    p_monitor.add_argument(
        "--yes", "-y", action="store_true",
        help="跳过缺白名单时的二次确认(无人值守运行用)",
    )
    p_monitor.set_defaults(func=_cmd_monitor)

    args = parser.parse_args()
    try:
        sys.exit(args.func(args))
    except (ConfigError, WhitelistError) as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
