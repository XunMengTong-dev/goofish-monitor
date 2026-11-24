from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
import requests


playwright_api = pytest.importorskip(
    "playwright.sync_api",
    reason="端到端测试需要安装 playwright：pip install -r requirements.txt",
)

PlaywrightError = playwright_api.Error
expect = playwright_api.expect
sync_playwright = playwright_api.sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
DIST_INDEX = REPO_ROOT / "dist" / "index.html"
STARTUP_TIMEOUT_SECONDS = 45
WEB_USERNAME = "e2e-admin"
WEB_PASSWORD = "e2e-password"

pytestmark = pytest.mark.e2e


if not DIST_INDEX.exists():
    pytest.skip(
        "端到端测试需要前端构建产物：cd web-ui && npm ci && npm run build",
        allow_module_level=True,
    )


@dataclass(frozen=True)
class E2EServer:
    base_url: str
    workspace: Path
    log_path: Path
    process: subprocess.Popen


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


def _terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_for_server(base_url: str, process: subprocess.Popen, log_path: Path) -> None:
    session = requests.Session()
    session.trust_env = False
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    last_error = "unknown"

    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        try:
            response = session.get(f"{base_url}/health", timeout=2)
            if response.status_code == 200:
                return
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
        except requests.RequestException as exc:
            last_error = str(exc)
        time.sleep(0.5)

    log_excerpt = ""
    if log_path.exists():
        log_excerpt = log_path.read_text(encoding="utf-8", errors="ignore")[-4000:]
    raise RuntimeError(
        "E2E 服务未在预期时间内启动。"
        f" last_error={last_error}\nserver_log={log_path}\n{log_excerpt}"
    )


@pytest.fixture(scope="session")
def e2e_server(tmp_path_factory):
    workspace = tmp_path_factory.mktemp("web-e2e")
    for asset_name in ("dist", "static", "prompts"):
        source = REPO_ROOT / asset_name
        if source.exists():
            (workspace / asset_name).symlink_to(source, target_is_directory=True)
    for directory in ("data", "logs", "images"):
        (workspace / directory).mkdir(parents=True, exist_ok=True)

    port = _find_free_port()
    base_url = f"http://127.0.0.1:{port}"
    log_path = workspace / "server.log"
    env = os.environ.copy()
    env.update(
        {
            "APP_DATABASE_FILE": str(workspace / "data" / "e2e.sqlite3"),
            "WEB_SESSION_SECRET": "e2e-session-secret-with-sufficient-entropy",
            "WEB_SESSION_SECRET_FILE": str(workspace / "data" / "session-secret"),
            "WEB_SESSION_TTL_SECONDS": "3600",
            "WEB_USERNAME": WEB_USERNAME,
            "WEB_PASSWORD": WEB_PASSWORD,
            "PYTHONPATH": os.pathsep.join(
                value for value in (str(REPO_ROOT), env.get("PYTHONPATH")) if value
            ),
            "PYTHONUNBUFFERED": "1",
        }
    )

    log_handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=workspace,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_server(base_url, process, log_path)
        yield E2EServer(
            base_url=base_url,
            workspace=workspace,
            log_path=log_path,
            process=process,
        )
    finally:
        _terminate_process(process)
        log_handle.close()
        shutil.rmtree(workspace, ignore_errors=True)


@pytest.fixture(scope="module")
def browser():
    playwright = sync_playwright().start()
    try:
        try:
            browser_instance = playwright.chromium.launch(
                headless=True,
                args=["--disable-dev-shm-usage"],
            )
        except PlaywrightError as exc:
            message = str(exc)
            if "Executable doesn't exist" in message or "looks like Playwright" in message:
                pytest.skip("未安装 Chromium，请运行：playwright install chromium")
            raise
        yield browser_instance
        browser_instance.close()
    finally:
        playwright.stop()


@pytest.fixture()
def page(browser, e2e_server):
    context = browser.new_context(
        base_url=e2e_server.base_url,
        locale="zh-CN",
    )
    page_instance = context.new_page()
    page_instance.set_default_timeout(15_000)
    try:
        yield page_instance
    finally:
        context.close()


@pytest.fixture()
def logged_in_page(page, e2e_server):
    page.goto("/login?redirect=/tasks")
    page.get_by_label("用户名").fill(WEB_USERNAME)
    page.get_by_label("密码").fill(WEB_PASSWORD)
    page.get_by_role("button", name="登录", exact=True).click()
    expect(page).to_have_url(f"{e2e_server.base_url}/tasks")
    expect(page.get_by_role("heading", name="任务管理")).to_be_visible()
    return page


def test_unauthenticated_visit_redirects_to_login(page):
    page.goto("/dashboard")

    expect(page).to_have_url(re.compile(r"/login(?:\?|$)"))
    query = parse_qs(urlsplit(page.url).query)
    assert query["redirect"] == ["/dashboard"]
    expect(page.get_by_role("heading", name="系统登录")).to_be_visible()


def test_invalid_password_shows_login_error(page):
    page.goto("/login")
    page.get_by_label("用户名").fill(WEB_USERNAME)
    page.get_by_label("密码").fill("wrong-password")
    page.get_by_role("button", name="登录", exact=True).click()

    expect(page.get_by_role("alert")).to_contain_text("登录失败：用户名或密码错误")
    assert page.url.endswith("/login")


def test_login_restores_authenticated_session_after_reload(page, e2e_server):
    page.goto("/login?redirect=/tasks")
    page.get_by_label("用户名").fill(WEB_USERNAME)
    page.get_by_label("密码").fill(WEB_PASSWORD)
    page.get_by_role("button", name="登录", exact=True).click()

    expect(page).to_have_url(f"{e2e_server.base_url}/tasks")
    expect(page.get_by_role("heading", name="任务管理")).to_be_visible()
    assert page.evaluate("() => localStorage.getItem('auth_username')") == WEB_USERNAME

    cookies = page.context.cookies(e2e_server.base_url)
    session_cookie = next(
        cookie for cookie in cookies if cookie["name"] == "goofish_monitor_session"
    )
    assert session_cookie["httpOnly"] is True
    assert session_cookie["sameSite"] == "Lax"

    page.reload()

    expect(page).to_have_url(f"{e2e_server.base_url}/tasks")
    expect(page.get_by_role("heading", name="任务管理")).to_be_visible()
    assert page.evaluate(
        "async () => (await fetch('/api/tasks', { credentials: 'same-origin' })).status"
    ) == 200


def test_logout_clears_session_and_requires_login_again(logged_in_page, e2e_server):
    page = logged_in_page

    page.get_by_role("button", name="退出登录").click()

    expect(page).to_have_url(re.compile(r"/login(?:\?|$)"))
    expect(page.get_by_role("heading", name="系统登录")).to_be_visible()
    assert page.evaluate(
        "async () => (await fetch('/api/tasks', { credentials: 'same-origin' })).status"
    ) == 401
    assert page.evaluate("() => localStorage.getItem('auth_username')") is None


def test_authenticated_websocket_connection_is_allowed(logged_in_page):
    page = logged_in_page
    browser_messages: list[str] = []
    page.on("console", lambda message: browser_messages.append(f"console {message.type}: {message.text}"))
    page.on("pageerror", lambda error: browser_messages.append(f"pageerror: {error}"))

    result = page.evaluate(
        """
        () => new Promise((resolve) => {
          const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
          const socket = new WebSocket(`${protocol}//${window.location.host}/ws`);
          let errorSeen = false;
          const timer = window.setTimeout(() => {
            socket.close();
            resolve({ status: 'timeout', errorSeen });
          }, 5000);
          socket.onopen = () => {
            window.clearTimeout(timer);
            socket.close();
            resolve({ status: 'open' });
          };
          socket.onerror = () => {
            errorSeen = true;
          };
          socket.onclose = (event) => {
            window.clearTimeout(timer);
            resolve({ status: 'closed', code: event.code, errorSeen });
          };
        })
        """
    )

    assert result == {"status": "open"}, browser_messages


def test_keyword_task_create_edit_and_delete(logged_in_page):
    page = logged_in_page
    task_name = "E2E 关键词任务"
    updated_task_name = f"{task_name}-已编辑"

    page.get_by_role("button", name="+ 创建新任务", exact=True).click()
    create_dialog = page.get_by_role("dialog")
    expect(create_dialog.get_by_role("heading", name="创建新监控任务（AI 或关键词）")).to_be_visible()
    create_dialog.get_by_label("任务名称").fill(task_name)
    create_dialog.get_by_label("搜索关键词").fill("e2e-keyword")
    create_dialog.get_by_label("判断模式").click()
    page.get_by_role("option", name="关键词判断").click()
    create_dialog.get_by_label("关键词规则").fill("e2e\n测试")
    create_dialog.get_by_role("button", name="创建任务", exact=True).click()

    created_row = page.locator("tr:visible").filter(has_text=task_name)
    expect(created_row).to_be_visible()

    page.locator(f'button[aria-label="编辑 {task_name}"]:visible').click()
    edit_dialog = page.get_by_role("dialog")
    expect(edit_dialog.get_by_role("heading", name=f"编辑任务: {task_name}")).to_be_visible()
    edit_dialog.get_by_label("任务名称").fill(updated_task_name)
    edit_dialog.get_by_role("button", name="保存更改", exact=True).click()

    updated_row = page.locator("tr:visible").filter(has_text=updated_task_name)
    expect(updated_row).to_be_visible()

    page.locator(f'button[aria-label="删除 {updated_task_name}"]:visible').click()
    delete_dialog = page.get_by_role("dialog")
    expect(
        delete_dialog.get_by_text(f"确定删除任务「{updated_task_name}」吗？此操作不可恢复。")
    ).to_be_visible()
    delete_dialog.get_by_role("button", name="确认删除", exact=True).click()

    expect(page.get_by_text(updated_task_name)).to_have_count(0)
    tasks = page.evaluate(
        "async () => await (await fetch('/api/tasks', "
        "{ credentials: 'same-origin' })).json()"
    )
    assert all(task["task_name"] != updated_task_name for task in tasks)
