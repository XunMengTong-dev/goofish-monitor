import stat

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routes import accounts, login_state


def test_account_files_are_written_with_restricted_permissions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ACCOUNT_STATE_DIR", "accounts")
    app = FastAPI()
    app.include_router(accounts.router)
    client = TestClient(app)

    response = client.post(
        "/api/accounts",
        json={"name": "demo", "content": '{"cookies": []}'},
    )

    assert response.status_code == 200
    account_file = tmp_path / "accounts" / "demo.json"
    assert stat.S_IMODE(account_file.stat().st_mode) == 0o600


def test_login_state_file_is_written_with_restricted_permissions(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = FastAPI()
    app.include_router(login_state.router)
    client = TestClient(app)

    response = client.post(
        "/api/login-state",
        json={"content": '{"cookies": []}'},
    )

    assert response.status_code == 200
    state_file = tmp_path / "xianyu_state.json"
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
