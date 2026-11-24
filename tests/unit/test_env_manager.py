import stat

from src.infrastructure.config.env_manager import EnvManager


def test_get_value_prefers_env_file_when_key_present(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("WEBHOOK_URL=https://hooks.example.com/new\n", encoding="utf-8")
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.com/old")

    manager = EnvManager(str(env_file))

    assert manager.get_value("WEBHOOK_URL") == "https://hooks.example.com/new"


def test_get_value_falls_back_to_runtime_when_key_missing_from_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    monkeypatch.setenv("WEBHOOK_URL", "https://hooks.example.com/runtime")

    manager = EnvManager(str(env_file))

    assert manager.get_value("WEBHOOK_URL") == "https://hooks.example.com/runtime"


def test_update_values_restricts_env_file_permissions(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    manager = EnvManager(str(env_file))

    assert manager.update_values({"OPENAI_API_KEY": "secret"}) is True
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
