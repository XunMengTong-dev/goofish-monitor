from src.services.web_auth_service import (
    WebSessionSettings,
    authenticate_session_token,
    create_session_token,
    verify_credentials,
    verify_session_token,
)


def test_session_token_round_trip_and_expiry():
    token = create_session_token("admin", "signing-key", ttl_seconds=60, now=1_000)

    assert verify_session_token(token, "signing-key", now=1_001) == "admin"
    assert verify_session_token(token, "signing-key", now=1_060) is None


def test_session_token_rejects_tampering_and_wrong_key():
    token = create_session_token("admin", "signing-key", ttl_seconds=60, now=1_000)
    payload, signature = token.split(".", 1)

    assert verify_session_token(f"{payload}x.{signature}", "signing-key", now=1_001) is None
    assert verify_session_token(token, "another-key", now=1_001) is None


def test_authenticate_session_token_requires_configured_username():
    settings = WebSessionSettings(
        username="admin",
        password="secret",
        signing_key="signing-key",
        ttl_seconds=60,
    )
    token = create_session_token("another-user", "signing-key", ttl_seconds=60, now=1_000)

    assert authenticate_session_token(token, settings) is None


def test_verify_credentials_uses_exact_match():
    assert verify_credentials("admin", "secret", "admin", "secret") is True
    assert verify_credentials("Admin", "secret", "admin", "secret") is False
    assert verify_credentials("admin", "wrong", "admin", "secret") is False
