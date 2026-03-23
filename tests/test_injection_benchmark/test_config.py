"""Tests for injection benchmark config loader."""
import pytest
import textwrap
from pathlib import Path

from config import load_config, validate_config


@pytest.fixture
def valid_yaml(tmp_path):
    """Write a valid config YAML and return its path."""
    pw_file = tmp_path / "password.txt"
    pw_file.write_text("s3cret123")

    pin_file = tmp_path / "pin.txt"
    pin_file.write_text("1234")

    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent(f"""\
        sentinel:
          base_url: "https://localhost:3001"
          pin_file: "{pin_file}"
          email: "sentinel@example.com"
          calendar_backend: "caldav"

        attacker:
          email: "attacker@evil.com"
          email_imap_server: "imap.evil.com"
          email_imap_user: "attacker@evil.com"
          email_imap_password_file: "{pw_file}"
          signal_phone: "+15550000000"

        seeding:
          email_smtp_server: "smtp.evil.com"
          email_smtp_user: "attacker@evil.com"
          email_smtp_password_file: "{pw_file}"
          web_base_url: "http://192.168.1.100"
          web_output_dir: "{tmp_path / 'web'}"
          workspace_volume: "sentinel_sentinel-workspace"

        contacts:
          known_signal: "+15551111111"
          known_telegram_chat_id: "12345"
          unknown_signal: "+15552222222"
          unknown_telegram_chat_id: "99999"

        run:
          scope: "core"
          payloads: "all"
          vectors: "all"
          cooldown_s: 5
          timeout_s: 120
          benchmark_mode: true
    """))
    return cfg


def test_load_config_reads_yaml(valid_yaml):
    """load_config reads YAML and returns typed Config object."""
    config = load_config(str(valid_yaml))
    assert config.sentinel.base_url == "https://localhost:3001"
    assert config.attacker.email == "attacker@evil.com"
    assert config.run.scope == "core"


def test_load_config_resolves_tilde(tmp_path):
    """load_config resolves ~ in file paths."""
    pw_file = tmp_path / "password.txt"
    pw_file.write_text("s3cret123")

    pin_file = tmp_path / "pin.txt"
    pin_file.write_text("1234")

    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent(f"""\
        sentinel:
          base_url: "https://localhost:3001"
          pin_file: "{pin_file}"
          email: "sentinel@example.com"
          calendar_backend: "caldav"
        attacker:
          email: "attacker@evil.com"
          email_imap_server: "imap.evil.com"
          email_imap_user: "attacker@evil.com"
          email_imap_password_file: "{pw_file}"
          signal_phone: "+15550000000"
        seeding:
          email_smtp_server: "smtp.evil.com"
          email_smtp_user: "attacker@evil.com"
          email_smtp_password_file: "{pw_file}"
          web_base_url: "http://192.168.1.100"
          web_output_dir: "{tmp_path / 'web'}"
          workspace_volume: "sentinel_sentinel-workspace"
        contacts:
          known_signal: "+15551111111"
          known_telegram_chat_id: "12345"
          unknown_signal: "+15552222222"
          unknown_telegram_chat_id: "99999"
        run:
          scope: "core"
          payloads: "all"
          vectors: "all"
          cooldown_s: 5
          timeout_s: 120
          benchmark_mode: true
    """))
    config = load_config(str(cfg))
    # Pin file path should be resolved (no ~)
    assert "~" not in config.sentinel.pin_file


def test_load_config_reads_password_from_file(valid_yaml):
    """load_config reads password from file reference."""
    config = load_config(str(valid_yaml))
    assert config.attacker.email_imap_password == "s3cret123"


def test_load_config_raises_on_missing_required_fields(tmp_path):
    """load_config raises on missing required fields."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("sentinel:\n  pin_file: '/tmp/pin.txt'\n")
    with pytest.raises((KeyError, ValueError)):
        load_config(str(cfg))


def test_load_config_raises_on_missing_password_file(tmp_path):
    """load_config raises on missing password file."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent("""\
        sentinel:
          base_url: "https://localhost:3001"
          pin_file: "/tmp/nonexistent_pin.txt"
          email: "sentinel@example.com"
          calendar_backend: "caldav"
        attacker:
          email: "attacker@evil.com"
          email_imap_server: "imap.evil.com"
          email_imap_user: "attacker@evil.com"
          email_imap_password_file: "/tmp/nonexistent_password.txt"
          signal_phone: "+15550000000"
        seeding:
          email_smtp_server: "smtp.evil.com"
          email_smtp_user: "attacker@evil.com"
          email_smtp_password_file: "/tmp/nonexistent_password.txt"
          web_base_url: "http://192.168.1.100"
          web_output_dir: "/tmp/web"
          workspace_volume: "sentinel_sentinel-workspace"
        contacts:
          known_signal: "+15551111111"
          known_telegram_chat_id: "12345"
          unknown_signal: "+15552222222"
          unknown_telegram_chat_id: "99999"
        run:
          scope: "core"
          payloads: "all"
          vectors: "all"
          cooldown_s: 5
          timeout_s: 120
          benchmark_mode: true
    """))
    with pytest.raises(FileNotFoundError):
        load_config(str(cfg))


def test_validate_config_checks_scope(valid_yaml):
    """validate_config checks scope is one of core/channels/chained/full."""
    config = load_config(str(valid_yaml))
    config.run.scope = "invalid_scope"
    warnings = validate_config(config)
    assert any("scope" in w.lower() for w in warnings)


def test_validate_config_warns_empty_telegram_allowlist(valid_yaml):
    """validate_config warns if telegram allowlist is empty for channel scope."""
    config = load_config(str(valid_yaml))
    config.run.scope = "channels"
    config.contacts.unknown_telegram_chat_id = ""
    warnings = validate_config(config)
    assert any("telegram" in w.lower() for w in warnings)
