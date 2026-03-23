"""Config loader for injection benchmark — reads YAML, validates, resolves secrets."""
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class SentinelConfig:
    base_url: str
    pin_file: str
    email: str
    calendar_backend: str = "caldav"
    caldav_url: str = ""
    caldav_user: str = ""
    caldav_password: str = ""
    caldav_password_file: str = ""


@dataclass
class AttackerConfig:
    email: str
    email_imap_server: str
    email_imap_user: str
    email_imap_password_file: str
    email_imap_password: str = ""
    signal_phone: str = ""


@dataclass
class SeedingConfig:
    email_smtp_server: str
    email_smtp_user: str
    email_smtp_password_file: str
    email_smtp_password: str = ""
    web_base_url: str = ""
    web_output_dir: str = ""
    workspace_volume: str = "sentinel_sentinel-workspace"


@dataclass
class ContactsConfig:
    known_signal: str = ""
    known_telegram_chat_id: str = ""
    unknown_signal: str = ""
    unknown_telegram_chat_id: str = ""


@dataclass
class RunConfig:
    scope: str = "core"
    payloads: str = "all"
    vectors: str = "all"
    cooldown_s: int = 5
    timeout_s: int = 120
    benchmark_mode: bool = True


@dataclass
class Config:
    sentinel: SentinelConfig
    attacker: AttackerConfig
    seeding: SeedingConfig
    contacts: ContactsConfig
    run: RunConfig


def _resolve_path(path: str) -> str:
    """Expand ~ and resolve to absolute path."""
    return str(Path(os.path.expanduser(path)).resolve())


def _read_secret(path: str) -> str:
    """Read a secret from a file, stripping whitespace."""
    resolved = _resolve_path(path)
    return Path(resolved).read_text().strip()


def load_config(path: str) -> Config:
    """Load and parse config from YAML file. Resolves paths and reads secrets."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    # Validate required top-level sections
    for section in ("sentinel", "attacker", "seeding", "contacts", "run"):
        if section not in raw:
            raise ValueError(f"Missing required config section: {section}")

    s = raw["sentinel"]
    if not s.get("base_url"):
        raise ValueError("Missing required field: sentinel.base_url")

    a = raw["attacker"]
    if not a.get("email"):
        raise ValueError("Missing required field: attacker.email")

    # Resolve paths
    pin_file = _resolve_path(s.get("pin_file", "~/.secrets/sentinel_pin.txt"))
    smtp_pw_file = _resolve_path(raw["seeding"]["email_smtp_password_file"])
    smtp_password = _read_secret(smtp_pw_file)

    # IMAP password (optional — only needed if using IMAP-based verification)
    imap_pw_file = a.get("email_imap_password_file", "")
    imap_password = ""
    if imap_pw_file and a.get("email_imap_server"):
        imap_pw_file = _resolve_path(imap_pw_file)
        imap_password = _read_secret(imap_pw_file)
    elif imap_pw_file:
        imap_pw_file = _resolve_path(imap_pw_file)

    # CalDAV password (optional — only needed for calendar vector)
    caldav_pw_file = s.get("caldav_password_file", "")
    caldav_password = ""
    if caldav_pw_file:
        caldav_pw_file = _resolve_path(caldav_pw_file)
        caldav_password = _read_secret(caldav_pw_file)

    sentinel = SentinelConfig(
        base_url=s["base_url"],
        pin_file=pin_file,
        email=s.get("email", ""),
        calendar_backend=s.get("calendar_backend", "caldav"),
        caldav_url=s.get("caldav_url", ""),
        caldav_user=s.get("caldav_user", ""),
        caldav_password=caldav_password,
        caldav_password_file=caldav_pw_file,
    )

    attacker = AttackerConfig(
        email=a["email"],
        email_imap_server=a.get("email_imap_server", ""),
        email_imap_user=a.get("email_imap_user", ""),
        email_imap_password_file=imap_pw_file,
        email_imap_password=imap_password,
        signal_phone=a.get("signal_phone", ""),
    )

    sd = raw["seeding"]
    seeding = SeedingConfig(
        email_smtp_server=sd.get("email_smtp_server", ""),
        email_smtp_user=sd.get("email_smtp_user", ""),
        email_smtp_password_file=smtp_pw_file,
        email_smtp_password=smtp_password,
        web_base_url=sd.get("web_base_url", ""),
        web_output_dir=sd.get("web_output_dir", ""),
        workspace_volume=sd.get("workspace_volume", "sentinel_sentinel-workspace"),
    )

    c = raw["contacts"]
    contacts = ContactsConfig(
        known_signal=c.get("known_signal", ""),
        known_telegram_chat_id=str(c.get("known_telegram_chat_id", "")),
        unknown_signal=c.get("unknown_signal", ""),
        unknown_telegram_chat_id=str(c.get("unknown_telegram_chat_id", "")),
    )

    r = raw["run"]
    run = RunConfig(
        scope=r.get("scope", "core"),
        payloads=r.get("payloads", "all"),
        vectors=r.get("vectors", "all"),
        cooldown_s=r.get("cooldown_s", 5),
        timeout_s=r.get("timeout_s", 120),
        benchmark_mode=r.get("benchmark_mode", True),
    )

    return Config(
        sentinel=sentinel,
        attacker=attacker,
        seeding=seeding,
        contacts=contacts,
        run=run,
    )


_VALID_SCOPES = {"core", "channels", "chained", "full"}


def validate_config(config: Config) -> list[str]:
    """Validate config and return a list of warnings (empty = OK)."""
    warnings = []

    if config.run.scope not in _VALID_SCOPES:
        warnings.append(
            f"Invalid scope '{config.run.scope}' — "
            f"must be one of: {', '.join(sorted(_VALID_SCOPES))}"
        )

    # Warn if channel scope but no Telegram unknown chat ID for gate tests
    if config.run.scope in ("channels", "chained", "full"):
        if not config.contacts.unknown_telegram_chat_id:
            warnings.append(
                "Telegram unknown_telegram_chat_id is empty — "
                "unknown-sender Telegram tests will be skipped"
            )

    return warnings
