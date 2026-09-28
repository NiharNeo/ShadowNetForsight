"""Deployment settings. Production startup fails closed on unsafe configuration."""
from dataclasses import dataclass
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    production: bool
    data_dir: Path
    checkpoint: Path
    trusted_hosts: tuple[str, ...]
    max_pcap_bytes: int = 250 * 1024 * 1024
    max_sessions: int = 32
    session_ttl_seconds: int = 1800

    @classmethod
    def from_env(cls):
        production = os.getenv("SHADOWNET_ENV", "development") == "production"
        hosts = tuple(x.strip() for x in os.getenv("SHADOWNET_TRUSTED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if x.strip())
        if production:
            secret = os.getenv("SHADOWNET_TOKEN_SECRET", "")
            if len(secret) < 32 or len(set(secret)) < 12:
                raise ValueError("Production requires a high-entropy SHADOWNET_TOKEN_SECRET of at least 32 characters")
            if not os.getenv("SHADOWNET_TRUSTED_HOSTS") or "*" in hosts:
                raise ValueError("Production requires explicit SHADOWNET_TRUSTED_HOSTS without a wildcard")
            fingerprint = os.getenv("SHADOWNET_CHECKPOINT_SHA256", "")
            if len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
                raise ValueError("Production requires SHADOWNET_CHECKPOINT_SHA256 for the trusted model release")
            if int(os.getenv("WEB_CONCURRENCY", "1")) != 1:
                raise ValueError("Session storage requires exactly one worker")
        return cls(production, Path(os.getenv("SHADOWNET_DATA_DIR", str(ROOT / "data"))),
                   Path(os.getenv("SHADOWNET_CHECKPOINT", str(ROOT / "models/cic2018-phase1-lstm/lstm.pt"))), hosts)
