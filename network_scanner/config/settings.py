from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class Settings:
    sqlite_path: Path = Path(os.getenv("NETWORK_SCANNER_DB", "./scanner.sqlite"))
    data_dir: Path = Path(os.getenv("NETWORK_SCANNER_DATA", "./data"))
    rate: int = int(os.getenv("NETWORK_SCANNER_RATE", "2048"))
    masscan_path: str = os.getenv("NETWORK_SCANNER_MASSCAN", "masscan")
    nmap_path: str = os.getenv("NETWORK_SCANNER_NMAP", "nmap")

    @staticmethod
    def load(config_path: Optional[str] = None) -> "Settings":
        settings = Settings()
        if config_path and Path(config_path).exists():
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            if "sqlite_path" in cfg:
                settings.sqlite_path = Path(cfg["sqlite_path"])  # type: ignore[assignment]
            if "data_dir" in cfg:
                settings.data_dir = Path(cfg["data_dir"])  # type: ignore[assignment]
            if "rate" in cfg:
                settings.rate = int(cfg["rate"])  # type: ignore[assignment]
            if "masscan_path" in cfg:
                settings.masscan_path = str(cfg["masscan_path"])  # type: ignore[assignment]
            if "nmap_path" in cfg:
                settings.nmap_path = str(cfg["nmap_path"])  # type: ignore[assignment]
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        return settings


