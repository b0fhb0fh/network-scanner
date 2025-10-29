from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class Settings:
    sqlite_path: Path = Path("./scanner.sqlite")
    data_dir: Path = Path("./data")
    rate: int = 2048
    nmap_path: str = "nmap"
    tcp_ports_default: Optional[str] = None

    @staticmethod
    def load(config_path: Optional[str] = None) -> "Settings":
        settings = Settings()
        if config_path and Path(config_path).exists():
            # .env parser: key=value, ignore comments (#/;) and blank lines
            cfg: dict[str, str] = {}
            with open(config_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    if "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    cfg[key.strip()] = value.strip()
            if "sqlite_path" in cfg:
                settings.sqlite_path = Path(cfg["sqlite_path"])  # type: ignore[assignment]
            if "data_dir" in cfg:
                settings.data_dir = Path(cfg["data_dir"])  # type: ignore[assignment]
            if "rate" in cfg:
                try:
                    settings.rate = int(cfg["rate"])  # type: ignore[assignment]
                except ValueError:
                    pass
            if "nmap_path" in cfg:
                settings.nmap_path = str(cfg["nmap_path"])  # type: ignore[assignment]
            if "tcp_ports_default" in cfg:
                settings.tcp_ports_default = (cfg["tcp_ports_default"].strip() or None)  # type: ignore[assignment]
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        return settings


