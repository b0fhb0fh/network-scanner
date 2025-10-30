from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional


@dataclass
class Settings:
    sqlite_path: Path = Path("./scanner.sqlite")
    data_dir: Path = Path("./data")
    rate: int = 2048
    nmap_path: str = "nmap"
    tcp_ports_default: Optional[str] = None
    exclude_ports: Optional[str] = None

    @staticmethod
    def load(config_path: Optional[str] = None) -> "Settings":
        def parse_kv_file(path: Path) -> dict[str, str]:
            cfg: dict[str, str] = {}
            try:
                with open(path, "r", encoding="utf-8") as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        if not line or line.startswith("#") or line.startswith(";"):
                            continue
                        if "=" not in line:
                            continue
                        key, value = line.split("=", 1)
                        cfg[key.strip()] = value.strip()
            except Exception:
                pass
            return cfg

        settings = Settings()

        # 1) Load from explicit config if provided
        file_cfg: dict[str, str] = {}
        if config_path and Path(config_path).exists():
            file_cfg = parse_kv_file(Path(config_path))
        else:
            # 2) Load from .env if present
            env_file = Path(".env")
            if env_file.exists():
                file_cfg = parse_kv_file(env_file)

        # Apply file config
        if file_cfg:
            if "sqlite_path" in file_cfg:
                settings.sqlite_path = Path(file_cfg["sqlite_path"])  # type: ignore[assignment]
            if "data_dir" in file_cfg:
                settings.data_dir = Path(file_cfg["data_dir"])  # type: ignore[assignment]
            if "rate" in file_cfg:
                try:
                    settings.rate = int(file_cfg["rate"])  # type: ignore[assignment]
                except ValueError:
                    pass
            if "nmap_path" in file_cfg:
                settings.nmap_path = str(file_cfg["nmap_path"])  # type: ignore[assignment]
            if "tcp_ports_default" in file_cfg:
                settings.tcp_ports_default = (file_cfg["tcp_ports_default"].strip() or None)  # type: ignore[assignment]
            if "exclude_ports" in file_cfg:
                settings.exclude_ports = (file_cfg["exclude_ports"].strip() or None)  # type: ignore[assignment]

        # 3) Override from environment variables if present
        env_overrides = {
            "sqlite_path": os.environ.get("NETWORK_SCANNER_DB") or os.environ.get("SQLITE_PATH"),
            "data_dir": os.environ.get("NETWORK_SCANNER_DATA") or os.environ.get("DATA_DIR"),
            "rate": os.environ.get("NETWORK_SCANNER_RATE") or os.environ.get("RATE"),
            "nmap_path": os.environ.get("NETWORK_SCANNER_NMAP") or os.environ.get("NMAP_PATH"),
            # support multiple env names for default tcp ports
            "tcp_ports_default": os.environ.get("NETWORK_SCANNER_TCP_PORTS_DEFAULT")
                or os.environ.get("TCP_PORTS_DEFAULT")
                or os.environ.get("tcp_ports_default"),
            "exclude_ports": os.environ.get("NETWORK_SCANNER_EXCLUDE_PORTS")
                or os.environ.get("EXCLUDE_PORTS")
                or os.environ.get("exclude_ports"),
        }
        if env_overrides["sqlite_path"]:
            settings.sqlite_path = Path(str(env_overrides["sqlite_path"]))  # type: ignore[assignment]
        if env_overrides["data_dir"]:
            settings.data_dir = Path(str(env_overrides["data_dir"]))  # type: ignore[assignment]
        if env_overrides["rate"]:
            try:
                settings.rate = int(str(env_overrides["rate"]))  # type: ignore[assignment]
            except ValueError:
                pass
        if env_overrides["nmap_path"]:
            settings.nmap_path = str(env_overrides["nmap_path"])  # type: ignore[assignment]
        if env_overrides["tcp_ports_default"]:
            settings.tcp_ports_default = (str(env_overrides["tcp_ports_default"]).strip() or None)  # type: ignore[assignment]
        if env_overrides["exclude_ports"]:
            settings.exclude_ports = (str(env_overrides["exclude_ports"]).strip() or None)  # type: ignore[assignment]

        settings.data_dir.mkdir(parents=True, exist_ok=True)
        return settings


