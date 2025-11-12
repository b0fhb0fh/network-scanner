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
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_significant_threshold: float = 0.1
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Nuclei settings
    nuclei_path: str = "nuclei"
    nuclei_templates: str = "http/cves,ssl"
    nuclei_timeout_sec: int = 1800
    nuclei_socks5_proxy: Optional[str] = None
    # AI summarization (optional)
    ai_api_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_model: str = "gpt-4o-mini"
    ai_enabled: bool = False
    ai_temperature: float = 0.4
    ai_max_tokens: int = 1200

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
        def cfg_get(*names: str) -> Optional[str]:
            for name in names:
                value = file_cfg.get(name)
                if value is not None:
                    return value
            return None

        if file_cfg:
            sqlite_path_val = cfg_get("sqlite_path", "SQLITE_PATH")
            if sqlite_path_val:
                settings.sqlite_path = Path(sqlite_path_val)  # type: ignore[assignment]

            data_dir_val = cfg_get("data_dir", "DATA_DIR")
            if data_dir_val:
                settings.data_dir = Path(data_dir_val)  # type: ignore[assignment]

            rate_val = cfg_get("rate", "RATE")
            if rate_val:
                try:
                    settings.rate = int(rate_val)  # type: ignore[assignment]
                except ValueError:
                    pass

            nmap_path_val = cfg_get("nmap_path", "NMAP_PATH")
            if nmap_path_val:
                settings.nmap_path = nmap_path_val  # type: ignore[assignment]

            tcp_ports_val = cfg_get("tcp_ports_default", "TCP_PORTS_DEFAULT")
            if tcp_ports_val is not None:
                settings.tcp_ports_default = tcp_ports_val.strip() or None  # type: ignore[assignment]

            exclude_ports_val = cfg_get("exclude_ports", "EXCLUDE_PORTS")
            if exclude_ports_val is not None:
                settings.exclude_ports = exclude_ports_val.strip() or None  # type: ignore[assignment]

            epss_api_val = cfg_get("epss_api_url", "EPSS_API_URL")
            if epss_api_val:
                settings.epss_api_url = epss_api_val  # type: ignore[assignment]

            epss_threshold_val = cfg_get("epss_significant_threshold", "EPSS_SIGNIFICANT_THRESHOLD")
            if epss_threshold_val:
                try:
                    settings.epss_significant_threshold = float(epss_threshold_val)  # type: ignore[assignment]
                except ValueError:
                    pass

            nvd_url_val = cfg_get("nvd_api_url", "NVD_API_URL")
            if nvd_url_val:
                settings.nvd_api_url = nvd_url_val  # type: ignore[assignment]

            nuclei_path_val = cfg_get("NUCLEI_PATH", "nuclei_path")
            if nuclei_path_val:
                settings.nuclei_path = nuclei_path_val  # type: ignore[assignment]

            nuclei_templates_val = cfg_get("NUCLEI_TEMPLATES", "nuclei_templates")
            if nuclei_templates_val:
                settings.nuclei_templates = nuclei_templates_val  # type: ignore[assignment]

            nuclei_timeout_val = cfg_get("NUCLEI_TIMEOUT_SEC", "nuclei_timeout_sec")
            if nuclei_timeout_val:
                try:
                    settings.nuclei_timeout_sec = int(nuclei_timeout_val)  # type: ignore[assignment]
                except ValueError:
                    pass

            nuclei_proxy_val = cfg_get("NUCLEI_SOCKS5_PROXY", "nuclei_socks5_proxy")
            if nuclei_proxy_val is not None:
                nuclei_proxy_val = nuclei_proxy_val.strip()
                # Treat empty string, "None", "null" as None
                if not nuclei_proxy_val or nuclei_proxy_val.lower() in {"none", "null", ""}:
                    settings.nuclei_socks5_proxy = None  # type: ignore[assignment]
                else:
                    settings.nuclei_socks5_proxy = nuclei_proxy_val  # type: ignore[assignment]

            ai_api_url_val = cfg_get("AI_API_URL", "ai_api_url")
            if ai_api_url_val is not None:
                settings.ai_api_url = ai_api_url_val.strip() or None  # type: ignore[assignment]

            ai_api_key_val = cfg_get("AI_API_KEY", "ai_api_key")
            if ai_api_key_val is not None:
                settings.ai_api_key = ai_api_key_val.strip() or None  # type: ignore[assignment]

            ai_model_val = cfg_get("AI_MODEL", "ai_model")
            if ai_model_val:
                settings.ai_model = ai_model_val  # type: ignore[assignment]

            ai_enabled_val = cfg_get("AI_ENABLED", "ai_enabled")
            if ai_enabled_val is not None:
                settings.ai_enabled = ai_enabled_val.strip().lower() in {"1", "true", "yes"}  # type: ignore[assignment]

            ai_temperature_val = cfg_get("AI_TEMPERATURE", "ai_temperature")
            if ai_temperature_val is not None:
                try:
                    settings.ai_temperature = float(ai_temperature_val)
                except ValueError:
                    pass

            ai_max_tokens_val = cfg_get("AI_MAX_TOKENS", "ai_max_tokens")
            if ai_max_tokens_val is not None:
                try:
                    settings.ai_max_tokens = int(ai_max_tokens_val)
                except ValueError:
                    pass

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
            "epss_api_url": os.environ.get("NETWORK_SCANNER_EPSS_API_URL")
                or os.environ.get("EPSS_API_URL")
                or os.environ.get("epss_api_url"),
            "epss_significant_threshold": os.environ.get("NETWORK_SCANNER_EPSS_SIGNIFICANT_THRESHOLD")
                or os.environ.get("EPSS_SIGNIFICANT_THRESHOLD")
                or os.environ.get("epss_significant_threshold"),
            "nvd_api_url": os.environ.get("NETWORK_SCANNER_NVD_API_URL")
                or os.environ.get("NVD_API_URL")
                or os.environ.get("nvd_api_url"),
            # Nuclei
            "nuclei_path": os.environ.get("NUCLEI_PATH"),
            "nuclei_templates": os.environ.get("NUCLEI_TEMPLATES"),
            "nuclei_timeout_sec": os.environ.get("NUCLEI_TIMEOUT_SEC"),
            "nuclei_socks5_proxy": os.environ.get("NUCLEI_SOCKS5_PROXY"),
            # AI
            "ai_api_url": os.environ.get("AI_API_URL"),
            "ai_api_key": os.environ.get("AI_API_KEY"),
            "ai_model": os.environ.get("AI_MODEL"),
            "ai_enabled": os.environ.get("AI_ENABLED"),
            "ai_temperature": os.environ.get("AI_TEMPERATURE"),
            "ai_max_tokens": os.environ.get("AI_MAX_TOKENS"),
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
        if env_overrides["epss_api_url"]:
            settings.epss_api_url = str(env_overrides["epss_api_url"])  # type: ignore[assignment]
        if env_overrides["epss_significant_threshold"]:
            try:
                settings.epss_significant_threshold = float(str(env_overrides["epss_significant_threshold"]))  # type: ignore[assignment]
            except ValueError:
                pass
        if env_overrides["nvd_api_url"]:
            settings.nvd_api_url = str(env_overrides["nvd_api_url"])  # type: ignore[assignment]
        # Nuclei
        if env_overrides["nuclei_path"]:
            settings.nuclei_path = str(env_overrides["nuclei_path"])  # type: ignore[assignment]
        if env_overrides["nuclei_templates"]:
            settings.nuclei_templates = str(env_overrides["nuclei_templates"])  # type: ignore[assignment]
        if env_overrides["nuclei_timeout_sec"]:
            try:
                settings.nuclei_timeout_sec = int(str(env_overrides["nuclei_timeout_sec"]))  # type: ignore[assignment]
            except ValueError:
                pass
        if env_overrides["nuclei_socks5_proxy"]:
            proxy_val = str(env_overrides["nuclei_socks5_proxy"]).strip()
            # Treat empty string, "None", "null" as None
            if not proxy_val or proxy_val.lower() in {"none", "null", ""}:
                settings.nuclei_socks5_proxy = None  # type: ignore[assignment]
            else:
                settings.nuclei_socks5_proxy = proxy_val  # type: ignore[assignment]
        # AI
        if env_overrides["ai_api_url"]:
            settings.ai_api_url = str(env_overrides["ai_api_url"]).strip() or None  # type: ignore[assignment]
        if env_overrides["ai_api_key"]:
            settings.ai_api_key = str(env_overrides["ai_api_key"]).strip() or None  # type: ignore[assignment]
        if env_overrides["ai_model"]:
            settings.ai_model = str(env_overrides["ai_model"])  # type: ignore[assignment]
        if env_overrides["ai_enabled"]:
            settings.ai_enabled = str(env_overrides["ai_enabled"]).lower() in {"1", "true", "yes"}  # type: ignore[assignment]
        if env_overrides["ai_temperature"]:
            try:
                settings.ai_temperature = float(str(env_overrides["ai_temperature"]))
            except ValueError:
                pass
        if env_overrides["ai_max_tokens"]:
            try:
                settings.ai_max_tokens = int(str(env_overrides["ai_max_tokens"]))
            except ValueError:
                pass

        settings.data_dir.mkdir(parents=True, exist_ok=True)
        return settings


