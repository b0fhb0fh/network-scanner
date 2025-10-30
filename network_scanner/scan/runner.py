from __future__ import annotations

import subprocess
import tempfile
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Iterable

from network_scanner.config.settings import Settings
from network_scanner.config.logging_utils import get_app_logger
from network_scanner.db.dao import create_sqlite_engine, get_session, init_db, get_tenant_by_name, get_tenant_ports, list_tenant_excludes
from network_scanner.db.models import Scan, Host, Service
from network_scanner.parsers.nmap_xml import parse_nmap_xml_into_db


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

def run_scan_for_tenant(settings: Settings, tenant_name: str, mode: str = "tcp", service_info: bool = False) -> None:
    import masscan  # python-masscan

    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    logger = get_app_logger(settings)
    with get_session(engine) as s:
        tenant = get_tenant_by_name(s, tenant_name)
        if not tenant:
            raise ValueError(f"Tenant '{tenant_name}' not found")

        scan = Scan(tenant_id=tenant.id, mode=mode, status="running", started_at=datetime.now(timezone.utc))
        s.add(scan)
        s.flush()

        date_dir = settings.data_dir / tenant.name / datetime.now(timezone.utc).strftime("%Y%m%d")
        date_dir.mkdir(parents=True, exist_ok=True)
        
        # Compose masscan parameters
        targets: list[str] = [n.cidr for n in tenant.networks]
        if not targets:
            scan.status = "failed"
            raise ValueError("No networks configured for this tenant")
        logger.info("Scan started: tenant=%s mode=%s targets=%s", tenant.name, mode, ",".join(targets))
        # Per-tenant port configuration (overrides defaults if present)
        cfg = get_tenant_ports(s, tenant)
        if mode == "all":
            ports_arg = "1-65535"
            logger.info("Mode 'all' selected: using full TCP range 1-65535")
        else:
            if cfg and cfg.tcp_ports:
                ports_arg = cfg.tcp_ports.strip()
            elif settings.tcp_ports_default:
                ports_arg = settings.tcp_ports_default
            else:
                ports_arg = "1-65535"
                logger.info("No tenant TCP ports or default configured; falling back to 1-65535")

        # Use python-masscan to perform the fast scan
        mas = masscan.PortScanner()
        host_spec = " ".join(targets)
        extra_args = f"--rate {settings.rate} --open-only"
        # Apply per-tenant excludes to masscan via --exclude
        excludes = [it.target for it in list_tenant_excludes(s, tenant)]
        if excludes:
            extra_args = f"{extra_args} --exclude {','.join(sorted(set(excludes)))}"
        logger.info("Masscan params: hosts='%s' ports='%s' args='%s'", host_spec, ports_arg, extra_args)
        # python-masscan internally uses JSON output and exposes it as scan_result
        mas.scan(hosts=host_spec, ports=ports_arg, arguments=extra_args)
        raw_result = getattr(mas, "scan_result", {}) or {}
        # scan_result can be either a dict or a JSON string depending on library/version
        if isinstance(raw_result, str):
            try:
                result = json.loads(raw_result)
            except Exception:
                result = {}
        elif isinstance(raw_result, dict):
            result = raw_result
        else:
            result = {}

        scan_data = result.get("scan", {}) or {}

        # Persist full masscan result for traceability
        try:
            (date_dir / "masscan.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            logger.info("Masscan result saved: %s", str(date_dir / "masscan.json"))
        except Exception as e:
            logger.info("Masscan result save failed: %s", str(e))

        def _extract_ports(entries: object) -> tuple[set[int], set[int]]:
            tcp: set[int] = set()
            udp: set[int] = set()
            # Format A: list of {proto, port}
            if isinstance(entries, list):
                for item in entries:
                    if isinstance(item, dict):
                        proto = item.get("proto")
                        port = item.get("port")
                        if isinstance(port, int):
                            if proto == "tcp":
                                tcp.add(port)
                            elif proto == "udp":
                                udp.add(port)
                return tcp, udp
            # Format B: dict with proto keys mapping to {port: {...}}
            if isinstance(entries, dict):
                for proto_key, ports_dict in entries.items():
                    if proto_key not in ("tcp", "udp"):
                        continue
                    if isinstance(ports_dict, dict):
                        for port_key in ports_dict.keys():
                            try:
                                p = int(port_key)
                            except Exception:
                                continue
                            if proto_key == "tcp":
                                tcp.add(p)
                            else:
                                udp.add(p)
                return tcp, udp
            return tcp, udp

        tcp_ports: set[int] = set()
        hosts: set[str] = set()
        for host, entries in scan_data.items():
            hosts.add(host)
            h_tcp, _ = _extract_ports(entries)
            tcp_ports.update(h_tcp)

        logger.info(
            "Masscan discovered: hosts=%d tcp_ports=%d",
            len(hosts),
            len(tcp_ports),
        )

        # Log concise per-host summary (limited to first 20 hosts to keep logs readable)
        try:
            summary_lines: list[str] = []
            for host in sorted(list(hosts))[:20]:
                entries = scan_data.get(host, []) or []
                h_tcp, _ = _extract_ports(entries)
                tcp_list = sorted(list(h_tcp))
                parts: list[str] = []
                if tcp_list:
                    parts.append(f"tcp:{','.join(str(p) for p in tcp_list)}")
                ports_repr = " ".join(parts) if parts else "(no open ports)"
                summary_lines.append(f"{host} -> {ports_repr}")
            if len(hosts) > 20:
                summary_lines.append(f"... and {len(hosts) - 20} more hosts")
            if summary_lines:
                logger.info("Masscan hosts summary:\n%s", "\n".join(summary_lines))
        except Exception as e:
            logger.info("Masscan summary build failed: %s", str(e))

        if not hosts:
            scan.status = "done"
            logger.info("Scan finished: tenant=%s no open hosts found", tenant.name)
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_file = Path(tmpdir) / "hosts.txt"
            hosts_file.write_text("\n".join(sorted(hosts)), encoding="utf-8")

            nmap_args: list[str] = [settings.nmap_path, "--open", "-n", "-PN", "-oX", str(date_dir / "nmap.xml")]
            if tcp_ports:
                nmap_args = [settings.nmap_path, "-sS", *nmap_args[2:]]
                nmap_args += ["-p", f"T:{','.join(str(p) for p in sorted(tcp_ports))}"]
            else:
                scan.status = "done"
                logger.info("Scan finished: tenant=%s no ports to probe with nmap", tenant.name)
                return

            # Добавим аргумент --exclude-ports если задан в конфиге
            if settings.exclude_ports:
                nmap_args += ["--exclude-ports", settings.exclude_ports]

            # Optionally enable service/version detection
            if service_info and "-sV" not in nmap_args:
                # Put -sV right after -sS if present, else near the start
                try:
                    sS_index = nmap_args.index("-sS")
                    nmap_args.insert(sS_index + 1, "-sV")
                except ValueError:
                    nmap_args.insert(1, "-sV")

            # Apply per-tenant excludes to nmap via --exclude
            if excludes:
                nmap_args += ["--exclude", ",".join(sorted(set(excludes)))]

            nmap_args += ["-iL", str(hosts_file)]
            logger.info("Nmap params: %s", " ".join(nmap_args))
            _run(nmap_args)

        # Commit and exit transaction before parsing XML to avoid SQLite write lock conflicts
        current_scan_id = scan.id
        tenant_name_local = tenant.name
        s.commit()

    # Outside of the session: parse results and write Hosts/Services in a separate session
    try:
        parse_nmap_xml_into_db(engine, date_dir / "nmap.xml", scan_id=current_scan_id)
        parse_ok = True
    except Exception as e:
        logger.info("Parsing nmap XML failed: %s", str(e))
        parse_ok = False

    # Update scan status in a fresh session
    with get_session(engine) as s2:
        sc = s2.get(Scan, current_scan_id)
        if sc:
            sc.status = "done" if parse_ok else "failed"
            sc.finished_at = datetime.now(timezone.utc)
    if parse_ok:
        logger.info("Scan finished: tenant=%s mode=%s results saved to %s", tenant_name_local, mode, str(date_dir / "nmap.xml"))
    else:
        logger.info("Scan finished with errors: tenant=%s mode=%s (parsing failed)", tenant_name_local, mode)


