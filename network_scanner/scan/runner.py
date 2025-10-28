from __future__ import annotations

import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Iterable

from network_scanner.config.settings import Settings
from network_scanner.db.dao import create_sqlite_engine, get_session, init_db, get_tenant_by_name
from network_scanner.db.models import Scan, Host, Service
from network_scanner.parsers.nmap_xml import parse_nmap_xml_into_db


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")

def run_scan_for_tenant(settings: Settings, tenant_name: str, mode: str = "tcp") -> None:
    import masscan  # python-masscan

    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    with get_session(engine) as s:
        tenant = get_tenant_by_name(s, tenant_name)
        if not tenant:
            raise ValueError(f"Tenant '{tenant_name}' not found")

        scan = Scan(tenant_id=tenant.id, mode=mode, status="running", started_at=datetime.utcnow())
        s.add(scan)
        s.flush()

        date_dir = settings.data_dir / tenant.name / datetime.utcnow().strftime("%Y%m%d")
        date_dir.mkdir(parents=True, exist_ok=True)
        
        # Compose masscan parameters
        targets: list[str] = [n.cidr for n in tenant.networks]
        if not targets:
            scan.status = "failed"
            raise ValueError("No networks configured for this tenant")
        ports_arg = "1-65535"
        if mode == "all":
            ports_arg = "1-65535,U:53,69,123,161"

        # Use python-masscan to perform the fast scan
        mas = masscan.PortScanner()
        host_spec = " ".join(targets)
        extra_args = f"--rate {settings.rate} --open-only"
        # python-masscan internally uses JSON output and exposes it as scan_result
        mas.scan(hosts=host_spec, ports=ports_arg, arguments=extra_args)
        result = getattr(mas, "scan_result", {}) or {}
        scan_data = result.get("scan", {})

        tcp_ports: set[int] = set()
        udp_ports: set[int] = set()
        hosts: set[str] = set()
        for host, entries in scan_data.items():
            hosts.add(host)
            for entry in entries or []:
                proto = entry.get("proto")
                port = entry.get("port")
                if isinstance(port, int):
                    if proto == "tcp":
                        tcp_ports.add(port)
                    elif proto == "udp":
                        udp_ports.add(port)

        if not hosts:
            scan.status = "done"
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_file = Path(tmpdir) / "hosts.txt"
            hosts_file.write_text("\n".join(sorted(hosts)), encoding="utf-8")

            nmap_args: list[str] = [settings.nmap_path, "--open", "-n", "-PN", "-oX", str(date_dir / "nmap.xml")]
            if tcp_ports:
                nmap_args += ["-p", f"T:{','.join(str(p) for p in sorted(tcp_ports))}" + (f"U:{','.join(str(p) for p in sorted(udp_ports))}" if udp_ports else "")]
                nmap_args = [settings.nmap_path, "-sS", "-sU", *nmap_args[2:]] if udp_ports else [settings.nmap_path, "-sS", *nmap_args[2:]]
            elif udp_ports:
                nmap_args = [settings.nmap_path, "-sU", "--open", "-n", "-PN", "-oX", str(date_dir / "nmap.xml"), "-p", f"U:{','.join(str(p) for p in sorted(udp_ports))}"]
            else:
                scan.status = "done"
                return

            nmap_args += ["-iL", str(hosts_file)]
            _run(nmap_args)

        parse_nmap_xml_into_db(engine, date_dir / "nmap.xml", scan_id=scan.id)
        scan.status = "done"


