from __future__ import annotations

from pathlib import Path
from typing import Optional

from lxml import etree
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from network_scanner.db.models import Host, Service
from network_scanner.db.dao import get_session


def _get_text(elem: Optional[etree._Element], attr: str, default: str = "") -> str:
    if elem is None:
        return default
    return elem.get(attr, default)


def _is_good(ip: str, proto: str, port: int, session: Session) -> bool:
    # Placeholder for future per-tenant good lists in DB
    return False


def _is_danger(service_name: str, proto: str, port: int, session: Session) -> bool:
    danger_services = {
        ("ftp", "tcp", 21),
        ("telnet", "tcp", 23),
        ("finger", "tcp", 79),
        ("snmp", "udp", 161),
        ("tftp", "udp", 69),
        ("mysql", "tcp", 3306),
        ("mssql", "tcp", 1433),
        ("postgres", "tcp", 5432),
        ("oracle", "tcp", 1521),
        ("microsoft-ds", "tcp", 445),
        ("netbios-ssn", "tcp", 139),
        ("nfs", "tcp", 2049),
        ("portmapper", "tcp", 111),
        ("microsoft-rdp", "tcp", 3389),
    }
    key = (service_name or "", proto, port)
    return key in danger_services


def parse_nmap_xml_into_db(engine: Engine, xml_path: Path, scan_id: int) -> None:
    parser = etree.XMLParser(recover=True)
    root = etree.parse(str(xml_path), parser=parser).getroot()

    with get_session(engine) as s:
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            addr_elem = host.find("address")
            ip = _get_text(addr_elem, "addr")
            hostnames_elem = host.find("hostnames")
            hostname = ""
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                hostname = _get_text(hn, "name")

            h = Host(scan_id=scan_id, ip=ip, hostname=hostname or None)
            s.add(h)
            s.flush()

            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                proto = _get_text(port_elem, "protocol")
                port_num = int(_get_text(port_elem, "portid", "0"))
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                service_elem = port_elem.find("service")
                name = _get_text(service_elem, "name")
                product = _get_text(service_elem, "product")
                version = _get_text(service_elem, "version")
                extrainfo = _get_text(service_elem, "extrainfo")

                sv = Service(
                    host_id=h.id,
                    port=port_num,
                    protocol=proto,
                    name=name or None,
                    product=product or None,
                    version=version or None,
                    extrainfo=extrainfo or None,
                    good=1 if _is_good(ip, proto, port_num, s) else 0,
                    danger=1 if _is_danger(name, proto, port_num, s) else 0,
                )
                s.add(sv)


