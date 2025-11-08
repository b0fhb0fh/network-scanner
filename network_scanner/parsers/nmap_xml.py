from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from lxml import etree
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from network_scanner.db.models import Host, Service, Scan, Vulnerability
from network_scanner.db.dao import get_session
from network_scanner.vuln import extract_cves_from_nmap_xml, get_epss_score, get_cvss_data, calculate_exploit_probability
from network_scanner.config.settings import Settings


def _get_text(elem: Optional[etree._Element], attr: str, default: str = "") -> str:
    if elem is None:
        return default
    return elem.get(attr, default)


def _is_good(ip: str, proto: str, port: int, session: Session) -> bool:
    # Placeholder for future per-tenant good lists in DB
    return False



def parse_nmap_xml_into_db(engine: Engine, xml_path: Path, scan_id: int, settings: Optional[Settings] = None) -> None:
    parser = etree.XMLParser(recover=True)
    root = etree.parse(str(xml_path), parser=parser).getroot()

    with get_session(engine) as s:
        scan = s.get(Scan, scan_id)
        time_discovery = scan.started_at if scan and isinstance(scan.started_at, datetime) else datetime.now(timezone.utc)
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
                    time_discovery=time_discovery,
                )
                s.add(sv)
        
        # Parse vulnerabilities from nmap XML if vulners script was used
        if settings:
            host_cves = extract_cves_from_nmap_xml(str(xml_path))
            for host_ip, cve_list in host_cves.items():
                # Find host by IP in current scan
                host_obj = s.scalar(
                    select(Host).where(Host.scan_id == scan_id, Host.ip == host_ip)
                )
                if not host_obj:
                    continue
                
                epss_scores: list[float] = []
                for cve_id in cve_list:
                    # Check if vulnerability already exists
                    existing = s.scalar(
                        select(Vulnerability).where(
                            Vulnerability.host_id == host_obj.id,
                            Vulnerability.cve_id == cve_id
                        )
                    )
                    if existing:
                        # Update EPSS and CVSS if needed
                        if existing.epss is None:
                            epss_data = get_epss_score(settings, cve_id)
                            existing.epss = epss_data["epss"]
                            existing.percentile = epss_data["percentile"]
                        if existing.cvss_score is None or existing.cvss_score == 0.0:
                            cvss_data = get_cvss_data(settings, cve_id)
                            existing.cvss_score = cvss_data.get("baseScore", 0.0)
                            existing.cvss_vector = cvss_data.get("vector", "N/A")
                        s.flush()
                        if existing.epss is not None:
                            epss_scores.append(existing.epss)
                    else:
                        # Create new vulnerability entry
                        epss_data = get_epss_score(settings, cve_id)
                        cvss_data = get_cvss_data(settings, cve_id)
                        vuln = Vulnerability(
                            host_id=host_obj.id,
                            cve_id=cve_id,
                            epss=epss_data["epss"],
                            percentile=epss_data["percentile"],
                            cvss_score=cvss_data.get("baseScore", 0.0),
                            cvss_vector=cvss_data.get("vector", "N/A"),
                            time_discovery=time_discovery,
                        )
                        s.add(vuln)
                        if epss_data["epss"] > 0:
                            epss_scores.append(epss_data["epss"])
                
                # Calculate exploit probability for host
                if epss_scores:
                    exploit_prob = calculate_exploit_probability(
                        epss_scores, settings.epss_significant_threshold
                    )
                    # Update all vulnerabilities for this host with exploit probability
                    host_vulns = s.scalars(
                        select(Vulnerability).where(Vulnerability.host_id == host_obj.id)
                    ).all()
                    for vuln in host_vulns:
                        vuln.exploit_probability = exploit_prob
                    s.flush()


