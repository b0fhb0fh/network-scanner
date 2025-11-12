from __future__ import annotations

import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.engine import Engine

import requests

from network_scanner.config.settings import Settings
from network_scanner.db.dao import (
    get_session,
    get_tenant_by_name,
    get_scan_by_id,
    create_nuclei_scan,
    update_nuclei_scan,
    add_nuclei_finding,
)
from network_scanner.db.models import Host, Service, NucleiScan
from network_scanner.parsers.nuclei_json import NucleiFindingRecord, load_nuclei_results


def _infer_scheme(service: Service) -> str | None:
    port = service.port
    name = (service.name or "").lower()
    product = (service.product or "").lower()
    if port in {443, 8443, 9443, 10443, 4443} or "https" in name or "https" in product or "ssl" in name or "tls" in name:
        return "https"
    if port in {80, 8080, 8000, 8888, 8081, 81} or "http" in name or "http" in product:
        return "http"
    return None


def _build_target(host: Host, service: Service) -> str:
    scheme = _infer_scheme(service)
    # Clean hostname/IP from any whitespace, %, and other unwanted characters
    def clean_str(s: str) -> str:
        """Remove all % characters and strip whitespace."""
        return s.replace("%", "").strip()
    
    hostname_raw = (host.hostname or "").strip() or host.ip.strip()
    hostname = clean_str(hostname_raw)
    
    if scheme:
        default_port = 80 if scheme == "http" else 443
        if service.port == default_port:
            return f"{scheme}://{hostname}"
        return f"{scheme}://{hostname}:{service.port}"
    return f"{hostname}:{service.port}"


def _collect_targets(pairs: Sequence[tuple[Host, Service]]) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for host, service in pairs:
        target = _build_target(host, service)
        # Clean target from any % characters and whitespace
        target = target.replace("%", "").strip()
        if target and target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def _generate_ai_summary(settings: Settings, tenant_name: str, findings: list[NucleiFindingRecord]) -> str | None:
    if not settings.ai_enabled or not settings.ai_api_url or not settings.ai_api_key:
        return None
    if not findings:
        return None

    subset = findings[: min(len(findings), 100)]
    payload = [
        {
            "target": rec.target,
            "template_id": rec.template_id,
            "template_name": rec.template_name,
            "severity": rec.severity,
            "description": rec.description,
            "references": rec.references,
            "tags": rec.tags,
            "matched_url": rec.matched_url,
            "evidence": rec.evidence,
        }
        for rec in subset
    ]

    prompt = (
        "Ты аналитик по безопасности. Проанализируй результаты nuclei-сканирования для клиента "
        f"'{tenant_name}' и подготовь краткий отчет на русском языке. "
        "Структура отчета:\n"
        "1. Краткое резюме (общее количество находок, количество критичных/высоких/средних/низких).\n"
        "2. Табличный список ключевых уязвимостей (template, цель, серьезность, краткое описание).\n"
        "3. Рекомендации по устранению (группировать по уровню критичности).\n"
        "Используй данные (JSON):\n"
        f"{json.dumps(payload, ensure_ascii=False)}"
    )

    headers = {
        "Authorization": f"Bearer {settings.ai_api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": settings.ai_model,
        "messages": [
            {"role": "system", "content": "Ты эксперт по кибербезопасности и анализу уязвимостей."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.4,
        "max_tokens": 1200,
    }

    try:
        response = requests.post(settings.ai_api_url, headers=headers, json=body, timeout=60)
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            message = choices[0].get("message") or {}
            content = message.get("content")
            if isinstance(content, str):
                return content.strip()
    except Exception:
        return None
    return None


def run_nuclei_scan_for_scan(
    engine: Engine,
    settings: Settings,
    tenant_name: str,
    scan_id: int,
    output_dir: Path,
    logger,
) -> None:
    templates = [tpl.strip() for tpl in (settings.nuclei_templates or "").split(",") if tpl.strip()]
    if not templates:
        templates = ["http/cves"]

    with get_session(engine) as session:
        tenant = get_tenant_by_name(session, tenant_name)
        scan = get_scan_by_id(session, scan_id)
        if not tenant or not scan:
            logger.error("Nuclei: tenant or scan not found (tenant=%s, scan_id=%s)", tenant_name, scan_id)
            return

        result = session.execute(
            select(Host, Service)
            .join(Service, Service.host_id == Host.id)
            .where(Host.scan_id == scan_id)
        )
        pairs = [(row[0], row[1]) for row in result]
        
        # Clean host data before processing - remove % from IP and hostname
        cleaned_pairs = []
        for host, service in pairs:
            # Clean IP and hostname directly from database objects
            if host.ip:
                host.ip = host.ip.replace("%", "").strip()
            if host.hostname:
                host.hostname = host.hostname.replace("%", "").strip()
            cleaned_pairs.append((host, service))
        
        targets = _collect_targets(cleaned_pairs)
        
        # Log targets for debugging
        if logger:
            logger.debug("Collected %d targets for nuclei scan", len(targets))
            if targets:
                logger.debug("First few targets: %s", targets[:3])

        nuclei_scan = create_nuclei_scan(
            session,
            tenant,
            scan=scan,
            templates=",".join(templates),
            target_count=len(targets),
        )
        nuclei_scan_id = nuclei_scan.id

    if not targets:
        with get_session(engine) as session:
            nuclei_scan_db = session.get(NucleiScan, nuclei_scan_id)
            if nuclei_scan_db:
                update_nuclei_scan(
                    session,
                    nuclei_scan_db,
                    status="done",
                    finished_at=datetime.now(timezone.utc),
                    target_count=0,
                )
        logger.info("Nuclei: no suitable targets for tenant %s scan %s", tenant_name, scan_id)
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"nuclei_{timestamp}.json"
    log_path = output_dir / f"nuclei_{timestamp}.log"

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_file = Path(tmpdir) / "targets.txt"
        # Filter empty targets and join with newlines
        cleaned_targets = [t.strip() for t in targets if t.strip()]
        targets_content = "\n".join(cleaned_targets)
        
        if logger:
            logger.debug("Writing %d targets to file", len(cleaned_targets))
            if cleaned_targets:
                logger.debug("Last target: %r", cleaned_targets[-1] if cleaned_targets else None)
        
        targets_file.write_text(targets_content, encoding="utf-8")

        cmd = [
            settings.nuclei_path,
            "-list",
            str(targets_file),
            "-json-export",
            str(report_path),
            "-silent",
        ]
        for tpl in templates:
            cmd.extend(["-t", tpl])
        if settings.nuclei_socks5_proxy and settings.nuclei_socks5_proxy.lower() not in {"none", "null", ""}:
            cmd.extend(["-proxy", settings.nuclei_socks5_proxy])

        logger.info("Nuclei command: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.nuclei_timeout_sec or None,
            )
            returncode = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            returncode = -1
            # exc.stdout and exc.stderr may be bytes, decode them to strings
            if exc.stdout is not None:
                stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout)
            else:
                stdout = ""
            if exc.stderr is not None:
                stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr)
                stderr += "\nTimeout expired"
            else:
                stderr = "Timeout expired"

    log_path.write_text(
        f"CMD: {' '.join(cmd)}\nRETURN: {returncode}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}",
        encoding="utf-8",
    )

    records: list[NucleiFindingRecord] = []
    if report_path.exists():
        records = load_nuclei_results(report_path)

    status = "done" if returncode == 0 else "failed"
    summary: str | None = None
    if status == "done":
        summary = _generate_ai_summary(settings, tenant_name, records)

    with get_session(engine) as session:
        nuclei_scan_db = session.get(NucleiScan, nuclei_scan_id)
        if nuclei_scan_db:
            update_nuclei_scan(
                session,
                nuclei_scan_db,
                status=status,
                finished_at=datetime.now(timezone.utc),
                report_path=str(report_path),
                ai_summary=summary,
                target_count=len(targets),
            )

            hosts: dict[str, Host] = {}
            for host in session.scalars(select(Host).where(Host.scan_id == scan_id)):
                hosts[host.ip] = host
                if host.hostname:
                    hosts[host.hostname] = host

            for record in records:
                host_obj = hosts.get(record.ip or "") or hosts.get(record.host or "")
                references = "\n".join(record.references) if record.references else None
                tags = ",".join(record.tags) if record.tags else None
                add_nuclei_finding(
                    session,
                    nuclei_scan_db,
                    host=host_obj,
                    target=record.target,
                    template_id=record.template_id,
                    template_name=record.template_name,
                    severity=(record.severity or "").upper() or None,
                    description=record.description,
                    evidence=record.evidence,
                    references=references,
                    tags=tags,
                    matched_url=record.matched_url,
                    matched_at=record.matched_at,
                )

    logger.info(
        "Nuclei scan finished: tenant=%s scan_id=%s status=%s findings=%d report=%s",
        tenant_name,
        scan_id,
        status,
        len(records),
        str(report_path),
    )
