from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional
import json


@dataclass(slots=True)
class NucleiFindingRecord:
    target: str
    template_id: Optional[str]
    template_name: Optional[str]
    severity: Optional[str]
    description: Optional[str]
    evidence: Optional[str]
    references: list[str]
    tags: list[str]
    matched_at: Optional[datetime]
    matched_url: Optional[str]
    host: Optional[str]
    ip: Optional[str]
    matcher_name: Optional[str]
    raw: dict[str, Any]


def _iter_json_objects(path: Path) -> Iterator[dict[str, Any]]:
    """
    Yield JSON objects from the nuclei report.
    Handles both newline-delimited JSON and single JSON array.
    """
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return

    # Try to detect NDJSON (newline separated objects)
    if "\n" in text and text.lstrip().startswith("{"):
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
        return

    # Fallback: assume JSON array
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for obj in data:
                if isinstance(obj, dict):
                    yield obj
        elif isinstance(data, dict):
            yield data
    except json.JSONDecodeError:
        return


def _normalize_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return None


def _to_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if v]
    return []


def load_nuclei_results(report_path: Path | str) -> list[NucleiFindingRecord]:
    """
    Parse nuclei JSON report into structured records.
    """
    path = Path(report_path)
    findings: list[NucleiFindingRecord] = []

    for raw in _iter_json_objects(path):
        info = raw.get("info", {}) if isinstance(raw, dict) else {}
        if not isinstance(info, dict):
            info = {}
        references = _to_list(info.get("reference") or info.get("references"))
        tags = _to_list(info.get("tags"))
        evidence_chunks: list[str] = []
        for key in ("extracted-results", "extracted_results", "extracted"):
            value = raw.get(key)
            evidence_chunks.extend(_to_list(value))
        if "matched-line" in raw:
            evidence_chunks.extend(_to_list(raw.get("matched-line")))
        if "matcher-name" in raw:
            evidence_chunks.append(str(raw.get("matcher-name")))
        evidence = "\n".join(evidence_chunks) if evidence_chunks else None

        record = NucleiFindingRecord(
            target=str(raw.get("host") or raw.get("matched-at") or raw.get("url") or raw.get("ip") or ""),
            template_id=str(raw.get("template-id") or raw.get("templateID") or info.get("id") or ""),
            template_name=str(info.get("name") or raw.get("template") or raw.get("name") or "") or None,
            severity=(info.get("severity") or raw.get("severity")),
            description=info.get("description") or raw.get("description"),
            evidence=evidence,
            references=references,
            tags=tags,
            matched_at=_normalize_datetime(raw.get("timestamp") or raw.get("matched-at")),
            matched_url=str(raw.get("matched-at") or raw.get("url") or raw.get("host") or "") or None,
            host=str(raw.get("host") or raw.get("hostname") or None),
            ip=str(raw.get("ip") or raw.get("ip-address") or None),
            matcher_name=str(raw.get("matcher-name") or raw.get("matcher_name") or None),
            raw=raw if isinstance(raw, dict) else {},
        )
        findings.append(record)

    return findings

