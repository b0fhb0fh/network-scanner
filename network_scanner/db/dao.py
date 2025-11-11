from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, select, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import (
    Base,
    Tenant,
    Network,
    Scan,
    Host,
    Service,
    TenantPorts,
    TenantExclude,
    Vulnerability,
    NucleiScan,
    NucleiFinding,
)


def create_sqlite_engine(db_path: Path) -> Engine:
    engine = create_engine(f"sqlite:///{db_path}", echo=False, future=True)

    # Ensure SQLite enforces foreign key constraints (required for ON DELETE CASCADE)
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[unused-argument]
        try:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
        except Exception:
            pass

    return engine


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    # Lightweight migration: drop udp_ports column from tenant_ports if it still exists
    try:
        with engine.begin() as conn:
            info = list(conn.exec_driver_sql("PRAGMA table_info('tenant_ports')").fetchall())
            col_names = {row[1] for row in info}  # row[1] is 'name'
            if "udp_ports" in col_names:
                conn.exec_driver_sql("ALTER TABLE tenant_ports DROP COLUMN udp_ports")
    except Exception:
        # Ignore migration errors (older SQLite without DROP COLUMN or already migrated)
        pass

    # Migration: add time_discovery to service and drop danger if present
    try:
        with engine.begin() as conn:
            info = list(conn.exec_driver_sql("PRAGMA table_info('service')").fetchall())
            col_names = {row[1] for row in info}
            if "time_discovery" not in col_names:
                conn.exec_driver_sql("ALTER TABLE service ADD COLUMN time_discovery TEXT")
                # Backfill from related scan.started_at
                conn.exec_driver_sql(
                    """
                    UPDATE service
                    SET time_discovery = (
                        SELECT started_at FROM scan
                        WHERE scan.id = (SELECT h.scan_id FROM host h WHERE h.id = service.host_id)
                    )
                    WHERE time_discovery IS NULL
                    """
                )
            if "danger" in col_names:
                try:
                    conn.exec_driver_sql("ALTER TABLE service DROP COLUMN danger")
                except Exception:
                    pass
    except Exception:
        pass

    # Ensure tenant_exclude table exists (create_all above should create it for new DBs)
    # No destructive migrations here to keep it simple
    
    # Ensure vulnerability table exists (create_all above should create it for new DBs)
    # Migration: create vulnerability table if it doesn't exist
    try:
        with engine.begin() as conn:
            info = list(conn.exec_driver_sql("PRAGMA table_info('vulnerability')").fetchall())
            if not info:
                # Table doesn't exist, create it
                Base.metadata.create_all(engine, tables=[Vulnerability.__table__])
    except Exception:
        # If migration fails, try to create all tables (for new DBs)
        Base.metadata.create_all(engine)

    # Ensure nuclei tables exist (create_all above should create it for new DBs)
    try:
        with engine.begin() as conn:
            info = list(conn.exec_driver_sql("PRAGMA table_info('nuclei_scan')").fetchall())
            if not info:
                Base.metadata.create_all(engine, tables=[NucleiScan.__table__, NucleiFinding.__table__])
    except Exception:
        Base.metadata.create_all(engine, tables=[NucleiScan.__table__, NucleiFinding.__table__])


@contextmanager
def get_session(engine: Engine) -> Iterator[Session]:
    session = Session(engine, expire_on_commit=False, future=True)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def add_tenant(session: Session, name: str, description: str | None = None) -> Tenant:
    tenant = Tenant(name=name, description=description)
    session.add(tenant)
    session.flush()
    return tenant


def get_tenant_by_name(session: Session, name: str) -> Tenant | None:
    return session.scalar(select(Tenant).where(Tenant.name == name))


def add_network(session: Session, tenant: Tenant, cidr: str) -> Network:
    net = Network(tenant_id=tenant.id, cidr=cidr)
    session.add(net)
    session.flush()
    return net


def list_tenants(session: Session) -> list[Tenant]:
    return list(session.scalars(select(Tenant).order_by(Tenant.name)))


def list_networks(session: Session, tenant: Tenant | None = None) -> list[Network]:
    stmt = select(Network)
    if tenant:
        stmt = stmt.where(Network.tenant_id == tenant.id)
    return list(session.scalars(stmt.order_by(Network.tenant_id, Network.cidr)))


# --- Update/Delete helpers ---

def update_tenant(session: Session, tenant: Tenant, *, name: str | None = None, description: str | None = None) -> Tenant:
    if name is not None:
        tenant.name = name
    if description is not None:
        tenant.description = description
    session.flush()
    return tenant


def delete_tenant(session: Session, tenant: Tenant) -> None:
    session.delete(tenant)
    session.flush()


def get_network_by_id(session: Session, network_id: int) -> Network | None:
    return session.get(Network, network_id)


def update_network(session: Session, network: Network, *, cidr: str | None = None) -> Network:
    if cidr is not None:
        network.cidr = cidr
    session.flush()
    return network


def delete_network(session: Session, network: Network) -> None:
    session.delete(network)
    session.flush()


def list_scans(session: Session, tenant: Tenant | None = None) -> list[Scan]:
    stmt = select(Scan)
    if tenant:
        stmt = stmt.where(Scan.tenant_id == tenant.id)
    return list(session.scalars(stmt.order_by(Scan.started_at.desc())))


def get_scan_by_id(session: Session, scan_id: int) -> Scan | None:
    return session.get(Scan, scan_id)


def delete_scan(session: Session, scan: Scan) -> None:
    session.delete(scan)
    session.flush()


# --- Per-tenant ports configuration ---

def get_tenant_ports(session: Session, tenant: Tenant) -> TenantPorts | None:
    return session.scalar(select(TenantPorts).where(TenantPorts.tenant_id == tenant.id))


def set_tenant_ports(session: Session, tenant: Tenant, *, tcp_ports: str | None) -> TenantPorts:
    cfg = get_tenant_ports(session, tenant)
    if cfg is None:
        cfg = TenantPorts(tenant_id=tenant.id)
        session.add(cfg)
        session.flush()
    cfg.tcp_ports = tcp_ports
    session.flush()
    return cfg


# --- Per-tenant exclude targets (hosts/ranges) ---

def list_tenant_excludes(session: Session, tenant: Tenant) -> list[TenantExclude]:
    return list(session.scalars(select(TenantExclude).where(TenantExclude.tenant_id == tenant.id)))


def add_tenant_exclude(session: Session, tenant: Tenant, target: str) -> TenantExclude:
    item = TenantExclude(tenant_id=tenant.id, target=target)
    session.add(item)
    session.flush()
    return item


def get_tenant_exclude_by_id(session: Session, exclude_id: int) -> TenantExclude | None:
    return session.get(TenantExclude, exclude_id)


def update_tenant_exclude(session: Session, item: TenantExclude, *, target: str) -> TenantExclude:
    item.target = target
    session.flush()
    return item


def delete_tenant_exclude(session: Session, item: TenantExclude) -> None:
    session.delete(item)
    session.flush()


# --- Nuclei scan helpers ---


def create_nuclei_scan(
    session: Session,
    tenant: Tenant,
    *,
    scan: Scan | None = None,
    templates: str | None = None,
    target_count: int = 0,
    nuclei_version: str | None = None,
) -> NucleiScan:
    item = NucleiScan(
        tenant_id=tenant.id,
        scan_id=scan.id if scan else None,
        templates=templates,
        target_count=target_count,
        nuclei_version=nuclei_version,
    )
    session.add(item)
    session.flush()
    return item


def get_nuclei_scan_by_id(session: Session, nuclei_scan_id: int) -> NucleiScan | None:
    return session.get(NucleiScan, nuclei_scan_id)


def list_nuclei_scans(
    session: Session,
    *,
    tenant: Tenant | None = None,
    scan: Scan | None = None,
) -> list[NucleiScan]:
    stmt = select(NucleiScan)
    if tenant is not None:
        stmt = stmt.where(NucleiScan.tenant_id == tenant.id)
    if scan is not None:
        stmt = stmt.where(NucleiScan.scan_id == scan.id)
    stmt = stmt.order_by(NucleiScan.started_at.desc())
    return list(session.scalars(stmt))


def update_nuclei_scan(
    session: Session,
    nuclei_scan: NucleiScan,
    *,
    status: str | None = None,
    finished_at: datetime | None = None,
    target_count: int | None = None,
    report_path: str | None = None,
    ai_summary: str | None = None,
    nuclei_version: str | None = None,
) -> NucleiScan:
    if status is not None:
        nuclei_scan.status = status
    if finished_at is not None:
        nuclei_scan.finished_at = finished_at
    if target_count is not None:
        nuclei_scan.target_count = target_count
    if report_path is not None:
        nuclei_scan.report_path = report_path
    if ai_summary is not None:
        nuclei_scan.ai_summary = ai_summary
    if nuclei_version is not None:
        nuclei_scan.nuclei_version = nuclei_version
    session.flush()
    return nuclei_scan


def delete_nuclei_scan(session: Session, nuclei_scan: NucleiScan) -> None:
    # Explicitly delete all findings first (even though CASCADE should handle it)
    # This ensures proper cleanup and avoids potential SQLite issues
    delete_nuclei_findings_for_scan(session, nuclei_scan)
    session.delete(nuclei_scan)
    session.flush()


def add_nuclei_finding(
    session: Session,
    nuclei_scan: NucleiScan,
    *,
    host: Host | None,
    target: str,
    template_id: str | None,
    template_name: str | None,
    severity: str | None,
    description: str | None,
    evidence: str | None,
    references: str | None,
    tags: str | None,
    matched_url: str | None,
    matched_at: datetime | None = None,
) -> NucleiFinding:
    finding = NucleiFinding(
        nuclei_scan_id=nuclei_scan.id,
        host_id=host.id if host else None,
        target=target,
        template_id=template_id,
        template_name=template_name,
        severity=severity,
        description=description,
        evidence=evidence,
        references=references,
        tags=tags,
        matched_url=matched_url,
        matched_at=matched_at or datetime.now(timezone.utc),
    )
    session.add(finding)
    session.flush()
    return finding


def list_nuclei_findings(
    session: Session,
    nuclei_scan: NucleiScan,
    *,
    severity: str | None = None,
) -> list[NucleiFinding]:
    stmt = select(NucleiFinding).where(NucleiFinding.nuclei_scan_id == nuclei_scan.id)
    if severity:
        stmt = stmt.where(NucleiFinding.severity == severity)
    stmt = stmt.order_by(NucleiFinding.matched_at.desc())
    return list(session.scalars(stmt))


def delete_nuclei_findings_for_scan(session: Session, nuclei_scan: NucleiScan) -> None:
    for finding in session.scalars(select(NucleiFinding).where(NucleiFinding.nuclei_scan_id == nuclei_scan.id)):
        session.delete(finding)
    session.flush()

