from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, select, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import Base, Tenant, Network, Scan, Host, Service, TenantPorts, TenantExclude, Vulnerability


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

