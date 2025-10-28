from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import Base, Tenant, Network, Scan, Host, Service


def create_sqlite_engine(db_path: Path) -> Engine:
    return create_engine(f"sqlite:///{db_path}", echo=False, future=True)


def init_db(engine: Engine) -> None:
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


