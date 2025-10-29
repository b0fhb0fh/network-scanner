from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenant"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)

    networks: Mapped[list[Network]] = relationship("Network", back_populates="tenant", cascade="all, delete-orphan")
    # optional one-to-one with ports config
    


class Network(Base):
    __tablename__ = "network"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False, index=True)

    tenant: Mapped[Tenant] = relationship("Tenant", back_populates="networks")

    __table_args__ = (
        UniqueConstraint("tenant_id", "cidr", name="uq_network_tenant_cidr"),
    )


class TenantPorts(Base):
    __tablename__ = "tenant_ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    tcp_ports: Mapped[Optional[str]] = mapped_column(String(4096), nullable=True)  # comma-separated

    tenant: Mapped[Tenant] = relationship("Tenant")


class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenant.id", ondelete="CASCADE"), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="tcp")  # tcp|all
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")  # running|done|failed

    tenant: Mapped[Tenant] = relationship("Tenant")


class Host(Base):
    __tablename__ = "host"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    __table_args__ = (
        UniqueConstraint("scan_id", "ip", name="uq_host_scan_ip"),
    )


class Service(Base):
    __tablename__ = "service"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)  # tcp|udp
    name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    extrainfo: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    good: Mapped[bool] = mapped_column(Integer, nullable=False, default=0)  # 0/1
    danger: Mapped[bool] = mapped_column(Integer, nullable=False, default=0)  # 0/1

    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol", name="uq_service_host_port_proto"),
    )


