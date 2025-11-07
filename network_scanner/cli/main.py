from __future__ import annotations

import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

import importlib

from network_scanner.config.settings import Settings
from network_scanner.config.logging_utils import get_app_logger
from network_scanner.db.dao import (
    create_sqlite_engine,
    init_db,
    get_session,
    add_tenant,
    get_tenant_by_name,
    add_network,
    list_tenants,
    list_networks,
    update_tenant,
    delete_tenant,
    get_network_by_id,
    update_network,
    delete_network,
    list_scans,
    get_scan_by_id,
    delete_scan,
    get_tenant_ports,
    set_tenant_ports,
    list_tenant_excludes,
    add_tenant_exclude,
    get_tenant_exclude_by_id,
    update_tenant_exclude,
    delete_tenant_exclude,
)
from network_scanner.db.models import Scan, Host, Service
from sqlalchemy import select, desc


console = Console()


def _sanitize_filename_component(value: str) -> str:
    allowed = {"-", "_"}
    return "".join(c if c.isalnum() or c in allowed else "_" for c in value)


def _build_pdf_path(settings: Settings, tenant_name: str, report_type: str, scan_dt: datetime | None) -> Path:
    tenant_dir = settings.data_dir / tenant_name
    base_dir = tenant_dir / "reports"
    base_dir.mkdir(parents=True, exist_ok=True)
    ts = (
        scan_dt.strftime("%Y%m%d_%H%M%S")
        if isinstance(scan_dt, datetime)
        else datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    )
    filename = f"{_sanitize_filename_component(tenant_name)}_{report_type}_{ts}.pdf"
    return base_dir / filename


def _export_pdf_report(
    settings: Settings,
    tenant_name: str,
    report_type: str,
    scan_dt: datetime | None,
    title: str,
    sections: list[tuple[str, list[str]]],
) -> Path:
    FPDF_cls = _load_fpdf()
    pdf_path = _build_pdf_path(settings, tenant_name, report_type, scan_dt)
    pdf = FPDF_cls()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, title, ln=True)
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 8, f"Tenant: {tenant_name}", ln=True)
    if isinstance(scan_dt, datetime):
        pdf.cell(0, 8, f"Scan started: {scan_dt.replace(microsecond=0).isoformat(sep=' ')}", ln=True)
    pdf.ln(4)

    usable_width = getattr(pdf, "epw", pdf.w - pdf.l_margin - pdf.r_margin)

    for heading, lines in sections:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_x(pdf.l_margin)
        pdf.cell(0, 8, heading, ln=True)
        pdf.set_font("Helvetica", size=11)
        if not lines:
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 6, "(no data)", ln=True)
        else:
            for line in lines:
                wrapped = textwrap.wrap(line, width=100) or [""]
                for item in wrapped:
                    pdf.set_x(pdf.l_margin)
                    pdf.multi_cell(usable_width, 6, item or " ")
        pdf.ln(2)

    pdf.output(str(pdf_path))
    return pdf_path


def _load_fpdf():
    try:
        module = importlib.import_module("fpdf")
        FPDF_cls = getattr(module, "FPDF")
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "PDF export requires 'fpdf2' package. Install it to enable --pdf option."
        ) from exc
    return FPDF_cls


def _fmt_dt(dt: object) -> str:
    try:
        if isinstance(dt, str):
            # Trim fractional seconds if present
            return dt.split(".")[0]
        # type: ignore[attr-defined]
        return dt.replace(microsecond=0).isoformat(sep=" ")  # type: ignore[union-attr]
    except Exception:
        return str(dt) if dt is not None else ""

@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to config file (.env or key=value lines). If omitted, .env is used when present",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[Path]) -> None:
    ctx.ensure_object(dict)
    settings = Settings.load(str(config_path) if config_path else None)
    ctx.obj["settings"] = settings
    # Initialize logger and store in context
    ctx.obj["logger"] = get_app_logger(settings)
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        ctx.exit(0)


@cli.command()
@click.pass_context
def init_db_cmd(ctx: click.Context) -> None:  # type: ignore[override]
    """Initialize the SQLite database schema."""
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    console.print(f"Initialized DB at {settings.sqlite_path}")


@cli.command()
@click.option("--name", required=True, help="Tenant unique name")
@click.option("--desc", required=False, default=None, help="Tenant description")
@click.pass_context
def add_tenant_cmd(ctx: click.Context, name: str, desc: Optional[str]) -> None:  # type: ignore[override]
    """Create a new tenant with optional description."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    with get_session(engine) as s:
        if get_tenant_by_name(s, name):
            console.print(f"Tenant '{name}' already exists", style="yellow")
            return
        t = add_tenant(s, name=name, description=desc)
        if logger:
            logger.info("Tenant created: id=%s name=%s desc=%s", t.id, t.name, t.description or "")
        console.print(f"Created tenant id={t.id} name={t.name}")


@cli.command()
@click.option("--name", required=True, help="Tenant current name")
@click.option("--new-name", required=False, default=None, help="New tenant name")
@click.option("--desc", required=False, default=None, help="New tenant description")
@click.pass_context
def edit_tenant_cmd(ctx: click.Context, name: str, new_name: Optional[str], desc: Optional[str]) -> None:  # type: ignore[override]
    """Edit tenant's name and/or description by current name."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, name)
        if not t:
            console.print(f"Tenant '{name}' not found", style="red")
            sys.exit(1)
        old_name, old_desc = t.name, t.description or ""
        update_tenant(s, t, name=new_name, description=desc)
        if logger:
            logger.info(
                "Tenant edited: id=%s name:%s->%s desc:%s->%s",
                t.id,
                old_name,
                t.name,
                old_desc,
                t.description or "",
            )
        console.print(f"Updated tenant id={t.id} name={t.name}")


@cli.command()
@click.option("--name", required=True, help="Tenant name to delete")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_tenant_cmd(ctx: click.Context, name: str, yes: bool) -> None:  # type: ignore[override]
    """Delete tenant and all associated data (requires --yes)."""
    if not yes:
        console.print("Use --yes to confirm deletion", style="yellow")
        sys.exit(1)
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, name)
        if not t:
            console.print(f"Tenant '{name}' not found", style="red")
            sys.exit(1)
        tid, tname = t.id, t.name
        delete_tenant(s, t)
        if logger:
            logger.info("Tenant deleted: id=%s name=%s", tid, tname)
        console.print(f"Deleted tenant '{name}'")


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--cidr", required=True, help="Network CIDR or IP/range")
@click.pass_context
def add_network_cmd(ctx: click.Context, tenant: str, cidr: str) -> None:  # type: ignore[override]
    """Add a network CIDR or IP/range to a tenant."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        n = add_network(s, t, cidr)
        if logger:
            logger.info("Network added: tenant=%s id=%s cidr=%s", t.name, n.id, n.cidr)
        console.print(f"Added network '{n.cidr}' to tenant '{t.name}'")


@cli.command()
@click.option("--network-id", type=int, required=True, help="Network id to edit")
@click.option("--cidr", required=True, help="New CIDR or IP/range")
@click.pass_context
def edit_network_cmd(ctx: click.Context, network_id: int, cidr: str) -> None:  # type: ignore[override]
    """Update CIDR for an existing network by id."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        net = get_network_by_id(s, network_id)
        if not net:
            console.print(f"Network id={network_id} not found", style="red")
            sys.exit(1)
        old_cidr = net.cidr
        update_network(s, net, cidr=cidr)
        if logger:
            logger.info("Network edited: id=%s cidr:%s->%s tenant=%s", net.id, old_cidr, net.cidr, net.tenant.name)
        console.print(f"Updated network id={net.id} cidr={net.cidr}")


@cli.command()
@click.option("--network-id", type=int, required=True, help="Network id to delete")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_network_cmd(ctx: click.Context, network_id: int, yes: bool) -> None:  # type: ignore[override]
    """Delete a network by id (requires --yes)."""
    if not yes:
        console.print("Use --yes to confirm deletion", style="yellow")
        sys.exit(1)
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        net = get_network_by_id(s, network_id)
        if not net:
            console.print(f"Network id={network_id} not found", style="red")
            sys.exit(1)
        nid, ncidr, tname = net.id, net.cidr, net.tenant.name
        delete_network(s, net)
        if logger:
            logger.info("Network deleted: id=%s cidr=%s tenant=%s", nid, ncidr, tname)
        console.print(f"Deleted network id={network_id}")


@cli.command()
@click.option("--tenant", required=False, default=None, help="Tenant name filter")
@click.pass_context
def list_scans_cmd(ctx: click.Context, tenant: Optional[str]) -> None:  # type: ignore[override]
    """List scans, optionally filtered by tenant name."""
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant) if tenant else None
        scans = list_scans(s, t)
        table = Table(title="Scans")
        table.add_column("ID", justify="right")
        table.add_column("Tenant")
        table.add_column("Mode")
        table.add_column("Status")
        table.add_column("Started")
        table.add_column("Finished")
        for sc in scans:
            tenant_name = t.name if t else (sc.tenant.name if getattr(sc, "tenant", None) else "(deleted)")
            table.add_row(
                str(sc.id),
                tenant_name,
                sc.mode,
                sc.status,
                _fmt_dt(sc.started_at),
                _fmt_dt(sc.finished_at) if sc.finished_at else "",
            )
        console.print(table)


@cli.command()
@click.option("--scan-id", type=int, required=True, help="Scan id to delete (cascade removes hosts/services)")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_scan_cmd(ctx: click.Context, scan_id: int, yes: bool) -> None:  # type: ignore[override]
    """Delete a scan (and its hosts/services) by id (requires --yes)."""
    if not yes:
        console.print("Use --yes to confirm deletion", style="yellow")
        sys.exit(1)
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        sc = get_scan_by_id(s, scan_id)
        if not sc:
            console.print(f"Scan id={scan_id} not found", style="red")
            sys.exit(1)
        delete_scan(s, sc)
        console.print(f"Deleted scan id={scan_id}")


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--tcp", required=False, default=None, help="Comma-separated TCP ports or ranges, e.g. 22,80,443,1-1024")
@click.pass_context
def set_ports_cmd(ctx: click.Context, tenant: str, tcp: Optional[str]) -> None:  # type: ignore[override]
    """Set tenant TCP ports as a comma-separated list or ranges (e.g. 22,80,443,1-1024)."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        cfg = set_tenant_ports(s, t, tcp_ports=(tcp or None))
        if logger:
            logger.info("Tenant ports set: tenant=%s tcp=%s", t.name, cfg.tcp_ports or "")
        console.print(f"Set ports for tenant '{t.name}': tcp='{cfg.tcp_ports or ''}'")


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--target", required=True, help="Exclude target (IP, CIDR, hostname or range)")
@click.pass_context
def add_exclude_cmd(ctx: click.Context, tenant: str, target: str) -> None:  # type: ignore[override]
    """Add an exclude target for a tenant (used with masscan/nmap --exclude)."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        item = add_tenant_exclude(s, t, target)
        if logger:
            logger.info("Tenant exclude added: tenant=%s id=%s target=%s", t.name, item.id, item.target)
        console.print(f"Added exclude id={item.id} target='{item.target}' for tenant '{t.name}'")


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.pass_context
def list_excludes_cmd(ctx: click.Context, tenant: str) -> None:  # type: ignore[override]
    """List exclude targets for a tenant."""
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        items = list_tenant_excludes(s, t)
        table = Table(title=f"Excludes for {t.name}")
        table.add_column("ID", justify="right")
        table.add_column("Target")
        for it in items:
            table.add_row(str(it.id), it.target)
        if not items:
            console.print("(no excludes)", style="yellow")
        else:
            console.print(table)


@cli.command()
@click.option("--id", "exclude_id", type=int, required=True, help="Exclude id to edit")
@click.option("--target", required=True, help="New exclude target")
@click.pass_context
def edit_exclude_cmd(ctx: click.Context, exclude_id: int, target: str) -> None:  # type: ignore[override]
    """Edit an exclude target by id."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        item = get_tenant_exclude_by_id(s, exclude_id)
        if not item:
            console.print(f"Exclude id={exclude_id} not found", style="red")
            sys.exit(1)
        old = item.target
        update_tenant_exclude(s, item, target=target)
        if logger:
            logger.info("Tenant exclude edited: id=%s %s->%s", item.id, old, item.target)
        console.print(f"Updated exclude id={item.id}: {old} -> {item.target}")


@cli.command()
@click.option("--id", "exclude_id", type=int, required=True, help="Exclude id to delete")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_exclude_cmd(ctx: click.Context, exclude_id: int, yes: bool) -> None:  # type: ignore[override]
    """Delete an exclude target by id (requires --yes)."""
    if not yes:
        console.print("Use --yes to confirm deletion", style="yellow")
        sys.exit(1)
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        item = get_tenant_exclude_by_id(s, exclude_id)
        if not item:
            console.print(f"Exclude id={exclude_id} not found", style="red")
            sys.exit(1)
        tid, target = item.tenant_id, item.target
        delete_tenant_exclude(s, item)
        if logger:
            logger.info("Tenant exclude deleted: tenant_id=%s target=%s", tid, target)
        console.print(f"Deleted exclude id={exclude_id}")


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.pass_context
def show_ports_cmd(ctx: click.Context, tenant: str) -> None:  # type: ignore[override]
    """Show tenant TCP ports or indicate that defaults are used."""
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        cfg = get_tenant_ports(s, t)
        table = Table(title=f"Ports for {t.name}")
        table.add_column("Protocol")
        table.add_column("Ports")
        table.add_row("TCP", cfg.tcp_ports or "(default)") if cfg else table.add_row("TCP", "(default)")
        console.print(table)


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--pdf", is_flag=True, help="Export report to PDF (data_dir/reports/<tenant>_last-scan_<time>.pdf)")
@click.pass_context
def show_last_scan_cmd(ctx: click.Context, tenant: str, pdf: bool) -> None:  # type: ignore[override]
    """Display results of the most recent scan for a tenant."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)

        # Get the most recent scan for this tenant
        last_scan = s.scalar(
            select(Scan)
            .where(Scan.tenant_id == t.id)
            .order_by(desc(Scan.started_at))
            .limit(1)
        )

        if not last_scan:
            console.print(f"No scans found for tenant '{tenant}'", style="yellow")
            return

        if logger:
            logger.info("Showing last scan results: tenant=%s scan_id=%s pdf=%s", tenant, last_scan.id, pdf)

        # Get hosts for this scan
        hosts = s.scalars(select(Host).where(Host.scan_id == last_scan.id).order_by(Host.ip)).all()

        if not hosts:
            console.print(f"No hosts found in last scan for tenant '{tenant}'", style="yellow")
            return

        # Display scan info
        scan_table = Table(title=f"Last Scan for {t.name}")
        scan_table.add_column("Property")
        scan_table.add_column("Value")
        scan_table.add_row("Scan ID", str(last_scan.id))
        scan_table.add_row("Mode", last_scan.mode)
        scan_table.add_row("Status", last_scan.status)
        scan_table.add_row("Started", _fmt_dt(last_scan.started_at))
        scan_table.add_row("Finished", _fmt_dt(last_scan.finished_at) if last_scan.finished_at else "N/A")
        console.print(scan_table)
        console.print()

        pdf_sections: list[tuple[str, list[str]]] = []
        pdf_sections.append(
            (
                "Scan Info",
                [
                    f"Scan ID: {last_scan.id}",
                    f"Mode: {last_scan.mode}",
                    f"Status: {last_scan.status}",
                    f"Started: {_fmt_dt(last_scan.started_at)}",
                    f"Finished: {_fmt_dt(last_scan.finished_at) if last_scan.finished_at else 'N/A'}",
                ],
            )
        )

        # Display hosts and services
        for host in hosts:
            host_table = Table(title=f"Host: {host.ip} ({host.hostname or 'No hostname'})")
            host_table.add_column("Port")
            host_table.add_column("Protocol")
            host_table.add_column("Service")
            host_table.add_column("Product")
            host_table.add_column("Version")
            host_table.add_column("Discovered")

            services = s.scalars(
                select(Service)
                .where(Service.host_id == host.id)
                .order_by(Service.port, Service.protocol)
            ).all()

            pdf_host_lines: list[str] = []
            if services:
                for svc in services:
                    host_table.add_row(
                        str(svc.port),
                        svc.protocol,
                        svc.name or "",
                        svc.product or "",
                        svc.version or "",
                        (_fmt_dt(svc.time_discovery) if svc.time_discovery else "N/A")
                    )
                    pdf_host_lines.append(
                        f"{svc.protocol}/{svc.port}: {svc.name or ''} {svc.product or ''} {svc.version or ''}".strip()
                    )
            else:
                host_table.add_row("No services", "", "", "", "", "")
                pdf_host_lines.append("No services")

            console.print(host_table)
            console.print()
            pdf_sections.append((f"Host {host.ip} ({host.hostname or 'No hostname'})", pdf_host_lines))

        if pdf:
            scan_dt = last_scan.started_at if isinstance(last_scan.started_at, datetime) else None
            pdf_path = _export_pdf_report(
                settings,
                tenant_name=t.name,
                report_type="last-scan",
                scan_dt=scan_dt,
                title=f"Last Scan Report: {t.name}",
                sections=pdf_sections,
            )
            console.print(f"PDF saved to {pdf_path}")
            if logger:
                logger.info("Last scan PDF generated: tenant=%s path=%s", t.name, pdf_path)


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--pdf", is_flag=True, help="Export diff report to PDF (data_dir/reports/<tenant>_diff-scans_<time>.pdf)")
@click.pass_context
def diff_scans_cmd(ctx: click.Context, tenant: str, pdf: bool) -> None:  # type: ignore[override]
    """Show differences between the last two scans for a tenant (hosts and ports)."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)

        scans = s.scalars(
            select(Scan)
            .where(Scan.tenant_id == t.id)
            .order_by(desc(Scan.started_at))
            .limit(2)
        ).all()
        if len(scans) < 2:
            console.print(f"Need at least two scans for tenant '{tenant}' to show diff", style="yellow")
            return

        newer, older = scans[0], scans[1]
        if logger:
            logger.info(
                "Diff scans requested: tenant=%s newer_id=%s older_id=%s pdf=%s",
                tenant,
                newer.id,
                older.id,
                pdf,
            )

        # Load hosts for both scans
        newer_hosts = s.scalars(select(Host).where(Host.scan_id == newer.id)).all()
        older_hosts = s.scalars(select(Host).where(Host.scan_id == older.id)).all()

        newer_host_ips = {h.ip for h in newer_hosts}
        older_host_ips = {h.ip for h in older_hosts}

        hosts_added = sorted(newer_host_ips - older_host_ips)
        hosts_removed = sorted(older_host_ips - newer_host_ips)
        common_hosts = sorted(newer_host_ips & older_host_ips)

        # Map host ip -> set of (protocol, port)
        def services_by_host(hosts: list[Host]) -> dict[str, set[tuple[str, int]]]:
            if not hosts:
                return {}
            host_id_to_ip = {h.id: h.ip for h in hosts}
            svc_rows = s.scalars(
                select(Service).where(Service.host_id.in_(list(host_id_to_ip.keys())))
            ).all()
            result: dict[str, set[tuple[str, int]]] = {}
            for sv in svc_rows:
                ip = host_id_to_ip.get(sv.host_id)
                if not ip:
                    continue
                result.setdefault(ip, set()).add((sv.protocol, int(sv.port)))
            return result

        newer_services = services_by_host(newer_hosts)
        older_services = services_by_host(older_hosts)

        # Header table
        info_table = Table(title=f"Diff of last two scans for {t.name}")
        info_table.add_column("Property")
        info_table.add_column("Value")
        info_table.add_row("Newer Scan ID", str(newer.id))
        info_table.add_row("Newer Started", _fmt_dt(newer.started_at))
        info_table.add_row("Older Scan ID", str(older.id))
        info_table.add_row("Older Started", _fmt_dt(older.started_at))
        console.print(info_table)
        console.print()

        pdf_sections: list[tuple[str, list[str]]] = []
        pdf_sections.append(
            (
                "Scans Compared",
                [
                    f"Newer Scan ID: {newer.id}",
                    f"Newer Started: {_fmt_dt(newer.started_at)}",
                    f"Older Scan ID: {older.id}",
                    f"Older Started: {_fmt_dt(older.started_at)}",
                ],
            )
        )

        # Hosts added/removed
        if hosts_added or hosts_removed:
            hr_table = Table(title="Hosts changes")
            hr_table.add_column("Type")
            hr_table.add_column("Hosts")
            if hosts_added:
                hr_table.add_row("Added", ", ".join(hosts_added))
            if hosts_removed:
                hr_table.add_row("Removed", ", ".join(hosts_removed))
            console.print(hr_table)
            console.print()
            changes_lines: list[str] = []
            if hosts_added:
                changes_lines.append(f"Added: {', '.join(hosts_added)}")
            if hosts_removed:
                changes_lines.append(f"Removed: {', '.join(hosts_removed)}")
            pdf_sections.append(("Host Changes", changes_lines))
        else:
            console.print("No host changes", style="green")
            console.print()
            pdf_sections.append(("Host Changes", ["No host changes"]))

        # Port diffs for common hosts
        any_port_changes = False
        for ip in common_hosts:
            new_set = newer_services.get(ip, set())
            old_set = older_services.get(ip, set())
            added_ports = sorted(list(new_set - old_set), key=lambda x: (x[0], x[1]))
            removed_ports = sorted(list(old_set - new_set), key=lambda x: (x[0], x[1]))
            if not added_ports and not removed_ports:
                continue
            any_port_changes = True
            ht = Table(title=f"Ports change for {ip}")
            ht.add_column("Type")
            ht.add_column("Ports")
            if added_ports:
                ht.add_row(
                    "Opened",
                    ", ".join(f"{proto}:{port}" for proto, port in added_ports),
                )
            if removed_ports:
                ht.add_row(
                    "Closed",
                    ", ".join(f"{proto}:{port}" for proto, port in removed_ports),
                )
            console.print(ht)
            console.print()

            port_lines: list[str] = []
            if added_ports:
                port_lines.append(
                    "Opened: "
                    + ", ".join(f"{proto}:{port}" for proto, port in added_ports)
                )
            if removed_ports:
                port_lines.append(
                    "Closed: "
                    + ", ".join(f"{proto}:{port}" for proto, port in removed_ports)
                )
            pdf_sections.append((f"Port Changes for {ip}", port_lines))

        if not any_port_changes:
            console.print("No port changes on common hosts", style="green")
            console.print()
            pdf_sections.append(("Port Changes", ["No port changes on common hosts"]))

        if pdf:
            scan_dt = newer.started_at if isinstance(newer.started_at, datetime) else None
            pdf_path = _export_pdf_report(
                settings,
                tenant_name=t.name,
                report_type="diff-scans",
                scan_dt=scan_dt,
                title=f"Scan Diff Report: {t.name}",
                sections=pdf_sections,
            )
            console.print(f"PDF saved to {pdf_path}")
            if logger:
                logger.info("Diff scan PDF generated: tenant=%s path=%s", t.name, pdf_path)


@cli.command()
@click.pass_context
def list_tenants_cmd(ctx: click.Context) -> None:  # type: ignore[override]
    """List all tenants."""
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        tenants = list_tenants(s)
        table = Table(title="Tenants")
        table.add_column("ID", justify="right")
        table.add_column("Name")
        table.add_column("Description")
        for t in tenants:
            table.add_row(str(t.id), t.name, t.description or "")
        console.print(table)


@cli.command()
@click.option("--tenant", required=False, default=None, help="Tenant name filter")
@click.pass_context
def list_networks_cmd(ctx: click.Context, tenant: Optional[str]) -> None:  # type: ignore[override]
    """List networks, optionally filtered by tenant name."""
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant) if tenant else None
        nets = list_networks(s, t)
        table = Table(title="Networks")
        table.add_column("ID", justify="right")
        table.add_column("Tenant")
        table.add_column("CIDR")
        for n in nets:
            table.add_row(str(n.id), n.tenant.name, n.cidr)
        console.print(table)


# Placeholder for scan command; implemented after runner and parser are ready
@cli.command()
@click.option("--tenant", required=False, default=None, help="Tenant name to scan (omit with --all-tenants)")
@click.option("--mode", type=click.Choice(["tcp", "all"]), default="tcp")
@click.option("--service-info", is_flag=True, help="Enable nmap service/version detection (-sV)")
@click.option("--iL", "input_list", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=False, help="File with targets for masscan (-iL). If set, targets are taken from file, not from DB")
@click.option("--all-tenants", is_flag=True, help="Scan all tenants sequentially with their individual settings")
@click.option("--rate", "rate_override", type=click.IntRange(min=1), required=False, help="Override masscan rate for this run")
@click.pass_context
def scan_cmd(ctx: click.Context, tenant: Optional[str], mode: str, service_info: bool, input_list: Optional[Path], all_tenants: bool, rate_override: Optional[int]) -> None:  # type: ignore[override]
    """Run scan(s).

    - Single tenant: specify --tenant NAME
    - All tenants: use --all-tenants (tenant is ignored)
    - If --iL is provided, masscan will read targets from the specified file (not from tenant networks) — only valid for single-tenant scans.
    - --rate overrides the masscan rate (defaults to settings.rate when omitted).
    """
    from network_scanner.scan.runner import run_scan_for_tenant

    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)

    if all_tenants:
        if input_list is not None:
            console.print("--iL cannot be used together with --all-tenants", style="red")
            sys.exit(1)
        with get_session(engine) as s:
            tenants = list_tenants(s)
            if not tenants:
                console.print("No tenants found", style="yellow")
                return
            for t in tenants:
                if logger:
                    logger.info(
                        "Scan requested (all-tenants): tenant=%s mode=%s service_info=%s rate=%s",
                        t.name,
                        mode,
                        service_info,
                        str(rate_override) if rate_override is not None else "(default)",
                    )
                run_scan_for_tenant(
                    settings,
                    tenant_name=t.name,
                    mode=mode,
                    service_info=service_info,
                    input_list=None,
                    rate_override=rate_override,
                )
        return

    if not tenant:
        console.print("--tenant is required unless --all-tenants is specified", style="red")
        sys.exit(1)
    if logger:
        logger.info(
            "Scan requested: tenant=%s mode=%s service_info=%s iL=%s rate=%s",
            tenant,
            mode,
            service_info,
            str(input_list) if input_list else "",
            str(rate_override) if rate_override is not None else "(default)",
        )
    run_scan_for_tenant(
        settings,
        tenant_name=tenant,
        mode=mode,
        service_info=service_info,
        input_list=input_list,
        rate_override=rate_override,
    )


