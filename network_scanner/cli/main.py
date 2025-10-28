from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from network_scanner.config.settings import Settings
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
)


console = Console()


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[Path]) -> None:
    ctx.ensure_object(dict)
    settings = Settings.load(str(config_path) if config_path else None)
    ctx.obj["settings"] = settings
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
        ctx.exit(0)


@cli.command()
@click.pass_context
def init_db_cmd(ctx: click.Context) -> None:  # type: ignore[override]
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    console.print(f"Initialized DB at {settings.sqlite_path}")


@cli.command()
@click.option("--name", required=True, help="Tenant unique name")
@click.option("--desc", required=False, default=None, help="Tenant description")
@click.pass_context
def add_tenant_cmd(ctx: click.Context, name: str, desc: Optional[str]) -> None:  # type: ignore[override]
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    with get_session(engine) as s:
        if get_tenant_by_name(s, name):
            console.print(f"Tenant '{name}' already exists", style="yellow")
            return
        t = add_tenant(s, name=name, description=desc)
        console.print(f"Created tenant id={t.id} name={t.name}")


@cli.command()
@click.option("--name", required=True, help="Tenant current name")
@click.option("--new-name", required=False, default=None, help="New tenant name")
@click.option("--desc", required=False, default=None, help="New tenant description")
@click.pass_context
def edit_tenant_cmd(ctx: click.Context, name: str, new_name: Optional[str], desc: Optional[str]) -> None:  # type: ignore[override]
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, name)
        if not t:
            console.print(f"Tenant '{name}' not found", style="red")
            sys.exit(1)
        update_tenant(s, t, name=new_name, description=desc)
        console.print(f"Updated tenant id={t.id} name={t.name}")


@cli.command()
@click.option("--name", required=True, help="Tenant name to delete")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_tenant_cmd(ctx: click.Context, name: str, yes: bool) -> None:  # type: ignore[override]
    if not yes:
        console.print("Use --yes to confirm deletion", style="yellow")
        sys.exit(1)
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, name)
        if not t:
            console.print(f"Tenant '{name}' not found", style="red")
            sys.exit(1)
        delete_tenant(s, t)
        console.print(f"Deleted tenant '{name}'")


@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--cidr", required=True, help="Network CIDR or IP/range")
@click.pass_context
def add_network_cmd(ctx: click.Context, tenant: str, cidr: str) -> None:  # type: ignore[override]
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        n = add_network(s, t, cidr)
        console.print(f"Added network '{n.cidr}' to tenant '{t.name}'")


@cli.command()
@click.option("--network-id", type=int, required=True, help="Network id to edit")
@click.option("--cidr", required=True, help="New CIDR or IP/range")
@click.pass_context
def edit_network_cmd(ctx: click.Context, network_id: int, cidr: str) -> None:  # type: ignore[override]
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        net = get_network_by_id(s, network_id)
        if not net:
            console.print(f"Network id={network_id} not found", style="red")
            sys.exit(1)
        update_network(s, net, cidr=cidr)
        console.print(f"Updated network id={net.id} cidr={net.cidr}")


@cli.command()
@click.option("--network-id", type=int, required=True, help="Network id to delete")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_network_cmd(ctx: click.Context, network_id: int, yes: bool) -> None:  # type: ignore[override]
    if not yes:
        console.print("Use --yes to confirm deletion", style="yellow")
        sys.exit(1)
    settings: Settings = ctx.obj["settings"]
    engine = create_sqlite_engine(settings.sqlite_path)
    with get_session(engine) as s:
        net = get_network_by_id(s, network_id)
        if not net:
            console.print(f"Network id={network_id} not found", style="red")
            sys.exit(1)
        delete_network(s, net)
        console.print(f"Deleted network id={network_id}")


@cli.command()
@click.option("--tenant", required=False, default=None, help="Tenant name filter")
@click.pass_context
def list_scans_cmd(ctx: click.Context, tenant: Optional[str]) -> None:  # type: ignore[override]
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
            table.add_row(str(sc.id), (t.name if t else sc.tenant.name), sc.mode, sc.status, str(sc.started_at), str(sc.finished_at or ""))
        console.print(table)


@cli.command()
@click.option("--scan-id", type=int, required=True, help="Scan id to delete (cascade removes hosts/services)")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_scan_cmd(ctx: click.Context, scan_id: int, yes: bool) -> None:  # type: ignore[override]
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
@click.pass_context
def list_tenants_cmd(ctx: click.Context) -> None:  # type: ignore[override]
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
@click.option("--tenant", required=True, help="Tenant name to scan")
@click.option("--mode", type=click.Choice(["tcp", "all"]), default="tcp")
@click.pass_context
def scan_cmd(ctx: click.Context, tenant: str, mode: str) -> None:  # type: ignore[override]
    from network_scanner.scan.runner import run_scan_for_tenant

    settings: Settings = ctx.obj["settings"]
    run_scan_for_tenant(settings, tenant_name=tenant, mode=mode)


