from __future__ import annotations

import sys
import io
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

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
    list_nuclei_scans,
    get_nuclei_scan_by_id,
    list_nuclei_findings,
    delete_nuclei_scan,
)
from network_scanner.db.models import Scan, Host, Service, Vulnerability, NucleiScan, NucleiFinding
from network_scanner.scan.nuclei_runner import run_nuclei_scan_for_scan
from sqlalchemy import select, desc


console = Console()

PDF_TABLE_WIDTH = 110
CONSOLE_TABLE_WIDTH = 120  # Fixed width for all console tables


def _table_to_data(table: Table) -> dict:
    """Extract table data for PDF generation."""
    data = {
        "title": table.title or "",
        "columns": [],
        "rows": [],
    }
    # Extract column headers
    for col in table.columns:
        header = col.header
        if hasattr(header, 'plain'):
            header = header.plain
        data["columns"].append(str(header) if header else "")
    
    # Extract rows directly from Rich table structure when available
    rows_data = []
    rich_rows = getattr(table, "rows", None) or getattr(table, "_rows", None)
    if rich_rows:
        for row in rich_rows:
            row_cells = getattr(row, "cells", None)
            if row_cells is None:
                continue
            cells = [_extract_cell_text(cell) for cell in row_cells]
            if not cells:
                continue
            # Pad or truncate to match column count
            if len(cells) < len(data["columns"]):
                cells.extend([""] * (len(data["columns"]) - len(cells)))
            elif len(cells) > len(data["columns"]):
                cells = cells[:len(data["columns"])]
            rows_data.append(cells)
    else:
        # Fallback: render table and parse it (but handle multi-line cells better)
        from rich.console import Console as RichConsole
        from io import StringIO
        output = StringIO()
        console = RichConsole(file=output, width=120, record=True, force_terminal=False)
        console.print(table)
        rendered = console.export_text(clear=False)
        
        # Parse rendered text to extract rows
        lines = rendered.splitlines()
        # Find data rows (lines with │ or ┃ separators)
        header_found = False
        current_row = None
        for line in lines:
            line = line.strip()
            # Skip empty lines and border lines
            if not line:
                continue
            # Skip border lines (lines that are only border characters)
            if all(c in '┏┓┗┛┃│┡┢┣┫┪┴┼╇╈╉╊╋┳┻║═╔╗╚╝╠╣╦╩╬━─├┤┬┴┼' for c in line):
                continue
            
            # Check if this is a data row (contains │ or ┃)
            if '│' in line or '┃' in line:
                # Split by │ or ┃ and clean up
                if '│' in line:
                    parts = line.split('│')
                else:
                    parts = line.split('┃')
                # Remove leading/trailing empty parts (borders)
                while parts and not parts[0].strip():
                    parts.pop(0)
                while parts and not parts[-1].strip():
                    parts.pop()
                cells = [c.strip() for c in parts]
                
                # Skip header row
                if not header_found:
                    header_found = True
                    continue
                
                # New row
                if cells:
                    # Pad or truncate to match column count
                    if len(cells) < len(data["columns"]):
                        cells.extend([""] * (len(data["columns"]) - len(cells)))
                    elif len(cells) > len(data["columns"]):
                        cells = cells[:len(data["columns"])]
                    rows_data.append(cells)
    
    data["rows"] = rows_data
    return data


def _extract_cell_text(cell) -> str:
    """Extract plain text from a Rich cell object."""
    if cell is None:
        return ""
    
    # Try different methods to extract text
    if isinstance(cell, str):
        return cell
    
    if hasattr(cell, 'plain'):
        return str(cell.plain)
    
    if hasattr(cell, '__rich__'):
        # Render rich object to text
        from rich.console import Console as RichConsole
        from io import StringIO
        cell_output = StringIO()
        cell_console = RichConsole(file=cell_output, record=True, force_terminal=False)
        cell_console.print(cell)
        return cell_console.export_text(clear=False).strip()
    
    return str(cell)
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


def _add_pdf_table(pdf, table_data: dict, col_widths: list[float] | None = None, center_table: bool = False):
    """Add a table to PDF using fpdf2 table capabilities."""
    if not table_data:
        return
    if not table_data.get("columns"):
        return
    # Allow empty rows - show at least header
    rows = table_data.get("rows", [])
    
    # Calculate column widths if not provided
    num_cols = len(table_data["columns"])
    if col_widths is None:
        page_width = pdf.w - 2 * pdf.l_margin
        col_width = page_width / num_cols if num_cols > 0 else page_width
        col_widths = [col_width] * num_cols
    
    # Calculate total table width
    total_table_width = sum(col_widths)
    
    # Table title
    if table_data.get("title"):
        pdf.set_font("Helvetica", "B", 11)
        if center_table:
            # Center the title
            title_width = pdf.get_string_width(table_data["title"])
            pdf.set_x(pdf.l_margin + (pdf.w - 2 * pdf.l_margin - title_width) / 2)
            pdf.cell(title_width, 8, table_data["title"], ln=True)
        else:
            pdf.cell(0, 8, table_data["title"], ln=True)
        pdf.ln(2)
    
    # Header row
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 230, 230)
    # Calculate header row height based on content (text wrapping)
    max_header_height = 7  # Minimum header height
    header_cell_lines = []
    for i, col_header in enumerate(table_data["columns"]):
        if i < len(col_widths):
            header_text = str(col_header) if col_header is not None else ""
            # Ensure ASCII-compatible
            try:
                header_text.encode('latin-1')
            except UnicodeEncodeError:
                header_text = header_text.encode('ascii', 'replace').decode('ascii')
            # Calculate height needed for header cell (with wrapping)
            lines = pdf.multi_cell(col_widths[i], 7, header_text, border=0, align="L", split_only=True)
            header_cell_lines.append(lines)
            cell_height = len(lines) * 7
            max_header_height = max(max_header_height, cell_height)
    
    # Draw header cells with text wrapping
    x_start = pdf.get_x()
    y_start = pdf.get_y()
    
    # Check if header fits on current page
    if y_start + max_header_height > pdf.h - pdf.b_margin:
        pdf.add_page()
        x_start = pdf.l_margin
        y_start = pdf.get_y()
    
    for i, col_header in enumerate(table_data["columns"]):
        if i < len(col_widths):
            x_pos = x_start + sum(col_widths[:i])
            # Draw cell border and background
            pdf.set_fill_color(230, 230, 230)
            pdf.rect(x_pos, y_start, col_widths[i], max_header_height, style='FD')
            # Draw text with wrapping
            for line_idx, line in enumerate(header_cell_lines[i]):
                pdf.set_xy(x_pos + 1, y_start + 1 + line_idx * 7)
                pdf.cell(col_widths[i] - 2, 7, line, border=0, align="L", ln=0)
    # Move to next row position
    pdf.set_xy(x_start, y_start + max_header_height)
    
    # Data rows
    pdf.set_font("Helvetica", size=8)
    pdf.set_fill_color(255, 255, 255)
    for row_idx, row in enumerate(rows):
        # Alternate row colors for better readability
        if row_idx % 2 == 1:
            fill_color = (245, 245, 245)
        else:
            fill_color = (255, 255, 255)
        
        # Calculate row height based on content (text wrapping)
        max_row_height = 6  # Minimum row height
        cell_lines_list = []
        for i, cell_value in enumerate(row):
            if i < len(col_widths):
                cell_text = str(cell_value) if cell_value is not None else ""
                # Ensure ASCII-compatible
                try:
                    cell_text.encode('latin-1')
                except UnicodeEncodeError:
                    cell_text = cell_text.encode('ascii', 'replace').decode('ascii')
                # Calculate height needed for this cell (with wrapping)
                lines = pdf.multi_cell(col_widths[i], 6, cell_text, border=0, align="L", split_only=True)
                cell_lines_list.append(lines)
                cell_height = len(lines) * 6
                max_row_height = max(max_row_height, cell_height)
        
        # Draw cells with proper height and text wrapping
        x_start = pdf.get_x()
        y_start = pdf.get_y()
        
        # Check if row fits on current page, if not add new page
        if y_start + max_row_height > pdf.h - pdf.b_margin:
            pdf.add_page()
            x_start = pdf.l_margin
            y_start = pdf.get_y()
            # Redraw header if table spans multiple pages
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_fill_color(230, 230, 230)
            for i, col_header in enumerate(table_data["columns"]):
                if i < len(col_widths):
                    x_pos = x_start + sum(col_widths[:i])
                    # Draw cell border and background
                    pdf.rect(x_pos, y_start, col_widths[i], max_header_height, style='FD')
                    # Draw text with wrapping
                    for line_idx, line in enumerate(header_cell_lines[i]):
                        pdf.set_xy(x_pos + 1, y_start + 1 + line_idx * 7)
                        pdf.cell(col_widths[i] - 2, 7, line, border=0, align="L", ln=0)
            y_start = y_start + max_header_height
            pdf.set_font("Helvetica", size=8)
        
        for i, cell_value in enumerate(row):
            if i < len(col_widths):
                x_pos = x_start + sum(col_widths[:i])
                # Draw cell border and background
                pdf.set_fill_color(fill_color[0], fill_color[1], fill_color[2])
                pdf.rect(x_pos, y_start, col_widths[i], max_row_height, style='FD')
                # Draw text with wrapping
                for line_idx, line in enumerate(cell_lines_list[i]):
                    pdf.set_xy(x_pos + 1, y_start + 1 + line_idx * 6)
                    pdf.cell(col_widths[i] - 2, 6, line, border=0, align="L", ln=0)
        # Move to next row position
        pdf.set_xy(x_start, y_start + max_row_height)
    
    pdf.ln(3)


def _export_pdf_report(
    settings: Settings,
    tenant_name: str,
    report_type: str,
    scan_dt: datetime | None,
    title: str,
    blocks: list[dict],
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

    # Process table blocks
    for block in blocks:
        if not block:
            continue
        # Always add table, even if rows are empty (will show header)
        if not block.get("rows") and block.get("columns"):
            _add_pdf_table(pdf, block)
            continue

        # Special handling for "Overall Risk" and "Last Scan" tables - make them 2x narrower
        if block.get("title", "").startswith("Overall Risk") or block.get("title", "").startswith("Last Scan"):
            page_width = pdf.w - 2 * pdf.l_margin
            table_width = page_width / 2
            num_cols = len(block.get("columns", []))
            if num_cols > 0:
                col_width = table_width / num_cols
                col_widths = [col_width] * num_cols
                old_x = pdf.get_x()
                pdf.set_x(pdf.l_margin + (page_width - table_width) / 2)
                _add_pdf_table(pdf, block, col_widths=col_widths, center_table=True)
                pdf.set_x(pdf.l_margin)
            else:
                _add_pdf_table(pdf, block)
        else:
            _add_pdf_table(pdf, block)

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
    init_db(engine)
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
        scan_table = Table(title=f"Last Scan for {t.name}", width=CONSOLE_TABLE_WIDTH)
        scan_table.add_column("Property")
        scan_table.add_column("Value")
        scan_table.add_row("Scan ID", str(last_scan.id))
        scan_table.add_row("Mode", last_scan.mode)
        scan_table.add_row("Status", last_scan.status)
        scan_table.add_row("Started", _fmt_dt(last_scan.started_at))
        scan_table.add_row("Finished", _fmt_dt(last_scan.finished_at) if last_scan.finished_at else "N/A")
        console.print(scan_table)
        pdf_blocks: list[dict] = [_table_to_data(scan_table)]

        # Display hosts and services
        for host in hosts:
            host_table = Table(title=f"Host: {host.ip} ({host.hostname or 'No hostname'})", width=CONSOLE_TABLE_WIDTH)
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
            else:
                host_table.add_row("No services", "", "", "", "", "")

            console.print(host_table)
            pdf_blocks.append(_table_to_data(host_table))
            
            # Display vulnerabilities for this host
            vulnerabilities = s.scalars(
                select(Vulnerability)
                .where(Vulnerability.host_id == host.id)
                .order_by(Vulnerability.cve_id)
            ).all()
            
            if vulnerabilities:
                from network_scanner.vuln import get_cvss_data
                
                # Get services for this host to show product/version info
                host_services = s.scalars(
                    select(Service)
                    .where(Service.host_id == host.id)
                    .order_by(Service.port, Service.protocol)
                ).all()
                
                # Create a list of services with product/version info
                services_with_info: list[dict[str, str]] = []
                for svc in host_services:
                    if svc.product or svc.version:
                        services_with_info.append({
                            "port": str(svc.port),
                            "product": svc.product or "",
                            "version": svc.version or "",
                        })
                
                vuln_table = Table(title=f"Vulnerabilities for {host.ip}", width=CONSOLE_TABLE_WIDTH)
                vuln_table.add_column("CVE")
                vuln_table.add_column("Port")
                vuln_table.add_column("Product")
                vuln_table.add_column("Version")
                vuln_table.add_column("CVSS")
                vuln_table.add_column("EPSS")
                vuln_table.add_column("Percentile")
                
                for vuln in vulnerabilities:
                    # Get CVSS if not already stored
                    if vuln.cvss_score is None or vuln.cvss_score == 0.0:
                        cvss_data = get_cvss_data(settings, vuln.cve_id)
                        vuln.cvss_score = cvss_data.get("baseScore", 0.0)
                        vuln.cvss_vector = cvss_data.get("vector", "N/A")
                        s.flush()
                    
                    # Show service info for this vulnerability
                    # If multiple services exist, show them comma-separated
                    if services_with_info:
                        # Combine all services with product/version info
                        ports = [s["port"] for s in services_with_info]
                        products = [s["product"] for s in services_with_info if s["product"]]
                        versions = [s["version"] for s in services_with_info if s["version"]]
                        
                        # Remove duplicates while preserving order
                        unique_ports = []
                        seen_ports = set()
                        for p in ports:
                            if p not in seen_ports:
                                unique_ports.append(p)
                                seen_ports.add(p)
                        
                        unique_products = []
                        seen_products = set()
                        for p in products:
                            if p not in seen_products:
                                unique_products.append(p)
                                seen_products.add(p)
                        
                        unique_versions = []
                        seen_versions = set()
                        for v in versions:
                            if v not in seen_versions:
                                unique_versions.append(v)
                                seen_versions.add(v)
                        
                        port_str = ", ".join(unique_ports) if unique_ports else ""
                        product_str = ", ".join(unique_products) if unique_products else ""
                        version_str = ", ".join(unique_versions) if unique_versions else ""
                    else:
                        port_str = ""
                        product_str = ""
                        version_str = ""
                    
                    cvss_str = f"{vuln.cvss_score:.1f}" if vuln.cvss_score and vuln.cvss_score > 0 else "N/A"
                    epss_str = f"{vuln.epss:.4f}" if vuln.epss is not None else "N/A"
                    percentile_str = f"{vuln.percentile:.2f}" if vuln.percentile is not None else "N/A"
                    vuln_table.add_row(vuln.cve_id, port_str, product_str, version_str, cvss_str, epss_str, percentile_str)
                
                console.print(vuln_table)
                pdf_blocks.append(_table_to_data(vuln_table))
                
                # Display overall exploit probability for host (only once per host)
                if vulnerabilities[0].exploit_probability is not None:
                    risk_table = Table(title=f"Overall Risk for {host.ip}", width=CONSOLE_TABLE_WIDTH)
                    risk_table.add_column("Metric")
                    risk_table.add_column("Value")
                    risk_table.add_row("Exploit Probability", f"{vulnerabilities[0].exploit_probability:.2%}")
                    console.print(risk_table)
                    pdf_blocks.append(_table_to_data(risk_table))

        # Display nuclei findings if available for this scan
        nuclei_scans = list_nuclei_scans(s, tenant=t, scan=last_scan)
        if nuclei_scans:
            latest_nuclei_scan = nuclei_scans[0]  # Most recent
            nuclei_findings = list_nuclei_findings(s, latest_nuclei_scan)
            if nuclei_findings:
                console.print()
                nuclei_summary_table = Table(title=f"Nuclei Findings Summary for {t.name}", width=CONSOLE_TABLE_WIDTH)
                nuclei_summary_table.add_column("Property")
                nuclei_summary_table.add_column("Value")
                nuclei_summary_table.add_row("Nuclei Scan ID", str(latest_nuclei_scan.id))
                nuclei_summary_table.add_row("Total Findings", str(len(nuclei_findings)))
                severity_counts = Counter((f.severity or "UNKNOWN").upper() for f in nuclei_findings)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                    if sev in severity_counts:
                        nuclei_summary_table.add_row(f"{sev} Findings", str(severity_counts[sev]))
                console.print(nuclei_summary_table)
                pdf_blocks.append(_table_to_data(nuclei_summary_table))
                
                if latest_nuclei_scan.ai_summary:
                    console.print(Panel(latest_nuclei_scan.ai_summary, title="AI Summary", expand=False))
                    ai_summary_table = Table(title="AI Summary", width=CONSOLE_TABLE_WIDTH)
                    ai_summary_table.add_column("Summary")
                    ai_summary_table.add_row(latest_nuclei_scan.ai_summary)
                    pdf_blocks.append(_table_to_data(ai_summary_table))

        if pdf:
            scan_dt = last_scan.started_at if isinstance(last_scan.started_at, datetime) else None
            pdf_path = _export_pdf_report(
                settings,
                tenant_name=t.name,
                report_type="last-scan",
                scan_dt=scan_dt,
                title=f"Last Scan Report: {t.name}",
                blocks=pdf_blocks,
            )
            console.print(f"PDF saved to {pdf_path}")
            if logger:
                logger.info("Last scan PDF generated: tenant=%s path=%s", t.name, pdf_path)


@cli.command("show-nuclei")
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--nuclei-scan-id", type=int, required=False, default=None, help="Specific nuclei scan id (defaults to latest)")
@click.option("--scan-id", type=int, required=False, default=None, help="Filter by base scan id")
@click.option("--pdf", is_flag=True, help="Export report to PDF")
@click.pass_context
def show_nuclei_cmd(  # type: ignore[override]
    ctx: click.Context,
    tenant: str,
    nuclei_scan_id: Optional[int],
    scan_id: Optional[int],
    pdf: bool,
) -> None:
    """Display nuclei scan findings for a tenant."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)

    with get_session(engine) as s:
        tenant_obj = get_tenant_by_name(s, tenant)
        if not tenant_obj:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)

        scan_obj: Scan | None = None
        if scan_id is not None:
            scan_obj = get_scan_by_id(s, scan_id)
            if not scan_obj or scan_obj.tenant_id != tenant_obj.id:
                console.print(f"Scan id={scan_id} not found for tenant '{tenant_obj.name}'", style="red")
                sys.exit(1)

        nuclei_scan: NucleiScan | None = None
        if nuclei_scan_id is not None:
            nuclei_scan = get_nuclei_scan_by_id(s, nuclei_scan_id)
            if not nuclei_scan or nuclei_scan.tenant_id != tenant_obj.id:
                console.print(f"Nuclei scan id={nuclei_scan_id} not found for tenant '{tenant_obj.name}'", style="red")
                sys.exit(1)
        else:
            scans = list_nuclei_scans(s, tenant=tenant_obj, scan=scan_obj)
            nuclei_scan = scans[0] if scans else None

        if not nuclei_scan:
            console.print("No nuclei scans found for the specified parameters", style="yellow")
            return

        findings = list_nuclei_findings(s, nuclei_scan)

    if logger:
        logger.info(
            "Show nuclei scan: tenant=%s nuclei_scan_id=%s findings=%d",
            tenant,
            nuclei_scan.id,
            len(findings),
        )

    pdf_blocks: list[dict] = []

    meta_table = Table(title=f"Nuclei Scan for {tenant}", width=CONSOLE_TABLE_WIDTH)
    meta_table.add_column("Property")
    meta_table.add_column("Value")
    meta_table.add_row("Nuclei Scan ID", str(nuclei_scan.id))
    meta_table.add_row("Base Scan ID", str(nuclei_scan.scan_id) if nuclei_scan.scan_id else "N/A")
    meta_table.add_row("Status", nuclei_scan.status)
    meta_table.add_row("Started", _fmt_dt(nuclei_scan.started_at))
    meta_table.add_row("Finished", _fmt_dt(nuclei_scan.finished_at))
    meta_table.add_row("Templates", nuclei_scan.templates or "-")
    meta_table.add_row("Targets", str(nuclei_scan.target_count))
    meta_table.add_row("Findings", str(len(findings)))
    meta_table.add_row("Report Path", nuclei_scan.report_path or "-")
    console.print(meta_table)
    pdf_blocks.append(_table_to_data(meta_table))

    if nuclei_scan.ai_summary:
        console.print(Panel(nuclei_scan.ai_summary, title="AI Summary", expand=False))
        summary_table = Table(title="AI Summary", width=CONSOLE_TABLE_WIDTH)
        summary_table.add_column("Summary")
        summary_table.add_row(nuclei_scan.ai_summary)
        pdf_blocks.append(_table_to_data(summary_table))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}

    if findings:
        severity_counter = Counter((finding.severity or "UNKNOWN").upper() for finding in findings)
        breakdown_table = Table(title="Findings by Severity", width=CONSOLE_TABLE_WIDTH)
        breakdown_table.add_column("Severity")
        breakdown_table.add_column("Count")
        for severity, count in sorted(severity_counter.items(), key=lambda item: severity_order.get(item[0], 99)):
            breakdown_table.add_row(severity, str(count))
        console.print(breakdown_table)
        pdf_blocks.append(_table_to_data(breakdown_table))

        findings_table = Table(title="Nuclei Findings", width=CONSOLE_TABLE_WIDTH)
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Target")
        findings_table.add_column("Template")
        findings_table.add_column("Name")
        findings_table.add_column("Description")
        findings_table.add_column("References")

        sorted_findings = sorted(
            findings,
            key=lambda f: (
                severity_order.get((f.severity or "UNKNOWN").upper(), 99),
                f.target,
                f.template_id or "",
            ),
        )

        for finding in sorted_findings:
            severity = (finding.severity or "UNKNOWN").upper()
            template_label = finding.template_id or "-"
            if finding.template_name and finding.template_name != finding.template_id:
                template_label = f"{finding.template_name} ({template_label})"
            description = (finding.description or "").strip()
            if len(description) > 200:
                description = description[:197] + "..."
            references = (finding.references or "").strip()
            if references:
                refs_lines = references.splitlines()
                if len(refs_lines) > 3:
                    references = "\n".join(refs_lines[:3]) + "\n..."
            findings_table.add_row(
                severity,
                finding.target,
                template_label,
                finding.template_name or "-",
                description or "-",
                references or "-",
            )

        console.print(findings_table)
        pdf_blocks.append(_table_to_data(findings_table))
    else:
        console.print("No findings recorded for this nuclei scan", style="green")

    if pdf:
        pdf_path = _export_pdf_report(
            settings=settings,
            tenant_name=tenant,
            report_type="nuclei",
            scan_dt=nuclei_scan.started_at,
            title=f"Nuclei Report for {tenant}",
            blocks=pdf_blocks,
        )
        console.print(f"PDF exported to {pdf_path}")

@cli.command()
@click.option("--tenant", required=True, help="Tenant name")
@click.pass_context
def search_vulners_cmd(ctx: click.Context, tenant: str) -> None:  # type: ignore[override]
    """Search for vulnerabilities in the last scan for a tenant.
    
    If the last scan didn't include vulnerability data, runs nmap --script vulners.
    If vulnerabilities already exist, refreshes EPSS scores and recalculates exploit probability.
    """
    from network_scanner.vuln import extract_cves_from_nmap_xml, get_epss_score, calculate_exploit_probability
    import subprocess
    import tempfile
    
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    
    with get_session(engine) as s:
        t = get_tenant_by_name(s, tenant)
        if not t:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        
        # Get the most recent scan
        last_scan = s.scalar(
            select(Scan)
            .where(Scan.tenant_id == t.id)
            .order_by(desc(Scan.started_at))
            .limit(1)
        )
        
        if not last_scan:
            console.print(f"No scans found for tenant '{tenant}'", style="yellow")
            return
        
        # Get hosts for this scan
        hosts = s.scalars(select(Host).where(Host.scan_id == last_scan.id).order_by(Host.ip)).all()
        if not hosts:
            console.print(f"No hosts found in last scan for tenant '{tenant}'", style="yellow")
            return
        
        # Check if vulnerabilities already exist
        host_ids = [h.id for h in hosts]
        existing_vulns = s.scalars(
            select(Vulnerability).where(Vulnerability.host_id.in_(host_ids))
        ).all()
        
        if existing_vulns:
            # Refresh EPSS scores and recalculate exploit probability
            console.print(f"Found {len(existing_vulns)} existing vulnerabilities. Refreshing EPSS scores...")
            if logger:
                logger.info("Refreshing EPSS for tenant=%s scan_id=%s", tenant, last_scan.id)
            
            for host in hosts:
                host_vulns = [v for v in existing_vulns if v.host_id == host.id]
                if not host_vulns:
                    continue
                
                epss_scores: list[float] = []
                for vuln in host_vulns:
                    epss_data = get_epss_score(settings, vuln.cve_id)
                    vuln.epss = epss_data["epss"]
                    vuln.percentile = epss_data["percentile"]
                    if epss_data["epss"] > 0:
                        epss_scores.append(epss_data["epss"])
                
                if epss_scores:
                    exploit_prob = calculate_exploit_probability(
                        epss_scores, settings.epss_significant_threshold
                    )
                    for vuln in host_vulns:
                        vuln.exploit_probability = exploit_prob
                
                s.flush()
            
            console.print("EPSS scores refreshed and exploit probabilities recalculated.")
            if logger:
                logger.info("EPSS refresh completed for tenant=%s", tenant)
        else:
            # Need to run vulners scan
            console.print("No vulnerabilities found in last scan. Running nmap --script vulners...")
            if logger:
                logger.info("Running vulners scan for tenant=%s scan_id=%s", tenant, last_scan.id)
            
            date_dir = settings.data_dir / t.name / last_scan.started_at.strftime("%Y%m%d")
            date_dir.mkdir(parents=True, exist_ok=True)
            
            with tempfile.TemporaryDirectory() as tmpdir:
                hosts_file = Path(tmpdir) / "hosts.txt"
                hosts_file.write_text("\n".join(sorted([h.ip for h in hosts])), encoding="utf-8")
                
                # Get ports for each host from services
                host_ports: dict[str, set[int]] = {}
                for host in hosts:
                    services = s.scalars(
                        select(Service).where(Service.host_id == host.id)
                    ).all()
                    ports = {svc.port for svc in services if svc.protocol == "tcp"}
                    if ports:
                        host_ports[host.ip] = ports
                
                # Run nmap with vulners script for each host
                for host in hosts:
                    if host.ip not in host_ports:
                        continue
                    
                    ports = sorted(host_ports[host.ip])
                    nmap_args = [
                        settings.nmap_path,
                        "-sS",
                        "-sV",
                        "--script", "vulners",
                        "-p", ",".join(str(p) for p in ports),
                        "-n",
                        "-PN",
                        "-oX", str(date_dir / f"vulners_{host.ip.replace('.', '_')}.xml"),
                        host.ip,
                    ]
                    
                    if logger:
                        logger.info("Running nmap vulners for host=%s", host.ip)
                    
                    try:
                        proc = subprocess.run(nmap_args, capture_output=True, text=True, timeout=600)
                        if proc.returncode != 0:
                            console.print(f"Warning: nmap failed for {host.ip}: {proc.stderr}", style="yellow")
                            continue
                        
                        # Parse vulnerabilities from XML
                        xml_path = date_dir / f"vulners_{host.ip.replace('.', '_')}.xml"
                        if xml_path.exists():
                            host_cves = extract_cves_from_nmap_xml(str(xml_path))
                            if host.ip in host_cves:
                                cve_list = host_cves[host.ip]
                                time_discovery = last_scan.started_at if isinstance(last_scan.started_at, datetime) else datetime.now(timezone.utc)
                                
                                epss_scores: list[float] = []
                                for cve_id in cve_list:
                                    # Check if already exists
                                    existing = s.scalar(
                                        select(Vulnerability).where(
                                            Vulnerability.host_id == host.id,
                                            Vulnerability.cve_id == cve_id
                                        )
                                    )
                                    if existing:
                                        continue
                                    
                                    epss_data = get_epss_score(settings, cve_id)
                                    vuln = Vulnerability(
                                        host_id=host.id,
                                        cve_id=cve_id,
                                        epss=epss_data["epss"],
                                        percentile=epss_data["percentile"],
                                        time_discovery=time_discovery,
                                    )
                                    s.add(vuln)
                                    if epss_data["epss"] > 0:
                                        epss_scores.append(epss_data["epss"])
                                
                                # Calculate exploit probability
                                if epss_scores:
                                    exploit_prob = calculate_exploit_probability(
                                        epss_scores, settings.epss_significant_threshold
                                    )
                                    host_vulns = s.scalars(
                                        select(Vulnerability).where(Vulnerability.host_id == host.id)
                                    ).all()
                                    for vuln in host_vulns:
                                        vuln.exploit_probability = exploit_prob
                                
                                s.flush()
                                console.print(f"Found {len(cve_list)} CVE(s) for {host.ip}")
                    except subprocess.TimeoutExpired:
                        console.print(f"Warning: nmap timeout for {host.ip}", style="yellow")
                    except Exception as e:
                        console.print(f"Error scanning {host.ip}: {str(e)}", style="red")
                        if logger:
                            logger.info("Vulners scan error for host=%s: %s", host.ip, str(e))
            
            console.print("Vulnerability scan completed.")
            if logger:
                logger.info("Vulners scan completed for tenant=%s", tenant)


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
        info_table_data = _table_to_data(info_table)
        console.print(info_table)
        console.print()

        pdf_blocks: list[dict] = [info_table_data]

        # Hosts added/removed
        if hosts_added or hosts_removed:
            hr_table = Table(title="Hosts changes")
            hr_table.add_column("Type")
            hr_table.add_column("Hosts")
            if hosts_added:
                hr_table.add_row("Added", ", ".join(hosts_added))
            if hosts_removed:
                hr_table.add_row("Removed", ", ".join(hosts_removed))
            hr_table_data = _table_to_data(hr_table)
            console.print(hr_table)
            console.print()
            pdf_blocks.append(hr_table_data)
        else:
            console.print("No host changes", style="green")
            console.print()
            hr_table = Table(title="Hosts changes")
            hr_table.add_column("Type")
            hr_table.add_column("Hosts")
            hr_table.add_row("Info", "No host changes")
            pdf_blocks.append(_table_to_data(hr_table))

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
            ht_data = _table_to_data(ht)
            console.print(ht)
            console.print()
            pdf_blocks.append(ht_data)

        if not any_port_changes:
            console.print("No port changes on common hosts", style="green")
            console.print()
            port_table = Table(title="Port Changes")
            port_table.add_column("Info")
            port_table.add_row("No port changes on common hosts")
            pdf_blocks.append(_table_to_data(port_table))

        if pdf:
            scan_dt = newer.started_at if isinstance(newer.started_at, datetime) else None
            pdf_path = _export_pdf_report(
                settings,
                tenant_name=t.name,
                report_type="diff-scans",
                scan_dt=scan_dt,
                title=f"Scan Diff Report: {t.name}",
                blocks=pdf_blocks,
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
@click.option("--vulners", is_flag=True, help="Enable nmap vulners script (requires --service-info)")
@click.option("--nuclei", is_flag=True, help="Run nuclei web scan after nmap parse")
@click.option("--iL", "input_list", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=False, help="File with targets for masscan (-iL). If set, targets are taken from file, not from DB")
@click.option("--all-tenants", is_flag=True, help="Scan all tenants sequentially with their individual settings")
@click.option("--rate", "rate_override", type=click.IntRange(min=1), required=False, help="Override masscan rate for this run")
@click.pass_context
def scan_cmd(ctx: click.Context, tenant: Optional[str], mode: str, service_info: bool, vulners: bool, nuclei: bool, input_list: Optional[Path], all_tenants: bool, rate_override: Optional[int]) -> None:  # type: ignore[override]
    """Run scan(s).

    - Single tenant: specify --tenant NAME
    - All tenants: use --all-tenants (tenant is ignored)
    - If --iL is provided, masscan will read targets from the specified file (not from tenant networks) — only valid for single-tenant scans.
    - --rate overrides the masscan rate (defaults to settings.rate when omitted).
    - --vulners enables nmap vulners script for CVE detection (requires --service-info).
    """
    if vulners and not service_info:
        console.print("--vulners requires --service-info", style="red")
        sys.exit(1)
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
                    logger.info(
                        "Scan requested (all-tenants): tenant=%s mode=%s service_info=%s nuclei=%s rate=%s",
                        t.name,
                        mode,
                        service_info,
                        str(nuclei),
                        str(rate_override) if rate_override is not None else "(default)",
                    )
                    run_scan_for_tenant(
                    settings,
                    tenant_name=t.name,
                    mode=mode,
                    service_info=service_info,
                    input_list=None,
                    rate_override=rate_override,
                    vulners=vulners,
                    nuclei=nuclei,
                )
        return

    if not tenant:
        console.print("--tenant is required unless --all-tenants is specified", style="red")
        sys.exit(1)
    if logger:
        logger.info(
            "Scan requested: tenant=%s mode=%s service_info=%s nuclei=%s iL=%s rate=%s",
            tenant,
            mode,
            service_info,
            str(nuclei),
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
        vulners=vulners,
        nuclei=nuclei,
    )


@cli.command("scan-nuclei")
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--scan-id", type=int, required=False, default=None, help="Reuse results of specific scan id (defaults to latest scan for tenant)")
@click.pass_context
def scan_nuclei_cmd(ctx: click.Context, tenant: str, scan_id: Optional[int]) -> None:  # type: ignore[override]
    """Run nuclei scan for an existing scan (or the latest one) without rerunning masscan/nmap."""
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)

    with get_session(engine) as s:
        tenant_obj = get_tenant_by_name(s, tenant)
        if not tenant_obj:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)

        scan_obj: Scan | None = None
        if scan_id is not None:
            scan_obj = get_scan_by_id(s, scan_id)
            if not scan_obj or scan_obj.tenant_id != tenant_obj.id:
                console.print(f"Scan id={scan_id} not found for tenant '{tenant_obj.name}'", style="red")
                sys.exit(1)
        else:
            scan_obj = (
                s.scalar(
                    select(Scan)
                    .where(Scan.tenant_id == tenant_obj.id)
                    .order_by(Scan.started_at.desc())
                )
            )
            if not scan_obj:
                console.print(f"No scans found for tenant '{tenant_obj.name}'", style="yellow")
                sys.exit(1)

        scan_started = scan_obj.started_at or datetime.now(timezone.utc)
        output_dir = settings.data_dir / tenant_obj.name / scan_started.strftime("%Y%m%d")
        output_dir.mkdir(parents=True, exist_ok=True)
        scan_id_value = scan_obj.id
        tenant_name = tenant_obj.name

    if logger:
        logger.info("Running nuclei scan: tenant=%s scan_id=%s", tenant_name, scan_id_value)

    run_nuclei_scan_for_scan(
        engine=engine,
        settings=settings,
        tenant_name=tenant_name,
        scan_id=scan_id_value,
        output_dir=output_dir,
        logger=logger,
    )


@cli.command("delete-nuclei")
@click.option("--tenant", required=True, help="Tenant name")
@click.option("--nuclei-scan-id", type=int, required=True, help="Nuclei scan id to delete")
@click.option("--yes", is_flag=True, help="Confirm deletion")
@click.pass_context
def delete_nuclei_cmd(ctx: click.Context, tenant: str, nuclei_scan_id: int, yes: bool) -> None:  # type: ignore[override]
    """Delete a nuclei scan and all its findings (requires --yes)."""
    if not yes:
        console.print("Use --yes to confirm deletion", style="yellow")
        sys.exit(1)
    settings: Settings = ctx.obj["settings"]
    logger = ctx.obj.get("logger")
    engine = create_sqlite_engine(settings.sqlite_path)
    init_db(engine)
    
    with get_session(engine) as s:
        tenant_obj = get_tenant_by_name(s, tenant)
        if not tenant_obj:
            console.print(f"Tenant '{tenant}' not found", style="red")
            sys.exit(1)
        
        nuclei_scan = get_nuclei_scan_by_id(s, nuclei_scan_id)
        if not nuclei_scan or nuclei_scan.tenant_id != tenant_obj.id:
            console.print(f"Nuclei scan id={nuclei_scan_id} not found for tenant '{tenant}'", style="red")
            sys.exit(1)
        
        scan_id = nuclei_scan.scan_id
        delete_nuclei_scan(s, nuclei_scan)
        if logger:
            logger.info("Nuclei scan deleted: id=%s tenant=%s scan_id=%s", nuclei_scan_id, tenant, scan_id)
        console.print(f"Deleted nuclei scan id={nuclei_scan_id} for tenant '{tenant}'")

