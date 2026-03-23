"""CLI for safe-logs: pipe, file, scan, patterns."""

from __future__ import annotations

from pathlib import Path

import click

from .file_processor import process_file, scan_directory
from .patterns import Category, get_categories, get_patterns
from .redactor import Redactor
from .reporter import format_result_report, format_scan_report
from .streamer import stream_redact


@click.group()
@click.version_option(package_name="safe-logs")
def cli() -> None:
    """safe-logs: Detect and redact secrets/PII from logs and output."""


@cli.command()
@click.option("--category", "-c", default=None, help="Filter to a specific category.")
@click.option("--count/--no-count", default=True, help="Show redaction count on stderr.")
def pipe(category: str | None, count: bool) -> None:
    """Pipe mode: read stdin, output redacted to stdout.

    Usage: npm start 2>&1 | safe-logs pipe
    """
    cat = None
    if category:
        try:
            cat = Category(category.lower())
        except ValueError:
            valid = ", ".join(c.value for c in get_categories())
            raise click.BadParameter(f"Unknown category '{category}'. Valid: {valid}")

    redactor = Redactor(categories=[cat] if cat else None)
    stream_redact(redactor=redactor, show_count=count)


@cli.command("file")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, type=click.Path(), help="Write redacted output to file.")
@click.option("--quiet", "-q", is_flag=True, help="Only output the redacted text, no report.")
def file_cmd(logfile: str, output: str | None, quiet: bool) -> None:
    """Redact a single log file."""
    redactor = Redactor()
    out_path = Path(output) if output else None

    result = process_file(Path(logfile), output_path=out_path, redactor=redactor)

    if quiet:
        click.echo(result.result.output)
        return

    if out_path:
        click.echo(f"Redacted output written to: {out_path}")
    else:
        click.echo(result.result.output)

    click.echo("")
    click.echo(format_result_report(result.result, source=logfile))


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option("--ext", "-e", multiple=True, help="Additional file extensions to check (e.g., .csv).")
def scan(directory: str, ext: tuple[str, ...]) -> None:
    """Scan a directory for files containing secrets."""
    redactor = Redactor()

    extensions = None
    if ext:
        extensions = {e if e.startswith(".") else f".{e}" for e in ext}

    click.echo(f"Scanning {directory}...")
    results = scan_directory(Path(directory), extensions=extensions, redactor=redactor)

    click.echo(format_scan_report(results))


@cli.command()
@click.option("--category", "-c", default=None, help="Filter by category.")
def patterns(category: str | None) -> None:
    """List all detection patterns."""
    cat = None
    if category:
        try:
            cat = Category(category.lower())
        except ValueError:
            valid = ", ".join(c.value for c in get_categories())
            raise click.BadParameter(f"Unknown category '{category}'. Valid: {valid}")

    pat_list = get_patterns(cat)

    current_cat = None
    for p in pat_list:
        if p.category != current_cat:
            current_cat = p.category
            click.echo(f"\n{current_cat.value.upper()}:")
        severity_marker = {
            "critical": "[!!!]",
            "high": "[!! ]",
            "medium": "[!  ]",
            "low": "[   ]",
        }
        marker = severity_marker.get(p.severity.value, "")
        click.echo(f"  {marker} {p.name:30s}  {p.description}")

    click.echo(f"\nTotal: {len(pat_list)} patterns")
    if not cat:
        click.echo("Categories: " + ", ".join(c.value for c in get_categories()))


if __name__ == "__main__":
    cli()
