"""Report: count of redactions by type, locations, severity assessment."""

from __future__ import annotations

from .file_processor import FileResult
from .patterns import Severity
from .redactor import RedactionResult


def format_result_report(result: RedactionResult, source: str = "input") -> str:
    """Format a human-readable report for a single redaction result."""
    lines: list[str] = []

    if not result.has_secrets:
        lines.append(f"No secrets or PII found in {source}.")
        return "\n".join(lines)

    lines.append(f"Found {result.total_redactions} secret(s) in {source}:")
    lines.append("")

    # By category
    by_cat = result.hits_by_category()
    if by_cat:
        lines.append("  By category:")
        for cat, count in sorted(by_cat.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"    {cat:15s}  {count}")
        lines.append("")

    # By severity
    by_sev = result.hits_by_severity()
    if by_sev:
        lines.append("  By severity:")
        order = ["critical", "high", "medium", "low"]
        for sev in order:
            if sev in by_sev:
                marker = "!!!" if sev == "critical" else "!!" if sev == "high" else "!" if sev == "medium" else ""
                lines.append(f"    {sev:15s}  {by_sev[sev]} {marker}")
        lines.append("")

    # Locations (unique by line)
    seen_lines: set[int] = set()
    lines.append("  Locations:")
    for hit in result.hits:
        if hit.line_number not in seen_lines:
            seen_lines.add(hit.line_number)
            lines.append(f"    line {hit.line_number:5d}: {hit.pattern_name} ({hit.original_snippet})")
        if len(seen_lines) >= 50:
            remaining = len(result.hits) - len(seen_lines)
            if remaining > 0:
                lines.append(f"    ... and {remaining} more")
            break

    return "\n".join(lines)


def format_scan_report(file_results: list[FileResult]) -> str:
    """Format a report for a directory scan."""
    lines: list[str] = []

    if not file_results:
        lines.append("No secrets or PII found in scanned files.")
        return "\n".join(lines)

    total_secrets = sum(fr.result.total_redactions for fr in file_results)
    lines.append(f"Found {total_secrets} secret(s) across {len(file_results)} file(s):")
    lines.append("")

    # Sort files by severity (critical first)
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}

    def file_max_severity(fr: FileResult) -> int:
        if not fr.result.hits:
            return 99
        return min(severity_order.get(h.severity, 99) for h in fr.result.hits)

    sorted_results = sorted(file_results, key=file_max_severity)

    for fr in sorted_results:
        max_sev = "critical" if file_max_severity(fr) == 0 else (
            "high" if file_max_severity(fr) == 1 else (
            "medium" if file_max_severity(fr) == 2 else "low"))
        lines.append(f"  [{max_sev.upper():8s}] {fr.path} ({fr.result.total_redactions} findings)")

        # Top hits per file (up to 5)
        for hit in fr.result.hits[:5]:
            lines.append(f"             line {hit.line_number}: {hit.pattern_name}")
        if len(fr.result.hits) > 5:
            lines.append(f"             ... +{len(fr.result.hits) - 5} more")
        lines.append("")

    # Overall severity assessment
    lines.append("Severity assessment:")
    all_hits = [h for fr in file_results for h in fr.result.hits]
    critical = sum(1 for h in all_hits if h.severity == Severity.CRITICAL)
    high = sum(1 for h in all_hits if h.severity == Severity.HIGH)
    if critical:
        lines.append(f"  CRITICAL: {critical} finding(s) require immediate attention")
    if high:
        lines.append(f"  HIGH: {high} finding(s) should be addressed soon")

    return "\n".join(lines)
