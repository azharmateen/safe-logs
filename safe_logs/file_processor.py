"""File mode: process log files and output redacted versions."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .redactor import RedactionResult, Redactor


@dataclass
class FileResult:
    """Result of processing a single file."""

    path: str
    result: RedactionResult
    size_bytes: int
    output_path: str | None = None


def process_file(
    file_path: Path,
    output_path: Path | None = None,
    redactor: Redactor | None = None,
) -> FileResult:
    """Process a single file, optionally writing redacted output.

    Args:
        file_path: Path to the input file.
        output_path: If provided, write redacted output here.
        redactor: Redactor instance.

    Returns:
        FileResult with redaction details.
    """
    r = redactor or Redactor()

    with open(file_path, "r", errors="replace") as f:
        content = f.read()

    size = os.path.getsize(file_path)
    result = r.redact_text(content)

    out_path_str: str | None = None
    if output_path:
        with open(output_path, "w") as f:
            f.write(result.output)
        out_path_str = str(output_path)

    return FileResult(
        path=str(file_path),
        result=result,
        size_bytes=size,
        output_path=out_path_str,
    )


def scan_directory(
    dir_path: Path,
    extensions: set[str] | None = None,
    redactor: Redactor | None = None,
    max_file_size: int = 50 * 1024 * 1024,  # 50 MB
) -> list[FileResult]:
    """Scan a directory for files containing secrets.

    Args:
        dir_path: Directory to scan.
        extensions: File extensions to check (e.g., {".log", ".txt", ".env"}).
                    None means check all text-looking files.
        redactor: Redactor instance.
        max_file_size: Skip files larger than this.

    Returns:
        List of FileResult for files that contain secrets.
    """
    r = redactor or Redactor()
    default_extensions = {
        ".log", ".txt", ".env", ".cfg", ".conf", ".ini", ".yaml", ".yml",
        ".json", ".xml", ".toml", ".properties", ".sh", ".bash", ".zsh",
        ".py", ".js", ".ts", ".rb", ".go", ".java", ".rs", ".csv",
    }
    allowed = extensions or default_extensions
    results: list[FileResult] = []

    for root, _dirs, files in os.walk(dir_path):
        # Skip hidden directories and common non-text dirs
        parts = Path(root).parts
        if any(p.startswith(".") and p not in (".", "..") for p in parts):
            continue
        if any(p in ("node_modules", "__pycache__", "venv", ".venv") for p in parts):
            continue

        for fname in files:
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in allowed and fname not in (".env", ".env.local", ".env.production"):
                continue

            try:
                size = fpath.stat().st_size
            except OSError:
                continue

            if size > max_file_size or size == 0:
                continue

            try:
                file_result = process_file(fpath, redactor=r)
                if file_result.result.has_secrets:
                    results.append(file_result)
            except (OSError, UnicodeDecodeError):
                continue

    return results
