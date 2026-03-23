"""Streaming mode: process stdin line-by-line for piping."""

from __future__ import annotations

import sys
from typing import TextIO

from .redactor import Redactor


def stream_redact(
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
    redactor: Redactor | None = None,
    show_count: bool = False,
) -> int:
    """Stream-redact from input to output, line by line.

    Args:
        input_stream: Input (defaults to stdin).
        output_stream: Output (defaults to stdout).
        redactor: Redactor instance (defaults to all patterns).
        show_count: If True, print redaction count to stderr at end.

    Returns:
        Total number of redactions made.
    """
    inp = input_stream or sys.stdin
    out = output_stream or sys.stdout
    r = redactor or Redactor()
    total = 0

    try:
        for line in inp:
            # Strip trailing newline, redact, then re-add newline
            stripped = line.rstrip("\n")
            redacted, count = r.redact_line(stripped)
            total += count
            out.write(redacted + "\n")
            out.flush()
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass

    if show_count and total > 0:
        sys.stderr.write(f"\n[safe-logs] Redacted {total} secret(s)\n")

    return total
