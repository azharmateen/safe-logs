"""Core redaction engine: apply patterns to text and track findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .patterns import PATTERNS, Category, Pattern, Severity


@dataclass
class RedactionHit:
    """A single redaction event."""

    pattern_name: str
    category: Category
    severity: Severity
    line_number: int
    original_snippet: str  # Truncated for safety


@dataclass
class RedactionResult:
    """Result of redacting text."""

    output: str
    hits: list[RedactionHit] = field(default_factory=list)
    total_redactions: int = 0

    @property
    def has_secrets(self) -> bool:
        return self.total_redactions > 0

    def hits_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for h in self.hits:
            key = h.category.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def hits_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for h in self.hits:
            key = h.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts


class Redactor:
    """Applies redaction patterns to text."""

    def __init__(
        self,
        patterns: list[Pattern] | None = None,
        categories: list[Category] | None = None,
        min_severity: Severity | None = None,
    ) -> None:
        self._patterns = patterns or list(PATTERNS)

        if categories:
            self._patterns = [p for p in self._patterns if p.category in categories]

        if min_severity:
            severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            min_idx = severity_order.index(min_severity)
            allowed = set(severity_order[min_idx:])
            self._patterns = [p for p in self._patterns if p.severity in allowed]

        # Compile all patterns once
        self._compiled: list[tuple[Pattern, re.Pattern]] = []
        for p in self._patterns:
            try:
                self._compiled.append((p, re.compile(p.regex)))
            except re.error:
                continue

    def redact_text(self, text: str) -> RedactionResult:
        """Redact all secrets/PII from the given text."""
        hits: list[RedactionHit] = []
        total = 0
        output = text

        # Process line by line to track line numbers
        lines = output.split("\n")
        redacted_lines: list[str] = []

        for line_num, line in enumerate(lines, start=1):
            for pattern, compiled in self._compiled:
                matches = list(compiled.finditer(line))
                for match in matches:
                    snippet = match.group(0)
                    # Truncate snippet for safety (don't log full secrets)
                    safe_snippet = snippet[:8] + "..." if len(snippet) > 12 else snippet[:4] + "..."
                    hits.append(RedactionHit(
                        pattern_name=pattern.name,
                        category=pattern.category,
                        severity=pattern.severity,
                        line_number=line_num,
                        original_snippet=safe_snippet,
                    ))
                    total += 1

                line = compiled.sub(pattern.replacement, line)
            redacted_lines.append(line)

        return RedactionResult(
            output="\n".join(redacted_lines),
            hits=hits,
            total_redactions=total,
        )

    def redact_line(self, line: str) -> tuple[str, int]:
        """Redact a single line. Returns (redacted_line, count)."""
        count = 0
        for pattern, compiled in self._compiled:
            new_line, n = compiled.subn(pattern.replacement, line)
            if n > 0:
                count += n
                line = new_line
        return line, count
