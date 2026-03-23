"""Entropy-based secret detection for catching unknown secret formats."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


# Characters typical of high-entropy secrets
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARS = set("0123456789abcdefABCDEF")

# Common false positives to skip
FALSE_POSITIVE_PATTERNS = {
    # File paths, URLs, HTML/CSS/JS common tokens
    re.compile(r'^https?://'),
    re.compile(r'^/[\w/.\-]+$'),
    re.compile(r'^[a-zA-Z]:\\'),
    re.compile(r'^\w+\.\w+\.\w+$'),  # dotted names like com.example.app
    re.compile(r'^[0-9a-f]{32}$', re.I),  # MD5 hashes (common, not secrets)
    re.compile(r'^[0-9a-f]{40}$', re.I),  # SHA-1 hashes (git commits)
    re.compile(r'^[0-9a-f]{64}$', re.I),  # SHA-256 hashes
}


@dataclass
class EntropyHit:
    """A high-entropy string that might be a secret."""

    value: str
    entropy: float
    line_number: int
    start: int
    end: int
    charset: str  # "base64", "hex", "mixed"

    @property
    def truncated(self) -> str:
        """Show first 8 and last 4 chars."""
        if len(self.value) <= 16:
            return self.value
        return f"{self.value[:8]}...{self.value[-4:]}"


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0

    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def _classify_charset(s: str) -> str:
    """Classify the character set of a string."""
    chars = set(s)
    if chars <= HEX_CHARS:
        return "hex"
    if chars <= BASE64_CHARS:
        return "base64"
    return "mixed"


def _is_false_positive(s: str) -> bool:
    """Check if a string is likely a false positive."""
    for pat in FALSE_POSITIVE_PATTERNS:
        if pat.match(s):
            return True
    # All same character repeated
    if len(set(s)) <= 2:
        return True
    # Looks like a version string (1.2.3.4.5...)
    if re.match(r'^[\d.]+$', s):
        return True
    return False


# Regex to extract candidate tokens from text
TOKEN_RE = re.compile(r'[A-Za-z0-9+/=_\-]{20,}')


def scan_entropy(
    text: str,
    threshold: float = 4.5,
    min_length: int = 20,
    max_length: int = 500,
) -> list[EntropyHit]:
    """Scan text for high-entropy strings that might be secrets.

    Args:
        text: The text to scan.
        threshold: Minimum bits-per-character entropy to flag (default 4.5).
        min_length: Minimum string length to consider.
        max_length: Maximum string length to consider.

    Returns:
        List of EntropyHit for each suspicious string.
    """
    hits: list[EntropyHit] = []

    for line_idx, line in enumerate(text.splitlines(), start=1):
        for match in TOKEN_RE.finditer(line):
            token = match.group(0)

            if len(token) < min_length or len(token) > max_length:
                continue

            if _is_false_positive(token):
                continue

            ent = shannon_entropy(token)
            if ent >= threshold:
                hits.append(EntropyHit(
                    value=token,
                    entropy=round(ent, 2),
                    line_number=line_idx,
                    start=match.start(),
                    end=match.end(),
                    charset=_classify_charset(token),
                ))

    return hits


def redact_high_entropy(
    text: str,
    threshold: float = 4.5,
    min_length: int = 20,
    replacement: str = "[REDACTED:high-entropy]",
) -> str:
    """Redact high-entropy strings from text."""
    hits = scan_entropy(text, threshold=threshold, min_length=min_length)

    # Sort by position (reverse) to replace from end to start
    hits_sorted = sorted(hits, key=lambda h: (h.line_number, h.start), reverse=True)

    lines = text.splitlines(keepends=True)
    for hit in hits_sorted:
        line_idx = hit.line_number - 1
        if 0 <= line_idx < len(lines):
            line = lines[line_idx]
            lines[line_idx] = line[:hit.start] + replacement + line[hit.end:]

    return "".join(lines)
