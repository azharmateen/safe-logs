"""Detection patterns for secrets, API keys, tokens, and PII.

40+ regex patterns organized by category with named groups, severity levels,
and human-readable descriptions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(Enum):
    CLOUD = "cloud"
    TOKEN = "token"
    AUTH = "auth"
    PII = "pii"
    FINANCIAL = "financial"
    CRYPTO = "crypto"
    INFRA = "infra"


@dataclass(frozen=True)
class Pattern:
    """A secret/PII detection pattern."""

    name: str
    regex: str
    replacement: str
    category: Category
    severity: Severity
    description: str

    @property
    def compiled(self) -> re.Pattern:
        return re.compile(self.regex)


# ============================================================
# All detection patterns
# ============================================================

PATTERNS: list[Pattern] = [
    # --- Cloud Keys ---
    Pattern(
        name="AWS Access Key",
        regex=r"(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])",
        replacement="[REDACTED-AWS-ACCESS-KEY]",
        category=Category.CLOUD,
        severity=Severity.CRITICAL,
        description="AWS IAM access key ID",
    ),
    Pattern(
        name="AWS Secret Key",
        regex=r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        replacement="[REDACTED-AWS-SECRET-KEY]",
        category=Category.CLOUD,
        severity=Severity.CRITICAL,
        description="AWS IAM secret access key (40-char base64)",
    ),
    Pattern(
        name="Azure Connection String",
        regex=r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+;?",
        replacement="[REDACTED-AZURE-CONN-STRING]",
        category=Category.CLOUD,
        severity=Severity.CRITICAL,
        description="Azure Storage connection string",
    ),
    Pattern(
        name="GCP Service Account Key",
        regex=r'"type"\s*:\s*"service_account"',
        replacement='"type": "[REDACTED-GCP-SA-KEY]"',
        category=Category.CLOUD,
        severity=Severity.CRITICAL,
        description="Google Cloud service account JSON key",
    ),
    Pattern(
        name="GCP API Key",
        regex=r"AIza[0-9A-Za-z_-]{35}",
        replacement="[REDACTED-GCP-API-KEY]",
        category=Category.CLOUD,
        severity=Severity.HIGH,
        description="Google Cloud API key",
    ),

    # --- API Tokens ---
    Pattern(
        name="OpenAI API Key",
        regex=r"sk-(?:proj-)?[A-Za-z0-9_-]{20,120}",
        replacement="[REDACTED-OPENAI-KEY]",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="OpenAI API key (sk- or sk-proj-)",
    ),
    Pattern(
        name="Stripe Secret Key",
        regex=r"sk_(?:live|test)_[A-Za-z0-9]{20,100}",
        replacement="[REDACTED-STRIPE-SECRET]",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="Stripe secret API key",
    ),
    Pattern(
        name="Stripe Publishable Key",
        regex=r"pk_(?:live|test)_[A-Za-z0-9]{20,100}",
        replacement="[REDACTED-STRIPE-PUB-KEY]",
        category=Category.TOKEN,
        severity=Severity.MEDIUM,
        description="Stripe publishable API key",
    ),
    Pattern(
        name="GitHub Token",
        regex=r"(?:ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}",
        replacement="[REDACTED-GITHUB-TOKEN]",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="GitHub personal access token or OAuth token",
    ),
    Pattern(
        name="GitLab Token",
        regex=r"glpat-[A-Za-z0-9_-]{20,}",
        replacement="[REDACTED-GITLAB-TOKEN]",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="GitLab personal access token",
    ),
    Pattern(
        name="Slack Token",
        regex=r"xox[bpras]-[A-Za-z0-9-]{10,250}",
        replacement="[REDACTED-SLACK-TOKEN]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Slack bot/user/app token",
    ),
    Pattern(
        name="Slack Webhook",
        regex=r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        replacement="[REDACTED-SLACK-WEBHOOK]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Slack incoming webhook URL",
    ),
    Pattern(
        name="Twilio API Key",
        regex=r"SK[0-9a-f]{32}",
        replacement="[REDACTED-TWILIO-KEY]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Twilio API key",
    ),
    Pattern(
        name="SendGrid API Key",
        regex=r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}",
        replacement="[REDACTED-SENDGRID-KEY]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="SendGrid API key",
    ),
    Pattern(
        name="HuggingFace Token",
        regex=r"hf_[A-Za-z0-9]{34,}",
        replacement="[REDACTED-HF-TOKEN]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="HuggingFace API token",
    ),
    Pattern(
        name="Anthropic API Key",
        regex=r"sk-ant-[A-Za-z0-9_-]{80,120}",
        replacement="[REDACTED-ANTHROPIC-KEY]",
        category=Category.TOKEN,
        severity=Severity.CRITICAL,
        description="Anthropic Claude API key",
    ),
    Pattern(
        name="Mailgun API Key",
        regex=r"key-[0-9a-f]{32}",
        replacement="[REDACTED-MAILGUN-KEY]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="Mailgun API key",
    ),
    Pattern(
        name="npm Token",
        regex=r"npm_[A-Za-z0-9]{36}",
        replacement="[REDACTED-NPM-TOKEN]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="npm publish token",
    ),
    Pattern(
        name="PyPI Token",
        regex=r"pypi-[A-Za-z0-9_-]{50,}",
        replacement="[REDACTED-PYPI-TOKEN]",
        category=Category.TOKEN,
        severity=Severity.HIGH,
        description="PyPI upload token",
    ),
    Pattern(
        name="Heroku API Key",
        regex=r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        replacement="[REDACTED-UUID]",
        category=Category.TOKEN,
        severity=Severity.LOW,
        description="UUID (could be Heroku API key or other token)",
    ),

    # --- Auth ---
    Pattern(
        name="JWT",
        regex=r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        replacement="[REDACTED-JWT]",
        category=Category.AUTH,
        severity=Severity.HIGH,
        description="JSON Web Token",
    ),
    Pattern(
        name="Bearer Token",
        regex=r"(?i)(Bearer\s+)[A-Za-z0-9_.\-/+=]{20,}",
        replacement=r"\1[REDACTED-BEARER-TOKEN]",
        category=Category.AUTH,
        severity=Severity.HIGH,
        description="HTTP Authorization Bearer token",
    ),
    Pattern(
        name="Basic Auth Header",
        regex=r"(?i)(Basic\s+)[A-Za-z0-9+/=]{10,}",
        replacement=r"\1[REDACTED-BASIC-AUTH]",
        category=Category.AUTH,
        severity=Severity.HIGH,
        description="HTTP Basic Auth base64 credentials",
    ),
    Pattern(
        name="Password in URL",
        regex=r"(?i)(://[^:]+:)[^@\s]+(@)",
        replacement=r"\1[REDACTED-PASSWORD]\2",
        category=Category.AUTH,
        severity=Severity.CRITICAL,
        description="Password embedded in URL",
    ),
    Pattern(
        name="Private Key",
        regex=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        replacement="[REDACTED-PRIVATE-KEY-HEADER]",
        category=Category.AUTH,
        severity=Severity.CRITICAL,
        description="PEM private key header",
    ),
    Pattern(
        name="Password Assignment",
        regex=r'(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*["\']?([^"\'\s,;}{]{6,})',
        replacement=r"[REDACTED-PASSWORD-VALUE]",
        category=Category.AUTH,
        severity=Severity.HIGH,
        description="Password or secret in config/env assignment",
    ),

    # --- PII ---
    Pattern(
        name="Email",
        regex=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        replacement="[REDACTED-EMAIL]",
        category=Category.PII,
        severity=Severity.MEDIUM,
        description="Email address",
    ),
    Pattern(
        name="Phone (US)",
        regex=r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}(?!\d)",
        replacement="[REDACTED-PHONE]",
        category=Category.PII,
        severity=Severity.MEDIUM,
        description="US phone number",
    ),
    Pattern(
        name="SSN",
        regex=r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
        replacement="[REDACTED-SSN]",
        category=Category.PII,
        severity=Severity.CRITICAL,
        description="US Social Security Number",
    ),
    Pattern(
        name="IPv4 Address",
        regex=r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)",
        replacement="[REDACTED-IPV4]",
        category=Category.PII,
        severity=Severity.LOW,
        description="IPv4 address",
    ),
    Pattern(
        name="IPv6 Address",
        regex=r"(?<![:\w])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![:\w])",
        replacement="[REDACTED-IPV6]",
        category=Category.PII,
        severity=Severity.LOW,
        description="IPv6 address (full form)",
    ),
    Pattern(
        name="MAC Address",
        regex=r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F:])",
        replacement="[REDACTED-MAC]",
        category=Category.PII,
        severity=Severity.LOW,
        description="MAC address",
    ),

    # --- Financial ---
    Pattern(
        name="Credit Card (Visa)",
        regex=r"(?<!\d)4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)",
        replacement="[REDACTED-CC-VISA]",
        category=Category.FINANCIAL,
        severity=Severity.CRITICAL,
        description="Visa credit card number",
    ),
    Pattern(
        name="Credit Card (Mastercard)",
        regex=r"(?<!\d)5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)",
        replacement="[REDACTED-CC-MC]",
        category=Category.FINANCIAL,
        severity=Severity.CRITICAL,
        description="Mastercard credit card number",
    ),
    Pattern(
        name="Credit Card (Amex)",
        regex=r"(?<!\d)3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}(?!\d)",
        replacement="[REDACTED-CC-AMEX]",
        category=Category.FINANCIAL,
        severity=Severity.CRITICAL,
        description="American Express credit card number",
    ),
    Pattern(
        name="IBAN",
        regex=r"(?<![A-Z0-9])[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})(?![A-Z0-9])",
        replacement="[REDACTED-IBAN]",
        category=Category.FINANCIAL,
        severity=Severity.HIGH,
        description="International Bank Account Number",
    ),

    # --- Crypto ---
    Pattern(
        name="Bitcoin Address",
        regex=r"(?<![A-Za-z0-9])(?:bc1|[13])[A-HJ-NP-Za-km-z1-9]{25,39}(?![A-Za-z0-9])",
        replacement="[REDACTED-BTC-ADDR]",
        category=Category.CRYPTO,
        severity=Severity.HIGH,
        description="Bitcoin wallet address",
    ),
    Pattern(
        name="Ethereum Address",
        regex=r"(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![A-Za-z0-9])",
        replacement="[REDACTED-ETH-ADDR]",
        category=Category.CRYPTO,
        severity=Severity.HIGH,
        description="Ethereum wallet address",
    ),

    # --- Infrastructure ---
    Pattern(
        name="Database URL",
        regex=r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"]+",
        replacement="[REDACTED-DB-URL]",
        category=Category.INFRA,
        severity=Severity.CRITICAL,
        description="Database connection URL with possible credentials",
    ),
    Pattern(
        name="SSH Connection",
        regex=r"ssh\s+-i\s+\S+\s+\S+@\S+",
        replacement="[REDACTED-SSH-CMD]",
        category=Category.INFRA,
        severity=Severity.MEDIUM,
        description="SSH connection command with identity file",
    ),
]


def get_patterns(category: Category | None = None) -> list[Pattern]:
    """Get patterns, optionally filtered by category."""
    if category is None:
        return list(PATTERNS)
    return [p for p in PATTERNS if p.category == category]


def get_categories() -> list[Category]:
    """Return all categories that have patterns."""
    seen: set[Category] = set()
    result: list[Category] = []
    for p in PATTERNS:
        if p.category not in seen:
            seen.add(p.category)
            result.append(p.category)
    return result
