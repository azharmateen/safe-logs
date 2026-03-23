# safe-logs

Automatically detect and redact secrets, API keys, and PII from terminal output, logs, and files. Never accidentally leak credentials again.

## Installation

```bash
pip install safe-logs
```

## Usage

```bash
# Pipe mode: redact stdin in real-time
npm start 2>&1 | safe-logs pipe

# Redact a log file
safe-logs file app.log
safe-logs file app.log --output app.redacted.log

# Scan a directory for files containing secrets
safe-logs scan ./logs/

# List all detection patterns
safe-logs patterns
safe-logs patterns --category cloud
```

## What It Detects

**Cloud Keys**: AWS Access Key, AWS Secret Key, Azure Connection String, GCP Service Account Key

**API Tokens**: Stripe (sk_live/pk_live), GitHub Token (ghp_/gho_/ghs_), OpenAI Key (sk-), Slack Token, Twilio, SendGrid, HuggingFace

**Auth**: JWTs, Bearer tokens, Basic auth headers, OAuth tokens, session cookies, password in URLs

**PII**: Email addresses, phone numbers, SSN, credit card numbers, IP addresses (v4/v6), MAC addresses

**Financial**: Credit card numbers (Visa, MC, Amex, Discover), IBAN, Bitcoin/Ethereum addresses

## Example

```
Input:  Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
Output: Authorization: Bearer [REDACTED-JWT]

Input:  OPENAI_API_KEY=sk-proj-abc123def456
Output: OPENAI_API_KEY=[REDACTED-OPENAI-KEY]

Input:  Contact john@example.com or 555-123-4567
Output: Contact [REDACTED-EMAIL] or [REDACTED-PHONE]
```

## License

MIT
