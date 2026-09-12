# lpa_credential_exposures.py

import re

# Canonical pattern lists – extend these over time as you see new cases
PASSWORD_PATTERNS = [
    "PASSWORD=", "password=", "db_password", "mysql user=", "config.bak contains password=",
]

TOKEN_PATTERNS = [
    "secret=", "api_key=", "token=",
]

AWS_ACCESS_KEY_PATTERNS = [
    "AWS_ACCESS_KEY_ID=",
]

AWS_SECRET_KEY_PATTERNS = [
    "AWS_SECRET_ACCESS_KEY=",
]

SSH_KEY_MARKERS = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
]


def process(section_id, subsection_id, context):
    """
    Normalizes all credential findings into PKB-canonical issues:

      - ssh_key_exposed
      - cred-aws
      - cred-password
      - cred-token

    Each line can trigger multiple issues (e.g. AWS key + generic token),
    but (line, issue) pairs are deduped.
    """
    section_text = context.get("section_text", "") or ""
    findings = []
    seen = set()  # (line, issue)

    def add(raw_line, issue, details):
        key = (raw_line, issue)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "item": raw_line.strip(),
            "issue": issue,
            "details": details,
        })

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # 1) SSH private keys
        if any(marker in line for marker in SSH_KEY_MARKERS):
            add(
                raw_line,
                "ssh_key_exposed",
                "Exposed SSH private key material detected",
            )

        # 2) AWS credentials (access key / secret key)
        if any(p in line for p in AWS_ACCESS_KEY_PATTERNS) or any(
            p in line for p in AWS_SECRET_KEY_PATTERNS
        ):
            add(
                raw_line,
                "cred-aws",
                "AWS credential detected in environment or files",
            )

        # 3) Plaintext passwords
        if any(p in line for p in PASSWORD_PATTERNS):
            add(
                raw_line,
                "cred-password",
                "Potential plaintext password exposure",
            )

        # 4) Generic tokens / secrets
        if any(p in line for p in TOKEN_PATTERNS):
            add(
                raw_line,
                "cred-token",
                "Potential token or secret exposure",
            )

    return findings
