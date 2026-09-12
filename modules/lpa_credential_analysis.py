#!/usr/bin/env python3

"""
lpa-credential_analysis.py

Analyse leaked or exposed credentials in linpeas output, including:
  - Private SSH keys
  - API tokens and secrets
  - Passwords in environment variables or config files
  - AWS keys
  - Git credentials
  - Database connection strings

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
  - pkb/skb: used by the engine when rendering (we just emit issue keys)

This module is intentionally heuristic-based: credential leakage appears in
many inconsistent formats across linpeas output.
"""

import re

# Patterns that strongly indicate credential leakage.
PRIVATE_KEY_MARKERS = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
]

PASSWORD_HINTS = [
    "password=",
    "passwd=",
    "pwd=",
    "db_pass",
    "db_password",
    "mysql_password",
    "postgres_password",
]

TOKEN_HINTS = [
    "token",
    "secret",
    "apikey",
    "api_key",
    "auth",
    "bearer",
]

AWS_KEY_REGEX = re.compile(r"(aws_access_key_id|aws_secret_access_key)", re.IGNORECASE)

GIT_CRED_HINTS = [
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "git-credential",
]

DB_CONN_HINTS = [
    "jdbc:",
    "postgres://",
    "mysql://",
    "mongodb://",
    "redis://",
]


def _detect_private_keys(section_text):
    """
    Detect private key material in linpeas output.
    """
    findings = []

    for raw_line in section_text.splitlines():
        for marker in PRIVATE_KEY_MARKERS:
            if marker.lower() in raw_line.lower():
                findings.append({
                    "item": raw_line,
                    "issue": "cred-private-key",
                    "details": f"Private key material detected: {marker}",
                })
                break

    return findings


def _detect_passwords(section_text):
    """
    Detect password-like strings.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for hint in PASSWORD_HINTS:
            if hint in lower:
                findings.append({
                    "item": raw_line,
                    "issue": "cred-password",
                    "details": f"Potential password leak: {hint}",
                })
                break

    return findings


def _detect_tokens(section_text):
    """
    Detect API tokens, secrets, and auth strings.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for hint in TOKEN_HINTS:
            if hint in lower:
                findings.append({
                    "item": raw_line,
                    "issue": "cred-token",
                    "details": f"Potential token/secret leak: {hint}",
                })
                break

    return findings


def _detect_aws_keys(section_text):
    """
    Detect AWS access keys and secret keys.
    """
    findings = []

    for raw_line in section_text.splitlines():
        if AWS_KEY_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "cred-aws",
                "details": "AWS credential detected",
            })

    return findings


def _detect_git_credentials(section_text):
    """
    Detect Git credential leaks.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for hint in GIT_CRED_HINTS:
            if hint in lower:
                findings.append({
                    "item": raw_line,
                    "issue": "cred-git",
                    "details": f"Potential Git credential leak: {hint}",
                })
                break

    return findings


def _detect_db_connection_strings(section_text):
    """
    Detect database connection strings.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for hint in DB_CONN_HINTS:
            if hint in lower:
                findings.append({
                    "item": raw_line,
                    "issue": "cred-db-connection",
                    "details": f"Database connection string detected: {hint}",
                })
                break

    return findings


def _detect_generic_credential_indicators(section_text):
    """
    Generic fallback for anything credential-like that doesn't fit the
    more specific detectors.
    """
    findings = []

    GENERIC_REGEX = re.compile(
        r"(key|secret|token|pass|credential|auth)[\s:=]", re.IGNORECASE
    )

    for raw_line in section_text.splitlines():
        if GENERIC_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "cred-generic",
                "details": "Generic credential indicator detected",
            })

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "credentials"
    subsection_id:  e.g. "ssh", "tokens", "aws" (may be None)
    context: {
        "pkb": dict,
        "skb": dict,
        "content": full linpeas text,
        "section_text": text for this section/subsection,
    }

    Returns: list of findings:
      [
        {
          "item": "... raw line ...",
          "issue": "cred-password",
          "details": "short explanation",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_private_keys(section_text))
    findings.extend(_detect_passwords(section_text))
    findings.extend(_detect_tokens(section_text))
    findings.extend(_detect_aws_keys(section_text))
    findings.extend(_detect_git_credentials(section_text))
    findings.extend(_detect_db_connection_strings(section_text))
    findings.extend(_detect_generic_credential_indicators(section_text))

    return findings

