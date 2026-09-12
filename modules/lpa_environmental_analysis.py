#!/usr/bin/env python3

"""
lpa-enviromental_analysis.py

Analyse environment-variable-based privilege escalation vectors, primarily:
  - Dangerous environment variables (LD_PRELOAD, LD_LIBRARY_PATH, etc.)
  - PATH hijack opportunities
  - Suspicious or insecure environment variable values
  - Writable directories in PATH
  - Indicators of manipulated or poisoned environments

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
  - pkb/skb: used by the engine when rendering (we just emit issue keys)

This module is intentionally heuristic-based: linpeas output varies widely.
"""

import re

# Dangerous environment variables commonly abused for privilege escalation.
DANGEROUS_ENV_VARS = {
    "ld_preload": "env-ld-preload",
    "ld_library_path": "env-ld-library-path",
    "ld_audit": "env-ld-audit",
    "pythonpath": "env-pythonpath",
    "rubyopt": "env-rubyopt",
    "perl5lib": "env-perl5lib",
    "gconv_path": "env-gconv-path",
}

# Regex to detect PATH entries
PATH_REGEX = re.compile(r"\bPATH\s*=\s*(.*)", re.IGNORECASE)

# Writable directory indicators
WRITABLE_HINTS = [
    "writable",
    "writeable",
    "world-writable",
    "777",
]


def _detect_dangerous_env_vars(section_text):
    """
    Detect dangerous environment variables that can influence execution flow.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for env_var, issue in DANGEROUS_ENV_VARS.items():
            if env_var in lower:
                findings.append({
                    "item": raw_line,
                    "issue": issue,
                    "details": f"Dangerous environment variable detected: {env_var}",
                })

    return findings


def _extract_path_entries(path_value):
    """
    Split PATH into individual directories.
    """
    return [p.strip() for p in path_value.split(":") if p.strip()]


def _detect_path_hijack(section_text):
    """
    Detect PATH hijack opportunities:
      - writable directories in PATH
      - empty PATH entries
      - relative PATH entries ('.')
    """
    findings = []

    for raw_line in section_text.splitlines():
        m = PATH_REGEX.search(raw_line)
        if not m:
            continue

        path_value = m.group(1).strip()
        entries = _extract_path_entries(path_value)

        for entry in entries:
            lower = entry.lower()

            # Empty or relative PATH entries
            if entry == "" or entry == ".":
                findings.append({
                    "item": raw_line,
                    "issue": "env-path-relative",
                    "details": "Relative or empty PATH entry detected",
                })
                continue

            # Writable directory hints
            for hint in WRITABLE_HINTS:
                if hint in lower:
                    findings.append({
                        "item": raw_line,
                        "issue": "env-path-writable",
                        "details": f"Writable directory in PATH: {entry}",
                    })
                    break

    return findings


def _detect_suspicious_env_patterns(section_text):
    """
    Detect suspicious environment variable patterns:
      - embedded credentials
      - shell overrides
      - LD_* injection patterns
    """
    findings = []

    SUSPICIOUS_REGEX = re.compile(
        r"(pass|secret|token|auth|preload|library|inject)[\s:=]", re.IGNORECASE
    )

    for raw_line in section_text.splitlines():
        if SUSPICIOUS_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "env-suspicious",
                "details": "Suspicious environment variable pattern detected",
            })

    return findings


def _detect_shell_overrides(section_text):
    """
    Detect environment variables that override shell behaviour.
    """
    findings = []

    SHELL_HINTS = [
        "bashrc",
        "profile",
        "env=",
        "shell=",
        "ps1=",
    ]

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for hint in SHELL_HINTS:
            if hint in lower:
                findings.append({
                    "item": raw_line,
                    "issue": "env-shell-override",
                    "details": f"Shell override indicator: {hint}",
                })
                break

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "environment"
    subsection_id:  e.g. "vars", "path" (may be None)
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
          "issue": "env-ld-preload",
          "details": "short explanation",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_dangerous_env_vars(section_text))
    findings.extend(_detect_path_hijack(section_text))
    findings.extend(_detect_suspicious_env_patterns(section_text))
    findings.extend(_detect_shell_overrides(section_text))

    return findings

