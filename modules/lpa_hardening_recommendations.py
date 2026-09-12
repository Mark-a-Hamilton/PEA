#!/usr/bin/env python3

"""
lpa-hardening_recommendations.py

Analyse missing or weak hardening controls that impact privilege escalation, primarily:
  - Kernel hardening (ASLR, etc.)
  - MAC frameworks (AppArmor, SELinux)
  - Compiler / binary hardening hints (NX, PIE, RELRO)
  - General "disabled security feature" indicators

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
  - pkb/skb: used by the engine when rendering (we just emit issue keys)

This module is heuristic-based and focuses on flags that commonly appear
in linpeas hardening sections.
"""

import re

HARDENING_HINTS = {
    "aslr": "hardening-aslr",
    "kptr_restrict": "hardening-kptr-restrict",
    "dmesg_restrict": "hardening-dmesg-restrict",
    "yama": "hardening-yama",
    "apparmor": "hardening-apparmor",
    "selinux": "hardening-selinux",
}

DISABLED_WORDS = [
    "disabled",
    "off",
    "0 (off)",
    "not enabled",
    "permissive",
]


def _detect_kernel_hardening(section_text):
    """
    Detect kernel hardening settings that are disabled or weak.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if not lower.strip():
            continue

        for key, issue in HARDENING_HINTS.items():
            if key in lower and any(w in lower for w in DISABLED_WORDS):
                findings.append({
                    "item": raw_line,
                    "issue": issue,
                    "details": f"{key.upper()} appears disabled or weak",
                })
                break

    return findings


def _detect_binary_hardening(section_text):
    """
    Detect binary hardening hints (NX, PIE, RELRO) from linpeas output.
    We don't try to be exhaustive; we just flag obvious weaknesses.
    """
    findings = []

    # Typical patterns from checksec / linpeas
    WEAK_PATTERNS = {
        "no canary found": "hardening-no-canary",
        "nx disabled": "hardening-nx-disabled",
        "nx: disabled": "hardening-nx-disabled",
        "pie disabled": "hardening-pie-disabled",
        "relro: no": "hardening-relro-none",
        "partial relro": "hardening-relro-partial",
    }

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if not lower.strip():
            continue

        for pattern, issue in WEAK_PATTERNS.items():
            if pattern in lower:
                findings.append({
                    "item": raw_line,
                    "issue": issue,
                    "details": f"Binary hardening weakness: {pattern}",
                })
                break

    return findings


def _detect_generic_security_disabled(section_text):
    """
    Generic fallback: detect lines that mention security features being disabled.
    """
    findings = []

    GENERIC_REGEX = re.compile(
        r"(security|protect|harden|mitigation).*(disabled|off|0)", re.IGNORECASE
    )

    for raw_line in section_text.splitlines():
        if GENERIC_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "hardening-generic-disabled",
                "details": "Security-related feature appears disabled",
            })

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "hardening"
    subsection_id:  e.g. "kernel", "binaries" (may be None)
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
          "issue": "hardening-aslr",
          "details": "short explanation",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_kernel_hardening(section_text))
    findings.extend(_detect_binary_hardening(section_text))
    findings.extend(_detect_generic_security_disabled(section_text))

    return findings

