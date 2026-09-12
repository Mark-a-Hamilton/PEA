#!/usr/bin/env python3

"""
lpa-execution_flow.py

Analyse execution-flow-related privilege escalation vectors, primarily:
  - PATH hijack opportunities (writable dirs, missing binaries)
  - Insecure service execution (custom scripts, world-writable units)
  - Cron / timer / job execution paths that can be hijacked
  - Interpreter / loader paths that can be influenced

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
  - pkb/skb: used by the engine when rendering (we just emit issue keys)

This module is intentionally heuristic-based: linpeas output varies widely.
"""

import re

WRITABLE_HINTS = [
    "writable",
    "writeable",
    "world-writable",
    "777",
]

MISSING_BINARY_HINTS = [
    "no such file or directory",
    "command not found",
    "not found",
]

CRON_HINTS = [
    "cron",
    "crontab",
    "/etc/cron.",
    "/var/spool/cron",
]

SERVICE_HINTS = [
    ".service",
    "systemd",
    "init.d",
    "/etc/rc.local",
]


def _detect_writable_exec_paths(section_text):
    """
    Detect writable paths that are part of execution flow:
      - scripts
      - services
      - cron jobs
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if not lower.strip():
            continue

        if not any(h in lower for h in WRITABLE_HINTS):
            continue

        if any(h in lower for h in CRON_HINTS + SERVICE_HINTS):
            findings.append({
                "item": raw_line,
                "issue": "exec-writable-exec-path",
                "details": "Writable path in execution flow (cron/service/script)",
            })

    return findings


def _detect_missing_binaries(section_text):
    """
    Detect missing binaries referenced in execution flow, which can be hijacked
    by placing a malicious binary earlier in PATH.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if not lower.strip():
            continue

        if any(h in lower for h in MISSING_BINARY_HINTS):
            findings.append({
                "item": raw_line,
                "issue": "exec-missing-binary",
                "details": "Missing binary in execution flow (potential hijack)",
            })

    return findings


def _detect_cron_exec_flow(section_text):
    """
    Detect cron jobs that reference writable or suspicious paths.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if not lower.strip():
            continue

        if not any(h in lower for h in CRON_HINTS):
            continue

        if any(h in lower for h in WRITABLE_HINTS):
            findings.append({
                "item": raw_line,
                "issue": "exec-cron-writable",
                "details": "Cron job referencing writable path",
            })
        else:
            findings.append({
                "item": raw_line,
                "issue": "exec-cron-job",
                "details": "Cron job in execution flow",
            })

    return findings


def _detect_service_exec_flow(section_text):
    """
    Detect services that reference writable or suspicious paths.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if not lower.strip():
            continue

        if not any(h in lower for h in SERVICE_HINTS):
            continue

        if any(h in lower for h in WRITABLE_HINTS):
            findings.append({
                "item": raw_line,
                "issue": "exec-service-writable",
                "details": "Service referencing writable path",
            })
        else:
            findings.append({
                "item": raw_line,
                "issue": "exec-service",
                "details": "Service in execution flow",
            })

    return findings


def _detect_interpreter_hijack(section_text):
    """
    Detect interpreter or loader paths that can be hijacked:
      - /usr/bin/python, /bin/sh, etc. in writable locations
    """
    findings = []

    INTERPRETER_HINTS = [
        "python",
        "perl",
        "ruby",
        "php",
        "sh",
        "bash",
        "dash",
        "zsh",
    ]

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if not lower.strip():
            continue

        if not any(h in lower for h in INTERPRETER_HINTS):
            continue

        if any(h in lower for h in WRITABLE_HINTS):
            findings.append({
                "item": raw_line,
                "issue": "exec-interpreter-writable",
                "details": "Interpreter in writable path (potential hijack)",
            })

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "exec-flow"
    subsection_id:  e.g. "cron", "services" (may be None)
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
          "issue": "exec-writable-exec-path",
          "details": "short explanation",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_writable_exec_paths(section_text))
    findings.extend(_detect_missing_binaries(section_text))
    findings.extend(_detect_cron_exec_flow(section_text))
    findings.extend(_detect_service_exec_flow(section_text))
    findings.extend(_detect_interpreter_hijack(section_text))

    return findings

