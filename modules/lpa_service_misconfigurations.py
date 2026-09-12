# lpa_service_misconfigurations.py

import os
import re

SERVICE_FILE_PATTERNS = [
    ".service",
    ".timer",
    ".target",
]

EXEC_PATTERNS = [
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
]

INTERPRETER_NAMES = [
    "python", "python3", "bash", "sh", "zsh", "perl"
]


def process(section_id, subsection_id, context):
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

        # 1) Writable systemd unit files
        if any(p in line for p in SERVICE_FILE_PATTERNS) and "writable" in line:
            add(
                raw_line,
                "systemd_unit_writable",
                "Writable systemd unit file allows service hijack",
            )

        # 2) Missing binaries in ExecStart (path hijack)
        if "No such file or directory" in line:
            add(
                raw_line,
                "systemd_path_hijack",
                "Service references missing binary; attacker can place malicious binary",
            )

        # 3) Writable interpreters (e.g., /usr/bin/python writable)
        if "writable" in line and any(interp in line for interp in INTERPRETER_NAMES):
            add(
                raw_line,
                "weak_service_permissions",
                "Writable interpreter in service execution chain",
            )

        # 4) Writable scripts referenced by ExecStart
        if any(p in line for p in EXEC_PATTERNS):
            match = re.search(r"(/[^ ]+)", line)
            if match:
                path = match.group(1)
                if os.path.basename(path) and "writable" in raw_line:
                    add(
                        raw_line,
                        "weak_service_permissions",
                        "Writable script referenced by systemd service",
                    )

    return findings
