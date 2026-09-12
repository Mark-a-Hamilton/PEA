# lpa_environmental_issues.py

import re

LD_PRELOAD_PATTERNS = ["LD_PRELOAD="]
LD_LIBRARY_PATH_PATTERNS = ["LD_LIBRARY_PATH="]
PATH_PATTERNS = ["PATH="]

# Optional: only keep if you want a generic "suspicious env var" class
SUSPICIOUS_ENV_PATTERNS = ["secret=", "token=", "api_key="]


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

        # LD_PRELOAD injection
        if any(p in line for p in LD_PRELOAD_PATTERNS):
            add(
                raw_line,
                "ld_preload_injection",
                "LD_PRELOAD points to attacker-controlled library",
            )

        # LD_LIBRARY_PATH hijack
        if any(p in line for p in LD_LIBRARY_PATH_PATTERNS):
            add(
                raw_line,
                "ld_library_path_hijack",
                "LD_LIBRARY_PATH includes attacker-controlled directory",
            )

        # PATH hijack (writable directory in PATH)
        if any(p in line for p in PATH_PATTERNS):
            # Detect writable directory in PATH
            path_value = line.split("=", 1)[-1]
            dirs = path_value.split(":")
            for d in dirs:
                if d.startswith("/tmp") or d.startswith("/var/tmp"):
                    add(
                        raw_line,
                        "path_hijack",
                        f"Writable directory in PATH: {d}",
                    )

        # Optional: suspicious env vars
        if any(p in line for p in SUSPICIOUS_ENV_PATTERNS):
            add(
                raw_line,
                "cred-token",
                "Suspicious environment variable containing a token/secret",
            )

    return findings
