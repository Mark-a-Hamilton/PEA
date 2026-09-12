# lpa_sudo_misconfigurations.py

import re

SHELL_ESCAPE_BINARIES = [
    "nano", "vim", "vi", "nvim", "less", "more", "man",
    "awk", "perl", "python", "python3", "find", "tee",
    "cp", "mv", "bash", "sh", "zsh"
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

        # Detect wildcard sudo rules
        if "*" in line and "NOPASSWD" in line:
            add(line, "sudo_wildcard",
                "Wildcard NOPASSWD rule allows execution of arbitrary binaries")
            continue

        # Detect env_keep abuse
        if "env_keep" in line:
            add(line, "sudo_env_keep",
                "Sudo env_keep allows dangerous environment variables to persist")
            continue

        # Detect sudoedit abuse
        if "sudoedit" in line:
            add(line, "sudo_edit_abuse",
                "sudoedit allows editing privileged files")
            continue

        # Detect shell-escape-capable binaries under NOPASSWD
        if "NOPASSWD" in line:
            for binary in SHELL_ESCAPE_BINARIES:
                if re.search(rf"\b{binary}\b", line):
                    add(line, "sudo_shell_escape",
                        f"Shell-escape capable binary allowed under NOPASSWD: {binary}")
                    break

    return findings
