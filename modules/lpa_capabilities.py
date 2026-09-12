# lpa_capabilities.py

import re

# Capabilities that directly enable privilege escalation
DANGEROUS_CAPS = {
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_sys_admin",
    "cap_sys_ptrace",
}

def process(section_id, subsection_id, context):
    section_text = context.get("section_text", "") or ""
    findings = []
    seen = set()  # (binary, issue)

    def add(binary, issue, details):
        key = (binary, issue)
        if key in seen:
            return
        seen.add(key)
        findings.append({
            "item": binary,
            "issue": issue,
            "details": details,
        })

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue

        # Example: "/usr/bin/python3 = cap_setuid,cap_setgid+ep"
        match = re.match(r"(.+?)\s*=\s*(.+)", line)
        if not match:
            continue

        binary = match.group(1).strip()
        caps_raw = match.group(2)

        # Extract capability names (strip +ep, commas, etc.)
        caps = re.findall(r"cap_[a-zA-Z0-9_]+", caps_raw)

        # Classify capabilities
        dangerous = [c for c in caps if c in DANGEROUS_CAPS]
        normal = [c for c in caps if c not in DANGEROUS_CAPS]

        # Emit dangerous capability finding
        if dangerous:
            add(
                binary,
                "dangerous_capability",
                f"Binary has dangerous capabilities: {', '.join(dangerous)}",
            )

        # Emit non-dangerous capability finding
        if normal:
            add(
                binary,
                "linux_capability",
                f"Binary has Linux capabilities: {', '.join(normal)}",
            )

    return findings
