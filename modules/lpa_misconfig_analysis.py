#!/usr/bin/env python3

"""
lpa-misconfig_analysis.py

Analyse misconfigurations in privilege-related tooling, primarily:
  - sudo NOPASSWD / misconfigured sudo rules
  - SUID binaries that are dangerous if misconfigured

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
  - pkb/skb: used by the engine when rendering (we just emit issue keys)
"""

# A reasonably broad set of binaries that are dangerous when misconfigured.
# This is intentionally GTFOBins-flavoured and can be extended via PKB.
DANGEROUS_BINARIES = [
    # Editors / pagers / shells
    "sh", "bash", "dash", "zsh",
    "vi", "vim", "nvim", "nano",
    "less", "more", "man",

    # Find / text / processing
    "find", "awk", "sed", "grep",

    # Interpreters / runtimes
    "python", "python2", "python3",
    "perl", "ruby", "php", "lua", "node",

    # Archiving / file operations
    "tar", "zip", "unzip", "cp", "mv", "rsync", "tee",

    # System / service / misc
    "systemctl", "journalctl", "env", "nice", "timeout",
]

def _line_contains_binary(line, bin_name):
    """
    Simple heuristic to check if a line references a given binary.
    Avoids partial matches like 'cp' in 'tcpdump'.
    """
    # crude but effective: space, start, slash, or equals before; space or end after
    import re
    pattern = rf"(^|[\s:=/]){bin_name}($|[\s])"
    return re.search(pattern, line) is not None


def _detect_sudo_misconfigs(section_text):
    """
    Detect sudo misconfigurations, especially NOPASSWD rules
    involving dangerous binaries.
    """
    findings = []

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Heuristic: sudoers-style lines or sudo -l output
        if "sudo" not in line.lower() and "NOPASSWD" not in line:
            continue

        # Focus on NOPASSWD or ALL=(ALL:ALL) style rules
        if "NOPASSWD" in line or "ALL=(ALL" in line or "ALL : ALL" in line:
            for bin_name in DANGEROUS_BINARIES:
                if _line_contains_binary(line, bin_name):
                    issue_key = f"sudo-{bin_name}-nopasswd"
                    findings.append({
                        "item": raw_line,
                        "issue": issue_key,
                        "details": f"Potentially dangerous sudo rule involving {bin_name}"
                    })
                    break

    return findings


def _detect_suid_binaries(section_text):
    """
    Detect SUID binaries that are known to be dangerous if misconfigured.
    Relies on linpeas-style SUID listings in section_text.
    """
    findings = []

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lower = line.lower()
        # Heuristic: lines that look like SUID listings
        if "suid" not in lower and "sgid" not in lower and " -rws" not in lower:
            # many linpeas SUID lines won't literally say 'suid', so also look for typical perms
            continue

        for bin_name in DANGEROUS_BINARIES:
            if bin_name in line and "/" in line:
                issue_key = f"suid-{bin_name}"
                findings.append({
                    "item": raw_line,
                    "issue": issue_key,
                    "details": f"SUID/SGID or special-perms binary: {bin_name}"
                })
                break

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "priv-esc"
    subsection_id:  e.g. "sudo", "suid-binaries" (may be None)
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
          "issue": "sudo-nano-nopasswd",
          "details": "short explanation",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    findings = []

    # We don't strictly need pkb/skb here; the engine uses them when rendering.
    # pkb = context.get("pkb", {})
    # skb = context.get("skb", {})

    # Run individual detectors
    findings.extend(_detect_sudo_misconfigs(section_text))
    findings.extend(_detect_suid_binaries(section_text))

    return findings

