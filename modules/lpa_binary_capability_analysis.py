#!/usr/bin/env python3

"""
lpa-binary_capability_analysis.py

Analyse binaries with Linux capabilities that are dangerous from a privilege
escalation perspective, primarily:
  - CAP_SYS_ADMIN, CAP_SETUID, CAP_SETGID, CAP_DAC_OVERRIDE, etc.
  - Any binary with a non-trivial capability set that looks interesting

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
    (typically the "Capabilities" or similar section)
  - pkb/skb: used by the engine when rendering (we just emit issue keys)
"""

# A reasonably broad set of capabilities that are dangerous or highly interesting.
# This is intentionally conservative but can be extended via PKB.
DANGEROUS_CAPS = [
    "cap_sys_admin",
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_sys_chroot",
    "cap_sys_boot",
    "cap_sys_time",
    "cap_net_admin",
]


def _normalise_caps(line):
    """
    Extract and normalise capability names from a line.

    linpeas-style capability lines often look like:
      /usr/bin/python3 = cap_setuid,cap_setgid+ep
      /usr/bin/ping = cap_net_raw+ep

    We don't try to fully parse the format; we just look for 'cap_*' tokens.
    """
    import re
    caps = set()

    for match in re.findall(r"cap_[a-z0-9_]+", line.lower()):
        caps.add(match.strip())

    return caps


def _extract_binary_path(line):
    """
    Best-effort extraction of a binary path from a capability line.

    Examples:
      '/usr/bin/python3 = cap_setuid+ep'
      'file: /usr/bin/ping  capabilities: cap_net_raw+ep'
    """
    import re

    # Prefer absolute paths
    m = re.search(r"(/[\w\-/\.]+)", line)
    if m:
        return m.group(1)

    # Fallback: last 'word' if it looks like a binary
    parts = line.strip().split()
    if parts:
        candidate = parts[0]
        if "/" in candidate:
            return candidate

    return None


def _detect_dangerous_capabilities(section_text):
    """
    Detect binaries that have dangerous capabilities assigned.

    We:
      - scan each line for capability tokens
      - intersect with DANGEROUS_CAPS
      - emit one finding per binary with at least one dangerous capability
    """
    findings = []

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if "cap_" not in line.lower():
            # Skip lines that clearly don't mention capabilities
            continue

        caps = _normalise_caps(line)
        if not caps:
            continue

        dangerous = sorted(caps.intersection(DANGEROUS_CAPS))
        if not dangerous:
            # Capabilities present, but none in our dangerous set
            continue

        binary = _extract_binary_path(line) or "<unknown-binary>"
        issue_key = "capabilities-" + "-".join(dangerous)

        findings.append({
            "item": raw_line,
            "issue": issue_key,
            "details": (
                f"Binary {binary} has dangerous capabilities: "
                + ", ".join(dangerous)
            ),
        })

    return findings


def _detect_any_capabilities(section_text):
    """
    Optionally flag any binary with capabilities at all, even if not in
    DANGEROUS_CAPS. This gives the operator a broader view.

    We keep this separate so you can later tune whether you want this noise.
    """
    findings = []

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if "cap_" not in line.lower():
            continue

        caps = _normalise_caps(line)
        if not caps:
            continue

        binary = _extract_binary_path(line) or "<unknown-binary>"
        issue_key = "capabilities-present"

        findings.append({
            "item": raw_line,
            "issue": issue_key,
            "details": (
                f"Binary {binary} has Linux capabilities: "
                + ", ".join(sorted(caps))
            ),
        })

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "priv-esc"
    subsection_id:  e.g. "capabilities" (may be None)
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
          "issue": "capabilities-cap_sys_admin-cap_setuid",
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

    findings.extend(_detect_dangerous_capabilities(section_text))
    findings.extend(_detect_any_capabilities(section_text))

    return findings

