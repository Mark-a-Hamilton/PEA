#!/usr/bin/env python3

"""
lpa-cve_contextualisation.py

Extract contextual information around CVE references in linpeas output.

Purpose:
  - Identify CVE references
  - Capture surrounding context (package names, versions, kernel info)
  - Emit issue keys for the engine to enrich via PKB/SKB

This module does NOT:
  - Score CVEs
  - Enrich CVEs
  - Deduplicate CVEs

It simply extracts structured context for the engine to use later.
"""

import re

# Regex for CVE identifiers: CVE-YYYY-NNNN+
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)

# Regex for package/version patterns often found near CVEs
PKG_VERSION_REGEX = re.compile(
    r"([a-z0-9\-\._]+)\s+([0-9]+\.[0-9][a-z0-9\.\-\+]*)",
    re.IGNORECASE,
)

# Kernel version patterns
KERNEL_REGEX = re.compile(
    r"(kernel|linux)\s*version\s*[:=]?\s*([0-9]+\.[0-9]+\.[0-9]+)",
    re.IGNORECASE,
)


def _extract_cve_context(section_text):
    """
    Extract CVE references and any contextual metadata from nearby text.

    Context includes:
      - package names
      - versions
      - kernel versions
      - descriptive text around the CVE
    """
    findings = []

    for raw_line in section_text.splitlines():
        if not raw_line.strip():
            continue

        cves = CVE_REGEX.findall(raw_line)
        if not cves:
            continue

        # Extract package/version hints
        pkg_matches = PKG_VERSION_REGEX.findall(raw_line)
        pkg_context = [
            f"{pkg} {ver}" for (pkg, ver) in pkg_matches
        ] if pkg_matches else []

        # Extract kernel version hints
        kernel_matches = KERNEL_REGEX.findall(raw_line)
        kernel_context = [
            match[1] for match in kernel_matches
        ] if kernel_matches else []

        for cve in cves:
            normalized = cve.upper()
            issue_key = f"cve-context-{normalized.lower()}"

            details_parts = [f"CVE reference detected: {normalized}"]

            if pkg_context:
                details_parts.append(
                    "Package/version context: " + ", ".join(pkg_context)
                )

            if kernel_context:
                details_parts.append(
                    "Kernel context: " + ", ".join(kernel_context)
                )

            findings.append({
                "item": raw_line,
                "issue": issue_key,
                "details": "; ".join(details_parts),
            })

    return findings


def _extract_generic_vuln_context(section_text):
    """
    Fallback: detect generic vulnerability indicators that may relate to CVEs.
    """
    findings = []

    GENERIC_HINTS = [
        "vulnerable",
        "exploit",
        "patched",
        "security update",
        "advisory",
        "fix available",
    ]

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for hint in GENERIC_HINTS:
            if hint in lower:
                findings.append({
                    "item": raw_line,
                    "issue": "cve-generic-context",
                    "details": f"Generic vulnerability context: {hint}",
                })
                break

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "vulns"
    subsection_id:  e.g. "packages", "kernel" (may be None)
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
          "issue": "cve-context-cve-2021-4034",
          "details": "CVE reference detected: CVE-2021-4034; Package/version context: pkexec 0.105",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_extract_cve_context(section_text))
    findings.extend(_extract_generic_vuln_context(section_text))

    return findings

