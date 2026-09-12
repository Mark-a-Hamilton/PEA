#!/usr/bin/env python3

"""
lpa-cv_collapse.py

Collapse and normalize CVE references found in linpeas output.

Purpose:
  - Extract CVE identifiers from any section of linpeas output
  - Normalize them into consistent issue keys
  - Emit one finding per CVE reference (engine handles deduplication)

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
  - pkb/skb: used by the engine when rendering (we just emit issue keys)

This module is intentionally simple: its job is to detect and normalize CVEs.
"""

import re

# Regex for CVE identifiers: CVE-YYYY-NNNN+
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


def _extract_cves(section_text):
    """
    Extract CVE references from the provided section text.

    We:
      - scan each line for CVE patterns
      - emit one finding per CVE occurrence
      - normalize issue keys to lowercase
    """
    findings = []

    for raw_line in section_text.splitlines():
        if not raw_line.strip():
            continue

        matches = CVE_REGEX.findall(raw_line)
        if not matches:
            continue

        for cve in matches:
            normalized = cve.upper()  # preserve canonical form
            issue_key = f"cve-{normalized.lower()}"

            findings.append({
                "item": raw_line,
                "issue": issue_key,
                "details": f"CVE reference detected: {normalized}",
            })

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "vulns"
    subsection_id:  e.g. "kernel", "packages" (may be None)
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
          "issue": "cve-cve-2021-4034",
          "details": "short explanation",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    return _extract_cves(section_text)

