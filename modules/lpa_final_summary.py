# modules/lpa_final_summary.py

from collections import defaultdict

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

def process(section_id, subsection_id, context):
    findings = context.get("all_findings", []) or []

    # severity -> cve -> count
    summary = {
        sev: defaultdict(int)
        for sev in SEVERITY_ORDER
    }

    for f in findings:
        kb = f.get("kb", {}) or {}
        severity = (kb.get("severity") or "unknown").lower()
        issue_key = f.get("issue_key") or "UNKNOWN"

        # treat issue_key that looks like CVE as CVE, else group under its key
        cve = issue_key

        if severity not in summary:
            severity = "unknown"

        # count each distinct (issue_key, item) pair as one instance
        items = f.get("evidence", {}).get("items", []) or [None]
        seen_local = set()
        for item in items:
            key = (cve, item)
            if key in seen_local:
                continue
            seen_local.add(key)
            summary[severity][cve] += 1

    lines = []

    for sev in SEVERITY_ORDER:
        cve_counts = summary[sev]
        total = sum(cve_counts.values())
        if total == 0:
            continue

        label = sev.capitalize()
        lines.append(f"{label} = {total}")
        for cve, count in sorted(cve_counts.items()):
            lines.append(f"  {cve} = {count}")
        lines.append("")

    return "\n".join(lines).strip()
