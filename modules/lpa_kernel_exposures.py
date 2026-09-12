#!/usr/bin/env python3

import re

# -----------------------------
# REGEX PATTERNS
# -----------------------------

CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

DIRTY_PIPE_REGEX = re.compile(r"dirty\s*pipe|CVE-2022-0847", re.IGNORECASE)

GENERIC_KERNEL_EXPLOIT_REGEX = re.compile(
    r"(exploit|vulnerable|privilege\s*escalation|dirty\s*cow|overlayfs)",
    re.IGNORECASE,
)

WRITABLE_MODULE_DIR_REGEX = re.compile(
    r"(writable|writeable).*(/lib/modules|/usr/lib/modules)", re.IGNORECASE
)

UNRESTRICTED_DMESG_REGEX = re.compile(
    r"(dmesg_restrict\s*=\s*0|unrestricted\s*dmesg)", re.IGNORECASE
)

PROC_MEM_REGEX = re.compile(
    r"/proc/\d+/mem.*(readable|permissions|access)", re.IGNORECASE
)


# -----------------------------
# DETECTION HELPERS
# -----------------------------

def _detect_cves(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        for match in CVE_REGEX.findall(raw_line):
            cve = match.upper()

            # Dirty Pipe gets its own PKB entry
            if cve == "CVE-2022-0847":
                findings.append({
                    "item": raw_line,
                    "issue": "cve-cve-2022-0847",
                    "details": f"CVE reference detected: {cve}",
                })
            else:
                findings.append({
                    "item": raw_line,
                    "issue": "unpatched_cve",
                    "details": f"CVE reference detected: {cve}",
                })
    return findings


def _detect_dirty_pipe(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if DIRTY_PIPE_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "cve-cve-2022-0847",
                "details": "Dirty Pipe vulnerability indicator found",
            })
    return findings


def _detect_generic_kernel_exploits(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if GENERIC_KERNEL_EXPLOIT_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "kernel_exploit_possible",
                "details": "Potential kernel exploit indicator found",
            })
    return findings


def _detect_writable_kernel_modules(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if WRITABLE_MODULE_DIR_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "kernel_modules_writable",
                "details": "Writable kernel module directory detected",
            })
    return findings


def _detect_unrestricted_dmesg(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if UNRESTRICTED_DMESG_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "unrestricted_dmesg",
                "details": "Kernel dmesg output appears unrestricted",
            })
    return findings


def _detect_proc_mem(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if PROC_MEM_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "proc_mem_accessible",
                "details": "Process memory appears readable",
            })
    return findings


# -----------------------------
# MAIN MODULE ENTRYPOINT
# -----------------------------

def process(section_id, subsection_id, context):
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_cves(section_text))
    findings.extend(_detect_dirty_pipe(section_text))
    findings.extend(_detect_generic_kernel_exploits(section_text))
    findings.extend(_detect_writable_kernel_modules(section_text))
    findings.extend(_detect_unrestricted_dmesg(section_text))
    findings.extend(_detect_proc_mem(section_text))

    return findings
