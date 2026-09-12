#!/usr/bin/env python3

import re

HOSTNAME_REGEX = re.compile(r"\b(hostname)\b\s*[:=]?\s*(\S+)", re.IGNORECASE)
KERNEL_REGEX = re.compile(
    r"\b(kernel|linux)\s*(version)?\b\s*[:=]?\s*([0-9]+\.[0-9]+\.[0-9][0-9a-z\.\-+]*)",
    re.IGNORECASE,
)
OS_REGEX = re.compile(
    r"\b(ubuntu|debian|centos|red hat|rhel|fedora|alpine|arch|kali|linux mint|suse)\b",
    re.IGNORECASE,
)
ARCH_REGEX = re.compile(r"\b(x86_64|amd64|i386|i686|arm|aarch64)\b", re.IGNORECASE)


def _detect_hostname(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        m = HOSTNAME_REGEX.search(raw_line)
        if not m:
            continue
        hostname = m.group(2)
        findings.append({
            "item": raw_line,
            "issue": "system_hostname",
            "details": f"Hostname detected: {hostname}",
        })
    return findings


def _detect_kernel(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        m = KERNEL_REGEX.search(raw_line)
        if not m:
            continue
        version = m.group(3)
        findings.append({
            "item": raw_line,
            "issue": "system_kernel_version",
            "details": f"Kernel version detected: {version}",
        })
    return findings


def _detect_os(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        m = OS_REGEX.search(raw_line)
        if not m:
            continue
        os_name = m.group(1)
        findings.append({
            "item": raw_line,
            "issue": "system_os",
            "details": f"Operating system detected: {os_name}",
        })
    return findings


def _detect_arch(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        m = ARCH_REGEX.search(raw_line)
        if not m:
            continue
        arch = m.group(1)
        findings.append({
            "item": raw_line,
            "issue": "system_architecture",
            "details": f"Architecture detected: {arch}",
        })
    return findings


def _detect_generic_uname(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        lower = raw_line.lower()
        if "uname" in lower or "linux" in lower:
            findings.append({
                "item": raw_line,
                "issue": "system_uname_info",
                "details": "System uname-style information",
            })
    return findings


def process(section_id, subsection_id, context):
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_hostname(section_text))
    findings.extend(_detect_kernel(section_text))
    findings.extend(_detect_os(section_text))
    findings.extend(_detect_arch(section_text))
    findings.extend(_detect_generic_uname(section_text))

    return findings
