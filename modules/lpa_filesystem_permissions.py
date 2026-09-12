#!/usr/bin/env python3

import re

# -----------------------------------
# REGEX PATTERNS
# -----------------------------------

WORLD_WRITABLE_FILE_REGEX = re.compile(
    r"^[-bcslp]..w..w..w.*\s(/[^ ]+)$"
)

WORLD_WRITABLE_DIR_REGEX = re.compile(
    r"^[d]..w..w..w.*\s(/[^ ]+)$"
)

PASSWD_WRITABLE_REGEX = re.compile(
    r"(/etc/passwd).*(writable|writeable|perm.*[0-7]{3})",
    re.IGNORECASE
)

SHADOW_WRITABLE_REGEX = re.compile(
    r"(/etc/shadow).*(writable|writeable|perm.*[0-7]{3})",
    re.IGNORECASE
)

SHADOW_READABLE_REGEX = re.compile(
    r"(/etc/shadow).*(readable|world-readable|group-readable|perm.*[0-7]{3})",
    re.IGNORECASE
)

WEAK_PERMS_REGEX = re.compile(
    r"(777|766|775|774|other\s+write|world-writable)",
    re.IGNORECASE
)

UMASK_REGEX = re.compile(
    r"\bumask\b\s+0?0?([0-7]{3})"
)


# -----------------------------------
# DETECTION HELPERS
# -----------------------------------

def _detect_world_writable_files(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        m = WORLD_WRITABLE_FILE_REGEX.search(raw_line)
        if not m:
            continue
        path = m.group(1)
        findings.append({
            "item": raw_line,
            "issue": "world_writable_file",
            "details": f"World-writable file detected: {path}",
        })
    return findings


def _detect_world_writable_dirs(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        m = WORLD_WRITABLE_DIR_REGEX.search(raw_line)
        if not m:
            continue
        path = m.group(1)
        findings.append({
            "item": raw_line,
            "issue": "world_writable_directory",
            "details": f"World-writable directory detected: {path}",
        })
    return findings


def _detect_passwd_shadow_perms(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if PASSWD_WRITABLE_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "passwd_writable",
                "details": "Writable /etc/passwd detected",
            })
        if SHADOW_WRITABLE_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "shadow_writable",
                "details": "Writable /etc/shadow detected",
            })
        if SHADOW_READABLE_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "shadow_readable",
                "details": "Readable /etc/shadow detected",
            })
    return findings


def _detect_weak_file_perms(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if WEAK_PERMS_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "weak_file_permissions",
                "details": f"Weak file permissions detected: {raw_line.strip()}",
            })
    return findings


def _detect_weak_umask(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        m = UMASK_REGEX.search(raw_line)
        if not m:
            continue
        umask_val = m.group(1)
        # Treat very permissive umasks as weak (e.g., 000, 002, 022)
        if umask_val in ("000", "002", "022"):
            findings.append({
                "item": raw_line,
                "issue": "weak_umask",
                "details": f"Weak system umask detected: {umask_val}",
            })
    return findings


# -----------------------------------
# MAIN MODULE ENTRYPOINT
# -----------------------------------

def process(section_id, subsection_id, context):
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_world_writable_files(section_text))
    findings.extend(_detect_world_writable_dirs(section_text))
    findings.extend(_detect_passwd_shadow_perms(section_text))
    findings.extend(_detect_weak_file_perms(section_text))
    findings.extend(_detect_weak_umask(section_text))

    return findings
