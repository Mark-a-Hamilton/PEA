#!/usr/bin/env python3

import re

# -----------------------------------
# REGEX PATTERNS
# -----------------------------------

OPEN_PORT_REGEX = re.compile(
    r"(tcp|udp)\s+\d+\s+LISTEN\s+.*(0\.0\.0\.0|\*)", re.IGNORECASE
)

CLEAR_TEXT_PROTOCOL_REGEX = re.compile(
    r"(ftp|telnet|imap|pop3|smtp)\s+.*(LISTEN|open)", re.IGNORECASE
)

FIREWALL_DISABLED_REGEX = re.compile(
    r"(ufw\s+disabled|firewalld\s+not\s+running|iptables\s+policy\s+ACCEPT)",
    re.IGNORECASE
)

EXPOSED_SERVICE_REGEX = re.compile(
    r"(http|https|ssh|rdp|vnc|redis|mongodb|mysql|postgres).*0\.0\.0\.0",
    re.IGNORECASE
)


# -----------------------------------
# DETECTION HELPERS
# -----------------------------------

def _detect_open_ports(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if OPEN_PORT_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "network_port_exposed",
                "details": "Service listening on all interfaces (0.0.0.0)",
            })
    return findings


def _detect_cleartext_protocols(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if CLEAR_TEXT_PROTOCOL_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "network_cleartext_protocol",
                "details": "Cleartext protocol exposed on the network",
            })
    return findings


def _detect_weak_firewall(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if FIREWALL_DISABLED_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "network_weak_firewall",
                "details": "Firewall appears disabled or permissive",
            })
    return findings


def _detect_exposed_services(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if EXPOSED_SERVICE_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "network_service_exposed",
                "details": "Potentially sensitive service exposed to the network",
            })
    return findings


# -----------------------------------
# MAIN MODULE ENTRYPOINT
# -----------------------------------

def process(section_id, subsection_id, context):
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_open_ports(section_text))
    findings.extend(_detect_cleartext_protocols(section_text))
    findings.extend(_detect_weak_firewall(section_text))
    findings.extend(_detect_exposed_services(section_text))

    return findings
