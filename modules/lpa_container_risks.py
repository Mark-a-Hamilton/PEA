#!/usr/bin/env python3

import re

# -----------------------------------
# REGEX PATTERNS
# -----------------------------------

DOCKER_SOCK_REGEX = re.compile(
    r"(/var/run/docker\.sock|docker\.sock).*exists", re.IGNORECASE
)

PRIVILEGED_CONTAINER_REGEX = re.compile(
    r"(privileged\s*:\s*true|--privileged|container\s+is\s+running\s+in\s+privileged\s+mode)",
    re.IGNORECASE
)

DOCKER_GROUP_REGEX = re.compile(
    r"(docker).*group", re.IGNORECASE
)

LXC_PRIV_REGEX = re.compile(
    r"(lxc|container).*privileged", re.IGNORECASE
)


# -----------------------------------
# DETECTION HELPERS
# -----------------------------------

def _detect_docker_sock(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if DOCKER_SOCK_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "container-docker-sock",
                "details": "docker.sock exposed — full host control possible",
            })
    return findings


def _detect_privileged_container(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if PRIVILEGED_CONTAINER_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "container-privileged",
                "details": "Privileged container detected",
            })
    return findings


def _detect_docker_group_membership(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if DOCKER_GROUP_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "docker_group_member",
                "details": "User is in docker group (root-equivalent access)",
            })
    return findings


def _detect_lxc_privileged(section_text):
    findings = []
    for raw_line in section_text.splitlines():
        if LXC_PRIV_REGEX.search(raw_line):
            findings.append({
                "item": raw_line,
                "issue": "lxc_privileged_container",
                "details": "Privileged LXC container detected",
            })
    return findings


# -----------------------------------
# MAIN MODULE ENTRYPOINT
# -----------------------------------

def process(section_id, subsection_id, context):
    section_text = context.get("section_text", "") or ""
    findings = []

    findings.extend(_detect_docker_sock(section_text))
    findings.extend(_detect_privileged_container(section_text))
    findings.extend(_detect_docker_group_membership(section_text))
    findings.extend(_detect_lxc_privileged(section_text))

    return findings
