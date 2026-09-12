#!/usr/bin/env python3

"""
lpa-container_analysis.py

Analyse container-related misconfigurations and breakout vectors, primarily:
  - docker.sock exposure
  - privileged containers
  - writable container runtimes (runc, containerd)
  - LXC/LXD misconfigurations
  - Podman / Kubernetes hints
  - Host mounts inside containers

Relies on:
  - section_text: extracted from linpeas.out by the engine/profile
  - pkb/skb: used by the engine when rendering (we just emit issue keys)

This module is intentionally heuristic-based: linpeas output varies widely.
"""

# Keywords that strongly indicate container breakout vectors.
DANGEROUS_KEYWORDS = {
    "docker.sock": "container-docker-sock",
    "/var/run/docker.sock": "container-docker-sock",
    "privileged": "container-privileged",
    "lxc": "container-lxc",
    "lxd": "container-lxd",
    "containerd": "container-containerd",
    "runc": "container-runc",
    "podman": "container-podman",
    "kube": "container-kubernetes",
    "kubernetes": "container-kubernetes",
    "mount": "container-mount",
    "overlay": "container-overlayfs",
}

# Additional patterns that often appear in linpeas container sections.
HOST_MOUNT_HINTS = [
    "/etc",
    "/root",
    "/var/lib",
    "/proc",
    "/sys",
    "/dev",
]


def _detect_docker_sock(section_text):
    """
    Detect exposure of docker.sock, which allows full host compromise.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        if "docker.sock" in lower or "/var/run/docker.sock" in lower:
            findings.append({
                "item": raw_line,
                "issue": "container-docker-sock",
                "details": "docker.sock exposed — full host control possible",
            })

    return findings


def _detect_privileged_containers(section_text):
    """
    Detect 'privileged' container indicators.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        if "privileged" in lower:
            findings.append({
                "item": raw_line,
                "issue": "container-privileged",
                "details": "Privileged container detected",
            })

    return findings


def _detect_runtime_exposure(section_text):
    """
    Detect exposure of container runtimes (runc, containerd).
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for key in ["runc", "containerd"]:
            if key in lower:
                findings.append({
                    "item": raw_line,
                    "issue": f"container-{key}",
                    "details": f"Container runtime exposed: {key}",
                })

    return findings


def _detect_lxc_lxd(section_text):
    """
    Detect LXC/LXD breakout vectors.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        if "lxc" in lower or "lxd" in lower:
            findings.append({
                "item": raw_line,
                "issue": "container-lxc-lxd",
                "details": "LXC/LXD configuration detected — may allow breakout",
            })

    return findings


def _detect_kubernetes(section_text):
    """
    Detect Kubernetes or kubelet hints.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        if "kube" in lower or "kubernetes" in lower:
            findings.append({
                "item": raw_line,
                "issue": "container-kubernetes",
                "details": "Kubernetes-related configuration detected",
            })

    return findings


def _detect_host_mounts(section_text):
    """
    Detect host filesystem mounts inside containers.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        if "mount" not in lower:
            continue

        for hint in HOST_MOUNT_HINTS:
            if hint in lower:
                findings.append({
                    "item": raw_line,
                    "issue": "container-host-mount",
                    "details": f"Potential host mount exposed: {hint}",
                })
                break

    return findings


def _detect_generic_keywords(section_text):
    """
    Generic keyword-based detection for anything container-related that
    doesn't fit the more specific detectors.
    """
    findings = []

    for raw_line in section_text.splitlines():
        lower = raw_line.lower()

        for key, issue in DANGEROUS_KEYWORDS.items():
            if key in lower:
                findings.append({
                    "item": raw_line,
                    "issue": issue,
                    "details": f"Container-related indicator: {key}",
                })

    return findings


def process(section_id, subsection_id, context):
    """
    Main entrypoint for the module.

    section_id:     e.g. "containers"
    subsection_id:  e.g. "docker", "lxc", "kube" (may be None)
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
          "issue": "container-docker-sock",
          "details": "short explanation",
        },
        ...
      ]
    """
    section_text = context.get("section_text", "") or ""
    findings = []

    # Specific detectors
    findings.extend(_detect_docker_sock(section_text))
    findings.extend(_detect_privileged_containers(section_text))
    findings.extend(_detect_runtime_exposure(section_text))
    findings.extend(_detect_lxc_lxd(section_text))
    findings.extend(_detect_kubernetes(section_text))
    findings.extend(_detect_host_mounts(section_text))

    # Generic keyword-based fallback
    findings.extend(_detect_generic_keywords(section_text))

    return findings

