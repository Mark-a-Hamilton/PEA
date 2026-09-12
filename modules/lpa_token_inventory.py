#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LPA Token Inventory Module (New Engine-Compatible)
--------------------------------------------------

This module:
- Extracts full JSON-like blocks from LinPEAS output
- Extracts non-JSON tokens (AWS, GitHub, JWT, generic)
- Computes entropy
- Classifies token type
- Returns findings using the evidence model expected by the engine

Required KB entries (in lpa-kb.json):
    token-aws_access_key
    token-aws_secret_key
    token-github_pat
    token-jwt
    token-generic_api_key
    token-unknown_token
    token-json-block
"""

import re
import base64
import math

# ------------------------------------------------------------
# TOKEN PATTERNS
# ------------------------------------------------------------
TOKEN_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?<![A-Za-z0-9+/=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9+/=])",
    "github_pat": r"gh[pousr]_[A-Za-z0-9]{36}",
    "jwt": r"eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+",
    "generic_api_key": r"[A-Za-z0-9_\-]{24,64}",
}


# ------------------------------------------------------------
# ENTROPY CALCULATION
# ------------------------------------------------------------
def shannon_entropy(s):
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ------------------------------------------------------------
# JWT DECODING (SAFE)
# ------------------------------------------------------------
def decode_jwt_segment(segment):
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(padded.encode()).decode(errors="ignore")
    except Exception:
        return None


# ------------------------------------------------------------
# TOKEN CLASSIFICATION
# ------------------------------------------------------------
def classify_token(value):
    for ttype, pattern in TOKEN_PATTERNS.items():
        if re.fullmatch(pattern, value):
            return ttype
    return "unknown_token"


# ------------------------------------------------------------
# TOKEN DISCOVERY
# ------------------------------------------------------------
def discover_tokens(full_text):
    tokens = []
    for ttype, pattern in TOKEN_PATTERNS.items():
        for match in re.findall(pattern, full_text):
            tokens.append({"raw": match, "type": ttype})
    return tokens


# ------------------------------------------------------------
# TOKEN ANALYSIS
# ------------------------------------------------------------
def analyse_token(token):
    raw = token["raw"]
    ttype = token["type"]

    entropy = shannon_entropy(raw)

    analysis = {
        "raw": raw,
        "type": ttype,
        "entropy": entropy,
        "valid_structure": True,
        "details": "",
    }

    # JWT structure analysis
    if ttype == "jwt":
        parts = raw.split(".")
        if len(parts) == 3:
            analysis["jwt_header"] = decode_jwt_segment(parts[0])
            analysis["jwt_payload"] = decode_jwt_segment(parts[1])
        else:
            analysis["valid_structure"] = False

    return analysis


# ------------------------------------------------------------
# RISK SCORING
# ------------------------------------------------------------
def score_token(analysis):
    score = 0

    # Base score by type
    if analysis["type"] in ("aws_access_key", "aws_secret_key", "github_pat", "jwt"):
        score += 6
    elif analysis["type"] == "generic_api_key":
        score += 4
    else:
        score += 2

    # Entropy bonus
    if analysis["entropy"] > 3.5:
        score += 2
    if analysis["entropy"] > 4.5:
        score += 3

    # Invalid structure penalty
    if not analysis["valid_structure"]:
        score -= 2

    return max(1, min(score, 10))


# ------------------------------------------------------------
# JSON BLOCK EXTRACTION
# ------------------------------------------------------------
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')


def clean_line(line):
    # Remove ANSI colour codes
    line = ANSI_ESCAPE.sub("", line)

    # Remove BOM, zero-width, and other invisible characters
    invisible = [
        "\ufeff",  # BOM
        "\u200b",  # zero-width space
        "\u200c", "\u200d",  # zero-width joiners
        "\u2060",  # word joiner
    ]
    for ch in invisible:
        line = line.replace(ch, "")

    # Remove all unicode control characters except JSON punctuation
    line = "".join(
        c for c in line
        if c.isprintable() or c in "{}[]:,\"'"
    )

    # Normalize ALL whitespace (including unicode) to plain space
    line = re.sub(r"\s+", " ", line)

    return line.strip()


def extract_json_blocks(text):
    blocks = []
    lines = text.splitlines()
    current = []
    in_block = False

    for raw_line in lines:
        cleaned = clean_line(raw_line)

        # Detect start BEFORE cleaning
        if not in_block and "{" in raw_line:
            in_block = True
            current = [cleaned]
            continue

        if in_block:
            # End block on blank cleaned line or new section header
            if cleaned == "" or cleaned.startswith("══╣"):
                blocks.append("\n".join(current))
                in_block = False
                current = []
                continue

            current.append(cleaned)

    # End-of-file block
    if in_block and current:
        blocks.append("\n".join(current))

    return blocks


# ------------------------------------------------------------
# MAIN ENTRYPOINT FOR ENGINE (NEW SIGNATURE)
# ------------------------------------------------------------
def process(section_id, subsection_id, context):
    """
    New engine-compatible entrypoint.
    Returns findings using the new evidence model.
    """
    full_text = context.get("content", "") or ""
    findings = []

    # 1. Extract JSON blocks
    json_blocks = extract_json_blocks(full_text)
    for jb in json_blocks:
        findings.append({
            "issue": "token-json-block",
            "item": "JSON block",
            "details": "Potential token/secret in JSON block.",
            "evidence": {
                "items": [],
                "json_blocks": [jb],
                "tokens": [],
                "raw_snippets": [],
            },
        })

    # 2. Extract non-JSON tokens
    discovered = discover_tokens(full_text)

    for token in discovered:
        analysis = analyse_token(token)
        score = score_token(analysis)

        if score >= 8:
            severity = "critical"
        elif score >= 6:
            severity = "high"
        elif score >= 4:
            severity = "medium"
        else:
            severity = "low"

        # Note: severity is computed but not yet wired into the engine's
        # evidence model; can be added later if the engine supports it.
        findings.append({
            "issue": f"token-{analysis['type']}",
            "item": analysis["raw"],
            "details": f"Token discovered: {analysis['type']} | Entropy={analysis['entropy']:.2f}",
            "evidence": {
                "items": [],
                "json_blocks": [],
                "tokens": [analysis["raw"]],
                "raw_snippets": [],
            },
        })

    return findings
