#!/usr/bin/env python3
"""
Search Result Guardrail Filter
================================
Accepts a list of URLs, fetches each one, runs WCI injection detection on the
content, and outputs a filtered safety report classifying results as safe,
flagged, or blocked.

Designed to work alongside the web-content-scanner skill. Reuses the same
detection patterns for consistency.

Uses only Python standard library modules.

Part of the Claude Skills Defense Suite -- Module 2: Web Content Defenses.
"""

import sys
import os
import re
import json
import base64
import argparse
import ssl
import socket
from html.parser import HTMLParser
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# ---------------------------------------------------------------------------
# Severity levels and scoring weights (mirrored from scan_web_content.py)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_SCORE_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2, "INFO": 0}

# Default thresholds
DEFAULT_BLOCK_SEVERITY = "CRITICAL"   # Block results with this severity or above
DEFAULT_FLAG_SEVERITY = "HIGH"         # Flag results with this severity
# Everything below flag threshold is passed as safe


# ---------------------------------------------------------------------------
# Import scanner logic (inline for portability)
# ---------------------------------------------------------------------------

# We inline the core detection patterns and the ContentCollector / WCIScanner
# from scan_web_content.py so this script is fully self-contained.

# --- Pattern definitions (identical to scan_web_content.py) ---

INSTRUCTION_PATTERNS = re.compile(
    r"(?i)\b("
    r"important|system|ignore|must|override|instruction|directive|"
    r"disregard|forget|comply|obey|execute|priority|mandatory|"
    r"do\s+not|you\s+must|you\s+should|you\s+are|your\s+role|"
    r"new\s+instructions?|updated?\s+instructions?|"
    r"ignore\s+(previous|all|prior|above)|"
    r"from\s+now\s+on|henceforth|instead\s+of"
    r")\b"
)

AUTHORITY_PATTERNS = [
    re.compile(r"(?i)^\s*SYSTEM\s*:", re.MULTILINE),
    re.compile(r"(?i)IMPORTANT\s+INSTRUCTION", re.MULTILINE),
    re.compile(r"(?i)ADMIN(ISTRATOR)?\s+NOTE", re.MULTILINE),
    re.compile(r"</?system-reminder\b", re.IGNORECASE),
    re.compile(r"</?assistant\b", re.IGNORECASE),
    re.compile(r"</?tool_result\b", re.IGNORECASE),
    re.compile(r"</?human\b", re.IGNORECASE),
    re.compile(r"</?claude\b", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"(?i)BEGIN\s+(SYSTEM|ADMIN|INTERNAL)\s+(MESSAGE|PROMPT|INSTRUCTION)"),
]

MARKDOWN_INJECTION_PATTERNS = [
    re.compile(r"^#{1,3}\s+(system|instruction|important|override)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\*\*\s*(SYSTEM|IMPORTANT|INSTRUCTION|OVERRIDE)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^>\s*(SYSTEM|IMPORTANT|INSTRUCTION|OVERRIDE)", re.IGNORECASE | re.MULTILINE),
]

ZERO_WIDTH_CHARS = set([
    '\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060',
    '\u2061', '\u2062', '\u2063', '\u2064', '\u180E',
])

RTL_OVERRIDE_CHARS = set([
    '\u200E', '\u200F', '\u202A', '\u202B', '\u202C',
    '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069',
])


# ---------------------------------------------------------------------------
# Lightweight content collector (simplified from scan_web_content.py)
# ---------------------------------------------------------------------------

class ContentCollector(HTMLParser):
    """Simplified HTML parser to collect injection-relevant elements."""

    def __init__(self):
        super().__init__()
        self.comments = []
        self.hidden_elements = []
        self.meta_tags = []
        self.data_attributes = []
        self.json_ld_blocks = []
        self.script_blocks = []
        self.iframes = []
        self.images = []
        self.svgs = []
        self.og_tags = []
        self.all_text = []
        self.http_equiv_tags = []
        self._in_script = False
        self._in_svg = False
        self._script_buf = []
        self._svg_text_buf = []

    def handle_comment(self, data):
        self.comments.append(data.strip())

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        tag_l = tag.lower()

        if tag_l == "script":
            self._in_script = True
            self._script_buf = []
        if tag_l == "svg":
            self._in_svg = True
        if self._in_svg and tag_l == "text":
            self._svg_text_buf = []

        # CSS hidden
        style = attr_dict.get("style", "").lower().replace(" ", "")
        if any(p in style for p in ["display:none", "visibility:hidden", "opacity:0", "font-size:0"]):
            self.hidden_elements.append({"tag": tag, "style": attr_dict.get("style", "")})

        if tag_l == "meta":
            self.meta_tags.append(attr_dict)
            prop = attr_dict.get("property", "")
            if prop.startswith("og:"):
                self.og_tags.append({"property": prop, "content": attr_dict.get("content", "")})
            if "http-equiv" in attr_dict:
                self.http_equiv_tags.append(attr_dict)

        for key, val in attr_dict.items():
            if key.startswith("data-") and val:
                self.data_attributes.append({"attr": key, "value": val})

        if tag_l == "iframe":
            self.iframes.append(attr_dict)
        if tag_l == "img":
            self.images.append({"alt": attr_dict.get("alt", ""), "src": attr_dict.get("src", "")})

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            content = "".join(self._script_buf)
            self.script_blocks.append(content)
            try:
                json.loads(content)
                self.json_ld_blocks.append(content)
            except (json.JSONDecodeError, ValueError):
                pass
            self._in_script = False
            self._script_buf = []
        if tag.lower() == "svg":
            self._in_svg = False
        if self._in_svg and tag.lower() == "text":
            self.svgs.append("".join(self._svg_text_buf))
            self._svg_text_buf = []

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)
        elif self._in_svg:
            self._svg_text_buf.append(data)
        else:
            self.all_text.append(data)


# ---------------------------------------------------------------------------
# Quick-scan function (produces findings list)
# ---------------------------------------------------------------------------

def quick_scan(html_content: str) -> List[Dict[str, Any]]:
    """Run a fast WCI scan on HTML content and return findings."""
    findings = []
    collector = ContentCollector()

    try:
        collector.feed(html_content)
    except Exception:
        pass  # Best-effort on malformed HTML

    full_text = " ".join(collector.all_text)

    # WCI-001: Comment injection
    for comment in collector.comments:
        matches = INSTRUCTION_PATTERNS.findall(comment)
        if len(matches) >= 2:
            findings.append({"vector_id": "WCI-001", "severity": "HIGH",
                             "description": f"HTML comment with {len(matches)} instruction keywords",
                             "evidence": comment[:150]})

    # WCI-002: CSS-hidden elements
    for elem in collector.hidden_elements:
        findings.append({"vector_id": "WCI-002", "severity": "MEDIUM",
                         "description": "CSS-hidden element detected",
                         "evidence": f"<{elem['tag']}> style={elem['style'][:100]}"})

    # WCI-003: Base64 in data attributes
    for da in collector.data_attributes:
        val = da["value"].strip()
        if len(val) > 20 and re.match(r'^[A-Za-z0-9+/=\s]{20,}$', val):
            findings.append({"vector_id": "WCI-003", "severity": "HIGH",
                             "description": "Possible base64 payload in data attribute",
                             "evidence": f"{da['attr']}={val[:80]}"})

    # WCI-004: Authority spoofing
    for pattern in AUTHORITY_PATTERNS:
        if pattern.search(full_text) or pattern.search(html_content):
            match = pattern.search(full_text) or pattern.search(html_content)
            findings.append({"vector_id": "WCI-004", "severity": "CRITICAL",
                             "description": "Authority spoofing pattern detected",
                             "evidence": match.group()[:100]})

    # WCI-005: Markdown injection
    for pattern in MARKDOWN_INJECTION_PATTERNS:
        if pattern.search(full_text):
            findings.append({"vector_id": "WCI-005", "severity": "HIGH",
                             "description": "Markdown injection in page text",
                             "evidence": pattern.search(full_text).group()[:100]})

    # WCI-006: Chain injection
    if len(collector.iframes) >= 3:
        findings.append({"vector_id": "WCI-006", "severity": "MEDIUM",
                         "description": f"{len(collector.iframes)} iframes detected",
                         "evidence": "Multiple iframes may indicate chain injection"})

    # WCI-007: Unicode obfuscation
    zw_count = sum(1 for ch in html_content if ch in ZERO_WIDTH_CHARS)
    rtl_count = sum(1 for ch in html_content if ch in RTL_OVERRIDE_CHARS)
    tag_count = sum(1 for ch in html_content if 0xE0001 <= ord(ch) <= 0xE007F)

    if zw_count > 5:
        sev = "HIGH" if zw_count > 20 else "MEDIUM"
        findings.append({"vector_id": "WCI-007", "severity": sev,
                         "description": f"{zw_count} zero-width characters found",
                         "evidence": "Potential steganographic payload"})
    if rtl_count > 2:
        findings.append({"vector_id": "WCI-007", "severity": "HIGH",
                         "description": f"{rtl_count} RTL/LTR override characters found",
                         "evidence": "Text direction manipulation"})
    if tag_count > 0:
        findings.append({"vector_id": "WCI-007", "severity": "CRITICAL",
                         "description": f"{tag_count} Unicode tag characters found",
                         "evidence": "Steganographic text hiding via U+E0001-U+E007F"})

    # WCI-008: Poisoned structured data
    for block in collector.json_ld_blocks:
        if INSTRUCTION_PATTERNS.search(block):
            findings.append({"vector_id": "WCI-008", "severity": "HIGH",
                             "description": "JSON-LD contains instruction patterns",
                             "evidence": block[:150]})
    for og in collector.og_tags:
        if len(og["content"]) > 500 or INSTRUCTION_PATTERNS.search(og["content"]):
            sev = "HIGH" if INSTRUCTION_PATTERNS.search(og["content"]) else "MEDIUM"
            findings.append({"vector_id": "WCI-008", "severity": sev,
                             "description": f"Suspicious OpenGraph: {og['property']}",
                             "evidence": og["content"][:150]})

    # WCI-009: SEO injection
    seo_names = {"description", "keywords", "robots", "author", "abstract", "summary"}
    for meta in collector.meta_tags:
        name = meta.get("name", "").lower()
        content = meta.get("content", "")
        if name in seo_names and INSTRUCTION_PATTERNS.search(content):
            findings.append({"vector_id": "WCI-009", "severity": "HIGH" if len(content) > 200 else "MEDIUM",
                             "description": f"SEO meta '{name}' contains instruction text",
                             "evidence": content[:150]})

    # WCI-010: JS injection
    js_patterns = [
        re.compile(r"(innerHTML|textContent|innerText)\s*=.*"
                   r"(system|instruction|important|ignore|override)", re.IGNORECASE),
        re.compile(r"document\.write.*"
                   r"(system|instruction|important|ignore|override)", re.IGNORECASE),
    ]
    for script in collector.script_blocks:
        for pat in js_patterns:
            if pat.search(script):
                findings.append({"vector_id": "WCI-010", "severity": "HIGH",
                                 "description": "JS dynamically injects instruction content",
                                 "evidence": pat.search(script).group()[:150]})

    # WCI-011: Alt-text / SVG injection
    for img in collector.images:
        alt = img.get("alt", "")
        if len(alt) > 200:
            sev = "HIGH" if INSTRUCTION_PATTERNS.search(alt) else "MEDIUM"
            findings.append({"vector_id": "WCI-011", "severity": sev,
                             "description": f"Long alt text ({len(alt)} chars)",
                             "evidence": alt[:150]})
    for svg_text in collector.svgs:
        if INSTRUCTION_PATTERNS.search(svg_text):
            findings.append({"vector_id": "WCI-011", "severity": "HIGH",
                             "description": "SVG text with instruction content",
                             "evidence": svg_text[:150]})

    # WCI-012: http-equiv injection
    for meta in collector.http_equiv_tags:
        content = meta.get("content", "")
        if INSTRUCTION_PATTERNS.search(content):
            findings.append({"vector_id": "WCI-012", "severity": "HIGH",
                             "description": f"http-equiv '{meta.get('http-equiv','')}' with instruction text",
                             "evidence": content[:150]})

    return findings


# ---------------------------------------------------------------------------
# URL fetching
# ---------------------------------------------------------------------------

def fetch_url(url: str, timeout: int = 15) -> Tuple[Optional[str], Optional[str]]:
    """Fetch a URL and return (content, error_message)."""
    try:
        # Create an SSL context that works broadly
        ctx = ssl.create_default_context()
        req = Request(url, headers={
            "User-Agent": "Mozilla/5.0 (WCI-Scanner/1.0; Security Research)"
        })
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            content = resp.read().decode(charset, errors="replace")
            return content, None
    except HTTPError as e:
        return None, f"HTTP {e.code}: {e.reason}"
    except URLError as e:
        return None, f"URL error: {e.reason}"
    except socket.timeout:
        return None, "Connection timed out"
    except Exception as e:
        return None, f"Fetch error: {str(e)}"


# ---------------------------------------------------------------------------
# Severity comparison
# ---------------------------------------------------------------------------

def max_severity(findings: List[Dict]) -> str:
    """Return the highest severity level from a list of findings."""
    if not findings:
        return "NONE"
    return max(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 0))["severity"]


def severity_at_or_above(severity: str, threshold: str) -> bool:
    """Check if severity meets or exceeds threshold."""
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(threshold, 0)


def compute_risk_score(findings: List[Dict]) -> int:
    """Compute a 0-100 risk score based on findings."""
    if not findings:
        return 0
    raw = sum(SEVERITY_SCORE_WEIGHT.get(f["severity"], 0) for f in findings)
    return min(100, int(raw))


# ---------------------------------------------------------------------------
# Main filter logic
# ---------------------------------------------------------------------------

def filter_urls(urls: List[str], block_threshold: str, flag_threshold: str,
                timeout: int) -> Dict[str, Any]:
    """Fetch and scan each URL, returning a categorized report."""
    results = {
        "safe": [],
        "flagged": [],
        "blocked": [],
        "errors": [],
        "summary": {
            "total_urls": len(urls),
            "safe_count": 0,
            "flagged_count": 0,
            "blocked_count": 0,
            "error_count": 0
        }
    }

    for url in urls:
        url = url.strip()
        if not url:
            continue

        content, error = fetch_url(url, timeout=timeout)
        if error:
            results["errors"].append({"url": url, "error": error})
            results["summary"]["error_count"] += 1
            continue

        findings = quick_scan(content)
        highest = max_severity(findings)
        risk_score = compute_risk_score(findings)

        entry = {
            "url": url,
            "risk_score": risk_score,
            "max_severity": highest,
            "finding_count": len(findings),
            "findings": findings
        }

        if highest != "NONE" and severity_at_or_above(highest, block_threshold):
            results["blocked"].append(entry)
            results["summary"]["blocked_count"] += 1
        elif highest != "NONE" and severity_at_or_above(highest, flag_threshold):
            results["flagged"].append(entry)
            results["summary"]["flagged_count"] += 1
        else:
            results["safe"].append(entry)
            results["summary"]["safe_count"] += 1

    return results


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_text_report(report: Dict[str, Any]) -> str:
    """Format the filter report as human-readable text."""
    lines = []
    lines.append("=" * 70)
    lines.append("  SEARCH GUARDRAIL -- FILTERED RESULTS REPORT")
    lines.append("=" * 70)
    lines.append("")

    s = report["summary"]
    lines.append(f"  URLs Scanned:  {s['total_urls']}")
    lines.append(f"  Safe:          {s['safe_count']}")
    lines.append(f"  Flagged:       {s['flagged_count']}")
    lines.append(f"  Blocked:       {s['blocked_count']}")
    lines.append(f"  Errors:        {s['error_count']}")
    lines.append("")

    if report["blocked"]:
        lines.append("-" * 70)
        lines.append("  BLOCKED (do not process)")
        lines.append("-" * 70)
        for entry in report["blocked"]:
            lines.append(f"  [BLOCKED] {entry['url']}")
            lines.append(f"    Risk Score: {entry['risk_score']}/100 | "
                         f"Max Severity: {entry['max_severity']} | "
                         f"Findings: {entry['finding_count']}")
            for f in entry["findings"][:5]:
                lines.append(f"    - [{f['severity']}] {f['vector_id']}: {f['description']}")
            lines.append("")

    if report["flagged"]:
        lines.append("-" * 70)
        lines.append("  FLAGGED (review before processing)")
        lines.append("-" * 70)
        for entry in report["flagged"]:
            lines.append(f"  [FLAGGED] {entry['url']}")
            lines.append(f"    Risk Score: {entry['risk_score']}/100 | "
                         f"Max Severity: {entry['max_severity']} | "
                         f"Findings: {entry['finding_count']}")
            for f in entry["findings"][:3]:
                lines.append(f"    - [{f['severity']}] {f['vector_id']}: {f['description']}")
            lines.append("")

    if report["safe"]:
        lines.append("-" * 70)
        lines.append("  SAFE (no significant threats detected)")
        lines.append("-" * 70)
        for entry in report["safe"]:
            lines.append(f"  [SAFE] {entry['url']} (score: {entry['risk_score']}/100)")
        lines.append("")

    if report["errors"]:
        lines.append("-" * 70)
        lines.append("  ERRORS (could not scan)")
        lines.append("-" * 70)
        for entry in report["errors"]:
            lines.append(f"  [ERROR] {entry['url']}: {entry['error']}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("  Scan complete. Blocked results should not be processed by Claude.")
    lines.append("  Flagged results require human review before processing.")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Filter search results for Web Content Injection attacks."
    )
    parser.add_argument(
        "urls", nargs="*", default=[],
        help="URLs to scan. If none given, reads URLs from stdin (one per line)."
    )
    parser.add_argument(
        "--threshold", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="CRITICAL",
        help="Minimum severity to BLOCK a result (default: CRITICAL). "
             "Results one level below this are FLAGGED."
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text",
        dest="output_format",
        help="Output format: json or text (default: text)"
    )
    parser.add_argument(
        "--timeout", type=int, default=15,
        help="Timeout in seconds for each URL fetch (default: 15)"
    )
    args = parser.parse_args()

    # Determine block/flag thresholds
    block_threshold = args.threshold
    flag_map = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO"}
    flag_threshold = flag_map.get(block_threshold, "MEDIUM")

    # Collect URLs
    urls = args.urls
    if not urls:
        try:
            stdin_data = sys.stdin.read()
            urls = [line.strip() for line in stdin_data.strip().split("\n") if line.strip()]
        except KeyboardInterrupt:
            sys.exit(130)

    if not urls:
        print("Error: No URLs provided. Pass URLs as arguments or via stdin.", file=sys.stderr)
        sys.exit(3)

    # Run filter
    report = filter_urls(urls, block_threshold, flag_threshold, args.timeout)

    # Output
    if args.output_format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_text_report(report))

    # Exit code
    if report["summary"]["blocked_count"] > 0:
        sys.exit(2)
    elif report["summary"]["flagged_count"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
