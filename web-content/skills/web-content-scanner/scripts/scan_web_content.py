#!/usr/bin/env python3
"""
Web Content Injection Scanner (WCI Scanner)
============================================
Scans HTML content for all 12 Web Content Injection (WCI) vectors defined in
the Claude Security Atlas threat taxonomy.

Accepts HTML via stdin or as a file path argument. Outputs a structured JSON
report or human-readable text summary.

Uses only Python standard library modules.

Part of the Claude Skills Defense Suite -- Module 2: Web Content Defenses.
"""

import sys
import os
import re
import json
import base64
import argparse
import html
import unicodedata
from html.parser import HTMLParser
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Severity levels and scoring weights
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_SCORE_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2, "INFO": 0}


# ---------------------------------------------------------------------------
# Pattern libraries
# ---------------------------------------------------------------------------

# WCI-001: Instruction-like phrases inside HTML comments
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

# WCI-004: Authority spoofing patterns
AUTHORITY_PATTERNS = [
    re.compile(r"(?i)^\s*SYSTEM\s*:", re.MULTILINE),
    re.compile(r"(?i)IMPORTANT\s+INSTRUCTION", re.MULTILINE),
    re.compile(r"(?i)ADMIN(ISTRATOR)?\s+NOTE", re.MULTILINE),
    re.compile(r"</?system-reminder\b", re.IGNORECASE),
    re.compile(r"</?assistant\b", re.IGNORECASE),
    re.compile(r"</?tool_result\b", re.IGNORECASE),
    re.compile(r"</?human\b", re.IGNORECASE),
    re.compile(r"</?user\b", re.IGNORECASE),
    re.compile(r"</?claude\b", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE),
    re.compile(r"(?i)BEGIN\s+(SYSTEM|ADMIN|INTERNAL)\s+(MESSAGE|PROMPT|INSTRUCTION)"),
    re.compile(r"(?i)END\s+(SYSTEM|ADMIN|INTERNAL)\s+(MESSAGE|PROMPT|INSTRUCTION)"),
]

# WCI-005: Markdown injection patterns
MARKDOWN_INJECTION_PATTERNS = [
    re.compile(r"^#{1,3}\s+(system|instruction|important|override)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\*\*\s*(SYSTEM|IMPORTANT|INSTRUCTION|OVERRIDE)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^>\s*(SYSTEM|IMPORTANT|INSTRUCTION|OVERRIDE)", re.IGNORECASE | re.MULTILINE),
    re.compile(r"```\s*(system|instruction|prompt)", re.IGNORECASE),
]

# WCI-007: Suspicious Unicode characters
ZERO_WIDTH_CHARS = set([
    '\u200B',  # Zero-width space
    '\u200C',  # Zero-width non-joiner
    '\u200D',  # Zero-width joiner
    '\uFEFF',  # Byte order mark / zero-width no-break space
    '\u2060',  # Word joiner
    '\u2061',  # Function application
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
    '\u180E',  # Mongolian vowel separator
])

RTL_OVERRIDE_CHARS = set([
    '\u200E',  # LTR mark
    '\u200F',  # RTL mark
    '\u202A',  # LTR embedding
    '\u202B',  # RTL embedding
    '\u202C',  # Pop directional
    '\u202D',  # LTR override
    '\u202E',  # RTL override
    '\u2066',  # LTR isolate
    '\u2067',  # RTL isolate
    '\u2068',  # First strong isolate
    '\u2069',  # Pop directional isolate
])

# WCI-010: Dynamic JS injection patterns
JS_INJECTION_PATTERNS = [
    re.compile(r"(innerHTML|textContent|innerText|outerHTML)\s*=\s*['\"`].*"
               r"(system|instruction|important|ignore|override)", re.IGNORECASE),
    re.compile(r"document\.write\s*\(.*"
               r"(system|instruction|important|ignore|override)", re.IGNORECASE),
    re.compile(r"(insertAdjacentHTML|insertBefore|appendChild|replaceChild)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# HTML Parser that collects structural data
# ---------------------------------------------------------------------------

class ContentCollector(HTMLParser):
    """Parses HTML and collects elements relevant to WCI scanning."""

    def __init__(self):
        super().__init__()
        self.comments: List[Tuple[str, int]] = []          # (comment_text, approx_line)
        self.hidden_elements: List[Dict] = []               # CSS-hidden elements
        self.meta_tags: List[Dict] = []                     # <meta> tags
        self.data_attributes: List[Dict] = []               # data-* attributes
        self.json_ld_blocks: List[str] = []                 # JSON-LD scripts
        self.script_blocks: List[str] = []                  # All script content
        self.iframes: List[Dict] = []                       # iframe elements
        self.links: List[Dict] = []                         # anchor tags
        self.images: List[Dict] = []                        # img elements
        self.svgs: List[Dict] = []                          # SVG text elements
        self.og_tags: List[Dict] = []                       # OpenGraph meta tags
        self.all_text: List[str] = []                       # All visible text
        self.http_equiv_tags: List[Dict] = []               # meta http-equiv

        self._current_tag = None
        self._current_attrs = {}
        self._in_script = False
        self._in_svg = False
        self._script_buf = []
        self._svg_text_buf = []
        self._line = 0

    def handle_comment(self, data):
        self.comments.append((data.strip(), self.getpos()[0]))

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        self._current_tag = tag.lower()
        self._current_attrs = attr_dict
        self._line = self.getpos()[0]

        # Track scripts
        if tag.lower() == "script":
            self._in_script = True
            self._script_buf = []
            # Check for JSON-LD
            if attr_dict.get("type", "").lower() == "application/ld+json":
                pass  # Will be captured on endtag

        # Track SVG text elements
        if tag.lower() == "svg":
            self._in_svg = True
        if self._in_svg and tag.lower() == "text":
            self._svg_text_buf = []

        # CSS-hidden detection
        style = attr_dict.get("style", "")
        css_class = attr_dict.get("class", "")
        if self._is_css_hidden(style, css_class):
            self.hidden_elements.append({
                "tag": tag, "style": style, "class": css_class,
                "line": self._line, "attrs": attr_dict
            })

        # Meta tags
        if tag.lower() == "meta":
            self.meta_tags.append({"attrs": attr_dict, "line": self._line})
            # OpenGraph
            prop = attr_dict.get("property", "")
            if prop.startswith("og:"):
                self.og_tags.append({"property": prop, "content": attr_dict.get("content", ""), "line": self._line})
            # http-equiv
            if "http-equiv" in attr_dict:
                self.http_equiv_tags.append({
                    "http-equiv": attr_dict["http-equiv"],
                    "content": attr_dict.get("content", ""),
                    "line": self._line
                })

        # data-* attributes
        for key, val in attr_dict.items():
            if key.startswith("data-") and val:
                self.data_attributes.append({
                    "tag": tag, "attr": key, "value": val, "line": self._line
                })

        # Iframes
        if tag.lower() == "iframe":
            self.iframes.append({"attrs": attr_dict, "line": self._line})

        # Links
        if tag.lower() == "a":
            self.links.append({"href": attr_dict.get("href", ""), "line": self._line})

        # Images
        if tag.lower() == "img":
            self.images.append({
                "alt": attr_dict.get("alt", ""),
                "src": attr_dict.get("src", ""),
                "line": self._line,
                "attrs": attr_dict
            })

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            content = "".join(self._script_buf)
            self.script_blocks.append(content)
            # Check if this was JSON-LD
            try:
                parsed = json.loads(content)
                self.json_ld_blocks.append(content)
            except (json.JSONDecodeError, ValueError):
                pass
            self._in_script = False
            self._script_buf = []

        if tag.lower() == "svg":
            self._in_svg = False

        if self._in_svg and tag.lower() == "text":
            text = "".join(self._svg_text_buf)
            self.svgs.append({"text": text, "line": self.getpos()[0]})
            self._svg_text_buf = []

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)
        elif self._in_svg:
            self._svg_text_buf.append(data)
        else:
            self.all_text.append(data)

    @staticmethod
    def _is_css_hidden(style: str, css_class: str) -> bool:
        """Detect CSS hiding techniques."""
        style_lower = style.lower().replace(" ", "")
        checks = [
            "display:none" in style_lower,
            "visibility:hidden" in style_lower,
            "opacity:0" in style_lower,
            "font-size:0" in style_lower,
            re.search(r"position:\s*absolute", style_lower) and
                re.search(r"(left|top)\s*:\s*-\d{4,}", style_lower),
            re.search(r"color\s*:\s*(white|#fff|#ffffff|rgba?\(\s*255)", style_lower) and
                not re.search(r"background", style_lower),
            re.search(r"height\s*:\s*0", style_lower),
            re.search(r"width\s*:\s*0", style_lower),
            re.search(r"overflow\s*:\s*hidden", style_lower) and
                re.search(r"(height|width)\s*:\s*[01]px", style_lower),
        ]
        # Also check common class names used to hide content
        hidden_classes = ["hidden", "sr-only", "visually-hidden", "d-none", "invisible"]
        for hc in hidden_classes:
            if hc in css_class.lower().split():
                checks.append(True)
        return any(checks)


# ---------------------------------------------------------------------------
# Individual WCI Scanners
# ---------------------------------------------------------------------------

class WCIScanner:
    """Container for all 12 WCI detection routines."""

    def __init__(self, html_content: str):
        self.html_content = html_content
        self.findings: List[Dict[str, Any]] = []
        self.collector = ContentCollector()

        try:
            self.collector.feed(html_content)
        except Exception:
            # Malformed HTML -- do best-effort scanning via regex fallbacks
            pass

    def scan_all(self) -> List[Dict[str, Any]]:
        """Run all 12 WCI detectors and return findings."""
        self._scan_wci_001()
        self._scan_wci_002()
        self._scan_wci_003()
        self._scan_wci_004()
        self._scan_wci_005()
        self._scan_wci_006()
        self._scan_wci_007()
        self._scan_wci_008()
        self._scan_wci_009()
        self._scan_wci_010()
        self._scan_wci_011()
        self._scan_wci_012()
        return self.findings

    def _add_finding(self, vector_id: str, severity: str, description: str,
                     location: str, evidence: str):
        # Truncate evidence to keep reports manageable
        evidence_truncated = evidence[:500] + "..." if len(evidence) > 500 else evidence
        self.findings.append({
            "vector_id": vector_id,
            "severity": severity,
            "description": description,
            "location": location,
            "evidence": evidence_truncated
        })

    # --- WCI-001: Hidden HTML comment injection --------------------------
    def _scan_wci_001(self):
        for comment_text, line in self.collector.comments:
            matches = INSTRUCTION_PATTERNS.findall(comment_text)
            if len(matches) >= 2:
                self._add_finding(
                    "WCI-001", "HIGH",
                    f"HTML comment contains {len(matches)} instruction-like keywords",
                    f"HTML comment near line {line}",
                    f"<!-- {comment_text[:200]} -->"
                )
            elif len(matches) == 1:
                # Single keyword is low-severity (common in legitimate comments)
                if len(comment_text) > 100:
                    self._add_finding(
                        "WCI-001", "MEDIUM",
                        "Long HTML comment with instruction-like keyword",
                        f"HTML comment near line {line}",
                        f"<!-- {comment_text[:200]} -->"
                    )

    # --- WCI-002: CSS-hidden text ----------------------------------------
    def _scan_wci_002(self):
        for elem in self.collector.hidden_elements:
            style = elem.get("style", "")
            # Check if the hidden element has substantial text content
            # We flag any hidden element; the severity depends on whether
            # the surrounding region contains instruction patterns.
            # For a reliable check, look at the raw HTML around the tag line.
            context = self._get_line_context(elem["line"], window=5)
            has_instructions = bool(INSTRUCTION_PATTERNS.search(context))
            severity = "HIGH" if has_instructions else "MEDIUM"
            desc = "CSS-hidden element"
            if has_instructions:
                desc += " containing instruction-like text"
            self._add_finding(
                "WCI-002", severity, desc,
                f"<{elem['tag']}> near line {elem['line']}",
                f"style=\"{style}\" class=\"{elem.get('class', '')}\""
            )

    # --- WCI-003: Encoded payloads in meta/data attributes ---------------
    def _scan_wci_003(self):
        # Check data-* attributes for base64
        for da in self.collector.data_attributes:
            if self._looks_like_base64(da["value"]):
                decoded = self._try_decode_base64(da["value"])
                severity = "HIGH"
                desc = f"data-* attribute contains base64-encoded content"
                if decoded and INSTRUCTION_PATTERNS.search(decoded):
                    severity = "CRITICAL"
                    desc += " with instruction-like decoded text"
                self._add_finding(
                    "WCI-003", severity, desc,
                    f"<{da['tag']}> {da['attr']} near line {da['line']}",
                    f"{da['attr']}=\"{da['value'][:100]}...\" decoded: {(decoded or 'N/A')[:200]}"
                )

        # Check meta content for base64
        for meta in self.collector.meta_tags:
            content = meta["attrs"].get("content", "")
            if self._looks_like_base64(content):
                decoded = self._try_decode_base64(content)
                severity = "HIGH"
                desc = "Meta tag contains base64-encoded content"
                if decoded and INSTRUCTION_PATTERNS.search(decoded):
                    severity = "CRITICAL"
                    desc += " with instruction-like decoded text"
                self._add_finding(
                    "WCI-003", severity, desc,
                    f"<meta> near line {meta['line']}",
                    f"content=\"{content[:100]}...\" decoded: {(decoded or 'N/A')[:200]}"
                )

    # --- WCI-004: Authority spoofing patterns ----------------------------
    def _scan_wci_004(self):
        full_text = " ".join(self.collector.all_text)
        for pattern in AUTHORITY_PATTERNS:
            for match in pattern.finditer(full_text):
                start = max(0, match.start() - 30)
                end = min(len(full_text), match.end() + 80)
                context = full_text[start:end].strip()
                self._add_finding(
                    "WCI-004", "CRITICAL",
                    f"Authority spoofing pattern detected: {match.group()[:60]}",
                    "Page visible text",
                    context
                )
        # Also scan raw HTML for spoofing tags that may not end up in visible text
        for pattern in AUTHORITY_PATTERNS:
            for match in pattern.finditer(self.html_content):
                # Avoid double-reporting by checking if it was already in visible text
                snippet = match.group()
                if snippet not in full_text:
                    start = max(0, match.start() - 30)
                    end = min(len(self.html_content), match.end() + 80)
                    self._add_finding(
                        "WCI-004", "CRITICAL",
                        f"Authority spoofing tag in raw HTML: {snippet[:60]}",
                        f"Raw HTML offset {match.start()}",
                        self.html_content[start:end].strip()
                    )

    # --- WCI-005: Markdown injection in HTML content ---------------------
    def _scan_wci_005(self):
        full_text = "\n".join(self.collector.all_text)
        for pattern in MARKDOWN_INJECTION_PATTERNS:
            for match in pattern.finditer(full_text):
                self._add_finding(
                    "WCI-005", "HIGH",
                    "Markdown injection pattern found in page text",
                    "Page text",
                    match.group()[:200]
                )
        # Also check in raw HTML (hidden markdown)
        for pattern in MARKDOWN_INJECTION_PATTERNS:
            for match in pattern.finditer(self.html_content):
                snippet = match.group()
                if snippet not in full_text:
                    self._add_finding(
                        "WCI-005", "MEDIUM",
                        "Markdown injection pattern in raw HTML (possibly hidden)",
                        f"Raw HTML offset {match.start()}",
                        snippet[:200]
                    )

    # --- WCI-006: Multi-page chain injection (iframes, links) -----------
    def _scan_wci_006(self):
        if len(self.collector.iframes) >= 3:
            self._add_finding(
                "WCI-006", "MEDIUM",
                f"Page contains {len(self.collector.iframes)} iframes (potential chain injection setup)",
                "Document structure",
                ", ".join(f["attrs"].get("src", "no-src") for f in self.collector.iframes[:5])
            )

        # Hidden iframes
        for iframe in self.collector.iframes:
            style = iframe["attrs"].get("style", "")
            width = iframe["attrs"].get("width", "")
            height = iframe["attrs"].get("height", "")
            if ("display:none" in style.replace(" ", "").lower() or
                    "visibility:hidden" in style.replace(" ", "").lower() or
                    width in ("0", "1") or height in ("0", "1")):
                self._add_finding(
                    "WCI-006", "HIGH",
                    "Hidden iframe detected (potential chain injection)",
                    f"<iframe> near line {iframe['line']}",
                    f"src={iframe['attrs'].get('src', 'N/A')} style={style}"
                )

        # Same-domain link clustering
        domains = defaultdict(int)
        for link in self.collector.links:
            href = link.get("href", "")
            domain = self._extract_domain(href)
            if domain:
                domains[domain] += 1
        for domain, count in domains.items():
            if count >= 10:
                self._add_finding(
                    "WCI-006", "LOW",
                    f"High same-domain link density: {count} links to {domain}",
                    "Document links",
                    f"{domain} referenced {count} times"
                )

    # --- WCI-007: Unicode/homoglyph obfuscation -------------------------
    def _scan_wci_007(self):
        zw_count = 0
        rtl_count = 0
        tag_count = 0
        zw_positions = []
        rtl_positions = []

        for i, ch in enumerate(self.html_content):
            if ch in ZERO_WIDTH_CHARS:
                zw_count += 1
                if len(zw_positions) < 5:
                    zw_positions.append(i)
            if ch in RTL_OVERRIDE_CHARS:
                rtl_count += 1
                if len(rtl_positions) < 5:
                    rtl_positions.append(i)
            # Tag characters U+E0001-U+E007F
            cp = ord(ch)
            if 0xE0001 <= cp <= 0xE007F:
                tag_count += 1

        if zw_count > 5:
            severity = "HIGH" if zw_count > 20 else "MEDIUM"
            self._add_finding(
                "WCI-007", severity,
                f"Found {zw_count} zero-width characters (potential steganographic payload)",
                "Full document",
                f"Positions (first 5): {zw_positions}"
            )

        if rtl_count > 2:
            self._add_finding(
                "WCI-007", "HIGH",
                f"Found {rtl_count} RTL/LTR override characters (potential text direction attack)",
                "Full document",
                f"Positions (first 5): {rtl_positions}"
            )

        if tag_count > 0:
            self._add_finding(
                "WCI-007", "CRITICAL",
                f"Found {tag_count} Unicode tag characters (U+E0001-U+E007F) -- steganographic text hiding",
                "Full document",
                "Tag characters detected (invisible text encoding)"
            )

    # --- WCI-008: Poisoned structured data (JSON-LD, OpenGraph) ---------
    def _scan_wci_008(self):
        for block in self.collector.json_ld_blocks:
            if INSTRUCTION_PATTERNS.search(block):
                self._add_finding(
                    "WCI-008", "HIGH",
                    "JSON-LD block contains instruction-like patterns",
                    "<script type=\"application/ld+json\">",
                    block[:300]
                )
            # Check for unusually long descriptions (payload smuggling)
            try:
                data = json.loads(block)
                self._check_json_depth(data, "JSON-LD")
            except (json.JSONDecodeError, ValueError):
                pass

        for og in self.collector.og_tags:
            content = og.get("content", "")
            if len(content) > 500:
                self._add_finding(
                    "WCI-008", "MEDIUM",
                    f"OpenGraph tag '{og['property']}' has unusually long content ({len(content)} chars)",
                    f"<meta property=\"{og['property']}\"> near line {og['line']}",
                    content[:200]
                )
            if INSTRUCTION_PATTERNS.search(content):
                self._add_finding(
                    "WCI-008", "HIGH",
                    f"OpenGraph tag '{og['property']}' contains instruction-like text",
                    f"<meta property=\"{og['property']}\"> near line {og['line']}",
                    content[:200]
                )

    def _check_json_depth(self, data: Any, source: str, path: str = ""):
        """Recursively check JSON data for suspicious values."""
        if isinstance(data, str):
            if len(data) > 500 and INSTRUCTION_PATTERNS.search(data):
                self._add_finding(
                    "WCI-008", "HIGH",
                    f"Long text field in {source} contains instruction-like content",
                    f"{source} path: {path}",
                    data[:200]
                )
        elif isinstance(data, dict):
            for k, v in data.items():
                self._check_json_depth(v, source, f"{path}.{k}")
        elif isinstance(data, list):
            for i, item in enumerate(data[:20]):  # Cap iteration for safety
                self._check_json_depth(item, source, f"{path}[{i}]")

    # --- WCI-009: SEO meta tags with injection content -------------------
    def _scan_wci_009(self):
        seo_names = {"description", "keywords", "robots", "author", "abstract", "summary"}
        for meta in self.collector.meta_tags:
            name = meta["attrs"].get("name", "").lower()
            content = meta["attrs"].get("content", "")
            if name in seo_names and content:
                if INSTRUCTION_PATTERNS.search(content):
                    severity = "HIGH" if len(content) > 200 else "MEDIUM"
                    self._add_finding(
                        "WCI-009", severity,
                        f"SEO meta tag '{name}' contains instruction-like content",
                        f"<meta name=\"{name}\"> near line {meta['line']}",
                        content[:300]
                    )
                if len(content) > 1000:
                    self._add_finding(
                        "WCI-009", "MEDIUM",
                        f"SEO meta tag '{name}' is unusually long ({len(content)} chars) -- potential payload",
                        f"<meta name=\"{name}\"> near line {meta['line']}",
                        content[:200]
                    )

    # --- WCI-010: Dynamic JS-generated injection -------------------------
    def _scan_wci_010(self):
        for script in self.collector.script_blocks:
            for pattern in JS_INJECTION_PATTERNS:
                match = pattern.search(script)
                if match:
                    self._add_finding(
                        "WCI-010", "HIGH",
                        "JavaScript dynamically injects instruction-like content into DOM",
                        "<script> block",
                        match.group()[:200]
                    )

            # Check for document.write with large string payloads
            write_matches = re.findall(r"document\.write\s*\(\s*['\"`](.*?)['\"`]\s*\)", script, re.DOTALL)
            for wm in write_matches:
                if len(wm) > 200 and INSTRUCTION_PATTERNS.search(wm):
                    self._add_finding(
                        "WCI-010", "HIGH",
                        "document.write() with large instruction-like payload",
                        "<script> block",
                        wm[:200]
                    )

    # --- WCI-011: Image alt-text / SVG text injection --------------------
    def _scan_wci_011(self):
        for img in self.collector.images:
            alt = img.get("alt", "")
            if len(alt) > 200:
                severity = "HIGH" if INSTRUCTION_PATTERNS.search(alt) else "MEDIUM"
                self._add_finding(
                    "WCI-011", severity,
                    f"Image alt text is unusually long ({len(alt)} chars)"
                    + (" and contains instruction-like text" if severity == "HIGH" else ""),
                    f"<img src=\"{img['src'][:80]}\"> near line {img['line']}",
                    f"alt=\"{alt[:200]}\""
                )

        for svg in self.collector.svgs:
            text = svg.get("text", "")
            if INSTRUCTION_PATTERNS.search(text):
                self._add_finding(
                    "WCI-011", "HIGH",
                    "SVG <text> element contains instruction-like content",
                    f"<svg> <text> near line {svg['line']}",
                    text[:200]
                )

        # EXIF-like patterns in raw HTML (data URIs in img src)
        for img in self.collector.images:
            src = img.get("src", "")
            if src.startswith("data:") and len(src) > 500:
                # Check the decoded portion for instruction patterns
                data_part = src.split(",", 1)[-1] if "," in src else ""
                decoded = self._try_decode_base64(data_part)
                if decoded and INSTRUCTION_PATTERNS.search(decoded):
                    self._add_finding(
                        "WCI-011", "HIGH",
                        "Image data URI contains base64-encoded instruction-like content",
                        f"<img> near line {img['line']}",
                        f"decoded excerpt: {decoded[:200]}"
                    )

    # --- WCI-012: Meta http-equiv header injection -----------------------
    def _scan_wci_012(self):
        safe_http_equivs = {
            "content-type", "x-ua-compatible", "refresh", "content-language",
            "cache-control", "pragma", "expires", "content-security-policy"
        }
        for meta in self.collector.http_equiv_tags:
            equiv = meta["http-equiv"].lower()
            content = meta.get("content", "")

            # Flag unusual http-equiv values
            if equiv not in safe_http_equivs:
                self._add_finding(
                    "WCI-012", "MEDIUM",
                    f"Unusual meta http-equiv value: {equiv}",
                    f"<meta http-equiv=\"{meta['http-equiv']}\"> near line {meta['line']}",
                    f"content=\"{content[:200]}\""
                )

            # Flag instruction-like content in any http-equiv
            if INSTRUCTION_PATTERNS.search(content):
                self._add_finding(
                    "WCI-012", "HIGH",
                    f"Meta http-equiv '{equiv}' contains instruction-like content",
                    f"<meta http-equiv=\"{meta['http-equiv']}\"> near line {meta['line']}",
                    content[:200]
                )

            # CSP headers with unusual directives could be interesting
            if equiv == "content-security-policy" and len(content) > 500:
                self._add_finding(
                    "WCI-012", "LOW",
                    "Unusually long Content-Security-Policy in meta tag",
                    f"<meta http-equiv=\"{meta['http-equiv']}\"> near line {meta['line']}",
                    content[:200]
                )

    # --- Utility methods ------------------------------------------------

    def _get_line_context(self, line_num: int, window: int = 3) -> str:
        """Get raw HTML context around a given line number."""
        lines = self.html_content.split("\n")
        start = max(0, line_num - window - 1)
        end = min(len(lines), line_num + window)
        return "\n".join(lines[start:end])

    @staticmethod
    def _looks_like_base64(text: str) -> bool:
        """Heuristic check for base64-encoded content."""
        text = text.strip()
        if len(text) < 20:
            return False
        # Base64 character set with possible padding
        if re.match(r'^[A-Za-z0-9+/=\s]{20,}$', text):
            # Additional check: length should be roughly divisible by 4
            stripped = re.sub(r'\s', '', text)
            if len(stripped) % 4 <= 1:
                return True
        return False

    @staticmethod
    def _try_decode_base64(text: str) -> Optional[str]:
        """Attempt to decode base64, returning None on failure."""
        try:
            stripped = re.sub(r'\s', '', text.strip())
            # Add padding if needed
            padding = 4 - (len(stripped) % 4) if len(stripped) % 4 else 0
            decoded = base64.b64decode(stripped + "=" * padding)
            return decoded.decode("utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        """Extract domain from a URL."""
        try:
            # Simple regex extraction without urllib.parse for robustness
            match = re.match(r'https?://([^/:]+)', url)
            return match.group(1) if match else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def compute_risk_score(findings: List[Dict]) -> int:
    """Compute a 0-100 risk score based on findings."""
    if not findings:
        return 0
    raw = sum(SEVERITY_SCORE_WEIGHT.get(f["severity"], 0) for f in findings)
    # Apply diminishing returns: cap at 100
    score = min(100, int(raw))
    return score


def severity_counts(findings: List[Dict]) -> Dict[str, int]:
    """Count findings by severity."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_report(findings: List[Dict]) -> Dict[str, Any]:
    """Build structured JSON report."""
    counts = severity_counts(findings)
    risk = compute_risk_score(findings)
    return {
        "scan_summary": {
            "total_findings": len(findings),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"]
        },
        "risk_score": risk,
        "findings": findings
    }


def format_text_report(report: Dict[str, Any]) -> str:
    """Format report for human-readable text output."""
    lines = []
    lines.append("=" * 70)
    lines.append("  WEB CONTENT INJECTION SCAN REPORT")
    lines.append("=" * 70)
    lines.append("")

    summary = report["scan_summary"]
    lines.append(f"  Risk Score: {report['risk_score']}/100")
    lines.append(f"  Total Findings: {summary['total_findings']}")
    lines.append(f"    CRITICAL: {summary['critical']}")
    lines.append(f"    HIGH:     {summary['high']}")
    lines.append(f"    MEDIUM:   {summary['medium']}")
    lines.append(f"    LOW:      {summary['low']}")
    lines.append("")

    if not report["findings"]:
        lines.append("  No injection indicators detected. Content appears clean.")
        lines.append("")
    else:
        lines.append("-" * 70)
        lines.append("  FINDINGS")
        lines.append("-" * 70)
        for i, f in enumerate(report["findings"], 1):
            lines.append("")
            sev = f["severity"]
            marker = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[.]"}.get(sev, "[i]")
            lines.append(f"  {marker} #{i} [{sev}] {f['vector_id']}")
            lines.append(f"      Description: {f['description']}")
            lines.append(f"      Location:    {f['location']}")
            lines.append(f"      Evidence:    {f['evidence'][:300]}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("  Scan complete. All findings are heuristic indicators, not")
    lines.append("  definitive proof of malicious content. Review flagged items")
    lines.append("  before allowing Claude to process this web content.")
    lines.append("=" * 70)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan HTML content for Web Content Injection (WCI) attack patterns."
    )
    parser.add_argument(
        "file", nargs="?", default=None,
        help="Path to HTML file to scan. If omitted, reads from stdin."
    )
    parser.add_argument(
        "--format", choices=["json", "text"], default="text",
        dest="output_format",
        help="Output format: json or text (default: text)"
    )
    args = parser.parse_args()

    # Read input
    try:
        if args.file:
            if not os.path.isfile(args.file):
                print(f"Error: File not found: {args.file}", file=sys.stderr)
                sys.exit(3)
            with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
                html_content = fh.read()
        else:
            html_content = sys.stdin.read()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        print(f"Error reading input: {e}", file=sys.stderr)
        sys.exit(3)

    if not html_content.strip():
        # Empty input -- produce a clean report
        report = build_report([])
        if args.output_format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(format_text_report(report))
        sys.exit(0)

    # Run scanner
    scanner = WCIScanner(html_content)
    findings = scanner.scan_all()
    report = build_report(findings)

    # Output
    if args.output_format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(format_text_report(report))

    # Exit code
    counts = severity_counts(findings)
    if counts["CRITICAL"] > 0:
        sys.exit(2)
    elif counts["HIGH"] > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
