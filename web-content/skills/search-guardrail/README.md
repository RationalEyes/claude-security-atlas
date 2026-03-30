# Search Guardrail

A web search result filter that scans fetched pages for injection attacks before
allowing an AI agent to process the content.

## Overview

When AI agents perform web searches, the returned pages may contain hidden
instructions designed to manipulate the agent. The Search Guardrail intercepts
search results, fetches each URL, scans for all 12 WCI injection vectors, and
categorizes results as safe, flagged, or blocked.

## Installation

No installation required. Uses only Python standard library. Requires Python 3.7+.

## Usage

### As a Claude Skill

Invoke with natural language:

- "Safe search for AI security research"
- "Search with guardrails for prompt injection defenses"
- "Filtered search for Claude Skills documentation"
- "Secure web search for LLM red teaming techniques"

### Standalone CLI

**Scan specific URLs:**

```bash
python3 scripts/filter_search_results.py \
    https://example.com/page1 \
    https://example.com/page2 \
    https://example.com/page3
```

**Scan URLs from stdin (one per line):**

```bash
echo "https://example.com/page1
https://example.com/page2" | python3 scripts/filter_search_results.py
```

**JSON output:**

```bash
python3 scripts/filter_search_results.py --format json URL1 URL2
```

**Adjust blocking threshold:**

```bash
# Block HIGH and above (stricter)
python3 scripts/filter_search_results.py --threshold HIGH URL1 URL2

# Block only CRITICAL (more permissive)
python3 scripts/filter_search_results.py --threshold CRITICAL URL1 URL2
```

**Set fetch timeout:**

```bash
python3 scripts/filter_search_results.py --timeout 10 URL1 URL2
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All results safe |
| 1 | At least one result flagged |
| 2 | At least one result blocked |
| 3 | Input error (no URLs provided) |

### JSON Report Structure

```json
{
  "safe": [
    {
      "url": "https://example.com/safe-page",
      "risk_score": 5,
      "max_severity": "LOW",
      "finding_count": 1,
      "findings": [...]
    }
  ],
  "flagged": [...],
  "blocked": [...],
  "errors": [
    {"url": "https://example.com/down", "error": "Connection timed out"}
  ],
  "summary": {
    "total_urls": 5,
    "safe_count": 3,
    "flagged_count": 1,
    "blocked_count": 1,
    "error_count": 0
  }
}
```

## Threshold Behavior

| --threshold | Blocked | Flagged | Passed |
|-------------|---------|---------|--------|
| CRITICAL (default) | CRITICAL | HIGH | MEDIUM, LOW |
| HIGH | HIGH, CRITICAL | MEDIUM | LOW |
| MEDIUM | MEDIUM, HIGH, CRITICAL | LOW | (none) |
| LOW | All findings | (none) | (none) |

## Limitations

- Each URL is fetched sequentially (no parallel fetching) to avoid overwhelming
  target servers
- JavaScript-rendered content is not executed; detection relies on static patterns
- Fetch timeout defaults to 15 seconds per URL; slow sites may time out
- The filter does not cache results between runs

## Integration

Works best as part of the full Module 2 defense stack:

1. **search-guardrail** (this skill) -- Pre-filters search results
2. **web-content-scanner** -- Deep-scans individual pages
3. **real-time-content-filter** -- Behavioral self-auditing during processing

## License

Part of the Claude Security Atlas research project. For educational and
defensive research purposes only.
