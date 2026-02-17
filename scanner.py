#!/usr/bin/env python3
"""
Markdown Security Scanner
Detects hidden comments, embedded malware indicators, and suspicious content
in Markdown files. Designed to run as a GitHub Action or standalone CLI tool.

Suppression directives (place anywhere in your Markdown):
  <!-- scanner-ignore -->                suppress ALL rules on the NEXT line
  <!-- scanner-ignore MD020,MD022 -->    suppress specific rules on the NEXT line
  <!-- scanner-ignore-block -->          suppress all rules until the closing tag
  <!-- scanner-ignore-end -->            end a scanner-ignore-block
"""

import re
import sys
import os
import json
import argparse
import glob
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    file: str
    line: int
    column: int
    snippet: str
    remediation: str = ""

    def to_dict(self):
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


# ─────────────────────────────────────────────
#  Detection Rules
# ─────────────────────────────────────────────
#
#  "scan_code_blocks": False  → skip matches inside fenced/inline code
#  "scan_code_blocks": True   → always fire (e.g. real credentials)

RULES = [
    # ── Hidden / Obfuscated Comments ──────────────────────────────────────
    {
        "id": "MD001",
        "severity": Severity.MEDIUM,
        "title": "HTML comment found",
        "description": "HTML comments (<!-- -->) can hide text from readers while still present in the raw file.",
        "pattern": re.compile(r'<!--(?!.*scanner-ignore)[\s\S]*?-->', re.DOTALL),
        "remediation": "Remove or convert to standard Markdown comments if documentation is needed.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD002",
        "severity": Severity.HIGH,
        "title": "Zero-width character detected",
        "description": "Zero-width spaces/joiners/non-joiners can watermark text, hide data, or bypass keyword filters.",
        "pattern": re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad]'),
        "remediation": "Strip all zero-width characters from the file.",
        "scan_code_blocks": True,
    },
    {
        "id": "MD003",
        "severity": Severity.MEDIUM,
        "title": "Unicode homoglyph / lookalike character",
        "description": "Non-ASCII lookalike characters (Cyrillic, Greek, etc.) can disguise URLs or keywords.",
        "pattern": re.compile(
            r'[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ'
            r'\u0400-\u04ff'
            r'\u0370-\u03ff'
            r'\u2100-\u214f'
            r']'
        ),
        "remediation": "Replace with standard ASCII characters where possible.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD004",
        "severity": Severity.LOW,
        "title": "Invisible/whitespace-only line",
        "description": "Lines consisting entirely of whitespace may be used to pad files or hide content.",
        "pattern": re.compile(r'^[ \t]{5,}$', re.MULTILINE),
        "remediation": "Remove unnecessary whitespace lines.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD005",
        "severity": Severity.HIGH,
        "title": "Base64-encoded data block",
        "description": "Large Base64 blobs can conceal binary payloads, scripts, or stolen data.",
        "pattern": re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})'),
        "remediation": "Verify the Base64 content is intentional (e.g., image data). Remove if unexpected.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD006",
        "severity": Severity.MEDIUM,
        "title": "Hexadecimal data block",
        "description": "Long hex strings may represent encoded payloads or shellcode.",
        "pattern": re.compile(r'\b(?:0x)?[0-9a-fA-F]{32,}\b'),
        "remediation": "Verify hex data is expected (e.g., a hash). Investigate and remove if unknown.",
        "scan_code_blocks": False,
    },

    # ── Malicious URLs & Redirects ─────────────────────────────────────────
    {
        "id": "MD010",
        "severity": Severity.HIGH,
        "title": "Suspicious URL shortener",
        "description": "URL shorteners can mask malicious destinations.",
        "pattern": re.compile(
            r'https?://(?:bit\.ly|t\.co|goo\.gl|tinyurl\.com|ow\.ly|is\.gd|'
            r'buff\.ly|adf\.ly|short\.link|rb\.gy|cutt\.ly|tiny\.cc)/\S+',
            re.IGNORECASE
        ),
        "remediation": "Expand and verify the full destination URL before using.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD011",
        "severity": Severity.CRITICAL,
        "title": "Raw IP address URL",
        "description": "Links directly to IP addresses are unusual and often indicate C2 servers or phishing pages.",
        "pattern": re.compile(
            r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/\S*)?',
            re.IGNORECASE
        ),
        "remediation": "Replace with a proper domain name or remove entirely.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD012",
        "severity": Severity.HIGH,
        "title": "Data URI in link or image",
        "description": "data: URIs can embed and execute arbitrary content.",
        "pattern": re.compile(r'data:[a-z/+;]+;base64,', re.IGNORECASE),
        "remediation": "Remove data: URIs. Use hosted assets instead.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD013",
        "severity": Severity.HIGH,
        "title": "JavaScript URI",
        "description": "javascript: URIs execute code in some renderers and are a common XSS vector.",
        "pattern": re.compile(r'javascript\s*:', re.IGNORECASE),
        "remediation": "Remove all javascript: URIs.",
        "scan_code_blocks": False,
    },

    # ── Embedded Scripts & Code Injection ─────────────────────────────────
    {
        "id": "MD020",
        "severity": Severity.CRITICAL,
        "title": "Inline script tag",
        "description": "<script> tags in Markdown may execute in certain renderers (e.g., GitHub Pages, Jekyll).",
        "pattern": re.compile(r'<script[\s>]', re.IGNORECASE),
        "remediation": "Remove all <script> tags from Markdown files.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD021",
        "severity": Severity.HIGH,
        "title": "Inline event handler",
        "description": "HTML event handlers (onload=, onclick=, etc.) are XSS vectors in rendered Markdown.",
        "pattern": re.compile(r'\bon\w+\s*=\s*["\']', re.IGNORECASE),
        "remediation": "Remove all inline event handlers.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD022",
        "severity": Severity.CRITICAL,
        "title": "Shell command injection pattern",
        "description": "Backtick command substitution or $() outside of inline code may indicate injection.",
        "pattern": re.compile(r'(?:`[^`\n]{10,}`|\$\([^)\n]{10,}\))'),
        "remediation": "Audit shell commands; ensure none execute outside intended contexts.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD023",
        "severity": Severity.CRITICAL,
        "title": "PowerShell download-and-execute pattern",
        "description": "Common pattern used by malware droppers.",
        "pattern": re.compile(
            r'(?:IEX|Invoke-Expression|powershell|pwsh).*(?:DownloadString|WebClient|'
            r'Net\.WebClient|Start-Process|Invoke-WebRequest)',
            re.IGNORECASE
        ),
        "remediation": "Remove immediately. This is a known malware dropper pattern.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD024",
        "severity": Severity.CRITICAL,
        "title": "curl/wget pipe-to-shell pattern",
        "description": "Piping remote content directly to a shell is a classic malware delivery technique.",
        "pattern": re.compile(
            r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|zsh|python|perl|ruby)',
            re.IGNORECASE
        ),
        "remediation": "Never pipe remote content to a shell. Download and inspect scripts first.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD025",
        "severity": Severity.HIGH,
        "title": "Suspicious eval usage",
        "description": "eval() of dynamic content is a common code injection vector.",
        "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
        "remediation": "Avoid eval(); use safer alternatives.",
        "scan_code_blocks": False,
    },

    # ── Credential & Secret Leakage ────────────────────────────────────────
    # scan_code_blocks=True: real creds are dangerous regardless of context
    {
        "id": "MD030",
        "severity": Severity.CRITICAL,
        "title": "Hardcoded secret / API key pattern",
        "description": "Strings matching common API key patterns found in Markdown content.",
        "pattern": re.compile(
            r'(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|'
            r'private[_-]?key|access[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9/+_\-]{16,}["\']?',
            re.IGNORECASE
        ),
        "remediation": "Rotate the exposed credential immediately and remove from the file.",
        "scan_code_blocks": True,
    },
    {
        "id": "MD031",
        "severity": Severity.CRITICAL,
        "title": "AWS credential pattern",
        "description": "Matches AWS Access Key ID or Secret Key formats.",
        "pattern": re.compile(r'(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}'),
        "remediation": "Rotate the AWS key immediately and remove from the file.",
        "scan_code_blocks": True,
    },
    {
        "id": "MD032",
        "severity": Severity.CRITICAL,
        "title": "Private key block",
        "description": "PEM private key material found in Markdown.",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        "remediation": "Remove all private key material immediately and rotate the key.",
        "scan_code_blocks": True,
    },
    {
        "id": "MD033",
        "severity": Severity.HIGH,
        "title": "GitHub / GitLab personal access token",
        "description": "Matches the ghp_, gho_, ghs_, glpat- token prefixes.",
        "pattern": re.compile(r'(?:ghp|gho|ghs|ghu|github_pat|glpat)_[A-Za-z0-9_]{20,}'),
        "remediation": "Revoke the token immediately and remove from the file.",
        "scan_code_blocks": True,
    },

    # ── Suspicious File References ─────────────────────────────────────────
    {
        "id": "MD040",
        "severity": Severity.HIGH,
        "title": "Reference to executable / dangerous file type",
        "description": "Links to .exe, .bat, .sh, .ps1 etc. in Markdown may be social engineering.",
        "pattern": re.compile(
            r'\[.*?\]\(.*?\.(?:exe|bat|cmd|sh|ps1|vbs|scr|msi|dmg|deb|rpm|jar|class)\)',
            re.IGNORECASE
        ),
        "remediation": "Verify the linked file is legitimate and expected.",
        "scan_code_blocks": False,
    },
    {
        "id": "MD041",
        "severity": Severity.HIGH,
        "title": "Path traversal pattern",
        "description": "../ sequences in links or paths may attempt directory traversal.",
        "pattern": re.compile(r'(?:\.\./){2,}'),
        "remediation": "Use absolute paths or remove the traversal sequence.",
        "scan_code_blocks": False,
    },

    # ── Metadata & Frontmatter Abuse ───────────────────────────────────────
    {
        "id": "MD050",
        "severity": Severity.MEDIUM,
        "title": "YAML frontmatter with executable field",
        "description": "Frontmatter keys like 'exec', 'run', or 'script' may be processed by static site generators.",
        "pattern": re.compile(r'^(?:exec|run|script|command|hook|plugin)\s*:', re.MULTILINE | re.IGNORECASE),
        "remediation": "Remove executable keys from YAML frontmatter.",
        "scan_code_blocks": False,
    },
]


# ─────────────────────────────────────────────
#  Content Preprocessing Helpers
# ─────────────────────────────────────────────

# Fenced code blocks (``` or ~~~, with optional language tag)
_FENCE_RE = re.compile(
    r'^[ \t]*(`{3,}|~{3,})[^\n]*\n[\s\S]*?\n[ \t]*\1[ \t]*$',
    re.MULTILINE
)
# Inline code spans  (`...`) — single backtick, no newlines inside
_INLINE_CODE_RE = re.compile(r'(?<!`)`(?!`)[^`\n]+`(?!`)')

# Ignore directive patterns
_IGNORE_LINE_RE        = re.compile(r'<!--\s*scanner-ignore(?:\s+([\w,\s]+?))?\s*-->', re.IGNORECASE)
_IGNORE_BLOCK_START_RE = re.compile(r'<!--\s*scanner-ignore-block\s*-->',               re.IGNORECASE)
_IGNORE_BLOCK_END_RE   = re.compile(r'<!--\s*scanner-ignore-end\s*-->',                 re.IGNORECASE)


def _build_code_block_mask(content: str) -> List[bool]:
    """Per-character boolean mask: True where char is inside a code block or inline code span."""
    mask = [False] * len(content)
    for m in _FENCE_RE.finditer(content):
        for i in range(m.start(), m.end()):
            mask[i] = True
    for m in _INLINE_CODE_RE.finditer(content):
        for i in range(m.start(), m.end()):
            mask[i] = True
    return mask


def _build_ignore_map(lines: List[str]) -> Dict[int, Optional[Set[str]]]:
    """
    Map 1-based line numbers → suppressed rule IDs (or None = suppress all).

    Directives:
      <!-- scanner-ignore -->               suppress all rules on the NEXT line
      <!-- scanner-ignore MD020,MD022 -->   suppress named rules on the NEXT line
      <!-- scanner-ignore-block -->         suppress all until scanner-ignore-end
      <!-- scanner-ignore-end -->
    """
    ignore: Dict[int, Optional[Set[str]]] = {}
    in_block = False

    for idx, line in enumerate(lines):
        lineno = idx + 1

        if _IGNORE_BLOCK_END_RE.search(line):
            in_block = False
            continue

        if _IGNORE_BLOCK_START_RE.search(line):
            in_block = True
            continue

        if in_block:
            ignore[lineno] = None   # suppress all
            continue

        m = _IGNORE_LINE_RE.search(line)
        if m:
            next_lineno = lineno + 1
            rule_ids_str = (m.group(1) or "").strip()
            if rule_ids_str:
                ids = {r.strip().upper() for r in rule_ids_str.split(",")}
                existing = ignore.get(next_lineno)
                if existing is not None:
                    ignore[next_lineno] = existing | ids
                # if existing is None (suppress all), leave it
                elif next_lineno not in ignore:
                    ignore[next_lineno] = ids
            else:
                ignore[next_lineno] = None   # suppress all

    return ignore


# ─────────────────────────────────────────────
#  Scanner
# ─────────────────────────────────────────────

def scan_file(filepath: str, severity_threshold: Severity = Severity.LOW) -> List[Finding]:
    """Scan a single Markdown file and return a list of findings."""
    severity_order = list(Severity)
    threshold_idx = severity_order.index(severity_threshold)

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        print(f"[ERROR] Cannot read {filepath}: {e}", file=sys.stderr)
        return []

    lines = content.splitlines()
    code_mask = _build_code_block_mask(content)
    ignore_map = _build_ignore_map(lines)

    findings: List[Finding] = []

    for rule in RULES:
        if severity_order.index(rule["severity"]) < threshold_idx:
            continue

        scan_code = rule.get("scan_code_blocks", True)

        for match in rule["pattern"].finditer(content):
            start = match.start()

            # Skip if inside code and rule doesn't fire there
            if not scan_code and code_mask[start]:
                continue

            # Determine line/column
            line_num = content[:start].count("\n") + 1
            line_start = content.rfind("\n", 0, start) + 1
            col = start - line_start + 1

            # Check suppress map
            suppressed = ignore_map.get(line_num)
            if line_num in ignore_map:
                if suppressed is None:          # suppress all
                    continue
                if rule["id"] in suppressed:    # suppress this rule
                    continue

            raw_line = lines[line_num - 1] if line_num <= len(lines) else ""
            snippet = raw_line.strip()[:120]

            findings.append(Finding(
                rule_id=rule["id"],
                severity=rule["severity"],
                title=rule["title"],
                description=rule["description"],
                file=filepath,
                line=line_num,
                column=col,
                snippet=snippet,
                remediation=rule.get("remediation", ""),
            ))

    return findings


def scan_paths(paths: List[str], recursive: bool, severity_threshold: Severity) -> List[Finding]:
    all_findings: List[Finding] = []
    files_scanned = 0

    for path in paths:
        if os.path.isfile(path):
            all_findings.extend(scan_file(path, severity_threshold))
            files_scanned += 1
        elif os.path.isdir(path):
            pattern = "**/*.md" if recursive else "*.md"
            for md_file in glob.glob(os.path.join(path, pattern), recursive=recursive):
                all_findings.extend(scan_file(md_file, severity_threshold))
                files_scanned += 1
        else:
            for md_file in glob.glob(path, recursive=recursive):
                all_findings.extend(scan_file(md_file, severity_threshold))
                files_scanned += 1

    print(f"[INFO] Scanned {files_scanned} file(s), found {len(all_findings)} issue(s).", file=sys.stderr)
    return all_findings


# ─────────────────────────────────────────────
#  Output Formatters
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.INFO:     "\033[36m",
    Severity.LOW:      "\033[34m",
    Severity.MEDIUM:   "\033[33m",
    Severity.HIGH:     "\033[31m",
    Severity.CRITICAL: "\033[1;31m",
}
RESET = "\033[0m"


def format_console(findings: List[Finding], no_color: bool = False) -> str:
    if not findings:
        return "✅  No issues found.\n"
    lines = []
    for f in findings:
        color = "" if no_color else SEVERITY_COLORS.get(f.severity, "")
        reset = "" if no_color else RESET
        lines.append(
            f"{color}[{f.severity.value.upper():8}] {f.rule_id}: {f.title}{reset}\n"
            f"  File    : {f.file}:{f.line}:{f.column}\n"
            f"  Snippet : {f.snippet}\n"
            f"  Details : {f.description}\n"
            f"  Fix     : {f.remediation}\n"
        )
    return "\n".join(lines)


def format_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def format_github_annotations(findings: List[Finding]) -> str:
    """Emit GitHub Actions workflow commands for inline PR annotations."""
    level_map = {
        Severity.INFO:     "notice",
        Severity.LOW:      "notice",
        Severity.MEDIUM:   "warning",
        Severity.HIGH:     "error",
        Severity.CRITICAL: "error",
    }
    lines = []
    for f in findings:
        level = level_map[f.severity]
        msg = f"{f.rule_id}: {f.title} — {f.description}"
        lines.append(
            f"::{level} file={f.file},line={f.line},col={f.column},"
            f"title={f.rule_id} {f.title}::{msg}"
        )
    return "\n".join(lines)


def format_sarif(findings: List[Finding]) -> str:
    """SARIF 2.1.0 — compatible with GitHub Code Scanning."""
    severity_map = {
        Severity.INFO:     ("note",    "none"),
        Severity.LOW:      ("note",    "low"),
        Severity.MEDIUM:   ("warning", "medium"),
        Severity.HIGH:     ("error",   "high"),
        Severity.CRITICAL: ("error",   "critical"),
    }
    numeric = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.5", "none": "0.0"}

    rules, results = [], []
    seen: Set[str] = set()

    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            _, sec_sev = severity_map[f.severity]
            rules.append({
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation},
                "properties": {
                    "security-severity": numeric.get(sec_sev, "0.0"),
                    "tags": ["security", "markdown"],
                },
            })
        level, _ = severity_map[f.severity]
        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.line, "startColumn": f.column},
                },
            }],
        })

    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "md-security-scanner",
            "version": "1.1.0",
            "informationUri": "https://github.com/your-org/md-security-scanner",
            "rules": rules,
        }}, "results": results}],
    }, indent=2)


# ─────────────────────────────────────────────
#  CLI Entry Point
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan Markdown files for hidden comments and malware indicators.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py docs/                       # scan all .md files in docs/
  python scanner.py README.md CHANGELOG.md      # scan specific files
  python scanner.py "**/*.md" --recursive       # glob, recursive
  python scanner.py docs/ --format json         # JSON output
  python scanner.py docs/ --format sarif        # SARIF for Code Scanning
  python scanner.py docs/ --severity high       # only high/critical
  python scanner.py docs/ --fail-on medium      # exit 1 if medium+ found

Suppressing false positives in your Markdown:
  <!-- scanner-ignore -->                next line: suppress all rules
  <!-- scanner-ignore MD020,MD022 -->    next line: suppress named rules
  <!-- scanner-ignore-block -->          suppress all rules until:
  <!-- scanner-ignore-end -->
        """,
    )
    parser.add_argument("paths", nargs="+")
    parser.add_argument("-r", "--recursive", action="store_true", default=True)
    parser.add_argument("--format", choices=["console", "json", "github", "sarif"], default="console")
    parser.add_argument("--severity", choices=[s.value for s in Severity], default="low")
    parser.add_argument("--fail-on", choices=[s.value for s in Severity], default="high")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--output", "-o")
    return parser.parse_args()


def main():
    args = parse_args()
    severity_threshold = Severity(args.severity)
    fail_threshold = Severity(args.fail_on)

    findings = scan_paths(args.paths, args.recursive, severity_threshold)

    severity_order = list(Severity)
    findings.sort(key=lambda f: severity_order.index(f.severity), reverse=True)

    fmt = args.format
    if fmt == "console":
        output = format_console(findings, no_color=args.no_color)
    elif fmt == "json":
        output = format_json(findings)
    elif fmt == "github":
        output = format_github_annotations(findings)
    else:
        output = format_sarif(findings)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[INFO] Output written to {args.output}", file=sys.stderr)
    else:
        print(output)

    if os.getenv("GITHUB_ACTIONS") and fmt != "github":
        print(format_github_annotations(findings))

    fail_idx = severity_order.index(fail_threshold)
    for f in findings:
        if severity_order.index(f.severity) >= fail_idx:
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
