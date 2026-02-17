#!/usr/bin/env python3
"""
Markdown Security Scanner
Detects hidden comments, embedded malware indicators, and suspicious content
in Markdown files. Designed to run as a GitHub Action or standalone CLI tool.
"""

import re
import sys
import os
import json
import argparse
import glob
from dataclasses import dataclass, field, asdict
from typing import Optional
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

RULES = [
    # ── Hidden / Obfuscated Comments ──────────────────────────────────────

    {
        "id": "MD001",
        "severity": Severity.MEDIUM,
        "title": "HTML comment found",
        "description": "HTML comments (<!-- -->) inside Markdown can hide text from readers while it still exists in the raw file.",
        "pattern": re.compile(r'<!--[\s\S]*?-->', re.DOTALL),
        "remediation": "Remove or convert to standard Markdown comments if documentation is needed.",
    },
    {
        "id": "MD002",
        "severity": Severity.HIGH,
        "title": "Zero-width character detected",
        "description": "Zero-width spaces/joiners/non-joiners can be used to watermark text, hide data, or bypass keyword filters.",
        "pattern": re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad]'),
        "remediation": "Strip all zero-width characters from the file.",
    },
    {
        "id": "MD003",
        "severity": Severity.MEDIUM,
        "title": "Unicode homoglyph / lookalike character",
        "description": "Non-ASCII lookalike characters (Cyrillic, Greek, etc.) can disguise URLs or keywords.",
        "pattern": re.compile(
            r'[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ'
            r'\u0400-\u04ff'   # Cyrillic
            r'\u0370-\u03ff'   # Greek
            r'\u2100-\u214f'   # Letterlike symbols
            r']'
        ),
        "remediation": "Replace with standard ASCII characters where possible.",
    },
    {
        "id": "MD004",
        "severity": Severity.LOW,
        "title": "Invisible/whitespace-only line",
        "description": "Lines consisting entirely of whitespace may be used to pad files or hide content.",
        "pattern": re.compile(r'^[ \t]{5,}$', re.MULTILINE),
        "remediation": "Remove unnecessary whitespace lines.",
    },
    {
        "id": "MD005",
        "severity": Severity.HIGH,
        "title": "Base64-encoded data block",
        "description": "Large Base64 blobs can conceal binary payloads, scripts, or stolen data.",
        "pattern": re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})'),
        "remediation": "Verify the Base64 content is intentional (e.g., image data). Remove if unexpected.",
    },
    {
        "id": "MD006",
        "severity": Severity.MEDIUM,
        "title": "Hexadecimal data block",
        "description": "Long hex strings may represent encoded payloads or shellcode.",
        "pattern": re.compile(r'\b(?:0x)?[0-9a-fA-F]{32,}\b'),
        "remediation": "Verify hex data is expected (e.g., a hash). Investigate and remove if unknown.",
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
    },
    {
        "id": "MD012",
        "severity": Severity.HIGH,
        "title": "Data URI in link or image",
        "description": "data: URIs can embed and execute arbitrary content.",
        "pattern": re.compile(r'data:[a-z/+;]+;base64,', re.IGNORECASE),
        "remediation": "Remove data: URIs. Use hosted assets instead.",
    },
    {
        "id": "MD013",
        "severity": Severity.HIGH,
        "title": "JavaScript URI",
        "description": "javascript: URIs execute code in some renderers and are a common XSS vector.",
        "pattern": re.compile(r'javascript\s*:', re.IGNORECASE),
        "remediation": "Remove all javascript: URIs.",
    },

    # ── Embedded Scripts & Code Injection ─────────────────────────────────

    {
        "id": "MD020",
        "severity": Severity.CRITICAL,
        "title": "Inline script tag",
        "description": "<script> tags in Markdown may execute in certain renderers (e.g., GitHub Pages, Jekyll).",
        "pattern": re.compile(r'<script[\s>]', re.IGNORECASE),
        "remediation": "Remove all <script> tags from Markdown files.",
    },
    {
        "id": "MD021",
        "severity": Severity.HIGH,
        "title": "Inline event handler",
        "description": "HTML event handlers (onload=, onclick=, etc.) are XSS vectors in rendered Markdown.",
        "pattern": re.compile(r'\bon\w+\s*=\s*["\']', re.IGNORECASE),
        "remediation": "Remove all inline event handlers.",
    },
    {
        "id": "MD022",
        "severity": Severity.CRITICAL,
        "title": "Shell command injection pattern",
        "description": "Backtick command substitution or $() in unexpected places may indicate injection attempts.",
        "pattern": re.compile(r'(?:`[^`\n]{10,}`|\$\([^)\n]{10,}\))'),
        "remediation": "Audit shell commands in code blocks; ensure none execute outside intended contexts.",
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
    },
    {
        "id": "MD025",
        "severity": Severity.HIGH,
        "title": "Suspicious eval usage",
        "description": "eval() of dynamic content is a common code injection vector.",
        "pattern": re.compile(r'\beval\s*\(', re.IGNORECASE),
        "remediation": "Avoid eval(); use safer alternatives.",
    },

    # ── Credential & Secret Leakage ────────────────────────────────────────

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
    },
    {
        "id": "MD031",
        "severity": Severity.CRITICAL,
        "title": "AWS credential pattern",
        "description": "Matches AWS Access Key ID or Secret Key formats.",
        "pattern": re.compile(r'(?:AKIA|AIPA|ASIA|AROA)[A-Z0-9]{16}'),
        "remediation": "Rotate the AWS key immediately and remove from the file.",
    },
    {
        "id": "MD032",
        "severity": Severity.CRITICAL,
        "title": "Private key block",
        "description": "PEM private key material found in Markdown.",
        "pattern": re.compile(
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
        ),
        "remediation": "Remove all private key material immediately and rotate the key.",
    },
    {
        "id": "MD033",
        "severity": Severity.HIGH,
        "title": "GitHub / GitLab personal access token",
        "description": "Matches the ghp_, gho_, ghs_, glpat- token prefixes.",
        "pattern": re.compile(r'(?:ghp|gho|ghs|ghu|github_pat|glpat)_[A-Za-z0-9_]{20,}'),
        "remediation": "Revoke the token immediately and remove from the file.",
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
    },
    {
        "id": "MD041",
        "severity": Severity.HIGH,
        "title": "Path traversal pattern",
        "description": "../ sequences in links or paths may attempt directory traversal.",
        "pattern": re.compile(r'(?:\.\./){2,}'),
        "remediation": "Use absolute paths or remove the traversal sequence.",
    },

    # ── Metadata & Frontmatter Abuse ───────────────────────────────────────

    {
        "id": "MD050",
        "severity": Severity.MEDIUM,
        "title": "YAML frontmatter with executable field",
        "description": "Frontmatter keys like 'exec', 'run', or 'script' may be processed by static site generators.",
        "pattern": re.compile(r'^(?:exec|run|script|command|hook|plugin)\s*:', re.MULTILINE | re.IGNORECASE),
        "remediation": "Remove executable keys from YAML frontmatter.",
    },
]


# ─────────────────────────────────────────────
#  Scanner
# ─────────────────────────────────────────────

def scan_file(filepath: str, severity_threshold: Severity = Severity.LOW) -> list[Finding]:
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
    findings: list[Finding] = []

    for rule in RULES:
        # Skip rules below severity threshold
        if severity_order.index(rule["severity"]) < threshold_idx:
            continue

        for match in rule["pattern"].finditer(content):
            # Calculate line and column from match position
            start = match.start()
            line_num = content[:start].count("\n") + 1
            line_start = content.rfind("\n", 0, start) + 1
            col = start - line_start + 1

            # Build a brief snippet (the matched line, truncated)
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


def scan_paths(paths: list[str], recursive: bool, severity_threshold: Severity) -> list[Finding]:
    all_findings: list[Finding] = []
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
            # Treat as a glob
            for md_file in glob.glob(path, recursive=recursive):
                all_findings.extend(scan_file(md_file, severity_threshold))
                files_scanned += 1

    print(f"[INFO] Scanned {files_scanned} file(s), found {len(all_findings)} issue(s).", file=sys.stderr)
    return all_findings


# ─────────────────────────────────────────────
#  Output Formatters
# ─────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.INFO:     "\033[36m",   # cyan
    Severity.LOW:      "\033[34m",   # blue
    Severity.MEDIUM:   "\033[33m",   # yellow
    Severity.HIGH:     "\033[31m",   # red
    Severity.CRITICAL: "\033[1;31m", # bold red
}
RESET = "\033[0m"


def format_console(findings: list[Finding], no_color: bool = False) -> str:
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


def format_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def format_github_annotations(findings: list[Finding]) -> str:
    """
    Emit GitHub Actions workflow commands so findings appear as
    inline annotations on the PR diff.
    """
    lines = []
    level_map = {
        Severity.INFO:     "notice",
        Severity.LOW:      "notice",
        Severity.MEDIUM:   "warning",
        Severity.HIGH:     "error",
        Severity.CRITICAL: "error",
    }
    for f in findings:
        level = level_map[f.severity]
        msg = f"{f.rule_id}: {f.title} — {f.description}"
        lines.append(
            f"::{level} file={f.file},line={f.line},col={f.column},"
            f"title={f.rule_id} {f.title}::{msg}"
        )
    return "\n".join(lines)


def format_sarif(findings: list[Finding]) -> str:
    """
    SARIF 2.1.0 output — compatible with GitHub Code Scanning.
    """
    severity_map = {
        Severity.INFO:     ("note",    "none"),
        Severity.LOW:      ("note",    "low"),
        Severity.MEDIUM:   ("warning", "medium"),
        Severity.HIGH:     ("error",   "high"),
        Severity.CRITICAL: ("error",   "critical"),
    }

    rules = []
    rule_ids_seen = set()
    results = []

    for f in findings:
        if f.rule_id not in rule_ids_seen:
            rule_ids_seen.add(f.rule_id)
            level, security_severity = severity_map[f.severity]
            rules.append({
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation},
                "properties": {
                    "security-severity": {"critical": "9.5", "high": "7.5",
                                          "medium": "5.0", "low": "2.5", "none": "0.0"
                                          }.get(security_severity, "0.0"),
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

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "md-security-scanner",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/md-security-scanner",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


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
        """,
    )
    parser.add_argument("paths", nargs="+", help="Files, directories, or globs to scan.")
    parser.add_argument("-r", "--recursive", action="store_true", default=True,
                        help="Recurse into subdirectories (default: true).")
    parser.add_argument("--format", choices=["console", "json", "github", "sarif"],
                        default="console", help="Output format.")
    parser.add_argument("--severity", choices=[s.value for s in Severity],
                        default="low", help="Minimum severity to report.")
    parser.add_argument("--fail-on", choices=[s.value for s in Severity],
                        default="high",
                        help="Exit with code 1 if any finding meets this severity (default: high).")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color codes in console output.")
    parser.add_argument("--output", "-o", help="Write output to a file instead of stdout.")
    return parser.parse_args()


def main():
    args = parse_args()

    severity_threshold = Severity(args.severity)
    fail_threshold = Severity(args.fail_on)

    findings = scan_paths(args.paths, args.recursive, severity_threshold)

    # Sort: critical first
    severity_order = list(Severity)
    findings.sort(key=lambda f: severity_order.index(f.severity), reverse=True)

    # Format output
    if args.format == "console":
        output = format_console(findings, no_color=args.no_color)
    elif args.format == "json":
        output = format_json(findings)
    elif args.format == "github":
        output = format_github_annotations(findings)
    elif args.format == "sarif":
        output = format_sarif(findings)
    else:
        output = format_console(findings, no_color=args.no_color)

    # Write or print
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[INFO] Output written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Also emit GitHub annotations when running inside Actions
    if os.getenv("GITHUB_ACTIONS") and args.format != "github":
        print(format_github_annotations(findings))

    # Exit code
    fail_idx = severity_order.index(fail_threshold)
    for f in findings:
        if severity_order.index(f.severity) >= fail_idx:
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
