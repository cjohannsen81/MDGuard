import os
import re
import sys
from pathlib import Path

# --- Suspicious patterns ---
SUSPICIOUS_PATTERNS = [
    r"<!--.*?-->",                    # HTML comments
    r"<script.*?>.*?</script>",       # <script> blocks
    r"eval\s*\(",                     # JS eval()
    r"atob\s*\(",                     # JS base64 decode
    r"Function\s*\(",                 # JS Function()
    r"powershell\s+-enc",             # PowerShell encoded commands
    r"curl\s+.*\|\s*sh",              # Curl to shell
    r"wget\s+.*\|\s*sh",
    r"/bin/bash\s+-c",
    r"base64\s+-d",
    r"[A-Za-z0-9+/]{200,}={0,2}",    # Large base64 blobs
    # --- New patterns ---
    r"<img\s+.*?on\w+\s*=",           # <img onerror=...>
    r"<form\s+.*?action\s*=",         # <form action=...>
    r"javascript\s*:",                # js: links
    r"<iframe.*?>.*?</iframe>",       # <iframe> tags
    r"<object.*?>.*?</object>",       # <object> tags
    r"<embed.*?>.*?</embed>",         # <embed> tags
    r"document\.cookie",              # JS cookie access
    r"window\.location",              # JS redirect access
]

# --- Suspicious URLs ---
SUSPICIOUS_URLS = [
    r"https?://\d+\.\d+\.\d+\.\d+",   # raw IP URLs
    r"https?://pastebin\.com",
    r"https?://raw\.githubusercontent\.com",
    r"https?://.*\.onion",
    r"https?://.*\.evil\.example\.com", # example phishing domain
]

# --- Hidden or homoglyph Unicode chars ---
ZERO_WIDTH_CHARS = [
    "\u200b", "\u200c", "\u200d", "\ufeff", # invisible
    "\u2212",                               # minus sign homoglyph
    "\u2013", "\u2014",                     # en-dash / em-dash
]

def scan_file(path: Path):
    issues = []
    text = path.read_text(errors="ignore")

    # Scan for patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.DOTALL | re.IGNORECASE):
            issues.append(f"Pattern match: {pattern}")

    # Scan for suspicious URLs
    for pattern in SUSPICIOUS_URLS:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append(f"Suspicious URL: {pattern}")

    # Scan for hidden/unicode tricks
    for char in ZERO_WIDTH_CHARS:
        if char in text:
            issues.append(f"Hidden/unusual Unicode character detected: U+{ord(char):04X}")

    return issues

def main():
    root = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    markdown_files = [
        p for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() == ".md"
    ]

    if not markdown_files:
        print("No markdown files found.")
        return

    found_issues = False

    for md in markdown_files:
        issues = scan_file(md)
        if issues:
            found_issues = True
            print(f"\nIssues found in {md}:")
            for issue in issues:
                print(f"  - {issue}")

    if found_issues:
        print("\nMalware scan failed.")
        sys.exit(1)

    print("\nMarkdown scan passed.")

if __name__ == "__main__":
    main()

