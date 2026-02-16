import os
import re
import sys
import base64
from pathlib import Path

SUSPICIOUS_PATTERNS = [
    r"<!--.*?-->",                             # HTML comments
    r"<script.*?>.*?</script>",                # Embedded scripts
    r"eval\s*\(",                              # JS eval
    r"atob\s*\(",                              # JS base64 decode
    r"Function\s*\(",                          # JS Function constructor
    r"powershell\s+-enc",                      # PowerShell encoded command
    r"curl\s+.*\|\s*sh",                       # Curl to shell
    r"wget\s+.*\|\s*sh",
    r"/bin/bash\s+-c",
    r"base64\s+-d",
    r"[A-Za-z0-9+/]{200,}={0,2}",               # Large base64 blobs
]

SUSPICIOUS_URLS = [
    r"https?://\d+\.\d+\.\d+\.\d+",             # Raw IP URLs
    r"https?://pastebin\.com",
    r"https?://raw\.githubusercontent\.com",
    r"https?://.*\.onion",
]

ZERO_WIDTH_CHARS = [
    "\u200b", "\u200c", "\u200d", "\ufeff"
]

def scan_file(path: Path):
    issues = []
    text = path.read_text(errors="ignore")

    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, text, re.DOTALL | re.IGNORECASE):
            issues.append(f"Pattern match: {pattern}")

    for pattern in SUSPICIOUS_URLS:
        if re.search(pattern, text, re.IGNORECASE):
            issues.append(f"Suspicious URL: {pattern}")

    for char in ZERO_WIDTH_CHARS:
        if char in text:
            issues.append("Zero-width / hidden Unicode character detected")

    return issues

def main():
    root = Path(os.environ.get("GITHUB_WORKSPACE", "."))
    markdown_files = list(root.rglob("*.md"))

    if not markdown_files:
        print("No markdown files found.")
        return

    found_issues = False

    for md in markdown_files:
        issues = scan_file(md)
        if issues:
            found_issues = True
            print(f"\n Issues found in {md}:")
            for issue in issues:
                print(f"  - {issue}")

    if found_issues:
        print("\n Malware scan failed.")
        sys.exit(1)

    print("\n Markdown scan passed.")

if __name__ == "__main__":
    main()
