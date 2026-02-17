# 🛡️ Markdown Security Scanner

A GitHub Action (and standalone CLI) that scans Markdown files for **hidden comments**, **obfuscated content**, **embedded credentials**, and **malware delivery patterns**.

---

## What it detects

| Category | Rule IDs | Examples |
|---|---|---|
| Hidden / obfuscated comments | MD001–MD006 | HTML comments, zero-width chars, Base64 blobs, hex strings |
| Malicious URLs & redirects | MD010–MD013 | URL shorteners, raw IP links, `javascript:`, `data:` URIs |
| Script injection | MD020–MD025 | `<script>` tags, inline event handlers, PowerShell droppers, `curl \| bash` |
| Credential leakage | MD030–MD033 | API keys, AWS keys, PEM private keys, GitHub tokens |
| Dangerous file references | MD040–MD041 | Links to `.exe`/`.ps1`, path traversal sequences |
| Frontmatter abuse | MD050 | YAML keys like `exec:`, `run:`, `script:` |

---

## Usage as a GitHub Action

Add this to `.github/workflows/md-security-scan.yml`:

```yaml
name: Markdown Security Scan
on:
  push:
    paths: ["**/*.md"]
  pull_request:
    paths: ["**/*.md"]

permissions:
  contents: read
  security-events: write  # for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan Markdown files
        uses: your-org/md-security-scanner@v1
        with:
          paths: "."
          severity: "low"
          fail-on: "high"
          format: "github"    # inline PR annotations
```

### With SARIF (GitHub Code Scanning dashboard)

```yaml
      - name: Scan Markdown files (SARIF)
        id: scan
        uses: your-org/md-security-scanner@v1
        with:
          format: "sarif"
          output-file: "results.sarif"
          fail-on: "critical"

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: "results.sarif"
```

---

## Action inputs

| Input | Default | Description |
|---|---|---|
| `paths` | `.` | Files, dirs, or globs to scan |
| `severity` | `low` | Minimum severity to report (`info`/`low`/`medium`/`high`/`critical`) |
| `fail-on` | `high` | Exit non-zero if any finding meets this level |
| `format` | `github` | Output format: `console`, `json`, `github`, `sarif` |
| `output-file` | _(stdout)_ | Write output to this file |
| `recursive` | `true` | Recurse into subdirectories |

## Action outputs

| Output | Description |
|---|---|
| `findings-count` | Total number of findings |
| `critical-count` | Number of CRITICAL findings |
| `high-count` | Number of HIGH findings |
| `sarif-path` | Path to the SARIF file (when `format: sarif`) |

---

## CLI usage

```bash
# Install (no external dependencies — stdlib only)
git clone https://github.com/your-org/md-security-scanner
cd md-security-scanner

# Scan all Markdown in current directory
python scanner.py .

# Only report high and above; fail the script on critical
python scanner.py docs/ --severity high --fail-on critical

# JSON output
python scanner.py README.md --format json

# SARIF output for Code Scanning
python scanner.py . --format sarif --output results.sarif
```

---

## Running the tests

```bash
python -m pytest tests/ -v
# or
python tests/test_scanner.py
```

---

## Publishing your own copy

1. Fork / push this repo to `your-org/md-security-scanner`.
2. Create a release tag (e.g. `v1.0.0`) and also move the `v1` tag:
   ```bash
   git tag v1.0.0
   git tag -f v1
   git push origin v1.0.0 v1 --force
   ```
3. Reference it in workflows with `uses: your-org/md-security-scanner@v1`.

---

## Adding custom rules

Open `scanner.py` and append to the `RULES` list:

```python
{
    "id": "MD999",
    "severity": Severity.HIGH,
    "title": "My custom rule",
    "description": "What this detects.",
    "pattern": re.compile(r'my-bad-pattern', re.IGNORECASE),
    "remediation": "How to fix it.",
},
```

No other changes needed — the scanner picks up all rules automatically.

---

## License

MIT
