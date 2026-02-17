name: "Markdown Security Scan"

on:
  push:
    paths:
      - "**/*.md"
  pull_request:
    paths:
      - "**/*.md"
  workflow_dispatch:   # allow manual runs

permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning

jobs:
  # ── Quick scan: inline PR annotations ───────────────────────────────────
  scan-annotations:
    name: "Scan (PR Annotations)"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Markdown Security Scan
        uses: your-org/md-security-scanner@v1   # <-- update to your repo
        with:
          paths: "."
          severity: "low"         # report everything low and above
          fail-on: "high"         # fail the job on high/critical findings
          format: "github"        # emit inline annotations
          recursive: "true"


  # ── SARIF upload: feeds GitHub Code Scanning dashboard ──────────────────
  scan-sarif:
    name: "Scan (SARIF → Code Scanning)"
    runs-on: ubuntu-latest
    # Only run on the default branch or PRs; skip forks without write access
    if: >
      github.event_name == 'push' ||
      (github.event_name == 'pull_request' &&
       github.event.pull_request.head.repo.full_name == github.repository)
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Markdown Security Scan (SARIF)
        id: md_scan
        uses: your-org/md-security-scanner@v1
        with:
          paths: "."
          severity: "low"
          fail-on: "critical"     # only hard-fail on critical in SARIF job
          format: "sarif"
          output-file: "md-security-results.sarif"

      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()              # upload even if the scan step failed
        with:
          sarif_file: "md-security-results.sarif"
          category: "markdown-security"

      - name: Print scan summary
        if: always()
        run: |
          echo "Total findings : ${{ steps.md_scan.outputs.findings-count }}"
          echo "Critical       : ${{ steps.md_scan.outputs.critical-count }}"
          echo "High           : ${{ steps.md_scan.outputs.high-count }}"
