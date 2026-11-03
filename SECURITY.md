# Security Policy

## Supported Versions

Currently, the following versions are being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of this project seriously. If you discover a security vulnerability, please bring it to our attention right away!

Please **DO NOT** report security vulnerabilities via public GitHub issues.

Instead, please report it privately via GitHub's **[private vulnerability reporting](https://github.com/ptkvaibhav/burp-fortify-ssc-parser-plugin/security/advisories/new)** (Security tab → *Report a vulnerability*). You should receive a response within 48 hours. If for some reason you do not, please follow up on the advisory to ensure we received your original message.

Please include:
- The affected plugin version and Fortify SSC version.
- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal (sanitized) Burp XML sample.

## Security Measures

- **Hardened XML parsing:** Uploaded Burp XML is untrusted input. DTD processing and external entity resolution are disabled to prevent XXE and entity-expansion attacks; regression tests (`XmlSecurityTest`) enforce this.
- **Dependency isolation:** Jackson is relocated inside the shaded JAR to avoid classloader conflicts with Fortify SSC.
- **Automated scanning:** CodeQL (Java and GitHub Actions workflows), Dependabot version/security updates, and OWASP Dependency-Check (`./gradlew dependencyCheckAnalyze`, fails on CVSS ≥ 7.0).
- **Least-privilege CI:** GitHub Actions workflows run with read-only `contents` permissions by default.
