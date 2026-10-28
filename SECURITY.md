# Security Policy

The TreeGuard project takes the security of its software, security rules, and users very seriously.

## Supported Versions

Only the latest major/minor release of TreeGuard receives active security patches.

| Version | Supported          |
| :------ | :----------------- |
| `v0.1.x`| :white_check_mark: |
| `< v0.1`| :x:                |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

If you discover a security vulnerability in TreeGuard, please report it through one of the following private channels:

1. **GitHub Security Advisory (Preferred)**:
   Navigate to the **Security** tab of the repository on GitHub and select **"Report a vulnerability"** to open a confidential report.
2. **Email**:
   If private vulnerability reporting is unavailable, send an email to the maintainers at **security@treeguard.dev** (or contact **loganprice** directly via GitHub).

### What to Include in Your Report

To help us triage and resolve the issue quickly, please provide:
* A clear description of the vulnerability and its potential impact.
* The affected component(s) (e.g., Tree-sitter parsing, Rego engine evaluation, rule pack registry client, CLI).
* Step-by-step instructions or a minimal reproducible code example / rule file.
* Any potential mitigations or remediations you have identified.

---

## Vulnerability Handling Process

1. **Acknowledgment**: We aim to acknowledge receipt of your vulnerability report within **48 hours**.
2. **Assessment & Confirmation**: We will investigate and confirm the vulnerability within **5 business days**, providing an initial severity rating and assessment.
3. **Remediation & Patch**: A fix will be developed in a private branch.
4. **Coordinated Disclosure**: Once a patched release is published, we will publish a GitHub Security Advisory crediting the finder (unless anonymity is requested).
