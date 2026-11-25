# CYBERX SENTINEL X
Discover. Analyze. Secure.

<div align="center">

<img src="assets/cyberx-sentinel-banner.svg" alt="CYBERX SENTINEL X — Defensive Web Intelligence" width="100%">

# CYBERX SENTINEL X

### Unified Defensive Website Intelligence & Configuration Assessment

<p>
  <img src="https://img.shields.io/badge/version-1.0-7c6cff?style=for-the-badge" alt="Version 1.0">
  <img src="https://img.shields.io/badge/python-3.9%2B-31c9c0?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/platform-Termux%20%7C%20Linux-18243a?style=for-the-badge" alt="Termux and Linux">
  <img src="https://img.shields.io/badge/purpose-Defensive%20Only-e7a83e?style=for-the-badge" alt="Defensive only">
</p>

**A focused, permission-based toolkit for reviewing public website configuration, exposure signals and security posture.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Reports](#-reports) • [Safety](#-authorized-use--safety)

</div>

---

## ✦ Overview

**CYBERX SENTINEL X** combines defensive website intelligence checks in one Python tool. It gathers publicly available configuration signals, performs limited checks against the authorized target, and creates readable reports for follow-up review.

> Built for website owners, developers, and authorized security reviewers. It is an assessment helper—not an exploitation framework or a replacement for a professional security audit.

## ⚡ Features

| Module | What it checks |
|---|---|
| **DNS Intelligence** | A, AAAA, MX, NS, TXT, CNAME and SOA records |
| **RDAP Lookup** | Public domain registration information |
| **Web Assessment** | HTTP/HTTPS response and security-header observations |
| **TLS Inspection** | Certificate details and validity information |
| **Public Files** | `robots.txt`, `sitemap.xml` and `security.txt` |
| **Passive Subdomains** | Certificate Transparency discovery through `crt.sh` |
| **Public Page Review** | Limited robots.txt-aware crawl of public pages |
| **Email Discovery** | Email addresses visibly published on crawled pages |
| **Admin Path Review** | Small fixed list of common paths, using ordinary GET requests |
| **Report Generator** | JSON, TXT and self-contained HTML reports |

### 🛡️ Safety-minded controls

- Target must be a public hostname; IP-address targets are not accepted.
- Redirects are followed manually with scope checks.
- Public-IP checks, request timeouts and response-size limits are applied.
- Sensitive response headers are redacted from reports.
- Crawling observes `robots.txt` and uses a limited page count.
- No brute-force, login attempts, exploitation, authentication bypass or form submission.

## 📱 Installation

### Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install python -y

mkdir -p ~/cyberx-sentinel
cd ~/cyberx-sentinel
```

Copy these project files into the folder:

- `cyberx_sentinel_x.py`
- `requirements.txt`

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Linux

```bash
sudo apt update
sudo apt install python3 python3-pip -y

python3 -m pip install -r requirements.txt
```

## 🚀 Usage

### Start the interactive menu

```bash
python cyberx_sentinel_x.py
```

### Run a full assessment

```bash
python cyberx_sentinel_x.py example.com --full
```

### Confirm authorization non-interactively

```bash
python cyberx_sentinel_x.py example.com --yes-authorized --full
```

Replace `example.com` with a domain you own or have explicit written permission to assess.

## 📊 Reports

Generated reports are saved in:

```text
reports/
```

Available formats:

- **HTML** — convenient browser-readable report
- **JSON** — structured results for further processing
- **TXT** — lightweight plain-text summary

## ⚠️ Authorized Use & Safety

Use this tool **only** on domains you own or are explicitly authorized to assess.

This tool does not exploit vulnerabilities, attempt logins, brute-force credentials, bypass authentication, submit forms, or access private data. A discovered login path, exposed email address, or missing security header is **not proof of a vulnerability**. Verify findings manually and responsibly.

## ℹ️ Known Limitations

- DNS is checked before each HTTP hop, but ordinary Requests networking cannot guarantee IP pinning across DNS changes. This does not fully eliminate DNS rebinding or time-of-check/time-of-use risk.
- Admin-path review intentionally checks only a small, fixed list of common paths.
- JavaScript-rendered pages may not expose their login forms in raw HTML.
- Email and technology detection are heuristic and may produce false positives or false negatives.
- RDAP and Certificate Transparency results depend on third-party service availability and network access.
- This is not a full penetration-testing suite and does not replace a professional security audit.

## 🧰 Project Structure

```text
CYBERX-SENTINEL-X/
├── assets/
│   └── cyberx-sentinel-banner.svg
├── cyberx_sentinel_x.py
├── requirements.txt
└── README.md
```

## 🤝 Responsible Disclosure

If an assessment reveals a potential issue, stop at verification that is safe and authorized. Document the evidence, avoid accessing or changing other users' data, and report the finding privately to the system owner.

---

<div align="center">

**CYBERX SENTINEL X · Defensive by design**

<sub>Use responsibly. Test only with permission.</sub>

</div>
