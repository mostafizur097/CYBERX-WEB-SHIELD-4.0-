#!/usr/bin/env python3
"""
CYBERX SENTINEL X 1.0
Unified defensive website intelligence and configuration assessment.

AUTHORIZED USE ONLY:
- Assess only domains you own or are explicitly authorized to assess.
- Public, unauthenticated, low-impact GET requests only.
- No exploitation, brute force, credential testing, form submission,
  authentication bypass, directory brute forcing, or private-data access.

Install:
    python -m pip install -r requirements.txt

Run:
    python cyberx_sentinel_x.py
    python cyberx_sentinel_x.py example.com --yes-authorized
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import (
    urljoin, urlparse, urldefrag, urlunparse, parse_qsl, urlencode,
)
from urllib.robotparser import RobotFileParser

import requests
import dns.resolver
from bs4 import BeautifulSoup

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None

APP = "CYBERX SENTINEL X"
VERSION = "1.0"
TIMEOUT = 10
MAX_PAGE_BYTES = 1_000_000
MAX_FILE_BYTES = 200_000
MAX_PAGES = 30
MAX_ADMIN_PATHS = 24
REQUEST_DELAY = 1.0
MAX_REDIRECTS = 4
REPORT_DIR = Path(__file__).resolve().parent / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = f"CyberX-Sentinel-X/{VERSION} (authorized-defensive-assessment)"
SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
)
ADMIN_PATHS = tuple(dict.fromkeys([
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/administrator/login", "/login", "/dashboard",
    "/dashboard/login", "/manage", "/controlpanel",
    "/user/login", "/wp-admin/", "/wp-login.php",
    "/administrator/index.php", "/admin.php", "/account/login",
    "/auth/login", "/panel/login", "/backend/login",
]))
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
SENSITIVE_KEYS = {
    "token", "access_token", "api_key", "apikey", "key", "password",
    "passwd", "secret", "auth", "session", "code", "signature",
}
SESSION = requests.Session()
SESSION.trust_env = False
SESSION.headers.update({
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5",
    "Connection": "close",
})


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def say(message: str = "") -> None:
    if RICH:
        console.print(message)
    else:
        print(message)


def section(title: str) -> None:
    say()
    say(f"[bold cyan]◆ {title}[/bold cyan]" if RICH else f"== {title} ==")


def banner() -> None:
    art = r"""
   _____ __   __ ____  ______  _____  __  __
  / ____|\ \ / /|  _ \|  ____|/ ____||  \/  |
 | |     \ V / | |_) | |__  | (___  | \  / |
 | |      > <  |  _ <|  __|  \___ \ | |\/| |
 | |____ / . \ | |_) | |____ ____) || |  | |
  \_____/_/ \_\|____/|______|_____/ |_|  |_|
"""
    if RICH:
        console.clear()
        console.print(Panel(
            f"[bold bright_cyan]{art}[/bold bright_cyan]\n"
            "[bold white]UNIFIED WEBSITE INTELLIGENCE & DEFENSIVE AUDIT[/bold white]\n"
            f"[cyan]VERSION {VERSION}[/cyan]  [dim]•[/dim] [green]TERMUX FRIENDLY[/green]",
            title="[bold cyan] C Y B E R X   S E N T I N E L   X [/bold cyan]",
            subtitle="[yellow]AUTHORIZED ASSESSMENT ONLY[/yellow]",
            border_style="bright_cyan", box=box.DOUBLE, expand=False,
        ))
    else:
        print(art)
        print(f"{APP} {VERSION} — AUTHORIZED USE ONLY")


def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Target cannot be empty.")
    candidate = raw if "://" in raw else "https://" + raw
    p = urlparse(candidate)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a valid domain or http(s) URL.")
    if p.username or p.password:
        raise ValueError("Credentials in target URLs are not allowed.")
    if p.path not in ("", "/") or p.query or p.fragment:
        raise ValueError("Enter the domain origin only, without path/query.")
    if p.port not in (None, 80, 443):
        raise ValueError("Only standard HTTP/HTTPS ports are allowed.")
    host = p.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        raise ValueError("Enter a public domain name, not an IP address.")
    except ValueError as exc:
        if str(exc).startswith("Enter a public domain"):
            raise
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid international domain name.") from exc
    if len(host) > 253 or "." not in host:
        raise ValueError("Enter a fully qualified domain name.")
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
           for x in labels):
        raise ValueError("Invalid domain format.")
    return host


def in_scope(host: str | None, domain: str) -> bool:
    if not host:
        return False
    h = host.rstrip(".").lower()
    return h in {domain, "www." + domain}


def resolve_public_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed: {exc}") from exc
    ips = sorted({item[4][0].split("%")[0] for item in infos})
    if not ips:
        raise RuntimeError("No IP addresses resolved.")
    for value in ips:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise RuntimeError(f"Blocked non-public destination: {value}")
    return ips


def validate_url(url: str, domain: str) -> str:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise RuntimeError("Only HTTP and HTTPS URLs are allowed.")
    if not in_scope(p.hostname, domain):
        raise RuntimeError("Redirect/link is outside authorized domain scope.")
    if p.username or p.password or p.port not in (None, 80, 443):
        raise RuntimeError("Credentials or non-standard ports are blocked.")
    resolve_public_host(p.hostname or "")
    return url


def safe_url_for_report(url: str) -> str:
    p = urlparse(url)
    pairs = []
    for key, value in parse_qsl(p.query, keep_blank_values=True):
        pairs.append((key, "[REDACTED]" if key.lower() in SENSITIVE_KEYS else value[:160]))
    return urlunparse(p._replace(query=urlencode(pairs)))


def safe_get(url: str, domain: str, max_bytes: int = MAX_PAGE_BYTES):
    """GET with per-hop scope/public-IP checks, no automatic redirects, byte cap."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_url(current, domain)
        response = SESSION.get(
            current, timeout=(5, TIMEOUT), allow_redirects=False, stream=True
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise RuntimeError("Redirect without Location header.")
            current = urljoin(current, location)
            continue
        chunks, size, truncated = [], 0, False
        try:
            for chunk in response.iter_content(8192):
                if not chunk:
                    continue
                remaining = max_bytes - size
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    size = max_bytes
                    truncated = True
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size >= max_bytes:
                    truncated = True
                    break
            body = b"".join(chunks)
            return response, body, truncated
        except Exception:
            response.close()
            raise
    raise RuntimeError("Redirect limit exceeded.")


def dns_lookup(domain: str) -> dict:
    section("DNS INTELLIGENCE")
    result = {}
    for record in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=5)
            values = [str(x).strip('"') for x in answers]
            result[record] = values
            say(f"{record}: " + (" | ".join(values[:12]) if values else "No records"))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            result[record] = []
            say(f"{record}: no record / unavailable")
        except Exception as exc:
            result[record] = {"error": str(exc)[:180]}
            say(f"{record}: lookup error")
    return result


def rdap_lookup(domain: str) -> dict:
    section("DOMAIN REGISTRATION (RDAP)")
    url = f"https://rdap.org/domain/{domain}"
    try:
        response = SESSION.get(url, timeout=TIMEOUT, allow_redirects=False)
        if response.is_redirect:
            return {"error": "RDAP redirect not followed"}
        response.raise_for_status()
        payload = response.json()
        result = {
            "domain": payload.get("ldhName"),
            "status": payload.get("status", []),
            "events": {
                e.get("eventAction", ""): e.get("eventDate", "")
                for e in payload.get("events", []) if e.get("eventAction")
            },
            "nameservers": [
                x.get("ldhName") for x in payload.get("nameservers", [])
                if x.get("ldhName")
            ],
            "source": "Public RDAP data",
        }
        say(json.dumps(result, indent=2, ensure_ascii=False))
        return result
    except Exception as exc:
        return {"error": str(exc)[:250], "source": "RDAP"}


def http_analysis(domain: str) -> dict:
    section("HTTP / HTTPS SECURITY")
    result = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            response, body, truncated = safe_get(url, domain)
            headers = dict(response.headers)
            security = {k: headers.get(k) for k in SECURITY_HEADERS}
            content_type = headers.get("Content-Type", "")
            encoding = response.encoding or "utf-8"
            text_body = body.decode(encoding, errors="replace")
            soup = BeautifulSoup(text_body, "html.parser") if "html" in content_type.lower() else None
            low = text_body.lower()
            tech = []
            server = headers.get("Server", "")
            powered = headers.get("X-Powered-By", "")
            if server:
                tech.append("Server header: " + server[:120])
            if powered:
                tech.append("X-Powered-By: " + powered[:120])
            fingerprints = {
                "WordPress": ("wp-content", "wp-includes"),
                "Drupal": ("drupal.settings", "sites/default/files"),
                "Shopify": ("cdn.shopify.com", "shopify"),
                "Joomla": ('content="joomla', "/media/system/js/"),
                "Next.js": ("_next/static", "__next_data__"),
                "React": ("reactroot", "__react"),
                "Vue.js": ("data-v-", "__vue"),
            }
            for name, markers in fingerprints.items():
                if any(m in low for m in markers):
                    tech.append(name + " (heuristic)")
            # Do not persist Set-Cookie or other potentially secret-bearing headers.
            safe_headers = {
                k: v[:500] for k, v in headers.items()
                if k.lower() not in {"set-cookie", "authorization", "proxy-authorization"}
            }
            result[scheme] = {
                "status_code": response.status_code,
                "requested_url": url,
                "final_url": safe_url_for_report(response.url),
                "content_type": content_type,
                "server": server[:150],
                "headers_redacted": safe_headers,
                "security_headers": security,
                "technology_hints": sorted(set(tech)),
                "body_truncated": truncated,
                "cookies": [
                    {
                        "name": c.name[:100], "secure": bool(c.secure),
                        "httponly": bool(c.has_nonstandard_attr("HttpOnly")),
                        "samesite": c.get_nonstandard_attr("SameSite"),
                    } for c in response.cookies
                ],
                "page_title": soup.title.get_text(" ", strip=True)[:250]
                    if soup and soup.title else None,
            }
            response.close()
            say(f"{scheme.upper()}: HTTP {result[scheme]['status_code']} | "
                f"{content_type or 'unknown content type'}")
            for key, value in security.items():
                say(f"  {key}: {value or 'Not observed'}")
            if tech:
                say("  Technology hints: " + ", ".join(tech))
        except Exception as exc:
            result[scheme] = {"error": str(exc)[:250]}
            say(f"{scheme.upper()}: unavailable — {exc}")
    return result


def tls_analysis(domain: str) -> dict:
    section("TLS CERTIFICATE")
    try:
        ips = resolve_public_host(domain)
        context = ssl.create_default_context()
        with socket.create_connection((ips[0], 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                result = {
                    "connected_ip": ips[0], "tls_version": tls.version(),
                    "cipher": tls.cipher(), "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"), "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_name": cert.get("subjectAltName", []),
                }
                say(f"TLS: {result['tls_version']} | Cipher: {result['cipher']}")
                say(f"Valid until: {result['not_after']}")
                return result
    except Exception as exc:
        say(f"TLS check unavailable: {exc}")
        return {"error": str(exc)[:250]}


def public_files(domain: str) -> dict:
    section("PUBLIC STANDARD FILES")
    result = {}
    for name in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
        url = f"https://{domain}/{name}"
        try:
            response, body, truncated = safe_get(url, domain, MAX_FILE_BYTES)
            result[name] = {
                "status_code": response.status_code,
                "url": safe_url_for_report(response.url),
                "content_type": response.headers.get("Content-Type"),
                "truncated": truncated,
                "preview": body.decode("utf-8", errors="replace")[:3500]
                    if response.status_code == 200 else "",
            }
            say(f"{name}: HTTP {response.status_code}")
            response.close()
        except Exception as exc:
            result[name] = {"error": str(exc)[:200]}
            say(f"{name}: unavailable")
    return result


def passive_subdomains(domain: str) -> dict:
    section("PASSIVE SUBDOMAIN DISCOVERY")
    url = "https://crt.sh/"
    try:
        response = SESSION.get(
            url, params={"q": "%." + domain, "output": "json"},
            timeout=20, allow_redirects=False, stream=True,
        )
        if response.is_redirect:
            response.close()
            return {"error": "CT service redirect not followed"}
        raw = response.raw.read(2_000_000 + 1)
        response.close()
        if len(raw) > 2_000_000:
            return {"error": "CT response exceeded size limit"}
        rows = json.loads(raw.decode("utf-8", errors="replace"))
        found = set()
        for row in rows if isinstance(rows, list) else []:
            for item in row.get("name_value", "").splitlines():
                name = item.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    found.add(name)
        names = sorted(found)
        say(f"Unique certificate-transparency names: {len(names)}")
        for name in names[:60]:
            say(" • " + name)
        return {
            "names": names[:250], "count_returned": len(names),
            "source": "Certificate Transparency via crt.sh",
            "note": "Discovered names are not automatically scanned.",
        }
    except Exception as exc:
        return {"error": str(exc)[:250], "source": url}


def load_robots(domain: str):
    url = f"https://{domain}/robots.txt"
    response, body, _ = safe_get(url, domain, MAX_FILE_BYTES)
    try:
        if response.status_code != 200:
            return None, f"robots.txt returned HTTP {response.status_code}"
        parser = RobotFileParser()
        parser.set_url(url)
        parser.parse(body.decode("utf-8", errors="replace").splitlines())
        return parser, None
    finally:
        response.close()


def crawl_public_site(domain: str, max_pages: int = MAX_PAGES) -> dict:
    section("PUBLIC PAGE INTELLIGENCE & EMAIL DISCOVERY")
    try:
        robots, robots_error = load_robots(domain)
    except Exception as exc:
        robots, robots_error = None, str(exc)
    if robots is None:
        say(f"Crawl safely skipped: robots.txt unavailable ({robots_error})")
        return {"error": "robots.txt unavailable; crawl skipped"}
    queue = deque([f"https://{domain}/"])
    visited, emails, gmail, pages, errors = set(), set(), set(), [], []
    while queue and len(pages) < max_pages:
        url, _ = urldefrag(queue.popleft())
        if url in visited:
            continue
        visited.add(url)
        if not in_scope(urlparse(url).hostname, domain):
            continue
        if not robots.can_fetch(USER_AGENT, url):
            continue
        try:
            response, body, truncated = safe_get(url, domain, MAX_PAGE_BYTES)
            if response.status_code != 200:
                response.close()
                continue
            ctype = response.headers.get("Content-Type", "").lower()
            if "text/html" not in ctype:
                response.close()
                continue
            final_url = response.url
            if not in_scope(urlparse(final_url).hostname, domain):
                response.close()
                continue
            html_text = body.decode(response.encoding or "utf-8", errors="replace")
            soup = BeautifulSoup(html_text, "html.parser")
            for tag in soup(["script", "style", "noscript", "svg"]):
                tag.decompose()
            title = soup.title.get_text(" ", strip=True)[:250] if soup.title else ""
            meta = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
            description = meta.get("content", "")[:400] if meta else ""
            found = set(EMAIL_RE.findall(soup.get_text(" ", strip=True)))
            for link in soup.select('a[href^="mailto:"]'):
                found.update(EMAIL_RE.findall(link.get("href", "").split(":", 1)[-1].split("?", 1)[0]))
            emails.update(found)
            gmail.update(x.lower() for x in found if x.lower().endswith("@gmail.com"))
            links = set()
            for anchor in soup.find_all("a", href=True):
                target, _ = urldefrag(urljoin(final_url, anchor["href"]))
                parsed = urlparse(target)
                if parsed.scheme in ("http", "https") and in_scope(parsed.hostname, domain):
                    if not parsed.query and not re.search(
                        r"/(logout|delete|remove|unsubscribe)(/|$)", parsed.path, re.I
                    ):
                        links.add(target)
            for target in sorted(links):
                if target not in visited and len(queue) < max_pages * 4:
                    queue.append(target)
            pages.append({
                "url": safe_url_for_report(final_url),
                "status_code": response.status_code,
                "title": title, "meta_description": description,
                "internal_links_count": len(links),
                "public_emails_found": sorted(found),
                "body_truncated": truncated,
            })
            response.close()
            say(f"Scanned {len(pages)}/{max_pages}: {urlparse(final_url).path or '/'}")
            time.sleep(REQUEST_DELAY)
        except Exception as exc:
            errors.append({"url": safe_url_for_report(url), "error": str(exc)[:200]})
            time.sleep(REQUEST_DELAY)
    result = {
        "pages_scanned": len(pages), "max_pages": max_pages, "pages": pages,
        "public_email_count": len(emails), "gmail_count": len(gmail),
        "public_emails": sorted(emails), "gmail_addresses": sorted(gmail),
        "crawl_errors": errors, "robots_txt_retrieved": True,
        "note": "Only publicly displayed addresses were collected; not proof of account ownership.",
    }
    say(f"Pages: {len(pages)} | Public emails: {len(emails)} | Gmail: {len(gmail)}")
    return result


def page_signals(body: str):
    soup = BeautifulSoup(body, "html.parser")
    title = soup.title.get_text(" ", strip=True)[:120] if soup.title else ""
    password = bool(soup.find("input", attrs={"type": re.compile("^password$", re.I)}))
    form = bool(soup.find("form"))
    text = soup.get_text(" ", strip=True).lower()
    hits = [word for word in ("admin login", "administrator", "dashboard",
                               "sign in", "log in", "login", "wordpress")
            if word in text]
    return title, password, form, hits


def admin_path_discovery(domain: str) -> dict:
    section("ADMIN LOGIN PATH DISCOVERY")
    results = []
    for index, path in enumerate(ADMIN_PATHS[:MAX_ADMIN_PATHS], 1):
        url = f"https://{domain}{path}"
        try:
            response, body, truncated = safe_get(url, domain, MAX_FILE_BYTES)
            status = response.status_code
            final_url = response.url
            content_type = response.headers.get("Content-Type", "")
            text_body = body.decode(response.encoding or "utf-8", errors="replace")
            title, has_password, has_form, hits = page_signals(text_body) if (
                "html" in content_type.lower() or body.lstrip().startswith(b"<")
            ) else ("", False, False, [])
            if status in (404, 410):
                label, reason = "NOT FOUND", "Server reports page missing"
            elif status in (401, 403):
                label, reason = "RESTRICTED", "Access restricted; not a confirmed exposed login"
            elif 300 <= status < 400:
                label, reason = "REDIRECT", "Redirect response"
            elif has_password and has_form:
                label, reason = "POSSIBLE LOGIN", "Password input and form detected"
            elif has_form and any(x in text_body.lower() for x in ("username", "email", "sign in", "login")):
                label, reason = "POSSIBLE LOGIN", "Login-related form signals detected"
            elif status == 200 and any(x in urlparse(final_url).path.lower()
                                       for x in ("admin", "login", "dashboard", "wp-admin")):
                label, reason = "REVIEW", "Path returned HTTP 200; manually verify"
            elif status == 200:
                label, reason = "HTTP 200", "Page exists; login not confirmed"
            else:
                label, reason = "OTHER", "Manual review required"
            record = {
                "path": path, "url": url, "status": status,
                "final_url": safe_url_for_report(final_url),
                "classification": label, "reason": reason, "title": title,
                "password_field_detected": has_password,
                "form_detected": has_form, "keyword_signals": hits,
                "content_type": content_type, "body_truncated": truncated,
            }
            response.close()
        except Exception as exc:
            record = {
                "path": path, "url": url, "status": None,
                "classification": "ERROR", "reason": str(exc)[:180],
            }
        results.append(record)
        say(f"[{index:02d}/{min(len(ADMIN_PATHS), MAX_ADMIN_PATHS)}] "
            f"{record.get('status') or 'ERR'}  {record['classification']:<14} {path}")
        if index < min(len(ADMIN_PATHS), MAX_ADMIN_PATHS):
            time.sleep(REQUEST_DELAY)
    return {
        "paths_checked": len(results),
        "possible_login_pages": sum(x["classification"] == "POSSIBLE LOGIN" for x in results),
        "manual_review": sum(x["classification"] == "REVIEW" for x in results),
        "results": results,
        "note": "A matching path is not proof of a vulnerability or unauthorized exposure.",
    }


def security_summary(data: dict) -> dict:
    observations = []
    https = data.get("http", {}).get("https", {})
    headers = https.get("security_headers", {}) if isinstance(https, dict) else {}
    for header in SECURITY_HEADERS:
        if not headers.get(header):
            observations.append({
                "type": "header_not_observed", "header": header,
                "severity": "informational",
                "note": "Not observed on sampled HTTPS response; assess applicability manually.",
            })
    tls = data.get("tls", {})
    if isinstance(tls, dict) and tls.get("error"):
        observations.append({
            "type": "tls_check_unavailable", "severity": "informational",
            "note": "TLS details could not be collected.",
        })
    return {
        "observations": observations,
        "note": "Observations are not proof of a vulnerability or exploitability.",
    }


def run_full(domain: str, data: dict) -> None:
    modules = [
        ("dns", dns_lookup), ("rdap", rdap_lookup),
        ("http", http_analysis), ("tls", tls_analysis),
        ("public_files", public_files), ("passive_subdomains", passive_subdomains),
        ("admin_discovery", admin_path_discovery),
        ("public_crawl", crawl_public_site),
    ]
    for key, function in modules:
        try:
            data[key] = function(domain)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            data[key] = {"error": str(exc)[:250]}
            say(f"{key}: module failed — {exc}")
    data["security_summary"] = security_summary(data)


def save_reports(domain: str, data: dict) -> tuple[Path, Path, Path]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    host = re.sub(r"[^a-zA-Z0-9_-]", "_", domain)
    token = uuid.uuid4().hex[:6]
    stem = f"{host}_{stamp}_{token}"
    data["report_generated_at_utc"] = now_utc()
    json_path = REPORT_DIR / f"{stem}.json"
    txt_path = REPORT_DIR / f"{stem}.txt"
    html_path = REPORT_DIR / f"{stem}.html"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    lines = [
        f"{APP} {VERSION}", "=" * 64,
        f"Target: {domain}", f"Generated UTC: {data['report_generated_at_utc']}",
        "Scope: public unauthenticated metadata and low-impact GET checks",
        "", "MODULE SUMMARY", "-" * 64,
    ]
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}: " + ("ERROR" if "error" in value else "collected"))
    crawl = data.get("public_crawl", {})
    lines += ["", "PUBLIC EMAILS", "-" * 64]
    if isinstance(crawl, dict):
        lines.extend(crawl.get("public_emails", []))
    lines += ["", "ADMIN PATH FINDINGS", "-" * 64]
    for item in data.get("admin_discovery", {}).get("results", []):
        lines.append(f"{item.get('status')} | {item.get('classification')} | {item.get('path')}")
    lines += ["", "LIMITATIONS",
              "A discovered path or missing header is not automatically a vulnerability.",
              "No authentication, exploitation, brute force or form submission was performed."]
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    # Self-contained HTML report; all dynamic content is escaped by JSON serialization.
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html_doc = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CYBERX SENTINEL X Report</title>
<style>
:root{color-scheme:dark}body{margin:0;background:#08111f;color:#e8f1ff;font:15px system-ui}
main{max-width:1050px;margin:36px auto;padding:24px}header,.card{background:#101e32;border:1px solid #203958;border-radius:14px;padding:20px;margin:14px 0}
h1{color:#55d8ff;margin:0}h2{color:#8ce8ff;font-size:18px}pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#c8d8ec}
small{color:#91a9c4}.notice{color:#ffd580}
</style></head><body><main><header><h1>CYBERX SENTINEL X</h1>
<p>Website intelligence & defensive assessment report</p>
<small>Generated report • Authorized assessments only</small></header>
<div class="card"><h2>Assessment Data</h2><pre id="data"></pre></div>
<p class="notice">Observations are not proof of vulnerability. Verify findings manually.</p>
</main><script>const data = """ + payload + """;
document.getElementById('data').textContent=JSON.stringify(data,null,2);</script></body></html>"""
    html_path.write_text(html_doc, encoding="utf-8")
    say(f"JSON report: {json_path}")
    say(f"TXT report:  {txt_path}")
    say(f"HTML report: {html_path}")
    return json_path, txt_path, html_path


def usage_rules() -> None:
    section("USAGE RULES & LIMITATIONS")
    rules = [
        "Only assess domains you own or have explicit written permission to assess.",
        "The tool collects public unauthenticated metadata only.",
        "The crawler obeys robots.txt and uses a page limit and request delay.",
        "Admin discovery checks a short list of common paths using GET only.",
        "No login attempts, brute force, exploitation, bypass or form submission.",
        "A 403 response is not proof of a vulnerability.",
        "A missing security header is not automatically a vulnerability.",
        "Public email discovery is not permission for spam or unsolicited outreach.",
        "Subdomains from certificate transparency are not automatically scanned.",
        "Stop if the owner, provider or applicable policy requests it.",
    ]
    for i, rule in enumerate(rules, 1):
        say(f"{i:02d}. {rule}")


def menu(domain: str, data: dict) -> None:
    options = {
        "1": ("Full assessment", lambda: run_full(domain, data)),
        "2": ("DNS intelligence", lambda: data.update(dns=dns_lookup(domain))),
        "3": ("RDAP lookup", lambda: data.update(rdap=rdap_lookup(domain))),
        "4": ("HTTP/HTTPS audit", lambda: data.update(http=http_analysis(domain))),
        "5": ("TLS certificate", lambda: data.update(tls=tls_analysis(domain))),
        "6": ("Public standard files", lambda: data.update(public_files=public_files(domain))),
        "7": ("Passive subdomains", lambda: data.update(passive_subdomains=passive_subdomains(domain))),
        "8": ("Public crawler & email discovery", lambda: data.update(public_crawl=crawl_public_site(domain))),
        "9": ("Admin login path discovery", lambda: data.update(admin_discovery=admin_path_discovery(domain))),
        "10": ("Save JSON/TXT/HTML reports", lambda: save_reports(domain, data)),
        "11": ("Usage rules", usage_rules),
    }
    while True:
        section(f"MAIN MENU — {domain}")
        for key, (label, _) in options.items():
            say(f"[{key}] {label}")
        say("[0] Exit")
        try:
            choice = input("Select module: ").strip()
            if choice == "0":
                break
            if choice not in options:
                say("Invalid selection.")
                continue
            options[choice][1]()
        except KeyboardInterrupt:
            say("\nModule stopped by user.")
        except Exception as exc:
            say(f"Module error: {str(exc)[:250]}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unified defensive website intelligence and configuration assessment."
    )
    parser.add_argument("domain", nargs="?", help="Domain you own or are authorized to assess")
    parser.add_argument("--yes-authorized", action="store_true",
                        help="Confirm authorization non-interactively")
    parser.add_argument("--full", action="store_true", help="Run full assessment and save reports")
    args = parser.parse_args()
    banner()
    try:
        raw = args.domain or input("Target domain: ").strip()
        domain = normalize_domain(raw)
        ips = resolve_public_host(domain)
    except (ValueError, RuntimeError) as exc:
        say(f"Target rejected: {exc}")
        return 2
    say(f"Target: {domain}")
    say(f"Resolved public IP(s): {', '.join(ips)}")
    say("Use only a domain you own or have explicit permission to assess.")
    authorized = args.yes_authorized
    if not authorized:
        answer = input("Do you have authorization? Type YES: ").strip()
        authorized = answer == "YES"
    if not authorized:
        say("Authorization not confirmed. Exiting.")
        return 2
    data = {
        "tool": APP, "version": VERSION, "target": domain,
        "started_at_utc": now_utc(),
        "authorization_confirmed_by_operator": True,
        "scope": "Public unauthenticated website information; low-impact GET only",
    }
    try:
        if args.full:
            run_full(domain, data)
            save_reports(domain, data)
        else:
            menu(domain, data)
    finally:
        SESSION.close()
    say("CYBERX SENTINEL X session closed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        say("\nStopped by user.")
