#!/usr/bin/env python3
"""
CYBERX WEB SHIELD 4.0
Defensive public website intelligence and configuration assessment.

AUTHORIZED USE ONLY:
- Assess domains you own or are explicitly authorized to assess.
- Collects only publicly accessible website metadata and configuration.
- Does not exploit vulnerabilities, bypass authentication, submit forms,
  brute-force credentials, evade access controls, or access private data.

Install:
    python -m pip install requests beautifulsoup4 dnspython rich

Run:
    python cyberx_web_shield.py
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, quote

import requests
import dns.resolver
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

APP = "CYBERX WEB SHIELD"
VERSION = "4.0"
TIMEOUT = 12
MAX_PAGES = 40
MAX_PAGE_BYTES = 1_500_000
MAX_FILE_BYTES = 250_000
REQUEST_DELAY = 1.2
MAX_REDIRECTS = 5
REPORT_DIR = Path(__file__).resolve().parent / "reports"
REPORT_DIR.mkdir(exist_ok=True)

console = Console()
SESSION = requests.Session()
SESSION.trust_env = False
SESSION.headers.update({
    "User-Agent": f"CyberX-WebShield/{VERSION} (authorized defensive assessment)"
})

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
SENSITIVE_QUERY_KEYS = {
    "token", "access_token", "api_key", "apikey", "key",
    "password", "passwd", "secret", "auth", "session"
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def banner() -> None:
    """Render a modern terminal banner with a compact ASCII shield logo."""
    console.clear()

    logo = (
        "[bold bright_cyan]   _____ __   __ ____  ______  _____  __  __[/bold bright_cyan]\n"
        "[bold cyan]  / ____|\\ \\ / /|  _ \\|  ____|/ ____||  \\/  |[/bold cyan]\n"
        "[bold bright_blue] | |     \\ V / | |_) | |__  | (___  | \\  / |[/bold bright_blue]\n"
        "[bold blue] | |      > <  |  _ <|  __|  \\___ \\ | |\\/| |[/bold blue]\n"
        "[bold bright_cyan] | |____ / . \\ | |_) | |____ ____) || |  | |[/bold bright_cyan]\n"
        "[bold cyan]  \\_____/_/ \\_\\|____/|______|_____/ |_|  |_|[/bold cyan]"
    )

    subtitle = (
        "[bold white]WEB SHIELD[/bold white]  "
        "[bright_cyan]◆[/bright_cyan]  "
        "[bright_blue]PUBLIC WEBSITE INTELLIGENCE[/bright_blue]\n"
        "[dim]Defensive Security Assessment • OSINT • Configuration Audit[/dim]"
    )

    console.print(Panel(
        f"{logo}\n\n{subtitle}\n"
        f"[bold bright_white]VERSION {VERSION}[/bold bright_white]  "
        "[dim]│[/dim] [green]TERMUX READY[/green]  "
        "[dim]│[/dim] [cyan]PYTHON[/cyan]",
        title="[bold bright_cyan] C Y B E R X [/bold bright_cyan]",
        subtitle="[dim]AUTHORIZED ASSESSMENT ONLY[/dim]",
        border_style="bright_cyan",
        box=box.DOUBLE,
        padding=(1, 3),
        expand=False
    ))

    console.print(
        Panel(
            "[bold yellow]⚠ SAFE USE NOTICE[/bold yellow]\n"
            "Assess only websites you own or have explicit permission to test.\n"
            "[dim]Public metadata and low-impact checks only — no exploitation or login bypass.[/dim]",
            border_style="yellow",
            box=box.ROUNDED,
            padding=(0, 2)
        )
    )


def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("No domain entered.")
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not accepted.")
    host = (parsed.hostname or "").strip(".").lower()
    if not host:
        raise ValueError("Could not read a hostname.")
    try:
        ipaddress.ip_address(host)
        raise ValueError("Enter a public domain name, not an IP address.")
    except ValueError as exc:
        if "Enter a public domain" in str(exc):
            raise
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid international domain name.") from exc
    if len(host) > 253 or "." not in host:
        raise ValueError("Enter a valid fully-qualified domain name.")
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("Invalid domain format.")
    return host


def host_in_scope(host: str | None, domain: str) -> bool:
    if not host:
        return False
    host = host.lower().rstrip(".")
    return host == domain or host == "www." + domain


def resolve_public_host(host: str) -> list[str]:
    """Resolve host and reject any non-global destination before HTTP requests."""
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for {host}: {exc}") from exc
    ips = sorted({item[4][0] for item in answers})
    if not ips:
        raise RuntimeError(f"No IP addresses returned for {host}")
    for value in ips:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise RuntimeError(f"Blocked non-public IP destination: {value}")
    return ips


def safe_url(url: str, domain: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError("Only HTTP and HTTPS URLs are allowed.")
    if not host_in_scope(parsed.hostname, domain):
        raise RuntimeError("URL is outside the authorized domain scope.")
    if parsed.port not in (None, 80, 443):
        raise RuntimeError("Non-standard ports are not included in this assessment.")
    if parsed.username or parsed.password:
        raise RuntimeError("Credentials in URLs are not accepted.")
    resolve_public_host(parsed.hostname or "")
    return url


def safe_get(url: str, domain: str, max_bytes: int = MAX_FILE_BYTES,
             stream: bool = True) -> tuple[requests.Response, bytes]:
    """GET with manual redirect validation, scope checks and response size cap."""
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        safe_url(current, domain)
        response = SESSION.get(
            current, timeout=TIMEOUT, allow_redirects=False, stream=True
        )
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise RuntimeError("Redirect response had no Location header.")
            current = urljoin(current, location)
            continue
        chunks = []
        size = 0
        try:
            for chunk in response.iter_content(8192):
                if not chunk:
                    continue
                size += len(chunk)
                if size > max_bytes:
                    response.close()
                    raise RuntimeError(f"Response exceeded {max_bytes} byte limit.")
                chunks.append(chunk)
        except Exception:
            response.close()
            raise
        body = b"".join(chunks)
        return response, body
    raise RuntimeError("Too many redirects.")


def section(title: str) -> None:
    console.print(f"\n[bold bright_cyan]◆ {title}[/bold bright_cyan]")


def dns_lookup(domain: str) -> dict:
    section("DNS INTELLIGENCE")
    result = {}
    for record in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=6)
            values = [str(x).strip('"') for x in answers]
            result[record] = values
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_row(f"[bold]{record}[/bold]", "\n".join(values[:15]))
            console.print(table)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            result[record] = []
            console.print(f"[dim]{record}: no record / lookup unavailable[/dim]")
        except Exception as exc:
            result[record] = {"lookup_error": str(exc)[:250]}
            console.print(f"[yellow]{record}: lookup unavailable[/yellow]")
    return result


def rdap_lookup(domain: str) -> dict:
    section("DOMAIN REGISTRATION (RDAP)")
    url = f"https://rdap.org/domain/{quote(domain, safe='.-')}"
    try:
        response = SESSION.get(url, timeout=TIMEOUT, allow_redirects=False)
        if response.is_redirect:
            return {"error": "RDAP redirect not followed by this module."}
        response.raise_for_status()
        payload = response.json()
        events = {
            e.get("eventAction", ""): e.get("eventDate", "")
            for e in payload.get("events", []) if e.get("eventAction")
        }
        result = {
            "ldhName": payload.get("ldhName"),
            "status": payload.get("status", []),
            "events": events,
            "nameservers": [
                x.get("ldhName") for x in payload.get("nameservers", [])
                if x.get("ldhName")
            ],
            "entities_roles": [
                {"roles": x.get("roles", [])}
                for x in payload.get("entities", []) if x.get("roles")
            ],
            "source": "Public RDAP registry data"
        }
        table = Table(box=box.SIMPLE)
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Domain", str(result["ldhName"]))
        table.add_row("Status", ", ".join(result["status"]) or "Not disclosed")
        for key, value in events.items():
            table.add_row(key, value)
        table.add_row("Nameservers", ", ".join(result["nameservers"]) or "Not disclosed")
        console.print(table)
        console.print("[dim]Registrant contact details may be redacted by the registry.[/dim]")
        return result
    except Exception as exc:
        console.print(f"[yellow]RDAP unavailable: {exc}[/yellow]")
        return {"error": str(exc)[:300], "source": url}


def http_analysis(domain: str) -> dict:
    section("HTTP / HTTPS SECURITY")
    result = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            response, body = safe_get(url, domain, max_bytes=MAX_PAGE_BYTES)
            headers = dict(response.headers)
            security = {name: headers.get(name) for name in SECURITY_HEADERS}
            final_url = response.url
            status = response.status_code
            content_type = headers.get("Content-Type", "")
            server = headers.get("Server", "Not disclosed")
            powered = headers.get("X-Powered-By")
            soup = BeautifulSoup(body, "html.parser") if "html" in content_type.lower() else None
            html = body.decode(response.encoding or "utf-8", errors="ignore").lower()
            tech = []
            if server != "Not disclosed":
                tech.append("Server header: " + server[:150])
            if powered:
                tech.append("X-Powered-By: " + powered[:150])
            fingerprints = {
                "WordPress": ["wp-content", "wp-includes"],
                "Drupal": ["drupal.settings", "sites/default/files"],
                "Shopify": ["cdn.shopify.com", "shopify"],
                "Joomla": ['content="joomla', "/media/system/js/"],
                "Laravel": ["laravel_session"],
                "Next.js": ["_next/static", "__next_data__"],
                "React": ["reactroot", "__react"],
                "Vue.js": ["data-v-", "__vue"]
            }
            for name, markers in fingerprints.items():
                if any(marker in html for marker in markers):
                    tech.append(name + " (heuristic)")
            result[scheme] = {
                "status_code": status,
                "requested_url": url,
                "final_url": final_url,
                "headers": headers,
                "security_headers": security,
                "technology_hints": sorted(set(tech)),
                "cookies": [
                    {
                        "name": c.name,
                        "secure": bool(c.secure),
                        "httponly": bool(c.has_nonstandard_attr("HttpOnly")),
                        "samesite": c.get_nonstandard_attr("SameSite")
                    } for c in response.cookies
                ],
                "page_title": soup.title.get_text(" ", strip=True)[:300]
                    if soup and soup.title else None
            }
            response.close()
            table = Table(box=box.SIMPLE)
            table.add_column("Security Header")
            table.add_column("Observation")
            for name, value in security.items():
                table.add_row(name, (str(value)[:90] if value else "[yellow]Not observed[/yellow]"))
            console.print(Panel(
                f"Requested: {url}\nFinal URL: {final_url}\n"
                f"Status: {status}\nServer: {server}\nContent-Type: {content_type}",
                title=f"{scheme.upper()} RESPONSE",
                border_style="green" if 200 <= status < 400 else "yellow"
            ))
            console.print(table)
            if tech:
                console.print("[cyan]Technology hints:[/cyan] " + ", ".join(tech))
        except Exception as exc:
            result[scheme] = {"error": str(exc)[:300]}
            console.print(f"[yellow]{scheme.upper()} unavailable: {exc}[/yellow]")
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
                    "connected_ip": ips[0],
                    "tls_version": tls.version(),
                    "cipher": tls.cipher(),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "subject_alt_name": cert.get("subjectAltName", [])
                }
                console.print(Panel(
                    f"TLS: {result['tls_version']}\nCipher: {result['cipher']}\n"
                    f"Issuer: {result['issuer']}\nValid from: {result['not_before']}\n"
                    f"Expires: {result['not_after']}",
                    title="CERTIFICATE DETAILS", border_style="green"
                ))
                return result
    except Exception as exc:
        console.print(f"[yellow]TLS check unavailable: {exc}[/yellow]")
        return {"error": str(exc)[:300]}


def public_files(domain: str) -> dict:
    section("PUBLIC WEBSITE FILES")
    result = {}
    for name in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
        url = f"https://{domain}/{name}"
        try:
            response, body = safe_get(url, domain, max_bytes=MAX_FILE_BYTES)
            item = {
                "status_code": response.status_code,
                "url": response.url,
                "content_type": response.headers.get("Content-Type"),
                "content_preview": body.decode("utf-8", errors="replace")[:5000]
                    if response.status_code == 200 else ""
            }
            result[name] = item
            console.print(f"{name}: [green]{response.status_code}[/green] — {response.url}")
            response.close()
        except Exception as exc:
            result[name] = {"error": str(exc)[:250]}
            console.print(f"{name}: [yellow]unavailable[/yellow]")
    return result


def passive_subdomains(domain: str) -> dict:
    section("PASSIVE SUBDOMAIN DISCOVERY")
    url = "https://crt.sh/"
    try:
        response = SESSION.get(
            url, params={"q": "%." + domain, "output": "json"},
            timeout=20, allow_redirects=False
        )
        response.raise_for_status()
        found = set()
        for row in response.json():
            for item in row.get("name_value", "").splitlines():
                name = item.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    found.add(name)
        names = sorted(found)
        for name in names[:80]:
            console.print(" • " + name)
        console.print(f"[bold]Unique names returned: {len(names)}[/bold]")
        return {
            "names": names[:300], "count_returned": len(names),
            "source": "crt.sh Certificate Transparency"
        }
    except Exception as exc:
        console.print(f"[yellow]Passive lookup unavailable: {exc}[/yellow]")
        return {"error": str(exc)[:300], "source": url}


def robots_parser(domain: str) -> tuple[RobotFileParser | None, str | None]:
    url = f"https://{domain}/robots.txt"
    try:
        response, body = safe_get(url, domain, max_bytes=MAX_FILE_BYTES)
        text = body.decode("utf-8", errors="replace")
        response.close()
        rp = RobotFileParser()
        rp.set_url(url)
        rp.parse(text.splitlines())
        return rp, text
    except Exception as exc:
        return None, str(exc)


def sanitize_url_for_report(url: str) -> str:
    """Avoid writing likely secret-bearing query parameters into reports."""
    p = urlparse(url)
    if not p.query:
        return url
    safe_pairs = []
    for part in p.query.split("&"):
        key = part.split("=", 1)[0]
        if key.lower() in SENSITIVE_QUERY_KEYS:
            safe_pairs.append(key + "=[REDACTED]")
        else:
            safe_pairs.append(part[:200])
    return p._replace(query="&".join(safe_pairs)).geturl()


def crawl_public_site(domain: str, max_pages: int = MAX_PAGES) -> dict:
    section("PUBLIC PAGE INTELLIGENCE & EMAIL DISCOVERY")
    rp, robots_text = robots_parser(domain)
    if rp is None:
        console.print(f"[yellow]Cannot verify robots.txt: {robots_text}[/yellow]")
        console.print("[yellow]Crawl skipped safely.[/yellow]")
        return {"error": "robots.txt unavailable; crawl skipped"}

    start_urls = [f"https://{domain}/", f"https://www.{domain}/"]
    queue = deque(start_urls)
    visited = set()
    emails = set()
    gmail = set()
    pages = []
    errors = []

    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console
    ) as progress:
        task = progress.add_task("Scanning public pages...", total=max_pages)
        while queue and len(pages) < max_pages:
            url = queue.popleft()
            url, _ = urldefrag(url)
            if url in visited:
                continue
            visited.add(url)
            parsed = urlparse(url)
            if not host_in_scope(parsed.hostname, domain):
                continue
            if not rp.can_fetch(SESSION.headers["User-Agent"], url):
                continue
            try:
                response, body = safe_get(url, domain, max_bytes=MAX_PAGE_BYTES)
                if response.status_code != 200:
                    response.close()
                    continue
                ctype = response.headers.get("Content-Type", "").lower()
                if "text/html" not in ctype:
                    response.close()
                    continue
                final_url = response.url
                if not host_in_scope(urlparse(final_url).hostname, domain):
                    response.close()
                    continue
                html = body.decode(response.encoding or "utf-8", errors="replace")
                soup = BeautifulSoup(html, "html.parser")
                for tag in soup(["script", "style", "noscript", "svg"]):
                    tag.decompose()
                title = soup.title.get_text(" ", strip=True)[:300] if soup.title else ""
                description_tag = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
                description = description_tag.get("content", "")[:500] if description_tag else ""
                canonical_tag = soup.find("link", rel=lambda x: x and "canonical" in x)
                canonical = canonical_tag.get("href") if canonical_tag else None
                page_text = soup.get_text(" ", strip=True)
                found = set(EMAIL_RE.findall(page_text))
                for link in soup.select('a[href^="mailto:"]'):
                    mail = link.get("href", "").split(":", 1)[-1].split("?", 1)[0]
                    found.update(EMAIL_RE.findall(mail))
                emails.update(found)
                gmail.update(x.lower() for x in found if x.lower().endswith("@gmail.com"))

                links = []
                for a in soup.find_all("a", href=True):
                    target = urljoin(final_url, a["href"])
                    target, _ = urldefrag(target)
                    tp = urlparse(target)
                    if tp.scheme in ("http", "https") and host_in_scope(tp.hostname, domain):
                        # Avoid query-string variants and likely logout/action URLs.
                        if not tp.query and not re.search(r"/(logout|delete|remove|unsubscribe)(/|$)", tp.path, re.I):
                            links.append(target)
                            if target not in visited and len(queue) < max_pages * 5:
                                queue.append(target)

                forms = []
                for form in soup.find_all("form"):
                    # Metadata only: never submit forms or collect entered values.
                    forms.append({
                        "method": (form.get("method") or "get").upper(),
                        "action_path": urlparse(urljoin(final_url, form.get("action", ""))).path[:200],
                        "field_names": [
                            x.get("name") for x in form.find_all(["input", "select", "textarea"])
                            if x.get("name")
                        ][:40]
                    })

                pages.append({
                    "url": sanitize_url_for_report(final_url),
                    "status_code": response.status_code,
                    "title": title,
                    "meta_description": description,
                    "canonical": canonical,
                    "content_type": ctype,
                    "internal_links_count": len(set(links)),
                    "forms_metadata": forms[:20],
                    "public_emails_found": sorted(found)
                })
                response.close()
                progress.update(task, advance=1, description=f"Scanned {len(pages)}/{max_pages} pages")
                time.sleep(REQUEST_DELAY)
            except Exception as exc:
                errors.append({"url": sanitize_url_for_report(url), "error": str(exc)[:250]})
                progress.update(task, description=f"Errors {len(errors)} | scanned {len(pages)}")
                time.sleep(REQUEST_DELAY)

    result = {
        "pages_scanned": len(pages),
        "max_pages": max_pages,
        "pages": pages,
        "public_email_count": len(emails),
        "gmail_count": len(gmail),
        "public_emails": sorted(emails),
        "gmail_addresses": sorted(gmail),
        "crawl_errors": errors,
        "robots_txt_retrieved": bool(robots_text)
    }
    table = Table(box=box.SIMPLE)
    table.add_column("Metric")
    table.add_column("Count")
    table.add_row("Pages scanned", str(len(pages)))
    table.add_row("Public emails", str(len(emails)))
    table.add_row("Public Gmail addresses", str(len(gmail)))
    table.add_row("Crawl errors", str(len(errors)))
    console.print(table)
    if emails:
        console.print(Panel("\n".join(sorted(emails)), title="PUBLIC EMAILS", border_style="bright_cyan"))
    return result


def security_summary(data: dict) -> dict:
    observations = []
    http = data.get("http", {})
    https = http.get("https", {}) if isinstance(http, dict) else {}
    headers = https.get("security_headers", {}) if isinstance(https, dict) else {}
    for header in SECURITY_HEADERS:
        if not headers.get(header):
            observations.append({
                "type": "header_not_observed",
                "header": header,
                "severity": "informational",
                "note": "Header was not observed in the sampled HTTPS response; assess applicability manually."
            })
    tls = data.get("tls", {})
    if isinstance(tls, dict) and tls.get("error"):
        observations.append({
            "type": "tls_check_unavailable", "severity": "informational",
            "note": "TLS details could not be collected."
        })
    return {
        "observations": observations,
        "note": "These are configuration observations, not proof of a vulnerability or exploitability."
    }


def save_report(domain: str, data: dict) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", domain)
    path = REPORT_DIR / f"{safe}_{stamp}.json"
    data["report_saved_at"] = utc_now()
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8"
    )
    console.print(Panel(f"[bold green]JSON report saved[/bold green]\n{path}", border_style="green"))
    return path


def save_text_report(domain: str, data: dict) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", domain)
    path = REPORT_DIR / f"{safe}_{stamp}.txt"
    lines = [
        f"{APP} {VERSION}", "=" * 60,
        f"Target: {domain}",
        f"Started: {data.get('started_at', '')}",
        f"Generated: {utc_now()}",
        "",
        "MODULES INCLUDED",
        ", ".join(k for k in data if k not in {
            "tool", "version", "target", "started_at",
            "authorization_confirmed_by_operator", "report_saved_at"
        }),
        "",
        "PUBLIC EMAILS",
        "-" * 30,
    ]
    crawl = data.get("public_crawl", {})
    for email in crawl.get("public_emails", []) if isinstance(crawl, dict) else []:
        lines.append(email)
    lines += ["", "ASSESSMENT NOTE",
              "Findings are public observations, not proof of vulnerability.",
              "No authentication bypass, exploitation, or form submission was performed."]
    path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]TXT report saved:[/green] {path}")
    return path


def run_full(domain: str, data: dict) -> None:
    data["dns"] = dns_lookup(domain)
    data["rdap"] = rdap_lookup(domain)
    data["http"] = http_analysis(domain)
    data["tls"] = tls_analysis(domain)
    data["public_files"] = public_files(domain)
    data["passive_subdomains"] = passive_subdomains(domain)
    data["public_crawl"] = crawl_public_site(domain)
    data["security_summary"] = security_summary(data)


def usage_rules() -> None:
    section("USAGE RULES & LIMITATIONS")
    rules = [
        "Use only domains you own or have explicit written permission to assess.",
        "Only publicly accessible DNS, registry, HTTP, TLS and page metadata are collected.",
        "The crawler obeys robots.txt and scans a limited number of pages with delays.",
        "No login, authentication bypass, vulnerability exploitation, brute force or form submission.",
        "No private databases, private files, hidden accounts or non-public personal information are accessed.",
        "Subdomain discovery from Certificate Transparency is passive; discovered names are not automatically tested.",
        "A missing security header is an observation, not automatically a vulnerability.",
        "Website content may change; reports are point-in-time observations and may contain false positives.",
        "Do not use collected contact details for spam, harassment, profiling or unauthorized outreach.",
        "Stop immediately if the site owner, provider or applicable policy requests that testing stop."
    ]
    for i, rule in enumerate(rules, 1):
        console.print(f"[cyan]{i:02d}.[/cyan] {rule}")
    console.print(
        "\n[dim]Scope limitation: no tool can collect literally all website information. "
        "This tool deliberately excludes private, authenticated, restricted and exploit-only data.[/dim]"
    )


def main() -> None:
    banner()
    console.print("Collects public website configuration, page metadata and publicly displayed email addresses.")
    try:
        domain = normalize_domain(Prompt.ask("\n[bold cyan]Target domain[/bold cyan]"))
        ips = resolve_public_host(domain)
    except (ValueError, RuntimeError) as exc:
        console.print(f"[red]Input / safety error: {exc}[/red]")
        return

    console.print(f"\n[bold]Target:[/bold] [bright_cyan]{domain}[/bright_cyan]")
    console.print(f"[bold]Resolved public IP(s):[/bold] {', '.join(ips)}")
    console.print("[yellow]Only continue if you own this domain or have explicit permission.[/yellow]")
    if not Confirm.ask("Do you have authorization?", default=False):
        console.print("[red]Stopped: authorization not confirmed.[/red]")
        return

    data = {
        "tool": APP,
        "version": VERSION,
        "target": domain,
        "started_at": utc_now(),
        "authorization_confirmed_by_operator": True,
        "scope": "Public unauthenticated website information only"
    }

    while True:
        console.print(Panel(
            "[1] Full assessment (DNS + RDAP + HTTP + TLS + files + subdomains + crawl)\n"
            "[2] DNS records\n"
            "[3] RDAP registration information\n"
            "[4] HTTP headers & technology hints\n"
            "[5] TLS certificate\n"
            "[6] robots.txt / sitemap / security.txt\n"
            "[7] Passive subdomain discovery (CT logs)\n"
            "[8] Public page metadata & email discovery\n"
            "[9] Save JSON report\n"
            "[10] Save TXT summary\n"
            "[11] Usage rules & limitations\n"
            "[0] Exit",
            title=f"[bold bright_cyan]{APP} MENU[/bold bright_cyan]",
            border_style="bright_blue"
        ))
        choice = Prompt.ask(
            "Select module",
            choices=[str(x) for x in range(0, 12)],
            default="1"
        )
        try:
            if choice == "1":
                run_full(domain, data)
            elif choice == "2":
                data["dns"] = dns_lookup(domain)
            elif choice == "3":
                data["rdap"] = rdap_lookup(domain)
            elif choice == "4":
                data["http"] = http_analysis(domain)
            elif choice == "5":
                data["tls"] = tls_analysis(domain)
            elif choice == "6":
                data["public_files"] = public_files(domain)
            elif choice == "7":
                data["passive_subdomains"] = passive_subdomains(domain)
            elif choice == "8":
                data["public_crawl"] = crawl_public_site(domain)
            elif choice == "9":
                save_report(domain, data)
            elif choice == "10":
                save_text_report(domain, data)
            elif choice == "11":
                usage_rules()
            else:
                console.print("[cyan]CYBERX session closed.[/cyan]")
                break
        except KeyboardInterrupt:
            console.print("\n[yellow]Module stopped by user.[/yellow]")
        except Exception as exc:
            console.print(f"[red]Module error: {str(exc)[:300]}[/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user.[/yellow]")
