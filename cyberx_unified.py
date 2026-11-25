#!/usr/bin/env python3
"""
CYBERX WEB INTELLIGENCE X — UNIFIED EDITION
Defensive website intelligence and low-impact security configuration auditing.

Authorized use only: assess domains you own or have explicit written permission to test.
No exploitation, brute force, credential attacks, or destructive testing.
"""
from __future__ import annotations

import argparse
import html
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
except ImportError:
    print("Missing dependency: rich. Install with: pip install rich")
    raise SystemExit(1)


APP = "CYBERX WEB INTELLIGENCE X"
VERSION = "3.0 UNIFIED"
USER_AGENT = f"CyberX-Web-Intelligence-X/{VERSION} (authorized defensive audit)"
TIMEOUT = 10
MAX_PAGE_BYTES = 350_000
MAX_CRAWL_PAGE_BYTES = 120_000
MAX_PAGES_HARD_LIMIT = 20
REPORT_DIR = Path(__file__).resolve().parent / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

console = Console()

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS for supported browsers",
    "Content-Security-Policy": "Restricts permitted content and script sources",
    "X-Content-Type-Options": "Helps prevent MIME-type sniffing",
    "X-Frame-Options": "Helps mitigate clickjacking",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts browser features and device APIs",
}
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.I | re.S)
LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#]+)["']""", re.I)
EXPOSURE_PATHS = (
    "/.env", "/.git/HEAD", "/config.php.bak", "/backup.zip",
    "/database.sql", "/phpinfo.php", "/.DS_Store",
)
COMMON_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443)


def banner() -> None:
    console.clear()
    console.print(Panel.fit(
        "[bold bright_cyan]CYBERX[/bold bright_cyan] [bold white]WEB INTELLIGENCE X[/bold white]\n"
        "[bright_blue]UNIFIED OSINT + DEFENSIVE SECURITY AUDITOR[/bright_blue]\n"
        f"[dim]Version {VERSION}  |  Python  |  Termux + Linux[/dim]",
        border_style="bright_blue", box=box.DOUBLE, padding=(1, 4),
    ))
    console.print("[bold yellow]AUTHORIZED ASSESSMENT ONLY[/bold yellow]")
    console.print("[dim]No exploitation, password attacks, or destructive tests.[/dim]\n")


def section(title: str) -> None:
    console.print(f"\n[bold bright_cyan]◆ {title}[/bold bright_cyan]")


def resolve_public(host: str, port: int) -> list[str]:
    """Resolve a host and reject any non-global destination address."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed: {exc}") from exc
    addresses = sorted({item[4][0].split("%")[0] for item in infos})
    if not addresses:
        raise ValueError("No IP addresses resolved.")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(f"Blocked non-public destination address: {address}")
    return addresses


def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("No target supplied.")
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// targets are supported.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid URL without embedded credentials.")
    if parsed.query or parsed.fragment:
        # Query strings/fragments are intentionally discarded for a clean root assessment.
        pass
    host = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        raise ValueError("Enter a public domain name, not a raw IP address.")
    except ValueError as exc:
        if str(exc).startswith("Enter a public"):
            raise
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid international domain name.") from exc
    if len(host) > 253 or "." not in host:
        raise ValueError("Enter a fully qualified domain name.")
    labels = host.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("Invalid domain format.")
    port = parsed.port
    if port is not None and not (1 <= port <= 65535):
        raise ValueError("Invalid port.")
    scheme = parsed.scheme.lower()
    netloc = host + (f":{port}" if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)) else "")
    resolve_public(host, port or (443 if scheme == "https" else 80))
    return urlunsplit((scheme, netloc, parsed.path or "/", "", ""))


def safe_request(session: requests.Session, method: str, url: str, **kwargs):
    """
    Make a request without automatically following redirects.
    Every destination is validated; cross-host redirects are not followed.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Blocked unsupported URL.")
    host = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolve_public(host, port)
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("allow_redirects", False)
    kwargs.setdefault("verify", True)
    headers = dict(kwargs.pop("headers", {}) or {})
    headers.setdefault("User-Agent", USER_AGENT)
    response = session.request(method, url, headers=headers, **kwargs)
    return response


def get_same_host(session: requests.Session, url: str, expected_host: str, **kwargs):
    response = safe_request(session, "GET", url, **kwargs)
    # Do not follow redirects automatically. Record the redirect response as-is.
    return response


def dns_lookup(domain: str) -> dict:
    section("DNS INTELLIGENCE")
    result = {"hostname": domain, "records": {}}
    if dns is None:
        result["error"] = "dnspython not installed; install with pip install dnspython"
        console.print("[yellow]DNS record module unavailable (dnspython missing).[/yellow]")
        return result
    for record in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            answers = dns.resolver.resolve(domain, record, lifetime=5)
            values = [str(item).strip('"') for item in answers]
            result["records"][record] = values
            if record in ("A", "AAAA"):
                result.setdefault("addresses", []).extend(values)
            table = Table(box=box.SIMPLE, show_header=False)
            table.add_row(f"[bold]{record}[/bold]", "\n".join(values[:12]) or "—")
            console.print(table)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            result["records"][record] = []
            console.print(f"[dim]{record}: no record returned[/dim]")
        except Exception as exc:
            result["records"][record] = {"lookup_error": str(exc)}
            console.print(f"[yellow]{record}: lookup unavailable ({exc})[/yellow]")
    return result


def rdap_lookup(domain: str) -> dict:
    section("DOMAIN REGISTRATION (RDAP)")
    url = f"https://rdap.org/domain/{domain}"
    try:
        with requests.Session() as session:
            response = safe_request(session, "GET", url)
            response.raise_for_status()
            payload = response.json()
        events = {}
        for event in payload.get("events", []):
            if event.get("eventAction"):
                events[event["eventAction"]] = event.get("eventDate", "")
        result = {
            "ldhName": payload.get("ldhName"),
            "status": payload.get("status", []),
            "events": events,
            "nameservers": [x.get("ldhName") for x in payload.get("nameservers", []) if x.get("ldhName")],
            "entities_roles": [{"roles": x.get("roles", [])} for x in payload.get("entities", []) if x.get("roles")],
            "source": "RDAP public registry data",
        }
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("Domain", str(result["ldhName"] or "Not disclosed"))
        table.add_row("Status", ", ".join(result["status"]) or "Not disclosed")
        for key, value in events.items():
            table.add_row(key, str(value))
        table.add_row("Nameservers", ", ".join(result["nameservers"]) or "Not disclosed")
        console.print(table)
        console.print("[dim]Registrant contact details may be redacted by the registry.[/dim]")
        return result
    except Exception as exc:
        console.print(f"[yellow]RDAP unavailable: {exc}[/yellow]")
        return {"error": str(exc), "source": url}


def extract_title(body: str):
    match = TITLE_RE.search(body)
    return re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()[:200] if match else None


def fetch_page(session: requests.Session, url: str, expected_host: str, max_bytes: int = MAX_PAGE_BYTES):
    result = {"url": url, "status_code": None, "headers": {}, "title": None, "technology_hints": []}
    try:
        response = get_same_host(session, url, expected_host, stream=True)
        result["status_code"] = response.status_code
        result["headers"] = dict(response.headers)
        result["final_url"] = response.url
        if response.is_redirect:
            result["redirect_location"] = response.headers.get("Location")
            response.close()
            return result, ""
        chunks, total = [], 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        encoding = response.encoding or "utf-8"
        body = b"".join(chunks)[:max_bytes].decode(encoding, errors="replace")
        response.close()
        result["title"] = extract_title(body)
        headers_lower = {k.lower(): v for k, v in result["headers"].items()}
        haystack = (str(headers_lower) + " " + body[:100000]).lower()
        fingerprints = {
            "wp-content": "WordPress", "wp-includes": "WordPress",
            "__next": "Next.js", "__nuxt": "Nuxt",
            "laravel_session": "Laravel", "drupal.settings": "Drupal",
            "cdn.shopify.com": "Shopify", "joomla": "Joomla",
            "cloudflare": "Cloudflare", "nginx": "Nginx", "apache": "Apache",
        }
        result["technology_hints"] = sorted({name for marker, name in fingerprints.items() if marker in haystack})
        return result, body
    except Exception as exc:
        result["error"] = str(exc)
        return result, ""


def http_analysis(domain: str) -> dict:
    section("HTTP / HTTPS SECURITY")
    output = {}
    with requests.Session() as session:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}/"
            data, body = fetch_page(session, url, domain)
            output[scheme] = data
            if data.get("status_code") is None:
                console.print(f"[yellow]{scheme.upper()} unavailable: {data.get('error', 'No response')}[/yellow]")
                continue
            table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
            table.add_column("Security header")
            table.add_column("Observed value")
            table.add_column("Assessment")
            lower = {k.lower(): v for k, v in data.get("headers", {}).items()}
            for header, purpose in SECURITY_HEADERS.items():
                value = lower.get(header.lower())
                table.add_row(header, str(value)[:85] if value else "Not observed",
                              "[green]Present[/green]" if value else "[yellow]Missing[/yellow]")
            console.print(Panel(
                f"Requested: {url}\nStatus: {data['status_code']}\n"
                f"Title: {data.get('title') or 'Not detected'}\n"
                f"Server: {data.get('headers', {}).get('Server', 'Not disclosed')}\n"
                f"Final URL: {data.get('final_url', url)}",
                title=f"{scheme.upper()} RESPONSE", border_style="green" if data["status_code"] < 400 else "yellow",
            ))
            console.print(table)
    return output


def tls_analysis(domain: str) -> dict:
    section("TLS CERTIFICATE")
    result = {"checked": True, "valid": False}
    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                expiry = cert.get("notAfter")
                result.update({
                    "valid": True,
                    "tls_version": tls_sock.version(),
                    "cipher": tls_sock.cipher(),
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"),
                    "not_after": expiry,
                    "subject_alt_name": cert.get("subjectAltName", []),
                })
                if expiry:
                    exp = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    result["days_remaining"] = (exp - datetime.now(timezone.utc)).days
        console.print(Panel(
            f"TLS version: {result.get('tls_version')}\n"
            f"Cipher: {result.get('cipher')}\nIssuer: {result.get('issuer')}\n"
            f"Expires: {result.get('not_after')}\nDays remaining: {result.get('days_remaining', 'Unknown')}",
            title="CERTIFICATE DETAILS", border_style="green",
        ))
    except Exception as exc:
        result["error"] = str(exc)
        console.print(f"[yellow]TLS check unavailable: {exc}[/yellow]")
    return result


def public_files(domain: str) -> dict:
    section("PUBLIC WEBSITE FILES")
    result = {}
    with requests.Session() as session:
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            url = f"https://{domain}{path}"
            try:
                response = safe_request(session, "GET", url, stream=True)
                result[path] = {
                    "status_code": response.status_code,
                    "url": response.url,
                    "content_type": response.headers.get("Content-Type"),
                    "redirect_location": response.headers.get("Location"),
                }
                console.print(f"{path}: [green]{response.status_code}[/green]")
                response.close()
            except Exception as exc:
                result[path] = {"error": str(exc)}
                console.print(f"[yellow]{path}: unavailable ({exc})[/yellow]")
    return result


def passive_subdomains(domain: str) -> dict:
    section("PASSIVE SUBDOMAIN INTELLIGENCE")
    url = "https://crt.sh/"
    try:
        with requests.Session() as session:
            response = safe_request(session, "GET", url, params={"q": "%." + domain, "output": "json"})
            response.raise_for_status()
            rows = response.json()
        found = set()
        for row in rows:
            for item in row.get("name_value", "").splitlines():
                name = item.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    found.add(name)
        names = sorted(found)
        for name in names[:60]:
            console.print(" • " + name)
        console.print(f"[bold]Unique names returned: {len(names)}[/bold]")
        return {"names": names[:200], "count_returned": len(names), "source": "crt.sh Certificate Transparency"}
    except Exception as exc:
        console.print(f"[yellow]Passive lookup unavailable: {exc}[/yellow]")
        return {"error": str(exc), "source": url}


def crawl_site(target: str, page_limit: int) -> dict:
    section("BOUNDED SAME-ORIGIN CRAWLER & PUBLIC EMAIL DISCOVERY")
    parsed = urlsplit(target)
    host = parsed.hostname
    origin = (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    queue = [target]
    seen = set()
    emails = set()
    pages = []
    with requests.Session() as session:
        while queue and len(seen) < page_limit:
            current = queue.pop(0)
            p = urlsplit(current)
            current_origin = (p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80))
            if current_origin != origin or current in seen:
                continue
            seen.add(current)
            try:
                response = safe_request(session, "GET", current, stream=True)
                ctype = response.headers.get("Content-Type", "").lower()
                if response.status_code >= 400 or "text/html" not in ctype:
                    pages.append({"url": current, "status": response.status_code, "skipped": "not successful HTML"})
                    response.close()
                    continue
                chunks, total = [], 0
                for chunk in response.iter_content(6000):
                    if chunk:
                        chunks.append(chunk)
                        total += len(chunk)
                    if total >= MAX_CRAWL_PAGE_BYTES:
                        break
                text_body = b"".join(chunks)[:MAX_CRAWL_PAGE_BYTES].decode(response.encoding or "utf-8", "replace")
                status = response.status_code
                response.close()
                pages.append({"url": current, "status": status})
                emails.update(EMAIL_RE.findall(text_body))
                for link in LINK_RE.findall(text_body):
                    absolute = urljoin(current, link)
                    lp = urlsplit(absolute)
                    link_origin = (lp.scheme, lp.hostname, lp.port or (443 if lp.scheme == "https" else 80))
                    clean = urlunsplit((lp.scheme, lp.netloc, lp.path or "/", "", ""))
                    if link_origin == origin and clean not in seen and len(queue) < page_limit * 4:
                        queue.append(clean)
            except Exception as exc:
                pages.append({"url": current, "error": str(exc)})
            time.sleep(0.15)
    found = sorted(emails)
    console.print(f"Pages visited: {len(pages)} | Public email addresses found: {len(found)}")
    for address in found[:30]:
        console.print(" • " + address)
    return {"pages_checked": pages, "pages_visited": len(pages), "emails_found": found}


def exposure_checks(target: str) -> list[dict]:
    section("OPTIONAL PUBLIC-PATH EXPOSURE INDICATORS")
    parsed = urlsplit(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    results = []
    with requests.Session() as session:
        for path in EXPOSURE_PATHS:
            try:
                response = safe_request(session, "GET", base + path, headers={"Range": "bytes=0-64"}, stream=True)
                results.append({
                    "path": path, "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type"),
                    "content_length": response.headers.get("Content-Length"),
                })
                console.print(f"{path}: HTTP {response.status_code}")
                response.close()
            except Exception as exc:
                results.append({"path": path, "error": str(exc)})
            time.sleep(0.15)
    console.print("[dim]HTTP 200 is only an indicator; do not assume file contents are exposed.[/dim]")
    return results


def port_assessment(domain: str) -> list[dict]:
    section("OPTIONAL LIMITED TCP PORT CHECK")
    addresses = resolve_public(domain, 443)
    # Resolve once and connect only to the first validated public address.
    ip = addresses[0]
    results = []
    for port in COMMON_PORTS:
        state = "closed_or_filtered"
        try:
            with socket.create_connection((ip, port), timeout=0.8):
                state = "open"
        except (OSError, socket.timeout):
            pass
        results.append({"port": port, "state": state})
        console.print(f"TCP/{port}: {'[green]open[/green]' if state == 'open' else '[dim]closed/filtered[/dim]'}")
    return results


def build_findings(data: dict) -> list[dict]:
    findings = []
    https = data.get("http", {}).get("https", {})
    headers = {k.lower(): v for k, v in https.get("headers", {}).items()}
    if https.get("status_code") is not None:
        for header, purpose in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                severity = "MEDIUM" if header in ("Content-Security-Policy", "Strict-Transport-Security") else "LOW"
                findings.append({"severity": severity, "title": f"Missing {header}", "detail": purpose})
    tls_data = data.get("tls", {})
    if data.get("target", "").startswith("https://") and not tls_data.get("valid"):
        findings.append({"severity": "HIGH", "title": "TLS validation failed", "detail": tls_data.get("error", "Certificate validation failed")})
    days = tls_data.get("days_remaining")
    if days is not None and days < 21:
        findings.append({"severity": "MEDIUM", "title": "TLS certificate expiry approaching", "detail": f"Certificate expires in {days} days"})
    for item in data.get("exposure_checks", []):
        if item.get("status_code") == 200:
            findings.append({
                "severity": "HIGH", "title": "Potential exposed path " + item["path"],
                "detail": "HTTP 200 observed. This is an indicator only; verify through an authorized administrator without retrieving sensitive data.",
            })
    return findings


def summarize(data: dict) -> None:
    findings = data.get("findings", [])
    counts = {level: sum(1 for item in findings if item["severity"] == level) for level in ("HIGH", "MEDIUM", "LOW")}
    score = max(0, 100 - counts["HIGH"] * 18 - counts["MEDIUM"] * 8 - counts["LOW"] * 3)
    data["summary"] = {"total": len(findings), **{k.lower(): v for k, v in counts.items()}}
    data["security_score"] = score
    console.print(Panel(
        f"[bold]Indicative security score:[/bold] [bright_cyan]{score}/100[/bright_cyan]\n"
        f"Findings: {len(findings)} | High: {counts['HIGH']} | Medium: {counts['MEDIUM']} | Low: {counts['LOW']}\n"
        "[dim]This heuristic score is not a certification or proof of security.[/dim]",
        title="ASSESSMENT SUMMARY", border_style="bright_blue",
    ))
    if findings:
        table = Table(box=box.ROUNDED, header_style="bold")
        table.add_column("Severity")
        table.add_column("Finding")
        table.add_column("Details")
        for item in findings:
            color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}[item["severity"]]
            table.add_row(f"[{color}]{item['severity']}[/{color}]", item["title"], item["detail"])
        console.print(table)
    else:
        console.print("[green]No findings from the enabled checks.[/green]")


def run_assessment(target: str, pages: int, check_exposures: bool, check_ports: bool, full: bool = True) -> dict:
    domain = urlsplit(target).hostname
    data = {
        "tool": APP, "version": VERSION, "target": target,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "authorization_confirmed_by_operator": True,
        "scope": "Public domain/site configuration; same-origin bounded crawling",
    }
    data["dns"] = dns_lookup(domain)
    data["rdap"] = rdap_lookup(domain)
    data["http"] = http_analysis(domain)
    data["tls"] = tls_analysis(domain) if urlsplit(target).scheme == "https" else {"checked": False, "note": "HTTP target"}
    data["public_files"] = public_files(domain)
    data["passive_subdomains"] = passive_subdomains(domain)
    data["crawl"] = crawl_site(target, max(1, min(pages, MAX_PAGES_HARD_LIMIT)))
    data["exposure_checks"] = exposure_checks(target) if check_exposures else []
    data["ports"] = port_assessment(domain) if check_ports else []
    data["findings"] = build_findings(data)
    data["assessment_note"] = (
        "Findings are automated observations, not proof of exploitability. "
        "Missing headers, HTTP status codes, technology hints, and discovered subdomains require manual context."
    )
    data["completed_at"] = datetime.now(timezone.utc).isoformat()
    summarize(data)
    return data


def save_reports(data: dict, out_dir: str | Path = REPORT_DIR) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    host = re.sub(r"[^a-zA-Z0-9_-]", "_", urlsplit(data["target"]).hostname or "target")
    stem = f"cyberx_{host}_{stamp}"
    json_path = out / f"{stem}.json"
    txt_path = out / f"{stem}.txt"
    html_path = out / f"{stem}.html"

    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    lines = [
        f"{APP} — {VERSION}", "=" * 64, f"Target: {data['target']}",
        f"Score: {data.get('security_score', 'N/A')}/100",
        f"Generated: {datetime.now(timezone.utc).isoformat()}", "",
        "SUMMARY",
        json.dumps(data.get("summary", {}), ensure_ascii=False),
        "", "FINDINGS",
    ]
    for item in data.get("findings", []):
        lines.extend([f"[{item['severity']}] {item['title']}", item["detail"], ""])
    lines.extend(["PUBLIC EMAILS"] + data.get("crawl", {}).get("emails_found", []))
    lines.extend(["", "ASSESSMENT NOTE", data.get("assessment_note", "")])
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    rows = "".join(
        "<tr><td>" + html.escape(item["severity"]) + "</td><td>" +
        html.escape(item["title"]) + "</td><td>" + html.escape(item["detail"]) + "</td></tr>"
        for item in data.get("findings", [])
    ) or '<tr><td colspan="3">No findings from enabled checks.</td></tr>'
    summary = data.get("summary", {})
    emails = html.escape(", ".join(data.get("crawl", {}).get("emails_found", [])))
    dns_addresses = html.escape(", ".join(data.get("dns", {}).get("addresses", [])))
    tech = html.escape(", ".join(data.get("http", {}).get("https", {}).get("technology_hints", [])))
    html_report = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP} Audit Report</title><style>
:root{{--bg:#07111f;--card:#101f33;--line:#263d56;--text:#eaf2fb;--muted:#9bb0c7;--accent:#45e2bd}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at top,#122b43,var(--bg) 55%);color:var(--text);font:15px/1.6 system-ui, sans-serif;padding:24px}}
main{{max-width:1050px;margin:auto}}section{{background:rgba(16,31,51,.94);border:1px solid var(--line);border-radius:18px;padding:22px;margin:16px 0;overflow-wrap:anywhere}}
h1{{color:var(--accent);margin:0}}h2{{margin-top:0;color:#bdeee3}}.muted{{color:var(--muted)}}.score{{font-size:52px;font-weight:850;color:var(--accent);line-height:1.2}}
.stats{{display:flex;gap:12px;flex-wrap:wrap}}.stat{{padding:10px 14px;border:1px solid var(--line);border-radius:12px}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:11px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}}th{{color:var(--accent)}}
code{{overflow-wrap:anywhere}}footer{{color:var(--muted);padding:10px}}
</style></head><body><main>
<section><h1>CYBERX WEB INTELLIGENCE X</h1><p class="muted">Unified OSINT + Defensive Security Assessment · {VERSION}</p>
<p>Target: <code>{html.escape(data['target'])}</code></p><div class="score">{data.get('security_score', 0)}/100</div>
<p class="muted">Indicative heuristic score — not a certification.</p></section>
<section><h2>Executive summary</h2><div class="stats">
<div class="stat">Total: <b>{summary.get('total', 0)}</b></div>
<div class="stat">High: <b>{summary.get('high', 0)}</b></div>
<div class="stat">Medium: <b>{summary.get('medium', 0)}</b></div>
<div class="stat">Low: <b>{summary.get('low', 0)}</b></div></div></section>
<section><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Details</th></tr>{rows}</table></section>
<section><h2>Website intelligence</h2><p>DNS addresses: {dns_addresses or 'Not available'}</p>
<p>Technology hints: {tech or 'Not detected'}</p><p>Public email addresses: {emails or 'None found'}</p>
<p>Crawled pages: {data.get('crawl', {}).get('pages_visited', 0)}</p></section>
<section><h2>Assessment limitations</h2><p>{html.escape(data.get('assessment_note', ''))}</p>
<p>Only public, low-impact checks were performed. A missing header or HTTP 200 response does not by itself prove a vulnerability.</p></section>
<footer>Generated {html.escape(data.get('completed_at', ''))} · Authorized use only.</footer>
</main></body></html>"""
    html_path.write_text(html_report, encoding="utf-8")
    console.print(Panel(
        "[bold green]Reports saved[/bold green]\n" +
        "\n".join(str(p.resolve()) for p in (html_path, json_path, txt_path)),
        title="REPORT EXPORT", border_style="green",
    ))
    return [html_path, json_path, txt_path]


def interactive() -> None:
    banner()
    console.print("[white]Public domain intelligence and low-impact defensive configuration checks.[/white]")
    try:
        target = normalize_target(Prompt.ask("\n[bold cyan]Authorized target domain / URL[/bold cyan]"))
    except Exception as exc:
        console.print(f"[red]Target error: {exc}[/red]")
        return
    console.print(f"\n[bold]Target:[/bold] [bright_cyan]{target}[/bright_cyan]")
    if not Confirm.ask("Do you own this target or have explicit written authorization?", default=False):
        console.print("[red]Stopped: authorization not confirmed.[/red]")
        return

    data = None
    while True:
        console.print(Panel(
            "[1] Full assessment\n[2] DNS records\n[3] RDAP registration\n"
            "[4] HTTP/HTTPS headers & technology hints\n[5] TLS certificate\n"
            "[6] robots.txt / sitemap.xml / security.txt\n"
            "[7] Passive subdomain discovery\n[8] Bounded crawler & public email discovery\n"
            "[9] Optional exposure indicators (explicit opt-in)\n"
            "[10] Optional limited TCP ports (explicit opt-in)\n"
            "[11] Export latest assessment (HTML / JSON / TXT)\n[0] Exit",
            title=f"[bold bright_cyan]{APP} MENU[/bold bright_cyan]", border_style="bright_blue",
        ))
        choice = Prompt.ask("Select module", choices=[str(x) for x in range(12)], default="1")
        domain = urlsplit(target).hostname
        if choice == "1":
            pages = int(Prompt.ask("Maximum pages to crawl (1–20)", default="8"))
            exposures = Confirm.ask("Enable optional known-path exposure indicators?", default=False)
            ports = Confirm.ask("Enable limited TCP port checks?", default=False)
            data = run_assessment(target, pages, exposures, ports)
        elif choice == "2":
            result = dns_lookup(domain)
            data = data or {"target": target}
            data["dns"] = result
        elif choice == "3":
            result = rdap_lookup(domain)
            data = data or {"target": target}
            data["rdap"] = result
        elif choice == "4":
            result = http_analysis(domain)
            data = data or {"target": target}
            data["http"] = result
        elif choice == "5":
            result = tls_analysis(domain)
            data = data or {"target": target}
            data["tls"] = result
        elif choice == "6":
            result = public_files(domain)
            data = data or {"target": target}
            data["public_files"] = result
        elif choice == "7":
            result = passive_subdomains(domain)
            data = data or {"target": target}
            data["passive_subdomains"] = result
        elif choice == "8":
            pages = int(Prompt.ask("Maximum pages to crawl (1–20)", default="8"))
            result = crawl_site(target, max(1, min(pages, MAX_PAGES_HARD_LIMIT)))
            data = data or {"target": target}
            data["crawl"] = result
        elif choice == "9":
            if Confirm.ask("Confirm this is your authorized website?", default=False):
                result = exposure_checks(target)
                data = data or {"target": target}
                data["exposure_checks"] = result
        elif choice == "10":
            if Confirm.ask("Confirm written authorization for port checks?", default=False):
                result = port_assessment(domain)
                data = data or {"target": target}
                data["ports"] = result
        elif choice == "11":
            if not data:
                console.print("[yellow]Run at least one module first.[/yellow]")
            else:
                data.setdefault("findings", build_findings(data))
                data.setdefault("summary", {"total": len(data["findings"]), "high": 0, "medium": 0, "low": 0})
                data.setdefault("security_score", 100)
                data.setdefault("crawl", {"emails_found": [], "pages_visited": 0})
                data.setdefault("dns", {"addresses": []})
                data.setdefault("http", {})
                data.setdefault("assessment_note", "Partial module run; interpret results in context.")
                save_reports(data)
        else:
            console.print("[cyan]CYBERX session closed.[/cyan]")
            break


def cli() -> None:
    parser = argparse.ArgumentParser(description=APP)
    parser.add_argument("target", nargs="?", help="Authorized domain or URL")
    parser.add_argument("--pages", type=int, default=8, help="Same-origin crawl limit (1–20)")
    parser.add_argument("--exposure-checks", action="store_true", help="Enable low-impact known-path indicators")
    parser.add_argument("--ports-consent", action="store_true", help="Enable limited TCP port checks")
    parser.add_argument("--out", default=str(REPORT_DIR), help="Report output directory")
    args = parser.parse_args()

    if not args.target:
        interactive()
        return
    banner()
    try:
        target = normalize_target(args.target)
    except Exception as exc:
        raise SystemExit(f"Target error: {exc}")
    console.print("[yellow]Authorized defensive testing only.[/yellow]")
    if not Confirm.ask("Do you own this target or have explicit written authorization?", default=False):
        raise SystemExit("Stopped: authorization not confirmed.")
    data = run_assessment(
        target,
        max(1, min(args.pages, MAX_PAGES_HARD_LIMIT)),
        args.exposure_checks,
        args.ports_consent,
    )
    save_reports(data, args.out)


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user.[/yellow]")
        raise SystemExit(130)
