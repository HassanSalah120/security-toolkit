#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
AccurateSurface - low-noise surface validator for authorized assessments.

This tool is intentionally conservative:
- It does low-impact TCP and HTTP probes only.
- It does not brute-force credentials, enumerate large wordlists, or exploit.
- It reports confidence and evidence so SPA 404 pages and protected endpoints
  do not become false "critical" findings.
"""

import argparse
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from common import parse_version

VERSION = "1.0.0"
USER_AGENT = "AccurateSurface/1.0 authorized-low-impact"

DEFAULT_PORTS = [
    22, 80, 443, 5000, 7547, 8080, 8443, 9000, 9001, 3389
]

DEFAULT_SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/config.json",
    "/package.json",
    "/composer.json",
    "/swagger.json",
    "/openapi.json",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/admin",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/adminer.php",
]

DEFAULT_CORS_PATHS = [
    "/api/public/events/1",
    "/api/config",
    "/api/version",
]


@dataclass
class TcpResult:
    host: str
    port: int
    open: bool
    banner: str = ""
    service_hint: str = ""
    error: str = ""


@dataclass
class HttpResult:
    url: str
    status: Optional[int]
    final_url: str = ""
    content_type: str = ""
    server: str = ""
    title: str = ""
    body_sha256: str = ""
    body_size: int = 0
    fallback_404: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""


@dataclass
class Finding:
    id: str
    severity: str
    confidence: str
    target: str
    title: str
    evidence: str
    recommendation: str


def parse_ports(value: str) -> List[int]:
    ports = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start < 1 or end > 65535 or start > end:
                raise argparse.ArgumentTypeError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise argparse.ArgumentTypeError(f"invalid port: {part}")
            ports.add(port)
    return sorted(ports)


def read_targets(args: argparse.Namespace) -> List[str]:
    targets = list(args.target or [])
    if args.target_file:
        with open(args.target_file, "r", encoding="utf-8") as fh:
            targets.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))
    cleaned = []
    for target in targets:
        parsed = urlparse(target if "://" in target else f"//{target}", scheme="")
        cleaned.append(parsed.hostname or target)
    return sorted(set(cleaned))


def tcp_probe(host: str, port: int, timeout: float) -> TcpResult:
    result = TcpResult(host=host, port=port, open=False)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result.open = True
            sock.settimeout(timeout)
            if port in (80, 8080, 8000, 8008, 8888, 9000, 9001, 5000, 7547):
                method = "GET" if port == 7547 else "HEAD"
                payload = f"{method} / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\r\n"
                sock.sendall(payload.encode("ascii"))
            elif port == 22:
                pass
            elif port in (443, 8443):
                result.service_hint = "tls/http"
                return result
            else:
                sock.sendall(b"\r\n")
            try:
                data = sock.recv(512)
                result.banner = data.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                result.banner = ""
    except Exception as exc:
        result.error = str(exc)

    result.service_hint = service_hint(port, result.banner)
    return result


def service_hint(port: int, banner: str) -> str:
    lower = banner.lower()
    if "ssh-" in lower:
        return "ssh"
    if "minio console" in lower:
        return "minio-console"
    if "server: minio" in lower or "<code>accessdenied</code>" in lower:
        return "minio-api"
    if "huaweihomegateway" in lower:
        return "huawei-home-gateway"
    if "http/" in lower:
        return "http"
    if port == 3389:
        return "rdp"
    return ""


def likely_http_ports(open_ports: Sequence[TcpResult]) -> List[Tuple[int, str]]:
    urls = []
    for item in open_ports:
        if not item.open:
            continue
        if item.port in (443, 8443):
            urls.append((item.port, "https"))
        elif item.port in (80, 8080, 8000, 8008, 8888, 9000, 9001, 5000, 7547):
            urls.append((item.port, "http"))
    return urls


def make_base_url(host: str, port: int, scheme: str) -> str:
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    # Handle IPv6 addresses
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}" if default else f"{scheme}://{host}:{port}"


def http_get(session: requests.Session, url: str, timeout: float, headers: Optional[Dict[str, str]] = None) -> HttpResult:
    merged_headers = {"User-Agent": USER_AGENT}
    if headers:
        merged_headers.update(headers)
    try:
        resp = session.get(
            url,
            headers=merged_headers,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        body = resp.content or b""
        text = resp.text[:5000]
        return HttpResult(
            url=url,
            status=resp.status_code,
            final_url=resp.url,
            content_type=resp.headers.get("Content-Type", ""),
            server=resp.headers.get("Server", ""),
            title=extract_title(text),
            body_sha256=hashlib.sha256(body).hexdigest(),
            body_size=len(body),
            fallback_404=looks_like_not_found(text),
            headers={k.lower(): v for k, v in resp.headers.items()},
        )
    except Exception as exc:
        return HttpResult(url=url, status=None, error=str(exc))


def extract_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()


def looks_like_not_found(text: str) -> bool:
    lower = text.lower()
    markers = [
        "no route matches url",
        "page not found",
        "404 not found",
        "the page you are looking for does not exist",
        "__staticrouterhydrationdata",
    ]
    return any(marker in lower for marker in markers)


def fetch_text(session: requests.Session, url: str, timeout: float) -> Tuple[HttpResult, str]:
    try:
        resp = session.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        body = resp.content or b""
        text = resp.text[:10000]
        result = HttpResult(
            url=url,
            status=resp.status_code,
            final_url=resp.url,
            content_type=resp.headers.get("Content-Type", ""),
            server=resp.headers.get("Server", ""),
            title=extract_title(text),
            body_sha256=hashlib.sha256(body).hexdigest(),
            body_size=len(body),
            fallback_404=looks_like_not_found(text),
            headers={k.lower(): v for k, v in resp.headers.items()},
        )
        return result, text
    except Exception as exc:
        return HttpResult(url=url, status=None, error=str(exc)), ""


def sensitive_signature(path: str, result: HttpResult, body: str, baseline: HttpResult) -> Tuple[str, str]:
    """Return classification and reason: exposed, fallback, protected, absent, unknown."""
    if result.status in (401, 403):
        return "protected", f"HTTP {result.status}"
    if result.status in (404, 410):
        return "absent", f"HTTP {result.status}"
    if result.status is None:
        return "unknown", result.error
    if result.fallback_404:
        return "fallback", "not-found HTML shell"
    if baseline.status == 200 and result.body_sha256 == baseline.body_sha256:
        return "fallback", "matches random missing-path response"

    lower = body.lower().lstrip()
    ctype = result.content_type.lower()
    is_html = "text/html" in ctype or lower.startswith("<!doctype") or lower.startswith("<html")
    name = path.rsplit("/", 1)[-1].lower()

    if path == "/.git/HEAD" and (body.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}\s*", body.strip())):
        return "exposed", "git HEAD signature"
    if path == "/.env" and any(marker in lower for marker in ("app_key=", "db_password=", "secret_key=", "database_url=", "aws_secret_access_key")):
        return "exposed", "environment variable markers"
    if name in {"package.json", "composer.json", "config.json", "swagger.json", "openapi.json"}:
        try:
            parsed = json.loads(body)
            if name == "package.json" and any(k in parsed for k in ("dependencies", "scripts", "devDependencies")):
                return "exposed", "package JSON keys"
            if name == "composer.json" and "require" in parsed:
                return "exposed", "composer JSON keys"
            if name == "config.json" and any(k in parsed for k in ("database", "auth", "api", "secret")):
                return "exposed", "configuration JSON keys"
            if name in {"swagger.json", "openapi.json"} and any(k in parsed for k in ("swagger", "openapi")):
                return "exposed", "OpenAPI/Swagger JSON keys"
        except json.JSONDecodeError:
            pass
    if name.endswith(".sql") and any(marker in lower for marker in ("create table", "insert into", "mysqldump", "postgresql database dump")):
        return "exposed", "SQL dump markers"
    if name == "phpinfo.php" and ("phpinfo()" in lower or "<title>phpinfo" in lower):
        return "exposed", "phpinfo markers"
    if path in {"/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer.php"}:
        if is_html and any(marker in lower for marker in ("login", "password", "wp-login", "phpmyadmin", "adminer")):
            return "exposed", "admin/login interface markers"

    if is_html:
        return "fallback", "HTML without expected sensitive-file signature"
    return "unknown", "200 response without known signature"


def version_tuple(version: str) -> Tuple[int, ...]:
    return parse_version(version)


def minio_release_key(version: str) -> str:
    match = re.search(r"RELEASE\.(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)", version)
    return match.group(1) if match else ""


def analyze_openwebui(base_url: str, session: requests.Session, timeout: float) -> Tuple[Optional[Dict], List[Finding]]:
    findings = []
    result, body = fetch_text(session, f"{base_url}/api/version", timeout)
    if result.status != 200:
        return None, findings
    try:
        version = json.loads(body).get("version", "")
    except json.JSONDecodeError:
        return None, findings
    if not version:
        return None, findings

    config_result, config_body = fetch_text(session, f"{base_url}/api/config", timeout)
    info = {
        "service": "Open WebUI",
        "base_url": base_url,
        "version": version,
        "config_status": config_result.status,
    }
    if config_result.status == 200:
        findings.append(Finding(
            id="OWUI-EXPOSED-CONFIG",
            severity="medium",
            confidence="high",
            target=base_url,
            title="Open WebUI config is public",
            evidence="/api/config returned 200 without authentication",
            recommendation="Restrict Open WebUI to VPN/admin IPs and avoid public config/version disclosure.",
        ))

    if version_tuple(version) and version_tuple(version) < version_tuple("0.6.35"):
        findings.append(Finding(
            id="OWUI-CVE-2025-64496",
            severity="high",
            confidence="medium",
            target=base_url,
            title=f"Open WebUI {version} is older than the CVE-2025-64496 fixed line",
            evidence=f"/api/version returned {version}",
            recommendation="Upgrade Open WebUI to at least 0.6.35 and disable Direct Connections if not needed.",
        ))
    return info, findings


def analyze_minio(base_url: str, session: requests.Session, timeout: float) -> Tuple[Optional[Dict], List[Finding]]:
    findings = []
    root = http_get(session, base_url + "/", timeout)
    if "minio" not in (root.server or "").lower() and "minio" not in (root.title or "").lower():
        return None, findings

    info = {
        "service": "MinIO",
        "base_url": base_url,
        "root_status": root.status,
        "server": root.server,
        "version": "",
    }
    findings.append(Finding(
        id="MINIO-PUBLIC",
        severity="high",
        confidence="high",
        target=base_url,
        title="MinIO service is publicly reachable",
        evidence=f"Root returned HTTP {root.status} with Server: {root.server}",
        recommendation="Move MinIO API/Console behind private networking, VPN, or strict IP allowlists.",
    ))

    version_result, version_body = fetch_text(session, f"{base_url}/minio/version", timeout)
    if version_result.status == 200:
        try:
            info["version"] = json.loads(version_body).get("version", "")
        except json.JSONDecodeError:
            info["version"] = version_body.strip()[:120]

    version = info["version"]
    release = minio_release_key(version)
    if release:
        if release < "2023-03-20T20-16-18Z":
            findings.append(Finding(
                id="MINIO-CVE-2023-28434",
                severity="critical",
                confidence="medium",
                target=base_url,
                title="MinIO release appears older than CVE-2023-28434 fixed release",
                evidence=f"Detected {version}",
                recommendation="Upgrade MinIO and audit credentials with broad S3 permissions.",
            ))
        if release < "2025-04-03T14-56-28Z":
            findings.append(Finding(
                id="MINIO-CVE-2025-31489",
                severity="high",
                confidence="medium",
                target=base_url,
                title="MinIO release appears older than CVE-2025-31489 fixed release",
                evidence=f"Detected {version}",
                recommendation="Upgrade MinIO to a fixed release newer than 2025-04-03.",
            ))
    else:
        findings.append(Finding(
            id="MINIO-VERSION-UNKNOWN",
            severity="info",
            confidence="high",
            target=base_url,
            title="MinIO version not exposed",
            evidence="/minio/version did not return a parseable release string",
            recommendation="Confirm MinIO version from the host before claiming version-specific CVEs.",
        ))

    return info, findings


def add_exposure_findings(target: str, tcp_results: Sequence[TcpResult]) -> List[Finding]:
    findings = []
    for item in tcp_results:
        if not item.open:
            continue
        if item.port == 3389:
            findings.append(Finding(
                id="RDP-PUBLIC",
                severity="critical",
                confidence="high",
                target=f"{target}:3389",
                title="RDP is publicly reachable",
                evidence="TCP connection succeeded on port 3389",
                recommendation="Restrict RDP to VPN/admin IPs or disable it.",
            ))
        elif item.port == 7547:
            findings.append(Finding(
                id="CPE-MGMT-PUBLIC",
                severity="high",
                confidence="high",
                target=f"{target}:7547",
                title="Gateway/customer-premises management interface is public",
                evidence=item.banner[:180] or "TCP connection succeeded on port 7547",
                recommendation="Block public access to CPE/router management ports.",
            ))
        elif item.port == 5000:
            findings.append(Finding(
                id="UNKNOWN-5000-PUBLIC",
                severity="medium",
                confidence="medium",
                target=f"{target}:5000",
                title="Unknown service is publicly reachable on port 5000",
                evidence=item.banner[:180] or "TCP connection succeeded but did not identify service",
                recommendation="Identify the service owner and restrict it if not intended to be public.",
            ))
    return findings


def scan_target(target: str, ports: Sequence[int], args: argparse.Namespace) -> Dict:
    session = requests.Session()
    session.max_redirects = 3
    started = time.time()

    tcp_results = []
    for port in ports:
        tcp_results.append(tcp_probe(target, port, args.timeout))

    findings = add_exposure_findings(target, tcp_results)
    http_results = []
    sensitive_results = []
    services = []
    seen_cors = set()

    for port, scheme in likely_http_ports(tcp_results):
        base_url = make_base_url(target, port, scheme)
        baseline_path = f"/__accurate_surface_missing_{int(time.time() * 1000)}"
        baseline = http_get(session, base_url + baseline_path, args.timeout)
        base_result = http_get(session, base_url + "/", args.timeout)
        http_results.append(base_result)

        openwebui, owui_findings = analyze_openwebui(base_url, session, args.timeout)
        if openwebui:
            services.append(openwebui)
            findings.extend(owui_findings)

        minio, minio_findings = analyze_minio(base_url, session, args.timeout)
        if minio:
            services.append(minio)
            findings.extend(minio_findings)

        for path in args.sensitive_path:
            time.sleep(args.rate_limit)
            result, body = fetch_text(session, base_url + path, args.timeout)
            state, reason = sensitive_signature(path, result, body, baseline)
            sensitive_results.append({
                "url": base_url + path,
                "status": result.status,
                "state": state,
                "reason": reason,
                "content_type": result.content_type,
                "size": result.body_size,
            })
            if state == "exposed":
                findings.append(Finding(
                    id="SENSITIVE-PATH-EXPOSED",
                    severity="high",
                    confidence="high",
                    target=base_url + path,
                    title=f"Sensitive path appears exposed: {path}",
                    evidence=reason,
                    recommendation="Remove the file/route from public web roots or require authentication.",
                ))

        for path in args.cors_path:
            time.sleep(args.rate_limit)
            cors = http_get(session, base_url + path, args.timeout, {"Origin": args.cors_origin})
            acao = cors.headers.get("access-control-allow-origin", "")
            acc = cors.headers.get("access-control-allow-credentials", "")
            cors_key = (cors.final_url or cors.url, acao, acc)
            if (
                cors.status is not None
                and 200 <= cors.status < 400
                and acao == args.cors_origin
                and acc.lower() == "true"
                and cors_key not in seen_cors
            ):
                seen_cors.add(cors_key)
                findings.append(Finding(
                    id="CORS-REFLECT-CREDENTIALS",
                    severity="high",
                    confidence="high",
                    target=cors.final_url or (base_url + path),
                    title="Credentialed CORS origin reflection",
                    evidence=f"Reflected {acao} with Access-Control-Allow-Credentials: {acc}",
                    recommendation="Use a strict origin allowlist and disable credentials unless required.",
                ))

    return {
        "target": target,
        "started_at": datetime.fromtimestamp(started).isoformat(),
        "duration_seconds": round(time.time() - started, 2),
        "tcp": [asdict(item) for item in tcp_results],
        "http": [asdict(item) for item in http_results],
        "services": services,
        "sensitive_paths": sensitive_results,
        "findings": [asdict(item) for item in findings],
    }


def write_outputs(results: List[Dict], output_dir: str) -> Tuple[str, str]:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"accurate_surface_{stamp}.json")
    md_path = os.path.join(output_dir, f"accurate_surface_{stamp}.md")
    payload = {
        "tool": f"AccurateSurface v{VERSION}",
        "generated_at": datetime.now().isoformat(),
        "results": results,
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(payload))
    return json_path, md_path


def render_markdown(payload: Dict) -> str:
    lines = [
        "# Accurate Surface Scan",
        "",
        f"Generated: {payload['generated_at']}",
        f"Tool: {payload['tool']}",
        "",
    ]
    for result in payload["results"]:
        lines.extend([
            f"## {result['target']}",
            "",
            "### Open TCP Ports",
            "",
            "| Port | Service hint | Evidence |",
            "|---:|---|---|",
        ])
        for tcp in result["tcp"]:
            if tcp["open"]:
                evidence = clean_md_text(tcp["banner"] or "TCP connect succeeded")[:160]
                lines.append(f"| {tcp['port']} | {tcp['service_hint'] or '-'} | {evidence} |")
        lines.extend(["", "### Findings", ""])
        if not result["findings"]:
            lines.append("No findings from the conservative checks.")
        for finding in result["findings"]:
            lines.extend([
                f"- **{finding['severity'].upper()} / {finding['confidence']}**: {finding['title']}",
                f"  Target: `{finding['target']}`",
                f"  Evidence: {clean_md_text(finding['evidence'])}",
                f"  Recommendation: {finding['recommendation']}",
            ])
        lines.extend(["", "### Sensitive Path Classification", ""])
        exposed_or_unknown = [
            item for item in result["sensitive_paths"]
            if item["state"] == "exposed" or (item["state"] == "unknown" and item.get("status") == 200)
        ][:40]
        if not exposed_or_unknown:
            lines.append("No exposed sensitive paths. Fallback HTML and protected paths were filtered.")
        for item in exposed_or_unknown:
            lines.append(f"- `{item['url']}`: {item['state']} ({clean_md_text(item['reason'])})")
        lines.append("")
    return "\n".join(lines)


def clean_md_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value)).strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AccurateSurface - low-noise authorized surface validator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-t", "--target", action="append", help="Target host, IP, or URL. Can be repeated.")
    parser.add_argument("--target-file", help="File containing one target per line.")
    parser.add_argument("-p", "--ports", type=parse_ports, default=DEFAULT_PORTS, help="Ports to check.")
    parser.add_argument("--timeout", type=float, default=4.0, help="Network timeout in seconds.")
    parser.add_argument("--rate-limit", type=float, default=0.15, help="Delay between HTTP path probes.")
    parser.add_argument("--output-dir", default="recon", help="Directory for JSON and Markdown output.")
    parser.add_argument("--sensitive-path", action="append", default=list(DEFAULT_SENSITIVE_PATHS), help="Sensitive path to validate. Can be repeated.")
    parser.add_argument("--cors-path", action="append", default=list(DEFAULT_CORS_PATHS), help="Path to test for CORS reflection. Can be repeated.")
    parser.add_argument("--cors-origin", default="https://evil.com", help="Origin value for CORS validation.")
    parser.add_argument("--version", action="version", version=f"AccurateSurface {VERSION}")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    targets = read_targets(args)
    if not targets:
        parser.error("provide at least one --target or --target-file")

    results = []
    for target in targets:
        print(f"[*] Scanning {target} with conservative checks")
        results.append(scan_target(target, args.ports, args))
    json_path, md_path = write_outputs(results, args.output_dir)
    print(f"[+] JSON: {json_path}")
    print(f"[+] Markdown: {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
