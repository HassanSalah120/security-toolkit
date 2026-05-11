#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""Shared utilities for all security testing tools."""

import os
import sys
import json
import math
import time
import random
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set, Tuple, TypeVar
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# COLOR CONSTANTS
# =============================================================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    @classmethod
    def disable(cls) -> None:
        for attr in dir(cls):
            if not attr.startswith('_') and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, '')

    @classmethod
    def severity_color(cls, severity: str) -> str:
        return {
            'CRITICAL': cls.RED,
            'HIGH': cls.YELLOW,
            'MEDIUM': cls.BLUE,
            'LOW': cls.CYAN,
            'INFO': cls.GREEN,
        }.get(severity.upper(), cls.END)


# =============================================================================
# LOGGING SETUP
# =============================================================================

def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logger.addHandler(handler)
    return logger


# =============================================================================
# HTTP SESSION FACTORY WITH PROXY SUPPORT
# =============================================================================

def make_session(auth_token: Optional[str] = None,
                 auth_type: str = "Bearer",
                 user_agent: Optional[str] = None,
                 verify: bool = False,
                 proxy: Optional[str] = None) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
    })
    if auth_token:
        session.headers.update({'Authorization': f'{auth_type} {auth_token}'})
    session.verify = verify
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    return session


# =============================================================================
# PROXY CLI ARGUMENT
# =============================================================================

def add_proxy_arg(parser) -> None:
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')


# =============================================================================
# OUTPUT HELPERS
# =============================================================================

def ensure_output_dir(base_name: Optional[str] = None) -> str:
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    dir_name = base_name or f"scan_{timestamp}"
    os.makedirs(dir_name, exist_ok=True)
    return dir_name


def save_json(data, filepath: str) -> str:
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, default=str)
    return filepath


def save_report_json(results, output_dir: str, prefix: str = "report") -> str:
    os.makedirs(output_dir, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(output_dir, f"{prefix}_{stamp}.json")
    return save_json(results, path)


# =============================================================================
# VERSION COMPARISON
# =============================================================================

def parse_version(version: str) -> Tuple[int, ...]:
    import re
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts[:4])


def version_less_than(v1: str, v2: str) -> bool:
    try:
        p1 = parse_version(v1)
        p2 = parse_version(v2)
        max_len = max(len(p1), len(p2))
        p1 = p1 + (0,) * (max_len - len(p1))
        p2 = p2 + (0,) * (max_len - len(p2))
        return p1 < p2
    except (ValueError, TypeError):
        return False


def version_greater_than(v1: str, v2: str) -> bool:
    return version_less_than(v2, v1)


# =============================================================================
# SAFE ERROR HANDLING
# =============================================================================

def safe_request(method: str, url: str, session: requests.Session,
                 **kwargs) -> Optional[requests.Response]:
    try:
        return session.request(method, url, **kwargs)
    except requests.RequestException:
        return None


# =============================================================================
# WAF DETECTION
# =============================================================================

WAF_SIGNATURES: List[Tuple[str, List[str], str]] = [
    ('Cloudflare', ['cf-ray', '__cfduid', 'cloudflare-nginx'], 'cloudflare'),
    ('Cloudfront', ['x-amz-cf-id', 'x-amz-cf-pop'], 'aws-cloudfront'),
    ('Akamai', ['akamai-x-cache', 'x-akamai-transformed'], 'akamai'),
    ('AWS WAF', ['x-amzn-requestid', 'x-amzn-errortype'], 'aws-waf'),
    ('F5 BIG-IP ASM', ['x-wa-info', 'x-asm-version', 'x-asm-policy'], 'f5'),
    ('Imperva', ['x-cdn', 'x-iinfo'], 'imperva'),
    ('ModSecurity', ['x-ms-enclave', 'mod_security'], 'modsecurity'),
    ('Sucuri', ['x-sucuri-id', 'x-sucuri-cache'], 'sucuri'),
    ('Barracuda', ['x-barracuda'], 'barracuda'),
    ('Wordfence', ['x-wordfence'], 'wordfence'),
]

WAF_BLOCK_RESPONSES = [
    b'cloudflare-nginx',
    b'attention required',
    b'please enable cookies',
    b'challenge platform',
    b'contact the website owner',
    b'blocked by',
    b'access denied',
    b'waf',
    b'firewall',
]


@dataclass
class WAFResult:
    detected: bool = False
    name: str = ''
    provider: str = ''
    confidence: str = ''
    evidence: str = ''

    def to_dict(self) -> dict:
        return {'detected': self.detected, 'name': self.name,
                'provider': self.provider, 'confidence': self.confidence,
                'evidence': self.evidence}


def detect_waf(url: str, session: Optional[requests.Session] = None) -> WAFResult:
    s = session or make_session()
    try:
        resp = s.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        return WAFResult(detected=False, evidence=f'Request failed: {e}')

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for name, sigs, provider in WAF_SIGNATURES:
        for sig in sigs:
            if sig in headers_lower:
                return WAFResult(detected=True, name=name, provider=provider,
                                 confidence='high',
                                 evidence=f'Header {sig} found in response')

    # Check block-page content
    body = resp.content[:5000].lower()
    for sig in WAF_BLOCK_RESPONSES:
        if sig in body:
            return WAFResult(detected=True, name='Unknown WAF',
                             provider='generic',
                             confidence='medium',
                             evidence=f'Block page signature: {sig.decode()}')

    # Aggressive probe: send SQLi payload and check for different response
    try:
        probe_url = url.rstrip('/') + '/?id=1%27%20OR%201=1--'
        probe_resp = s.get(probe_url, timeout=10, allow_redirects=True)
        if probe_resp.status_code in (403, 406, 501) or len(probe_resp.content) < 100:
            return WAFResult(detected=True, name='Unknown WAF',
                             provider='generic',
                             confidence='low',
                             evidence=f'Suspicious status {probe_resp.status_code} on SQLi probe')
    except requests.RequestException:
        pass

    return WAFResult(detected=False)


# =============================================================================
# THREADING & CONCURRENCY HELPERS
# =============================================================================

T = TypeVar('T')
U = TypeVar('U')


def parallel_map(func: Callable[..., U], items: List[T],
                 max_workers: int = 10, timeout: float = 30,
                 desc: str = 'Processing') -> List[Tuple[T, U]]:
    """Run func on each item in parallel with a progress indicator."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = []
    total = len(items)
    completed = 0
    lock = threading.Lock()

    def wrapped(item):
        try:
            return item, func(item)
        except Exception as e:
            return item, e

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(wrapped, item): item for item in items}
        for future in as_completed(futures, timeout=timeout):
            with lock:
                completed += 1
                sys.stdout.write(f'\r[{desc}] {completed}/{total}')
                sys.stdout.flush()
            results.append(future.result())
    sys.stdout.write('\n')
    return results


@dataclass
class ProgressTracker:
    total: int
    current: int = 0
    start_time: float = field(default_factory=time.time)
    lock: threading.Lock = field(default_factory=threading.Lock)
    label: str = ''

    def advance(self, n: int = 1) -> None:
        with self.lock:
            self.current += n
            elapsed = time.time() - self.start_time
            pct = (self.current / self.total) * 100 if self.total else 0
            rate = self.current / elapsed if elapsed > 0 else 0
            eta = (self.total - self.current) / rate if rate > 0 else 0
            sys.stdout.write(f'\r[{self.label}] {self.current}/{self.total} ({pct:.0f}%) '
                             f'{rate:.1f}/s ETA {eta:.0f}s')
            sys.stdout.flush()

    def done(self) -> None:
        elapsed = time.time() - self.start_time
        sys.stdout.write(f'\r[{self.label}] {self.current}/{self.total} - '
                         f'Done in {elapsed:.1f}s\n')
        sys.stdout.flush()


# =============================================================================
# RESULTS DEDUPLICATION
# =============================================================================

def deduplicate_findings(findings: List[Dict],
                         key_fields: Optional[List[str]] = None) -> List[Dict]:
    seen: Set[str] = set()
    deduped = []
    for f in findings:
        if key_fields:
            key = json.dumps({k: f.get(k) for k in key_fields if k in f}, sort_keys=True)
        else:
            key = json.dumps({k: f.get(k) for k in ('name', 'endpoint', 'url', 'description')
                              if k in f}, sort_keys=True)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


# =============================================================================
# NMAP XML PARSER (IMPORT)
# =============================================================================

def parse_nmap_xml(xml_path: str) -> List[Dict]:
    """Parse Nmap XML into a list of port findings."""
    import xml.etree.ElementTree as ET
    results = []
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, FileNotFoundError) as e:
        return [{'error': str(e)}]

    root = tree.getroot()
    for host in root.findall('host'):
        addr_el = host.find('address')
        addr = addr_el.get('addr') if addr_el is not None else ''
        status = host.find('status')
        if status is not None and status.get('state') != 'up':
            continue
        for port_el in host.findall('.//port'):
            port_num = port_el.get('portid')
            protocol = port_el.get('protocol', 'tcp')
            state_el = port_el.find('state')
            state = state_el.get('state') if state_el is not None else 'unknown'
            service_el = port_el.find('service')
            svc_name = service_el.get('name', '') if service_el is not None else ''
            svc_product = service_el.get('product', '') if service_el is not None else ''
            svc_version = service_el.get('version', '') if service_el is not None else ''
            banner_el = port_el.find('script')
            banner = banner_el.get('output', '') if banner_el is not None else ''

            results.append({
                'host': addr,
                'port': int(port_num),
                'protocol': protocol,
                'state': state,
                'service': svc_name,
                'product': svc_product,
                'version': svc_version,
                'banner': banner,
            })
    return results


# =============================================================================
# TLS CERTIFICATE PARSING
# =============================================================================

def get_tls_cert(host: str, port: int = 443, timeout: float = 5) -> Optional[Dict]:
    """Retrieve and parse TLS certificate from a host."""
    import ssl
    import socket as sock_mod
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with sock_mod.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert(binary_form=False)
                if not cert:
                    return None
                subject = dict(cert.get('subject', [[('CN', '')]])[0])
                issuer = dict(cert.get('issuer', [[('CN', '')]])[0])
                sans = []
                for ext in cert.get('subjectAltName', ()):
                    if ext[0] == 'DNS':
                        sans.append(ext[1])
                return {
                    'subject_cn': subject.get('CN', ''),
                    'issuer_cn': issuer.get('CN', ''),
                    'serial': cert.get('serialNumber', ''),
                    'not_before': cert.get('notBefore', ''),
                    'not_after': cert.get('notAfter', ''),
                    'sans': sans,
                    'version': cert.get('version', ''),
                    'signature_algorithm': cert.get('signatureAlgorithm', ''),
                }
    except Exception:
        return None


# =============================================================================
# CVE CHECK VIA NVD API
# =============================================================================

def check_nvd_cve(product: str, version: str,
                  api_key: Optional[str] = None,
                  proxy: Optional[str] = None) -> List[Dict]:
    """Check NVD API for CVEs matching a product + version."""
    import urllib.parse
    base = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'keywordSearch': f'{product} {version}',
        'resultsPerPage': 20,
    }
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    try:
        sess = make_session(proxy=proxy) if proxy else requests
        resp = sess.get(base, params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            return [{'error': f'NVD API returned {resp.status_code}'}]
        data = resp.json()
        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            metrics = cve.get('metrics', {})
            base_score = None
            for severity_key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                if metrics.get(severity_key):
                    base_score = metrics[severity_key][0].get('cvssData', {}).get('baseScore')
                    break
            cves.append({
                'id': cve.get('id'),
                'description': cve.get('descriptions', [{}])[0].get('value', '')[:200],
                'severity': 'CRITICAL' if (base_score or 0) >= 9.0 else
                            'HIGH' if (base_score or 0) >= 7.0 else
                            'MEDIUM' if (base_score or 0) >= 4.0 else 'LOW',
                'cvss': base_score,
                'url': f'https://nvd.nist.gov/vuln/detail/{cve.get("id")}',
            })
        return cves
    except requests.RequestException as e:
        return [{'error': f'NVD request failed: {e}'}]
