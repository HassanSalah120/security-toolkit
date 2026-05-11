#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
ShadowScanner - Advanced Port Scanner with Service Detection
==============================================================

A professional-grade, multi-threaded port scanner with service fingerprinting,
vulnerability detection, and comprehensive reporting capabilities.

Author: Security Research Team
Version: 1.1.0
License: MIT

Features:
    - Multi-threaded TCP connect scanning
    - Service banner grabbing with protocol-specific probes
    - Version-based vulnerability detection
    - UDP scanning capability
    - Host discovery (ping sweep)
    - TLS certificate parsing
    - NVD CVE checking
    - Nmap XML import
    - WAF detection
    - OS fingerprinting hints
    - JSON and HTML report generation
    - Colored terminal output with progress indicators

Usage:
    python shadow_scanner.py -t 192.168.1.1
    python shadow_scanner.py -t example.com -p 1-65535 -T 200 --vuln -o scan.json
    python shadow_scanner.py -t 10.0.0.1 -p 80,443,8080,3306 --html -v
    python shadow_scanner.py -t target.com --udp --nvd --nvd-api-key YOURKEY
    python shadow_scanner.py --import-nmap scan.xml

Requirements:
    - Python 3.8+
    - Requires: `requests` library for NVD API calls
"""

import argparse
import concurrent.futures
import json
import os
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from common import Colors, version_less_than, version_greater_than, \
    get_tls_cert, check_nvd_cve, parse_nmap_xml, detect_waf, make_session, add_proxy_arg

# Version information
__version__ = "1.1.0"
__author__ = "Security Research Team"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class PortResult:
    """Represents the result of scanning a single port."""
    port: int
    state: str  # 'open', 'closed', 'filtered'
    protocol: str  # 'tcp', 'udp'
    service: str = 'unknown'
    version: str = ''
    banner: str = ''
    ttl: Optional[int] = None
    vulnerabilities: List[Dict] = field(default_factory=list)
    waf: Optional[Dict] = None
    tls_cert: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        d = {
            'port': self.port,
            'state': self.state,
            'protocol': self.protocol,
            'service': self.service,
            'version': self.version,
            'banner': self.banner[:500] if self.banner else '',  # Truncate for safety
            'ttl': self.ttl,
            'vulnerabilities': self.vulnerabilities,
        }
        if self.waf:
            d['waf'] = self.waf
        if self.tls_cert:
            d['tls_certificate'] = self.tls_cert
        return d


@dataclass
class ScanResult:
    """Complete scan results for a target."""
    target: str
    scan_time: str
    duration: float
    ports_scanned: int
    open_ports: List[PortResult] = field(default_factory=list)
    os_guess: str = 'unknown'
    scan_type: str = 'tcp'

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'target': self.target,
            'scan_time': self.scan_time,
            'duration_seconds': round(self.duration, 2),
            'ports_scanned': self.ports_scanned,
            'open_ports_count': len(self.open_ports),
            'os_guess': self.os_guess,
            'scan_type': self.scan_type,
            'open_ports': [p.to_dict() for p in self.open_ports]
        }


# =============================================================================
# VULNERABILITY DATABASE
# =============================================================================

class VulnDatabase:
    """Built-in vulnerability database for version matching."""

    # Known vulnerable versions and their CVEs
    VULNERABILITIES = {
        'vsftpd': [
            {'version': '2.3.4', 'cve': 'CVE-2011-2523', 'severity': 'CRITICAL',
             'description': 'Backdoor in vsftpd 2.3.4, malicious backdoor opens port 6200'},
        ],
        'apache': [
            {'version': '<2.4.50', 'cve': 'CVE-2021-41773', 'severity': 'HIGH',
             'description': 'Path traversal and file disclosure vulnerability'},
            {'version': '<2.4.49', 'cve': 'CVE-2021-41524', 'severity': 'HIGH',
             'description': 'Path traversal vulnerability'},
        ],
        'httpd': [
            {'version': '<2.4.50', 'cve': 'CVE-2021-41773', 'severity': 'HIGH',
             'description': 'Path traversal and file disclosure vulnerability'},
        ],
        'openssh': [
            {'version': '<8.0', 'cve': 'CVE-2018-15473', 'severity': 'MEDIUM',
             'description': 'User enumeration via timing attack'},
            {'version': '<7.7', 'cve': 'CVE-2018-15473', 'severity': 'MEDIUM',
             'description': 'User enumeration vulnerability'},
            {'version': '<6.9', 'cve': 'CVE-2016-0777', 'severity': 'HIGH',
             'description': 'Roaming vulnerability, information leak'},
        ],
        'ssh': [
            {'version': '<8.0', 'cve': 'CVE-2018-15473', 'severity': 'MEDIUM',
             'description': 'User enumeration via timing attack'},
        ],
        'mysql': [
            {'version': '5.0', 'cve': 'CVE-2006-0903', 'severity': 'HIGH',
             'description': 'Authentication bypass, multiple vulnerabilities'},
            {'version': '5.1', 'cve': 'CVE-2010-3677', 'severity': 'MEDIUM',
             'description': 'Multiple vulnerabilities in 5.1.x versions'},
            {'version': '5.5', 'cve': 'CVE-2012-5611', 'severity': 'HIGH',
             'description': 'Stack-based buffer overflow'},
            {'version': '5.6', 'cve': 'CVE-2013-1861', 'severity': 'MEDIUM',
             'description': 'Multiple vulnerabilities in 5.6.x'},
        ],
        'mariadb': [
            {'version': '<10.3', 'cve': 'CVE-2021-27928', 'severity': 'HIGH',
             'description': 'Remote code execution via wsrep_provider'},
        ],
        'redis': [
            {'version': '<5.0', 'cve': 'CVE-2018-11219', 'severity': 'MEDIUM',
             'description': 'Integer overflow in hyperloglog'},
            {'version': '<4.0', 'cve': 'CVE-2018-12453', 'severity': 'HIGH',
             'description': 'Authenticated RCE via Lua scripting'},
        ],
        'tomcat': [
            {'version': '<9.0.44', 'cve': 'CVE-2021-25329', 'severity': 'HIGH',
             'description': 'Remote code execution via JSP uploading'},
            {'version': '<8.5.66', 'cve': 'CVE-2021-33037', 'severity': 'MEDIUM',
             'description': 'Request mix-up vulnerability'},
        ],
        'nginx': [
            {'version': '<1.20', 'cve': 'CVE-2021-23017', 'severity': 'HIGH',
             'description': 'DNS resolver vulnerability, 1-byte memory overwrite'},
            {'version': '<1.18', 'cve': 'CVE-2020-12440', 'severity': 'MEDIUM',
             'description': 'Information disclosure vulnerability'},
        ],
        'openwebui': [
            {'version': '0.6.22', 'cve': 'CVE-2025-64496', 'severity': 'HIGH',
             'description': 'Account takeover via malicious model connections'},
        ],
        # MinIO CVEs are version/configuration specific. Do not flag every
        # MinIO banner as vulnerable; use tools/accurate_surface_scanner.py
        # for evidence-based MinIO checks.
        'minio': [],
        'wordpress': [
            {'version': '<5.8', 'cve': 'CVE-2021-44223', 'severity': 'HIGH',
             'description': 'SQL injection in WP_Query'},
        ],
        'php': [
            {'version': '<8.0', 'cve': 'CVE-2019-11043', 'severity': 'CRITICAL',
             'description': 'Remote code execution in PHP-FPM (PHPAUTHCHECK)'},
            {'version': '<7.4', 'cve': 'CVE-2019-11043', 'severity': 'CRITICAL',
             'description': 'Remote code execution in PHP-FPM'},
        ],
        'exim': [
            {'version': '<4.93', 'cve': 'CVE-2019-15846', 'severity': 'CRITICAL',
             'description': 'Remote command execution via TLS SNI'},
        ],
        'proftpd': [
            {'version': '<1.3.7a', 'cve': 'CVE-2020-9272', 'severity': 'HIGH',
             'description': 'Use-after-free vulnerability'},
        ],
        'postfix': [
            {'version': '<3.5', 'cve': 'CVE-2020-12271', 'severity': 'MEDIUM',
             'description': 'Information disclosure vulnerability'},
        ],
    }

    @classmethod
    def check_vulnerabilities(cls, service: str, version: str) -> List[Dict]:
        """Check if a service version has known vulnerabilities.

        Args:
            service: Service name (lowercase)
            version: Version string

        Returns:
            List of matching vulnerabilities
        """
        vulns = []
        service_lower = service.lower()

        if service_lower not in cls.VULNERABILITIES:
            return vulns

        for vuln in cls.VULNERABILITIES[service_lower]:
            vuln_version = vuln['version']

            # Exact version match
            if vuln_version == version:
                vulns.append(vuln)
            # Less than version (simplified comparison)
            elif vuln_version.startswith('<') and cls._version_less_than(version, vuln_version[1:]):
                vulns.append(vuln)
            # Greater than version
            elif vuln_version.startswith('>') and cls._version_greater_than(version, vuln_version[1:]):
                vulns.append(vuln)
            # Wildcard match
            elif vuln_version == 'any':
                vulns.append(vuln)
            # Prefix match (e.g., "5.0" matches "5.0.95")
            elif version.startswith(vuln_version):
                vulns.append(vuln)

        return vulns

    @staticmethod
    def _version_less_than(v1: str, v2: str) -> bool:
        return version_less_than(v1, v2)

    @staticmethod
    def _version_greater_than(v1: str, v2: str) -> bool:
        return version_greater_than(v1, v2)


# =============================================================================
# SERVICE PROBES
# =============================================================================

class ServiceProbes:
    """Protocol-specific probes for service detection."""

    # Common ports and their expected services
    COMMON_SERVICES = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
        67: 'dhcp', 68: 'dhcp', 69: 'tftp', 80: 'http', 110: 'pop3',
        111: 'rpcbind', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns',
        139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 162: 'snmp-trap',
        443: 'https', 445: 'microsoft-ds', 500: 'isakmp', 514: 'syslog',
        520: 'rip', 631: 'ipp', 993: 'imaps', 995: 'pop3s',
        1434: 'ms-sql-m', 1723: 'pptp', 1900: 'upnp', 3306: 'mysql',
        3389: 'ms-wbt-server', 4500: 'nat-t', 5353: 'mdns', 5432: 'postgresql',
        5900: 'vnc', 6379: 'redis', 8080: 'http-proxy',
        8443: 'https-alt', 9000: 'minio', 9200: 'elasticsearch',
        27017: 'mongodb', 5000: 'upnp', 8000: 'http-alt', 8008: 'http',
        8888: 'sun-answerbook', 10000: 'webmin', 11211: 'memcached',
        27018: 'mongodb', 27019: 'mongodb', 28017: 'mongodb', 27020: 'mongodb',
    }

    @staticmethod
    def get_probe(port: int) -> bytes:
        """Get the appropriate probe for a port."""
        probes = {
            80: b'GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: ShadowScanner/1.0\r\nAccept: */*\r\n\r\n',
            443: b'GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: ShadowScanner/1.0\r\nAccept: */*\r\n\r\n',
            8080: b'GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: ShadowScanner/1.0\r\nAccept: */*\r\n\r\n',
            21: b'',  # Wait for banner
            22: b'',  # Wait for banner
            25: b'EHLO target\r\n',
            110: b'',  # Wait for banner
            143: b'',  # Wait for banner
            3306: b'\x00',  # MySQL initial packet
            6379: b'PING\r\n',
            5432: b'\x00\x00\x00\x08\x04\xd2\x16\x2f',
        }
        return probes.get(port, b'\x00')

    @staticmethod
    def parse_response(port: int, data: bytes) -> Tuple[str, str]:
        """Parse service response to identify service and version."""
        if not data:
            return ServiceProbes.COMMON_SERVICES.get(port, 'unknown'), ''

        try:
            text = data.decode('utf-8', errors='ignore').lower()
        except Exception:
            text = ''

        # HTTP detection
        if b'HTTP/' in data or b'http' in text[:20]:
            return ServiceProbes._parse_http(data)

        # SSH detection
        if b'SSH-' in data or 'ssh' in text[:20]:
            return ServiceProbes._parse_ssh(text)

        # FTP detection
        if b'FTP' in data or 'ftp' in text[:20]:
            return ServiceProbes._parse_ftp(text)

        # SMTP detection
        if b'220' in data and ('smtp' in text or 'esmtp' in text):
            return ServiceProbes._parse_smtp(text)

        # Redis detection
        if b'+PONG' in data or b'$-1' in data:
            return 'redis', ''

        # MySQL detection - proper handshake parsing
        if len(data) > 4 and data[0] == 0x0a:
            null_idx = data.find(b'\x00', 1)
            if null_idx > 1:
                version_str = data[1:null_idx].decode('utf-8', errors='ignore')
                if re.search(r'\d+\.\d+\.\d+', version_str):
                    return 'mysql', version_str

        # MinIO detection
        if b'MinIO' in data or b'AccessDenied' in data:
            return 'minio', ''

        # Open WebUI detection
        if b'Open WebUI' in data or b'open-webui' in text:
            return 'openwebui', ''

        return ServiceProbes.COMMON_SERVICES.get(port, 'unknown'), ''

    @staticmethod
    def _parse_http(data: bytes) -> Tuple[str, str]:
        """Parse HTTP response."""
        try:
            text = data.decode('utf-8', errors='ignore')
            server = ''

            for line in text.split('\r\n'):
                if line.lower().startswith('server:'):
                    server = line.split(':', 1)[1].strip()
            # Extract version from Server header
            version = ''
            if server:
                # Match version patterns like Apache/2.4.41, nginx/1.18.0
                match = re.search(r'(\d+\.\d+(?:\.\d+)?)', server)
                if match:
                    version = match.group(1)

                service = 'apache' if 'apache' in server.lower() else \
                         'nginx' if 'nginx' in server.lower() else \
                         'openresty' if 'openresty' in server.lower() else \
                         'http'

                return service, version

            return 'http', ''
        except Exception:
            return 'http', ''

    @staticmethod
    def _parse_ssh(text: str) -> Tuple[str, str]:
        """Parse SSH banner."""
        # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15
        match = re.search(r'ssh-(\d+\.\d+)-(\S+)', text, re.IGNORECASE)
        if match:
            software = match.group(2)
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', software)
            version = version_match.group(1) if version_match else ''
            return 'openssh', version
        return 'ssh', ''

    @staticmethod
    def _parse_ftp(text: str) -> Tuple[str, str]:
        """Parse FTP banner."""
        # 220 vsftpd 3.0.3
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', text)
        version = match.group(1) if match else ''

        if 'vsftpd' in text:
            return 'vsftpd', version
        elif 'proftpd' in text:
            return 'proftpd', version
        elif 'pure-ftpd' in text:
            return 'pure-ftpd', version
        return 'ftp', version

    @staticmethod
    def _parse_smtp(text: str) -> Tuple[str, str]:
        """Parse SMTP banner."""
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', text)
        version = match.group(1) if match else ''

        if 'postfix' in text:
            return 'postfix', version
        elif 'exim' in text:
            return 'exim', version
        elif 'sendmail' in text:
            return 'sendmail', version
        return 'smtp', version


# =============================================================================
# PORT SCANNER CLASS
# =============================================================================

class ShadowScanner:
    """Main port scanner class with multi-threaded scanning capabilities."""

    def __init__(self, target: str, ports: List[int], threads: int = 100,
                 timeout: float = 2.0, verbose: bool = False,
                 grab_banner: bool = True, check_vulns: bool = False,
                 scan_udp: bool = False, no_ping: bool = False,
                 check_nvd: bool = False,
                 nvd_api_key: Optional[str] = None,
                 proxy: Optional[str] = None):
        """Initialize the scanner.

        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            threads: Number of concurrent threads
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            grab_banner: Enable banner grabbing
            check_vulns: Check for vulnerabilities
            scan_udp: Include UDP scan
            no_ping: Skip host discovery ping sweep
            check_nvd: Check NVD database for CVEs
            nvd_api_key: API key for NVD (optional)
        """
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.grab_banner = grab_banner
        self.check_vulns = check_vulns
        self.scan_udp = scan_udp
        self.no_ping = no_ping
        self.check_nvd = check_nvd
        self.nvd_api_key = nvd_api_key
        self.proxy = proxy

        self.results: List[PortResult] = []
        self.scanned = 0
        self.total_ports = len(ports)
        self.tls_certificates: Dict[int, Dict] = {}
        self.waf_results: Dict[int, Dict] = {}

    def _resolve_target(self) -> str:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            print(f"{Colors.RED}[!] Could not resolve {self.target}{Colors.END}")
            sys.exit(1)

    def _scan_port_tcp(self, port: int) -> Optional[PortResult]:
        """Scan a single TCP port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))

                if result == 0:
                    # Port is open
                    service, version = ServiceProbes.COMMON_SERVICES.get(port, 'unknown'), ''
                    banner = ''
                    ttl = None

                    if self.grab_banner:
                        try:
                            # Get TTL from socket options (Linux only)
                            try:
                                ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                            except Exception:
                                pass

                            # Send probe and receive banner
                            probe = ServiceProbes.get_probe(port)
                            if probe:
                                sock.send(probe)

                            sock.settimeout(1.0)
                            data = sock.recv(1024)

                            if data:
                                service, version = ServiceProbes.parse_response(port, data)
                                banner = data.decode('utf-8', errors='ignore').strip()

                        except Exception as e:
                            if self.verbose:
                                print(f"{Colors.YELLOW}[!] Banner grab failed on {port}: {e}{Colors.END}")

                    vulnerabilities = []
                    if self.check_vulns and service != 'unknown':
                        vulnerabilities = VulnDatabase.check_vulnerabilities(service, version)

                    return PortResult(
                        port=port,
                        state='open',
                        protocol='tcp',
                        service=service,
                        version=version,
                        banner=banner,
                        ttl=ttl,
                        vulnerabilities=vulnerabilities
                    )

        except socket.timeout:
            pass
        except Exception as e:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] Error scanning port {port}: {e}{Colors.END}")

        return None

    def _scan_port_udp(self, port: int) -> Optional[PortResult]:
        """Scan a single UDP port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)

                # Send appropriate probe
                probes = {
                    53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03',
                    123: b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00',
                    161: b'\x30\x26\x02\x01\x00\x04\x06public\xa1\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',
                }

                probe = probes.get(port, b'\x00')
                sock.sendto(probe, (self.target, port))

                data, addr = sock.recvfrom(1024)

                if data:
                    service = ServiceProbes.COMMON_SERVICES.get(port, 'unknown')
                    return PortResult(
                        port=port,
                        state='open',
                        protocol='udp',
                        service=service,
                        version='',
                        banner=data[:100].hex() if self.verbose else '',
                        ttl=None,
                        vulnerabilities=[]
                    )

        except socket.timeout:
            pass
        except Exception:
            pass

        return None

    def scan_udp(self) -> List[PortResult]:
        """Scan common UDP ports using protocol-specific probes.

        Uses _scan_port_udp for ports with custom probes (DNS, NTP, SNMP)
        and falls back to empty probes for the remaining common UDP ports.

        Returns:
            List of PortResult for open UDP ports
        """
        udp_ports = [53, 67, 68, 123, 161, 162, 500, 514, 520, 1900, 4500, 5353]
        results = []
        print(f"\n{Colors.YELLOW}[*] Starting UDP scan ({len(udp_ports)} ports)...{Colors.END}")

        specific_probe_ports = {53, 123, 161}

        for port in udp_ports:
            if port in specific_probe_ports:
                result = self._scan_port_udp(port)
                if result:
                    results.append(result)
                    self._print_port_result(result)
            else:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.settimeout(self.timeout)
                        # Send empty probe
                        sock.sendto(b'', (self.target, port))
                        data, addr = sock.recvfrom(1024)
                        if data:
                            service = ServiceProbes.COMMON_SERVICES.get(port, 'unknown')
                            result = PortResult(
                                port=port,
                                state='open',
                                protocol='udp',
                                service=service,
                                version='',
                                banner=data[:100].hex() if self.verbose else '',
                                ttl=None,
                                vulnerabilities=[]
                            )
                            results.append(result)
                            self._print_port_result(result)
                except socket.timeout:
                    pass
                except Exception:
                    pass

        return results

    def ping_sweep(self) -> bool:
        """Check if target is alive before full scanning.

        Uses multiple methods:
            1. TCP connect probes to common ports (80, 443, 22, 25, 445)
            2. ICMP echo request (may require admin privileges)
            3. DNS resolution

        Returns:
            True if target appears alive, False otherwise
        """
        if self.verbose:
            print(f"{Colors.CYAN}[*] Ping sweep: checking {self.target}...{Colors.END}")

        # Method 1: TCP connect to common ports
        probe_ports = [80, 443, 22, 25, 445, 3389, 8080, 8443]
        for port in probe_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((self.target, port)) == 0:
                        if self.verbose:
                            print(f"{Colors.GREEN}[+] Host responded on TCP port {port}{Colors.END}")
                        return True
            except Exception:
                pass

        # Method 2: ICMP echo request
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.settimeout(self.timeout)
                # Craft ICMP echo request (type=8, code=0)
                packet_id = os.getpid() & 0xFFFF
                header = struct.pack('!BBHHH', 8, 0, 0, packet_id, 1)
                # Calculate checksum
                if len(header) % 2 != 0:
                    header += b'\x00'
                checksum = 0
                for i in range(0, len(header), 2):
                    checksum += (header[i] << 8) + header[i + 1]
                checksum = (checksum >> 16) + (checksum & 0xFFFF)
                checksum = ~checksum & 0xFFFF
                packet = struct.pack('!BBHHH', 8, 0, checksum, packet_id, 1)
                sock.sendto(packet, (self.target, 1))
                data, addr = sock.recvfrom(1024)
                if data:
                    if self.verbose:
                        print(f"{Colors.GREEN}[+] Host responded to ICMP echo{Colors.END}")
                    return True
        except PermissionError:
            if self.verbose:
                print(f"{Colors.YELLOW}[!] ICMP requires admin privileges, skipping{Colors.END}")
        except Exception:
            pass

        return False

    def get_tls_certificate(self, port: int = 443) -> Optional[Dict]:
        """Retrieve and parse TLS certificate from an HTTPS port.

        Args:
            port: Port number (default: 443)

        Returns:
            Dict with cert info (CN, issuer, SANs, expiry) or None
        """
        cert = get_tls_cert(self.target, port, self.timeout)
        if cert and self.verbose:
            print(f"{Colors.CYAN}[*] TLS cert on {port}: CN={cert.get('subject_cn','')}, "
                  f"issuer={cert.get('issuer_cn','')}, "
                  f"SANs={len(cert.get('sans',[]))} entries{Colors.END}")
        return cert

    def check_nvd_cves(self) -> None:
        """Query NVD API for CVEs matching detected service versions.

        Iterates over all open port results and checks the NVD database
        for known vulnerabilities matching each service and version.
        Results are appended to each port's vulnerabilities list.
        """
        checked = 0
        for result in self.results:
            if result.service != 'unknown' and result.version:
                if self.verbose:
                    print(f"{Colors.CYAN}[*] Checking NVD: {result.service} {result.version}{Colors.END}")
                cves = check_nvd_cve(result.service, result.version, self.nvd_api_key, proxy=self.proxy)
                if cves:
                    # Filter out error entries
                    real_cves = [c for c in cves if 'error' not in c]
                    if real_cves:
                        existing_ids = {v.get('cve', v.get('id', '')) for v in result.vulnerabilities}
                        new_cves = [c for c in real_cves if c.get('cve', c.get('id', '')) not in existing_ids]
                        result.vulnerabilities.extend(new_cves)
                        if self.verbose:
                            print(f"{Colors.RED}[!] Found {len(real_cves)} NVD CVEs for "
                                  f"{result.service} {result.version} on port {result.port}{Colors.END}")
                checked += 1

        if self.verbose:
            print(f"{Colors.GREEN}[+] NVD check complete: {checked} services checked{Colors.END}")

    @classmethod
    def import_nmap_xml(cls, xml_path: str) -> 'ScanResult':
        """Import scan results from an Nmap XML file.

        Uses parse_nmap_xml from common to parse the file and
        populates a ScanResult object from the parsed data.

        Args:
            xml_path: Path to Nmap XML file

        Returns:
            ScanResult populated with imported data
        """
        if not os.path.exists(xml_path):
            print(f"{Colors.RED}[!] Nmap XML file not found: {xml_path}{Colors.END}")
            sys.exit(1)

        data = parse_nmap_xml(xml_path)

        if not data:
            print(f"{Colors.YELLOW}[!] No parseable data in {xml_path}{Colors.END}")
            return ScanResult(
                target='unknown',
                scan_time=datetime.now().isoformat(),
                duration=0.0,
                ports_scanned=0,
                scan_type='import'
            )

        target = data[0].get('host', 'unknown')
        open_ports = []
        for entry in data:
            if 'error' in entry:
                print(f"{Colors.YELLOW}[!] Skipping malformed entry: {entry['error']}{Colors.END}")
                continue
            service = entry.get('service', '') or entry.get('product', '')
            port = PortResult(
                port=entry['port'],
                state=entry['state'],
                protocol=entry.get('protocol', 'tcp'),
                service=service,
                version=entry.get('version', ''),
                banner=entry.get('banner', '')
            )
            open_ports.append(port)

        result = ScanResult(
            target=target,
            scan_time=datetime.now().isoformat(),
            duration=0.0,
            ports_scanned=len(data),
            open_ports=open_ports,
            scan_type='import'
        )

        print(f"{Colors.GREEN}[+] Imported {len(open_ports)} ports from {xml_path}{Colors.END}")
        print(f"{Colors.GREEN}[+] Target:{Colors.END} {target}")

        return result

    def _progress_callback(self, future):
        """Update progress bar."""
        self.scanned += 1
        if not self.verbose and sys.stdout.isatty():
            progress = (self.scanned / self.total_ports) * 100
            bar_length = 50
            filled = int(bar_length * self.scanned / self.total_ports)
            bar = '█' * filled + '-' * (bar_length - filled)
            sys.stdout.write(f'\r{Colors.CYAN}[*] Progress: |{bar}| {progress:.1f}% ({self.scanned}/{self.total_ports}){Colors.END}')
            sys.stdout.flush()

    def scan(self) -> ScanResult:
        """Execute the port scan.

        Returns:
            ScanResult object containing all findings
        """
        start_time = time.time()
        target_ip = self._resolve_target()

        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}  ShadowScanner v{__version__}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.END}\n")

        print(f"{Colors.GREEN}[+] Target:{Colors.END} {self.target} ({target_ip})")
        print(f"{Colors.GREEN}[+] Ports:{Colors.END} {len(self.ports)} ports to scan")
        print(f"{Colors.GREEN}[+] Threads:{Colors.END} {self.threads}")
        print(f"{Colors.GREEN}[+] Timeout:{Colors.END} {self.timeout}s")
        print(f"{Colors.GREEN}[+] Banner Grab:{Colors.END} {'Enabled' if self.grab_banner else 'Disabled'}")
        print(f"{Colors.GREEN}[+] Vuln Check:{Colors.END} {'Enabled' if self.check_vulns else 'Disabled'}")
        print(f"{Colors.GREEN}[+] Host Discovery:{Colors.END} {'Disabled' if self.no_ping else 'Enabled'}")
        if self.scan_udp:
            print(f"{Colors.GREEN}[+] UDP Scan:{Colors.END} Enabled")
        if self.nvd_api_key:
            print(f"{Colors.GREEN}[+] NVD API:{Colors.END} Configured")
        print()

        # Host discovery phase
        if not self.no_ping:
            print(f"{Colors.YELLOW}[*] Host discovery: checking if {self.target} is alive...{Colors.END}")
            if not self.ping_sweep():
                print(f"{Colors.RED}[!] Target {self.target} appears to be down (no response to probes).{Colors.END}")
                print(f"{Colors.YELLOW}[!] Use --no-ping to skip host discovery and scan anyway.{Colors.END}")
                duration = time.time() - start_time
                scan_result = ScanResult(
                    target=self.target,
                    scan_time=datetime.now().isoformat(),
                    duration=duration,
                    ports_scanned=0,
                    open_ports=[],
                    os_guess='unknown',
                    scan_type='tcp'
                )
                self._print_summary(scan_result)
                return scan_result
            else:
                print(f"{Colors.GREEN}[+] Target {self.target} is alive.{Colors.END}\n")
        else:
            if self.verbose:
                print(f"{Colors.YELLOW}[*] Host discovery skipped (--no-ping){Colors.END}\n")

        print(f"{Colors.YELLOW}[*] Starting TCP scan...{Colors.END}\n")

        # TCP Scan
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self._scan_port_tcp, port): port
                for port in self.ports
            }

            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    self.results.append(result)
                    self._print_port_result(result)
                self._progress_callback(future)

        # WAF detection on HTTP/HTTPS ports
        http_ports = []
        for result in self.results:
            if result.service in ('http', 'https', 'apache', 'nginx', 'httpd',
                                  'openresty', 'http-proxy', 'https-alt'):
                http_ports.append(result)

        if http_ports:
            if self.verbose:
                print(f"\n{Colors.YELLOW}[*] Detecting WAF on {len(http_ports)} HTTP port(s)...{Colors.END}")
            for result in http_ports:
                scheme = 'https' if result.port in (443, 8443) or 'https' in result.service else 'http'
                url = f"{scheme}://{self.target}:{result.port}/"
                try:
                    sess = make_session(proxy=self.proxy) if self.proxy else None
                    waf_result = detect_waf(url, sess)
                    if waf_result.detected:
                        result.waf = {
                            'name': waf_result.name,
                            'provider': waf_result.provider,
                            'confidence': waf_result.confidence,
                            'evidence': waf_result.evidence
                        }
                        self.waf_results[result.port] = result.waf
                        print(f"{Colors.MAGENTA}[!] WAF Detected on port {result.port}: "
                              f"{waf_result.name} ({waf_result.confidence}){Colors.END}")
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.YELLOW}[!] WAF detection failed on {result.port}: {e}{Colors.END}")

        # TLS certificate extraction on HTTPS ports
        tls_ports = [r for r in self.results if r.port in (443, 8443, 465, 993, 995)
                     or r.service in ('https', 'https-alt', 'imaps', 'pop3s')]
        if tls_ports:
            if self.verbose:
                print(f"\n{Colors.YELLOW}[*] Retrieving TLS certificates from {len(tls_ports)} port(s)...{Colors.END}")
            for result in tls_ports:
                cert = self.get_tls_certificate(result.port)
                if cert:
                    result.tls_cert = cert
                    self.tls_certificates[result.port] = cert
                    if self.verbose:
                        print(f"{Colors.CYAN}[+] TLS cert on {result.port}: "
                              f"CN={cert.get('subject_cn','')}, "
                              f"Issuer={cert.get('issuer_cn','')}{Colors.END}")

        # UDP Scan (if enabled)
        if self.scan_udp:
            udp_results = self.scan_udp()
            self.results.extend(udp_results)

        # NVD CVE check for services with versions
        if self.check_nvd:
            print(f"\n{Colors.YELLOW}[*] Checking NVD for CVEs...{Colors.END}")
            self.check_nvd_cves()

        duration = time.time() - start_time

        if not self.verbose:
            print()  # New line after progress bar

        # OS fingerprinting guess based on TTL
        os_guess = self._guess_os()

        # Sort results by port number
        self.results.sort(key=lambda x: x.port)

        scan_result = ScanResult(
            target=self.target,
            scan_time=datetime.now().isoformat(),
            duration=duration,
            ports_scanned=self.total_ports,
            open_ports=self.results,
            os_guess=os_guess,
            scan_type='tcp-udp' if self.scan_udp else 'tcp'
        )

        self._print_summary(scan_result)

        return scan_result

    def _print_port_result(self, result: PortResult) -> None:
        """Print a single port result to terminal."""
        protocol_color = Colors.CYAN if result.protocol == 'tcp' else Colors.MAGENTA
        service_str = f"{Colors.YELLOW}{result.service}{Colors.END}"

        if result.version:
            service_str += f" {Colors.WHITE}{result.version}{Colors.END}"

        if result.tls_cert and 'sans' in result.tls_cert:
            service_str += f" {Colors.CYAN}[TLS]{Colors.END}"

        vuln_indicator = ""
        if result.vulnerabilities:
            critical = any(v['severity'] == 'CRITICAL' for v in result.vulnerabilities)
            high = any(v['severity'] == 'HIGH' for v in result.vulnerabilities)
            if critical:
                vuln_indicator = f" {Colors.RED}[!]{Colors.END}"
            elif high:
                vuln_indicator = f" {Colors.YELLOW}[!]{Colors.END}"

        waf_indicator = ""
        if result.waf:
            waf_indicator = f" {Colors.MAGENTA}[WAF]{Colors.END}"

        print(f"{Colors.GREEN}[+]{Colors.END} {protocol_color}{result.port}/{result.protocol}{Colors.END} "
              f"{Colors.GREEN}open{Colors.END}  {service_str}{vuln_indicator}{waf_indicator}")

        if result.banner and self.verbose:
            banner_preview = result.banner[:80].replace('\n', ' ').replace('\r', '')
            print(f"    {Colors.CYAN}Banner:{Colors.END} {banner_preview}")

        if result.waf and self.verbose:
            print(f"    {Colors.MAGENTA}WAF:{Colors.END} {result.waf['name']} "
                  f"({result.waf['confidence']}) - {result.waf['evidence'][:80]}")

        if result.tls_cert and self.verbose:
            cert = result.tls_cert
            print(f"    {Colors.CYAN}TLS Cert:{Colors.END} CN={cert.get('subject_cn','')}, "
                  f"Issuer={cert.get('issuer_cn','')}")
            if cert.get('sans'):
                print(f"    {Colors.CYAN}SANs:{Colors.END} {', '.join(cert['sans'][:5])}"
                      f"{'...' if len(cert['sans']) > 5 else ''}")
            if cert.get('not_after'):
                print(f"    {Colors.CYAN}Expires:{Colors.END} {cert['not_after']}")

        if result.vulnerabilities and self.verbose:
            for vuln in result.vulnerabilities:
                severity_color = Colors.RED if vuln['severity'] == 'CRITICAL' else \
                               Colors.YELLOW if vuln['severity'] == 'HIGH' else \
                               Colors.YELLOW
                print(f"    {severity_color}[!] {vuln.get('cve', vuln.get('id',''))} - {vuln['severity']}{Colors.END}")
                print(f"        {vuln.get('description', '')[:120]}")

    def _guess_os(self) -> str:
        """Guess OS based on TTL values from responses."""
        ttls = [r.ttl for r in self.results if r.ttl is not None]

        if not ttls:
            return 'unknown'

        avg_ttl = sum(ttls) / len(ttls)

        # Common TTL values by OS
        if 60 <= avg_ttl <= 64:
            return 'Linux/Unix (likely)'
        elif 120 <= avg_ttl <= 128:
            return 'Windows (likely)'
        elif 250 <= avg_ttl <= 255:
            return 'Cisco/BSD/macOS (likely)'

        return 'unknown'

    def _print_summary(self, result: ScanResult) -> None:
        """Print scan summary."""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}  SCAN SUMMARY{Colors.END}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.END}\n")

        print(f"{Colors.GREEN}[+] Scan Duration:{Colors.END} {result.duration:.2f} seconds")
        print(f"{Colors.GREEN}[+] Ports Scanned:{Colors.END} {result.ports_scanned}")
        print(f"{Colors.GREEN}[+] Open Ports:{Colors.END} {len(result.open_ports)}")
        print(f"{Colors.GREEN}[+] OS Guess:{Colors.END} {result.os_guess}")

        if self.tls_certificates:
            print(f"{Colors.GREEN}[+] TLS Certs Retrieved:{Colors.END} {len(self.tls_certificates)}")

        if self.waf_results:
            waf_names = ', '.join(f"Port {p}: {w['name']}" for p, w in self.waf_results.items())
            print(f"{Colors.MAGENTA}[!] WAF Detected:{Colors.END} {waf_names}")

        if any(r.vulnerabilities for r in result.open_ports):
            vuln_count = sum(len(r.vulnerabilities) for r in result.open_ports)
            print(f"\n{Colors.RED}[!] Vulnerabilities Found: {vuln_count}{Colors.END}")

        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.END}\n")


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """Generate output reports in various formats."""

    @staticmethod
    def save_json(result: ScanResult, filepath: str) -> None:
        """Save scan results to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"{Colors.GREEN}[+] JSON report saved to:{Colors.END} {filepath}")

    @staticmethod
    def generate_html(result: ScanResult) -> str:
        """Generate HTML report with dark theme."""
        vuln_count = sum(len(p.vulnerabilities) for p in result.open_ports)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowScanner Report - {result.target}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #238636;
            --accent-yellow: #f0883e;
            --accent-red: #da3633;
            --accent-cyan: #39d0d8;
            --accent-blue: #58a6ff;
            --accent-magenta: #bc8cff;
            --border-color: #30363d;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            text-align: center;
            padding: 3rem 0;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 2rem;
        }}

        .logo {{
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}

        .card-value {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-cyan);
        }}

        .card-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }}

        .card.danger .card-value {{
            color: var(--accent-red);
        }}

        .card.warning .card-value {{
            color: var(--accent-yellow);
        }}

        section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 2rem;
            overflow: hidden;
        }}

        .section-header {{
            background: var(--bg-tertiary);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            color: var(--accent-cyan);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .section-content {{
            padding: 1.5rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95rem;
        }}

        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }}

        tr:hover {{
            background: var(--bg-tertiary);
        }}

        .port-open {{
            color: var(--accent-green);
            font-weight: 600;
        }}

        .port-udp {{
            color: var(--accent-cyan);
        }}

        .severity-critical {{
            background: var(--accent-red);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .severity-high {{
            background: var(--accent-yellow);
            color: #000;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .severity-medium {{
            background: #f1e05a;
            color: #000;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .badge-waf {{
            background: var(--accent-magenta);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .badge-tls {{
            background: var(--accent-cyan);
            color: #000;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .vulnerability {{
            background: var(--bg-tertiary);
            border-left: 3px solid var(--accent-red);
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 4px;
        }}

        .vulnerability-title {{
            font-weight: 600;
            color: var(--accent-red);
            margin-bottom: 0.5rem;
        }}

        .banner-preview {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 0.75rem;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: var(--text-secondary);
            max-width: 400px;
            overflow-x: auto;
        }}

        .cert-info {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 0.75rem;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border-color);
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}

            .summary-cards {{
                grid-template-columns: 1fr;
            }}

            th, td {{
                padding: 0.5rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">ShadowScanner</div>
            <div class="subtitle">Security Assessment Report</div>
        </header>

        <div class="summary-cards">
            <div class="card">
                <div class="card-value">{result.target}</div>
                <div class="card-label">Target</div>
            </div>
            <div class="card">
                <div class="card-value">{result.duration:.1f}s</div>
                <div class="card-label">Scan Duration</div>
            </div>
            <div class="card">
                <div class="card-value">{result.ports_scanned}</div>
                <div class="card-label">Ports Scanned</div>
            </div>
            <div class="card">
                <div class="card-value">{len(result.open_ports)}</div>
                <div class="card-label">Open Ports</div>
            </div>
            <div class="card {'danger' if vuln_count > 0 else ''}">
                <div class="card-value">{vuln_count}</div>
                <div class="card-label">Vulnerabilities</div>
            </div>
            <div class="card">
                <div class="card-value">{result.os_guess}</div>
                <div class="card-label">OS Guess</div>
            </div>
        </div>

        <section>
            <div class="section-header">
                <span> Open Ports & Services</span>
            </div>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Vulnerabilities</th>
                            <th>WAF</th>
                            <th>TLS</th>
                        </tr>
                    </thead>
                    <tbody>
                        {ReportGenerator._generate_port_rows(result)}
                    </tbody>
                </table>
            </div>
        </section>

        {ReportGenerator._generate_vulnerability_section(result)}

        {ReportGenerator._generate_tls_cert_section(result)}

        <footer>
            <p>Generated by ShadowScanner v{__version__} on {result.scan_time}</p>
            <p>For authorized security testing only</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    @staticmethod
    def _generate_port_rows(result: ScanResult) -> str:
        """Generate HTML table rows for ports."""
        rows = []
        for port in result.open_ports:
            protocol_class = 'port-udp' if port.protocol == 'udp' else ''
            vuln_badges = ''
            for v in port.vulnerabilities:
                severity = v['severity'].lower()
                vuln_badges += f'<span class="severity-{severity}">{v.get("cve", v.get("id",""))}</span> '

            waf_badge = ''
            if port.waf:
                waf_badge = f'<span class="badge-waf">{port.waf["name"]}</span>'

            tls_badge = ''
            if port.tls_cert:
                tls_badge = '<span class="badge-tls">TLS</span>'

            rows.append(f"""<tr>
                <td class="port-open">{port.port}</td>
                <td class="{protocol_class}">{port.protocol.upper()}</td>
                <td class="port-open">{port.state.upper()}</td>
                <td>{port.service}</td>
                <td>{port.version or '-'}</td>
                <td>{vuln_badges or '-'}</td>
                <td>{waf_badge or '-'}</td>
                <td>{tls_badge or '-'}</td>
            </tr>""")

        if not rows:
            return '<tr><td colspan="8" style="text-align: center; color: var(--text-secondary);">No open ports found</td></tr>'
        return '\n'.join(rows)

    @staticmethod
    def _generate_vulnerability_section(result: ScanResult) -> str:
        """Generate vulnerability details section."""
        vulns = []
        for port in result.open_ports:
            for vuln in port.vulnerabilities:
                vulns.append((port, vuln))

        if not vulns:
            return ''

        vuln_html = ''
        for port, vuln in vulns:
            severity_class = vuln['severity'].lower()
            vuln_html += f"""
            <div class="vulnerability">
                <div class="vulnerability-title">
                    {vuln.get('cve', vuln.get('id',''))} - Port {port.port} ({port.service})
                    <span class="severity-{severity_class}">{vuln['severity']}</span>
                </div>
                <p>{vuln.get('description', '')[:300]}</p>
            </div>"""

        return f"""
        <section>
            <div class="section-header">
                <span> Vulnerability Details</span>
            </div>
            <div class="section-content">
                {vuln_html}
            </div>
        </section>"""

    @staticmethod
    def _generate_tls_cert_section(result: ScanResult) -> str:
        """Generate TLS certificate details section."""
        certs = [(p, p.tls_cert) for p in result.open_ports if p.tls_cert]
        if not certs:
            return ''

        cert_html = ''
        for port, cert in certs:
            sans = ', '.join(cert.get('sans', [])[:10])
            cert_html += f"""
            <div class="cert-info">
                <strong>Port {port.port}</strong><br>
                <strong>Subject CN:</strong> {cert.get('subject_cn', '')}<br>
                <strong>Issuer CN:</strong> {cert.get('issuer_cn', '')}<br>
                <strong>Serial:</strong> {cert.get('serial', '')}<br>
                <strong>Valid From:</strong> {cert.get('not_before', '')}<br>
                <strong>Valid Until:</strong> {cert.get('not_after', '')}<br>
                <strong>SANs:</strong> {sans}<br>
                <strong>Signature Algorithm:</strong> {cert.get('signature_algorithm', '')}
            </div><br>"""

        return f"""
        <section>
            <div class="section-header">
                <span> TLS Certificates</span>
            </div>
            <div class="section-content">
                {cert_html}
            </div>
        </section>"""

    @staticmethod
    def save_html(result: ScanResult, filepath: str) -> None:
        """Save HTML report to file."""
        html = ReportGenerator.generate_html(result)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"{Colors.GREEN}[+] HTML report saved to:{Colors.END} {filepath}")


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def parse_port_range(port_string: str) -> List[int]:
    """Parse port range string into list of ports.

    Supports formats:
        - "80" (single port)
        - "1-1024" (range)
        - "80,443,8080" (list)
        - "1-1024,8080,9000" (mixed)

    Args:
        port_string: Port specification string

    Returns:
        Sorted list of unique port numbers
    """
    ports = set()

    for part in port_string.split(','):
        part = part.strip()

        if '-' in part:
            # Range format: "1-1024"
            try:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())

                if start_port < 1 or end_port > 65535:
                    raise ValueError("Port range must be 1-65535")
                if start_port > end_port:
                    raise ValueError(f"Invalid range: {start_port} > {end_port}")

                ports.update(range(start_port, end_port + 1))
            except ValueError as e:
                print(f"{Colors.RED}[!] Invalid port range '{part}': {e}{Colors.END}")
                sys.exit(1)
        else:
            # Single port
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError("Port must be 1-65535")
                ports.add(port)
            except ValueError as e:
                print(f"{Colors.RED}[!] Invalid port '{part}': {e}{Colors.END}")
                sys.exit(1)

    return sorted(list(ports))


def print_banner() -> None:
    """Print tool banner."""
    banner = f"""
{Colors.CYAN}    ____  _           _            _____
   / ___|| |__  _   _| |__   ___  |_   _|__  _ __ ___ ___
   \\___ \\| '_ \\| | | | '_ \\ / _ \\   | |/ _ \\| '__/ __/ _ \\
    ___) | | | | |_| | | | | (_) |  | | (_) | | | (_|  __/
   |____/|_| |_|\\__,_|_| |_|\\___/   |_|\\___/|_|  \\___\\___|
{Colors.END}
{Colors.GREEN}                    Advanced Port Scanner v{__version__}{Colors.END}
{Colors.YELLOW}              Professional Security Assessment Tool{Colors.END}
    """
    print(banner)


def main() -> None:
    """Main entry point for ShadowScanner."""
    parser = argparse.ArgumentParser(
        description='ShadowScanner - Advanced Port Scanner with Service Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan (top 1024 ports)
  python shadow_scanner.py -t 192.168.1.1

  # Full port range with vulnerability check
  python shadow_scanner.py -t example.com -p 1-65535 --vuln -T 200

  # Specific ports with HTML report
  python shadow_scanner.py -t 10.0.0.1 -p 22,80,443,3306,8080 --html -v

  # UDP scan with NVD CVE checking
  python shadow_scanner.py -t target.com --udp --nvd --nvd-api-key YOURKEY

  # Import scan from Nmap XML
  python shadow_scanner.py --import-nmap scan.xml

  # Skip host discovery
  python shadow_scanner.py -t target.com --no-ping
        """
    )

    parser.add_argument('-t', '--target', default=None,
                        help='Target IP address or hostname')

    parser.add_argument('-p', '--ports', default='1-1024',
                        help='Port range to scan (default: 1-1024). '
                             'Formats: "80", "1-1024", "22,80,443"')

    parser.add_argument('-T', '--threads', type=int, default=100,
                        help='Number of concurrent threads (default: 100)')

    parser.add_argument('--timeout', type=float, default=2.0,
                        help='Connection timeout in seconds (default: 2)')

    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Save JSON output to file')

    parser.add_argument('--html', metavar='FILE',
                        help='Generate HTML report')

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output (show banners, all details)')

    parser.add_argument('--no-banner', action='store_true',
                        help='Skip banner grabbing (faster scan)')

    parser.add_argument('--udp', action='store_true',
                        help='Include UDP scan (common UDP ports)')

    parser.add_argument('--vuln', action='store_true',
                        help='Check for known vulnerabilities based on versions')

    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')

    parser.add_argument('--no-ping', action='store_true',
                        help='Skip host discovery ping sweep before scanning')

    parser.add_argument('--nvd', action='store_true',
                        help='Check NVD database for CVEs on detected service versions')

    parser.add_argument('--nvd-api-key', metavar='KEY', default=None,
                        help='NVD API key (optional, for higher rate limits)')

    parser.add_argument('--import-nmap', metavar='FILE', default=None,
                        help='Import scan results from Nmap XML file')

    parser.add_argument('--version', action='version',
                        version=f'ShadowScanner {__version__}')

    add_proxy_arg(parser)

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        Colors.disable()

    # Handle Nmap XML import mode
    if args.import_nmap:
        result = ShadowScanner.import_nmap_xml(args.import_nmap)

        # Optionally run CVE checks on imported data
        if args.vuln or args.nvd:
            print(f"{Colors.YELLOW}[*] Checking imported services for vulnerabilities...{Colors.END}")
            for port in result.open_ports:
                if port.service != 'unknown' and port.version:
                    if args.vuln:
                        port.vulnerabilities = VulnDatabase.check_vulnerabilities(
                            port.service, port.version)
                    if args.nvd:
                        nvd_cves = check_nvd_cve(port.service, port.version, args.nvd_api_key, proxy=args.proxy)
                        port.vulnerabilities.extend(
                            [c for c in nvd_cves if 'error' not in c])
            vuln_count = sum(len(p.vulnerabilities) for p in result.open_ports)
            if vuln_count > 0:
                print(f"{Colors.RED}[!] Found {vuln_count} potential vulnerabilities in imported data{Colors.END}")

        # Save reports if requested
        if args.output:
            ReportGenerator.save_json(result, args.output)
        if args.html:
            ReportGenerator.save_html(result, args.html)

        # Print summary
        result.duration = 0.0
        print(f"\n{Colors.GREEN}[+] Imported {len(result.open_ports)} open ports from Nmap XML{Colors.END}")
        return

    # Validate target is required for normal mode
    if not args.target:
        parser.print_help()
        print(f"\n{Colors.RED}[!] --target/-t is required for normal scan mode{Colors.END}")
        print(f"{Colors.YELLOW}[!] Use --import-nmap to import from Nmap XML instead{Colors.END}")
        sys.exit(1)

    # Parse port range
    ports = parse_port_range(args.ports)

    # Print banner (unless verbose mode which shows more detail)
    if not args.verbose:
        print_banner()

    # Validate threads
    if args.threads < 1 or args.threads > 1000:
        print(f"{Colors.RED}[!] Thread count must be between 1 and 1000{Colors.END}")
        sys.exit(1)

    # Validate timeout
    if args.timeout < 0.1 or args.timeout > 60:
        print(f"{Colors.RED}[!] Timeout must be between 0.1 and 60 seconds{Colors.END}")
        sys.exit(1)

    # Initialize scanner
    scanner = ShadowScanner(
        target=args.target,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose,
        grab_banner=not args.no_banner,
        check_vulns=args.vuln,
        scan_udp=args.udp,
        no_ping=args.no_ping,
        check_nvd=args.nvd,
        nvd_api_key=args.nvd_api_key if (args.nvd or args.vuln) else None,
        proxy=args.proxy,
    )

    try:
        # Run scan
        result = scanner.scan()

        # Save reports if requested
        if args.output:
            ReportGenerator.save_json(result, args.output)

        if args.html:
            ReportGenerator.save_html(result, args.html)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
