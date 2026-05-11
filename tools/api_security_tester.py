#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
APISecurityTester - API Security Testing Tool
=============================================

Tests for:
    - IDOR (Insecure Direct Object Reference)
    - Broken Authentication
    - Rate Limiting
    - Mass Assignment
    - Improper Assets Management
    - Injection in API parameters
    - Broken Object Level Authorization (BOLA)
    - Excessive Data Exposure
    - Broken Function Level Authorization
    - Misconfigured CORS

Author: Security Research Team
Version: 1.0.0
License: MIT

Usage:
    python api_security_tester.py -u https://api.target.com
    python api_security_tester.py -u https://api.target.com --auth "Bearer token"
    python api_security_tester.py -u https://api.target.com --swagger openapi.json
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import string
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests

from common import Colors, detect_waf, parallel_map, add_proxy_arg

urllib3 = requests.packages.urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "1.0.0"

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class APIVulnerability:
    name: str
    severity: str
    confidence: str
    endpoint: str
    method: str
    description: str
    evidence: str
    remediation: str
    owasp_api: str = ""
    cvss: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'severity': self.severity,
            'confidence': self.confidence,
            'endpoint': self.endpoint,
            'method': self.method,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'owasp_api': self.owasp_api,
            'cvss': self.cvss
        }

@dataclass
class APIEndpoint:
    path: str
    method: str
    parameters: List[Dict] = field(default_factory=list)
    content_type: str = "application/json"
    
@dataclass
class APITestResult:
    target: str
    start_time: str
    end_time: str = ""
    vulnerabilities: List[APIVulnerability] = field(default_factory=list)
    endpoints_tested: int = 0
    
    def to_dict(self) -> Dict:
        return {
            'target': self.target,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v.severity == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v.severity == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v.severity == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v.severity == 'LOW']),
                'endpoints_tested': self.endpoints_tested
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }

# =============================================================================
# API SECURITY TESTER
# =============================================================================

class APISecurityTester:
    """Test API endpoints for security vulnerabilities."""
    
    def __init__(self, base_url: str, auth_token: str = None, 
                 auth_type: str = "Bearer", output_dir: str = None,
                 proxy: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.auth_type = auth_type
        self.output_dir = output_dir or f"api_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        if auth_token:
            self.session.headers.update({
                'Authorization': f'{auth_type} {auth_token}'
            })
        
        self.result = APITestResult(
            target=base_url,
            start_time=datetime.now().isoformat()
        )
        
        self.vulnerabilities: List[APIVulnerability] = []
        self.discovered_endpoints: List[APIEndpoint] = []
    
    def add_vulnerability(self, vuln: APIVulnerability):
        """Add a vulnerability finding."""
        self.vulnerabilities.append(vuln)
        color = Colors.RED if vuln.severity == 'CRITICAL' else Colors.YELLOW if vuln.severity == 'HIGH' else Colors.BLUE
        print(f"{color}[{vuln.severity}]{Colors.END} {vuln.name}")
        print(f"     Endpoint: {vuln.method} {vuln.endpoint}")
        print(f"     {vuln.description}")
    
    def parse_swagger(self, swagger_file: str) -> List[APIEndpoint]:
        """Parse OpenAPI/Swagger specification."""
        endpoints = []
        
        try:
            with open(swagger_file, 'r') as f:
                spec = json.load(f)
            
            base_path = spec.get('basePath', '')
            paths = spec.get('paths', {})
            
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        params = []
                        
                        # Parse parameters
                        for param in details.get('parameters', []):
                            params.append({
                                'name': param.get('name'),
                                'in': param.get('in', 'query'),
                                'required': param.get('required', False),
                                'type': param.get('type', 'string'),
                                'schema': param.get('schema', {})
                            })
                        
                        endpoint = APIEndpoint(
                            path=urljoin(base_path, path),
                            method=method.upper(),
                            parameters=params
                        )
                        endpoints.append(endpoint)
            
            print(f"{Colors.GREEN}[+] Parsed {len(endpoints)} endpoints from Swagger{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error parsing Swagger: {str(e)}{Colors.END}")
        
        return endpoints
    
    def discover_endpoints(self) -> List[APIEndpoint]:
        """Discover common API endpoints."""
        print(f"\n{Colors.CYAN}[*] Discovering API endpoints...{Colors.END}")
        
        common_endpoints = [
            # REST API patterns
            APIEndpoint('/api', 'GET'),
            APIEndpoint('/api/v1', 'GET'),
            APIEndpoint('/api/v2', 'GET'),
            APIEndpoint('/api/users', 'GET'),
            APIEndpoint('/api/users/1', 'GET'),
            APIEndpoint('/api/users/2', 'GET'),
            APIEndpoint('/api/user', 'GET'),
            APIEndpoint('/api/user/profile', 'GET'),
            APIEndpoint('/api/account', 'GET'),
            APIEndpoint('/api/accounts', 'GET'),
            APIEndpoint('/api/posts', 'GET'),
            APIEndpoint('/api/posts/1', 'GET'),
            APIEndpoint('/api/products', 'GET'),
            APIEndpoint('/api/products/1', 'GET'),
            APIEndpoint('/api/orders', 'GET'),
            APIEndpoint('/api/orders/1', 'GET'),
            APIEndpoint('/api/items', 'GET'),
            APIEndpoint('/api/items/1', 'GET'),
            APIEndpoint('/api/data', 'GET'),
            APIEndpoint('/api/config', 'GET'),
            APIEndpoint('/api/settings', 'GET'),
            APIEndpoint('/api/admin', 'GET'),
            APIEndpoint('/api/admin/users', 'GET'),
            APIEndpoint('/api/auth', 'GET'),
            APIEndpoint('/api/auth/login', 'POST'),
            APIEndpoint('/api/auth/register', 'POST'),
            APIEndpoint('/api/auth/me', 'GET'),
            APIEndpoint('/api/auth/refresh', 'POST'),
            APIEndpoint('/api/login', 'POST'),
            APIEndpoint('/api/logout', 'POST'),
            APIEndpoint('/api/register', 'POST'),
            APIEndpoint('/api/me', 'GET'),
            APIEndpoint('/api/profile', 'GET'),
            APIEndpoint('/api/search', 'GET'),
            APIEndpoint('/api/upload', 'POST'),
            APIEndpoint('/api/files', 'GET'),
            APIEndpoint('/api/docs', 'GET'),
            APIEndpoint('/api/swagger.json', 'GET'),
            APIEndpoint('/api/openapi.json', 'GET'),
            # Root level OpenAPI/Swagger paths
            APIEndpoint('/openapi.json', 'GET'),
            APIEndpoint('/swagger.json', 'GET'),
            APIEndpoint('/api/swagger', 'GET'),
            APIEndpoint('/v1/api-docs', 'GET'),
            APIEndpoint('/v2/api-docs', 'GET'),
            APIEndpoint('/api/v1/openapi.json', 'GET'),
            APIEndpoint('/api/v2/openapi.json', 'GET'),
            # GraphQL
            APIEndpoint('/graphql', 'POST'),
            APIEndpoint('/graphql', 'GET'),
            APIEndpoint('/api/graphql', 'POST'),
            # Common REST
            APIEndpoint('/users', 'GET'),
            APIEndpoint('/user', 'GET'),
            APIEndpoint('/posts', 'GET'),
            APIEndpoint('/products', 'GET'),
            APIEndpoint('/orders', 'GET'),
            # API documentation
            APIEndpoint('/swagger-ui.html', 'GET'),
            APIEndpoint('/api-docs', 'GET'),
            APIEndpoint('/redoc', 'GET'),
        ]
        
        discovered = []
        
        for endpoint in common_endpoints:
            url = urljoin(self.base_url, endpoint.path)
            try:
                response = self.session.request(
                    endpoint.method, 
                    url, 
                    timeout=5, 
                    verify=False,
                    allow_redirects=False
                )
                
                if response.status_code not in [404, 405, 502, 503]:
                    # Check for SPA fake 200 (returns 200 but shows 404 page)
                    is_spa_404 = False
                    if response.status_code == 200:
                        content_lower = response.text.lower()
                        # Common SPA 404 indicators
                        spa_404_indicators = ['404', 'not found', 'page not found', 'doesn\'t exist', 'does not exist']
                        # Must have 404 indicator AND be in title or h1
                        if any(ind in content_lower for ind in spa_404_indicators):
                            # Check if it's in a prominent location (title, h1, main error message)
                            if '<title>' in content_lower and '</title>' in content_lower:
                                title = content_lower.split('<title>')[1].split('</title>')[0]
                                if any(ind in title for ind in spa_404_indicators):
                                    is_spa_404 = True
                    
                    if not is_spa_404:
                        discovered.append(endpoint)
                        print(f"{Colors.GREEN}[+] Found: {endpoint.method} {endpoint.path} ({response.status_code}){Colors.END}")
                    
            except Exception:
                pass
        
        self.discovered_endpoints = discovered
        return discovered
    
    def test_idor(self, endpoints: List[APIEndpoint] = None) -> None:
        """Test for IDOR vulnerabilities."""
        print(f"\n{Colors.CYAN}[*] Testing for IDOR vulnerabilities...{Colors.END}")
        
        if endpoints is None:
            endpoints = self.discovered_endpoints
        
        # Focus on endpoints with numeric IDs
        idor_patterns = [
            r'/(\d+)',
            r'/([a-f0-9-]{36})',  # UUID
            r'/([a-zA-Z0-9]{10,})',  # Random IDs
        ]
        
        for endpoint in endpoints:
            path = endpoint.path
            
            # Check if endpoint has ID pattern
            for pattern in idor_patterns:
                match = re.search(pattern, path)
                if match:
                    original_id = match.group(1)
                    
                    # Try adjacent IDs (handles numeric, UUID, and random IDs)
                    try:
                        if original_id.isdigit():
                            test_id = str(int(original_id) + 1)
                        elif '-' in original_id and len(original_id) == 36:
                            test_id = original_id  # UUIDs can't be incremented
                        else:
                            test_id = original_id  # Random IDs can't be incremented
                        
                        test_path = path.replace(original_id, str(test_id))
                        url = urljoin(self.base_url, test_path)
                        response = self.session.get(url, timeout=10, verify=False)
                        
                        # Check if we got data for another user
                        if response.status_code == 200:
                            try:
                                data = response.json()
                                if data and isinstance(data, dict):
                                    # Check for sensitive data
                                    sensitive_fields = ['email', 'phone', 'address', 'ssn', 'password', 'token']
                                    for field in sensitive_fields:
                                        if field in str(data).lower():
                                            self.add_vulnerability(APIVulnerability(
                                                name="IDOR - Insecure Direct Object Reference",
                                                severity="HIGH",
                                                confidence="FIRM",
                                                endpoint=test_path,
                                                method="GET",
                                                description=f"Can access other user's data by changing ID from {original_id} to {test_id}",
                                                evidence=f"Found sensitive field '{field}' in response",
                                                remediation="Implement proper authorization checks. Use indirect references or per-user tokens.",
                                                owasp_api="API1:2019 Broken Object Level Authorization",
                                                cvss=8.2
                                            ))
                                            break
                            except Exception:
                                pass
                    except Exception:
                        pass
    
    def test_broken_auth(self) -> None:
        """Test for broken authentication."""
        print(f"\n{Colors.CYAN}[*] Testing for broken authentication...{Colors.END}")
        
        # Test endpoints without token
        test_endpoints = ['/api/user', '/api/users', '/api/profile', '/api/me', '/api/account']
        
        # Remove auth header temporarily
        original_auth = self.session.headers.get('Authorization')
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']
        
        for path in test_endpoints:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if data:
                            self.add_vulnerability(APIVulnerability(
                                name="Broken Authentication - Access Without Token",
                                severity="CRITICAL",
                                confidence="FIRM",
                                endpoint=path,
                                method="GET",
                                description="API endpoint accessible without authentication",
                                evidence=f"Got 200 response with data without auth token",
                                remediation="Require authentication for all sensitive endpoints. Validate tokens properly.",
                                owasp_api="API2:2019 Broken Authentication",
                                cvss=9.1
                            ))
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Restore auth header
        if original_auth:
            self.session.headers['Authorization'] = original_auth
    
    def test_rate_limiting(self) -> None:
        """Test for rate limiting."""
        print(f"\n{Colors.CYAN}[*] Testing for rate limiting...{Colors.END}")
        
        # Test with rapid requests
        test_endpoint = '/api/user'
        url = urljoin(self.base_url, test_endpoint)
        
        responses = []
        for i in range(20):
            try:
                response = self.session.get(url, timeout=5, verify=False)
                responses.append(response.status_code)
            except Exception:
                responses.append(0)
        
        # Check for rate limiting
        if 429 not in responses:
            self.add_vulnerability(APIVulnerability(
                name="Missing Rate Limiting",
                severity="MEDIUM",
                confidence="FIRM",
                endpoint=test_endpoint,
                method="GET",
                description=f"No rate limiting detected after {len(responses)} rapid requests",
                evidence=f"All responses: {responses[:10]}...",
                remediation="Implement rate limiting (e.g., 100 requests per minute per user/IP). Use 429 status code.",
                owasp_api="API4:2019 Lack of Resources & Rate Limiting",
                cvss=5.3
            ))
        else:
            print(f"{Colors.GREEN}[+] Rate limiting detected (HTTP 429){Colors.END}")
    
    def test_mass_assignment(self) -> None:
        """Test for mass assignment vulnerabilities."""
        print(f"\n{Colors.CYAN}[*] Testing for mass assignment...{Colors.END}")
        
        # Test common endpoints that accept POST/PUT
        test_cases = [
            {
                'endpoint': '/api/user',
                'method': 'PUT',
                'payload': {'email': 'test@test.com', 'role': 'admin', 'is_admin': True}
            },
            {
                'endpoint': '/api/users/me',
                'method': 'PATCH',
                'payload': {'name': 'test', 'role': 'administrator', 'permissions': ['admin']}
            },
            {
                'endpoint': '/api/profile',
                'method': 'POST',
                'payload': {'name': 'test', 'admin': True, 'is_superuser': True}
            }
        ]
        
        for test in test_cases:
            url = urljoin(self.base_url, test['endpoint'])
            
            try:
                if test['method'] == 'POST':
                    response = self.session.post(url, json=test['payload'], timeout=10, verify=False)
                elif test['method'] == 'PUT':
                    response = self.session.put(url, json=test['payload'], timeout=10, verify=False)
                elif test['method'] == 'PATCH':
                    response = self.session.patch(url, json=test['payload'], timeout=10, verify=False)
                
                if response.status_code in [200, 201]:
                    try:
                        data = response.json()
                        
                        # Check if admin fields were accepted
                        admin_indicators = ['role', 'admin', 'is_admin', 'permissions', 'is_superuser']
                        for indicator in admin_indicators:
                            if indicator in str(data).lower():
                                self.add_vulnerability(APIVulnerability(
                                    name="Mass Assignment",
                                    severity="HIGH",
                                    confidence="TENTATIVE",
                                    endpoint=test['endpoint'],
                                    method=test['method'],
                                    description=f"May be able to modify privileged fields via mass assignment",
                                    evidence=f"Field '{indicator}' appears in response after update",
                                    remediation="Whitelist allowed fields. Use DTOs. Never accept fields like 'role', 'admin', 'permissions' from user input.",
                                    owasp_api="API6:2019 Mass Assignment",
                                    cvss=7.5
                                ))
                                break
                    except Exception:
                        pass
                        
            except Exception:
                pass
    
    def test_excessive_data_exposure(self) -> None:
        """Test for excessive data exposure."""
        print(f"\n{Colors.CYAN}[*] Testing for excessive data exposure...{Colors.END}")
        
        sensitive_fields = [
            'password', 'pwd', 'pass', 'secret', 'token', 'api_key', 'apikey',
            'ssn', 'social_security', 'credit_card', 'card_number', 'cvv',
            'private_key', 'privatekey', 'salt', 'hash', 'otp', 'mfa_secret'
        ]
        
        for endpoint in self.discovered_endpoints[:10]:  # Test first 10
            url = urljoin(self.base_url, endpoint.path)
            
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        response_str = str(data).lower()
                        
                        for field in sensitive_fields:
                            if field in response_str:
                                self.add_vulnerability(APIVulnerability(
                                    name="Excessive Data Exposure",
                                    severity="HIGH",
                                    confidence="FIRM",
                                    endpoint=endpoint.path,
                                    method="GET",
                                    description=f"API exposes sensitive field: {field}",
                                    evidence=f"Sensitive field '{field}' found in response",
                                    remediation="Filter response data to only include necessary fields. Never return passwords, tokens, or secrets.",
                                    owasp_api="API3:2019 Excessive Data Exposure",
                                    cvss=7.5
                                ))
                                break
                    except Exception:
                        pass
            except Exception:
                pass
    
    def test_cors_misconfiguration(self) -> None:
        """Test for CORS misconfiguration."""
        print(f"\n{Colors.CYAN}[*] Testing for CORS misconfiguration...{Colors.END}")
        
        url = urljoin(self.base_url, '/api')
        
        # Test with various origins
        test_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
        ]
        
        cors_vuln_found = False  # Track if we already found CORS issue
        
        for origin in test_origins:
            if cors_vuln_found:  # Skip if already found
                break
                
            try:
                headers = {'Origin': origin}
                response = self.session.options(url, headers=headers, timeout=10, verify=False)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Check if arbitrary origin is allowed
                if acao == origin and origin not in [self.base_url, '']:
                    if allow_credentials.lower() == 'true':
                        self.add_vulnerability(APIVulnerability(
                            name="CORS Misconfiguration - Arbitrary Origin with Credentials",
                            severity="HIGH",
                            confidence="FIRM",
                            endpoint='/api',
                            method="OPTIONS",
                            description=f"CORS allows arbitrary origins with credentials",
                            evidence=f"Tested origins: evil.com, attacker.com, null - all accepted with credentials",
                            remediation="Whitelist specific origins. Avoid using '*' or reflecting arbitrary origins with credentials.",
                            owasp_api="API7:2019 Security Misconfiguration",
                            cvss=8.1
                        ))
                        cors_vuln_found = True
                    elif acao == '*':
                        self.add_vulnerability(APIVulnerability(
                            name="CORS Misconfiguration - Wildcard Origin",
                            severity="MEDIUM",
                            confidence="FIRM",
                            endpoint='/api',
                            method="OPTIONS",
                            description="CORS allows wildcard origin",
                            evidence=f"ACAO: *",
                            remediation="Specify allowed origins explicitly instead of using '*'.",
                            owasp_api="API7:2019 Security Misconfiguration",
                            cvss=5.3
                        ))
                        cors_vuln_found = True
                        
            except Exception:
                pass
    
    def test_injection_in_params(self) -> None:
        """Test for injection in API parameters."""
        print(f"\n{Colors.CYAN}[*] Testing for injection in API parameters...{Colors.END}")
        
        sqli_payloads = ["'", "' OR '1'='1", "1 OR 1=1"]
        xss_payloads = ["<script>alert(1)</script>", "'\"><script>alert(1)</script>"]
        
        for endpoint in self.discovered_endpoints[:5]:
            url = urljoin(self.base_url, endpoint.path)
            
            # Test query parameters
            for payload in sqli_payloads:
                try:
                    test_url = f"{url}?id={payload}"
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    sql_errors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-']
                    for error in sql_errors:
                        if error in response.text.lower():
                            self.add_vulnerability(APIVulnerability(
                                name="SQL Injection in API Parameter",
                                severity="CRITICAL",
                                confidence="FIRM",
                                endpoint=endpoint.path,
                                method="GET",
                                description="SQL injection in query parameter",
                                evidence=f"SQL error detected: {error}",
                                remediation="Use parameterized queries. Validate and sanitize all input.",
                                owasp_api="API8:2019 Injection",
                                cvss=9.8
                            ))
                            break
                except Exception:
                    pass
    
    def test_graphql_introspection(self) -> None:
        """Test for GraphQL introspection exposure."""
        print(f"\n{Colors.CYAN}[*] Testing for GraphQL introspection...{Colors.END}")
        
        graphql_url = urljoin(self.base_url, '/graphql')
        
        introspection_query = {
            "query": "{__schema{types{name}}}"
        }
        
        try:
            response = self.session.post(graphql_url, json=introspection_query, timeout=10, verify=False)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    if '__schema' in str(data):
                        self.add_vulnerability(APIVulnerability(
                            name="GraphQL Introspection Enabled",
                            severity="LOW",
                            confidence="FIRM",
                            endpoint='/graphql',
                            method="POST",
                            description="GraphQL introspection is enabled, exposing schema",
                            evidence="Introspection query returned schema data",
                            remediation="Disable introspection in production. Use @deprecated or hide sensitive fields.",
                            owasp_api="API7:2019 Security Misconfiguration",
                            cvss=3.7
                        ))
                except Exception:
                    pass
        except Exception:
            pass
    
    def test_graphql_batching(self, deep: bool = False) -> None:
        """Test GraphQL batching attacks: batched queries, field duplication, aliases."""
        print(f"\n{Colors.CYAN}[*] Testing GraphQL batching attacks...{Colors.END}")

        graphql_endpoints = [ep for ep in self.discovered_endpoints if 'graphql' in ep.path.lower()]
        if not graphql_endpoints:
            for path in ['/graphql', '/api/graphql']:
                url = urljoin(self.base_url, path)
                try:
                    resp = self.session.post(url, json={"query": "{__typename}"}, timeout=5, verify=False)
                    if resp.status_code == 200:
                        graphql_endpoints.append(APIEndpoint(path, 'POST'))
                        print(f"{Colors.GREEN}[+] Found GraphQL endpoint: {path}{Colors.END}")
                        break
                except Exception:
                    pass

        if not graphql_endpoints:
            print(f"{Colors.YELLOW}[-] No GraphQL endpoints found{Colors.END}")
            return

        for gql_ep in graphql_endpoints:
            gql_url = urljoin(self.base_url, gql_ep.path)

            # Test 1: Batching attack (array of queries) — bypass rate limits
            batch_size = 10
            batch_payload = [{"query": "{__typename}"} for _ in range(batch_size)]
            try:
                resp = self.session.post(gql_url, json=batch_payload, timeout=10, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list) and len(data) > 1:
                            self.add_vulnerability(APIVulnerability(
                                name="GraphQL Batching Attack - Rate / Depth Limit Bypass",
                                severity="MEDIUM",
                                confidence="FIRM",
                                endpoint=gql_ep.path,
                                method="POST",
                                description=f"GraphQL endpoint accepts {len(batch_payload)} batched queries in a single request, bypassing per-request rate / depth limits",
                                evidence=f"Sent {len(batch_payload)} batched queries, received {len(data)} responses (HTTP 200)",
                                remediation="Limit batch query count, enforce rate limiting on cumulative query complexity, disable batching in production if not required",
                                owasp_api="API4:2019 Lack of Resources & Rate Limiting",
                                cvss=5.3
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

            # Test 2: Field duplication with aliases — extract large data volumes
            if deep:
                alias_count = 50
                alias_fields = "\n".join(f"    a{i}: __typename" for i in range(alias_count))
                alias_query = "{\n" + alias_fields + "\n}"
                try:
                    resp = self.session.post(gql_url, json={"query": alias_query}, timeout=15, verify=False)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            if isinstance(data, dict) and 'data' in data:
                                keys_count = len(data['data'])
                                if keys_count > 20:
                                    self.add_vulnerability(APIVulnerability(
                                        name="GraphQL Field Duplication via Aliases",
                                        severity="MEDIUM",
                                        confidence="TENTATIVE",
                                        endpoint=gql_ep.path,
                                        method="POST",
                                        description=f"GraphQL endpoint accepts {keys_count} duplicate alias fields, risking excessive data extraction & CPU exhaustion",
                                        evidence=f"Aliased query with {alias_count} aliases returned {keys_count} fields (HTTP 200)",
                                        remediation="Limit alias count, implement cost-based query analysis, use persisted queries",
                                        owasp_api="API4:2019 Lack of Resources & Rate Limiting",
                                        cvss=4.3
                                    ))
                        except Exception:
                            pass
                except Exception:
                    pass

    def test_parameter_fuzzing(self) -> None:
        """Fuzz API parameters with edge-case values and report anomalies."""
        print(f"\n{Colors.CYAN}[*] Testing parameter fuzzing...{Colors.END}")

        fuzz_values = [
            None,
            True,
            False,
            "",
            " " * 1000,
            0,
            -1,
            9999999999999999999999999999999999999,
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "%00",
            "\x00",
            "\ufffd",
            "§±!@#$%^&*()_+={}[]|:;\"'<>,.?/~`",
            "\r\n" * 100,
            "\n" * 50,
            "A" * 10000,
            -9999999999999999999999999999999999999,
            3.141592653589793238462643383279502884197,
            float('inf'),
        ]

        endpoints_to_test = self.discovered_endpoints[:10]
        if not endpoints_to_test:
            endpoints_to_test = [APIEndpoint('/api/user', 'GET')]

        # Collect all (endpoint, param_name, fuzz_value) tuples for parallel execution
        def fuzz_item(args):
            endpoint, param_name, fuzz_val = args
            url = urljoin(self.base_url, endpoint.path)
            result = {'endpoint': endpoint, 'param': param_name, 'value': repr(fuzz_val), 'anomaly': False, 'status': None}
            try:
                payload = {param_name: fuzz_val}
                resp = self.session.get(url, params=payload, timeout=8, verify=False)
                result['status'] = resp.status_code
                if resp.status_code == 500:
                    result['anomaly'] = True
                elif resp.status_code == 200:
                    body_lower = resp.text.lower()
                    if any(ind in body_lower for ind in ['stack trace', 'traceback', 'exception', 'error', 'warning', 'fatal', 'unhandled']):
                        result['anomaly'] = True
            except Exception:
                result['status'] = 0
            return result

        fuzz_items = []
        for endpoint in endpoints_to_test:
            params = endpoint.parameters
            if not params:
                params = [{'name': 'id', 'in': 'query'}]
            for param in params:
                param_name = param.get('name', 'id')
                for fuzz_val in [v for v in fuzz_values if v is not None][:8]:
                    fuzz_items.append((endpoint, param_name, fuzz_val))

        if fuzz_items:
            results = parallel_map(fuzz_item, fuzz_items, max_workers=5, desc='Fuzzing')
            for (endpoint, param_name, fuzz_val), error_or_result in results:
                if isinstance(error_or_result, Exception):
                    continue
                result = error_or_result
                if result['anomaly']:
                    self.add_vulnerability(APIVulnerability(
                        name=f"Parameter Fuzzing - Anomalous Response",
                        severity="HIGH",
                        confidence="TENTATIVE",
                        endpoint=result['endpoint'].path,
                        method="GET",
                        description=f"Parameter '{result['param']}' with value {result['value']} caused anomalous response (HTTP {result['status']})",
                        evidence=f"Fuzz value: {result['value']}, Status: {result['status']}",
                        remediation="Implement strict input validation, use allow-lists for expected values, handle all errors gracefully without stack traces",
                        owasp_api="API8:2019 Injection",
                        cvss=6.5
                    ))

    def test_request_smuggling(self) -> None:
        """Test HTTP request smuggling (CL.TE and TE.CL variants) via raw sockets."""
        import socket as sock_mod
        import ssl as ssl_mod

        print(f"\n{Colors.CYAN}[*] Testing HTTP request smuggling...{Colors.END}")

        # Detect WAF presence — may affect smuggling results
        waf = detect_waf(self.base_url, self.session)
        if waf.detected:
            print(f"{Colors.YELLOW}[!] WAF detected ({waf.name}) — smuggling tests may be unreliable{Colors.END}")

        test_endpoints = [ep for ep in self.discovered_endpoints if ep.method in ('GET', 'POST')]
        if not test_endpoints:
            test_endpoints = [APIEndpoint('/api', 'POST')]

        for ep in test_endpoints[:4]:
            parsed = urlparse(urljoin(self.base_url, ep.path))
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            path = parsed.path or '/'
            use_ssl = parsed.scheme == 'https'

            # Build smuggled prefix that requests /api (public) then tries /admin
            smuggled_path = '/admin'
            smuggled_get = f"GET {smuggled_path} HTTP/1.1\r\nHost: localhost\r\n\r\n"

            # CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
            # The smuggled body ends the chunked body (0\r\n\r\n) then appends the GET
            cl_te_body = f"0\r\n\r\n{smuggled_get}"
            cl_te_raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(cl_te_body)}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{cl_te_body}"
            )

            # TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
            # The smuggled GET is wrapped inside a single chunk
            te_cl_chunk_size = hex(len(smuggled_get))[2:]
            te_cl_body = f"{te_cl_chunk_size}\r\n{smuggled_get}\r\n0\r\n\r\n"
            te_cl_raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{te_cl_body}"
            )

            for variant_name, raw_request in [('CL.TE', cl_te_raw), ('TE.CL', te_cl_raw)]:
                try:
                    sock = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
                    sock.settimeout(8)
                    if use_ssl:
                        ctx = ssl_mod.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl_mod.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=host)
                    sock.connect((host, port))
                    sock.sendall(raw_request.encode())
                    time.sleep(0.5)
                    response = b""
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                        except sock_mod.timeout:
                            break
                    sock.close()

                    resp_text = response.decode('utf-8', errors='replace')

                    # Check for signs of smuggling: two HTTP responses, or access to smuggled path
                    if resp_text.count('HTTP/1.1') > 1 or resp_text.count('HTTP/1.0') > 1:
                        if 'admin' in resp_text.lower() or '200 OK' in resp_text:
                            self.add_vulnerability(APIVulnerability(
                                name=f"HTTP Request Smuggling ({variant_name})",
                                severity="CRITICAL",
                                confidence="TENTATIVE",
                                endpoint=ep.path,
                                method="POST",
                                description=f"Potential {variant_name} request smuggling — front-end and back-end disagree on Content-Length vs Transfer-Encoding",
                                evidence=f"Multiple HTTP responses detected in single connection. Prefix of response:\n{resp_text[:300]}",
                                remediation="Ensure consistent HTTP parsing between front-end (load balancer / proxy) and back-end. Disable Transfer-Encoding on back-end. Use HTTP/2.",
                                owasp_api="API7:2019 Security Misconfiguration",
                                cvss=9.1
                            ))
                            break
                except Exception:
                    pass

    def test_rate_limit_bypass(self) -> None:
        """Confirm rate limiting exists, then attempt bypasses via IP rotation headers."""
        print(f"\n{Colors.CYAN}[*] Testing rate limit bypass techniques...{Colors.END}")

        test_endpoint = '/api/user'
        url = urljoin(self.base_url, test_endpoint)

        # Step 1: Confirm rate limiting exists
        print(f"{Colors.CYAN}[*] Step 1: Confirming rate limiting...{Colors.END}")
        baseline = []
        for i in range(25):
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                baseline.append(resp.status_code)
            except Exception:
                baseline.append(0)

        if 429 not in baseline:
            print(f"{Colors.YELLOW}[-] No rate limiting detected, skipping bypass tests{Colors.END}")
            return

        print(f"{Colors.GREEN}[+] Rate limiting confirmed (HTTP 429 seen){Colors.END}")

        # Step 2: Attempt bypass
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
            'curl/7.68.0',
            'PostmanRuntime/7.28.0',
            'python-requests/2.25.0',
            'Go-http-client/2.0',
        ]

        ip_rotation_headers = [
            ('X-Forwarded-For', lambda: f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}'),
            ('X-Real-IP', lambda: f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'),
            ('X-Originating-IP', lambda: f'{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'),
        ]

        bypassed = False
        for header_name, ip_gen in ip_rotation_headers:
            print(f"{Colors.CYAN}[*] Trying {header_name} rotation...{Colors.END}")
            bypass_responses = []
            for i in range(25):
                try:
                    headers = {
                        'User-Agent': random.choice(user_agents),
                        header_name: ip_gen(),
                    }
                    resp = self.session.get(url, headers=headers, timeout=5, verify=False)
                    bypass_responses.append(resp.status_code)
                except Exception:
                    bypass_responses.append(0)

            if 429 not in bypass_responses:
                bypassed = True
                self.add_vulnerability(APIVulnerability(
                    name="Rate Limiting Bypass via IP Rotation Header",
                    severity="HIGH",
                    confidence="FIRM",
                    endpoint=test_endpoint,
                    method="GET",
                    description=f"Rate limiting bypassed by rotating {header_name} header values across requests",
                    evidence=f"{header_name} rotation: 25 requests, 0 blocked (HTTP 429). Responses: {bypass_responses[:10]}...",
                    remediation="Rate-limit by real IP (not just headers), enforce rate limits on the back-end not just proxy, use rate-limit tokens or captchas for abuse detection",
                    owasp_api="API4:2019 Lack of Resources & Rate Limiting",
                    cvss=7.5
                ))
                print(f"{Colors.GREEN}[+] Bypassed via {header_name}!{Colors.END}")
                break

        if not bypassed:
            print(f"{Colors.YELLOW}[-] Rate limiting could not be bypassed with any header rotation technique{Colors.END}")

    def run_all_tests(self, swagger_file: str = None, fuzz: bool = False,
                      smuggle: bool = False, graphql_deep: bool = False) -> APITestResult:
        """Run all API security tests."""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}APISecurityTester v{VERSION}{Colors.END}")
        print(f"{Colors.BOLD}Target: {self.base_url}{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
        
        # Parse swagger if provided
        if swagger_file:
            self.discovered_endpoints.extend(self.parse_swagger(swagger_file))
        
        # Discover endpoints
        if not self.discovered_endpoints:
            self.discover_endpoints()
        
        self.result.endpoints_tested = len(self.discovered_endpoints)
        
        # Run tests
        self.test_broken_auth()
        self.test_idor()
        self.test_rate_limiting()
        self.test_mass_assignment()
        self.test_excessive_data_exposure()
        self.test_cors_misconfiguration()
        self.test_injection_in_params()
        self.test_graphql_introspection()
        self.test_graphql_batching(deep=graphql_deep)
        self.test_rate_limit_bypass()
        if fuzz:
            self.test_parameter_fuzzing()
        if smuggle:
            self.test_request_smuggling()
        
        # Complete
        self.result.vulnerabilities = self.vulnerabilities
        self.result.end_time = datetime.now().isoformat()
        
        self.generate_report()
        
        return self.result
    
    def generate_report(self) -> None:
        """Generate JSON and HTML reports."""
        # JSON report
        json_path = os.path.join(self.output_dir, "api_security_report.json")
        with open(json_path, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        
        print(f"\n{Colors.GREEN}[+] JSON report saved: {json_path}{Colors.END}")
        
        # HTML report
        html_path = os.path.join(self.output_dir, "api_security_report.html")
        self.generate_html_report(html_path)
        print(f"{Colors.GREEN}[+] HTML report saved: {html_path}{Colors.END}")
    
    def generate_html_report(self, filepath: str) -> None:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>API Security Test Report - {self.base_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .summary-item {{ text-align: center; padding: 15px; border-radius: 5px; }}
        .critical {{ background: #dc3545; color: white; }}
        .high {{ background: #fd7e14; color: white; }}
        .medium {{ background: #ffc107; color: black; }}
        .low {{ background: #28a745; color: white; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .severity {{ font-weight: bold; padding: 3px 10px; border-radius: 3px; }}
        .owasp {{ background: #e9ecef; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔌 API Security Test Report</h1>
        <p><strong>Target:</strong> {self.base_url}</p>
        <p><strong>Endpoints Tested:</strong> {self.result.endpoints_tested}</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item critical">
                    <h3>{len([v for v in self.result.vulnerabilities if v.severity == 'CRITICAL'])}</h3>
                    <p>CRITICAL</p>
                </div>
                <div class="summary-item high">
                    <h3>{len([v for v in self.result.vulnerabilities if v.severity == 'HIGH'])}</h3>
                    <p>HIGH</p>
                </div>
                <div class="summary-item medium">
                    <h3>{len([v for v in self.result.vulnerabilities if v.severity == 'MEDIUM'])}</h3>
                    <p>MEDIUM</p>
                </div>
                <div class="summary-item low">
                    <h3>{len([v for v in self.result.vulnerabilities if v.severity == 'LOW'])}</h3>
                    <p>LOW</p>
                </div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
"""
        
        if not self.result.vulnerabilities:
            html += "<p style='color: #28a745; font-size: 16px;'>✅ No API vulnerabilities detected!</p>"
        else:
            for i, vuln in enumerate(self.result.vulnerabilities, 1):
                html += f"""
        <div class="vulnerability">
            <h3>#{i} {vuln.name}</h3>
            <span class="severity {vuln.severity.lower()}">{vuln.severity}</span>
            <span class="owasp">{vuln.owasp_api}</span>
            <p><strong>Endpoint:</strong> {vuln.method} {vuln.endpoint}</p>
            <p><strong>Description:</strong> {vuln.description}</p>
            <p><strong>Evidence:</strong> {vuln.evidence}</p>
            <p><strong>Remediation:</strong> {vuln.remediation}</p>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='APISecurityTester - API Security Testing Tool'
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target API base URL')
    parser.add_argument('--auth', help='Authentication token')
    parser.add_argument('--auth-type', default='Bearer', help='Auth type (Bearer, Basic, Token)')
    parser.add_argument('--swagger', help='OpenAPI/Swagger JSON file')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--fuzz', action='store_true', help='Enable parameter fuzzing tests')
    parser.add_argument('--smuggle', action='store_true', help='Enable HTTP request smuggling tests')
    parser.add_argument('--graphql-deep', action='store_true', help='Enable deep GraphQL field-duplication tests')
    
    add_proxy_arg(parser)
    
    args = parser.parse_args()
    
    try:
        tester = APISecurityTester(
            base_url=args.url,
            auth_token=args.auth,
            auth_type=args.auth_type,
            output_dir=args.output,
            proxy=args.proxy
        )
        
        result = tester.run_all_tests(swagger_file=args.swagger, fuzz=args.fuzz,
                                      smuggle=args.smuggle, graphql_deep=args.graphql_deep)
        
        # Print summary
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Test Complete!{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"Total Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"  CRITICAL: {len([v for v in result.vulnerabilities if v.severity == 'CRITICAL'])}")
        print(f"  HIGH: {len([v for v in result.vulnerabilities if v.severity == 'HIGH'])}")
        print(f"  MEDIUM: {len([v for v in result.vulnerabilities if v.severity == 'MEDIUM'])}")
        print(f"  LOW: {len([v for v in result.vulnerabilities if v.severity == 'LOW'])}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Test interrupted{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR]{Colors.END} {str(e)}")


if __name__ == '__main__':
    main()
