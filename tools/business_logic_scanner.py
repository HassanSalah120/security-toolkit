#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
BusinessLogicScanner - Business Logic Vulnerability Scanner
============================================================

Tests for:
    - Price manipulation
    - Quantity manipulation
    - Coupon/Promo code abuse
    - Race conditions
    - Workflow bypass
    - Privilege escalation
    - Account state manipulation
    - Payment flow flaws
    - Inventory manipulation
    - Discount abuse
    - Multi-step workflow logic
    - Promo code race conditions
    - Discount stacking
    - Session integrity

Author: Security Research Team
Version: 1.0.0
License: MIT

Usage:
    python business_logic_scanner.py -u https://shop.target.com
    python business_logic_scanner.py -u https://shop.target.com --cart-test
    python business_logic_scanner.py -u https://shop.target.com --promo-test
    python business_logic_scanner.py -u https://shop.target.com --promo-code SUMMER20
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
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests

from common import Colors, add_proxy_arg

urllib3 = requests.packages.urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "1.0.0"

# Colors imported from common.py

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class LogicVulnerability:
    name: str
    severity: str
    confidence: str
    endpoint: str
    method: str
    description: str
    evidence: str
    remediation: str
    category: str = ""
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
            'category': self.category,
            'cvss': self.cvss
        }

@dataclass
class LogicTestResult:
    target: str
    start_time: str
    end_time: str = ""
    vulnerabilities: List[LogicVulnerability] = field(default_factory=list)
    tests_run: int = 0
    
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
                'tests_run': self.tests_run
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }

# =============================================================================
# BUSINESS LOGIC SCANNER
# =============================================================================

class BusinessLogicScanner:
    """Test for business logic vulnerabilities."""
    
    def __init__(self, base_url: str, auth_token: str = None, output_dir: str = None, promo_code: str = None,
                 proxy: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.output_dir = output_dir or f"logic_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.promo_code = promo_code
        self.proxy = proxy
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        if self.proxy:
            self.session.proxies = {'http': self.proxy, 'https': self.proxy}
        
        if auth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {auth_token}'
            })
        
        self.result = LogicTestResult(
            target=base_url,
            start_time=datetime.now().isoformat()
        )
        
        self.vulnerabilities: List[LogicVulnerability] = []
        self.cart_data = {}
        self.order_data = {}
    
    def add_vulnerability(self, vuln: LogicVulnerability):
        """Add a vulnerability finding."""
        self.vulnerabilities.append(vuln)
        color = Colors.RED if vuln.severity == 'CRITICAL' else Colors.YELLOW if vuln.severity == 'HIGH' else Colors.BLUE
        print(f"{color}[{vuln.severity}]{Colors.END} {vuln.name}")
        print(f"     Category: {vuln.category}")
        print(f"     {vuln.description}")
    
    def _make_thread_session(self) -> requests.Session:
        """Create a per-thread requests.Session with the same auth headers."""
        s = requests.Session()
        s.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        if self.auth_token:
            s.headers.update({'Authorization': f'Bearer {self.auth_token}'})
        if self.proxy:
            s.proxies = {'http': self.proxy, 'https': self.proxy}
        return s
    
    def test_price_manipulation(self) -> None:
        """Test for price manipulation vulnerabilities."""
        print(f"\n{Colors.CYAN}[*] Testing for price manipulation...{Colors.END}")
        
        # Common cart/checkout endpoints
        cart_endpoints = [
            '/api/cart',
            '/api/cart/add',
            '/api/checkout',
            '/api/order',
            '/api/order/create',
            '/api/basket',
            '/api/basket/add',
        ]
        
        price_test_payloads = [
            # Negative price
            {'product_id': 1, 'price': -100, 'quantity': 1},
            {'product_id': 1, 'price': -0.01, 'quantity': 1},
            # Zero price
            {'product_id': 1, 'price': 0, 'quantity': 1},
            {'product_id': 1, 'price': 0.00, 'quantity': 1},
            # Very low price
            {'product_id': 1, 'price': 0.01, 'quantity': 1},
            {'product_id': 1, 'price': 1, 'quantity': 1},
            # Price as string
            {'product_id': 1, 'price': '0', 'quantity': 1},
            {'product_id': 1, 'price': 'free', 'quantity': 1},
            # Large negative (refund abuse)
            {'product_id': 1, 'price': -999999, 'quantity': 1},
        ]
        
        for endpoint in cart_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in price_test_payloads:
                try:
                    response = self.session.post(url, json=payload, timeout=10, verify=False)
                    
                    # Check if price was accepted
                    if response.status_code in [200, 201]:
                        try:
                            data = response.json()
                            
                            # Check if negative/zero price is reflected
                            if 'price' in str(data) or 'total' in str(data):
                                response_str = str(data).lower()
                                
                                if any(x in response_str for x in ['-', '0.00', '0.0', '"0"']):
                                    self.add_vulnerability(LogicVulnerability(
                                        name="Price Manipulation",
                                        severity="CRITICAL",
                                        confidence="FIRM",
                                        endpoint=endpoint,
                                        method="POST",
                                        description="Application accepts manipulated prices (negative/zero)",
                                        evidence=f"Payload: {payload}, Response: {str(data)[:100]}",
                                        remediation="Calculate prices server-side only. Never trust client-provided prices. Validate all price values.",
                                        category="Price Manipulation",
                                        cvss=9.1
                                    ))
                                    break
                        except Exception:
                            pass
                            
                except Exception:
                    pass
    
    def test_quantity_manipulation(self) -> None:
        """Test for quantity manipulation."""
        print(f"\n{Colors.CYAN}[*] Testing for quantity manipulation...{Colors.END}")
        
        quantity_payloads = [
            {'product_id': 1, 'quantity': -1},
            {'product_id': 1, 'quantity': -100},
            {'product_id': 1, 'quantity': 0},
            {'product_id': 1, 'quantity': 999999999},
            {'product_id': 1, 'quantity': 1.5},
            {'product_id': 1, 'quantity': -0.5},
            {'product_id': 1, 'quantity': '999'},
            {'product_id': 1, 'quantity': 'many'},
        ]
        
        cart_endpoints = ['/api/cart/add', '/api/cart', '/api/basket/add']
        
        for endpoint in cart_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in quantity_payloads:
                try:
                    response = self.session.post(url, json=payload, timeout=10, verify=False)
                    
                    if response.status_code in [200, 201]:
                        data = response.json() if response.text else {}
                        
                        # Check for negative quantity (could cause refund)
                        if '-' in str(data.get('quantity', '')):
                            self.add_vulnerability(LogicVulnerability(
                                name="Negative Quantity Accepted",
                                severity="HIGH",
                                confidence="FIRM",
                                endpoint=endpoint,
                                method="POST",
                                description="Application accepts negative quantities",
                                evidence=f"Quantity: {payload.get('quantity')}",
                                remediation="Validate quantity is positive integer. Set maximum limits.",
                                category="Quantity Manipulation",
                                cvss=8.2
                            ))
                            return
                        
                        # Check for extremely large quantity
                        if payload.get('quantity') == 999999999:
                            if 'error' not in str(data).lower():
                                self.add_vulnerability(LogicVulnerability(
                                    name="No Maximum Quantity Limit",
                                    severity="MEDIUM",
                                    confidence="FIRM",
                                    endpoint=endpoint,
                                    method="POST",
                                    description="No maximum quantity limit enforced",
                                    evidence="Extremely large quantity accepted",
                                    remediation="Set reasonable maximum quantity limits per product/order.",
                                    category="Quantity Manipulation",
                                    cvss=5.3
                                ))
                                
                except Exception:
                    pass
    
    def test_coupon_abuse(self) -> None:
        """Test for coupon/promo code abuse."""
        print(f"\n{Colors.CYAN}[*] Testing for coupon/promo code abuse...{Colors.END}")
        
        # Common promo endpoints
        promo_endpoints = [
            '/api/coupon/apply',
            '/api/promo/apply',
            '/api/discount/apply',
            '/api/cart/coupon',
            '/api/checkout/coupon',
        ]
        
        # Test payloads
        promo_payloads = [
            # Multiple applications
            {'code': 'DISCOUNT10'},
            # Case variations
            {'code': 'discount10'},
            {'code': 'DISCOUNT10'},
            {'code': 'DiScOuNt10'},
            # SQL injection in promo
            {'code': "' OR '1'='1"},
            {'code': "admin'--"},
            # Common codes
            {'code': 'FREE'},
            {'code': 'ADMIN'},
            {'code': 'TEST'},
            {'code': 'WELCOME'},
            {'code': 'FIRST'},
            {'code': 'NEWUSER'},
            {'code': '100OFF'},
            {'code': '100%OFF'},
        ]
        
        for endpoint in promo_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Test multiple applications with each payload
            for test_payload in promo_payloads:
                code = test_payload.get('code', 'TEST')
                successful_applications = 0
                
                for i in range(5):
                    try:
                        response = self.session.post(url, json=test_payload, timeout=10, verify=False)
                        
                        if response.status_code == 200:
                            successful_applications += 1
                            
                    except Exception:
                        pass
            
                # If code applied multiple times
                if successful_applications > 1:
                    self.add_vulnerability(LogicVulnerability(
                        name="Coupon Can Be Applied Multiple Times",
                        severity="HIGH",
                        confidence="FIRM",
                        endpoint=endpoint,
                        method="POST",
                        description=f"Coupon '{code}' applied {successful_applications} times",
                        evidence=f"Same coupon code '{code}' accepted {successful_applications} times in a row",
                        remediation="Track coupon usage. Limit to one use per user/order.",
                        category="Coupon Abuse",
                        cvss=7.5
                    ))
                    break
            
            # Test SQL injection in promo codes
            for payload in promo_payloads:
                if "'" in payload['code']:
                    try:
                        response = self.session.post(url, json=payload, timeout=10, verify=False)
                        
                        sql_errors = ['sql', 'syntax', 'mysql', 'sqlite', 'postgres']
                        for error in sql_errors:
                            if error in response.text.lower():
                                self.add_vulnerability(LogicVulnerability(
                                    name="SQL Injection in Promo Code",
                                    severity="CRITICAL",
                                    confidence="FIRM",
                                    endpoint=endpoint,
                                    method="POST",
                                    description="SQL injection in promo code field",
                                    evidence=f"SQL error: {error}",
                                    remediation="Use parameterized queries. Validate promo codes against whitelist.",
                                    category="Injection",
                                    cvss=9.8
                                ))
                                break
                                
                    except Exception:
                        pass
    
    def test_race_condition(self) -> None:
        """Test for race conditions."""
        print(f"\n{Colors.CYAN}[*] Testing for race conditions...{Colors.END}")
        
        # Test concurrent requests to same endpoint
        race_endpoints = [
            ('/api/cart/add', 'POST', {'product_id': 1, 'quantity': 1}),
            ('/api/checkout', 'POST', {}),
            ('/api/order/create', 'POST', {}),
            ('/api/wallet/withdraw', 'POST', {'amount': 100}),
            ('/api/points/redeem', 'POST', {'points': 100}),
        ]
        
        for endpoint, method, payload in race_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            # Use ThreadPoolExecutor for thread-safe concurrent requests
            results = []
            results_lock = threading.Lock()
            barrier = threading.Barrier(10)
            
            def make_request():
                try:
                    barrier.wait(timeout=5)
                    with requests.Session() as race_session:
                        race_session.headers.update(self.session.headers)
                        if self.proxy:
                            race_session.proxies = {'http': self.proxy, 'https': self.proxy}
                        if method == 'POST':
                            response = race_session.post(url, json=payload, timeout=10, verify=False)
                        else:
                            response = race_session.get(url, timeout=10, verify=False)
                        with results_lock:
                            results.append(response.status_code)
                except Exception as e:
                    with results_lock:
                        results.append(0)
            
            threads = []
            for _ in range(10):
                t = threading.Thread(target=make_request)
                threads.append(t)
            
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            # Check results
            successful = [r for r in results if r == 200 or r == 201]
            
            # If multiple requests succeeded when only one should
            if len(successful) > 1 and any(x in endpoint for x in ['checkout', 'order', 'withdraw', 'redeem']):
                self.add_vulnerability(LogicVulnerability(
                    name="Race Condition",
                    severity="HIGH",
                    confidence="TENTATIVE",
                    endpoint=endpoint,
                    method=method,
                    description=f"Race condition allows multiple concurrent operations",
                    evidence=f"{len(successful)} out of 10 concurrent requests succeeded",
                    remediation="Implement proper locking mechanisms. Use database transactions. Add idempotency keys.",
                    category="Race Condition",
                    cvss=7.5
                ))
    
    def test_workflow_bypass(self) -> None:
        """Test for workflow bypass."""
        print(f"\n{Colors.CYAN}[*] Testing for workflow bypass...{Colors.END}")
        
        # Test skipping payment step
        workflow_tests = [
            {
                'name': 'Skip Payment Step',
                'steps': [
                    ('/api/cart', 'GET'),
                    ('/api/checkout/confirm', 'POST', {'skip_payment': True}),
                ]
            },
            {
                'name': 'Direct Order Creation',
                'steps': [
                    ('/api/order/create', 'POST', {'status': 'completed', 'paid': True}),
                ]
            },
            {
                'name': 'Bypass Email Verification',
                'steps': [
                    ('/api/register', 'POST', {'email': 'test@test.com', 'verified': True}),
                ]
            },
            {
                'name': 'Skip Approval Workflow',
                'steps': [
                    ('/api/request/create', 'POST', {'status': 'approved'}),
                ]
            },
        ]
        
        for test in workflow_tests:
            for step in test['steps']:
                if len(step) == 2:
                    endpoint, method = step
                    payload = {}
                else:
                    endpoint, method, payload = step
                
                url = urljoin(self.base_url, endpoint)
                
                try:
                    if method == 'GET':
                        response = self.session.get(url, timeout=10, verify=False)
                    else:
                        response = self.session.post(url, json=payload, timeout=10, verify=False)
                    
                    if response.status_code in [200, 201]:
                        data = response.json() if response.text else {}
                        
                        # Check if bypass worked
                        bypass_indicators = ['approved', 'completed', 'verified', 'paid', 'success']
                        for indicator in bypass_indicators:
                            if indicator in str(data).lower() and indicator in str(payload).lower():
                                self.add_vulnerability(LogicVulnerability(
                                    name=f"Workflow Bypass: {test['name']}",
                                    severity="HIGH",
                                    confidence="TENTATIVE",
                                    endpoint=endpoint,
                                    method=method,
                                    description=f"Workflow step can be bypassed",
                                    evidence=f"Payload: {payload}",
                                    remediation="Implement server-side workflow validation. Never trust client-provided status values.",
                                    category="Workflow Bypass",
                                    cvss=8.1
                                ))
                                break
                                
                except Exception:
                    pass
    
    def test_workflow_logic(self) -> None:
        """Simulate multi-step e-commerce workflow and detect logic flaws.

        Maintains a session chain through: add to cart -> apply promo -> checkout -> confirm.
        Reports if any step can be skipped or reordered.
        Tests if negative quantities in early steps affect later price calculations.
        """
        print(f"\n{Colors.CYAN}[*] Testing multi-step workflow logic...{Colors.END}")

        workflow_steps = [
            ('add_to_cart', '/api/cart/add', 'POST', {'product_id': 1, 'quantity': 1, 'price': 10.00}),
            ('apply_promo', '/api/promo/apply', 'POST', {'code': self.promo_code or 'TEST10'}),
            ('checkout', '/api/checkout', 'POST', {}),
            ('confirm_order', '/api/order/confirm', 'POST', {}),
        ]

        # --- 1. Test normal workflow execution ---
        print(f"     [i] Running normal workflow sequence...")
        workflow_session = self._make_thread_session()
        workflow_ok = True
        step_responses = {}
        for step_name, endpoint, method, payload in workflow_steps:
            url = urljoin(self.base_url, endpoint)
            try:
                if method == 'POST':
                    resp = workflow_session.post(url, json=payload, timeout=10, verify=False)
                else:
                    resp = workflow_session.get(url, timeout=10, verify=False)
                step_responses[step_name] = resp
                if resp.status_code in (200, 201):
                    print(f"       [+] {step_name}: {resp.status_code}")
                else:
                    print(f"       [-] {step_name}: {resp.status_code} (step failed or rejected)")
                    workflow_ok = False
            except Exception as e:
                print(f"       [!] {step_name}: exception - {str(e)[:60]}")
                step_responses[step_name] = None
                workflow_ok = False

        # --- 2. Test skipping steps ---
        print(f"     [i] Testing step skipping...")
        skip_scenarios = [
            (['checkout', 'confirm_order'], 'Skip add_to_cart and promo'),
            (['confirm_order'], 'Skip all intermediate steps'),
            (['add_to_cart', 'confirm_order'], 'Skip promo and checkout'),
        ]
        for run_steps, label in skip_scenarios:
            skip_session = self._make_thread_session()
            for step_name, endpoint, method, payload in workflow_steps:
                if step_name not in run_steps:
                    continue
                url = urljoin(self.base_url, endpoint)
                try:
                    resp = skip_session.post(url, json=payload, timeout=10, verify=False)
                    if resp.status_code in (200, 201):
                        self.add_vulnerability(LogicVulnerability(
                            name="Workflow Step Skipped",
                            severity="MEDIUM",
                            confidence="TENTATIVE",
                            endpoint=endpoint,
                            method=method,
                            description=f"Workflow step can be skipped: {label}",
                            evidence=f"Skipped steps {run_steps} and reached {step_name} successfully",
                            remediation="Enforce server-side workflow state machine. Require prerequisite steps before allowing later ones.",
                            category="Workflow Logic",
                            cvss=6.2
                        ))
                except Exception:
                    pass

        # --- 3. Test reordering steps ---
        print(f"     [i] Testing step reordering...")
        reordered = [workflow_steps[3], workflow_steps[1], workflow_steps[2], workflow_steps[0]]
        reorder_session = self._make_thread_session()
        reorder_ok = False
        for step_name, endpoint, method, payload in reordered:
            url = urljoin(self.base_url, endpoint)
            try:
                resp = reorder_session.post(url, json=payload, timeout=10, verify=False)
                if step_name == 'confirm_order' and resp.status_code in (200, 201):
                    reorder_ok = True
            except Exception:
                pass
        if reorder_ok:
            self.add_vulnerability(LogicVulnerability(
                name="Workflow Reordering Bypass",
                severity="HIGH",
                confidence="TENTATIVE",
                endpoint="/api/order/confirm",
                method="POST",
                description="Workflow steps can be reordered - confirm_order succeeded before add_to_cart",
                evidence="Executed confirm_order before add_to_cart and succeeded",
                remediation="Enforce strict workflow ordering on the server side.",
                category="Workflow Logic",
                cvss=7.8
            ))

        # --- 4. Test negative quantity impact on later steps ---
        print(f"     [i] Testing negative quantity carry-over...")
        neg_qty_session = self._make_thread_session()
        neg_payload = {'product_id': 1, 'quantity': -5, 'price': 10.00}
        try:
            add_url = urljoin(self.base_url, '/api/cart/add')
            resp_add = neg_qty_session.post(add_url, json=neg_payload, timeout=10, verify=False)
            if resp_add.status_code in (200, 201):
                checkout_url = urljoin(self.base_url, '/api/checkout')
                resp_checkout = neg_qty_session.post(checkout_url, json={}, timeout=10, verify=False)
                if resp_checkout.status_code in (200, 201):
                    body = resp_checkout.text.lower()
                    if 'total' in body:
                        try:
                            data = resp_checkout.json()
                            total = data.get('total', 0)
                            if isinstance(total, (int, float)) and total < 0:
                                self.add_vulnerability(LogicVulnerability(
                                    name="Negative Quantity Affects Price Calculation",
                                    severity="CRITICAL",
                                    confidence="FIRM",
                                    endpoint="/api/checkout",
                                    method="POST",
                                    description="Negative quantity from cart step resulted in negative total at checkout",
                                    evidence=f"Added -5 qty, checkout total: {total}",
                                    remediation="Validate quantities at every workflow step. Never allow negative quantities to accumulate server-side.",
                                    category="Workflow Logic",
                                    cvss=9.3
                                ))
                        except Exception:
                            pass
        except Exception:
            pass

    def test_promo_code_race(self) -> None:
        """Test race condition on a specific promo code.

        Sends 20 concurrent redemption requests for the same code using threading.Barrier.
        Each request uses its own requests.Session with the same auth.
        Reports if the same code was applied more times than its max_uses allows.
        """
        print(f"\n{Colors.CYAN}[*] Testing promo code race condition...{Colors.END}")

        test_codes = []
        if self.promo_code:
            test_codes.append(self.promo_code)
        test_codes.extend(['RACE100', 'STACK50', 'WELCOME20', 'FIRST10', 'VIP30'])

        promo_endpoints = [
            '/api/coupon/apply',
            '/api/promo/apply',
            '/api/discount/apply',
            '/api/cart/coupon',
            '/api/checkout/coupon',
        ]

        for code in test_codes:
            for endpoint in promo_endpoints:
                url = urljoin(self.base_url, endpoint)
                print(f"     [i] Racing promo code '{code}' on {endpoint} with 20 threads...")

                success_count = 0
                results_lock = threading.Lock()
                barrier = threading.Barrier(20)

                def race_apply():
                    nonlocal success_count
                    try:
                        barrier.wait(timeout=10)
                        thread_session = self._make_thread_session()
                        resp = thread_session.post(url, json={'code': code}, timeout=10, verify=False)
                        with results_lock:
                            if resp.status_code in (200, 201):
                                success_count += 1
                    except Exception:
                        pass

                threads = []
                for _ in range(20):
                    t = threading.Thread(target=race_apply)
                    threads.append(t)

                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                if success_count > 1:
                    # Typically a promo code should only be usable once per user/cart
                    max_expected = 1
                    if success_count > max_expected:
                        self.add_vulnerability(LogicVulnerability(
                            name="Promo Code Race Condition",
                            severity="CRITICAL",
                            confidence="FIRM",
                            endpoint=endpoint,
                            method="POST",
                            description=f"Promo code '{code}' was redeemed {success_count} times concurrently (expected max {max_expected})",
                            evidence=f"20 concurrent requests for code '{code}' resulted in {success_count} successful redemptions",
                            remediation="Use database-level unique constraints or pessimistic locking for promo code redemption. Add idempotency keys per request.",
                            category="Race Condition",
                            cvss=9.0
                        ))
                        break  # Found vulnerability for this code, no need to test more endpoints
                else:
                    print(f"       [+] Code '{code}' on {endpoint}: {success_count} successes (within limits)")

    def test_discount_stacking(self) -> None:
        """Test for discount stacking / combining vulnerabilities.

        Attempts to apply multiple promo codes to the same cart/order.
        Tests if percentage discounts compound (100% + 100% = free).
        Tests if free-shipping + percentage discounts stack.
        """
        print(f"\n{Colors.CYAN}[*] Testing discount stacking...{Colors.END}")

        # First, add an item to cart to have a base price
        stack_session = self._make_thread_session()
        add_url = urljoin(self.base_url, '/api/cart/add')
        try:
            stack_session.post(add_url, json={'product_id': 1, 'quantity': 1, 'price': 50.00}, timeout=10, verify=False)
        except Exception:
            pass

        stacking_tests = [
            {
                'name': 'Multiple percentage codes stacking',
                'codes': ['100OFF', '100OFF'],
                'endpoint': '/api/promo/apply',
                'expected_behavior': 'compounding_percentage'
            },
            {
                'name': 'Free shipping + percentage discount',
                'codes': ['FREESHIP', 'SAVE20'],
                'endpoint': '/api/promo/apply',
                'expected_behavior': 'stacking_free_shipping_with_percent'
            },
            {
                'name': 'Same code applied twice to same cart',
                'codes': ['STACK50', 'STACK50'],
                'endpoint': '/api/coupon/apply',
                'expected_behavior': 'duplicate_code_stacking'
            },
            {
                'name': 'Flat + percentage hybrid stacking',
                'codes': ['FLAT10', 'PERCENT20'],
                'endpoint': '/api/discount/apply',
                'expected_behavior': 'hybrid_discount_stacking'
            },
        ]

        for test_case in stacking_tests:
            codes = test_case['codes']
            ep = test_case['endpoint']
            url = urljoin(self.base_url, ep)
            applied_count = 0
            final_cart = None

            session = self._make_thread_session()
            # Add fresh item per test case
            try:
                session.post(add_url, json={'product_id': 1, 'quantity': 1, 'price': 50.00}, timeout=10, verify=False)
            except Exception:
                pass

            for code in codes:
                try:
                    resp = session.post(url, json={'code': code}, timeout=10, verify=False)
                    if resp.status_code in (200, 201):
                        applied_count += 1
                        final_cart = resp.json() if resp.text else {}
                except Exception:
                    pass

            # Now try to apply a second code that should conflict
            if applied_count >= 2:
                self.add_vulnerability(LogicVulnerability(
                    name="Discount Stacking",
                    severity="HIGH",
                    confidence="TENTATIVE",
                    endpoint=ep,
                    method="POST",
                    description=f"Discount stacking detected: {test_case['name']}",
                    evidence=f"Applied codes {codes} to same cart, {applied_count} succeeded. Expected: only 1 should apply.",
                    remediation="Restrict carts to a single promo code. Validate exclusivity groups. Prevent stacking of overlapping discount types.",
                    category="Discount Abuse",
                    cvss=7.8
                ))

            # Check if the total reflects compounded discounts
            if final_cart:
                try:
                    total = str(final_cart).lower()
                    if 'total' in total:
                        total_val = final_cart.get('total', 0)
                        if isinstance(total_val, (int, float)) and total_val <= 0:
                            self.add_vulnerability(LogicVulnerability(
                                name="Negative/Zero Total via Discount Stacking",
                                severity="CRITICAL",
                                confidence="FIRM",
                                endpoint=ep,
                                method="POST",
                                description=f"Discount stacking resulted in zero or negative total: {total_val}",
                                evidence=f"Applied {codes}, final cart total = {total_val}",
                                remediation="Enforce minimum order totals. Prevent discounts from reducing price below zero. Validate after each discount application.",
                                category="Discount Abuse",
                                cvss=9.2
                            ))
                except Exception:
                    pass

    def test_session_integrity(self) -> None:
        """Test session handling across users.

        Performs actions as user A, then checks if user B can see/affect the same data.
        Tests if logout properly invalidates the session.
        Tests if session fixation allows another user to take over.
        """
        print(f"\n{Colors.CYAN}[*] Testing session integrity...{Colors.END}")

        # Generate two distinct auth tokens for user A and user B
        user_a_token = self.auth_token or 'test_user_a_token'
        user_b_token = 'test_user_b_token_fake'

        session_a = self._make_thread_session()
        session_b = self._make_thread_session()
        session_b.headers.update({'Authorization': f'Bearer {user_b_token}'})

        # --- Test 1: User A creates data, User B accesses it ---
        print(f"     [i] Testing data isolation between users...")
        cart_add_url = urljoin(self.base_url, '/api/cart/add')
        cart_get_url = urljoin(self.base_url, '/api/cart')
        orders_url = urljoin(self.base_url, '/api/orders')

        user_a_cart_id = None
        try:
            resp_a = session_a.post(cart_add_url, json={'product_id': 1, 'quantity': 1}, timeout=10, verify=False)
            if resp_a.status_code in (200, 201):
                data_a = resp_a.json() if resp_a.text else {}
                user_a_cart_id = data_a.get('cart_id') or data_a.get('id')
        except Exception:
            pass

        # User B tries to read User A's cart
        try:
            resp_b = session_b.get(cart_get_url, timeout=10, verify=False)
            if resp_b.status_code in (200, 201):
                data_b = resp_b.json() if resp_b.text else {}
                body_b = str(data_b).lower()
                # If user B sees user A's cart data, that's a vulnerability
                if user_a_cart_id and str(user_a_cart_id) in body_b:
                    self.add_vulnerability(LogicVulnerability(
                        name="Session Integrity - Data Leak Between Users",
                        severity="HIGH",
                        confidence="TENTATIVE",
                        endpoint="/api/cart",
                        method="GET",
                        description="User B could access cart data belonging to User A",
                        evidence=f"User B's cart response contained User A's cart_id: {user_a_cart_id}",
                        remediation="Enforce per-user data isolation. Always scope queries by the authenticated user. Never return data belonging to other users.",
                        category="Session Integrity",
                        cvss=8.5
                    ))
        except Exception:
            pass

        # User B tries to affect User A's data directly
        if user_a_cart_id:
            try:
                resp_b_affect = session_b.post(
                    urljoin(self.base_url, f'/api/cart/{user_a_cart_id}/add'),
                    json={'product_id': 2, 'quantity': 1},
                    timeout=10, verify=False
                )
                if resp_b_affect.status_code in (200, 201):
                    self.add_vulnerability(LogicVulnerability(
                        name="Session Integrity - Cross-User Data Manipulation",
                        severity="CRITICAL",
                        confidence="TENTATIVE",
                        endpoint=f"/api/cart/{user_a_cart_id}/add",
                        method="POST",
                        description="User B modified User A's cart data",
                        evidence=f"User B successfully added items to User A's cart (cart_id: {user_a_cart_id})",
                        remediation="Authorize every data access against the authenticated user. Use user-scoped identifiers server-side.",
                        category="Session Integrity",
                        cvss=9.4
                    ))
            except Exception:
                pass

        # --- Test 2: Logout invalidation ---
        print(f"     [i] Testing logout session invalidation...")
        logout_url = urljoin(self.base_url, '/api/logout')
        try:
            resp_logout = session_a.post(logout_url, timeout=10, verify=False)
            if resp_logout.status_code in (200, 201, 204):
                # After logout, try to access cart again with same session
                resp_after_logout = session_a.get(cart_get_url, timeout=10, verify=False)
                if resp_after_logout.status_code in (200, 201):
                    # Session still functional - possible invalidation failure
                    # Check if it returned actual data vs a "not authenticated" message
                    body_al = resp_after_logout.text.lower()
                    if 'cart' in body_al or 'items' in body_al or 'product' in body_al:
                        self.add_vulnerability(LogicVulnerability(
                            name="Session Not Invalidated on Logout",
                            severity="HIGH",
                            confidence="FIRM",
                            endpoint="/api/logout",
                            method="POST",
                            description="Session remained active after logout - cart data still accessible",
                            evidence=f"After logout, GET {cart_get_url} returned {resp_after_logout.status_code} with data",
                            remediation="Invalidate the server-side session on logout. Clear auth tokens and force re-authentication.",
                            category="Session Integrity",
                            cvss=7.9
                        ))
        except Exception:
            pass

        # --- Test 3: Session fixation ---
        print(f"     [i] Testing session fixation...")
        # Attempt to set a forged session cookie and see if the server accepts it
        fixed_session_id = 'FIXED-SESSION-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
        fixation_session = requests.Session()
        fixation_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        if self.proxy:
            fixation_session.proxies = {'http': self.proxy, 'https': self.proxy}
        fixation_session.cookies.set('session', fixed_session_id, domain=urlparse(self.base_url).hostname)
        if self.auth_token:
            fixation_session.headers.update({'Authorization': f'Bearer {self.auth_token}'})

        try:
            # First verify endpoint requires authentication before testing
            unauth_session = requests.Session()
            if self.proxy:
                unauth_session.proxies = {'http': self.proxy, 'https': self.proxy}
            unauth_resp = unauth_session.get(cart_get_url, timeout=10, verify=False)
            if unauth_resp.status_code in (200, 201):
                return  # Endpoint is public, no session fixation risk
            resp_fix = fixation_session.get(cart_get_url, timeout=10, verify=False)
            if resp_fix.status_code in (200, 201):
                data_fix = resp_fix.json() if resp_fix.text else {}
                # If the server accepted our fixed session and returned user data
                if data_fix and ('cart' in str(data_fix).lower() or 'items' in str(data_fix).lower()):
                    self.add_vulnerability(LogicVulnerability(
                        name="Session Fixation",
                        severity="HIGH",
                        confidence="TENTATIVE",
                        endpoint="/api/cart",
                        method="GET",
                        description="Server accepted a pre-set (fixed) session cookie without proper regeneration",
                        evidence=f"Set session cookie to '{fixed_session_id}' and server returned valid cart data",
                        remediation="Regenerate session IDs after login. Never accept user-provided session tokens. Use secure, random session identifiers.",
                        category="Session Integrity",
                        cvss=7.5
                    ))
        except Exception:
            pass
    
    def test_privilege_escalation(self) -> None:
        """Test for privilege escalation."""
        print(f"\n{Colors.CYAN}[*] Testing for privilege escalation...{Colors.END}")
        
        # Test accessing admin endpoints
        admin_endpoints = [
            '/api/admin',
            '/api/admin/users',
            '/api/admin/orders',
            '/api/admin/settings',
            '/api/admin/config',
            '/api/users',
            '/api/manage',
            '/api/dashboard/admin',
        ]
        
        for endpoint in admin_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            try:
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    data = response.json() if response.text else {}
                    
                    if data and not isinstance(data, list):
                        data = [data]
                    
                    if data:
                        self.add_vulnerability(LogicVulnerability(
                            name="Privilege Escalation - Admin Endpoint Accessible",
                            severity="CRITICAL",
                            confidence="FIRM",
                            endpoint=endpoint,
                            method="GET",
                            description="Admin endpoint accessible without proper authorization",
                            evidence=f"Got {len(data)} items from admin endpoint",
                            remediation="Implement proper role-based access control. Verify user permissions on every request.",
                            category="Privilege Escalation",
                            cvss=9.8
                        ))
                        
            except Exception:
                pass
    
    def test_account_state_manipulation(self) -> None:
        """Test for account state manipulation."""
        print(f"\n{Colors.CYAN}[*] Testing for account state manipulation...{Colors.END}")
        
        state_payloads = [
            {'is_premium': True},
            {'is_verified': True},
            {'balance': 999999},
            {'credits': 999999},
            {'subscription': 'premium'},
            {'role': 'admin'},
            {'permissions': ['admin', 'write', 'delete']},
            {'account_type': 'business'},
            {'tier': 'gold'},
        ]
        
        profile_endpoints = [
            '/api/user',
            '/api/user/update',
            '/api/profile',
            '/api/account',
            '/api/settings',
        ]
        
        for endpoint in profile_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in state_payloads:
                try:
                    response = self.session.patch(url, json=payload, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        data = response.json() if response.text else {}
                        
                        # Check if state was changed
                        for key in payload.keys():
                            if key in str(data):
                                self.add_vulnerability(LogicVulnerability(
                                    name="Account State Manipulation",
                                    severity="HIGH",
                                    confidence="TENTATIVE",
                                    endpoint=endpoint,
                                    method="PATCH",
                                    description=f"Can modify account state: {key}",
                                    evidence=f"Payload: {payload}",
                                    remediation="Whitelist allowed fields for user updates. Never allow modification of privilege fields.",
                                    category="Account Manipulation",
                                    cvss=8.2
                                ))
                                return
                                
                except Exception:
                    pass
    
    def test_payment_flow_flaws(self) -> None:
        """Test for payment flow flaws."""
        print(f"\n{Colors.CYAN}[*] Testing for payment flow flaws...{Colors.END}")
        
        payment_endpoints = [
            '/api/payment/process',
            '/api/payment/verify',
            '/api/checkout/payment',
        ]
        
        payment_payloads = [
            # Currency manipulation
            {'amount': 100, 'currency': 'USD', 'converted_currency': 'JPY', 'converted_amount': 100},
            # Payment status manipulation
            {'amount': 100, 'status': 'completed'},
            {'amount': 100, 'paid': True},
            # Transaction ID reuse
            {'transaction_id': 'txn_test_123'},
            # Negative amount (refund abuse)
            {'amount': -100},
        ]
        
        for endpoint in payment_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in payment_payloads:
                try:
                    response = self.session.post(url, json=payload, timeout=10, verify=False)
                    
                    if response.status_code in [200, 201]:
                        data = response.json() if response.text else {}
                        
                        # Check if payment was processed with manipulated data
                        if 'success' in str(data).lower() or 'completed' in str(data).lower():
                            self.add_vulnerability(LogicVulnerability(
                                name="Payment Flow Manipulation",
                                severity="CRITICAL",
                                confidence="TENTATIVE",
                                endpoint=endpoint,
                                method="POST",
                                description="Payment flow accepts manipulated parameters",
                                evidence=f"Payload: {payload}",
                                remediation="Verify all payment details server-side. Use payment gateway validation. Never trust client-provided payment status.",
                                category="Payment Flaws",
                                cvss=9.1
                            ))
                            return
                            
                except Exception:
                    pass
    
    def test_inventory_manipulation(self) -> None:
        """Test for inventory manipulation."""
        print(f"\n{Colors.CYAN}[*] Testing for inventory manipulation...{Colors.END}")
        
        inventory_endpoints = [
            '/api/inventory',
            '/api/products',
            '/api/stock',
            '/api/admin/inventory',
        ]
        
        inventory_payloads = [
            {'product_id': 1, 'stock': 999999},
            {'product_id': 1, 'stock': -1},
            {'product_id': 1, 'available': True, 'stock': 0},
        ]
        
        for endpoint in inventory_endpoints:
            url = urljoin(self.base_url, endpoint)
            
            for payload in inventory_payloads:
                try:
                    response = self.session.put(url, json=payload, timeout=10, verify=False)
                    
                    if response.status_code == 200:
                        self.add_vulnerability(LogicVulnerability(
                            name="Inventory Manipulation",
                            severity="HIGH",
                            confidence="FIRM",
                            endpoint=endpoint,
                            method="PUT",
                            description="Can modify inventory without authorization",
                            evidence=f"Payload: {payload}",
                            remediation="Restrict inventory management to admin users. Implement audit logging.",
                            category="Inventory Manipulation",
                            cvss=7.5
                        ))
                        return
                        
                except Exception:
                    pass
    
    def run_all_tests(self) -> LogicTestResult:
        """Run all business logic tests."""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}BusinessLogicScanner v{VERSION}{Colors.END}")
        print(f"{Colors.BOLD}Target: {self.base_url}{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")
        
        tests = [
            ('Price Manipulation', self.test_price_manipulation),
            ('Quantity Manipulation', self.test_quantity_manipulation),
            ('Coupon Abuse', self.test_coupon_abuse),
            ('Race Condition', self.test_race_condition),
            ('Workflow Bypass', self.test_workflow_bypass),
            ('Workflow Logic', self.test_workflow_logic),
            ('Promo Code Race Condition', self.test_promo_code_race),
            ('Discount Stacking', self.test_discount_stacking),
            ('Session Integrity', self.test_session_integrity),
            ('Privilege Escalation', self.test_privilege_escalation),
            ('Account State Manipulation', self.test_account_state_manipulation),
            ('Payment Flow Flaws', self.test_payment_flow_flaws),
            ('Inventory Manipulation', self.test_inventory_manipulation),
        ]
        
        for test_name, test_func in tests:
            try:
                print(f"\n{Colors.CYAN}[*] Testing for {test_name}...{Colors.END}")
                test_func()
                self.result.tests_run += 1
            except Exception as e:
                print(f"{Colors.YELLOW}[!] {test_name} test encountered error: {str(e)[:50]}{Colors.END}")
                continue
        
        # Complete
        self.result.vulnerabilities = self.vulnerabilities
        self.result.end_time = datetime.now().isoformat()
        
        self.generate_report()
        
        return self.result
    
    def generate_report(self) -> None:
        """Generate JSON and HTML reports."""
        # JSON report
        json_path = os.path.join(self.output_dir, "business_logic_report.json")
        with open(json_path, 'w') as f:
            json.dump(self.result.to_dict(), f, indent=2)
        
        print(f"\n{Colors.GREEN}[+] JSON report saved: {json_path}{Colors.END}")
        
        # HTML report
        html_path = os.path.join(self.output_dir, "business_logic_report.html")
        self.generate_html_report(html_path)
        print(f"{Colors.GREEN}[+] HTML report saved: {html_path}{Colors.END}")
    
    def generate_html_report(self, filepath: str) -> None:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Business Logic Security Test Report - {self.base_url}</title>
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
        .category {{ background: #e9ecef; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>💰 Business Logic Security Test Report</h1>
        <p><strong>Target:</strong> {self.base_url}</p>
        
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
            html += "<p style='color: #28a745; font-size: 16px;'>✅ No business logic vulnerabilities detected!</p>"
        else:
            for i, vuln in enumerate(self.result.vulnerabilities, 1):
                html += f"""
        <div class="vulnerability">
            <h3>#{i} {vuln.name}</h3>
            <span class="severity {vuln.severity.lower()}">{vuln.severity}</span>
            <span class="category">{vuln.category}</span>
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
        description='BusinessLogicScanner - Business Logic Vulnerability Scanner'
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target base URL')
    parser.add_argument('--auth', help='Authentication token')
    parser.add_argument('--cart-test', action='store_true', help='Test cart/checkout flows')
    parser.add_argument('--promo-test', action='store_true', help='Test promo codes')
    parser.add_argument('--promo-code', help='Specific promo code to use in race condition testing')
    parser.add_argument('-o', '--output', help='Output directory')
    
    add_proxy_arg(parser)
    
    args = parser.parse_args()
    
    try:
        scanner = BusinessLogicScanner(
            base_url=args.url,
            auth_token=args.auth,
            output_dir=args.output,
            promo_code=args.promo_code,
            proxy=args.proxy
        )
        
        result = scanner.run_all_tests()
        
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
