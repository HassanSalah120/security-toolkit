#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
DEEP SECURITY ANALYSIS TOOL
Comprehensive vulnerability assessment for Insomnia Gaming Egypt API
"""

import requests
import json
import os
import time
from datetime import datetime
from urllib.parse import urljoin, parse_qs, urlparse
from colorama import Fore, Style, init

init(autoreset=True)

class DeepSecurityAnalyzer:
    def __init__(self, base_url="https://insomniagamingegypt.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://insomniagamingegypt.com/event/1/insomnia-egypt-gaming-festival-2026',
        })
        
        self.findings = []
        self.output_dir = f"evidence\deep_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Load existing data
        self.load_existing_data()
    
    def load_existing_data(self):
        """Load previously downloaded data"""
        try:
            with open('evidence\downloaded_data\event_1_full_data.json', 'r') as f:
                self.event_data = json.load(f)
            print(f"{Fore.GREEN}[+] Loaded event data")
        except:
            self.event_data = None
    
    def save_finding(self, category, title, data):
        """Save a finding to file"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'title': title,
            'data': data
        }
        self.findings.append(finding)
        
        filename = f"{category}_{title.replace(' ', '_').replace('/', '_')}.json"
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(finding, f, indent=2)
        print(f"{Fore.CYAN}[SAVED] {filepath}")
        return finding
    
    def analyze_event_data_deep(self):
        """Deep analysis of event data for sensitive exposure"""
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}DEEP ANALYSIS: Event Data Sensitive Information")
        print(f"{Fore.MAGENTA}{'='*70}\n")
        
        if not self.event_data:
            print(f"{Fore.RED}[-] No event data loaded")
            return
        
        data = self.event_data.get('data', {})
        sensitive_fields = []
        
        # Check for sensitive fields
        checks = [
            ('organizer.email', 'Organizer email exposed'),
            ('organizer.phone', 'Organizer phone exposed'),
            ('settings.support_email', 'Support email exposed'),
            ('settings.maps_url', 'Internal maps URL'),
            ('settings.payment_providers', 'Payment providers exposed'),
            ('settings.location_details', 'Venue location details'),
            ('product_categories', 'Product/pricing data'),
        ]
        
        for field_path, description in checks:
            value = self.get_nested_value(data, field_path)
            if value:
                sensitive_fields.append({
                    'field': field_path,
                    'description': description,
                    'value': str(value)[:200]
                })
                print(f"{Fore.YELLOW}[!] {description}: {str(value)[:100]}")
        
        # Check for internal API endpoints in config
        if 'settings' in data:
            settings = data['settings']
            internal_endpoints = []
            for key, value in settings.items():
                if isinstance(value, str) and ('api' in value or 'localhost' in value or 'internal' in value):
                    internal_endpoints.append({key: value})
                    print(f"{Fore.RED}[CRITICAL] Internal endpoint exposed: {key} = {value}")
            
            if internal_endpoints:
                self.save_finding('information_disclosure', 'internal_endpoints_exposed', {
                    'endpoints': internal_endpoints,
                    'location': 'event.settings'
                })
        
        # Check product data for pricing manipulation
        if 'product_categories' in data:
            products = []
            for cat in data['product_categories']:
                for prod in cat.get('products', []):
                    products.append({
                        'id': prod.get('id'),
                        'title': prod.get('title'),
                        'price': prod.get('max_tier_price'),
                        'type': prod.get('type'),
                        'event_id': prod.get('event_id')
                    })
            
            print(f"\n{Fore.CYAN}[*] Found {len(products)} products with pricing data")
            self.save_finding('data_exposure', 'product_pricing_exposed', {
                'product_count': len(products),
                'products': products,
                'risk': 'Price manipulation possible if checkout lacks server validation'
            })
        
        self.save_finding('information_disclosure', 'sensitive_fields_exposed', sensitive_fields)
    
    def get_nested_value(self, data, path):
        """Get nested dictionary value"""
        keys = path.split('.')
        value = data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
    
    def test_idor_deep(self):
        """Deep IDOR testing"""
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}DEEP ANALYSIS: IDOR (Insecure Direct Object Reference)")
        print(f"{Fore.MAGENTA}{'='*70}\n")
        
        # Test event ID enumeration
        print(f"{Fore.YELLOW}[TEST] Testing event ID access patterns...")
        
        event_tests = []
        for event_id in [1, 2, 3, 99, 100, 1000]:
            try:
                resp = self.session.get(f"{self.base_url}/api/public/events/{event_id}", timeout=5)
                event_tests.append({
                    'id': event_id,
                    'status': resp.status_code,
                    'size': len(resp.text),
                    'exists': resp.status_code == 200 and len(resp.text) > 1000
                })
                if resp.status_code == 200:
                    print(f"{Fore.GREEN}[+] Event {event_id}: ACCESSIBLE ({len(resp.text)} bytes)")
                else:
                    print(f"{Fore.RED}[-] Event {event_id}: {resp.status_code}")
            except Exception as e:
                print(f"{Fore.RED}[!] Event {event_id}: Error - {e}")
        
        self.save_finding('idor', 'event_id_enumeration', event_tests)
        
        # Test product ID access
        print(f"\n{Fore.YELLOW}[TEST] Testing product ID access...")
        product_tests = []
        for product_id in [1, 2, 3, 4, 5, 99, 100]:
            try:
                # Try to access product directly
                resp = self.session.get(
                    f"{self.base_url}/api/public/events/1/products/{product_id}",
                    timeout=5
                )
                product_tests.append({
                    'product_id': product_id,
                    'status': resp.status_code,
                    'accessible': resp.status_code == 200
                })
                if resp.status_code == 200:
                    print(f"{Fore.GREEN}[+] Product {product_id}: ACCESSIBLE")
                else:
                    print(f"{Fore.RED}[-] Product {product_id}: {resp.status_code}")
            except:
                pass
        
        self.save_finding('idor', 'product_id_enumeration', product_tests)
    
    def test_parameter_tampering(self):
        """Test for parameter tampering vulnerabilities"""
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}DEEP ANALYSIS: Parameter Tampering")
        print(f"{Fore.MAGENTA}{'='*70}\n")
        
        tests = [
            # Try to manipulate event data
            ('/api/public/events/1?id=2', 'ID parameter override'),
            ('/api/public/events/1?event_id=99', 'Event ID parameter'),
            ('/api/public/events/1?admin=true', 'Admin flag'),
            ('/api/public/events/1?debug=true', 'Debug flag'),
            ('/api/public/events/1?internal=true', 'Internal flag'),
            ('/api/public/events/1?preview=true', 'Preview mode'),
            ('/api/public/events/1?draft=true', 'Draft mode'),
            ('/api/public/events/1?bypass=true', 'Bypass flag'),
        ]
        
        results = []
        for endpoint, description in tests:
            try:
                resp = self.session.get(f"{self.base_url}{endpoint}", timeout=5)
                results.append({
                    'endpoint': endpoint,
                    'description': description,
                    'status': resp.status_code,
                    'different': False  # Would compare to baseline
                })
                print(f"{Fore.CYAN}[TEST] {description}: {resp.status_code}")
            except Exception as e:
                print(f"{Fore.RED}[!] {description}: Error - {e}")
        
        self.save_finding('parameter_tampering', 'parameter_manipulation_tests', results)
    
    def analyze_payment_security(self):
        """Analyze payment flow security"""
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}DEEP ANALYSIS: Payment Flow Security")
        print(f"{Fore.MAGENTA}{'='*70}\n")
        
        findings = []
        
        # Check for exposed payment config
        if self.event_data:
            settings = self.event_data.get('data', {}).get('settings', {})
            
            # PAYMOB integration check
            payment_providers = settings.get('payment_providers', [])
            if 'PAYMOB' in payment_providers:
                print(f"{Fore.YELLOW}[!] PAYMOB payment provider detected")
                findings.append({
                    'provider': 'PAYMOB',
                    'exposed_data': 'Payment provider name visible',
                    'risk': 'Attackers can research PAYMOB vulnerabilities'
                })
            
            # Check for API keys in frontend
            if 'VITE_STRIPE_PUBLISHABLE_KEY' in str(self.event_data):
                print(f"{Fore.RED}[CRITICAL] Stripe key in frontend config!")
                findings.append({
                    'type': 'api_key_exposure',
                    'location': 'frontend_config',
                    'severity': 'CRITICAL'
                })
        
        # Test order creation endpoint
        print(f"\n{Fore.YELLOW}[TEST] Testing order endpoints...")
        order_tests = []
        for method in ['GET', 'POST', 'PUT', 'DELETE']:
            try:
                resp = self.session.request(
                    method,
                    f"{self.base_url}/api/public/events/1/orders",
                    timeout=5
                )
                order_tests.append({
                    'method': method,
                    'status': resp.status_code,
                    'endpoint': '/api/public/events/1/orders'
                })
                if resp.status_code != 404:
                    print(f"{Fore.RED}[!] Order endpoint {method}: {resp.status_code}")
                else:
                    print(f"{Fore.GREEN}[OK] Order endpoint {method}: 404")
            except:
                pass
        
        self.save_finding('payment_security', 'order_endpoint_analysis', {
            'tests': order_tests,
            'payment_findings': findings
        })
    
    def test_http_methods(self):
        """Test HTTP method handling"""
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}DEEP ANALYSIS: HTTP Method Testing")
        print(f"{Fore.MAGENTA}{'='*70}\n")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD']
        results = []
        
        for method in methods:
            try:
                resp = self.session.request(
                    method,
                    f"{self.base_url}/api/public/events/1",
                    timeout=5
                )
                results.append({
                    'method': method,
                    'status': resp.status_code,
                    'allowed': resp.status_code != 405
                })
                status_color = Fore.RED if resp.status_code != 405 and method != 'GET' else Fore.GREEN
                print(f"{status_color}[{method}] Status: {resp.status_code}")
            except Exception as e:
                print(f"{Fore.RED}[{method}] Error: {e}")
        
        # Check for dangerous methods
        dangerous = [r for r in results if r['method'] in ['PUT', 'DELETE', 'TRACE'] and r['allowed']]
        if dangerous:
            print(f"\n{Fore.RED}[CRITICAL] Dangerous HTTP methods allowed:")
            for d in dangerous:
                print(f"  - {d['method']}: {d['status']}")
        
        self.save_finding('http_methods', 'method_analysis', results)
    
    def analyze_response_headers_deep(self):
        """Deep analysis of response headers"""
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}DEEP ANALYSIS: Response Headers")
        print(f"{Fore.MAGENTA}{'='*70}\n")
        
        try:
            resp = self.session.get(f"{self.base_url}/api/public/events/1", timeout=10)
            headers = dict(resp.headers)
            
            security_analysis = {
                'headers_present': {},
                'headers_missing': [],
                'information_disclosure': []
            }
            
            # Check security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'Content-Security-Policy': None,
                'Strict-Transport-Security': None,
                'X-XSS-Protection': '1; mode=block',
                'Referrer-Policy': None,
                'Permissions-Policy': None
            }
            
            for header, expected in security_headers.items():
                value = headers.get(header)
                if value:
                    security_analysis['headers_present'][header] = value
                    if expected and value not in (expected if isinstance(expected, list) else [expected]):
                        print(f"{Fore.YELLOW}[!] {header} has weak value: {value}")
                else:
                    security_analysis['headers_missing'].append(header)
                    print(f"{Fore.RED}[-] {header}: MISSING")
            
            # Check for information disclosure
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
            for header in disclosure_headers:
                if header in headers:
                    security_analysis['information_disclosure'].append({
                        'header': header,
                        'value': headers[header]
                    })
                    print(f"{Fore.RED}[!] Information disclosure: {header}: {headers[header]}")
            
            self.save_finding('response_headers', 'security_header_analysis', security_analysis)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")
    
    def generate_deep_report(self):
        """Generate comprehensive deep analysis report"""
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}GENERATING DEEP ANALYSIS REPORT")
        print(f"{Fore.GREEN}{'='*70}\n")
        
        # Summary statistics
        categories = {}
        for finding in self.findings:
            cat = finding['category']
            categories[cat] = categories.get(cat, 0) + 1
        
        print(f"{Fore.CYAN}Findings by Category:")
        for cat, count in categories.items():
            print(f"  - {cat}: {count}")
        
        # Critical findings
        critical = [f for f in self.findings if 'CRITICAL' in str(f.get('data', {}))]
        if critical:
            print(f"\n{Fore.RED}[CRITICAL] {len(critical)} critical issues found")
        
        # Save master report
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'total_findings': len(self.findings),
            'categories': categories,
            'findings': self.findings,
            'risk_score': self.calculate_risk_score()
        }
        
        report_path = os.path.join(self.output_dir, 'DEEP_ANALYSIS_REPORT.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved: {report_path}")
        print(f"{Fore.GREEN}[+] All findings in: {self.output_dir}")
        
        return report
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        score = 0
        for finding in self.findings:
            data = str(finding.get('data', {}))
            if 'CRITICAL' in data:
                score += 10
            elif 'HIGH' in data:
                score += 7
            elif 'MEDIUM' in data:
                score += 4
            elif 'LOW' in data:
                score += 1
        return min(score, 100)
    
    def run_full_deep_analysis(self):
        """Run all deep analysis tests"""
        print(f"""
{Fore.CYAN}
  _____  _____  ______  _______     ______ _____  _____ ______ _   _
 |  __ \|  __ \|  ____|/ ____\ \   / /  _ \_   _|/ ____|  ____| \ | |
 | |  | | |  | | |__  | (___  \ \_/ /| |_) || | | (___ | |__  |  \| |
 | |  | | |  | |  __|  \___ \  \   / |  _ < | |  \___ \|  __| | . ` |
 | |__| | |__| | |____ ____) |  | |  | |_) || |_ ____) | |____| |\  |
 |_____/|_____/|______|_____/   |_|  |____/_____|_____/|______|_| \_|

        DEEP SECURITY ANALYSIS - COMPREHENSIVE AUDIT
        """)
        
        print(f"{Fore.YELLOW}[!] This will perform deep analysis on {self.base_url}")
        # Auto-start without waiting for input
        time.sleep(1)
        
        # Run all tests
        self.analyze_event_data_deep()
        self.test_idor_deep()
        self.test_parameter_tampering()
        self.analyze_payment_security()
        self.test_http_methods()
        self.analyze_response_headers_deep()
        
        # Generate report
        report = self.generate_deep_report()
        
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}DEEP ANALYSIS COMPLETE")
        print(f"{Fore.GREEN}{'='*70}")
        print(f"\n{Fore.CYAN}Risk Score: {report['risk_score']}/100")
        print(f"{Fore.CYAN}Total Findings: {report['total_findings']}")
        print(f"\n{Fore.YELLOW}Review all findings in: {self.output_dir}")

def main():
    analyzer = DeepSecurityAnalyzer()
    analyzer.run_full_deep_analysis()

if __name__ == "__main__":
    main()
