#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
API Reconnaissance & Analysis Tool
Safely maps and documents the Insomnia Gaming Egypt API structure
For security research and vulnerability analysis purposes
"""

import requests
import json
import time
import datetime
import os
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

init(autoreset=True)

class APIReconnaissanceLogger:
    """
    Safe API reconnaissance tool that logs all interactions
    for vulnerability analysis without aggressive testing
    """
    
    def __init__(self, base_url="https://insomniagamingegypt.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.log_dir = f"api_analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Default headers matching the provided request
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Referer': 'https://insomniagamingegypt.com/event/1/insomnia-egypt-gaming-festival-2026',
            'Sec-Ch-Ua': '"Not:A-Brand";v="99", "Opera GX";v="129", "Chromium";v="145"',
            'Sec-Ch-Ua-Mobile': '?1',
            'Sec-Ch-Ua-Platform': '"Android"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Cache-Control': 'no-cache'
        })
        
        self.findings = {
            "endpoints": {},
            "rate_limits": {},
            "response_patterns": {},
            "security_headers": {},
            "discovered_data": {}
        }
        
        self.master_log = []
        
    def log_interaction(self, method, endpoint, request_headers, response, duration, notes=""):
        """Log a complete API interaction"""
        timestamp = datetime.datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "method": method,
            "endpoint": endpoint,
            "url": response.url if response else "N/A",
            "request_headers": dict(request_headers),
            "status_code": response.status_code if response else None,
            "response_headers": dict(response.headers) if response else {},
            "response_body": None,
            "duration_ms": round(duration * 1000, 2),
            "notes": notes
        }
        
        # Try to parse JSON response
        if response:
            try:
                log_entry["response_body"] = response.json()
            except:
                log_entry["response_body"] = response.text[:1000]  # Limit text size
        
        self.master_log.append(log_entry)
        
        # Save individual log
        safe_endpoint = endpoint.replace('/', '_').replace(':', '_')
        log_file = os.path.join(self.log_dir, f"{timestamp.replace(':', '-')}_{method}_{safe_endpoint}.json")
        with open(log_file, 'w') as f:
            json.dump(log_entry, f, indent=2)
        
        return log_entry
    
    def safe_request(self, method, endpoint, delay=1.0):
        """
        Make a safe request with proper delays to avoid overwhelming the server
        """
        url = urljoin(self.base_url, endpoint)
        
        print(f"{Fore.CYAN}[REQUEST] {method} {endpoint}")
        
        start_time = time.time()
        try:
            response = self.session.request(method, url, timeout=10)
            duration = time.time() - start_time
            
            # Log the interaction
            log = self.log_interaction(method, endpoint, self.session.headers, response, duration)
            
            # Print summary
            status_color = Fore.GREEN if response.status_code == 200 else Fore.YELLOW if response.status_code < 500 else Fore.RED
            print(f"{status_color}  Status: {response.status_code}")
            print(f"{Fore.CYAN}  Duration: {duration*1000:.2f}ms")
            
            # Extract rate limit info
            rate_limit = response.headers.get('X-RateLimit-Limit')
            rate_remaining = response.headers.get('X-RateLimit-Remaining')
            if rate_limit:
                print(f"{Fore.YELLOW}  Rate Limit: {rate_remaining}/{rate_limit}")
            
            # Server info
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            print(f"{Fore.CYAN}  Server: {server} | X-Powered-By: {powered_by}")
            
            print()
            
            # Respectful delay between requests
            time.sleep(delay)
            
            return response
            
        except requests.exceptions.RequestException as e:
            duration = time.time() - start_time
            print(f"{Fore.RED}  ERROR: {str(e)}")
            self.log_interaction(method, endpoint, self.session.headers, None, duration, f"Error: {str(e)}")
            time.sleep(delay)
            return None
    
    def analyze_event_endpoint(self, event_id=1):
        """Analyze the main event endpoint"""
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}ANALYZING EVENT ENDPOINT (ID: {event_id})")
        print(f"{Fore.MAGENTA}{'='*60}\n")
        
        # Get event details
        response = self.safe_request('GET', f'/api/public/events/{event_id}')
        if response and response.status_code == 200:
            try:
                data = response.json()
                self.findings["discovered_data"][f"event_{event_id}"] = data
                print(f"{Fore.GREEN}[+] Event data collected")
                
                # Look for interesting fields
                if isinstance(data, dict):
                    for key in data.keys():
                        print(f"{Fore.CYAN}  Field: {key}")
            except:
                pass
    
    def analyze_questions_endpoint(self, event_id=1):
        """Analyze the questions endpoint"""
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}ANALYZING QUESTIONS ENDPOINT (ID: {event_id})")
        print(f"{Fore.MAGENTA}{'='*60}\n")
        
        response = self.safe_request('GET', f'/api/public/events/{event_id}/questions')
        if response and response.status_code == 200:
            try:
                data = response.json()
                self.findings["discovered_data"][f"questions_{event_id}"] = data
                print(f"{Fore.GREEN}[+] Questions data collected")
            except:
                pass
    
    def analyze_promo_code_endpoint(self, event_id=1, test_codes=None):
        """
        Analyze the promo code endpoint
        Tests a few sample codes to understand response patterns
        """
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}ANALYZING PROMO CODE ENDPOINT (ID: {event_id})")
        print(f"{Fore.MAGENTA}{'='*60}\n")
        
        if test_codes is None:
            # Safe test codes - random strings unlikely to exist
            test_codes = ["TEST99999", "INVALIDCODE123", "RANDOMSTRING"]
        
        responses = {}
        
        for code in test_codes:
            print(f"{Fore.YELLOW}[TEST] Testing code: {code}")
            response = self.safe_request('GET', f'/api/public/events/{event_id}/promo-codes/{code}', delay=2.0)
            
            if response:
                key = f"status_{response.status_code}"
                if key not in responses:
                    responses[key] = []
                responses[key].append({
                    "code": code,
                    "status": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:500] if response.text else None
                })
        
        self.findings["response_patterns"]["promo_code_endpoint"] = responses
        
        # Analyze patterns
        print(f"\n{Fore.CYAN}[ANALYSIS] Response Patterns Detected:")
        for pattern, data in responses.items():
            print(f"{Fore.CYAN}  {pattern}: {len(data)} occurrences")
    
    def discover_event_ids(self, max_id=10):
        """
        Discover valid event IDs
        Tests IDs sequentially to find active events
        """
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}DISCOVERING EVENT IDs")
        print(f"{Fore.MAGENTA}{'='*60}\n")
        
        valid_events = []
        
        for event_id in range(1, max_id + 1):
            print(f"{Fore.CYAN}[DISCOVER] Testing event ID: {event_id}")
            response = self.safe_request('GET', f'/api/public/events/{event_id}', delay=1.5)
            
            if response:
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] VALID EVENT ID: {event_id}")
                    valid_events.append(event_id)
                    
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            event_name = data.get('name') or data.get('title') or 'Unknown'
                            print(f"{Fore.GREEN}    Name: {event_name}")
                    except:
                        pass
                elif response.status_code == 404:
                    print(f"{Fore.RED}[-] Event ID {event_id} not found")
                else:
                    print(f"{Fore.YELLOW}[?] Event ID {event_id} returned: {response.status_code}")
        
        self.findings["discovered_data"]["valid_event_ids"] = valid_events
        print(f"\n{Fore.GREEN}[+] Found {len(valid_events)} valid event IDs: {valid_events}")
        
        return valid_events
    
    def test_common_endpoints(self):
        """Test common API endpoint patterns"""
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}TESTING COMMON API PATTERNS")
        print(f"{Fore.MAGENTA}{'='*60}\n")
        
        common_patterns = [
            '/api/public/events',
            '/api/public/events/1/tickets',
            '/api/public/events/1/schedule',
            '/api/public/events/1/speakers',
            '/api/public/events/1/sponsors',
            '/api/public/events/1/venues',
            '/api/public/events/1/faq',
            '/api/public/config',
            '/api/public/status',
            '/api/public/health',
        ]
        
        for endpoint in common_patterns:
            response = self.safe_request('GET', endpoint, delay=1.5)
            if response:
                self.findings["endpoints"][endpoint] = {
                    "exists": response.status_code != 404,
                    "status": response.status_code,
                    "requires_auth": response.status_code in [401, 403]
                }
    
    def analyze_security_headers(self):
        """Analyze security headers across responses"""
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}SECURITY HEADER ANALYSIS")
        print(f"{Fore.MAGENTA}{'='*60}\n")
        
        response = self.safe_request('GET', '/api/public/events/1')
        if response:
            security_headers = [
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            print(f"{Fore.CYAN}[Security Headers Present:]")
            for header in security_headers:
                value = response.headers.get(header)
                if value:
                    print(f"{Fore.GREEN}  ✓ {header}: {value}")
                else:
                    print(f"{Fore.RED}  ✗ {header}: Missing")
            
            self.findings["security_headers"]["event_endpoint"] = dict(response.headers)
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}GENERATING COMPREHENSIVE REPORT")
        print(f"{Fore.GREEN}{'='*60}\n")
        
        report = {
            "analysis_timestamp": datetime.datetime.now().isoformat(),
            "target": self.base_url,
            "findings": self.findings,
            "total_interactions": len(self.master_log),
            "summary": {
                "endpoints_tested": len(self.findings["endpoints"]),
                "events_discovered": len(self.findings["discovered_data"].get("valid_event_ids", [])),
                "response_patterns": list(self.findings["response_patterns"].keys())
            }
        }
        
        # Save comprehensive report
        report_file = os.path.join(self.log_dir, "COMPREHENSIVE_REPORT.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save master log
        log_file = os.path.join(self.log_dir, "MASTER_LOG.json")
        with open(log_file, 'w') as f:
            json.dump(self.master_log, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Report saved to: {report_file}")
        print(f"{Fore.GREEN}[+] Master log saved to: {log_file}")
        print(f"{Fore.GREEN}[+] All interaction logs in: {self.log_dir}/")
        
        # Print summary
        print(f"\n{Fore.CYAN}[SUMMARY]")
        print(f"  Total API interactions: {len(self.master_log)}")
        print(f"  Endpoints analyzed: {report['summary']['endpoints_tested']}")
        print(f"  Events discovered: {report['summary']['events_discovered']}")
        
        return report
    
    def run_full_analysis(self, event_id=1):
        """Run complete API analysis"""
        print(f"""
{Fore.CYAN}
  ____ ____  ___   ___    ____  _____ __  __ _____ _____ 
 / ___|  _ \|_ _| / _ \  |  _ \| ____|  \/  | ____|_   _|
| |   | |_) || | | | | | | |_) |  _| | |\/| |  _|   | |  
| |___|  _ < | | | |_| | |  _ <| |___| |  | | |___  | |  
 \____|_| \_\___| \___/  |_| \_\_____|_|  |_|_____| |_|  
                                                          
  API RECONNAISSANCE & VULNERABILITY ANALYSIS TOOL
  Target: {self.base_url}
        """)
        
        print(f"{Fore.YELLOW}[!] IMPORTANT: This tool performs safe reconnaissance only.")
        print(f"{Fore.YELLOW}    Respects rate limits and avoids aggressive testing.\n")
        
        input(f"{Fore.CYAN}Press Enter to begin analysis...")
        
        # Run all analysis modules
        self.analyze_event_endpoint(event_id)
        self.analyze_questions_endpoint(event_id)
        self.analyze_promo_code_endpoint(event_id)
        self.discover_event_ids(max_id=5)
        self.test_common_endpoints()
        self.analyze_security_headers()
        
        # Generate final report
        report = self.generate_report()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}ANALYSIS COMPLETE")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"\n{Fore.YELLOW}Next steps:")
        print(f"  1. Review logs in: {self.log_dir}/")
        print(f"  2. Analyze response patterns for vulnerabilities")
        print(f"  3. Check COMPREHENSIVE_REPORT.json for findings")
        
        return report

def main():
    logger = APIReconnaissanceLogger()
    logger.run_full_analysis(event_id=1)

if __name__ == "__main__":
    main()
