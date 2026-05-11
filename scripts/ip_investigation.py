#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
IP Investigation Tool - Testing http://196.218.83.9/
"""

import requests
import socket
import json
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def test_ip_ports(ip):
    """Test all open ports on the IP"""
    print(f"\n{'='*60}")
    print(f"INVESTIGATING IP: {ip}")
    print(f"{'='*60}\n")
    
    ports = [80, 443, 8080, 9000]
    
    for port in ports:
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{ip}:{port}/" if port != 80 else f"{protocol}://{ip}/"
        
        print(f"\n[TESTING] Port {port}: {url}")
        
        try:
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            
            print(f"  Status: {resp.status_code}")
            print(f"  Size: {len(resp.text)} bytes")
            print(f"  Server: {resp.headers.get('Server', 'unknown')}")
            print(f"  Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
            
            # Get title
            if '<title>' in resp.text:
                title = resp.text.split('<title>')[1].split('</title>')[0][:60]
                print(f"  Title: {title}")
            
            # Preview
            preview = resp.text[:200].replace('\n', ' ')
            print(f"  Preview: {preview}...")
            
            # Save full response
            with open(f'evidence\ip_{ip}_port_{port}_response.html', 'w', encoding='utf-8') as f:
                f.write(resp.text)
            print(f"  Saved to: evidence\ip_{ip}_port_{port}_response.html")
            
        except Exception as e:
            print(f"  Error: {e}")

def test_api_on_ip(ip, port=8080):
    """Test API endpoints on the IP"""
    print(f"\n{'='*60}")
    print(f"TESTING API ENDPOINTS ON {ip}:{port}")
    print(f"{'='*60}\n")
    
    base = f"http://{ip}:{port}"
    
    endpoints = [
        '/api/public/events/1',
        '/api/public/events/1/questions',
        '/api/public/events/1/promo-codes/TEST',
        '/api/public/events/2',
        '/admin',
        '/login',
        '/api',
    ]
    
    results = {}
    
    for endpoint in endpoints:
        url = f"{base}{endpoint}"
        print(f"[TEST] {endpoint}", end=' ')
        
        try:
            resp = requests.get(url, timeout=5)
            print(f"-> {resp.status_code} ({len(resp.text)}b)")
            
            results[endpoint] = {
                'status': resp.status_code,
                'size': len(resp.text),
                'preview': resp.text[:100]
            }
            
        except Exception as e:
            print(f"-> ERROR: {e}")
            results[endpoint] = {'error': str(e)}
    
    # Save results
    with open(f'evidence\ip_{ip}_api_scan.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n[+] API scan saved to: evidence\ip_{ip}_api_scan.json")

def main():
    ip = "196.218.83.9"
    
    test_ip_ports(ip)
    test_api_on_ip(ip, 8080)
    
    print(f"\n{'='*60}")
    print("INVESTIGATION COMPLETE")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
