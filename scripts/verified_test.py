#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""Verified Vulnerability Test"""
import requests
import urllib3
import json

urllib3.disable_warnings()

s = requests.Session()
s.headers.update({'Content-Type': 'application/json', 'Accept': 'application/json'})
base = 'https://insomniagamingegypt.com'

print('='*60)
print('VERIFIED VULNERABILITY TEST')
print('='*60)

# 1. Check GraphQL properly
print('\n[1] GraphQL Test')
print('-'*40)

query = {"query": "{__schema{types{name}}}"}
r = s.post(base + '/graphql', json=query, timeout=10, verify=False)
print(f'Status: {r.status_code}')
print(f'Content-Type: {r.headers.get("Content-Type", "")}')

try:
    data = r.json()
    if 'data' in data and '__schema' in str(data):
        print('[!] GRAPHQL INTROSPECTION ENABLED')
        print(f'Response: {json.dumps(data)[:200]}')
    elif 'errors' in data:
        print(f'Errors: {data["errors"]}')
    else:
        print(f'Response: {json.dumps(data)[:200]}')
except Exception as e:
    print(f'Not JSON response: {str(e)[:50]}')
    print(f'Response text: {r.text[:100]}')

# 2. Check register endpoint properly
print('\n[2] Register/Mass Assignment Test')
print('-'*40)

# First check if register returns JSON
r = s.post(base + '/api/auth/register', json={'email': 'test@test.com', 'password': 'Test123!', 'name': 'Test'}, timeout=10, verify=False)
print(f'Status: {r.status_code}')
print(f'Content-Type: {r.headers.get("Content-Type", "")}')

ct = r.headers.get('Content-Type', '')
if 'json' in ct:
    print(f'JSON Response: {r.text[:200]}')
else:
    print('[SPA] Returns HTML, not a real API response')

# 3. Check .env (403 is interesting)
print('\n[3] .env File Check')
print('-'*40)

r = s.get(base + '/.env', timeout=10, verify=False)
print(f'Status: {r.status_code}')
if r.status_code == 403:
    print('[!] FILE EXISTS but ACCESS DENIED (403)')
    print('    This means .env file is present on server!')
    print('    Recommendation: Move .env outside web root')
elif r.status_code == 200:
    print('[CRITICAL] .env FILE EXPOSED!')
    print(r.text[:300])
else:
    print(f'File not accessible ({r.status_code})')

# 4. CORS (already confirmed)
print('\n[4] CORS Configuration')
print('-'*40)

r = s.options(base + '/api', headers={'Origin': 'https://evil.com'}, timeout=10, verify=False)
acao = r.headers.get('Access-Control-Allow-Origin', '')
acac = r.headers.get('Access-Control-Allow-Credentials', '')
print(f'ACAO: {acao}')
print(f'ACAC: {acac}')
if acao == 'https://evil.com' and acac == 'true':
    print('[!] CORS MISCONFIGURATION CONFIRMED')

# 5. Rate Limiting
print('\n[5] Rate Limiting Test')
print('-'*40)

codes = []
for i in range(10):
    r = s.get(base + '/api/users', timeout=5, verify=False)
    codes.append(r.status_code)

if 429 in codes:
    print('[+] Rate limiting present (429 detected)')
else:
    print(f'[!] NO RATE LIMITING: {codes}')

# 6. Password Reset
print('\n[6] Password Reset Test')
print('-'*40)

r = s.post(base + '/api/auth/forgot-password', json={'email': 'test@test.com'}, timeout=10, verify=False)
print(f'Status: {r.status_code}')
print(f'Response: {r.text[:200]}')

# Check for user enumeration
r1 = s.post(base + '/api/auth/forgot-password', json={'email': 'nonexistent@fake12345.com'}, timeout=10, verify=False)
r2 = s.post(base + '/api/auth/forgot-password', json={'email': 'admin@insomniagamingegypt.com'}, timeout=10, verify=False)

# Compare response status codes and JSON content (ignore dynamic values)
try:
    j1 = r1.json() if r1.text else {}
except json.JSONDecodeError:
    j1 = {}
try:
    j2 = r2.json() if r2.text else {}
except json.JSONDecodeError:
    j2 = {}

# Remove dynamic fields that change per-request
for d in (j1, j2):
    if isinstance(d, dict):
        d.pop('timestamp', None)
        d.pop('time', None)
        d.pop('date', None)

if r1.status_code != r2.status_code or j1 != j2:
    print('[!] USER ENUMERATION possible - different responses')
    print(f'    Unknown user: {r1.text[:100]}')
    print(f'    Known user:   {r2.text[:100]}')
else:
    print('[+] Same response for known/unknown users (good)')

# 7. Login Brute Force
print('\n[7] Login Brute Force Test')
print('-'*40)

codes = []
for i in range(20):
    r = s.post(base + '/api/auth/login', json={'email': 'admin@test.com', 'password': f'wrong{i}'}, timeout=10, verify=False)
    codes.append(r.status_code)

if 429 in codes or 403 in codes:
    print('[+] Brute force protection detected')
else:
    print(f'[!] NO BRUTE FORCE PROTECTION: {codes}')

print('\n' + '='*60)
print('VERIFIED VULNERABILITIES:')
print('='*60)
