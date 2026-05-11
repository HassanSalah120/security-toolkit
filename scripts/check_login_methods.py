#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
Login Detection Tool for IP 196.218.83.9
Checks for authentication methods and potential access
"""

import requests
import json

ip = '196.218.83.9'
port = 8080
base = f'http://{ip}:{port}'

print(f"Checking login methods for {ip}:{port}\n")
print("="*60)

# 1. Check session status
print("\n[1] Current Session Status:")
try:
    resp = requests.get(f"{base}/api/auth/session", timeout=5)
    print(f"    Status: {resp.status_code}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"    Authenticated: {data.get('authenticated', False)}")
        if data.get('user'):
            print(f"    User: {data['user']}")
        print(f"    Full session: {json.dumps(data, indent=2)}")
except Exception as e:
    print(f"    Error: {e}")

# 2. Check auth configuration
print("\n[2] Authentication Configuration:")
try:
    resp = requests.get(f"{base}/api/config", timeout=5)
    if resp.status_code == 200:
        config = resp.json()
        features = config.get('features', {})
        print(f"    Auth enabled: {features.get('auth', False)}")
        print(f"    Trusted header auth: {features.get('auth_trusted_header', False)}")
        print(f"    Name: {config.get('name', 'Unknown')}")
        print(f"    Version: {config.get('version', 'Unknown')}")
except Exception as e:
    print(f"    Error: {e}")

# 3. Check for user list access
print("\n[3] User List Access:")
try:
    resp = requests.get(f"{base}/api/users", timeout=5)
    print(f"    Status: {resp.status_code}")
    if resp.status_code == 200:
        print(f"    Users accessible - Data exposed!")
        try:
            users = resp.json()
            print(f"    Users: {json.dumps(users, indent=2)[:500]}")
        except:
            print(f"    Response: {resp.text[:300]}")
    elif resp.status_code == 401:
        print(f"    Requires authentication (401)")
    elif resp.status_code == 403:
        print(f"    Access forbidden (403)")
except Exception as e:
    print(f"    Error: {e}")

# 4. Check login page content
print("\n[4] Login Page Analysis:")
try:
    resp = requests.get(f"{base}/login", timeout=5)
    print(f"    Status: {resp.status_code}")
    if resp.status_code == 200:
        content = resp.text.lower()
        if 'password' in content:
            print(f"    Password field found")
        if 'username' in content or 'email' in content:
            print(f"    Username/Email field found")
        if 'oauth' in content or 'google' in content or 'github' in content:
            print(f"    OAuth login option detected")
        if 'register' in content or 'signup' in content:
            print(f"    Registration option available")
except Exception as e:
    print(f"    Error: {e}")

# 5. Check for API keys or tokens
print("\n[5] API/Token Access:")
endpoints = ['/api/keys', '/api/token', '/api/settings']
for endpoint in endpoints:
    try:
        resp = requests.get(f"{base}{endpoint}", timeout=3)
        if resp.status_code == 200:
            print(f"    {endpoint} -> 200 (Data accessible)")
        elif resp.status_code != 404:
            print(f"    {endpoint} -> {resp.status_code}")
    except:
        pass

print("\n" + "="*60)
print("Summary:")
print("- Check /api/auth/session for current auth status")
print("- Login page at /login")
print("- Auth required based on config.features.auth setting")
print("="*60)
