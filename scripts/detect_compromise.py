#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
CVE-2024-6387 Compromise Detection Tool
Checks for signs of regreSSHion exploitation
"""

import subprocess
import sys
from datetime import datetime

def check_ssh_version():
    """Check if SSH version is vulnerable"""
    print("="*70)
    print("CHECKING SSH VERSION FOR CVE-2024-6387 VULNERABILITY")
    print("="*70)
    
    try:
        result = subprocess.run(['ssh', '-V'], capture_output=True, text=True)
        version = result.stderr.strip()  # ssh -V outputs to stderr
        print(f"Current version: {version}")
        
        # Parse version
        if 'OpenSSH_8.9' in version or 'OpenSSH_8.5' in version or 'OpenSSH_8.8' in version or 'OpenSSH_9.' in version:
            print("\n[ALERT] Version is in VULNERABLE range (8.5p1 - 9.7p1)")
            print("        CVE-2024-6387 (regreSSHion) applies!")
            return True
        elif 'OpenSSH_9.8' in version:
            print("\n[OK] Version 9.8+ - Patched against CVE-2024-6387")
            return False
        else:
            print("\n[INFO] Check version manually against CVE-2024-6387")
            return None
    except:
        print("[ERROR] Could not check SSH version")
        return None

def check_recent_logins():
    """Check for suspicious login activity"""
    print("\n" + "="*70)
    print("CHECKING RECENT LOGIN ACTIVITY")
    print("="*70)
    
    try:
        # Check last logins
        result = subprocess.run(['last', '-20'], capture_output=True, text=True)
        print("\nRecent logins:")
        print(result.stdout)
        
        # Check auth log for accepted connections
        try:
            with open('/var/log/auth.log', 'r') as f:
                lines = f.readlines()
                accepted = [l for l in lines if 'Accepted' in l]
                if accepted:
                    print(f"\n[WARNING] Found {len(accepted)} accepted connections:")
                    for line in accepted[-10:]:  # Last 10
                        print(f"  {line.strip()}")
        except:
            print("[INFO] Could not read auth.log (may need sudo)")
            
    except:
        print("[ERROR] Could not check login activity")

def check_user_accounts():
    """Check for suspicious user accounts"""
    print("\n" + "="*70)
    print("CHECKING USER ACCOUNTS")
    print("="*70)
    
    try:
        with open('/etc/passwd', 'r') as f:
            users = f.readlines()
        
        # Look for users with shell access
        shell_users = [u for u in users if '/bin/bash' in u or '/bin/sh' in u]
        
        print(f"\nUsers with shell access ({len(shell_users)} total):")
        for user in shell_users:
            parts = user.split(':')
            print(f"  {parts[0]} (UID: {parts[2]})")
        
        # Check for recently modified accounts
        print("\n[!] Check for any unknown accounts above")
        print("[!] UIDs 1000+ are typically regular users")
        
    except:
        print("[ERROR] Could not check user accounts (may need sudo)")

def check_ssh_keys():
    """Check for unauthorized SSH keys"""
    print("\n" + "="*70)
    print("CHECKING SSH AUTHORIZED KEYS")
    print("="*70)
    
    # Check root
    try:
        result = subprocess.run(['cat', '/root/.ssh/authorized_keys'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            keys = result.stdout.strip()
            if keys:
                print("\n[WARNING] Root has SSH keys:")
                print(keys[:500])
            else:
                print("\n[OK] Root has no SSH keys")
    except:
        print("[INFO] Could not check root SSH keys (may need sudo)")
    
    # Check common users
    import os
    for user in ['ubuntu', 'admin', 'user', 'test']:
        key_path = f'/home/{user}/.ssh/authorized_keys'
        if os.path.exists(key_path):
            print(f"\n[WARNING] Found SSH keys for user: {user}")

def check_cron_jobs():
    """Check for suspicious cron jobs"""
    print("\n" + "="*70)
    print("CHECKING CRON JOBS (Persistence Mechanisms)")
    print("="*70)
    
    try:
        # User crontab
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            print("\n[WARNING] User cron jobs found:")
            print(result.stdout)
        else:
            print("\n[OK] No user cron jobs")
    except:
        pass
    
    # System crontab
    try:
        with open('/etc/crontab', 'r') as f:
            content = f.read()
            if content.strip():
                print("\n[WARNING] System crontab found - review manually:")
                print("  Run: cat /etc/crontab")
    except:
        print("[INFO] Could not check system crontab (may need sudo)")

def check_suspicious_processes():
    """Check for suspicious processes"""
    print("\n" + "="*70)
    print("CHECKING RUNNING PROCESSES")
    print("="*70)
    
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        processes = result.stdout
        
        suspicious = ['nc', 'netcat', 'ncat', 'reverse', 'backdoor', 
                     'python -c', 'bash -i', '/dev/tcp', 'socket']
        
        print("\nLooking for suspicious process names...")
        found = False
        for proc in suspicious:
            if proc in processes.lower():
                print(f"  [WARNING] Found: {proc}")
                found = True
        
        if not found:
            print("  [OK] No obvious suspicious processes found")
        
        print("\n[!] Review full process list: ps aux")
        
    except:
        print("[ERROR] Could not check processes")

def check_network_connections():
    """Check for suspicious network connections"""
    print("\n" + "="*70)
    print("CHECKING NETWORK CONNECTIONS")
    print("="*70)
    
    try:
        result = subprocess.run(['netstat', '-tulpn'], 
                              capture_output=True, text=True)
        print("\nListening network services:")
        print(result.stdout[:1000])
        
        print("\n[!] Look for unknown listening ports or external connections")
        
    except:
        print("[INFO] Could not check network (netstat may not be available)")

def generate_report():
    """Generate compromise detection report"""
    print("\n" + "="*70)
    print("COMPROMISE DETECTION REPORT")
    print("="*70)
    print(f"\nTimestamp: {datetime.now().isoformat()}")
    print("\nCVE-2024-6387 (regreSSHion) Detection Summary:")
    print("-" * 70)
    print("\nThis tool checked for:")
    print("  1. SSH version vulnerability")
    print("  2. Recent login activity")
    print("  3. Suspicious user accounts")
    print("  4. Unauthorized SSH keys")
    print("  5. Persistence mechanisms (cron)")
    print("  6. Suspicious processes")
    print("  7. Network connections")
    
    print("\n[!] IMPORTANT: This is a basic check. Professional forensic")
    print("    analysis may be required if compromise is suspected.")
    
    print("\n[!] If you found ANY suspicious indicators:")
    print("    1. Disconnect server from internet immediately")
    print("    2. Do not log in via SSH (use console/VNC)")
    print("    3. Create forensic backup")
    print("    4. Rebuild server from clean image")
    
    print("\n[!] References:")
    print("    - CVE-2024-6387: https://nvd.nist.gov/vuln/detail/CVE-2024-6387")
    print("    - Qualys Report: https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion")

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║           CVE-2024-6387 (regreSSHion) COMPROMISE CHECK              ║
    ║                   Unauthorized Access Detection                      ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    is_vulnerable = check_ssh_version()
    check_recent_logins()
    check_user_accounts()
    check_ssh_keys()
    check_cron_jobs()
    check_suspicious_processes()
    check_network_connections()
    generate_report()

if __name__ == "__main__":
    main()
