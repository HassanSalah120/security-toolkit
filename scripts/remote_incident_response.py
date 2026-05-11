#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
REMOTE INCIDENT RESPONSE - Executes via SSH on target server
This script connects to the server and runs all compromise checks remotely
"""

import paramiko
import sys
import json
from datetime import datetime
from getpass import getpass

TARGET_IP = "196.218.83.9"
USERNAME = "ubuntu"  # Change if needed

# All commands to run on remote server
REMOTE_COMMANDS = """
echo "=== INCIDENT RESPONSE ANALYSIS ==="
echo "Target: 196.218.83.9"
echo "Date: $(date)"
echo ""

echo "[1] SSH VERSION CHECK"
echo "------------------------"
ssh -V 2>&1
echo ""

echo "[2] AUTH LOG ANALYSIS"
echo "------------------------"
if [ -f /var/log/auth.log ]; then
    echo "=== Recent SSH connections ==="
    grep "Accepted" /var/log/auth.log 2>/dev/null | tail -20
    echo ""
    echo "=== Failed attempts ==="
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10
    echo ""
    echo "=== Invalid users ==="
    grep "Invalid user" /var/log/auth.log 2>/dev/null | tail -10
fi
echo ""

echo "[3] USER ACCOUNTS"
echo "------------------------"
echo "=== Users with shell access ==="
cat /etc/passwd | grep -E "/bin/bash|/bin/sh" | cut -d: -f1,3
echo ""
echo "=== Root accounts (UID 0) ==="
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo ""
echo "=== Recently modified home dirs ==="
find /home -maxdepth 1 -type d -mtime -7 -ls 2>/dev/null
echo ""

echo "[4] SSH KEYS"
echo "------------------------"
echo "=== Root SSH keys ==="
if [ -f /root/.ssh/authorized_keys ]; then
    echo "[!] ROOT HAS SSH KEYS:"
    cat /root/.ssh/authorized_keys
else
    echo "[OK] No root SSH keys"
fi
echo ""
echo "=== Common user SSH keys ==="
for user in ubuntu admin deploy docker; do
    if [ -f /home/$user/.ssh/authorized_keys ]; then
        echo "[!] $user has SSH keys:"
        cat /home/$user/.ssh/authorized_keys
        echo ""
    fi
done
echo ""

echo "[5] PERSISTENCE - CRON JOBS"
echo "------------------------"
echo "=== System crontab ==="
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$"
echo ""
echo "=== Cron.d directory ==="
ls -la /etc/cron.d/ 2>/dev/null
echo ""
echo "=== User crontabs ==="
for user in root ubuntu; do
    crontab -u $user -l 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "[$user has active crontab]"
done
echo ""

echo "[6] SUSPICIOUS PROCESSES"
echo "------------------------"
echo "=== Looking for reverse shells ==="
ps aux | grep -E "nc |ncat|netcat|/dev/tcp|python -c|bash -i|perl -e" | grep -v grep
echo ""
echo "=== All processes ==="
ps aux | head -30
echo ""

echo "[7] NETWORK CONNECTIONS"
echo "------------------------"
echo "=== Listening ports ==="
netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null | head -20
echo ""
echo "=== Established connections ==="
netstat -tupn 2>/dev/null | grep ESTABLISHED | head -20 || ss -tupn 2>/dev/null | grep ESTAB | head -20
echo ""

echo "[8] SUSPICIOUS FILES"
echo "------------------------"
echo "=== Recent files in /tmp ==="
find /tmp -type f -mtime -1 -ls 2>/dev/null | head -10
echo ""
echo "=== Modified system binaries ==="
find /usr/bin /bin -type f -mtime -1 2>/dev/null | head -5
echo ""

echo "[9] SYSTEMD SERVICES"
echo "------------------------"
systemctl list-units --type=service --state=running 2>/dev/null | grep -v "^●" | head -20
echo ""

echo "[10] LOGIN HISTORY"
echo "------------------------"
last -20 2>/dev/null
echo ""
echo "=== Failed logins ==="
lastb -10 2>/dev/null
echo ""

echo "=== ANALYSIS COMPLETE ==="
"""

def main():
    print("="*70)
    print("REMOTE INCIDENT RESPONSE TOOL")
    print("Target: 196.218.83.9")
    print("="*70)
    
    # Get credentials
    password = getpass(f"Enter password for {USERNAME}@{TARGET_IP}: ")
    
    try:
        # Connect via SSH
        print(f"\n[*] Connecting to {TARGET_IP}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(TARGET_IP, username=USERNAME, password=password, timeout=30)
        
        print("[+] Connected! Running compromise analysis...")
        print("[+] This will take 1-2 minutes...")
        print()
        
        # Execute commands
        stdin, stdout, stderr = client.exec_command(REMOTE_COMMANDS, get_pty=True, timeout=120)
        
        # Get output
        output = stdout.read().decode('utf-8', errors='ignore')
        errors = stderr.read().decode('utf-8', errors='ignore')
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"REMOTE_ANALYSIS_{TARGET_IP}_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("="*70 + "\n")
            f.write("REMOTE INCIDENT RESPONSE ANALYSIS\n")
            f.write(f"Target: {TARGET_IP}\n")
            f.write(f"Date: {datetime.now().isoformat()}\n")
            f.write("="*70 + "\n\n")
            f.write("OUTPUT:\n")
            f.write("-"*70 + "\n")
            f.write(output)
            if errors:
                f.write("\n\nERRORS:\n")
                f.write("-"*70 + "\n")
                f.write(errors)
        
        # Display critical findings
        print("\n" + "="*70)
        print("CRITICAL FINDINGS SUMMARY")
        print("="*70)
        
        critical_found = False
        
        if "ROOT HAS SSH KEYS" in output:
            print("\n[!] CRITICAL: Root account has SSH authorized_keys!")
            critical_found = True
            
        if "Invalid user" in output and "Failed password" in output:
            print("\n[!] HIGH: Brute force attempts detected in auth logs")
            critical_found = True
            
        if any(shell in output for shell in ["nc", "ncat", "/dev/tcp", "python -c", "bash -i"]):
            print("\n[!] CRITICAL: Suspicious processes detected!")
            critical_found = True
            
        if "ESTABLISHED" in output and output.count("ESTABLISHED") > 10:
            print(f"\n[!] MEDIUM: Many active connections ({output.count('ESTABLISHED')})")
            
        if "ubuntu" in output and "Accepted" in output:
            print("\n[!] INFO: Successful logins detected")
            
        if not critical_found:
            print("\n[?] No obvious critical indicators found (but server still compromised)")
        
        print(f"\n[+] Full analysis saved to: {filename}")
        print("[+] Review the file for complete results")
        
        client.close()
        
    except paramiko.AuthenticationException:
        print("[-] Authentication failed - wrong password")
        print("[-] The attacker has likely changed the password")
        sys.exit(1)
    except paramiko.SSHException as e:
        print(f"[-] SSH error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
