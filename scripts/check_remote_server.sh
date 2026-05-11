#!/bin/bash
# REMOTE COMPROMISE CHECK FOR 196.218.83.9
# Run this via SSH on the target server
# 
# Usage: ssh user@196.218.83.9 'bash -s' < check_remote_server.sh
# OR: Copy to server and run: sudo bash check_remote_server.sh

echo "======================================================================"
echo "CVE-2024-6387 (regreSSHion) COMPROMISE CHECK"
echo "Target: 196.218.83.9"
echo "Date: $(date)"
echo "======================================================================"
echo ""

# 1. CHECK SSH VERSION
echo "[1] CHECKING SSH VERSION"
echo "---------------------------------------------------------------------"
SSH_VERSION=$(ssh -V 2>&1)
echo "Current: $SSH_VERSION"

if echo "$SSH_VERSION" | grep -q "8.9p1\|8.5p1\|8.8p1\|9.0p1\|9.1p1\|9.2p1\|9.3p1\|9.4p1\|9.5p1\|9.6p1\|9.7p1"; then
    echo ""
    echo "[!] ALERT: Version is VULNERABLE to CVE-2024-6387 (regreSSHion)"
    echo "[!] Patch immediately: sudo apt update && sudo apt install openssh-server"
    echo ""
fi

# 2. CHECK RECENT LOGINS
echo "[2] CHECKING RECENT LOGIN ACTIVITY"
echo "---------------------------------------------------------------------"
echo "Last 20 logins:"
last -20 2>/dev/null | head -20

echo ""
echo "Successful SSH connections (auth.log):"
if [ -f /var/log/auth.log ]; then
    grep "Accepted" /var/log/auth.log 2>/dev/null | tail -10
elif [ -f /var/log/secure ]; then
    grep "Accepted" /var/log/secure 2>/dev/null | tail -10
else
    echo "[!] Could not find auth logs"
fi
echo ""

# 3. CHECK USER ACCOUNTS
echo "[3] CHECKING USER ACCOUNTS"
echo "---------------------------------------------------------------------"
echo "Users with shell access:"
cat /etc/passwd | grep -E "/bin/bash|/bin/sh" | cut -d: -f1,3,6
echo ""

echo "Recently modified accounts:"
find /home -maxdepth 1 -type d -mtime -7 -exec ls -ld {} \; 2>/dev/null
echo ""

# 4. CHECK SSH KEYS
echo "[4] CHECKING SSH AUTHORIZED KEYS"
echo "---------------------------------------------------------------------"
echo "Root SSH keys:"
if [ -f /root/.ssh/authorized_keys ]; then
    echo "[!] Root has SSH keys:"
    cat /root/.ssh/authorized_keys
    echo ""
else
    echo "[OK] Root has no SSH keys"
fi

echo ""
echo "Checking common users for SSH keys:"
for user in ubuntu admin user test deploy docker; do
    if [ -f /home/$user/.ssh/authorized_keys ]; then
        echo "[!] User '$user' has SSH keys"
    fi
done
echo ""

# 5. CHECK CRON JOBS
echo "[5] CHECKING CRON JOBS (PERSISTENCE)"
echo "---------------------------------------------------------------------"
echo "System crontab:"
cat /etc/crontab 2>/dev/null | grep -v "^#" | grep -v "^$"

echo ""
echo "Cron.d directory:"
ls -la /etc/cron.d/ 2>/dev/null

echo ""
echo "Current user crontab:"
crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$"
echo ""

# 6. CHECK PROCESSES
echo "[6] CHECKING SUSPICIOUS PROCESSES"
echo "---------------------------------------------------------------------"
echo "Looking for reverse shells, netcat, suspicious processes:"
ps aux | grep -E "nc |ncat|netcat|reverse|/dev/tcp|python -c|bash -i" | grep -v grep
echo ""

echo "All listening network connections:"
netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null
echo ""

# 7. CHECK FOR BACKDOOR FILES
echo "[7] CHECKING FOR BACKDOOR FILES"
echo "---------------------------------------------------------------------"
echo "Recently modified system binaries:"
find /usr/bin /usr/sbin /bin /sbin -type f -mtime -1 2>/dev/null | head -10

echo ""
echo "Suspicious files in /tmp:"
ls -la /tmp/ | grep -E "^-.*x" | head -10
echo ""

# 8. CHECK SSH CONFIG
echo "[8] CHECKING SSH CONFIGURATION"
echo "---------------------------------------------------------------------"
echo "LoginGraceTime setting (CVE-2024-6387 mitigation):"
grep -i "LoginGraceTime" /etc/ssh/sshd_config 2>/dev/null || echo "Not set (vulnerable)"

echo ""
echo "PermitRootLogin setting:"
grep -i "PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null
echo ""

# 9. CHECK FOR ROOTKIT INDICATORS
echo "[9] CHECKING FOR ROOTKIT INDICATORS"
echo "---------------------------------------------------------------------"
echo "Hidden processes (ps vs /proc):"
ps aux | wc -l
ls /proc | grep -E "^[0-9]+$" | wc -l

echo ""
echo "Modified system libraries:"
find /lib /lib64 /usr/lib -type f -mtime -1 2>/dev/null | head -5
echo ""

# SUMMARY
echo "======================================================================"
echo "COMPROMISE CHECK SUMMARY"
echo "======================================================================"
echo ""
echo "[!] Review the above output carefully:"
echo "    - Unknown user accounts"
echo "    - Unfamiliar SSH keys"
echo "    - Suspicious cron jobs"
echo "    - Unknown processes or connections"
echo "    - Recently modified system files"
echo ""
echo "[!] If you found ANYTHING suspicious:"
echo "    1. Disconnect server from internet IMMEDIATELY"
echo "    2. Do not trust SSH - use console/VNC if possible"
echo "    3. Create forensic backup before fixing"
echo "    4. Rebuild from clean image"
echo ""
echo "[!] CVE-2024-6387 References:"
echo "    https://nvd.nist.gov/vuln/detail/CVE-2024-6387"
echo "    https://blog.qualys.com/vulnerabilities-threat-research/2024/07/01/regresshion"
echo ""
echo "Check completed at: $(date)"
echo "======================================================================"
