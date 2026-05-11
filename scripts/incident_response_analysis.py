#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
INCIDENT RESPONSE & COMPROMISE ANALYSIS TOOL
For Server: 196.218.83.9
Purpose: Detect signs of CVE-2024-6387 exploitation and attacker activity
"""

import os
import sys
import subprocess
import json
import hashlib
import re
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

class IncidentResponseAnalyzer:
    def __init__(self, target_ip="196.218.83.9"):
        self.target_ip = target_ip
        self.findings = []
        self.suspicious_indicators = []
        self.output_dir = f"incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_dir, exist_ok=True)
        
    def log_finding(self, severity, category, message, details=None):
        """Log a security finding"""
        finding = {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "category": category,
            "message": message,
            "details": details or {}
        }
        self.findings.append(finding)
        
        severity_colors = {
            "CRITICAL": "\033[91m",  # Red
            "HIGH": "\033[93m",      # Yellow
            "MEDIUM": "\033[94m",    # Blue
            "LOW": "\033[92m",       # Green
            "INFO": "\033[90m"       # Gray
        }
        
        color = severity_colors.get(severity, "\033[0m")
        print(f"{color}[{severity}] [{category}] {message}\033[0m")
        
    def run_command(self, cmd, timeout=30):
        """Execute shell command safely"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except Exception as e:
            return "", str(e), 1
    
    def check_ssh_version(self):
        """Check OpenSSH version for vulnerability"""
        print("\n" + "="*70)
        print("CHECK 1: OpenSSH Version Analysis")
        print("="*70)
        
        stdout, stderr, rc = self.run_command("ssh -V 2>&1")
        version = stdout + stderr
        
        vulnerable_versions = [
            "8.5p1", "8.6p1", "8.7p1", "8.8p1", "8.9p1",
            "9.0p1", "9.1p1", "9.2p1", "9.3p1", "9.4p1", "9.5p1", "9.6p1", "9.7p1"
        ]
        
        is_vulnerable = any(v in version for v in vulnerable_versions)
        
        if is_vulnerable:
            self.log_finding(
                "CRITICAL", 
                "CVE-2024-6387",
                f"Server is VULNERABLE to regreSSHion exploit",
                {"version": version, "cve": "CVE-2024-6387"}
            )
        else:
            self.log_finding(
                "INFO",
                "SSH Version",
                f"SSH Version: {version.strip()}",
                {"version": version}
            )
        
        return is_vulnerable
    
    def analyze_auth_logs(self):
        """Analyze authentication logs for intrusion signs"""
        print("\n" + "="*70)
        print("CHECK 2: Authentication Log Analysis")
        print("="*70)
        
        log_files = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/syslog"
        ]
        
        suspicious_patterns = [
            r"Accepted.*for.*root",           # Root login
            r"Accepted.*from.*",              # Any accepted login
            r"Failed password.*",             # Failed attempts
            r"Connection closed by.*",       # Connection patterns
            r"Received disconnect from",       # Disconnects
            r"Invalid user.*",                # Invalid user attempts
            r"reverse mapping checking",      # DNS spoofing attempts
            r"POSSIBLE BREAK-IN ATTEMPT",    # Break-in signs
            r"sshd.*:.*error",                # SSH errors
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                self.log_finding("INFO", "Logs", f"Found log file: {log_file}")
                
                try:
                    with open(log_file, 'r', errors='ignore') as f:
                        lines = f.readlines()
                        
                    # Check last 500 lines for suspicious activity
                    recent_lines = lines[-500:]
                    
                    for pattern in suspicious_patterns:
                        matches = [line for line in recent_lines if re.search(pattern, line)]
                        if matches:
                            self.log_finding(
                                "HIGH" if "Accepted" in pattern or "POSSIBLE" in pattern else "MEDIUM",
                                "Auth Logs",
                                f"Pattern '{pattern}' found {len(matches)} times in {log_file}",
                                {"sample": matches[-1].strip() if matches else None}
                            )
                            
                    # Save suspicious entries
                    output_file = os.path.join(self.output_dir, f"auth_analysis_{os.path.basename(log_file)}.txt")
                    with open(output_file, 'w') as f:
                        f.write(f"Analysis of {log_file}\n")
                        f.write("="*70 + "\n\n")
                        for pattern in suspicious_patterns:
                            matches = [line for line in recent_lines if re.search(pattern, line)]
                            if matches:
                                f.write(f"Pattern: {pattern}\n")
                                f.write("-"*70 + "\n")
                                for match in matches[-10:]:  # Last 10 matches
                                    f.write(match)
                                f.write("\n")
                                
                except Exception as e:
                    self.log_finding("MEDIUM", "Logs", f"Could not read {log_file}: {e}")
    
    def check_user_accounts(self):
        """Check for suspicious user accounts"""
        print("\n" + "="*70)
        print("CHECK 3: User Account Analysis")
        print("="*70)
        
        try:
            with open('/etc/passwd', 'r') as f:
                users = f.readlines()
            
            shell_users = []
            for user_line in users:
                parts = user_line.strip().split(':')
                if len(parts) >= 7:
                    username, uid, home, shell = parts[0], parts[2], parts[5], parts[6]
                    if shell in ['/bin/bash', '/bin/sh', '/bin/zsh']:
                        shell_users.append({
                            'username': username,
                            'uid': uid,
                            'home': home,
                            'shell': shell
                        })
            
            # Check for UID 0 (root) accounts
            root_accounts = [u for u in shell_users if u['uid'] == '0']
            if len(root_accounts) > 1:
                self.log_finding(
                    "CRITICAL",
                    "User Accounts",
                    f"Multiple root accounts detected: {[u['username'] for u in root_accounts]}",
                    {"accounts": root_accounts}
                )
            
            # Check for recently created accounts (last 7 days)
            try:
                stdout, _, _ = self.run_command("find /home -maxdepth 1 -type d -mtime -7 2>/dev/null")
                recent_homes = stdout.strip().split('\n') if stdout.strip() else []
                if recent_homes and recent_homes[0]:
                    self.log_finding(
                        "HIGH",
                        "User Accounts",
                        f"Recently created home directories: {recent_homes}",
                        {"directories": recent_homes}
                    )
            except:
                pass
            
            # Check /etc/shadow for password changes
            try:
                stdout, _, _ = self.run_command("stat /etc/shadow 2>/dev/null")
                self.log_finding("INFO", "User Accounts", 
                               f"/etc/shadow modified: {stdout}")
            except:
                pass
            
            # Save user list
            output_file = os.path.join(self.output_dir, "user_accounts.json")
            with open(output_file, 'w') as f:
                json.dump(shell_users, f, indent=2)
                
            self.log_finding("INFO", "User Accounts", 
                           f"Found {len(shell_users)} users with shell access",
                           {"count": len(shell_users)})
            
        except Exception as e:
            self.log_finding("MEDIUM", "User Accounts", f"Could not analyze users: {e}")
    
    def check_ssh_keys(self):
        """Check for unauthorized SSH keys"""
        print("\n" + "="*70)
        print("CHECK 4: SSH Authorized Keys Analysis")
        print("="*70)
        
        key_locations = [
            '/root/.ssh/authorized_keys',
            '/root/.ssh/authorized_keys2',
        ]
        
        # Check common users
        common_users = ['ubuntu', 'admin', 'user', 'deploy', 'docker', 'test']
        for user in common_users:
            key_locations.append(f'/home/{user}/.ssh/authorized_keys')
        
        found_keys = []
        
        for key_file in key_locations:
            if os.path.exists(key_file):
                try:
                    with open(key_file, 'r') as f:
                        content = f.read().strip()
                    
                    if content:
                        lines = [l for l in content.split('\n') if l.strip() and not l.startswith('#')]
                        if lines:
                            self.log_finding(
                                "HIGH" if 'root' in key_file else "MEDIUM",
                                "SSH Keys",
                                f"Found {len(lines)} SSH key(s) in {key_file}",
                                {"file": key_file, "key_count": len(lines)}
                            )
                            found_keys.append({
                                'file': key_file,
                                'keys': lines
                            })
                except Exception as e:
                    self.log_finding("MEDIUM", "SSH Keys", 
                                   f"Could not read {key_file}: {e}")
        
        # Save keys for analysis
        if found_keys:
            output_file = os.path.join(self.output_dir, "ssh_keys.json")
            with open(output_file, 'w') as f:
                json.dump(found_keys, f, indent=2)
        else:
            self.log_finding("INFO", "SSH Keys", "No SSH authorized_keys found")
    
    def check_persistence(self):
        """Check for persistence mechanisms"""
        print("\n" + "="*70)
        print("CHECK 5: Persistence Mechanisms")
        print("="*70)
        
        # Check crontab
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/etc/cron.hourly/',
            '/etc/cron.daily/',
            '/etc/cron.weekly/',
            '/etc/cron.monthly/',
            '/var/spool/cron/',
        ]
        
        for cron_path in cron_locations:
            if os.path.exists(cron_path):
                if os.path.isfile(cron_path):
                    try:
                        with open(cron_path, 'r') as f:
                            content = f.read()
                        # Check for non-comment, non-empty lines
                        active_lines = [l for l in content.split('\n') 
                                       if l.strip() and not l.startswith('#')]
                        if active_lines:
                            self.log_finding(
                                "HIGH" if '/etc/cron' in cron_path else "MEDIUM",
                                "Persistence",
                                f"Active cron entries in {cron_path}",
                                {"entries": active_lines[:5]}
                            )
                    except:
                        pass
                elif os.path.isdir(cron_path):
                    try:
                        files = os.listdir(cron_path)
                        if files:
                            self.log_finding(
                                "MEDIUM",
                                "Persistence",
                                f"Cron directory {cron_path} contains: {files}"
                            )
                    except:
                        pass
        
        # Check systemd services
        try:
            stdout, _, _ = self.run_command("systemctl list-units --type=service --state=running 2>/dev/null | grep -v '^●' | head -30")
            if stdout:
                output_file = os.path.join(self.output_dir, "running_services.txt")
                with open(output_file, 'w') as f:
                    f.write(stdout)
                self.log_finding("INFO", "Persistence", 
                               "Saved running services list")
        except:
            pass
        
        # Check for systemd user services
        try:
            systemd_user_dirs = [
                '/etc/systemd/system/',
                '/lib/systemd/system/',
                '/usr/lib/systemd/system/',
            ]
            for d in systemd_user_dirs:
                if os.path.exists(d):
                    files = os.listdir(d)
                    recent = [f for f in files 
                             if os.path.isfile(os.path.join(d, f)) 
                             and os.stat(os.path.join(d, f)).st_mtime > (datetime.now().timestamp() - 86400)]
                    if recent:
                        self.log_finding(
                            "HIGH",
                            "Persistence",
                            f"Recently modified systemd services in {d}: {recent}",
                            {"files": recent}
                        )
        except:
            pass
    
    def check_processes(self):
        """Check for suspicious processes"""
        print("\n" + "="*70)
        print("CHECK 6: Process Analysis")
        print("="*70)
        
        suspicious_patterns = [
            'nc ', 'ncat', 'netcat', 'nc -e', 'ncat -e',
            'reverse', 'backdoor', '/dev/tcp/', '/dev/udp/',
            'python -c', 'python3 -c', 'perl -e', 'ruby -e',
            'bash -i', 'sh -i', 'cmd.exe',
            'socket', 'connect', 'listen',
        ]
        
        try:
            stdout, _, _ = self.run_command("ps auxww")
            if stdout:
                lines = stdout.split('\n')
                suspicious = []
                
                for line in lines:
                    for pattern in suspicious_patterns:
                        if pattern in line.lower():
                            suspicious.append(line)
                            break
                
                if suspicious:
                    self.log_finding(
                        "CRITICAL",
                        "Processes",
                        f"Found {len(suspicious)} suspicious process(es)",
                        {"processes": suspicious[:10]}
                    )
                else:
                    self.log_finding("INFO", "Processes", "No obvious suspicious processes found")
                
                # Save full process list
                output_file = os.path.join(self.output_dir, "process_list.txt")
                with open(output_file, 'w') as f:
                    f.write(stdout)
        except Exception as e:
            self.log_finding("MEDIUM", "Processes", f"Could not check processes: {e}")
    
    def check_network(self):
        """Check network connections"""
        print("\n" + "="*70)
        print("CHECK 7: Network Analysis")
        print("="*70)
        
        # Check listening ports
        try:
            stdout, _, _ = self.run_command("netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null")
            if stdout:
                output_file = os.path.join(self.output_dir, "network_listeners.txt")
                with open(output_file, 'w') as f:
                    f.write(stdout)
                self.log_finding("INFO", "Network", "Saved network listener information")
                
                # Check for suspicious ports
                suspicious_ports = ['4444', '5555', '6666', '7777', '8888', '9999', '1234']
                for port in suspicious_ports:
                    if f":{port}" in stdout:
                        self.log_finding(
                            "HIGH",
                            "Network",
                            f"Suspicious port {port} is listening",
                            {"port": port}
                        )
        except:
            pass
        
        # Check established connections
        try:
            stdout, _, _ = self.run_command("netstat -tupn 2>/dev/null | grep ESTABLISHED || ss -tupn 2>/dev/null | grep ESTAB")
            if stdout:
                lines = stdout.strip().split('\n')
                if len(lines) > 10:
                    self.log_finding(
                        "MEDIUM",
                        "Network",
                        f"Found {len(lines)} established connections",
                        {"count": len(lines)}
                    )
                
                output_file = os.path.join(self.output_dir, "established_connections.txt")
                with open(output_file, 'w') as f:
                    f.write(stdout)
        except:
            pass
    
    def check_files(self):
        """Check for suspicious files"""
        print("\n" + "="*70)
        print("CHECK 8: File System Analysis")
        print("="*70)
        
        # Check /tmp for suspicious files
        try:
            stdout, _, _ = self.run_command("find /tmp -type f -mtime -1 2>/dev/null | head -20")
            if stdout.strip():
                recent_files = stdout.strip().split('\n')
                self.log_finding(
                    "MEDIUM",
                    "Files",
                    f"Found {len(recent_files)} recently created files in /tmp",
                    {"files": recent_files[:10]}
                )
        except:
            pass
        
        # Check for modified system binaries
        try:
            stdout, _, _ = self.run_command("find /usr/bin /usr/sbin /bin /sbin -type f -mtime -1 2>/dev/null | head -10")
            if stdout.strip():
                modified_bins = stdout.strip().split('\n')
                self.log_finding(
                    "CRITICAL",
                    "Files",
                    f"Recently modified system binaries detected: {modified_bins[:5]}",
                    {"binaries": modified_bins}
                )
        except:
            pass
        
        # Check /var/www or web directories
        web_dirs = ['/var/www', '/var/html', '/usr/share/nginx/html']
        for d in web_dirs:
            if os.path.exists(d):
                try:
                    stdout, _, _ = self.run_command(f"find {d} -name '*.php' -o -name '*.jsp' -o -name '*.asp' -o -name '*.sh' 2>/dev/null | head -20")
                    if stdout.strip():
                        self.log_finding(
                            "INFO",
                            "Files",
                            f"Found web files in {d} - review for backdoors",
                            {"files": stdout.strip().split('\n')[:10]}
                        )
                except:
                    pass
    
    def generate_report(self):
        """Generate final incident report"""
        print("\n" + "="*70)
        print("INCIDENT RESPONSE REPORT")
        print("="*70)
        
        # Categorize findings
        critical = [f for f in self.findings if f['severity'] == 'CRITICAL']
        high = [f for f in self.findings if f['severity'] == 'HIGH']
        medium = [f for f in self.findings if f['severity'] == 'MEDIUM']
        info = [f for f in self.findings if f['severity'] == 'INFO']
        
        print(f"\n[SUMMARY]")
        print(f"  Critical findings: {len(critical)}")
        print(f"  High findings: {len(high)}")
        print(f"  Medium findings: {len(medium)}")
        print(f"  Info: {len(info)}")
        
        if critical:
            print(f"\n\033[91m[CRITICAL FINDINGS - IMMEDIATE ACTION REQUIRED]\033[0m")
            for f in critical:
                print(f"  - {f['category']}: {f['message']}")
        
        if high:
            print(f"\n\033[93m[HIGH FINDINGS]\033[0m")
            for f in high:
                print(f"  - {f['category']}: {f['message']}")
        
        # Save full report
        report = {
            "target_ip": self.target_ip,
            "analysis_timestamp": datetime.now().isoformat(),
            "summary": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "info": len(info)
            },
            "findings": self.findings,
            "output_directory": self.output_dir
        }
        
        report_file = os.path.join(self.output_dir, "incident_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n\n[+] Full report saved: {report_file}")
        print(f"[+] All evidence saved in: {self.output_dir}/")
        
        print("\n" + "="*70)
        print("RECOMMENDATIONS")
        print("="*70)
        
        if critical or high:
            print("""
[!] COMPROMISE LIKELY - TAKE IMMEDIATE ACTION:

    1. DISCONNECT SERVER FROM INTERNET
       - Block port 22 at firewall
       - Or physically disconnect network
    
    2. DO NOT TRUST SSH - Use console/VNC only
    
    3. CREATE FORENSIC BACKUP
       - dd if=/dev/sda of=/backup/forensic.img bs=1M
    
    4. ANALYZE ALL DATA ACCESSED
       - MinIO buckets: backup, database, config, files
       - Open WebUI data
       - Any credentials stored on server
    
    5. REBUILD CLEAN SERVER
       - Do not attempt to "clean" the compromise
       - Create new server from scratch
       - Restore only from known-clean backups
    
    6. CHANGE ALL CREDENTIALS
       - All passwords
       - All SSH keys
       - All API keys
       - Database credentials
       - Any tokens
            """)
        else:
            print("""
[?] No critical indicators found, but server was vulnerable.
    Still recommend patching OpenSSH and monitoring closely.
            """)
    
    def run_all_checks(self):
        """Execute all incident response checks"""
        print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║          INCIDENT RESPONSE & COMPROMISE ANALYSIS                   ║
    ║                    CVE-2024-6387 (regreSSHion)                     ║
    ╚══════════════════════════════════════════════════════════════════════╝
        """)
        print(f"Target: {self.target_ip}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Output: {self.output_dir}/")
        print()
        
        # Run all checks
        self.check_ssh_version()
        self.analyze_auth_logs()
        self.check_user_accounts()
        self.check_ssh_keys()
        self.check_persistence()
        self.check_processes()
        self.check_network()
        self.check_files()
        
        # Generate report
        self.generate_report()

def main():
    analyzer = IncidentResponseAnalyzer()
    analyzer.run_all_checks()

if __name__ == "__main__":
    main()
