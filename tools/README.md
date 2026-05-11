# PenTestToolkit - Professional Penetration Testing Framework

A comprehensive, ethical hacking toolkit for authorized security assessments.

## ⚠️ Legal Disclaimer

**This toolkit is for AUTHORIZED security testing ONLY.**

- Only use on systems you own or have explicit written permission to test
- Unauthorized use is illegal and unethical
- Always obtain proper authorization before testing
- Follow responsible disclosure practices

## Features

### 🔍 Network Reconnaissance
- Port scanning (TCP/UDP)
- Service fingerprinting
- Banner grabbing
- CVE-based vulnerability detection

### 🌐 Web Application Security
- **SQL Injection** (Error-based, Time-based blind, Boolean-based)
- **Cross-Site Scripting (XSS)** (Reflected, Stored, DOM-based)
- **Command Injection**
- **Local File Inclusion (LFI)**
- **Server-Side Request Forgery (SSRF)**
- **XML External Entity (XXE)**
- **NoSQL Injection**
- **LDAP Injection**

### 🔐 Authentication Security
- Username enumeration
- Weak password testing
- Brute force protection detection
- Session security analysis
- Cookie security flags
- JWT security testing
- Security headers validation

### 🔌 API Security
- IDOR (Insecure Direct Object Reference)
- Broken Authentication
- Rate Limiting
- Mass Assignment
- Excessive Data Exposure
- CORS Misconfiguration
- GraphQL Introspection

### 💰 Business Logic
- Price manipulation
- Quantity manipulation
- Coupon/Promo abuse
- Race conditions
- Workflow bypass
- Privilege escalation
- Payment flow flaws

## Installation

```bash
cd tools
pip install -r requirements.txt
```

## Usage

### Full Security Assessment

```bash
python pentest_toolkit.py -t https://target.com --full-scan
```

### Individual Scans

```bash
# Web vulnerability scan
python web_vulnerability_scanner.py -u https://target.com --crawl --forms --all

# API security scan
python api_security_tester.py -u https://api.target.com --auth "Bearer token"

# Authentication security
python auth_security_tester.py -u https://target.com/login

# Business logic testing
python business_logic_scanner.py -u https://shop.target.com

# Network reconnaissance
python shadow_scanner.py -t 192.168.1.1
```

### With Authentication

```bash
python pentest_toolkit.py -t https://target.com --full-scan --auth "Bearer YOUR_TOKEN"
```

## Output

All scans generate:
- **JSON Report** - Machine-readable for integration
- **HTML Report** - Professional report for clients

Reports include:
- Executive summary
- Risk score (0-100)
- Vulnerability details with CVSS scores
- Evidence and remediation recommendations

## Report Structure

```
pentest_YYYYMMDD_HHMMSS/
├── pentest_report.json      # Unified JSON report
├── pentest_report.html      # Professional HTML report
├── web_scan/                # Web vulnerability details
├── api_scan/                # API security details
├── auth_scan/               # Authentication details
└── logic_scan/              # Business logic details
```

## Methodology

This toolkit follows industry standards:
- **OWASP Testing Guide v4.2**
- **OWASP API Security Top 10**
- **PTES (Penetration Testing Execution Standard)**
- **NIST Cybersecurity Framework**

## Tools Included

| Tool | Purpose |
|------|---------|
| `pentest_toolkit.py` | Unified CLI for all scans |
| `web_vulnerability_scanner.py` | Web app vulnerabilities |
| `api_security_tester.py` | API security testing |
| `auth_security_tester.py` | Authentication testing |
| `business_logic_scanner.py` | Business logic flaws |
| `shadow_scanner.py` | Network port scanning |
| `shadow_recon.py` | Reconnaissance |
| `accurate_surface_scanner.py` | Surface validation |

## Ethical Guidelines

1. ✅ Obtain written authorization before testing
2. ✅ Sign NDA with clients
3. ✅ Respect scope boundaries
4. ✅ Report findings responsibly
5. ✅ Delete all data after engagement
6. ❌ Never test without permission
7. ❌ Never exfiltrate data
8. ❌ Never cause service disruption

## License

MIT License - Use responsibly and ethically.

## Support

For authorized security professionals only.
