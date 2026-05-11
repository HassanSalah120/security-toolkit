# PenTestToolkit — Security Testing Framework

A modular, extensible penetration testing framework for authorized security assessments.

## Structure

```
├── tools/          ← Core framework (8 scanners + shared utilities)
├── scripts/        ← Engagement-specific investigation scripts
├── exploits/       ← CVE exploit implementations
├── docs/           ← Project documentation
├── tests/          ← Test suite
```

## Tools

| Tool | Purpose |
|------|---------|
| `tools/pentest_toolkit.py` | Unified CLI orchestrating all scans |
| `tools/web_vulnerability_scanner.py` | SQLi, XSS, CMDi, LFI, SSRF, XXE, NoSQL, LDAP, SSTI |
| `tools/api_security_tester.py` | API security: IDOR, rate limiting, GraphQL, smuggling |
| `tools/auth_security_tester.py` | Auth: OAuth, SAML, MFA bypass, password policy |
| `tools/business_logic_scanner.py` | Business logic: promo abuse, race conditions, workflow |
| `tools/shadow_scanner.py` | Port scanner: TCP/UDP, service detection, CVE lookup |
| `tools/shadow_recon.py` | Recon: subdomains, DNS, tech detection |
| `tools/accurate_surface_scanner.py` | Surface validation scanner |
| `tools/common.py` | Shared utilities (WAF detection, parallel_map, NVD CVE check) |

## Quick Start

```bash
pip install -r requirements.txt
python tools/web_vulnerability_scanner.py -u https://target.com --sqli --xss
```

See `tools/README.md` for full documentation.

## License

MIT — use responsibly and only on authorized systems.
