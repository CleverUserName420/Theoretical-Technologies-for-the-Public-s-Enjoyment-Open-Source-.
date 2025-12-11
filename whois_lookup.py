#!/usr/bin/env python3
"""
Simple WHOIS Lookup Script
Paste multiple domains or URLs, one per line
"""

import subprocess
import re
from urllib.parse import urlparse

def extract_domain(input_string):
    """Extract domain from URL or return as-is if already a domain"""
    input_string = input_string.strip()
    
    # If it looks like a URL, parse it
    if '://' in input_string or input_string.startswith('www.'):
        if not input_string.startswith(('http://', 'https://')):
            input_string = 'http://' + input_string
        parsed = urlparse(input_string)
        return parsed.netloc or parsed.path.split('/')[0]
    
    # Otherwise assume it's already a domain
    return input_string.split('/')[0]

def whois_lookup(domain):
    """Perform WHOIS lookup on a domain"""
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Error: WHOIS lookup timed out for {domain}"
    except FileNotFoundError:
        return "Error: 'whois' command not found. Install it with: sudo apt-get install whois"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    print("=" * 70)
    print("WHOIS Lookup Tool")
    print("=" * 70)
    print("\nPaste your domains or URLs below (one per line).")
    print("Press Enter twice when done (empty line to finish):\n")
    
    # Collect input
    domains_input = []
    while True:
        try:
            line = input()
            if not line.strip():
                break
            domains_input.append(line.strip())
        except EOFError:
            break
    
    if not domains_input:
        print("No domains provided. Exiting.")
        return
    
    # Process each domain
    print(f"\n{'=' * 70}")
    print(f"Processing {len(domains_input)} domain(s)...")
    print(f"{'=' * 70}\n")
    
    for i, input_line in enumerate(domains_input, 1):
        domain = extract_domain(input_line)
        
        print(f"\n{'─' * 70}")
        print(f"[{i}/{len(domains_input)}] Domain: {domain}")
        if domain != input_line:
            print(f"      (from: {input_line})")
        print(f"{'─' * 70}\n")
        
        whois_result = whois_lookup(domain)
        print(whois_result)

if __name__ == "__main__":
    main()
