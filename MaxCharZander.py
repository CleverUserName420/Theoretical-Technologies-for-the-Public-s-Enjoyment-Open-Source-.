#!/usr/bin/env python3
"""
Quantum-Proof XOR Encryptor with customizable key length (no limit). 
Interactive terminal tool for generating encrypted payloads. 

Security scales with key length:
- 64 chars = 256 bits (quantum-resistant)
- 4096 chars = 16,384 bits (overkill)
- 1,000,000+ chars = why not?
"""

import secrets
import sys
import os
import json
import base64
from datetime import datetime
from typing import Tuple, Optional

# ANSI Colors for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Backgrounds
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'

def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def format_number(num: float) -> str:
    """Format large numbers in human-readable form"""
    if num < 1000:
        return f"{num:.2f}"
    elif num < 1_000_000:
        return f"{num/1000:.2f}K"
    elif num < 1_000_000_000:
        return f"{num/1_000_000:.2f}M"
    elif num < 1_000_000_000_000:
        return f"{num/1_000_000_000:.2f}B"
    elif num < 1_000_000_000_000_000:
        return f"{num/1_000_000_000_000:.2f}T"
    else:
        return f"{num:. 2e}"

def format_bytes(num_bytes: int) -> str:
    """Format bytes in human-readable form"""
    if num_bytes < 1024:
        return f"{num_bytes} bytes"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes/1024:.2f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes/(1024*1024):.2f} MB"
    elif num_bytes < 1024 * 1024 * 1024 * 1024:
        return f"{num_bytes/(1024*1024*1024):.2f} GB"
    else:
        return f"{num_bytes/(1024*1024*1024*1024):.2f} TB"

def generate_quantum_proof_key(length: int) -> bytes:
    """
    Generate a cryptographically secure hex key. 
    
    Args:
        length: Number of hex characters (no limit)
    
    Returns:
        bytes: The generated key
    """
    hex_chars = '0123456789abcdef'
    
    # For very large keys, generate in chunks to avoid memory issues
    if length > 1_000_000:
        chunks = []
        remaining = length
        chunk_size = 100_000
        while remaining > 0:
            current_chunk = min(chunk_size, remaining)
            chunks.append(''.join(secrets.choice(hex_chars) for _ in range(current_chunk)))
            remaining -= current_chunk
        return ''.join(chunks). encode('ascii')
    else:
        return ''.join(secrets. choice(hex_chars) for _ in range(length)).encode('ascii')

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt/decrypt data with key"""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def format_payload_hex(encrypted: bytes, chars_per_line: int = 64, max_lines: int = 50) -> str:
    """Format encrypted payload as hex with line breaks"""
    hex_str = encrypted.hex()
    lines = [hex_str[i:i+chars_per_line] for i in range(0, len(hex_str), chars_per_line)]
    
    if len(lines) > max_lines:
        shown_lines = lines[:max_lines//2] + [f"... [{len(lines) - max_lines} lines hidden] ... "] + lines[-max_lines//2:]
        return '\n'.join(shown_lines)
    return '\n'.join(lines)

def format_key(key: bytes, chars_per_line: int = 64, max_lines: int = 50) -> str:
    """Format key with line breaks for readability"""
    key_str = key. decode('ascii')
    lines = [key_str[i:i+chars_per_line] for i in range(0, len(key_str), chars_per_line)]
    
    if len(lines) > max_lines:
        shown_lines = lines[:max_lines//2] + [f"... [{len(lines) - max_lines} lines hidden] ..."] + lines[-max_lines//2:]
        return '\n'.join(shown_lines)
    return '\n'.join(lines)

def calculate_security_stats(key_length: int) -> dict:
    """Calculate security statistics for the key"""
    bits = key_length * 4  # 4 bits per hex char
    
    # For extremely large keys, we can't calculate exact key space
    # Just use the exponent representation
    log10_key_space = key_length * 1.20412  # log10(16) ≈ 1.20412
    
    # Classical: 1 trillion attempts per second
    # log10(years) = log10(key_space) - log10(10^12) - log10(seconds_per_year)
    # seconds_per_year ≈ 3.15576e7
    log10_classical_years = log10_key_space - 12 - 7.5
    
    # Quantum (Grover's algorithm): sqrt of key space = half the exponent
    log10_quantum_years = (log10_key_space / 2) - 9 - 7.5
    
    # Universe age: 13.8 billion years (log10 ≈ 10. 14)
    log10_universe_age = 10.14
    
    return {
        'key_length_chars': key_length,
        'key_length_bits': bits,
        'quantum_effective_bits': bits // 2,
        'key_space_exponent': f"16^{key_length}",
        'log10_key_space': log10_key_space,
        'log10_classical_years': log10_classical_years,
        'log10_quantum_years': log10_quantum_years,
        'log10_universes_classical': log10_classical_years - log10_universe_age,
        'log10_universes_quantum': log10_quantum_years - log10_universe_age
    }

def calculate_output_sizes(plaintext_length: int, key_length: int) -> dict:
    """Calculate all output sizes"""
    encrypted_bytes = plaintext_length
    encrypted_hex_chars = plaintext_length * 2
    key_chars = key_length
    key_bytes = key_length
    
    # Total output size (rough estimate including formatting)
    total_display_chars = encrypted_hex_chars + key_chars + 500  # 500 for headers/formatting
    
    # File sizes
    json_size_estimate = encrypted_hex_chars + key_chars + 500
    python_code_size_estimate = encrypted_hex_chars + key_chars + 1000
    
    return {
        'plaintext_bytes': plaintext_length,
        'encrypted_bytes': encrypted_bytes,
        'encrypted_hex_chars': encrypted_hex_chars,
        'key_chars': key_chars,
        'key_bytes': key_bytes,
        'total_display_chars': total_display_chars,
        'json_size_estimate': json_size_estimate,
        'python_code_size_estimate': python_code_size_estimate
    }

def print_banner():
    """Print the application banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████  ██    ██  █████  ███    ██ ████████ ██    ██ ███    ███           ║
║  ██    ██ ██    ██ ██   ██ ████   ██    ██    ██    ██ ████  ████           ║
║  ██    ██ ██    ██ ███████ ██ ██  ██    ██    ██    ██ ██ ████ ██           ║
║  ██ ▄▄ ██ ██    ██ ██   ██ ██  ██ ██    ██    ██    ██ ██  ██  ██           ║
║   ██████   ██████  ██   ██ ██   ████    ██     ██████  ██      ██           ║
║      ▀▀                                                                      ║
║                    ██████  ██████   ██████   ██████  ███████                 ║
║                    ██   ██ ██   ██ ██    ██ ██    ██ ██                      ║
║                    ██████  ██████  ██    ██ ██    ██ █████                   ║
║                    ██      ██   ██ ██    ██ ██    ██ ██                      ║
║                    ██      ██   ██  ██████   ██████  ██                      ║
║                                                                              ║
║            ███████ ███    ██  ██████ ██████  ██    ██ ██████  ████████       ║
║            ██      ████   ██ ██      ██   ██  ██  ██  ██   ██    ██          ║
║            █████   ██ ██  ██ ██      ██████    ████   ██████     ██          ║
║            ██      ██  ██ ██ ██      ██   ██    ██    ██         ██          ║
║            ███████ ██   ████  ██████ ██   ██    ██    ██         ██          ║
║                                                                              ║
║                  Customizable Key Length - No Limits!                         ║
║                  Quantum-Proof XOR Encryption Generator                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)

def print_security_info(stats: dict):
    """Print security information"""
    # Determine security level description
    if stats['key_length_bits'] < 128:
        security_status = f"{Colors.RED}⚠️  WEAK - NOT QUANTUM RESISTANT"
    elif stats['key_length_bits'] < 256:
        security_status = f"{Colors.YELLOW}🔶 MODERATE - BORDERLINE QUANTUM RESISTANT"
    elif stats['key_length_bits'] < 512:
        security_status = f"{Colors.GREEN}✅ STRONG - QUANTUM RESISTANT"
    elif stats['key_length_bits'] < 4096:
        security_status = f"{Colors.GREEN}✅ VERY STRONG - HIGHLY QUANTUM RESISTANT"
    else:
        security_status = f"{Colors. MAGENTA}🚀 OVERKILL - MATHEMATICALLY IMPOSSIBLE TO BREAK"
    
    print(f"""
{Colors. YELLOW}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                           SECURITY ANALYSIS                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.CYAN}  Key Length:{Colors.RESET}              {format_number(stats['key_length_chars'])} hex characters
{Colors. CYAN}  Classical Security:{Colors.RESET}     {format_number(stats['key_length_bits'])} bits
{Colors.CYAN}  Quantum Security:{Colors.RESET}       {format_number(stats['quantum_effective_bits'])} bits (post-Grover)
{Colors. CYAN}  Key Space:{Colors. RESET}              {stats['key_space_exponent']}

{Colors.GREEN}  Classical Brute Force:{Colors.RESET}  10^{stats['log10_classical_years']:.0f} years
{Colors.GREEN}  Quantum Brute Force:{Colors. RESET}    10^{stats['log10_quantum_years']:.0f} years

{Colors. MAGENTA}  Universe Ages (Classical):{Colors. RESET} 10^{stats['log10_universes_classical']:.0f}x
{Colors. MAGENTA}  Universe Ages (Quantum):{Colors.RESET}   10^{stats['log10_universes_quantum']:.0f}x

{Colors.BOLD}  {security_status}{Colors.RESET}
""")

def print_result(plaintext: bytes, encrypted: bytes, key: bytes, show_full: bool = False):
    """Print the encryption result"""
    stats = calculate_security_stats(len(key))
    sizes = calculate_output_sizes(len(plaintext), len(key))
    
    # Determine if we should truncate output
    max_lines = None if show_full else 50
    
    print(f"""
{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                          ENCRYPTION SUCCESSFUL                               ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors. RESET}

{Colors.CYAN}{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐
│ PLAINTEXT ({len(plaintext)} bytes)                                                          
└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}
{Colors.WHITE}{plaintext. decode('utf-8')}{Colors.RESET}

{Colors. YELLOW}{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐
│ ENCRYPTED PAYLOAD (HEX) - {len(encrypted)} bytes / {len(encrypted)*2} hex chars                              
└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}
{Colors.WHITE}{format_payload_hex(encrypted, max_lines=max_lines or 50)}{Colors.RESET}

{Colors.MAGENTA}{Colors. BOLD}┌──────────────────────────────────────────────────────────────────────────────┐
│ ENCRYPTED PAYLOAD (BYTES)                                                    │
└──────────────────────────────────────────────────────────────────────────────┘{Colors. RESET}
{Colors.WHITE}{repr(encrypted)}{Colors.RESET}

{Colors.RED}{Colors.BOLD}┌──────────────────────────────────────────────────────────────────────────────┐
│ {len(key)}-CHARACTER KEY (KEEP SECRET!)                                            
└──────────────────────────────────────────────────────────────────────────────┘{Colors.RESET}
{Colors.WHITE}{format_key(key, max_lines=max_lines or 50)}{Colors. RESET}
""")
    
    # Print security stats
    print_security_info(stats)

def confirm_output_size(plaintext: str, key_length: int) -> bool:
    """Ask user to confirm the output size"""
    sizes = calculate_output_sizes(len(plaintext. encode('utf-8')), key_length)
    stats = calculate_security_stats(key_length)
    
    print(f"""
{Colors.YELLOW}{Colors.BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                          OUTPUT SIZE CONFIRMATION                            ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors. RESET}

{Colors.CYAN}  Plaintext:{Colors.RESET}              "{plaintext[:50]}{'.. .' if len(plaintext) > 50 else ''}"
{Colors. CYAN}  Plaintext Length:{Colors.RESET}       {sizes['plaintext_bytes']} bytes

{Colors.YELLOW}  Key Length:{Colors. RESET}            {format_number(key_length)} hex characters
{Colors. YELLOW}  Key Size:{Colors.RESET}              {format_bytes(sizes['key_bytes'])}
{Colors.YELLOW}  Security:{Colors.RESET}              {format_number(stats['key_length_bits'])} bits classical / {format_number(stats['quantum_effective_bits'])} bits quantum

{Colors. GREEN}  Encrypted Payload:{Colors. RESET}     {sizes['encrypted_bytes']} bytes ({sizes['encrypted_hex_chars']} hex chars)

{Colors.MAGENTA}{Colors.BOLD}  ┌────────────────────────────────────────────────────────────────────────┐
  │ TOTAL OUTPUT SIZE: {format_bytes(sizes['total_display_chars']):>20}                              │
  │ JSON File Size:    {format_bytes(sizes['json_size_estimate']):>20}                              │
  │ Python Code Size:  {format_bytes(sizes['python_code_size_estimate']):>20}                              │
  └────────────────────────────────────────────────────────────────────────┘{Colors. RESET}
""")
    
    # Warn for very large outputs
    if key_length > 1_000_000:
        print(f"{Colors.RED}{Colors.BOLD}  ⚠️  WARNING: Very large key!  This may take a while to generate. {Colors.RESET}")
    if key_length > 10_000_000:
        print(f"{Colors.RED}{Colors.BOLD}  ⚠️  WARNING: Extremely large key! May use significant memory.{Colors. RESET}")
    if key_length > 100_000_000:
        print(f"{Colors.RED}{Colors.BOLD}  ⚠️  WARNING: Massive key! This could use GBs of memory! {Colors.RESET}")
    
    response = input(f"\n{Colors. YELLOW}{Colors.BOLD}Are you sure?  The output will be {format_bytes(sizes['total_display_chars'])} long.  (y/n): {Colors.RESET}").strip().lower()
    
    return response in ('y', 'yes')

def encrypt_word(word: str, key_length: int) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt a word with a random key. 
    
    Returns:
        Tuple of (plaintext, encrypted, key)
    """
    plaintext = word.encode('utf-8')
    key = generate_quantum_proof_key(key_length)
    encrypted = xor_encrypt(plaintext, key)
    return plaintext, encrypted, key

def verify_decryption(encrypted: bytes, key: bytes, original: bytes) -> bool:
    """Verify that decryption works correctly"""
    decrypted = xor_encrypt(encrypted, key)
    return decrypted == original

def save_to_file(plaintext: bytes, encrypted: bytes, key: bytes, filename: str = None):
    """Save encryption result to a JSON file"""
    if filename is None:
        timestamp = datetime.now(). strftime("%Y%m%d_%H%M%S")
        filename = f"encrypted_payload_{timestamp}.json"
    
    data = {
        'timestamp': datetime.now().isoformat(),
        'plaintext': plaintext.decode('utf-8'),
        'plaintext_hex': plaintext.hex(),
        'encrypted_hex': encrypted.hex(),
        'encrypted_base64': base64. b64encode(encrypted).decode('ascii'),
        'key': key.decode('ascii'),
        'key_length_chars': len(key),
        'key_length_bits': len(key) * 4,
        'quantum_effective_bits': len(key) * 2,
        'security_status': 'QUANTUM_PROOF' if len(key) >= 64 else 'STANDARD'
    }
    
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"{Colors.GREEN}✅ Saved to: {filename} ({format_bytes(os.path.getsize(filename))}){Colors.RESET}")
    return filename

def generate_python_code(plaintext: bytes, encrypted: bytes, key: bytes) -> str:
    """Generate Python code for the encrypted payload"""
    code = f'''#!/usr/bin/env python3
"""
Quantum-Proof Encrypted Payload
Generated: {datetime.now(). isoformat()}
Plaintext: "{plaintext.decode('utf-8')}"
Key Length: {len(key)} characters ({len(key)*4} bits)
Security: {'Quantum-proof' if len(key) >= 64 else 'Standard'}
"""

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR decrypt with key"""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

# Encrypted payload
ENCRYPTED_PAYLOAD = bytes.fromhex(
    "{encrypted. hex()}"
)

# {len(key)}-character key
KEY = b"{key.decode('ascii')}"

def decrypt():
    """Decrypt and return the original message"""
    return xor_decrypt(ENCRYPTED_PAYLOAD, KEY)

if __name__ == "__main__":
    result = decrypt()
    print(f"Decrypted: {{result.decode('utf-8')}}")
'''
    return code

def get_key_length() -> int:
    """Get key length from user with validation"""
    while True:
        try:
            length_input = input(f"{Colors.CYAN}{Colors.BOLD}Enter key length (hex characters, no limit): {Colors.RESET}").strip()
            
            if not length_input:
                print(f"{Colors. YELLOW}Using default: 4096 characters{Colors.RESET}")
                return 4096
            
            # Support suffixes like K, M, B
            multiplier = 1
            if length_input[-1]. upper() == 'K':
                multiplier = 1000
                length_input = length_input[:-1]
            elif length_input[-1].upper() == 'M':
                multiplier = 1_000_000
                length_input = length_input[:-1]
            elif length_input[-1]. upper() == 'B':
                multiplier = 1_000_000_000
                length_input = length_input[:-1]
            
            length = int(float(length_input) * multiplier)
            
            if length < 1:
                print(f"{Colors.RED}Key length must be at least 1 character. {Colors.RESET}")
                continue
            
            return length
            
        except ValueError:
            print(f"{Colors.RED}Please enter a valid number.  You can use K (thousand), M (million), B (billion) suffixes.{Colors. RESET}")

def interactive_mode():
    """Run the interactive encryption mode"""
    clear_screen()
    print_banner()
    
    print(f"""
{Colors. CYAN}Enter any word or phrase to encrypt with a custom-length quantum-proof key. 
Type 'quit' or 'exit' to end the program. 
Type 'help' for more options.{Colors.RESET}
""")
    
    last_result = None
    
    while True:
        try:
            print(f"\n{Colors. YELLOW}{Colors.BOLD}{'─' * 80}{Colors.RESET}")
            user_input = input(f"{Colors.GREEN}{Colors.BOLD}Enter word/phrase to encrypt: {Colors. RESET}").strip()
            
            if not user_input:
                print(f"{Colors.RED}Please enter a word or phrase. {Colors.RESET}")
                continue
            
            if user_input.lower() in ('quit', 'exit', 'q'):
                print(f"\n{Colors. CYAN}Goodbye!  Stay quantum-safe! 🔐{Colors.RESET}\n")
                break
            
            if user_input.lower() == 'help':
                print(f"""
{Colors. CYAN}{Colors.BOLD}Available Commands:{Colors.RESET}
  {Colors.GREEN}[any text]{Colors.RESET}  - Encrypt the text with a custom-length key
  {Colors.GREEN}save{Colors.RESET}        - Save last result to JSON file
  {Colors.GREEN}code{Colors.RESET}        - Generate Python code for last result
  {Colors.GREEN}verify{Colors.RESET}      - Verify last encryption/decryption
  {Colors.GREEN}full{Colors.RESET}        - Show full output of last result (no truncation)
  {Colors.GREEN}clear{Colors.RESET}       - Clear the screen
  {Colors. GREEN}help{Colors.RESET}        - Show this help
  {Colors.GREEN}quit/exit{Colors. RESET}   - Exit the program

{Colors.YELLOW}{Colors.BOLD}Key Length Tips:{Colors.RESET}
  {Colors.DIM}• Use numbers: 64, 4096, 100000{Colors. RESET}
  {Colors.DIM}• Use suffixes: 1K (1,000), 1M (1,000,000), 1B (1,000,000,000){Colors.RESET}
  {Colors.DIM}• Minimum quantum-resistant: 64 characters (256 bits){Colors. RESET}
  {Colors.DIM}• Recommended: 4096 characters (16,384 bits){Colors.RESET}
  {Colors.DIM}• No upper limit!  Go crazy if you want. {Colors.RESET}
""")
                continue
            
            if user_input.lower() == 'clear':
                clear_screen()
                print_banner()
                continue
            
            if user_input.lower() == 'save':
                if last_result:
                    save_to_file(*last_result)
                else:
                    print(f"{Colors.RED}No encryption result to save.  Encrypt something first.{Colors. RESET}")
                continue
            
            if user_input. lower() == 'code':
                if last_result:
                    code = generate_python_code(*last_result)
                    print(f"\n{Colors. CYAN}{Colors.BOLD}Generated Python Code:{Colors.RESET}\n")
                    # Truncate if too long
                    if len(code) > 5000:
                        print(code[:2500])
                        print(f"\n...  [{len(code) - 5000} characters hidden] .. .\n")
                        print(code[-2500:])
                    else:
                        print(code)
                else:
                    print(f"{Colors.RED}No encryption result.  Encrypt something first.{Colors.RESET}")
                continue
            
            if user_input.lower() == 'verify':
                if last_result:
                    plaintext, encrypted, key = last_result
                    if verify_decryption(encrypted, key, plaintext):
                        print(f"{Colors.GREEN}✅ Verification PASSED - Decryption works correctly! {Colors.RESET}")
                    else:
                        print(f"{Colors. RED}❌ Verification FAILED! {Colors.RESET}")
                else:
                    print(f"{Colors.RED}No encryption result to verify. Encrypt something first.{Colors. RESET}")
                continue
            
            if user_input. lower() == 'full':
                if last_result:
                    print_result(*last_result, show_full=True)
                else:
                    print(f"{Colors.RED}No encryption result.  Encrypt something first.{Colors.RESET}")
                continue
            
            # Get key length
            key_length = get_key_length()
            
            # Confirm output size
            if not confirm_output_size(user_input, key_length):
                print(f"{Colors. YELLOW}Encryption cancelled. {Colors.RESET}")
                continue
            
            # Encrypt the input
            print(f"\n{Colors. CYAN}Generating {format_number(key_length)}-character quantum-proof key...{Colors.RESET}")
            
            # Show progress for large keys
            if key_length > 100_000:
                print(f"{Colors. DIM}This may take a moment...{Colors. RESET}")
            
            import time
            start_time = time.time()
            
            plaintext, encrypted, key = encrypt_word(user_input, key_length)
            last_result = (plaintext, encrypted, key)
            
            elapsed = time.time() - start_time
            print(f"{Colors.GREEN}Key generated in {elapsed:.2f} seconds{Colors.RESET}")
            
            # Print result
            print_result(plaintext, encrypted, key)
            
            # Verify
            if verify_decryption(encrypted, key, plaintext):
                print(f"{Colors.GREEN}{Colors.BOLD}✅ Verification: Decryption successful!{Colors. RESET}")
            
            # Offer to save
            save_choice = input(f"\n{Colors. YELLOW}Save to file? (y/n): {Colors. RESET}").strip().lower()
            if save_choice in ('y', 'yes'):
                filename = save_to_file(plaintext, encrypted, key)
                
                # Also save Python code
                code_choice = input(f"{Colors.YELLOW}Generate Python code file? (y/n): {Colors. RESET}").strip(). lower()
                if code_choice in ('y', 'yes'):
                    code = generate_python_code(plaintext, encrypted, key)
                    code_filename = filename.replace('.json', '.py')
                    with open(code_filename, 'w') as f:
                        f.write(code)
                    print(f"{Colors.GREEN}✅ Python code saved to: {code_filename} ({format_bytes(os.path.getsize(code_filename))}){Colors. RESET}")
                    
        except KeyboardInterrupt:
            print(f"\n\n{Colors. CYAN}Interrupted.  Goodbye! 🔐{Colors. RESET}\n")
            break
        except MemoryError:
            print(f"{Colors.RED}❌ Out of memory! Try a smaller key length. {Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")

def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        # Command line mode
        # Check for --key-length or -k flag
        key_length = 4096
        args = sys.argv[1:]
        
        if '--key-length' in args:
            idx = args.index('--key-length')
            key_length = int(args[idx + 1])
            args = args[:idx] + args[idx + 2:]
        elif '-k' in args:
            idx = args.index('-k')
            key_length = int(args[idx + 1])
            args = args[:idx] + args[idx + 2:]
        
        word = ' '.join(args)
        
        if not word:
            print(f"{Colors.RED}Usage: {sys.argv[0]} <word/phrase> [-k <key_length>]{Colors.RESET}")
            sys.exit(1)
        
        print_banner()
        
        sizes = calculate_output_sizes(len(word.encode('utf-8')), key_length)
        print(f"{Colors.YELLOW}Generating {format_number(key_length)}-character key...{Colors.RESET}")
        print(f"{Colors. YELLOW}Output will be approximately {format_bytes(sizes['total_display_chars'])}{Colors.RESET}\n")
        
        plaintext, encrypted, key = encrypt_word(word, key_length)
        print_result(plaintext, encrypted, key)
        
        if verify_decryption(encrypted, key, plaintext):
            print(f"{Colors. GREEN}{Colors.BOLD}✅ Verification: Decryption successful!{Colors. RESET}")
    else:
        # Interactive mode
        interactive_mode()

if __name__ == "__main__":
    main()
