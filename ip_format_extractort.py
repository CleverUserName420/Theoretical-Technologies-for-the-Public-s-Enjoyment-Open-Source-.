#!/usr/bin/env python3
"""
Nathan Adie's IP Address Format Extractor & Converter - Enhanced Edition v3.0
Identifies and converts various IP address representations to standard dotted-decimal format.
Designed for malware analysis and C2 infrastructure investigation.

Enhanced Features:
- Standard IPv6 Support (uncompressed, compressed, embedded IPv4)
- Alternative Encodings (Base32, Base58, Base85)
- Custom Separators (spaces, tabs, pipes, semicolons, Unicode)
- Unicode Escapes (\\uXXXX)
- Mixed Radix per Octet (decimal, hex, octal, binary)
- Subnet/Range Support
- Confidence Scoring for False Positive Filtering
- Compression-Wrapped Content (GZip, zlib)
- Malformed/Obfuscated Extraction (char codes, math ops)
- YARA Output
- CSV/JSON Export
- Hostname#Port:Port Extraction
"""

import re
import sys
import base64
import struct
import socket
import binascii
import gzip
import zlib
import json
import csv
import io
import ipaddress
from pathlib import Path
from typing import List, Tuple, Set, Dict, Any, Optional
from urllib.parse import unquote

# Base58 alphabet (Bitcoin-style)
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58_decode(s: str) -> bytes:
    """
    Decode a Base58-encoded string to bytes.
    Used for detecting potential Base58-encoded IP addresses.
    """
    num = 0
    for char in s:
        if char not in BASE58_ALPHABET:
            raise ValueError(f"Invalid Base58 character: {char}")
        num = num * 58 + BASE58_ALPHABET.index(char)
    # Convert to bytes
    result = []
    while num > 0:
        result.append(num % 256)
        num //= 256
    # Handle leading zeros
    for char in s:
        if char == '1':
            result.append(0)
        else:
            break
    return bytes(reversed(result))


def base85_decode(s: str) -> bytes:
    """
    Decode a Base85 (ASCII85) string to bytes.
    Used for detecting potential Base85-encoded IP addresses.
    """
    try:
        return base64.a85decode(s, foldspaces=True)
    except Exception:
        return b''


class IPFormatExtractor:
    """
    Comprehensive IP address format extractor supporting multiple encodings,
    IPv4/IPv6, obfuscation detection, and confidence scoring.
    """
    
    def __init__(self, min_confidence: float = 0.0):
        """
        Initialize the IP Format Extractor.
        
        Args:
            min_confidence: Minimum confidence threshold (0.0-1.0) for filtering results
        """
        self.found_ips = set()
        self.found_ipv6 = set()
        self.results = []
        self.ip_ranges = []
        self.subnets = []
        self.hostnames = []
        self.min_confidence = min_confidence
        
    def validate_ip(self, ip_str: str) -> bool:
        """Validate if string is a valid IPv4 address"""
        try:
            octets = ip_str.split('.')
            if len(octets) != 4:
                return False
            for octet in octets:
                num = int(octet)
                if num < 0 or num > 255:
                    return False
            return True
        except Exception:
            return False
    
    def validate_ipv6(self, ip_str: str) -> bool:
        """
        Validate if string is a valid IPv6 address.
        Supports standard, compressed, and embedded IPv4 formats.
        """
        try:
            ipaddress.IPv6Address(ip_str)
            return True
        except Exception:
            return False
    
    def calculate_confidence(self, context: str, format_type: str, original: str) -> float:
        """
        Calculate confidence score based on contextual heuristics.
        
        Args:
            context: Surrounding text context
            format_type: The format type of the detection
            original: The original matched string
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.5  # Base confidence
        
        # Increase confidence for quoted values
        if '"' + original + '"' in context or "'" + original + "'" in context:
            confidence += 0.2
        
        # Increase confidence for labeled values (e.g., ip=, address:, host=)
        ip_labels = ['ip=', 'ip:', 'address=', 'address:', 'host=', 'host:',
                     'server=', 'server:', 'target=', 'target:', 'dst=', 'src=']
        context_lower = context.lower()
        for label in ip_labels:
            if label in context_lower:
                confidence += 0.15
                break
        
        # High-confidence formats
        high_conf_formats = ['Standard Dotted-Decimal', 'CIDR Notation', 'JSON String Value',
                            'XML Element', 'IPv4-mapped IPv6', 'inet_addr()']
        if any(fmt in format_type for fmt in high_conf_formats):
            confidence += 0.2
        
        # Lower confidence for raw hex or potentially ambiguous formats
        low_conf_formats = ['Raw Hex', 'Hex Sequence', 'Base32', 'Base58', 'Base85']
        if any(fmt in format_type for fmt in low_conf_formats):
            confidence -= 0.2
        
        # Increase confidence if surrounded by network context
        network_context = ['port', 'tcp', 'udp', 'http', 'https', 'connect', 'socket', 'network']
        for term in network_context:
            if term in context_lower:
                confidence += 0.1
                break
        
        return max(0.0, min(1.0, confidence))
    
    def add_result(self, ip: str, format_type: str, original: str,
                   confidence: float = 0.7, context: str = "", is_range: bool = False):
        """
        Add found IP to results if valid and meets confidence threshold.
        
        Args:
            ip: The extracted IP address
            format_type: Description of the format detected
            original: The original matched string
            confidence: Detection confidence score (0.0-1.0)
            context: Surrounding text for context analysis
            is_range: Whether this is a range/subnet entry
        """
        if confidence < self.min_confidence:
            return
            
        if self.validate_ip(ip) and ip not in self.found_ips:
            self.found_ips.add(ip)
            self.results.append({
                'ip': ip,
                'format': format_type,
                'original': original[:100],  # Truncate long strings
                'confidence': round(confidence, 2),
                'context': context[:50] if context else ""
            })
    
    def add_ipv6_result(self, ip: str, format_type: str, original: str,
                        confidence: float = 0.7, context: str = ""):
        """
        Add found IPv6 address to results if valid.
        
        Args:
            ip: The extracted IPv6 address
            format_type: Description of the format detected
            original: The original matched string
            confidence: Detection confidence score
            context: Surrounding text for context analysis
        """
        if confidence < self.min_confidence:
            return
            
        if self.validate_ipv6(ip) and ip not in self.found_ipv6:
            self.found_ipv6.add(ip)
            self.results.append({
                'ip': ip,
                'format': format_type,
                'original': original[:100],
                'confidence': round(confidence, 2),
                'context': context[:50] if context else "",
                'type': 'ipv6'
            })
    
    def int_to_ip(self, num: int) -> Optional[str]:
        """Convert integer to IPv4 address"""
        try:
            if num < 0 or num > 0xFFFFFFFF:
                return None
            return socket.inet_ntoa(struct.pack('!I', num))
        except Exception:
            return None
    
    # =========================================================================
    # FEATURE 1: Standard IPv6 Support
    # =========================================================================
    
    def extract_ipv6_standard(self, content: str):
        """
        Extract standard IPv6 addresses.
        Supports: uncompressed, compressed (::), and embedded IPv4.
        
        Test patterns:
        - 2001:0db8:85a3:0000:0000:8a2e:0370:7334 (standard)
        - 2001:db8::8a2e:370:7334 (compressed)
        - ::ffff:192.168.1.1 (embedded IPv4)
        - fe80::1 (link-local)
        """
        # Standard uncompressed IPv6: 8 groups of 4 hex digits
        pattern_full = r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
        for match in re.finditer(pattern_full, content):
            ip = match.group(0)
            if self.validate_ipv6(ip):
                start = max(0, match.start() - 30)
                ctx = content[start:match.end() + 30]
                conf = self.calculate_confidence(ctx, "IPv6 Standard", ip)
                self.add_ipv6_result(ip, "IPv6 Standard (Uncompressed)", ip, conf, ctx)
        
        # Compressed IPv6 with :: shorthand
        pattern_compressed = r'\b(?:[0-9a-fA-F]{1,4}:)*:(?::[0-9a-fA-F]{1,4})*\b'
        for match in re.finditer(pattern_compressed, content):
            ip = match.group(0)
            if self.validate_ipv6(ip):
                start = max(0, match.start() - 30)
                ctx = content[start:match.end() + 30]
                conf = self.calculate_confidence(ctx, "IPv6 Compressed", ip)
                self.add_ipv6_result(ip, "IPv6 Compressed (::)", ip, conf, ctx)
        
        # Mixed :: patterns - more flexible
        pattern_mixed = r'\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,6}::[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5}\b'
        for match in re.finditer(pattern_mixed, content):
            ip = match.group(0)
            if self.validate_ipv6(ip):
                start = max(0, match.start() - 30)
                ctx = content[start:match.end() + 30]
                conf = self.calculate_confidence(ctx, "IPv6 Mixed", ip)
                self.add_ipv6_result(ip, "IPv6 Mixed (::)", ip, conf, ctx)
        
        # IPv6 with embedded IPv4: ::ffff:192.168.1.1
        pattern_embedded = r'::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        for match in re.finditer(pattern_embedded, content, re.IGNORECASE):
            full_match = match.group(0)
            ipv4 = match.group(1)
            if self.validate_ipv6(full_match):
                start = max(0, match.start() - 30)
                ctx = content[start:match.end() + 30]
                conf = self.calculate_confidence(ctx, "IPv6 Embedded IPv4", full_match)
                self.add_ipv6_result(full_match, "IPv6 Embedded IPv4 (::ffff:x.x.x.x)", full_match, conf, ctx)
                # Also extract the IPv4 portion
                if self.validate_ip(ipv4):
                    self.add_result(ipv4, "IPv4 from IPv6-embedded", full_match, conf, ctx)
        
        # Link-local and special patterns
        pattern_special = r'\b(fe80|fc00|fd00|ff00)(?::[0-9a-fA-F]{1,4}){1,7}\b'
        for match in re.finditer(pattern_special, content, re.IGNORECASE):
            ip = match.group(0)
            if self.validate_ipv6(ip):
                start = max(0, match.start() - 30)
                ctx = content[start:match.end() + 30]
                conf = self.calculate_confidence(ctx, "IPv6 Special", ip)
                self.add_ipv6_result(ip, "IPv6 Special (link-local/ULA)", ip, conf, ctx)
    
    # =========================================================================
    # FEATURE 2: Alternative Encodings (Base32, Base58, Base85)
    # =========================================================================
    
    def extract_base32_encoded(self, content: str):
        """
        Extract potential Base32-encoded IPv4 addresses.
        Attempts to decode all possible windows that could decode to 4 bytes.
        Marks results with confidence labels.
        """
        # Base32 encoded 4 bytes would be approximately 7-8 characters
        pattern = r'\b([A-Z2-7]{5,16}=*)\b'
        for match in re.finditer(pattern, content):
            b32_str = match.group(1)
            # Try various substrings that might decode to 4 bytes
            for start in range(len(b32_str)):
                for end in range(start + 5, min(start + 16, len(b32_str) + 1)):
                    substr = b32_str[start:end]
                    # Pad if needed
                    padded = substr + '=' * ((8 - len(substr) % 8) % 8)
                    try:
                        decoded = base64.b32decode(padded)
                        if len(decoded) == 4:
                            octets = list(decoded)
                            ip = '.'.join(map(str, octets))
                            if self.validate_ip(ip):
                                ctx_start = max(0, match.start() - 20)
                                ctx = content[ctx_start:match.end() + 20]
                                # Low confidence for Base32 due to false positive risk
                                conf = self.calculate_confidence(ctx, "Base32", substr) * 0.5
                                self.add_result(ip, "Base32 Encoded (low confidence)", substr, conf, ctx)
                    except Exception:
                        pass
    
    def extract_base58_encoded(self, content: str):
        """
        Extract potential Base58-encoded IPv4/IPv6 addresses.
        Attempts various window sizes for decoding.
        """
        # Base58 chars - no 0, O, I, l
        pattern = r'\b([123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{4,22})\b'
        for match in re.finditer(pattern, content):
            b58_str = match.group(1)
            # Try substrings that might decode to 4 bytes (IPv4) or 16 bytes (IPv6)
            for start in range(len(b58_str)):
                for end in range(start + 4, min(start + 22, len(b58_str) + 1)):
                    substr = b58_str[start:end]
                    try:
                        decoded = base58_decode(substr)
                        if len(decoded) == 4:
                            octets = list(decoded)
                            ip = '.'.join(map(str, octets))
                            if self.validate_ip(ip):
                                ctx_start = max(0, match.start() - 20)
                                ctx = content[ctx_start:match.end() + 20]
                                conf = self.calculate_confidence(ctx, "Base58", substr) * 0.4
                                self.add_result(ip, "Base58 Encoded (low confidence)", substr, conf, ctx)
                        elif len(decoded) == 16:
                            # Potential IPv6
                            try:
                                ip = str(ipaddress.IPv6Address(decoded))
                                ctx_start = max(0, match.start() - 20)
                                ctx = content[ctx_start:match.end() + 20]
                                conf = self.calculate_confidence(ctx, "Base58 IPv6", substr) * 0.4
                                self.add_ipv6_result(ip, "Base58 Encoded IPv6 (low confidence)", substr, conf, ctx)
                            except Exception:
                                pass
                    except Exception:
                        pass
    
    def extract_base85_encoded(self, content: str):
        """
        Extract potential Base85 (ASCII85) encoded IP addresses.
        """
        # Base85 pattern - ASCII85 variant
        pattern = r'\b([0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{4,25})\b'
        for match in re.finditer(pattern, content):
            b85_str = match.group(1)
            for start in range(len(b85_str)):
                for end in range(start + 4, min(start + 25, len(b85_str) + 1)):
                    substr = b85_str[start:end]
                    try:
                        decoded = base85_decode(substr)
                        if len(decoded) == 4:
                            octets = list(decoded)
                            ip = '.'.join(map(str, octets))
                            if self.validate_ip(ip):
                                ctx_start = max(0, match.start() - 20)
                                ctx = content[ctx_start:match.end() + 20]
                                conf = self.calculate_confidence(ctx, "Base85", substr) * 0.4
                                self.add_result(ip, "Base85 Encoded (low confidence)", substr, conf, ctx)
                    except Exception:
                        pass
    
    # =========================================================================
    # FEATURE 3: Custom Separators
    # =========================================================================
    
    def extract_custom_separators(self, content: str):
        """
        Extract IPs with custom separators.
        Supports: spaces, tabs, pipes, semicolons, Unicode variants.
        """
        # Tab-separated
        pattern_tab = r'\b(\d{1,3})\t(\d{1,3})\t(\d{1,3})\t(\d{1,3})\b'
        for match in re.finditer(pattern_tab, content):
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Tab-Separated (X\\tX\\tX\\tX)", match.group(0), 0.6)
            except Exception:
                pass
        
        # Pipe-separated
        pattern_pipe = r'\b(\d{1,3})\|(\d{1,3})\|(\d{1,3})\|(\d{1,3})\b'
        for match in re.finditer(pattern_pipe, content):
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Pipe-Separated (X|X|X|X)", match.group(0), 0.6)
            except Exception:
                pass
        
        # Semicolon-separated
        pattern_semi = r'\b(\d{1,3});(\d{1,3});(\d{1,3});(\d{1,3})\b'
        for match in re.finditer(pattern_semi, content):
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Semicolon-Separated (X;X;X;X)", match.group(0), 0.6)
            except Exception:
                pass
        
        # Unicode dot variants (fullwidth period, middle dot, etc.)
        unicode_dots = ['\uff0e', '\u00b7', '\u2022', '\u2024', '\u22c5']
        for udot in unicode_dots:
            pattern_unicode = rf'\b(\d{{1,3}}){udot}(\d{{1,3}}){udot}(\d{{1,3}}){udot}(\d{{1,3}})\b'
            for match in re.finditer(pattern_unicode, content):
                try:
                    octets = [int(match.group(i)) for i in range(1, 5)]
                    if all(0 <= o <= 255 for o in octets):
                        ip = '.'.join(map(str, octets))
                        self.add_result(ip, f"Unicode Dot Separator ({repr(udot)})", match.group(0), 0.65)
                except Exception:
                    pass
    
    # =========================================================================
    # FEATURE 4: Unicode Escapes
    # =========================================================================
    
    def extract_unicode_escapes(self, content: str):
        """
        Extract IPs written as Unicode escapes.
        Supports \\uXXXX format for both octets and hex bytes.
        Example: \\u00C0\\u00A8\\u0001\\u0001 -> 192.168.1.1
        """
        # Pattern for 4 consecutive unicode escapes representing bytes
        pattern = r'\\u([0-9a-fA-F]{4})\\u([0-9a-fA-F]{4})\\u([0-9a-fA-F]{4})\\u([0-9a-fA-F]{4})'
        for match in re.finditer(pattern, content):
            try:
                # Each \uXXXX represents a byte value
                bytes_list = []
                for i in range(1, 5):
                    val = int(match.group(i), 16)
                    if val <= 255:
                        bytes_list.append(val)
                    else:
                        break
                if len(bytes_list) == 4:
                    ip = '.'.join(map(str, bytes_list))
                    if self.validate_ip(ip):
                        start = max(0, match.start() - 20)
                        ctx = content[start:match.end() + 20]
                        conf = self.calculate_confidence(ctx, "Unicode Escape", match.group(0))
                        self.add_result(ip, "Unicode Escape (\\uXXXX)", match.group(0), conf, ctx)
            except Exception:
                pass
        
        # Also check for \xNN format which is similar
        pattern_hex = r'\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})'
        for match in re.finditer(pattern_hex, content):
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                if self.validate_ip(ip):
                    start = max(0, match.start() - 20)
                    ctx = content[start:match.end() + 20]
                    conf = self.calculate_confidence(ctx, "Hex Escape", match.group(0))
                    self.add_result(ip, "Hex-Escaped (\\xXX)", match.group(0), conf, ctx)
            except Exception:
                pass
    
    # =========================================================================
    # FEATURE 5: Mixed Radix per Octet
    # =========================================================================
    
    def extract_mixed_radix(self, content: str):
        """
        Detect IPs where octets use mixed notations.
        Supports: decimal, hex (0x), octal (0), binary (0b) per octet.
        Example: 192.0xA8.0250.0b00001000 => 192.168.168.8
        """
        # Pattern to match potential mixed-radix octets separated by dots
        # Octet can be: decimal, 0xNN (hex), 0NNN (octal), 0bNNNNNNNN (binary)
        octet_pattern = r'(0x[0-9a-fA-F]{1,2}|0b[01]{1,8}|0[0-7]{1,3}|\d{1,3})'
        full_pattern = rf'\b{octet_pattern}\.{octet_pattern}\.{octet_pattern}\.{octet_pattern}\b'
        
        for match in re.finditer(full_pattern, content):
            try:
                octets = []
                has_non_decimal = False
                
                for i in range(1, 5):
                    octet_str = match.group(i)
                    
                    if octet_str.lower().startswith('0x'):
                        # Hex
                        val = int(octet_str, 16)
                        has_non_decimal = True
                    elif octet_str.lower().startswith('0b'):
                        # Binary
                        val = int(octet_str, 2)
                        has_non_decimal = True
                    elif octet_str.startswith('0') and len(octet_str) > 1:
                        # Octal (0x and 0b already handled above)
                        val = int(octet_str, 8)
                        has_non_decimal = True
                    else:
                        # Decimal
                        val = int(octet_str)
                    
                    if 0 <= val <= 255:
                        octets.append(val)
                    else:
                        break
                
                if len(octets) == 4 and has_non_decimal:
                    ip = '.'.join(map(str, octets))
                    start = max(0, match.start() - 20)
                    ctx = content[start:match.end() + 20]
                    conf = self.calculate_confidence(ctx, "Mixed Radix", match.group(0))
                    self.add_result(ip, "Mixed Radix (decimal/hex/octal/binary)", match.group(0), conf, ctx)
            except Exception:
                pass
    
    # =========================================================================
    # FEATURE 6: Subnet/Range Support
    # =========================================================================
    
    def extract_ip_ranges(self, content: str):
        """
        Recognize IP ranges (e.g., 10.0.0.0-10.0.0.255) and subnets (e.g., 192.168.1.0/24).
        Stores as ranges distinctly from single IPs.
        """
        # IP range pattern: x.x.x.x-y.y.y.y
        range_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        for match in re.finditer(range_pattern, content):
            start_ip = match.group(1)
            end_ip = match.group(2)
            if self.validate_ip(start_ip) and self.validate_ip(end_ip):
                self.ip_ranges.append({
                    'start': start_ip,
                    'end': end_ip,
                    'original': match.group(0),
                    'type': 'range'
                })
                # Also add the start and end IPs individually
                ctx_start = max(0, match.start() - 20)
                ctx = content[ctx_start:match.end() + 20]
                self.add_result(start_ip, "IP Range Start", match.group(0), 0.8, ctx)
                self.add_result(end_ip, "IP Range End", match.group(0), 0.8, ctx)
        
        # Subnet/CIDR pattern: x.x.x.x/nn
        subnet_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})\b'
        for match in re.finditer(subnet_pattern, content):
            ip = match.group(1)
            prefix = int(match.group(2))
            if self.validate_ip(ip) and 0 <= prefix <= 32:
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                    self.subnets.append({
                        'network': str(network),
                        'ip': ip,
                        'prefix': prefix,
                        'original': match.group(0),
                        'type': 'subnet',
                        'num_hosts': network.num_addresses
                    })
                    ctx_start = max(0, match.start() - 20)
                    ctx = content[ctx_start:match.end() + 20]
                    self.add_result(ip, f"CIDR Notation (/{prefix})", match.group(0), 0.9, ctx)
                except Exception:
                    pass
    
    # =========================================================================
    # FEATURE 8: Compression-Wrapped Content
    # =========================================================================
    
    def extract_from_compressed(self, content: bytes):
        """
        Try decompressing content using GZip, zlib, and scan for IPs.
        Handles decompression errors gracefully.
        """
        decompressed_content = None
        
        # Try GZip
        try:
            decompressed_content = gzip.decompress(content)
        except Exception:
            pass
        
        # Try zlib
        if decompressed_content is None:
            try:
                decompressed_content = zlib.decompress(content)
            except Exception:
                pass
        
        # Try zlib with different window bits
        if decompressed_content is None:
            for wbits in [-15, 15, 31, 47]:
                try:
                    decompressed_content = zlib.decompress(content, wbits)
                    break
                except Exception:
                    pass
        
        if decompressed_content:
            try:
                text_content = decompressed_content.decode('utf-8', errors='ignore')
                # Recursively scan decompressed content
                self.extract_standard_ips(text_content)
                self.extract_ipv6_standard(text_content)
                self.extract_hex_direct(text_content)
            except Exception:
                pass
    
    # =========================================================================
    # FEATURE 9: Malformed/Obfuscated Extraction
    # =========================================================================
    
    def extract_obfuscated(self, content: str):
        """
        Identify and heuristically reconstruct obfuscated IPs.
        Detects: char codes, spread strings, math/join ops, JavaScript-like tricks.
        """
        # String.fromCharCode(192, 168, 1, 1) pattern (JavaScript)
        pattern_charcode = r'String\.fromCharCode\s*\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)'
        for match in re.finditer(pattern_charcode, content, re.IGNORECASE):
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    start = max(0, match.start() - 20)
                    ctx = content[start:match.end() + 20]
                    self.add_result(ip, "Obfuscated (String.fromCharCode)", match.group(0), 0.75, ctx)
            except Exception:
                pass
        
        # chr() based assembly: chr(192)+chr(46)+chr(168)+... (Python style)
        pattern_chr = r'chr\s*\(\s*(\d{1,3})\s*\)\s*\+\s*chr\s*\(\s*46\s*\)\s*\+\s*chr\s*\(\s*(\d{1,3})\s*\)\s*\+\s*chr\s*\(\s*46\s*\)\s*\+\s*chr\s*\(\s*(\d{1,3})\s*\)\s*\+\s*chr\s*\(\s*46\s*\)\s*\+\s*chr\s*\(\s*(\d{1,3})\s*\)'
        for match in re.finditer(pattern_chr, content, re.IGNORECASE):
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    start = max(0, match.start() - 20)
                    ctx = content[start:match.end() + 20]
                    self.add_result(ip, "Obfuscated (chr() assembly)", match.group(0), 0.75, ctx)
            except Exception:
                pass
        
        # Simple math obfuscation: (200-8).(100+68).(1).(1) = 192.168.1.1
        pattern_math = r'\(\s*(\d+)\s*[-+*/]\s*(\d+)\s*\)\s*\.\s*\(\s*(\d+)\s*[-+*/]\s*(\d+)\s*\)\s*\.\s*\(\s*(\d+)\s*[-+*/]?\s*(\d*)\s*\)\s*\.\s*\(\s*(\d+)\s*[-+*/]?\s*(\d*)\s*\)'
        for match in re.finditer(pattern_math, content):
            try:
                # This is a simplified pattern, actual parsing would need eval-like logic
                start = max(0, match.start() - 20)
                ctx = content[start:match.end() + 20]
                # Mark as potential obfuscation for manual review
                self.results.append({
                    'ip': 'OBFUSCATED',
                    'format': 'Math Expression (needs manual review)',
                    'original': match.group(0)[:100],
                    'confidence': 0.4,
                    'context': ctx
                })
            except Exception:
                pass
        
        # Array join patterns: [192,168,1,1].join('.')
        pattern_join = r'\[\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\]\s*\.\s*join\s*\(\s*[\'"]\.[\'"]\s*\)'
        for match in re.finditer(pattern_join, content, re.IGNORECASE):
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    start = max(0, match.start() - 20)
                    ctx = content[start:match.end() + 20]
                    self.add_result(ip, "Obfuscated (Array.join)", match.group(0), 0.75, ctx)
            except Exception:
                pass
        
        # Hex char concatenation: "\xC0\xA8\x01\x01"
        pattern_hex_concat = r'["\']((?:\\x[0-9a-fA-F]{2}){4})["\']'
        for match in re.finditer(pattern_hex_concat, content):
            try:
                hex_str = match.group(1)
                hex_bytes = re.findall(r'\\x([0-9a-fA-F]{2})', hex_str)
                if len(hex_bytes) == 4:
                    octets = [int(h, 16) for h in hex_bytes]
                    ip = '.'.join(map(str, octets))
                    start = max(0, match.start() - 20)
                    ctx = content[start:match.end() + 20]
                    self.add_result(ip, "Obfuscated (Hex String)", match.group(0), 0.7, ctx)
            except Exception:
                pass
    
    # =========================================================================
    # FEATURE 12: Hostname#Port:Port Extraction
    # =========================================================================
    
    def extract_hostname_port_patterns(self, content: str):
        """
        Extract patterns like hostname#1234:5678 (e.g., example.com#443:8080).
        Parses hostname and associated port numbers.
        """
        # Pattern: hostname#port:port or hostname#port
        pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})#(\d{1,5})(?::(\d{1,5}))?\b'
        for match in re.finditer(pattern, content):
            hostname = match.group(1)
            port1 = match.group(2)
            port2 = match.group(3)
            
            ports = [int(port1)]
            if port2:
                ports.append(int(port2))
            
            # Validate ports are in valid range
            if all(0 < p <= 65535 for p in ports):
                self.hostnames.append({
                    'hostname': hostname,
                    'ports': ports,
                    'original': match.group(0),
                    'type': 'hostname_port'
                })
                
                # Try to resolve hostname to IP (best effort, may fail offline)
                try:
                    resolved_ip = socket.gethostbyname(hostname)
                    if self.validate_ip(resolved_ip):
                        start = max(0, match.start() - 20)
                        ctx = content[start:match.end() + 20]
                        self.add_result(resolved_ip, f"Resolved from {hostname}", match.group(0), 0.85, ctx)
                except Exception:
                    # Offline or resolution failed - just record the hostname
                    pass
    
    def extract_standard_ips(self, content: str):
        """Extract standard dotted-decimal IPs with confidence scoring."""
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            ip = match.group(0)
            if self.validate_ip(ip):
                start = max(0, match.start() - 30)
                ctx = content[start:match.end() + 30]
                conf = self.calculate_confidence(ctx, "Standard Dotted-Decimal", ip)
                self.add_result(ip, "Standard Dotted-Decimal", ip, conf, ctx)
    
    def extract_hex_direct(self, content: str):
        """Extract direct hex format: 0xd494ad88"""
        pattern = r'\b0x([0-9a-fA-F]{8})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            hex_val = match.group(1)
            try:
                num = int(hex_val, 16)
                ip = self.int_to_ip(num)
                if ip:
                    self.add_result(ip, "Hex Direct (0xXXXXXXXX)", match.group(0))
            except:
                pass
    
    def extract_hex_octets(self, content: str):
        """Extract hex octet format: 0xd4.0x94.0xad.0x88"""
        pattern = r'\b0x([0-9a-fA-F]{1,2})\.0x([0-9a-fA-F]{1,2})\.0x([0-9a-fA-F]{1,2})\.0x([0-9a-fA-F]{1,2})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Hex Octet (0xXX.0xXX.0xXX.0xXX)", match.group(0))
            except:
                pass
    
    def extract_hex_colon_separated(self, content: str):
        """Extract hex colon-separated: d4:94:ad:88"""
        pattern = r'\b([0-9a-fA-F]{2}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Hex Colon-Separated (XX:XX:XX:XX)", match.group(0))
            except:
                pass
    
    def extract_hex_hyphen_separated(self, content: str):
        """Extract hex hyphen-separated: d4-94-ad-88"""
        pattern = r'\b([0-9a-fA-F]{2})-([0-9a-fA-F]{2})-([0-9a-fA-F]{2})-([0-9a-fA-F]{2})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Hex Hyphen-Separated (XX-XX-XX-XX)", match.group(0))
            except:
                pass
    
    def extract_decimal_integer(self, content: str):
        """Extract single decimal integer representation"""
        # Look for standalone large numbers
        pattern = r'\b([0-9]{9,10})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                num = int(match.group(1))
                if 0 <= num <= 0xFFFFFFFF:
                    ip = self.int_to_ip(num)
                    if ip:
                        self.add_result(ip, "Decimal Integer", match.group(0))
            except:
                pass
    
    def extract_octal_octets(self, content: str):
        """Extract octal octet format: 0o324.0o224.0o255.0o210"""
        pattern = r'\b0o([0-7]{1,3})\.0o([0-7]{1,3})\.0o([0-7]{1,3})\.0o([0-7]{1,3})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 8) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Octal Octets (0oXXX.0oXXX.0oXXX.0oXXX)", match.group(0))
            except:
                pass
    
    def extract_octal_unix_style(self, content: str):
        """Extract Unix-style octal: 0324.0224.0255.0210"""
        pattern = r'\b(0[0-7]{3})\.(0[0-7]{3})\.(0[0-7]{3})\.(0[0-7]{3})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 8) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Octal Unix-Style (0XXX.0XXX.0XXX.0XXX)", match.group(0))
            except:
                pass
    
    def extract_binary_octets(self, content: str):
        """Extract binary octet format: 11010100.10010100.10101101.10001000"""
        pattern = r'\b([01]{8})\.([01]{8})\.([01]{8})\.([01]{8})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 2) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Binary Octets (XXXXXXXX.XXXXXXXX.XXXXXXXX.XXXXXXXX)", match.group(0))
            except:
                pass
    
    def extract_binary_continuous(self, content: str):
        """Extract continuous binary: 11010100100101001010110110001000"""
        pattern = r'\b([01]{32})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                binary = match.group(1)
                octets = [int(binary[i:i+8], 2) for i in range(0, 32, 8)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Binary Continuous (32-bit)", match.group(0))
            except:
                pass
    
    def extract_base64(self, content: str):
        """Extract base64 encoded IPs"""
        # Look for base64-like strings (4, 8, 12 chars with optional padding)
        # Use a pattern that captures with or without trailing =
        pattern = r'([A-Za-z0-9+/]{4,12}={0,2})'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                b64_str = match.group(1)
                # Add padding if needed for proper decoding
                padded = b64_str + '=' * ((4 - len(b64_str) % 4) % 4)
                decoded = base64.b64decode(padded)
                if len(decoded) == 4:
                    octets = list(decoded)
                    ip = '.'.join(map(str, octets))
                    if self.validate_ip(ip):
                        self.add_result(ip, "Base64 Encoded", match.group(0))
            except Exception:
                pass
    
    def extract_url_encoded(self, content: str):
        """Extract URL encoded hex bytes: %64%94%ad%88"""
        pattern = r'%([0-9a-fA-F]{2})%([0-9a-fA-F]{2})%([0-9a-fA-F]{2})%([0-9a-fA-F]{2})'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "URL Encoded (%XX%XX%XX%XX)", match.group(0))
            except:
                pass
    
    def extract_html_entities(self, content: str):
        """Extract HTML numeric entities: &#212;&#148;&#173;&#136;"""
        pattern = r'&#(\d{1,3});&#(\d{1,3});&#(\d{1,3});&#(\d{1,3});'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "HTML Entities (&#XXX;)", match.group(0))
            except:
                pass
    
    def extract_reverse_dns(self, content: str):
        """Extract reverse DNS format: 136.173.148.212.in-addr.arpa (FIXED)"""
        pattern = r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.in-addr\.arpa\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                # FIXED: Reverse octets correctly (4,3,2,1 order)
                octets = [match.group(i) for i in range(4, 0, -1)]
                ip = '.'.join(octets)
                if self.validate_ip(ip):
                    self.add_result(ip, "Reverse DNS (in-addr.arpa)", match.group(0))
            except:
                pass
    
    def extract_cidr_notation(self, content: str):
        """Extract CIDR notation: 212.148.173.136/32"""
        pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            ip = match.group(1)
            if self.validate_ip(ip):
                self.add_result(ip, f"CIDR Notation (/{match.group(2)})", match.group(0))
    
    def extract_json_array(self, content: str):
        """Extract JSON arrays: [212, 148, 173, 136]"""
        pattern = r'\[(\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3})\]'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "JSON Array [x,x,x,x]", match.group(0))
            except:
                pass
    
    def extract_little_endian_hex(self, content: str):
        """Extract little-endian hex: 0x88ad94d4"""
        pattern = r'\b0x([0-9a-fA-F]{8})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            hex_val = match.group(1)
            try:
                # Try little-endian interpretation
                num = int(hex_val, 16)
                # Swap byte order
                swapped = struct.unpack('<I', struct.pack('>I', num))[0]
                ip = self.int_to_ip(swapped)
                if ip and ip not in self.found_ips:
                    self.add_result(ip, "Little-Endian Hex", f"{match.group(0)} (swapped)")
            except:
                pass
    
    def extract_port_embedded(self, content: str):
        """Extract port-embedded formats: d494ad88:443"""
        pattern = r'\b([0-9a-fA-F]{8}):(\d{1,5})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            hex_val = match.group(1)
            port = match.group(2)
            try:
                num = int(hex_val, 16)
                ip = self.int_to_ip(num)
                if ip:
                    self.add_result(ip, f"Port-Embedded (:{port})", match.group(0))
            except:
                pass
    
    def extract_scientific_notation(self, content: str):
        """Extract scientific notation: 2.12148173136e+9"""
        pattern = r'\b(\d+\.\d+)e\+(\d+)\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                num = float(match.group(0))
                if num <= 0xFFFFFFFF:
                    ip = self.int_to_ip(int(num))
                    if ip:
                        self.add_result(ip, "Scientific Notation", match.group(0))
            except:
                pass
    
    def extract_hex_raw(self, content: str):
        """Extract raw hex strings (8 chars) that might be IPs"""
        pattern = r'\b([0-9a-fA-F]{8})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            hex_val = match.group(1)
            # Skip if already processed as 0x format
            if f"0x{hex_val}" in content:
                continue
            try:
                num = int(hex_val, 16)
                ip = self.int_to_ip(num)
                if ip and ip not in self.found_ips:
                    self.add_result(ip, "Raw Hex (8 chars)", match.group(0))
            except:
                pass
    
    # NEW FORENSIC & DEFENSIVE FORMATS
    
    def extract_dotted_hex(self, content: str):
        """Extract dotted hex without 0x prefix: d4.94.ad.88"""
        pattern = r'\b([0-9a-fA-F]{2})\.([0-9a-fA-F]{2})\.([0-9a-fA-F]{2})\.([0-9a-fA-F]{2})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Dotted Hex (XX.XX.XX.XX)", match.group(0))
            except:
                pass
    
    def extract_c_array(self, content: str):
        """Extract C-style arrays: {212, 148, 173, 136}"""
        pattern = r'\{(\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3})\}'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "C-Style Array {x,x,x,x}", match.group(0))
            except:
                pass
    
    def extract_hex_escaped(self, content: str):
        """Extract hex-escaped format: \\xd4\\x94\\xad\\x88"""
        pattern = r'\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Hex-Escaped (\\xXX)", match.group(0))
            except:
                pass
    
    def extract_python_bytes(self, content: str):
        """Extract Python bytes format: b'\\xd4\\x94\\xad\\x88'"""
        pattern = r"b['\"]\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})\\x([0-9a-fA-F]{2})['\"]"
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Python Bytes b'\\xXX'", match.group(0))
            except:
                pass
    
    def extract_space_separated_decimal(self, content: str):
        """Extract space-separated decimal: 212 148 173 136"""
        pattern = r'\b(\d{1,3})\s+(\d{1,3})\s+(\d{1,3})\s+(\d{1,3})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Space-Separated Decimal", match.group(0))
            except:
                pass
    
    def extract_comma_separated_decimal(self, content: str):
        """Extract comma-separated decimal: 212,148,173,136"""
        pattern = r'\b(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    # Avoid false positives with JSON arrays
                    if match.group(0) not in content.replace('[', '').replace(']', ''):
                        continue
                    self.add_result(ip, "Comma-Separated Decimal", match.group(0))
            except:
                pass
    
    def extract_underscore_separated(self, content: str):
        """Extract underscore-separated: 212_148_173_136"""
        pattern = r'\b(\d{1,3})_(\d{1,3})_(\d{1,3})_(\d{1,3})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "Underscore-Separated (X_X_X_X)", match.group(0))
            except:
                pass
    
    def extract_dword_decimal(self, content: str):
        """Extract DWORD in decimal with common markers"""
        patterns = [
            r'\bDWORD\s*[=:]\s*(\d{9,10})\b',
            r'\bdword\s*[=:]\s*(\d{9,10})\b',
            r'\bip_addr\s*[=:]\s*(\d{9,10})\b',
            r'\bip_int\s*[=:]\s*(\d{9,10})\b'
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                try:
                    num = int(match.group(1))
                    if 0 <= num <= 0xFFFFFFFF:
                        ip = self.int_to_ip(num)
                        if ip:
                            self.add_result(ip, "DWORD Decimal (labeled)", match.group(0))
                except:
                    pass
    
    def extract_dword_hex(self, content: str):
        """Extract DWORD hex with common markers"""
        patterns = [
            r'\bDWORD\s*[=:]\s*0x([0-9a-fA-F]{8})\b',
            r'\bdword\s*[=:]\s*0x([0-9a-fA-F]{8})\b',
            r'\bip_addr\s*[=:]\s*0x([0-9a-fA-F]{8})\b',
            r'\bip_hex\s*[=:]\s*0x([0-9a-fA-F]{8})\b'
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                try:
                    num = int(match.group(1), 16)
                    ip = self.int_to_ip(num)
                    if ip:
                        self.add_result(ip, "DWORD Hex (labeled)", match.group(0))
                except:
                    pass
    
    def extract_shellcode_format(self, content: str):
        """Extract shellcode push format: push 0x88ad94d4"""
        patterns = [
            r'\bpush\s+0x([0-9a-fA-F]{8})\b',
            r'\bmov\s+\w+,\s*0x([0-9a-fA-F]{8})\b',
            r'\blea\s+\w+,\s*\[0x([0-9a-fA-F]{8})\]'
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                try:
                    num = int(match.group(1), 16)
                    # Try both endianness
                    ip_be = self.int_to_ip(num)
                    if ip_be and ip_be not in self.found_ips:
                        self.add_result(ip_be, "Shellcode Assembly (BE)", match.group(0))
                    # Little-endian
                    swapped = struct.unpack('<I', struct.pack('>I', num))[0]
                    ip_le = self.int_to_ip(swapped)
                    if ip_le and ip_le not in self.found_ips:
                        self.add_result(ip_le, "Shellcode Assembly (LE)", match.group(0))
                except:
                    pass
    
    def extract_powershell_format(self, content: str):
        """Extract PowerShell byte array format: [byte[]](212,148,173,136)"""
        pattern = r'\[byte\[\]\]\s*\((\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3})\)'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "PowerShell [byte[]]", match.group(0))
            except:
                pass
    
    def extract_vba_format(self, content: str):
        """Extract VBA byte array: Array(212, 148, 173, 136)"""
        pattern = r'Array\s*\((\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3}),\s*(\d{1,3})\)'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            try:
                octets = [int(match.group(i)) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    self.add_result(ip, "VBA Array", match.group(0))
            except:
                pass
    
    def extract_struct_sockaddr(self, content: str):
        """Extract sockaddr_in struct format"""
        pattern = r'sin_addr\s*[=:]\s*0x([0-9a-fA-F]{8})'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            try:
                num = int(match.group(1), 16)
                ip = self.int_to_ip(num)
                if ip:
                    self.add_result(ip, "sockaddr_in struct", match.group(0))
            except:
                pass
    
    def extract_registry_format(self, content: str):
        """Extract Windows Registry hex format"""
        pattern = r'\bhex:\s*([0-9a-fA-F]{2}),([0-9a-fA-F]{2}),([0-9a-fA-F]{2}),([0-9a-fA-F]{2})'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Windows Registry hex:", match.group(0))
            except:
                pass
    
    def extract_hex_0x_notation(self, content: str):
        """Extract 0xXX,0xXX,0xXX,0xXX format"""
        pattern = r'\b0x([0-9a-fA-F]{2}),\s*0x([0-9a-fA-F]{2}),\s*0x([0-9a-fA-F]{2}),\s*0x([0-9a-fA-F]{2})\b'
        matches = re.finditer(pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                ip = '.'.join(map(str, octets))
                self.add_result(ip, "Hex Comma 0x,0x,0x,0x", match.group(0))
            except:
                pass
    
    def extract_network_order_int(self, content: str):
        """Extract network order integers with markers"""
        patterns = [
            r'\bhtonl\s*\(\s*0x([0-9a-fA-F]{8})\s*\)',
            r'\bntohl\s*\(\s*0x([0-9a-fA-F]{8})\s*\)',
            r'\binet_addr\s*\(\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"\s*\)'
        ]
        for i, pattern in enumerate(patterns):
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                try:
                    if i < 2:  # htonl/ntohl
                        num = int(match.group(1), 16)
                        ip = self.int_to_ip(num)
                        if ip:
                            func_name = "htonl" if i == 0 else "ntohl"
                            self.add_result(ip, f"{func_name}() format", match.group(0))
                    else:  # inet_addr
                        ip = match.group(1)
                        if self.validate_ip(ip):
                            self.add_result(ip, "inet_addr() format", match.group(0))
                except:
                    pass
    
    def extract_dns_query_format(self, content: str):
        """Extract DNS query format with length prefixes"""
        # Matches patterns like: 03www06google03com00 => www.google.com
        pattern = r'(?:[0-9a-fA-F]{2})([0-9a-fA-F]+)'
        # This is complex, simplified for IP octets in DNS responses
        pattern = r'\x03(\d{1,3})\x03(\d{1,3})\x03(\d{1,3})\x03(\d{1,3})'
        # Hex representation
        hex_pattern = r'([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})([0-9a-fA-F]{2})'
        matches = re.finditer(hex_pattern, content)
        for match in matches:
            try:
                octets = [int(match.group(i), 16) for i in range(1, 5)]
                if all(0 <= o <= 255 for o in octets):
                    ip = '.'.join(map(str, octets))
                    # Only add if looks like a valid IP context
                    if self.validate_ip(ip) and ip not in self.found_ips:
                        self.add_result(ip, "Hex Sequence (potential DNS)", match.group(0))
            except:
                pass
    
    def extract_ipv4_mapped_ipv6(self, content: str):
        """Extract IPv4-mapped IPv6: ::ffff:212.148.173.136"""
        pattern = r'::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            ip = match.group(1)
            if self.validate_ip(ip):
                self.add_result(ip, "IPv4-mapped IPv6", match.group(0))
    
    def extract_xml_element(self, content: str):
        """Extract XML elements: <ip>212.148.173.136</ip>"""
        patterns = [
            r'<ip>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</ip>',
            r'<address>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</address>',
            r'<host>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})</host>',
            r'ip="(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"'
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                ip = match.group(1)
                if self.validate_ip(ip):
                    self.add_result(ip, "XML Element", match.group(0))
    
    def extract_json_string(self, content: str):
        """Extract JSON string values"""
        patterns = [
            r'"ip"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',
            r'"address"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',
            r'"host"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"',
            r'"server"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"'
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                ip = match.group(1)
                if self.validate_ip(ip):
                    self.add_result(ip, "JSON String Value", match.group(0))
    
    def extract_cisco_config(self, content: str):
        """Extract Cisco router config format"""
        pattern = r'ip\s+address\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            ip = match.group(1)
            if self.validate_ip(ip):
                self.add_result(ip, "Cisco Config Format", match.group(0))
    
    def extract_iptables_format(self, content: str):
        """Extract iptables/firewall rule format"""
        patterns = [
            r'-s\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'-d\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'--source\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'--destination\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                ip = match.group(1)
                if self.validate_ip(ip):
                    self.add_result(ip, "iptables/Firewall Rule", match.group(0))
    
    def process_file(self, filepath: str):
        """Process file and extract all IP formats including new enhanced methods."""
        try:
            path = Path(filepath)
            if not path.exists():
                print(f"[ERROR] File not found: {filepath}")
                return
            
            print(f"\n[*] Processing: {filepath}")
            print(f"[*] File size: {path.stat().st_size} bytes\n")
            
            # Read as bytes first for compression detection
            raw_bytes = path.read_bytes()
            
            # Try to read as text
            try:
                content = raw_bytes.decode('utf-8', errors='ignore')
            except Exception:
                content = raw_bytes.hex()
            
            # Run all extraction methods
            print("[*] Scanning for IP address formats...")
            
            # NEW: Feature 8 - Try decompressing and scanning
            print("[*] Checking for compressed content...")
            self.extract_from_compressed(raw_bytes)
            
            # Standard formats
            self.extract_standard_ips(content)
            self.extract_hex_direct(content)
            self.extract_hex_octets(content)
            self.extract_hex_colon_separated(content)
            self.extract_hex_hyphen_separated(content)
            self.extract_decimal_integer(content)
            self.extract_octal_octets(content)
            self.extract_octal_unix_style(content)
            self.extract_binary_octets(content)
            self.extract_binary_continuous(content)
            self.extract_base64(content)
            self.extract_url_encoded(content)
            self.extract_html_entities(content)
            self.extract_reverse_dns(content)
            self.extract_cidr_notation(content)
            self.extract_json_array(content)
            self.extract_little_endian_hex(content)
            self.extract_port_embedded(content)
            self.extract_scientific_notation(content)
            self.extract_hex_raw(content)
            
            # ORIGINAL ADDITIONAL FORMATS
            self.extract_dotted_hex(content)
            self.extract_c_array(content)
            self.extract_hex_escaped(content)
            self.extract_python_bytes(content)
            self.extract_space_separated_decimal(content)
            self.extract_comma_separated_decimal(content)
            self.extract_underscore_separated(content)
            self.extract_dword_decimal(content)
            self.extract_dword_hex(content)
            self.extract_shellcode_format(content)
            self.extract_powershell_format(content)
            self.extract_vba_format(content)
            self.extract_struct_sockaddr(content)
            self.extract_registry_format(content)
            self.extract_hex_0x_notation(content)
            self.extract_network_order_int(content)
            self.extract_dns_query_format(content)
            self.extract_ipv4_mapped_ipv6(content)
            self.extract_xml_element(content)
            self.extract_json_string(content)
            self.extract_cisco_config(content)
            self.extract_iptables_format(content)
            
            # NEW ENHANCED FEATURES
            print("[*] Running enhanced detection methods...")
            
            # Feature 1: IPv6 Support
            self.extract_ipv6_standard(content)
            
            # Feature 2: Alternative Encodings (Base32, Base58, Base85)
            self.extract_base32_encoded(content)
            self.extract_base58_encoded(content)
            self.extract_base85_encoded(content)
            
            # Feature 3: Custom Separators
            self.extract_custom_separators(content)
            
            # Feature 4: Unicode Escapes
            self.extract_unicode_escapes(content)
            
            # Feature 5: Mixed Radix
            self.extract_mixed_radix(content)
            
            # Feature 6: Subnet/Range Support
            self.extract_ip_ranges(content)
            
            # Feature 9: Obfuscated/Malformed
            self.extract_obfuscated(content)
            
            # Feature 12: Hostname#Port patterns
            self.extract_hostname_port_patterns(content)
            
            # Display results
            self.display_results()
            
        except Exception as e:
            print(f"[ERROR] Failed to process file: {e}")
            import traceback
            traceback.print_exc()
    
    def display_results(self):
        """Display extracted IP addresses with confidence scores."""
        if not self.results and not self.ip_ranges and not self.subnets and not self.hostnames:
            print("\n[!] No IP addresses found in file.\n")
            return
        
        print(f"\n{'='*80}")
        print(f"FOUND {len(self.results)} IP ADDRESS(ES)")
        print(f"{'='*80}\n")
        
        # Group by IP for cleaner output
        ip_groups = {}
        for result in self.results:
            ip = result['ip']
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(result)
        
        for ip in sorted(ip_groups.keys()):
            print(f"\n[IP] {ip}")
            print("-" * 80)
            for result in ip_groups[ip]:
                conf = result.get('confidence', 'N/A')
                print(f"  Format: {result['format']}")
                print(f"  Original: {result['original']}")
                print(f"  Confidence: {conf}")
                if result.get('context'):
                    print(f"  Context: {result['context']}")
                print()
        
        # Display IP Ranges (Feature 6)
        if self.ip_ranges:
            print(f"\n{'='*80}")
            print(f"IP RANGES FOUND: {len(self.ip_ranges)}")
            print(f"{'='*80}")
            for r in self.ip_ranges:
                print(f"  {r['start']} - {r['end']} (from: {r['original']})")
        
        # Display Subnets (Feature 6)
        if self.subnets:
            print(f"\n{'='*80}")
            print(f"SUBNETS FOUND: {len(self.subnets)}")
            print(f"{'='*80}")
            for s in self.subnets:
                print(f"  {s['network']} ({s['num_hosts']} hosts) (from: {s['original']})")
        
        # Display Hostnames (Feature 12)
        if self.hostnames:
            print(f"\n{'='*80}")
            print(f"HOSTNAME PATTERNS FOUND: {len(self.hostnames)}")
            print(f"{'='*80}")
            for h in self.hostnames:
                ports_str = ', '.join(map(str, h['ports']))
                print(f"  {h['hostname']} -> Ports: [{ports_str}] (from: {h['original']})")
        
        # Summary
        print(f"\n{'='*80}")
        print(f"SUMMARY: {len(ip_groups)} unique IP(s) found in {len(self.results)} format(s)")
        if self.ip_ranges:
            print(f"         {len(self.ip_ranges)} IP range(s) detected")
        if self.subnets:
            print(f"         {len(self.subnets)} subnet(s) detected")
        if self.hostnames:
            print(f"         {len(self.hostnames)} hostname pattern(s) detected")
        print(f"{'='*80}\n")
        
        # Export option
        export_file = Path("extracted_ips.txt")
        with open(export_file, 'w') as f:
            f.write("# Extracted IP Addresses\n")
            f.write(f"# Total unique IPs: {len(ip_groups)}\n\n")
            for ip in sorted(ip_groups.keys()):
                f.write(f"{ip}\n")
        print(f"[*] Unique IPs saved to: {export_file}\n")
    
    # =========================================================================
    # FEATURE 10: YARA Output
    # =========================================================================
    
    def export_yara(self, output_path: str = "extracted_ips.yar") -> str:
        """
        Export extracted IPs as a YARA rule.
        Creates a rule with string patterns and optional uint32 format.
        
        Args:
            output_path: Path to save the YARA rule file
            
        Returns:
            The YARA rule as a string
        """
        unique_ips = sorted(self.found_ips)
        
        if not unique_ips:
            return ""
        
        yara_lines = [
            'rule Extracted_IP_Addresses',
            '{',
            '    meta:',
            '        description = "IP addresses extracted by IPFormatExtractor"',
            '        author = "IPFormatExtractor v3.0"',
            f'        ip_count = {len(unique_ips)}',
            '',
            '    strings:',
        ]
        
        # Add string patterns for each IP
        for i, ip in enumerate(unique_ips):
            yara_lines.append(f'        $ip_{i} = "{ip}" ascii wide')
        
        # Add uint32 representations (network byte order)
        yara_lines.append('')
        yara_lines.append('    /* uint32 big-endian representations */')
        for i, ip in enumerate(unique_ips):
            try:
                octets = [int(o) for o in ip.split('.')]
                hex_val = '{:02x}{:02x}{:02x}{:02x}'.format(*octets)
                yara_lines.append(f'        $ip_hex_{i} = {{ {hex_val} }}')
            except Exception:
                pass
        
        yara_lines.extend([
            '',
            '    condition:',
            '        any of them',
            '}',
        ])
        
        yara_rule = '\n'.join(yara_lines)
        
        with open(output_path, 'w') as f:
            f.write(yara_rule)
        
        print(f"[*] YARA rule saved to: {output_path}")
        return yara_rule
    
    # =========================================================================
    # FEATURE 11: Export to CSV/JSON
    # =========================================================================
    
    def export_csv(self, output_path: str = "extracted_ips.csv") -> None:
        """
        Export results to CSV format.
        Includes: IP, original format, original value, confidence, context.
        
        Args:
            output_path: Path to save the CSV file
        """
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Format', 'Original', 'Confidence', 'Context', 'Type'])
            
            for result in self.results:
                writer.writerow([
                    result.get('ip', ''),
                    result.get('format', ''),
                    result.get('original', ''),
                    result.get('confidence', ''),
                    result.get('context', ''),
                    result.get('type', 'ipv4')
                ])
            
            # Export ranges
            for r in self.ip_ranges:
                writer.writerow([
                    f"{r['start']}-{r['end']}",
                    'IP Range',
                    r['original'],
                    '0.9',
                    '',
                    'range'
                ])
            
            # Export subnets
            for s in self.subnets:
                writer.writerow([
                    s['network'],
                    'Subnet/CIDR',
                    s['original'],
                    '0.9',
                    f"{s['num_hosts']} hosts",
                    'subnet'
                ])
            
            # Export hostnames
            for h in self.hostnames:
                writer.writerow([
                    h['hostname'],
                    'Hostname#Port',
                    h['original'],
                    '0.8',
                    f"Ports: {h['ports']}",
                    'hostname'
                ])
        
        print(f"[*] CSV export saved to: {output_path}")
    
    def export_json(self, output_path: str = "extracted_ips.json") -> Dict[str, Any]:
        """
        Export results to JSON format.
        Includes: IPs, ranges, subnets, hostnames with all metadata.
        
        Args:
            output_path: Path to save the JSON file
            
        Returns:
            The exported data as a dictionary
        """
        export_data = {
            'metadata': {
                'total_ips': len(self.found_ips),
                'total_ipv6': len(self.found_ipv6),
                'total_results': len(self.results),
                'total_ranges': len(self.ip_ranges),
                'total_subnets': len(self.subnets),
                'total_hostnames': len(self.hostnames),
                'extractor_version': '3.0'
            },
            'ips': list(self.found_ips),
            'ipv6': list(self.found_ipv6),
            'results': self.results,
            'ranges': self.ip_ranges,
            'subnets': self.subnets,
            'hostnames': self.hostnames
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"[*] JSON export saved to: {output_path}")
        return export_data
    
    def filter_by_confidence(self, min_conf: float) -> List[Dict]:
        """
        Filter results by minimum confidence score.
        
        Args:
            min_conf: Minimum confidence threshold (0.0-1.0)
            
        Returns:
            List of results meeting the confidence threshold
        """
        return [r for r in self.results if r.get('confidence', 0) >= min_conf]


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║        Nathan Adie's IP Address Format Extractor & Converter v3.0        ║
║              Malware C2 Infrastructure Analysis Tool                      ║
║                      ENHANCED FORENSIC EDITION                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(
        description='IP Address Format Extractor - Enhanced Edition v3.0'
    )
    parser.add_argument('file', nargs='?', help='File to scan for IP addresses')
    parser.add_argument('--min-confidence', '-c', type=float, default=0.0,
                        help='Minimum confidence threshold (0.0-1.0)')
    parser.add_argument('--export-csv', action='store_true',
                        help='Export results to CSV')
    parser.add_argument('--export-json', action='store_true',
                        help='Export results to JSON')
    parser.add_argument('--export-yara', action='store_true',
                        help='Export results as YARA rule')
    parser.add_argument('--output-dir', '-o', type=str, default='.',
                        help='Output directory for exports')
    
    args = parser.parse_args()
    
    if not args.file:
        print("Usage: python3 ip_format_extractorE.py <file_path> [options]")
        print("\nOptions:")
        print("  -c, --min-confidence FLOAT  Minimum confidence threshold (0.0-1.0)")
        print("  --export-csv                Export results to CSV")
        print("  --export-json               Export results to JSON")
        print("  --export-yara               Export results as YARA rule")
        print("  -o, --output-dir DIR        Output directory for exports")
        print("\nSupported formats (70+ detection patterns):")
        print("  • Standard dotted-decimal ")
        print("  • Hexadecimal (multiple variants)")
        print("  • Decimal integer ")
        print("  • Octal (Python & Unix style)")
        print("  • Binary (dotted & continuous)")
        print("  • Base64/Base32/Base58/Base85 encoded")
        print("  • URL encoded ")
        print("  • HTML entities ")
        print("  • Reverse DNS (FIXED)")
        print("  • CIDR notation ")
        print("  • JSON arrays & strings")
        print("  • C/VBA arrays")
        print("  • PowerShell byte arrays")
        print("  • Assembly/Shellcode formats")
        print("  • Python bytes")
        print("  • Windows Registry hex")
        print("  • sockaddr_in structs")
        print("  • XML elements")
        print("  • Cisco router configs")
        print("  • iptables/firewall rules")
        print("  • IPv4-mapped IPv6")
        print("  • Standard IPv6 (uncompressed, compressed, embedded)")
        print("  • Port-embedded formats")
        print("  • Scientific notation ")
        print("  • Little-endian variants")
        print("  • Hex escaped (\\xXX)")
        print("  • Unicode escapes (\\uXXXX)")
        print("  • Space/comma/underscore separated")
        print("  • Custom separators (tabs, pipes, semicolons, Unicode)")
        print("  • Mixed radix per octet (decimal/hex/octal/binary)")
        print("  • Network order functions (htonl/ntohl)")
        print("  • IP ranges (x.x.x.x-y.y.y.y)")
        print("  • Subnets (x.x.x.x/nn)")
        print("  • Obfuscated IPs (char codes, math ops, joins)")
        print("  • Hostname#Port patterns")
        print("  • Compressed content (gzip, zlib)")
        print("  • And many more!\n")
        sys.exit(1)
    
    extractor = IPFormatExtractor(min_confidence=args.min_confidence)
    extractor.process_file(args.file)
    
    # Handle exports
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if args.export_csv:
        extractor.export_csv(str(output_dir / "extracted_ips.csv"))
    
    if args.export_json:
        extractor.export_json(str(output_dir / "extracted_ips.json"))
    
    if args.export_yara:
        extractor.export_yara(str(output_dir / "extracted_ips.yar"))


if __name__ == "__main__":
    main()
