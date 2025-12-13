#!/bin/bash

import os
import sys
import glob
import math
import base64
import re
import struct
import argparse
import hashlib
import socket
import ipaddress
import zlib
import gzip
import logging
import time
import pickle
import tempfile
import shutil
import sqlite3
import csv
import urllib.request
import urllib.parse
import urllib.error
import mmap
import ctypes
import platform
import email
import email.policy
import quopri
import mimetypes
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Any, Optional
from enum import Enum
from dataclasses import dataclass, field
from email import message_from_bytes, message_from_string
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import threading
import multiprocessing

# Performance optimization imports
try:
    import orjson as json
except ImportError:
    import json

try:
    import xxhash
    USE_XXHASH = True
except ImportError:
    USE_XXHASH = False

try:
    import regex as re_optimized
    USE_REGEX = True
except ImportError:
    USE_REGEX = False

try:
    from numba import jit
    USE_NUMBA = True
except ImportError:
    USE_NUMBA = False
    def jit(*args, **kwargs):
        def decorator(func):
            return func
        return decorator


try:
    import numpy as np
    USE_NUMPY = True
except ImportError:
    USE_NUMPY = False

try:
    import cytoolz
    USE_CYTOOLZ = True
except ImportError:
    USE_CYTOOLZ = False

# Optional compression library imports
try:
    import bz2
    USE_BZ2 = True
except ImportError:
    USE_BZ2 = False

try:
    import lzma
    USE_LZMA = True
except ImportError:
    USE_LZMA = False

try:
    import lz4.frame
    USE_LZ4 = True
except ImportError:
    USE_LZ4 = False

try:
    import zstandard
    USE_ZSTD = True
except ImportError:
    USE_ZSTD = False

try:
    import brotli
    USE_BROTLI = True
except ImportError:
    USE_BROTLI = False

try:
    import py7zr
    USE_7ZIP = True
except ImportError:
    USE_7ZIP = False

try:
    import rarfile
    USE_RAR = True
except ImportError:
    USE_RAR = False

try:
    import zipfile
    USE_ZIP = True
except ImportError:
    USE_ZIP = False

try:
    import tarfile
    USE_TAR = True
except ImportError:
    USE_TAR = False

# Optional compression library imports for enhanced CompressionDetector
try:
    import snappy
    USE_SNAPPY = True
except ImportError:
    USE_SNAPPY = False

try:
    import pyzipper
    USE_PYZIPPER = True
except ImportError:
    USE_PYZIPPER = False

try:
    import magic
    USE_MAGIC = True
except ImportError:
    USE_MAGIC = False

try:
    import imagehash
    from PIL import Image
    import io
    USE_IMAGEHASH = True
except ImportError:
    USE_IMAGEHASH = False

echo "========================================="
echo "SCRIPT 1: Network & Infrastructure Analysis"
echo "Started: $(date)"
echo "========================================="
echo ""

# ============================================================================
# NETWORK SCANNING AND ENUMERATION
# ============================================================================

echo "=== NETWORK SCANNING AND ENUMERATION ==="
echo ""

echo "--- WiFi System Preferences ---"
if [ -f "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist" 2>/dev/null
fi
echo ""

echo "--- Known WiFi Networks ---"
if [ -f "$HOME/Library/Preferences/com.apple.wifi.known-networks.plist" ]; then
    plutil -p "$HOME/Library/Preferences/com.apple.wifi.known-networks.plist" 2>/dev/null
fi
echo ""

echo "--- Preferred Wireless Networks ---"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null
networksetup -listpreferredwirelessnetworks en1 2>/dev/null
echo ""

echo "--- Current WiFi Network ---"
networksetup -getairportnetwork en0 2>/dev/null
networksetup -getairportnetwork en1 2>/dev/null
echo ""

echo "--- WiFi Power Status ---"
networksetup -getairportpower en0 2>/dev/null
networksetup -getairportpower en1 2>/dev/null
echo ""

echo "--- ARP Cache (Connected Devices) ---"
arp -a
echo ""

echo "--- ARP Cache Statistics ---"
arp -a | wc -l
echo ""

echo "--- Routing Table ---"
netstat -rn
echo ""

echo "--- Default Gateway ---"
netstat -rn | grep default
echo ""

echo "--- DHCP Lease Information (en0) ---"
ipconfig getpacket en0 2>/dev/null
echo ""

echo "--- DHCP Lease Information (en1) ---"
ipconfig getpacket en1 2>/dev/null
echo ""

echo "--- Network Interfaces Overview ---"
ifconfig -a
echo ""

echo "--- Active Network Connections ---"
netstat -an
echo ""

echo "--- Established Connections Only ---"
netstat -an | grep ESTABLISHED
echo ""

echo "--- Listening Ports ---"
netstat -an | grep LISTEN
echo ""

echo "--- WiFi Scan Results ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null
echo ""

echo "--- Current WiFi Interface Details ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null
echo ""

echo "--- Network Service Order ---"
networksetup -listnetworkserviceorder
echo ""

echo "--- All Network Services ---"
networksetup -listallnetworkservices
echo ""

echo "--- Hardware Ports ---"
networksetup -listallhardwareports
echo ""

echo "--- System Network Preferences ---"
if [ -f "/Library/Preferences/SystemConfiguration/preferences.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/preferences.plist" 2>/dev/null | head -1000
fi
echo ""

echo "--- Network Interfaces Configuration ---"
if [ -f "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist" 2>/dev/null
fi
echo ""

echo "--- Current Network Location ---"
networksetup -getcurrentlocation
echo ""

echo "--- All Network Locations ---"
networksetup -listlocations
echo ""

echo "--- WiFi Activity Logs (Last 7 Days) ---"
log show --predicate 'subsystem == "com.apple.wifi"' --last 7d --style syslog 2>/dev/null | tail -2000
echo ""

echo "--- Airport Daemon Activity ---"
log show --predicate 'process == "airportd"' --last 7d --style syslog 2>/dev/null | tail -1000
echo ""

echo "--- Network Configuration Changes ---"
log show --predicate 'subsystem == "com.apple.networkd"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- configd Activity ---"
log show --predicate 'process == "configd"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- Network Extension Activity ---"
log show --predicate 'subsystem == "com.apple.networkextension"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Network Probe Requests ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "probe"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- WiFi Roaming Events ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "roam"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Interface State Changes ---"
log show --predicate 'eventMessage CONTAINS "interface" AND eventMessage CONTAINS "state"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- DHCP Activity Logs ---"
log show --predicate 'process == "bootpd" OR eventMessage CONTAINS "DHCP"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Port Scan Detection ---"
log show --predicate 'eventMessage CONTAINS "port" AND eventMessage CONTAINS "scan"' --last 7d 2>/dev/null | tail -200
echo ""

# ============================================================================
# ROUTER/MODEM ATTACK INDICATORS
# ============================================================================

echo "=== ROUTER/MODEM ATTACK INDICATORS ==="
echo ""

echo "--- DNS Configuration ---"
scutil --dns
echo ""

echo "--- DNS Servers Only ---"
scutil --dns | grep "nameserver"
echo ""

echo "--- Hosts File ---"
cat /etc/hosts
echo ""

echo "--- Hosts File Timestamp ---"
stat /etc/hosts 2>/dev/null
echo ""

echo "--- Resolver Directory ---"
ls -la /etc/resolver/ 2>/dev/null
echo ""

echo "--- Resolver Configurations ---"
for resolver in /etc/resolver/*; do
    if [ -f "$resolver" ]; then
        echo "=== $resolver ==="
        cat "$resolver"
        echo ""
    fi
done
echo ""

echo "--- Web Proxy Settings (All Services) ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getwebproxy "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Secure Web Proxy Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getsecurewebproxy "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Auto Proxy Configuration ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getautoproxyurl "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- FTP Proxy Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getftpproxy "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- SOCKS Proxy Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getsocksfirewallproxy "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Streaming Proxy Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getstreamingproxy "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Gopher Proxy Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getgopherproxy "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Proxy Bypass Domains ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getproxybypassdomains "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Passive FTP Mode ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getpassiveftp "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- UPnP/SSDP Related Processes ---"
ps aux | grep -iE "upnp|ssdp" | grep -v grep
echo ""

echo "--- mDNS/Bonjour Processes ---"
ps aux | grep -iE "mdns|bonjour" | grep -v grep
echo ""

echo "--- DNS Responder Processes ---"
ps aux | grep -i "mDNSResponder\|DNSResponder" | grep -v grep
echo ""

echo "--- Network Discovery Services ---"
ps aux | grep -iE "discoveryd|configd" | grep -v grep
echo ""

echo "--- Gateway MAC Address ---"
default_gw=$(netstat -rn | grep default | awk '{print $2}' | head -1)
if [ ! -z "$default_gw" ]; then
    arp -a | grep "$default_gw"
fi
echo ""

echo "--- Router Admin Access Attempts ---"
log show --predicate 'eventMessage CONTAINS "192.168" OR eventMessage CONTAINS "10.0.0" OR eventMessage CONTAINS "172.16"' --last 7d 2>/dev/null | grep -iE "admin|login|auth" | tail -500
echo ""

echo "--- UPnP Port Forwarding Activity ---"
log show --predicate 'eventMessage CONTAINS "UPnP" OR eventMessage CONTAINS "NAT-PMP"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- DNS Hijacking Indicators ---"
log show --predicate 'process == "mDNSResponder" AND eventMessage CONTAINS "redirect"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Unusual DNS Responses ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -iE "nxdomain|refused|servfail" | tail -300
echo ""

# ============================================================================
# PROTOCOL-LEVEL ATTACKS
# ============================================================================

echo "=== PROTOCOL-LEVEL ATTACKS ==="
echo ""

echo "--- WPA/WPA2/WPA3 Security Events ---"
log show --predicate 'subsystem == "com.apple.wifi" AND (eventMessage CONTAINS "WPA" OR eventMessage CONTAINS "security")' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Authentication Failures ---"
log show --predicate 'eventMessage CONTAINS "auth" AND eventMessage CONTAINS "fail"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Deauthentication Events ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "deauth"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Disassociation Events ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "disassoc"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- DHCP Events and Issues ---"
log show --predicate 'process == "bootpd" OR eventMessage CONTAINS "DHCP"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- ARP Activity ---"
log show --predicate 'eventMessage CONTAINS "ARP"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- ARP Spoofing Detection ---"
arp -a | awk '{print $4}' | sort | uniq -d
echo ""

echo "--- Duplicate IP Detection ---"
log show --predicate 'eventMessage CONTAINS "duplicate" OR eventMessage CONTAINS "conflict"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Rogue DHCP Server Detection ---"
log show --predicate 'eventMessage CONTAINS "DHCP" AND eventMessage CONTAINS "server"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- 802.11 Frame Errors ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "error"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Beacon Flood Detection ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "beacon"' --last 1d 2>/dev/null | wc -l
echo ""

echo "--- Management Frame Anomalies ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "management"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Key Reinstallation Indicators ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "key"' --last 7d 2>/dev/null | grep -iE "reinstall|rekey" | tail -200
echo ""

echo "--- WPA Handshake Issues ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "handshake"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- 4-Way Handshake Failures ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "4-way"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- EAPoL Frame Activity ---"
log show --predicate 'eventMessage CONTAINS "EAPoL"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Network Downgrade Attempts ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "downgrade"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Encryption Weakening ---"
log show --predicate 'subsystem == "com.apple.wifi" AND (eventMessage CONTAINS "WEP" OR eventMessage CONTAINS "open" OR eventMessage CONTAINS "none")' --last 7d 2>/dev/null | tail -200
echo ""

# ============================================================================
# CAPTIVE PORTAL EXPLOITATION
# ============================================================================

echo "=== CAPTIVE PORTAL EXPLOITATION ==="
echo ""

echo "--- Captive Portal Detection Activity ---"
log show --predicate 'subsystem CONTAINS "captive" OR eventMessage CONTAINS "portal"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Captive Network Assistant Process ---"
ps aux | grep -i "captivenetworkassistant" | grep -v grep
echo ""

echo "--- Captive Network Assistant Logs ---"
log show --predicate 'process == "CaptiveNetworkAssistant"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Portal Redirect Activity ---"
log show --predicate 'eventMessage CONTAINS "redirect" AND (subsystem CONTAINS "captive" OR process == "CaptiveNetworkAssistant")' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Apple Captive Portal Checks ---"
log show --predicate 'eventMessage CONTAINS "captive.apple.com" OR eventMessage CONTAINS "apple.com/library/test"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- HTTP Captive Detection Requests ---"
log show --predicate 'eventMessage CONTAINS "hotspot" OR eventMessage CONTAINS "success.txt"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Browser Captive Portal Interactions ---"
log show --predicate 'process == "Safari" AND eventMessage CONTAINS "captive"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Captive Portal Authentication ---"
log show --predicate 'eventMessage CONTAINS "captive" AND eventMessage CONTAINS "auth"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Portal Bypass Attempts ---"
log show --predicate 'eventMessage CONTAINS "captive" AND eventMessage CONTAINS "bypass"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Fake Portal Detection ---"
log show --predicate 'eventMessage CONTAINS "captive" AND eventMessage CONTAINS "invalid"' --last 7d 2>/dev/null | tail -200
echo ""

# ============================================================================
# ADVANCED ROUTER COMPROMISE
# ============================================================================

echo "=== ADVANCED ROUTER COMPROMISE ==="
echo ""

echo "--- Gateway Information ---"
netstat -rn | grep default
echo ""

echo "--- Gateway ARP Entry ---"
default_gw=$(netstat -rn | grep default | awk '{print $2}' | head -1)
if [ ! -z "$default_gw" ]; then
    arp -n | grep "$default_gw"
fi
echo ""

echo "--- Connections to Gateway ---"
lsof -i -n -P 2>/dev/null | grep "$default_gw"
echo ""

echo "--- DNS Server Tampering ---"
scutil --dns | grep "nameserver" | grep -vE "8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|208\.67\.222\.222|208\.67\.220\.220"
echo ""

echo "--- Custom DNS Configurations ---"
for service in $(networksetup -listallnetworkservices 2>/dev/null | grep -v "^An asterisk"); do
    dns_servers=$(networksetup -getdnsservers "$service" 2>/dev/null)
    if [ "$dns_servers" != "There aren't any DNS Servers set on"* ]; then
        echo "Service: $service"
        echo "$dns_servers"
        echo ""
    fi
done
echo ""

echo "--- Router Firmware Update Activity ---"
log show --predicate 'eventMessage CONTAINS "firmware" OR eventMessage CONTAINS "upgrade"' --last 30d 2>/dev/null | grep -iE "router|gateway|modem" | tail -200
echo ""

echo "--- TR-069/CWMP Activity ---"
log show --predicate 'eventMessage CONTAINS "TR-069" OR eventMessage CONTAINS "CWMP"' --last 30d 2>/dev/null | tail -200
echo ""

echo "--- UPnP IGD Activity ---"
log show --predicate 'eventMessage CONTAINS "IGD" OR eventMessage CONTAINS "InternetGatewayDevice"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Port Forwarding Rules ---"
lsof -i -n -P 2>/dev/null | awk '{print $9}' | grep -oE ":[0-9]+" | sort -u
echo ""

echo "--- NAT-PMP Activity ---"
log show --predicate 'eventMessage CONTAINS "NAT-PMP"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Router Management Interface Access ---"
log show --predicate 'eventMessage CONTAINS ":80" OR eventMessage CONTAINS ":8080" OR eventMessage CONTAINS ":443"' --last 7d 2>/dev/null | grep -E "192\.168\.|10\.|172\.16\." | tail -500
echo ""

echo "--- SNMP Activity ---"
lsof -i :161 -i :162 2>/dev/null
echo ""

echo "--- Router Configuration Backup ---"
log show --predicate 'eventMessage CONTAINS "backup" OR eventMessage CONTAINS "config"' --last 30d 2>/dev/null | grep -iE "router|gateway" | tail -200
echo ""

# ============================================================================
# NETWORK DIAGNOSTICS
# ============================================================================

echo "=== ADDITIONAL NETWORK DIAGNOSTICS ==="
echo ""

echo "--- All Hardware Ports ---"
networksetup -listallhardwareports
echo ""

echo "--- IPv4 Configuration (All Services) ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "=== Service: $service ==="
        networksetup -getinfo "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- IPv6 Configuration ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        ipv6=$(networksetup -getinfo "$service" 2>/dev/null | grep -i "ipv6")
        if [ ! -z "$ipv6" ]; then
            echo "$ipv6"
        fi
        echo ""
    fi
done
echo ""

echo "--- MTU Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getMTU "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Media Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while IFS= read -r service; do
    if [ "$service" != "An asterisk (*) denotes that a network service is disabled." ]; then
        echo "Service: $service"
        networksetup -getmedia "$service" 2>/dev/null
        echo ""
    fi
done
echo ""

echo "--- Wake on Network Access ---"
networksetup -getwakeonnetworkaccess 2>/dev/null
echo ""

echo "--- Network Service Order ---"
networksetup -listnetworkserviceorder
echo ""

echo "--- DNS Search Domains ---"
scutil --dns | grep "search domain"
echo ""

echo "--- Network Interface Statistics ---"
netstat -i
echo ""

echo "--- Interface Byte Counts ---"
netstat -ib
echo ""

echo "--- Network Protocol Statistics ---"
netstat -s
echo ""

echo "--- Multicast Group Memberships ---"
netstat -g
echo ""

echo "--- IPv6 Neighbor Discovery ---"
ndp -a 2>/dev/null
echo ""

echo "--- IPv6 Routing Table ---"
netstat -rn -f inet6
echo ""

echo "--- Network Time Synchronization ---"
systemsetup -getusingnetworktime 2>/dev/null
systemsetup -getnetworktimeserver 2>/dev/null
echo ""

echo "--- NTP Activity ---"
log show --predicate 'process == "ntpd" OR eventMessage CONTAINS "NTP"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Reachability ---"
log show --predicate 'subsystem == "com.apple.network.reachability"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Network Quality of Service ---"
log show --predicate 'subsystem CONTAINS "qos" OR eventMessage CONTAINS "QoS"' --last 7d 2>/dev/null | tail -300
echo ""

echo ""
echo "========================================="
echo "Script 1 Complete: $(date)"
echo "========================================="
echo ""

echo "========================================="
echo "SCRIPT 2: Evasion & Anti-Forensics Analysis"
echo "Started: $(date)"
echo "========================================="
echo ""

# ============================================================================
# LIVING OFF THE LAND
# ============================================================================

echo "=== LIVING OFF THE LAND ==="
echo ""

echo "--- CoreWLAN Framework Usage ---"
lsof 2>/dev/null | grep -i corewlan
echo ""

echo "--- CoreWLAN Framework Files ---"
ls -laR /System/Library/Frameworks/CoreWLAN.framework/ 2>/dev/null | head -100
echo ""

echo "--- NetworkExtension Framework Usage ---"
lsof 2>/dev/null | grep -i networkextension
echo ""

echo "--- NetworkExtension Framework Files ---"
ls -laR /System/Library/Frameworks/NetworkExtension.framework/ 2>/dev/null | head -100
echo ""

echo "--- CoreLocation Framework Usage ---"
lsof 2>/dev/null | grep -i corelocation
echo ""

echo "--- SystemConfiguration Framework Usage ---"
lsof 2>/dev/null | grep -i systemconfiguration
echo ""

echo "--- configd Usage ---"
lsof 2>/dev/null | grep configd | head -200
echo ""

echo "--- configd Process Details ---"
ps aux | grep configd | grep -v grep
echo ""

echo "--- Network Framework Usage ---"
lsof 2>/dev/null | grep -i "network.framework"
echo ""

echo "--- Network Tools in Active Use ---"
ps aux | grep -iE "networksetup|scutil|ifconfig|airport|ipconfig|route" | grep -v grep
echo ""

echo "--- Airport Utility Usage ---"
lsof 2>/dev/null | grep -i airport
echo ""

echo "--- Airport Binary ---"
ls -la /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport 2>/dev/null
echo ""

echo "--- System Network Binaries (usr/bin) ---"
ls -la /usr/bin/ 2>/dev/null | grep -iE "net|ip|route|arp|dns|ping|trace"
echo ""

echo "--- System Network Binaries (usr/sbin) ---"
ls -la /usr/sbin/ 2>/dev/null | grep -iE "net|ip|route|arp|dns|ping|trace"
echo ""

echo "--- Recently Executed Network Commands ---"
log show --predicate 'process == "networksetup" OR process == "scutil" OR process == "ifconfig"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Network Utility Processes ---"
ps aux | grep -iE "netstat|nettop|lsof|tcpdump|wireshark|nmap" | grep -v grep
echo ""

echo "--- System Extensions ---"
systemextensionsctl list 2>/dev/null
echo ""

echo "--- Network Extension Processes ---"
ps aux | grep -i "nesession\|NEAgent" | grep -v grep
echo ""

echo "--- VPN Framework Usage ---"
lsof 2>/dev/null | grep -iE "vpn|ipsec"
echo ""

echo "--- Packet Capture Capabilities ---"
ls -la /dev/bpf* 2>/dev/null
echo ""

echo "--- BPF Device Access ---"
lsof /dev/bpf* 2>/dev/null
echo ""

echo "--- Native Network Diagnostics Usage ---"
log show --predicate 'process == "ping" OR process == "traceroute" OR process == "nslookup" OR process == "dig" OR process == "host"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Preference APIs ---"
log show --predicate 'subsystem == "com.apple.preferences.network"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Built-in WiFi Debugging ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "debug"' --last 7d 2>/dev/null | tail -300
echo ""

# ============================================================================
# GEOFENCING
# ============================================================================

echo "=== GEOFENCING ==="
echo ""

echo "--- Location Services Status ---"
ps aux | grep -i "locationd" | grep -v grep
echo ""

echo "--- Location Services Logs ---"
log show --predicate 'subsystem == "com.apple.locationd"' --last 7d --style syslog 2>/dev/null | tail -1500
echo ""

echo "--- CoreLocation Daemon Activity ---"
log show --predicate 'process == "locationd"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- WiFi-Based Location Requests ---"
log show --predicate 'subsystem == "com.apple.locationd" AND eventMessage CONTAINS "wifi"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Geographic Region Monitoring ---"
log show --predicate 'eventMessage CONTAINS "region" OR eventMessage CONTAINS "geofence"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Routine Location Data ---"
if [ -d "$HOME/Library/Caches/com.apple.routined" ]; then
    ls -laR "$HOME/Library/Caches/com.apple.routined" 2>/dev/null
fi
echo ""

echo "--- Significant Location Changes ---"
log show --predicate 'subsystem == "com.apple.routined"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- Location Authorization Changes ---"
log show --predicate 'eventMessage CONTAINS "authorization" AND subsystem == "com.apple.locationd"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Geographic Preferences ---"
if [ -f "$HOME/Library/Preferences/com.apple.preferences.timezone.plist" ]; then
    plutil -p "$HOME/Library/Preferences/com.apple.preferences.timezone.plist" 2>/dev/null
fi
echo ""

echo "--- Time Zone Settings ---"
systemsetup -gettimezone 2>/dev/null
echo ""

echo "--- Time Zone Changes ---"
log show --predicate 'eventMessage CONTAINS "timezone"' --last 30d 2>/dev/null | tail -200
echo ""

echo "--- AirPort Environment Profile ---"
system_profiler SPAirPortDataType
echo ""

echo "--- WiFi Country Code ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null | grep -i "country"
echo ""

echo "--- Network Time Settings ---"
systemsetup -getusingnetworktime 2>/dev/null
systemsetup -getnetworktimeserver 2>/dev/null
echo ""

echo "--- Find My Network Activity ---"
log show --predicate 'subsystem CONTAINS "findmy"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Find My Location Beacons ---"
log show --predicate 'subsystem CONTAINS "findmy" AND eventMessage CONTAINS "beacon"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Location-Based Alerts ---"
log show --predicate 'eventMessage CONTAINS "location" AND eventMessage CONTAINS "alert"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- App Location Permissions ---"
log show --predicate 'subsystem == "com.apple.locationd" AND eventMessage CONTAINS "app"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Background Location Usage ---"
log show --predicate 'subsystem == "com.apple.locationd" AND eventMessage CONTAINS "background"' --last 7d 2>/dev/null | tail -300
echo ""

# ============================================================================
# SELF-DESTRUCTION/ANTI-FORENSICS
# ============================================================================

echo "=== SELF-DESTRUCTION/ANTI-FORENSICS ==="
echo ""

echo "--- File Deletion Events (7 Days) ---"
log show --predicate 'eventMessage CONTAINS "delete" OR eventMessage CONTAINS "remove" OR eventMessage CONTAINS "unlink"' --last 7d 2>/dev/null | tail -1500
echo ""

echo "--- Clear/Wipe Events ---"
log show --predicate 'eventMessage CONTAINS "clear" OR eventMessage CONTAINS "wipe" OR eventMessage CONTAINS "erase"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- Trash/Removal Activity ---"
log show --predicate 'eventMessage CONTAINS "trash" OR eventMessage CONTAINS "rm " OR eventMessage CONTAINS "rmdir"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- File System Modifications ---"
log show --predicate 'subsystem == "com.apple.filesystemui" OR subsystem == "com.apple.fskit"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- Log Rotation Status ---"
ls -la /var/log/*.gz /var/log/*.old /var/log/*.bz2 2>/dev/null
echo ""

echo "--- Log File Timestamps ---"
ls -lat /var/log/ 2>/dev/null | head -50
echo ""

echo "--- Recent Log File Modifications (7 Days) ---"
find /var/log -type f -mtime -7 -exec ls -la {} \; 2>/dev/null
echo ""

echo "--- System Log Files ---"
ls -la /var/log/system.log* 2>/dev/null
echo ""

echo "--- ASL Database ---"
ls -la /var/log/asl/ 2>/dev/null | head -50
echo ""

echo "--- Diagnostic Messages ---"
ls -laR /var/log/DiagnosticMessages/ 2>/dev/null | head -500
echo ""

echo "--- Cleaned/Empty Caches ---"
find ~/Library/Caches -type d -empty 2>/dev/null | head -100
echo ""

echo "--- Recent Cache Deletions ---"
log show --predicate 'eventMessage CONTAINS "cache" AND (eventMessage CONTAINS "delete" OR eventMessage CONTAINS "clear")' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Temporary File Cleanup ---"
ls -la /tmp/ 2>/dev/null
ls -la /var/tmp/ 2>/dev/null
echo ""

echo "--- Temporary Directory Timestamps ---"
stat /tmp /var/tmp 2>/dev/null
echo ""

echo "--- Secure Deletion Activity ---"
log show --predicate 'eventMessage CONTAINS "srm" OR eventMessage CONTAINS "secure delete"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Shredding/Overwrite Activity ---"
log show --predicate 'eventMessage CONTAINS "shred" OR eventMessage CONTAINS "overwrite"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Privacy Preference Changes ---"
log show --predicate 'subsystem == "com.apple.privacy" OR eventMessage CONTAINS "privacy"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Network Configuration Resets ---"
log show --predicate 'eventMessage CONTAINS "reset" AND eventMessage CONTAINS "network"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- WiFi Configuration Deletions ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "delete"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- Keychain Modifications ---"
log show --predicate 'process == "securityd" AND eventMessage CONTAINS "delete"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Configuration Profile Removals ---"
log show --predicate 'eventMessage CONTAINS "profile" AND eventMessage CONTAINS "remove"' --last 30d 2>/dev/null | tail -200
echo ""

echo "--- Anti-Forensics Tool Detection ---"
ps aux | grep -iE "ccleaner|bleachbit|eraser|antiforensics" | grep -v grep
echo ""

echo "--- Log Sanitization ---"
log show --predicate 'eventMessage CONTAINS "sanitize" OR eventMessage CONTAINS "redact"' --last 7d 2>/dev/null | tail -200
echo ""

# ============================================================================
# CREDENTIAL HARVESTING
# ============================================================================

echo "=== CREDENTIAL HARVESTING ==="
echo ""

echo "--- WiFi Keychain Entries ---"
security dump-keychain 2>/dev/null | grep -iE "wifi|airport|802\.1x|wpa|eap" | head -500
echo ""

echo "--- AirPort Passwords ---"
security dump-keychain 2>/dev/null | grep -B3 -A3 -i "airport" | head -200
echo ""

echo "--- 802.1X Credentials ---"
security dump-keychain 2>/dev/null | grep -B3 -A3 -iE "802\.1x|eap" | head -200
echo ""

echo "--- WPA Pre-Shared Keys ---"
security dump-keychain 2>/dev/null | grep -B3 -A3 -i "wpa" | head -200
echo ""

echo "--- System Keychain WiFi Entries ---"
security dump-keychain /Library/Keychains/System.keychain 2>/dev/null | grep -iE "wifi|airport|network" | head -500
echo ""

echo "--- Network Password Items ---"
security dump-keychain 2>/dev/null | grep -i "network password" | head -200
echo ""

echo "--- WiFi Preference Files ---"
find ~/Library/Preferences -name "*wifi*" -o -name "*airport*" -o -name "*network*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- System WiFi Preferences ---"
find /Library/Preferences -name "*wifi*" -o -name "*airport*" -o -name "*network*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- SystemConfiguration Credentials ---"
ls -la /Library/Preferences/SystemConfiguration/ 2>/dev/null
echo ""

echo "--- Network Interfaces Plist ---"
if [ -f "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist" 2>/dev/null
fi
echo ""

echo "--- 802.1X Profiles ---"
find /Library/Preferences/SystemConfiguration -name "*802*" -o -name "*eap*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- EAPoL Client Configuration ---"
if [ -f "/Library/Preferences/SystemConfiguration/com.apple.eapolclient.configuration.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/com.apple.eapolclient.configuration.plist" 2>/dev/null
fi
echo ""

echo "--- VPN Credentials ---"
security dump-keychain 2>/dev/null | grep -iE "vpn|ipsec|l2tp|pptp|ikev2" | head -300
echo ""

echo "--- VPN Configurations ---"
find /Library/Preferences/SystemConfiguration -name "*vpn*" -o -name "*ipsec*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Proxy Authentication Credentials ---"
security dump-keychain 2>/dev/null | grep -i "proxy" | head -200
echo ""

echo "--- Stored Network Passwords ---"
security dump-keychain 2>/dev/null | grep -i "password" | grep -iE "network|wifi|internet" | head -500
echo ""

echo "--- Certificate Authorities ---"
security find-certificate -a /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -E "labl|issu" | head -300
echo ""

echo "--- User Installed Certificates ---"
security find-certificate -a ~/Library/Keychains/login.keychain-db 2>/dev/null | grep -E "labl|issu|subj" | head -500
echo ""

echo "--- System Keychain Certificates ---"
security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep -E "labl|issu|subj" | head -500
echo ""

echo "--- Identity Preferences ---"
if [ -f "$HOME/Library/Preferences/com.apple.security.identities.plist" ]; then
    plutil -p "$HOME/Library/Preferences/com.apple.security.identities.plist" 2>/dev/null
fi
echo ""

echo "--- Keychain Access Logs ---"
log show --predicate 'process == "securityd"' --last 7d 2>/dev/null | grep -iE "wifi|network|password" | tail -500
echo ""

echo "--- Credential Access Events ---"
log show --predicate 'eventMessage CONTAINS "credential" OR eventMessage CONTAINS "password"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Security Agent Activity ---"
log show --predicate 'process == "SecurityAgent"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Authentication Attempts ---"
log show --predicate 'eventMessage CONTAINS "authentication"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Keychain Item Access ---"
log show --predicate 'subsystem == "com.apple.securityd" AND eventMessage CONTAINS "access"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Browser Saved Passwords ---"
find ~/Library/Application\ Support -name "*Login*" -o -name "*Password*" -o -name "*Credential*" 2>/dev/null | head -100
echo ""

echo "--- Password Manager Databases ---"
find ~/Library -name "*password*" -o -name "*credential*" -o -name "*vault*" 2>/dev/null | grep -v Cache | head -100
echo ""

# ============================================================================
# ANTI-ANALYSIS AND DETECTION EVASION
# ============================================================================

echo "=== ANTI-ANALYSIS AND DETECTION EVASION ==="
echo ""

echo "--- Virtual Machine Detection ---"
system_profiler SPHardwareDataType | grep -iE "virtual|vmware|parallels|virtualbox|qemu|kvm"
echo ""

echo "--- Hardware Model ---"
system_profiler SPHardwareDataType | grep "Model"
echo ""

echo "--- Serial Number Check ---"
system_profiler SPHardwareDataType | grep "Serial Number"
echo ""

echo "--- Virtualization Indicators in IO Registry ---"
ioreg -l | grep -iE "virtual|vmware|parallels|vbox|qemu" | head -100
echo ""

echo "--- Hypervisor Detection ---"
sysctl -a | grep -i hypervisor
echo ""

echo "--- Sandbox Environment Detection ---"
ps aux | grep -iE "sandbox|container|vm" | grep -v grep
echo ""

echo "--- Security Tool Detection ---"
ps aux | grep -iE "little.?snitch|lulu|blockblock|knockknock|kextviewer|taskexplorer|oversight" | grep -v grep
echo ""

echo "--- Security Software Processes ---"
ps aux | grep -iE "antivirus|firewall|security|protection" | grep -v grep
echo ""

echo "--- Packet Capture Tools ---"
ps aux | grep -iE "tcpdump|wireshark|tshark|sniff|pcap|ettercap" | grep -v grep
echo ""

echo "--- Network Monitoring Tools ---"
ps aux | grep -iE "charles|burp|mitmproxy|fiddler|proxyman" | grep -v grep
echo ""

echo "--- IDS/IPS Detection ---"
ps aux | grep -iE "snort|suricata|bro|zeek|ids|ips" | grep -v grep
echo ""

echo "--- Debugging Tools ---"
ps aux | grep -iE "lldb|gdb|dtrace|dtruss|fs_usage|instruments|sample" | grep -v grep
echo ""

echo "--- Forensic Tools ---"
ps aux | grep -iE "volatility|autopsy|sleuthkit|foremost|photorec|testdisk" | grep -v grep
echo ""

echo "--- System Tracing ---"
ps aux | grep -iE "trace|dtrace|ktrace" | grep -v grep
echo ""

echo "--- File System Monitoring ---"
ps aux | grep -iE "fs_usage|opensnoop|fseventer" | grep -v grep
echo ""

echo "--- Network Packet Inspection ---"
lsof /dev/bpf* 2>/dev/null
echo ""

echo "--- Promiscuous Mode Detection ---"
ifconfig | grep -i promisc
echo ""

echo "--- Honeypot Network SSIDs ---"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null | grep -iE "honey|trap|canary|decoy|fake|test"
echo ""

echo "--- Security Vendor Networks ---"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null | grep -iE "sophos|mcafee|symantec|kaspersky|trend|crowdstrike|palo.?alto|fortinet|checkpoint|fireeye"
echo ""

echo "--- Analysis Lab Networks ---"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null | grep -iE "lab|research|analysis|sandbox|malware"
echo ""

echo "--- Unusual MAC Addresses in ARP ---"
arp -a | grep -iE "00:00:00|ff:ff:ff|00:0c:29|00:1c:14|00:50:56|08:00:27"
echo ""

echo "--- Known Vendor OUIs (VM Detection) ---"
arp -a | grep -iE "VMware|VirtualBox|Parallels|QEMU"
echo ""

echo "--- Debugging Enabled ---"
log show --predicate 'eventMessage CONTAINS "debug" AND eventMessage CONTAINS "enable"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Developer Mode ---"
DevToolsSecurity -status 2>/dev/null
echo ""

echo "--- System Integrity Protection Status ---"
csrutil status 2>/dev/null
echo ""

echo "--- Secure Boot Status ---"
if [ -x /usr/sbin/nvram ]; then
    nvram -p | grep -i "secure"
fi
echo ""

echo "--- Analysis Environment Indicators ---"
log show --predicate 'eventMessage CONTAINS "analysis" OR eventMessage CONTAINS "forensic"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Timing Analysis ---"
sysctl kern.boottime
uptime
echo ""

echo "--- CPU Throttling/Emulation ---"
sysctl -a | grep cpu | head -50
echo ""

echo "--- Network Delay Indicators ---"
log show --predicate 'eventMessage CONTAINS "latency" OR eventMessage CONTAINS "delay"' --last 7d 2>/dev/null | tail -200
echo ""

echo ""
echo "========================================="
echo "Script 2 Complete: $(date)"
echo "========================================="
echo ""

echo "========================================="
echo "SCRIPT 3: Traffic & Communication Analysis"
echo "Started: $(date)"
echo "========================================="
echo ""

# ============================================================================
# NETWORK TRAFFIC EVASION AND OBFUSCATION
# ============================================================================

echo "=== NETWORK TRAFFIC EVASION AND OBFUSCATION ==="
echo ""

echo "--- All Network Connections ---"
lsof -i -n -P 2>/dev/null
echo ""

echo "--- Established TCP Connections ---"
lsof -i TCP -n -P 2>/dev/null | grep ESTABLISHED
echo ""

echo "--- Established UDP Connections ---"
lsof -i UDP -n -P 2>/dev/null
echo ""

echo "--- Listening Services ---"
lsof -i -n -P 2>/dev/null | grep LISTEN
echo ""

echo "--- Foreign Address Summary ---"
lsof -i -n -P 2>/dev/null | awk '{print $9}' | grep -E "^[0-9]" | cut -d: -f1 | sort | uniq -c | sort -rn
echo ""

echo "--- High Port Connections ---"
lsof -i -n -P 2>/dev/null | grep -E ":[8-9][0-9]{3}|:[1-6][0-9]{4}"
echo ""

echo "--- VPN Processes ---"
ps aux | grep -iE "vpn|openvpn|wireguard|nordvpn|expressvpn" | grep -v grep
echo ""

echo "--- Tunnel Processes ---"
ps aux | grep -iE "tunnel|ssh.*-[DLR]|autossh|stunnel" | grep -v grep
echo ""

echo "--- Tor Processes ---"
ps aux | grep -iE "^tor |torrc|/tor$" | grep -v grep
echo ""

echo "--- Tor Connections ---"
lsof -i :9050 -i :9051 -i :9150 2>/dev/null
echo ""

echo "--- I2P Processes ---"
ps aux | grep -i "i2p" | grep -v grep
echo ""

echo "--- Proxy Processes ---"
ps aux | grep -iE "proxy|squid|privoxy|tinyproxy|polipo" | grep -v grep
echo ""

echo "--- SOCKS Proxy Activity ---"
lsof -i -n -P 2>/dev/null | grep -E ":1080|:1081|:9050"
echo ""

echo "--- Packet Filter Status ---"
pfctl -s info 2>/dev/null
echo ""

echo "--- Packet Filter Rules ---"
pfctl -s rules 2>/dev/null
echo ""

echo "--- Packet Filter NAT Rules ---"
pfctl -s nat 2>/dev/null
echo ""

echo "--- Packet Filter States ---"
pfctl -s states 2>/dev/null | head -200
echo ""

echo "--- PF Configuration File ---"
if [ -f "/etc/pf.conf" ]; then
    cat /etc/pf.conf
fi
echo ""

echo "--- Application Firewall Status ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null
echo ""

echo "--- Application Firewall Applications ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null
echo ""

echo "--- Application Firewall Logging ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode 2>/dev/null
echo ""

echo "--- Stealth Mode ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null
echo ""

echo "--- DNS Activity (7 Days) ---"
log show --predicate 'process == "mDNSResponder" OR process == "DNSResponder"' --last 7d 2>/dev/null | tail -2000
echo ""

echo "--- DNS-over-HTTPS Activity ---"
log show --predicate 'eventMessage CONTAINS "DoH" OR eventMessage CONTAINS "dns-over-https"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- DNS-over-TLS Activity ---"
log show --predicate 'eventMessage CONTAINS "DoT" OR eventMessage CONTAINS "dns-over-tls"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Cloudflare DNS Usage ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -E "1\.1\.1\.1|1\.0\.0\.1" | tail -200
echo ""

echo "--- Quad9 DNS Usage ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -E "9\.9\.9\.9" | tail -200
echo ""

echo "--- Google DNS Usage ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -E "8\.8\.8\.8|8\.8\.4\.4" | tail -200
echo ""

echo "--- Unusual DNS Queries ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -iE "\.onion|\.i2p|long.*query" | tail -500
echo ""

echo "--- DNS TXT Record Queries ---"
log show --predicate 'process == "mDNSResponder" AND eventMessage CONTAINS "TXT"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Extension Processes ---"
ps aux | grep -i "nesession\|neagent" | grep -v grep
echo ""

echo "--- Network Extension Logs ---"
log show --predicate 'subsystem == "com.apple.networkextension"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- VPN Configuration Files ---"
ls -la /Library/Preferences/SystemConfiguration/ 2>/dev/null | grep -i vpn
find /Library/Preferences/SystemConfiguration -name "*vpn*" -o -name "*VPN*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- IPSec Configuration ---"
if [ -f "/etc/ipsec.conf" ]; then
    cat /etc/ipsec.conf
fi
echo ""

echo "--- IPSec Activity ---"
log show --predicate 'eventMessage CONTAINS "IPSec" OR eventMessage CONTAINS "IKE"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Kernel Extensions ---"
kextstat | grep -iE "network|vpn|tunnel|tun|tap|pf"
echo ""

echo "--- TUN/TAP Interfaces ---"
ifconfig -a | grep -A5 -iE "tun|tap|utun"
echo ""

echo "--- UTUN Interface Details ---"
for iface in $(ifconfig -a | grep -o "utun[0-9]*"); do
    echo "=== $iface ==="
    ifconfig $iface
    echo ""
done
echo ""

echo "--- Protocol Mimicry Detection ---"
lsof -i -n -P 2>/dev/null | grep -E ":80|:443" | grep -v -E "Safari|Chrome|Firefox|curl|wget"
echo ""

echo "--- Encrypted Traffic Endpoints ---"
lsof -i -n -P 2>/dev/null | grep ":443"
echo ""

echo "--- Steganography Tools ---"
ps aux | grep -iE "steghide|outguess|stegano|covert" | grep -v grep
echo ""

echo "--- Traffic Shaping ---"
log show --predicate 'eventMessage CONTAINS "traffic shaping" OR eventMessage CONTAINS "bandwidth"' --last 7d 2>/dev/null | tail -200
echo ""

# ============================================================================
# COVERT CHANNELS AND EXFILTRATION
# ============================================================================

echo "=== COVERT CHANNELS AND EXFILTRATION ==="
echo ""

echo "--- Unusual Outbound Connections ---"
lsof -i -n -P 2>/dev/null | grep -v "localhost\|127\.0\.0\.1\|::1" | grep ESTABLISHED
echo ""

echo "--- Data Transfer by Process ---"
lsof -i -n -P 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -30
echo ""

echo "--- High Volume Network Processes ---"
nettop -P -L 1 2>/dev/null | head -100
echo ""

echo "--- DNS Tunneling Indicators ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -E "TXT|NULL|CNAME|MX" | tail -500
echo ""

echo "--- Long DNS Queries ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -E ".{50,}" | tail -300
echo ""

echo "--- High Frequency DNS Queries ---"
log show --predicate 'process == "mDNSResponder"' --last 1d 2>/dev/null | awk '{print $NF}' | sort | uniq -c | sort -rn | head -50
echo ""

echo "--- ICMP Traffic ---"
ps aux | grep -iE "ping|icmp" | grep -v grep
echo ""

echo "--- ICMP Tunneling Tools ---"
ps aux | grep -iE "icmptunnel|ptunnel|pingtunnel" | grep -v grep
echo ""

echo "--- Connections to Cloud Services ---"
lsof -i -n -P 2>/dev/null | grep -iE "amazonaws|aws|cloudflare|azure|google|dropbox|box\.com"
echo ""

echo "--- Connections to CDN Services ---"
lsof -i -n -P 2>/dev/null | grep -iE "cdn|cloudfront|akamai|fastly"
echo ""

echo "--- Connections to File Hosting ---"
lsof -i -n -P 2>/dev/null | grep -iE "mega\.nz|wetransfer|sendspace|mediafire"
echo ""

echo "--- Unusual Destination Ports ---"
lsof -i -n -P 2>/dev/null | grep -vE ":80|:443|:22|:53|:25|:587|:993|:995|:110|:143" | grep -v LISTEN
echo ""

echo "--- Network Interface Byte Counts ---"
netstat -ib
echo ""

echo "--- Interface Statistics ---"
for iface in $(ifconfig -a | grep -o "^[a-z0-9]*:" | tr -d ":"); do
    echo "=== $iface ==="
    netstat -I $iface -b 2>/dev/null
    echo ""
done
echo ""

echo "--- Network Protocol Statistics ---"
netstat -s
echo ""

echo "--- Large Data Transfers ---"
log show --predicate 'eventMessage CONTAINS "bytes" OR eventMessage CONTAINS "transfer"' --last 7d 2>/dev/null | grep -E "[0-9]{6,}" | tail -300
echo ""

echo "--- Exfiltration Time Patterns ---"
log show --predicate 'subsystem == "com.apple.networkd"' --last 7d 2>/dev/null | awk '{print $1, $2}' | cut -d: -f1 | sort | uniq -c
echo ""

echo "--- Beacon Interval Detection ---"
lsof -i -n -P 2>/dev/null | awk '{print $1, $9}' | grep ESTABLISHED | sort
echo ""

echo "--- Persistent Long Connections ---"
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $2}' | sort | uniq -c | sort -rn | head -20
echo ""

# ============================================================================
# CROSS-DEVICE AND MESH NETWORK EXPLOITATION
# ============================================================================

echo "=== CROSS-DEVICE AND MESH NETWORK EXPLOITATION ==="
echo ""

echo "--- Bluetooth Status ---"
system_profiler SPBluetoothDataType
echo ""

echo "--- Bluetooth Devices ---"
if command -v blueutil >/dev/null 2>&1; then
    blueutil --paired 2>/dev/null
    blueutil --connected 2>/dev/null
fi
echo ""

echo "--- Bluetooth Activity ---"
log show --predicate 'subsystem CONTAINS "bluetooth"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- AirDrop Activity ---"
log show --predicate 'subsystem CONTAINS "airdrop" OR subsystem CONTAINS "sharing"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Sharing Services Status ---"
sharing -l 2>/dev/null
echo ""

echo "--- AirDrop Transfers ---"
log show --predicate 'subsystem CONTAINS "airdrop" AND eventMessage CONTAINS "transfer"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Continuity Framework ---"
log show --predicate 'subsystem CONTAINS "continuity"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Handoff Activity ---"
log show --predicate 'subsystem CONTAINS "handoff"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Universal Clipboard ---"
log show --predicate 'subsystem CONTAINS "clipboard" OR subsystem CONTAINS "universalclipboard"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Clipboard Synchronization ---"
log show --predicate 'eventMessage CONTAINS "clipboard" AND eventMessage CONTAINS "sync"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- AirPlay Activity ---"
log show --predicate 'subsystem CONTAINS "airplay"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- AirPlay Receivers ---"
log show --predicate 'subsystem CONTAINS "airplay" AND eventMessage CONTAINS "receiver"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Sidecar Activity ---"
log show --predicate 'subsystem CONTAINS "sidecar"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- AWDL Interface ---"
ifconfig awdl0 2>/dev/null
echo ""

echo "--- AWDL Activity Logs ---"
log show --predicate 'subsystem CONTAINS "awdl"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- AWDL Peers ---"
log show --predicate 'subsystem CONTAINS "awdl" AND eventMessage CONTAINS "peer"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Bonjour Services ---"
dns-sd -B _services._dns-sd._udp 2>&1 &
sleep 3
kill %1 2>/dev/null
echo ""

echo "--- Network Service Discovery ---"
log show --predicate 'process == "mDNSResponder" AND eventMessage CONTAINS "service"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- SMB/CIFS Activity ---"
ps aux | grep -iE "smb|cifs|samba" | grep -v grep
echo ""

echo "--- AFP (Apple File Protocol) ---"
ps aux | grep -i "afp" | grep -v grep
echo ""

echo "--- File Sharing Connections ---"
lsof -i :445 -i :139 -i :548 2>/dev/null
echo ""

echo "--- Printer Sharing ---"
lpstat -p 2>/dev/null
lpstat -v 2>/dev/null
echo ""

echo "--- CUPS Activity ---"
log show --predicate 'process == "cupsd"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Printers ---"
lpstat -a 2>/dev/null
echo ""

echo "--- Screen Sharing ---"
ps aux | grep -iE "screensharing|vnc|rfb|ard" | grep -v grep
echo ""

echo "--- Remote Desktop ---"
log show --predicate 'subsystem CONTAINS "remotedesktop" OR eventMessage CONTAINS "ARD"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- VNC Connections ---"
lsof -i :5900 -i :5901 -i :5902 2>/dev/null
echo ""

echo "--- IoT Device Connections ---"
arp -a | grep -iE "esp|arduino|raspberry|philips|nest|ring|alexa|google.home"
echo ""

echo "--- Smart Home Protocols ---"
log show --predicate 'eventMessage CONTAINS "homekit" OR eventMessage CONTAINS "matter" OR eventMessage CONTAINS "zigbee"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Chromecast/Media Devices ---"
dns-sd -B _googlecast._tcp 2>&1 &
sleep 3
kill %1 2>/dev/null
echo ""

# ============================================================================
# WIFI-BASED C2 COMMUNICATION
# ============================================================================

echo "=== WIFI-BASED C2 COMMUNICATION ==="
echo ""

echo "--- Cloud Service Connections ---"
lsof -i -n -P 2>/dev/null | grep -iE "amazonaws|aws|s3|ec2|cloudflare|azure|blob|googleusercontent|storage\.googleapis"
echo ""

echo "--- Specific Cloud Endpoints ---"
lsof -i -n -P 2>/dev/null | grep -iE "compute.*amazonaws|*.cloudfront.net|*.azureedge.net"
echo ""

echo "--- Social Media API Connections ---"
lsof -i -n -P 2>/dev/null | grep -iE "twitter|api\.twitter|telegram|discord|slack\.com|api\.slack"
echo ""

echo "--- Messaging Platform APIs ---"
lsof -i -n -P 2>/dev/null | grep -iE "whatsapp|signal|messenger|wechat"
echo ""

echo "--- Pastebin Services ---"
lsof -i -n -P 2>/dev/null | grep -iE "pastebin|paste|ghostbin|hastebin"
echo ""

echo "--- Code Hosting Connections ---"
lsof -i -n -P 2>/dev/null | grep -iE "github|gitlab|bitbucket|raw\.githubusercontent"
echo ""

echo "--- Blockchain Connections ---"
lsof -i -n -P 2>/dev/null | grep -iE "blockchain|bitcoin|ethereum|crypto|coinbase"
echo ""

echo "--- Cryptocurrency Activity ---"
ps aux | grep -iE "bitcoin|ethereum|monero|crypto|miner" | grep -v grep
echo ""

echo "--- P2P Network Activity ---"
lsof -i -n -P 2>/dev/null | grep -iE "torrent|p2p|bittorrent|utorrent"
echo ""

echo "--- P2P Processes ---"
ps aux | grep -iE "transmission|deluge|rtorrent|qbittorrent" | grep -v grep
echo ""

echo "--- Domain Generation Algorithm Patterns ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -oE "[a-z0-9]{15,}\.com|[a-z0-9]{15,}\.net|[a-z0-9]{15,}\.org" | head -200
echo ""

echo "--- Random Domain Queries ---"
log show --predicate 'process == "mDNSResponder"' --last 7d 2>/dev/null | grep -E "[a-z]{10,}" | tail -500
echo ""

echo "--- Fast Flux DNS Indicators ---"
log show --predicate 'process == "mDNSResponder"' --last 1d 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) print $i}' | sort | uniq -c | sort -rn | head -50
echo ""

echo "--- Short-Lived DNS Responses ---"
log show --predicate 'process == "mDNSResponder" AND eventMessage CONTAINS "TTL"' --last 7d 2>/dev/null | grep -E "TTL.*[0-9]{1,3}" | tail -300
echo ""

echo "--- Dead Drop Resolver Activity ---"
log show --predicate 'eventMessage CONTAINS "pastebin" OR eventMessage CONTAINS "github" OR eventMessage CONTAINS "gitlab"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Onion/Dark Web Indicators ---"
log show --predicate 'eventMessage CONTAINS ".onion"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- TLS/SSL Connections Summary ---"
lsof -i :443 -n -P 2>/dev/null | awk '{print $9}' | cut -d: -f1 | sort | uniq -c | sort -rn
echo ""

echo "--- Certificate Validation Logs ---"
log show --predicate 'subsystem == "com.apple.securityd" AND eventMessage CONTAINS "certificate"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Unusual User Agents ---"
log show --predicate 'eventMessage CONTAINS "User-Agent" OR eventMessage CONTAINS "user agent"' --last 7d 2>/dev/null | tail -200
echo ""

# ============================================================================
# WIFI ADVERTISING AND TRACKING
# ============================================================================

echo "=== WIFI ADVERTISING AND TRACKING ==="
echo ""

echo "--- WiFi Probe Requests ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "probe"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- Probe Request Frequency ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "probe"' --last 1d 2>/dev/null | wc -l
echo ""

echo "--- MAC Address Randomization ---"
log show --predicate 'eventMessage CONTAINS "random" AND eventMessage CONTAINS "MAC"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- MAC Address Changes ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "MAC address"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Hardware Address History ---"
log show --predicate 'eventMessage CONTAINS "hardware address"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- Location Services for Apps ---"
log show --predicate 'subsystem == "com.apple.locationd" AND eventMessage CONTAINS "wifi"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- WiFi-Based Location Tracking ---"
log show --predicate 'subsystem == "com.apple.locationd" AND eventMessage CONTAINS "scan"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- App Network Activity ---"
log show --predicate 'eventMessage CONTAINS "application" AND eventMessage CONTAINS "network"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Analytics Data Collection ---"
find ~/Library/Application\ Support -name "*analytic*" -o -name "*telemetry*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Telemetry Uploads ---"
log show --predicate 'eventMessage CONTAINS "telemetry" OR eventMessage CONTAINS "analytics"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Tracking Beacons ---"
log show --predicate 'eventMessage CONTAINS "beacon" OR eventMessage CONTAINS "tracking"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Marketing SDK Activity ---"
log show --predicate 'eventMessage CONTAINS "marketing" OR eventMessage CONTAINS "advertising"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Third-Party Trackers ---"
lsof -i -n -P 2>/dev/null | grep -iE "doubleclick|google-analytics|facebook|criteo|taboola"
echo ""

echo ""
echo "========================================="
echo "Script 3 Complete: $(date)"
echo "========================================="
echo ""


echo "========================================="
echo "SCRIPT 4: System & Persistence Analysis"
echo "Started: $(date)"
echo "========================================="
echo ""

# ============================================================================
# PERSISTENCE AND STEALTH
# ============================================================================

echo "=== PERSISTENCE AND STEALTH ==="
echo ""

echo "--- WiFi Kernel Extensions ---"
find /System/Library/Extensions -name "*[Ww]i[Ff]i*" -o -name "*[Aa]irport*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Network Kernel Extensions ---"
find /System/Library/Extensions -name "*[Nn]etwork*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- IO80211 Family ---"
ls -laR /System/Library/Extensions/IO80211Family.kext/ 2>/dev/null
echo ""

echo "--- Loaded WiFi KEXTs ---"
kextstat | grep -iE "wifi|airport|80211"
echo ""

echo "--- Loaded Network KEXTs ---"
kextstat | grep -iE "network|ethernet|en[0-9]"
echo ""

echo "--- All Loaded Kernel Extensions ---"
kextstat
echo ""

echo "--- Third-Party KEXTs ---"
kextstat | grep -v "com.apple"
echo ""

echo "--- KEXT Load History ---"
log show --predicate 'eventMessage CONTAINS "kext" OR eventMessage CONTAINS "kernel extension"' --last 30d 2>/dev/null | tail -1000
echo ""

echo "--- Launch Daemons (All) ---"
ls -la /Library/LaunchDaemons/ 2>/dev/null
echo ""

echo "--- Launch Daemons (Network-Related) ---"
find /Library/LaunchDaemons -type f 2>/dev/null -exec grep -l -iE "network|wifi|airport|vpn|tunnel" {} \;
echo ""

echo "--- Launch Daemon Contents (Network) ---"
for daemon in /Library/LaunchDaemons/*; do
    if [ -f "$daemon" ]; then
        if grep -q -iE "network|wifi|airport|vpn" "$daemon" 2>/dev/null; then
            echo "=== $daemon ==="
            cat "$daemon"
            echo ""
        fi
    fi
done
echo ""

echo "--- Launch Agents (System) ---"
ls -la /Library/LaunchAgents/ 2>/dev/null
echo ""

echo "--- Launch Agents (User) ---"
ls -la ~/Library/LaunchAgents/ 2>/dev/null
echo ""

echo "--- Launch Agent Contents (Network) ---"
for agent in /Library/LaunchAgents/* ~/Library/LaunchAgents/*; do
    if [ -f "$agent" ]; then
        if grep -q -iE "network|wifi|airport|vpn" "$agent" 2>/dev/null; then
            echo "=== $agent ==="
            cat "$agent"
            echo ""
        fi
    fi
done
echo ""

echo "--- Running Launch Services ---"
launchctl list
echo ""

echo "--- Network-Related Launch Services ---"
launchctl list | grep -iE "network|wifi|airport|vpn"
echo ""

echo "--- System Launch Daemons ---"
ls -la /System/Library/LaunchDaemons/ 2>/dev/null | grep -iE "network|wifi"
echo ""

echo "--- System Launch Agents ---"
ls -la /System/Library/LaunchAgents/ 2>/dev/null | grep -iE "network|wifi"
echo ""

echo "--- System Extensions Directory ---"
ls -laR /Library/SystemExtensions/ 2>/dev/null
echo ""

echo "--- Approved System Extensions ---"
systemextensionsctl list 2>/dev/null
echo ""

echo "--- StartupItems (Legacy) ---"
ls -laR /Library/StartupItems /System/Library/StartupItems 2>/dev/null
echo ""

echo "--- Periodic Scripts ---"
ls -la /etc/periodic/daily/ 2>/dev/null
ls -la /etc/periodic/weekly/ 2>/dev/null
ls -la /etc/periodic/monthly/ 2>/dev/null
echo ""

echo "--- Periodic Script Contents ---"
for script in /etc/periodic/daily/* /etc/periodic/weekly/* /etc/periodic/monthly/*; do
    if [ -f "$script" ]; then
        echo "=== $script ==="
        cat "$script" 2>/dev/null | head -50
        echo ""
    fi
done
echo ""

echo "--- rc.common Scripts ---"
if [ -f "/etc/rc.common" ]; then
    cat /etc/rc.common
fi
echo ""

echo "--- Login Items ---"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null
echo ""

echo "--- Login Hooks ---"
defaults read com.apple.loginwindow LoginHook 2>/dev/null
defaults read com.apple.loginwindow LogoutHook 2>/dev/null
echo ""

echo "--- Persistent Applications ---"
log show --predicate 'eventMessage CONTAINS "persistent" OR eventMessage CONTAINS "always run"' --last 30d 2>/dev/null | tail -300
echo ""

# ============================================================================
# TEMPORAL AND TRIGGER BEHAVIORS
# ============================================================================

echo "=== TEMPORAL AND TRIGGER BEHAVIORS ==="
echo ""

echo "--- User Cron Jobs ---"
crontab -l 2>/dev/null
echo ""

echo "--- Root Cron Jobs ---"
sudo crontab -l 2>/dev/null
echo ""

echo "--- System Cron ---"
cat /etc/crontab 2>/dev/null
echo ""

echo "--- Cron Directory ---"
ls -la /usr/lib/cron/ 2>/dev/null
echo ""

echo "--- Scheduled Launch Items ---"
find /Library/LaunchAgents /Library/LaunchDaemons ~/Library/LaunchAgents -type f 2>/dev/null -exec grep -l "StartCalendarInterval\|StartInterval" {} \;
echo ""

echo "--- Timed Launch Items ---"
for item in /Library/LaunchAgents/* /Library/LaunchDaemons/* ~/Library/LaunchAgents/*; do
    if [ -f "$item" ]; then
        if grep -q "StartCalendarInterval\|StartInterval" "$item" 2>/dev/null; then
            echo "=== $item ==="
            grep -A5 "StartCalendarInterval\|StartInterval" "$item"
            echo ""
        fi
    fi
done
echo ""

echo "--- Path-Watching Launch Items ---"
for item in /Library/LaunchAgents/* /Library/LaunchDaemons/* ~/Library/LaunchAgents/*; do
    if [ -f "$item" ]; then
        if grep -q "WatchPaths\|QueueDirectories" "$item" 2>/dev/null; then
            echo "=== $item ==="
            cat "$item"
            echo ""
        fi
    fi
done
echo ""

echo "--- Power Management Events (7 Days) ---"
log show --predicate 'eventMessage CONTAINS "wake" OR eventMessage CONTAINS "sleep" OR eventMessage CONTAINS "power"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- Network State Change Events ---"
log show --predicate 'eventMessage CONTAINS "network change" OR eventMessage CONTAINS "link status" OR eventMessage CONTAINS "interface.*up\|down"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- WiFi Association Events ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "assoc"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- WiFi Join Events ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "join"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- Network Transition Triggers ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "transition"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Time-Based Network Activity ---"
log show --predicate 'subsystem == "com.apple.networkd"' --last 24h 2>/dev/null | awk '{print $1}' | cut -d: -f1 | sort | uniq -c
echo ""

echo "--- Network Activity by Hour ---"
log show --predicate 'subsystem == "com.apple.networkd"' --last 7d 2>/dev/null | awk '{print $2}' | cut -d: -f1 | sort | uniq -c
echo ""

echo "--- At Jobs ---"
atq 2>/dev/null
echo ""

echo "--- Calendar-Based Triggers ---"
log show --predicate 'eventMessage CONTAINS "calendar" OR eventMessage CONTAINS "schedule"' --last 7d 2>/dev/null | grep -iE "network|wifi" | tail -300
echo ""

# ============================================================================
# CHIPSET AND DRIVER LEVEL ATTACKS
# ============================================================================

echo "=== CHIPSET AND DRIVER LEVEL ATTACKS ==="
echo ""

echo "--- WiFi Chipset Information ---"
system_profiler SPAirPortDataType
echo ""

echo "--- Network Hardware Details ---"
system_profiler SPNetworkDataType
echo ""

echo "--- PCI Devices ---"
system_profiler SPPCIDataType
echo ""

echo "--- USB Devices (WiFi Adapters) ---"
system_profiler SPUSBDataType | grep -A 10 -iE "wifi|wireless|802\.11|network"
echo ""

echo "--- IO80211 Family Details ---"
kextstat -l -b com.apple.iokit.IO80211Family 2>/dev/null
echo ""

echo "--- Broadcom KEXTs ---"
kextstat | grep -i broadcom
echo ""

echo "--- Broadcom Extensions ---"
find /System/Library/Extensions -name "*Broadcom*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Intel WiFi KEXTs ---"
kextstat | grep -i "intel.*wifi\|intel.*wireless"
echo ""

echo "--- Intel Extensions ---"
find /System/Library/Extensions -name "*Intel*" 2>/dev/null | grep -iE "wifi|wireless|network"
echo ""

echo "--- Atheros KEXTs ---"
kextstat | grep -i atheros
echo ""

echo "--- Atheros Extensions ---"
find /System/Library/Extensions -name "*Atheros*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- WiFi Firmware Location ---"
ls -laR /usr/share/firmware/ 2>/dev/null
echo ""

echo "--- System Firmware ---"
ls -laR /System/Library/Firmware/ 2>/dev/null | head -200
echo ""

echo "--- Driver Diagnostics ---"
log show --predicate 'subsystem == "com.apple.iokit"' --last 7d 2>/dev/null | grep -iE "wifi|airport|80211|network" | tail -1000
echo ""

echo "--- IO Registry WiFi Devices ---"
ioreg -l | grep -iE "wifi|airport|80211|broadcom|atheros" | head -500
echo ""

echo "--- IO Registry Network Interfaces ---"
ioreg -l -n "IONetworkInterface" 2>/dev/null
echo ""

echo "--- IO Registry WiFi Properties ---"
ioreg -l -n "AirPort" 2>/dev/null
echo ""

echo "--- Driver Load Errors ---"
log show --predicate 'subsystem == "com.apple.iokit" AND eventMessage CONTAINS "error"' --last 7d 2>/dev/null | grep -iE "wifi|network|driver" | tail -500
echo ""

echo "--- Kernel Panic Logs ---"
ls -la /Library/Logs/DiagnosticReports/Kernel* 2>/dev/null
echo ""

echo "--- Recent Kernel Panics (30 Days) ---"
find /Library/Logs/DiagnosticReports -name "Kernel*" -mtime -30 -exec ls -la {} \; 2>/dev/null
echo ""

echo "--- Kernel Panic Content (Most Recent) ---"
find /Library/Logs/DiagnosticReports -name "Kernel*" -type f 2>/dev/null | head -1 | xargs cat
echo ""

echo "--- DMA Configuration ---"
ioreg -l | grep -i "dma" | head -100
echo ""

echo "--- WiFi Firmware Version ---"
system_profiler SPAirPortDataType | grep -i "firmware"
echo ""

echo "--- Driver Versions ---"
kextstat | grep -iE "wifi|airport|network" | awk '{print $1, $2, $6}'
echo ""

# ============================================================================
# RECONNAISSANCE AND PROFILING
# ============================================================================

echo "=== RECONNAISSANCE AND PROFILING ==="
echo ""

echo "--- WiFi Connection History (30 Days) ---"
log show --predicate 'subsystem == "com.apple.wifi" AND (eventMessage CONTAINS "join" OR eventMessage CONTAINS "connect")' --last 30d 2>/dev/null | tail -1000
echo ""

echo "--- Network SSID History ---"
log show --predicate 'subsystem == "com.apple.wifi"' --last 30d 2>/dev/null | grep -oE 'SSID.*' | sort -u | head -200
echo ""

echo "--- BSSID History ---"
log show --predicate 'subsystem == "com.apple.wifi"' --last 30d 2>/dev/null | grep -oE 'BSSID.*[0-9a-f:]{17}' | sort -u | head -200
echo ""

echo "--- Location History Caches ---"
find ~/Library/Caches -name "*location*" -o -name "*gps*" -o -name "*map*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Significant Locations Database ---"
if [ -f "$HOME/Library/Caches/com.apple.routined/Local.sqlite" ]; then
    ls -la "$HOME/Library/Caches/com.apple.routined/"
fi
echo ""

echo "--- Route Daemon Cache ---"
ls -laR "$HOME/Library/Caches/com.apple.routined/" 2>/dev/null
echo ""

echo "--- Travel Pattern Analysis ---"
log show --predicate 'subsystem == "com.apple.routined"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- Frequent Locations ---"
log show --predicate 'subsystem == "com.apple.routined" AND eventMessage CONTAINS "frequent"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- Corporate Network Detection ---"
security dump-keychain 2>/dev/null | grep -iE "corp|enterprise|company|work|office" | head -200
echo ""

echo "--- Enterprise WiFi Networks ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "802.1X"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- VPN Usage Patterns ---"
log show --predicate 'eventMessage CONTAINS "VPN"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- Network Profile Analysis ---"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null
echo ""

echo "--- Network Naming Patterns ---"
networksetup -listpreferredwirelessnetworks en0 2>/dev/null | awk '{print length, $0}' | sort -n
echo ""

echo "--- Frequent Network Transitions ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "transition"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Roaming Behavior ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "roam"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- Device Mobility Patterns ---"
log show --predicate 'subsystem == "com.apple.locationd" AND eventMessage CONTAINS "movement"' --last 30d 2>/dev/null | tail -300
echo ""

# ============================================================================
# FIRMWARE AND BOOT LEVEL
# ============================================================================

echo "=== FIRMWARE AND BOOT LEVEL ==="
echo ""

echo "--- EFI/Firmware Version ---"
system_profiler SPSoftwareDataType | grep -iE "boot|firmware|efi"
echo ""

echo "--- Boot ROM Version ---"
system_profiler SPHardwareDataType | grep -i "boot rom"
echo ""

echo "--- SMC Version ---"
system_profiler SPHardwareDataType | grep -i "smc"
echo ""

echo "--- Secure Boot Status ---"
csrutil status 2>/dev/null
echo ""

echo "--- System Integrity Protection ---"
csrutil status 2>/dev/null
echo ""

echo "--- Authenticated Root Status ---"
csrutil authenticated-root status 2>/dev/null
echo ""

echo "--- FileVault Status ---"
fdesetup status 2>/dev/null
echo ""

echo "--- Gatekeeper Status ---"
spctl --status 2>/dev/null
echo ""

echo "--- Gatekeeper Assessment ---"
spctl --assess --verbose /Applications/*.app 2>/dev/null | head -50
echo ""

echo "--- NVRAM Variables ---"
nvram -p 2>/dev/null | head -200
echo ""

echo "--- Boot Arguments ---"
nvram boot-args 2>/dev/null
echo ""

echo "--- Recovery Lock Status ---"
if command -v firmwarepasswd >/dev/null 2>&1; then
    firmwarepasswd -check 2>/dev/null
fi
echo ""

echo "--- EFI Login Items ---"
find /Library/StartupItems /System/Library/StartupItems -type f 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Boot Cache ---"
ls -la /var/db/BootCache* 2>/dev/null
echo ""

echo "--- Boot Plist ---"
if [ -f "/Library/Preferences/SystemConfiguration/com.apple.Boot.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/com.apple.Boot.plist" 2>/dev/null
fi
echo ""

echo "--- Kernel Extensions at Boot ---"
kextstat | head -100
echo ""

echo "--- Kernel Boot Messages ---"
log show --predicate 'messageType == 17' --last 30d 2>/dev/null | head -500
echo ""

echo "--- System Boot History ---"
log show --predicate 'eventMessage CONTAINS "boot" OR eventMessage CONTAINS "startup"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- Firmware Updates ---"
log show --predicate 'eventMessage CONTAINS "firmware" AND eventMessage CONTAINS "update"' --last 90d 2>/dev/null | tail -300
echo ""

echo "--- UEFI Logs ---"
log show --predicate 'subsystem CONTAINS "uefi" OR subsystem CONTAINS "efi"' --last 30d 2>/dev/null | tail -300
echo ""

# ============================================================================
# ADDITIONAL FORENSIC INDICATORS
# ============================================================================

echo "=== ADDITIONAL FORENSIC INDICATORS ==="
echo ""

echo "--- Modified System Binaries (30 Days) ---"
find /usr/bin /usr/sbin /bin /sbin -type f -mtime -30 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Modified System Files (30 Days) ---"
find /System/Library -type f -mtime -30 2>/dev/null | head -500
echo ""

echo "--- Modified LaunchDaemons (30 Days) ---"
find /Library/LaunchDaemons -type f -mtime -30 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Modified LaunchAgents (30 Days) ---"
find /Library/LaunchAgents ~/Library/LaunchAgents -type f -mtime -30 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Recently Modified KEXTs ---"
find /System/Library/Extensions /Library/Extensions -type f -mtime -30 2>/dev/null | head -200
echo ""

echo "--- Suspicious File Locations ---"
find /tmp /var/tmp -type f -mtime -7 2>/dev/null -exec ls -la {} \; | head -200
echo ""

echo "--- Hidden Files (Recent) ---"
find ~ -name ".*" -type f -mtime -30 2>/dev/null | head -500
echo ""

echo "--- World-Writable Files ---"
find /Library /System/Library -type f -perm -002 2>/dev/null | head -200
echo ""

echo "--- SUID Files ---"
find /usr /Library -type f -perm -4000 2>/dev/null | head -100
echo ""

echo "--- SGID Files ---"
find /usr /Library -type f -perm -2000 2>/dev/null | head -100
echo ""

echo "--- Files with No Owner ---"
find / -nouser 2>/dev/null | head -100
echo ""

echo "--- Files with No Group ---"
find / -nogroup 2>/dev/null | head -100
echo ""

echo "--- Unsigned Applications ---"
find /Applications -name "*.app" -type d 2>/dev/null | while read app; do
    codesign -v "$app" 2>&1 | grep -q "invalid" && echo "UNSIGNED: $app"
done | head -50
echo ""

echo "--- Code Signature Violations ---"
log show --predicate 'eventMessage CONTAINS "signature" AND eventMessage CONTAINS "invalid"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- Gatekeeper Violations ---"
log show --predicate 'process == "syspolicyd" AND eventMessage CONTAINS "deny"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- Quarantine Events ---"
log show --predicate 'eventMessage CONTAINS "quarantine"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- System Log Errors ---"
log show --predicate 'messageType == 16' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- Crash Reports (User) ---"
ls -lat ~/Library/Logs/DiagnosticReports/ 2>/dev/null | head -100
echo ""

echo "--- Crash Reports (System) ---"
ls -lat /Library/Logs/DiagnosticReports/ 2>/dev/null | head -100
echo ""

echo "--- Recent Application Crashes ---"
find ~/Library/Logs/DiagnosticReports -name "*.crash" -mtime -7 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Install History ---"
if [ -f "/Library/Receipts/InstallHistory.plist" ]; then
    plutil -p "/Library/Receipts/InstallHistory.plist" 2>/dev/null | tail -500
fi
echo ""

echo "--- Package Receipts ---"
ls -lat /var/db/receipts/ 2>/dev/null | head -100
echo ""

echo "--- System Update History ---"
softwareupdate --history 2>/dev/null
echo ""

echo ""
echo "========================================="
echo "Script 4 Complete: $(date)"
echo "========================================="
echo ""


echo "========================================="
echo "SCRIPT 5: Platform & Protocol Specific Analysis"
echo "Started: $(date)"
echo "========================================="
echo ""

# ============================================================================
# macOS SPECIFIC WIFI BEHAVIORS
# ============================================================================

echo "=== macOS SPECIFIC WIFI BEHAVIORS ==="
echo ""

echo "--- AWDL Interface Status ---"
ifconfig awdl0 2>/dev/null
echo ""

echo "--- AWDL Interface Statistics ---"
netstat -I awdl0 -b 2>/dev/null
echo ""

echo "--- AWDL Activity Logs (7 Days) ---"
log show --predicate 'subsystem CONTAINS "awdl"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- AWDL Peer Discovery ---"
log show --predicate 'subsystem CONTAINS "awdl" AND eventMessage CONTAINS "peer"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- AWDL State Changes ---"
log show --predicate 'subsystem CONTAINS "awdl" AND eventMessage CONTAINS "state"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- CoreWLAN Preferences ---"
if [ -f "$HOME/Library/Preferences/com.apple.wifi.plist" ]; then
    plutil -p "$HOME/Library/Preferences/com.apple.wifi.plist" 2>/dev/null
fi
echo ""

echo "--- Airport Preferences ---"
if [ -f "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist" 2>/dev/null | head -500
fi
echo ""

echo "--- NetworkExtension Configurations ---"
find ~/Library/Preferences /Library/Preferences -name "*networkextension*" -o -name "*NetworkExtension*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Network Extension Activity ---"
log show --predicate 'subsystem == "com.apple.networkextension"' --last 7d 2>/dev/null | tail -1000
echo ""

echo "--- iCloud Private Relay Status ---"
log show --predicate 'subsystem CONTAINS "privaterelay"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Private Relay Connections ---"
log show --predicate 'eventMessage CONTAINS "private relay" OR eventMessage CONTAINS "icloud relay"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- WiFi Assist Activity ---"
log show --predicate 'eventMessage CONTAINS "WiFi Assist" OR eventMessage CONTAINS "wifi assist"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- WiFi to Cellular Handoff ---"
log show --predicate 'eventMessage CONTAINS "handoff" AND eventMessage CONTAINS "cellular"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Location Services via WiFi ---"
log show --predicate 'subsystem == "com.apple.locationd" AND eventMessage CONTAINS "wifi"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Continuity Services ---"
log show --predicate 'subsystem CONTAINS "continuity"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Handoff Activity ---"
log show --predicate 'subsystem CONTAINS "handoff"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Handoff App Launches ---"
log show --predicate 'subsystem CONTAINS "handoff" AND eventMessage CONTAINS "launch"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Universal Clipboard Events ---"
log show --predicate 'subsystem CONTAINS "universalclipboard" OR subsystem CONTAINS "clipboard"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Clipboard Sync Activity ---"
log show --predicate 'eventMessage CONTAINS "clipboard" AND eventMessage CONTAINS "sync"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- AirPlay Activity ---"
log show --predicate 'subsystem CONTAINS "airplay"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- AirPlay Mirroring ---"
log show --predicate 'subsystem CONTAINS "airplay" AND eventMessage CONTAINS "mirror"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Sidecar Sessions ---"
log show --predicate 'subsystem CONTAINS "sidecar"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Sidecar Connections ---"
log show --predicate 'subsystem CONTAINS "sidecar" AND eventMessage CONTAINS "connect"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Find My Network ---"
log show --predicate 'subsystem CONTAINS "findmy"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Find My Beaconing ---"
log show --predicate 'subsystem CONTAINS "findmy" AND eventMessage CONTAINS "beacon"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Find My Location Updates ---"
log show --predicate 'subsystem CONTAINS "findmy" AND eventMessage CONTAINS "location"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Framework Usage ---"
lsof 2>/dev/null | grep -i "network.framework" | head -200
echo ""

echo "--- Network Framework Logs ---"
log show --predicate 'subsystem CONTAINS "com.apple.network"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- NEHelper Activity ---"
log show --predicate 'process == "nehelper" OR process == "nesessionmanager"' --last 7d 2>/dev/null | tail -500
echo ""

# ============================================================================
# WIFI SPOOFING AND INTERCEPTION
# ============================================================================

echo "=== WIFI SPOOFING AND INTERCEPTION ==="
echo ""

echo "--- Current MAC Address (en0) ---"
ifconfig en0 | grep ether
echo ""

echo "--- Current MAC Address (en1) ---"
ifconfig en1 | grep ether 2>/dev/null
echo ""

echo "--- MAC Address Changes ---"
log show --predicate 'eventMessage CONTAINS "MAC" OR eventMessage CONTAINS "hardware address"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- MAC Address Spoofing Detection ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "MAC address"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- Hardware UUID ---"
system_profiler SPAirPortDataType | grep -i "hardware uuid"
echo ""

echo "--- Network Hardware Information ---"
networksetup -listallhardwareports
echo ""

echo "--- SSL/TLS Interception Indicators ---"
security dump-keychain 2>/dev/null | grep -iE "mitm|intercept|proxy" | head -100
echo ""

echo "--- Untrusted Certificates ---"
security dump-keychain 2>/dev/null | grep -B10 -A10 "untrusted"
echo ""

echo "--- Certificate Trust Modifications ---"
security dump-trust-settings 2>/dev/null | head -500
echo ""

echo "--- Custom Root CAs ---"
security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep -E "labl|issu" | head -500
echo ""

echo "--- Self-Signed Certificates ---"
security find-certificate -a 2>/dev/null | grep -B5 "self signed"
echo ""

echo "--- Certificate Installation Events ---"
log show --predicate 'eventMessage CONTAINS "certificate" AND eventMessage CONTAINS "install"' --last 30d 2>/dev/null | tail -300
echo ""

echo "--- Evil Twin Detection (Duplicate BSSIDs) ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "BSSID"' --last 7d 2>/dev/null | awk '{print $NF}' | grep -E "[0-9a-f:]{17}" | sort | uniq -d
echo ""

echo "--- Unexpected Network Changes ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "unexpected"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Network Authentication Failures ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "auth" AND eventMessage CONTAINS "fail"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- TLS/SSL Errors ---"
log show --predicate 'eventMessage CONTAINS "SSL" OR eventMessage CONTAINS "TLS"' --last 7d 2>/dev/null | grep -i error | tail -500
echo ""

echo "--- Certificate Validation Failures ---"
log show --predicate 'subsystem == "com.apple.securityd" AND eventMessage CONTAINS "certificate" AND eventMessage CONTAINS "fail"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- MITM Detection ---"
log show --predicate 'eventMessage CONTAINS "man-in-the-middle" OR eventMessage CONTAINS "MITM"' --last 30d 2>/dev/null | tail -200
echo ""

# ============================================================================
# ENTERPRISE WIFI ATTACKS
# ============================================================================

echo "=== ENTERPRISE WIFI ATTACKS ==="
echo ""

echo "--- 802.1X Configurations ---"
security dump-keychain 2>/dev/null | grep -iE "802\.1x|eap|radius" | head -500
echo ""

echo "--- 802.1X Activity ---"
log show --predicate 'eventMessage CONTAINS "802.1X"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- EAP Methods ---"
log show --predicate 'eventMessage CONTAINS "EAP"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- EAP-TLS Activity ---"
log show --predicate 'eventMessage CONTAINS "EAP-TLS"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- PEAP Activity ---"
log show --predicate 'eventMessage CONTAINS "PEAP"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- RADIUS Authentication ---"
log show --predicate 'eventMessage CONTAINS "RADIUS"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- RADIUS Server Communication ---"
lsof -i :1812 -i :1813 2>/dev/null
echo ""

echo "--- Enterprise WiFi Profiles ---"
find /Library/Preferences/SystemConfiguration -name "*eapolclient*" -o -name "*8021x*" -o -name "*EAP*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- EAPoL Client Configuration ---"
if [ -f "/Library/Preferences/SystemConfiguration/com.apple.eapolclient.configuration.plist" ]; then
    plutil -p "/Library/Preferences/SystemConfiguration/com.apple.eapolclient.configuration.plist" 2>/dev/null
fi
echo ""

echo "--- Certificate-Based Authentication ---"
security find-identity -v 2>/dev/null
echo ""

echo "--- Identity Certificates ---"
security find-identity -v -p sslclient 2>/dev/null
echo ""

echo "--- Client Certificates ---"
security find-certificate -a -c "client" 2>/dev/null | grep -E "labl|issu|subj"
echo ""

echo "--- NAC Bypass Indicators ---"
log show --predicate 'eventMessage CONTAINS "NAC" OR eventMessage CONTAINS "posture" OR eventMessage CONTAINS "compliance"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- MDM Profiles ---"
profiles -P 2>/dev/null
echo ""

echo "--- MDM Profile Details ---"
profiles list 2>/dev/null
echo ""

echo "--- Configuration Profiles ---"
profiles show 2>/dev/null
echo ""

echo "--- MDM Enrollment ---"
log show --predicate 'eventMessage CONTAINS "MDM" OR eventMessage CONTAINS "enrollment"' --last 30d 2>/dev/null | tail -500
echo ""

echo "--- Enterprise VPN Profiles ---"
find /Library/Preferences/SystemConfiguration -name "*vpn*" 2>/dev/null -exec grep -l "enterprise\|company\|corp" {} \;
echo ""

echo "--- Corporate Proxy Settings ---"
networksetup -listallnetworkservices 2>/dev/null | while read service; do
    proxy_info=$(networksetup -getwebproxy "$service" 2>/dev/null)
    if echo "$proxy_info" | grep -q "Enabled: Yes"; then
        echo "Service: $service"
        echo "$proxy_info"
        echo ""
    fi
done
echo ""


# ============================================================================
# EMERGING WIFI TECHNOLOGIES
# ============================================================================

echo "=== EMERGING WIFI TECHNOLOGIES ==="
echo ""

echo "--- WiFi 6/6E Support ---"
system_profiler SPAirPortDataType | grep -iE "wifi.*6|802\.11ax|6.*ghz"
echo ""

echo "--- WiFi 6 Activity ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "802.11ax"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- WPA3 Usage ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "WPA3"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- WPA3 Transition Mode ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "WPA3-transition"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- SAE (Simultaneous Authentication of Equals) ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "SAE"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- 6GHz Band Activity ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "6GHz"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Channel Width Detection ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null | grep -i "channel"
echo ""

echo "--- WiFi Sensing/Radar ---"
log show --predicate 'eventMessage CONTAINS "sensing" OR eventMessage CONTAINS "radar" OR eventMessage CONTAINS "motion"' --last 7d 2>/dev/null | grep -i wifi | tail -200
echo ""

echo "--- OWE (Opportunistic Wireless Encryption) ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "OWE"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Enhanced Open ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "enhanced open"' --last 7d 2>/dev/null | tail -200
echo ""

# ============================================================================
# PHYSICAL LAYER ATTACKS
# ============================================================================

echo "=== PHYSICAL LAYER ATTACKS ==="
echo ""

echo "--- Signal Strength ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null | grep -iE "rssi|noise|signal|rate"
echo ""

echo "--- Current Channel ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null | grep -i "channel"
echo ""

echo "--- Signal Quality Metrics ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null
echo ""

echo "--- Interference Detection ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "interference"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Channel Interference ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "channel" AND eventMessage CONTAINS "busy"' --last 7d 2>/dev/null | tail -200
echo ""

echo "--- Jamming Indicators ---"
log show --predicate 'subsystem == "com.apple.wifi" AND (eventMessage CONTAINS "jam" OR eventMessage CONTAINS "blocked" OR eventMessage CONTAINS "unable")' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Deauthentication Frequency (24h) ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "deauth"' --last 24h 2>/dev/null | wc -l
echo ""

echo "--- Deauthentication Events ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "deauth"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Excessive Disconnections ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "disconnect"' --last 24h 2>/dev/null | wc -l
echo ""

echo "--- Channel Hopping ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "channel"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Beacon Loss ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "beacon" AND eventMessage CONTAINS "loss"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Link Quality ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "link quality"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Retry Rate ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "retry"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- Frame Errors ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "frame" AND eventMessage CONTAINS "error"' --last 7d 2>/dev/null | tail -300
echo ""

# ============================================================================
# MALICIOUS NETWORK PROCESSES
# ============================================================================

echo "=== MALICIOUS NETWORK PROCESSES ==="
echo ""

echo "--- Suspicious Process Names ---"
ps aux | grep -iE "bot|rat|backdoor|payload|shell|cmd|reverse|bind|exploit|dropper|loader" | grep -v grep
echo ""

echo "--- Processes with Network Activity ---"
lsof -i -n -P 2>/dev/null | awk '{print $1}' | sort -u
echo ""

echo "--- Network Processes Details ---"
for proc in $(lsof -i -n -P 2>/dev/null | awk '{print $1}' | sort -u); do
    echo "=== $proc ==="
    ps aux | grep "^[^ ]*  *[^ ]*  *[^ ]*  *[^ ]*  *[^ ]*  *[^ ]*  *[^ ]*  *[^ ]*  *[^ ]*  *[^ ]*  *.*$proc" | head -5
    echo ""
done | head -500
echo ""

echo "--- Unsigned Network Processes ---"
lsof -i -n -P 2>/dev/null | awk '{print $1}' | sort -u | while read proc; do
    proc_path=$(ps aux | grep "$proc" | grep -v grep | awk '{for(i=11;i<=NF;i++) printf $i" "; print ""}' | head -1 | awk '{print $1}')
    if [ -f "$proc_path" ]; then
        if codesign -v "$proc_path" 2>&1 | grep -q "invalid"; then
            echo "UNSIGNED: $proc ($proc_path)"
        fi
    fi
done
echo ""

echo "--- Hidden Processes ---"
ps aux | awk '$11 ~ /^\./' | grep -v grep
echo ""

echo "--- Processes from Temp Directories ---"
ps aux | grep -E "/tmp/|/var/tmp/|/private/tmp/" | grep -v grep
echo ""

echo "--- Processes from User Directories ---"
ps aux | grep -E "/Users/.*/\." | grep -v "Library\|Application Support" | grep -v grep
echo ""

echo "--- Suspicious Parent-Child Relationships ---"
ps auxww -o pid,ppid,user,command | grep -iE "bash.*curl|bash.*wget|python.*http|perl.*socket"
echo ""

echo "--- Network Activity from Scripts ---"
lsof -i -n -P 2>/dev/null | grep -iE "python|perl|ruby|php|bash|sh"
echo ""

# ============================================================================
# PROCESS AND MEMORY ANALYSIS
# ============================================================================

echo "=== PROCESS AND MEMORY ANALYSIS ==="
echo ""

echo "--- All Running Processes ---"
ps aux
echo ""

echo "--- Process Tree ---"
ps auxww -o pid,ppid,user,%cpu,%mem,command
echo ""

echo "--- Long-Running Processes ---"
ps auxww -o etime,pid,command | sort -k1 -rn | head -50
echo ""

echo "--- Processes with Open Files ---"
lsof 2>/dev/null | head -2000
echo ""

echo "--- Virtual Memory Statistics ---"
vm_stat
echo ""

echo "--- Memory Pressure ---"
memory_pressure
echo ""

echo "--- Swap Usage ---"
sysctl vm.swapusage
echo ""

echo "--- Page Faults ---"
vm_stat | grep -i "page.*fault"
echo ""

echo "--- Process Memory Maps ---"
for pid in $(ps aux | grep -iE "network|wifi|vpn" | grep -v grep | awk '{print $2}'); do
    echo "=== PID $pid ==="
    vmmap $pid 2>/dev/null | head -100
    echo ""
done | head -1000
echo ""

# ============================================================================
# FILE SYSTEM FORENSICS
# ============================================================================

echo "=== FILE SYSTEM FORENSICS ==="
echo ""

echo "--- Recently Modified Files (Library) ---"
find ~/Library -type f -mtime -7 2>/dev/null -exec ls -la {} \; | head -1000
echo ""

echo "--- Recently Accessed Network Preferences ---"
find ~/Library/Preferences /Library/Preferences -type f -atime -7 -name "*network*" -o -name "*wifi*" -o -name "*airport*" 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Suspicious Hidden Files (30 Days) ---"
find ~ -name ".*" -type f -mtime -30 2>/dev/null | head -500
echo ""

echo "--- Recently Created Files ---"
find ~ -type f -mtime -7 2>/dev/null -exec ls -la {} \; | head -500
echo ""

echo "--- Large Files in Temp ---"
find /tmp /var/tmp -type f -size +10M 2>/dev/null -exec ls -lh {} \;
echo ""

echo "--- Binary Files in User Directories ---"
find ~ -type f \( -name "*.bin" -o -name "*.dat" -o -name "*.dylib" -o -name "*.so" \) 2>/dev/null | grep -v Library | head -200
echo ""

echo "--- Script Files (Recent) ---"
find ~ -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o -name "*.js" \) -mtime -30 2>/dev/null -exec ls -la {} \;
echo ""

echo "--- Executable Files (Recent) ---"
find ~ -type f -perm +111 -mtime -30 2>/dev/null -exec ls -la {} \; | head -200
echo ""

echo ""
echo "========================================="
echo "Script 5 Complete: $(date)"
echo "========================================="
echo ""


# ============================================================================
# POWER AND RESOURCE EXPLOITATION
# ============================================================================

echo "=== POWER AND RESOURCE EXPLOITATION ==="
echo ""

echo "--- Battery Status ---"
pmset -g batt
echo ""

echo "--- Power Management Settings ---"
pmset -g
echo ""

echo "--- AC Power Settings ---"
pmset -g ac
echo ""

echo "--- Battery Power Settings ---"
pmset -g batt
echo ""

echo "--- System Power State ---"
pmset -g ps
echo ""

echo "--- Assertions ---"
pmset -g assertions
echo ""

echo "--- Energy Impact (Top Processes) ---"
ps aux -m | head -100
echo ""

echo "--- CPU Usage (Top 30) ---"
ps aux | sort -k3 -rn | head -30
echo ""

echo "--- Memory Usage (Top 30) ---"
ps aux | sort -k4 -rn | head -30
echo ""

echo "--- Network Process CPU Usage ---"
ps aux | grep -iE "network|wifi|airport|vpn|dns" | sort -k3 -rn | head -30
echo ""

echo "--- Network Process Memory Usage ---"
ps aux | grep -iE "network|wifi|airport|vpn|dns" | sort -k4 -rn | head -30
echo ""

echo "--- WiFi Scanning Frequency (24h) ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "scan"' --last 24h 2>/dev/null | wc -l
echo ""

echo "--- WiFi Scan Activity ---"
log show --predicate 'subsystem == "com.apple.wifi" AND eventMessage CONTAINS "scan"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Network I/O Statistics ---"
iostat -w 1 -c 5 2>/dev/null
echo ""

echo "--- Disk I/O by Process ---"
iotop -P 2>/dev/null | head -50
echo ""

echo "--- Thermal State ---"
pmset -g therm
echo ""

echo "--- Thermal Pressure ---"
log show --predicate 'eventMessage CONTAINS "thermal" OR eventMessage CONTAINS "temperature"' --last 7d 2>/dev/null | tail -300
echo ""

echo "--- CPU Temperature ---"
sysctl machdep.xcpm.cpu_thermal_level 2>/dev/null
echo ""

echo "--- Fan Speed ---"
sysctl machdep.xcpm.fan_speed 2>/dev/null
echo ""

echo "--- Sleep/Wake History ---"
pmset -g log | grep -E "Sleep|Wake" | tail -100
echo ""

echo "--- Power Events ---"
log show --predicate 'subsystem == "com.apple.powermanagement"' --last 7d 2>/dev/null | tail -500
echo ""

echo "--- Battery Drain Rate ---"
pmset -g rawlog | tail -100
echo ""
