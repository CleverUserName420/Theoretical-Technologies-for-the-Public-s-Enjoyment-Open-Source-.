#!/bin/bash

################################################################################
# Enhanced QR Code Malware Detection & Analysis System
# Version: 2.0.0
# Author: Enhanced for comprehensive threat detection
# Purpose: Advanced QR code malware detection with IOC correlation
################################################################################

# Strict error handling
set -o pipefail
shopt -s nullglob extglob nocasematch

################################################################################
# GLOBAL CONFIGURATION
################################################################################

VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${SCRIPT_DIR}/qr_analysis_${TIMESTAMP}"
REPORT_FILE="${OUTPUT_DIR}/analysis_report.txt"
JSON_REPORT="${OUTPUT_DIR}/analysis_report.json"
IOC_REPORT="${OUTPUT_DIR}/iocs_detected.csv"
TEMP_DIR="${OUTPUT_DIR}/temp"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"
LOG_FILE="${OUTPUT_DIR}/scanner.log"

# Threat scoring
THREAT_SCORE=0
MAX_THREAT_SCORE=1000

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Analysis flags
VERBOSE=false
DEEP_ANALYSIS=false
NETWORK_CHECK=true
VT_CHECK=false
STEALTH_MODE=false

################################################################################
# DEPENDENCY VERIFICATION
################################################################################

declare -A REQUIRED_DEPS=(
    ["zbarimg"]="QR code decoding"
    ["python3"]="Advanced analysis"
    ["file"]="File type detection"
    ["hexdump"]="Binary analysis"
    ["awk"]="Text processing"
    ["grep"]="Pattern matching"
    ["sed"]="Stream editing"
    ["jq"]="JSON processing"
    ["curl"]="Network requests"
)

declare -A OPTIONAL_DEPS=(
    ["convert"]="ImageMagick - image analysis"
    ["compare"]="ImageMagick - diff analysis"
    ["tesseract"]="OCR analysis"
    ["exiftool"]="Metadata extraction"
    ["ssdeep"]="Fuzzy hashing"
    ["yara"]="Pattern matching"
    ["tshark"]="Network analysis"
    ["xxd"]="Hex viewing"
    ["strings"]="String extraction"
    ["openssl"]="Cryptographic operations"
    ["quirc"]="Alternative QR decoder"
    ["zxing"]="ZXing QR decoder"
    ["qrdecode"]="libqrencode QR decoder"
    ["steghide"]="Steganography detection"
    ["zsteg"]="PNG steganography detection"
    ["stegdetect"]="Steganography detection"
    ["whois"]="Domain registration lookup"
    ["identify"]="ImageMagick identify tool"
)

check_dependencies() {
    log_info "Checking dependencies..."
    local missing_required=()
    local missing_optional=()
    
    for cmd in "${!REQUIRED_DEPS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_required+=("$cmd (${REQUIRED_DEPS[$cmd]})")
        fi
    done
    
    for cmd in "${!OPTIONAL_DEPS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_optional+=("$cmd (${OPTIONAL_DEPS[$cmd]})")
        fi
    done
    
    if [ ${#missing_required[@]} -ne 0 ]; then
        log_error "Missing required dependencies:"
        printf '%s\n' "${missing_required[@]}" >&2
        echo -e "\n${YELLOW}Install with:${NC}"
        echo "brew install zbar python3 coreutils grep gnu-sed jq curl"
        echo "pip3 install pillow pyzbar"
        exit 1
    fi
    
    if [ ${#missing_optional[@]} -ne 0 ]; then
        log_warning "Missing optional dependencies (reduced functionality):"
        printf '%s\n' "${missing_optional[@]}"
        echo -e "\n${YELLOW}Install additional tools:${NC}"
        echo "brew install qrencode quirc imagemagick tesseract exiftool ssdeep steghide zsteg whois"
    fi
    
    # Check Python modules
    python3 -c "import PIL, pyzbar" 2>/dev/null || {
        log_error "Missing Python dependencies"
        echo "Install: pip3 install pillow pyzbar qrcode opencv-python-headless"
        exit 1
    }
    
    log_success "Dependency check complete"
}

################################################################################
# LOGGING FUNCTIONS
################################################################################

log_msg() {
    local level=$1
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $msg" >> "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    log_msg "INFO" "$*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
    log_msg "SUCCESS" "$*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" >&2
    log_msg "WARNING" "$*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    log_msg "ERROR" "$*"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $*" >&2
    log_msg "CRITICAL" "$*"
}

log_threat() {
    local score=$1
    shift
    echo -e "${MAGENTA}[THREAT:$score]${NC} $*"
    log_msg "THREAT:$score" "$*"
    ((THREAT_SCORE += score))
}

################################################################################
# IOC DATABASES - Comprehensive Threat Intelligence
################################################################################

# Malicious URL shorteners and link manipulation services
declare -a URL_SHORTENERS=(
    "bit\.ly" "t\.co" "tinyurl\.com" "rb\.gy" "goo\.gl"
    "buff\.ly" "adf\.ly" "cutt\.ly" "ow\.ly" "is\.gd"
    "cli\.gs" "pic\.gd" "DwarfURL\.com" "yfrog\.com" "migre\.me"
    "ff\.im" "tiny\.cc" "url4\.eu" "tr\.im" "twit\.ac"
    "su\.pr" "twurl\.nl" "snipurl\.com" "short\.to" "BudURL\.com"
    "ping\.fm" "post\.ly" "Just\.as" "bkite\.com" "snipr\.com"
    "fic\.kr" "loopt\.us" "doiop\.com" "short\.ie" "kl\.am"
    "wp\.me" "rubyurl\.com" "om\.ly" "to\.ly" "bit\.do"
    "lnkd\.in" "db\.tt" "qr\.ae" "adf\.ly" "bitly\.com"
    "cur\.lv" "tinyurl\.cc" "ity\.im" "q\.gs" "po\.st"
    "bc\.vc" "twitthis\.com" "u\.to" "j\.mp" "buzurl\.com"
    "cutt\.us" "u\.bb" "yourls\.org" "x\.co" "prettylinkpro\.com"
    "scrnch\.me" "filoops\.info" "vzturl\.com" "qr\.net" "1url\.com"
    "tweez\.me" "v\.gd" "tr\.im" "link\.zip" "shorturl\.at"
)

# Known malicious TLDs and suspicious domains
declare -a SUSPICIOUS_TLDS=(
    "\.tk" "\.ml" "\.ga" "\.cf" "\.gq" "\.pw" "\.cc"
    "\.ws" "\.buzz" "\.link" "\.top" "\.click" "\.loan"
    "\.download" "\.stream" "\.science" "\.racing" "\.review"
    "\.work" "\.party" "\.gdn" "\.mom" "\.xin" "\.kim"
    "\.men" "\.win" "\.date" "\.trade" "\.webcam" "\.bid"
)

# Cryptocurrency wallet address patterns
declare -a CRYPTO_PATTERNS=(
    # Bitcoin Legacy
    "1[a-km-zA-HJ-NP-Z1-9]{25,34}"
    # Bitcoin SegWit
    "3[a-km-zA-HJ-NP-Z1-9]{25,34}"
    # Bitcoin Bech32
    "bc1[a-z0-9]{39,87}"
    # Ethereum
    "0x[a-fA-F0-9]{40}"
    # Litecoin
    "[LM][a-km-zA-HJ-NP-Z1-9]{26,33}"
    # Dogecoin
    "D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}"
    # Ripple
    "r[0-9a-zA-Z]{24,34}"
    # Monero
    "4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"
    # Bitcoin Cash
    "(bitcoincash:)?[qp][a-z0-9]{41}"
    # Tether (ERC-20)
    "0x[a-fA-F0-9]{40}"
    # Cardano
    "addr1[a-z0-9]{58,103}"
    # Solana
    "[1-9A-HJ-NP-Za-km-z]{32,44}"
)

# Dangerous file extensions
declare -a DANGEROUS_EXTENSIONS=(
    "\.exe" "\.dll" "\.scr" "\.bat" "\.cmd" "\.com" "\.pif"
    "\.apk" "\.ipa" "\.deb" "\.rpm" "\.dmg" "\.pkg"
    "\.vbs" "\.js" "\.jar" "\.wsf" "\.hta" "\.msi"
    "\.ps1" "\.psm1" "\.sh" "\.bash" "\.zsh" "\.csh"
    "\.app" "\.action" "\.workflow" "\.command"
    "\.mobileconfig" "\.provisionprofile"
    "\.docm" "\.xlsm" "\.pptm" "\.dotm" "\.xltm"
    "\.iso" "\.img" "\.vhd" "\.vmdk"
)

# Suspicious URL patterns
declare -a SUSPICIOUS_URL_PATTERNS=(
    "login" "signin" "verify" "account" "update" "secure"
    "banking" "paypal" "wallet" "confirm" "suspended"
    "unlock" "password" "reset" "security" "authenticate"
    "validate" "support" "billing" "payment" "invoice"
    "tax" "refund" "prize" "winner" "claim" "urgent"
    "action.*required" "verify.*identity" "suspended.*account"
)

# Mobile configuration profile indicators
declare -a MOBILE_CONFIG_PATTERNS=(
    "mobileconfig" "provisionprofile" "PayloadType"
    "com\.apple\.wifi\.managed" "com\.apple\.vpn\.managed"
    "com\.apple\.security\.root" "com\.apple\.mdm"
    "PayloadCertificateFileName" "PayloadContent"
)

# Script injection patterns
declare -a SCRIPT_INJECTION_PATTERNS=(
    "<script" "javascript:" "onerror=" "onload=" "onclick="
    "eval\(" "setTimeout\(" "setInterval\(" "Function\("
    "document\.cookie" "document\.write" "innerHTML"
    "%3Cscript" "%3E" "fromCharCode" "atob\(" "btoa\("
    "unescape\(" "String\.fromCharCode" "\\.src\s*="
)

# Social engineering keywords
declare -a SOCIAL_ENGINEERING_KEYWORDS=(
    "verify.*account" "confirm.*identity" "urgent.*action"
    "suspended.*account" "unusual.*activity" "security.*alert"
    "click.*here" "claim.*prize" "you.*won" "congratulations"
    "limited.*time" "act.*now" "expires.*today" "final.*notice"
    "your.*package" "delivery.*failed" "tax.*refund"
    "IRS" "bank.*alert" "payment.*failed" "card.*declined"
)

# Deep link scheme patterns (app URL schemes)
declare -a DEEPLINK_SCHEMES=(
    "whatsapp:" "telegram:" "signal:" "discord:" "slack:"
    "venmo:" "cashapp:" "paypal:" "zelle:" "applepay:"
    "googlepay:" "bitcoin:" "ethereum:" "crypto:"
    "fb:" "instagram:" "twitter:" "tiktok:" "snapchat:"
    "spotify:" "youtube:" "maps:" "mailto:" "tel:" "sms:"
    "facetime:" "facetime-audio:" "itms:" "itms-apps:"
)

# QR code action prefixes
declare -a QR_ACTION_PREFIXES=(
    "WIFI:" "SMSTO:" "MATMSG:" "mailto:" "tel:" "geo:"
    "BEGIN:VEVENT" "BEGIN:VCARD" "otpauth:" "bitcoin:"
    "ethereum:" "lightning:" "solana:" "sms:" "mms:"
)

# APT and threat actor infrastructure indicators
declare -a APT_INDICATORS=(
    # C2 patterns
    "pastebin\.com/raw" "github\.com/.*\.txt" "gitlab\.com/.*\.txt"
    "telegra\.ph" "t\.me" "discord\.gg" "bit\.ly/.*[0-9]{5,}"
    # DGA-like patterns
    "[a-z]{8,16}\.(top|xyz|info|club|online)"
    # IP-based URLs
    "http[s]?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
)

# Phishing brand impersonation patterns
declare -a PHISHING_BRANDS=(
    "paypal" "amazon" "netflix" "microsoft" "apple" "google"
    "facebook" "instagram" "twitter" "linkedin" "ebay"
    "chase" "wellsfargo" "bankofamerica" "citi" "usbank"
    "fedex" "ups" "usps" "dhl" "irs" "social.*security"
    "covid" "vaccine" "stimulus" "refund" "invoice"
)

# Encoded/obfuscated content patterns
declare -a OBFUSCATION_PATTERNS=(
    "base64," "data:text/html" "data:application"
    "%[0-9a-fA-F]{2}" "\\x[0-9a-fA-F]{2}" "\\u[0-9a-fA-F]{4}"
    "&#[0-9]{2,4};" "&#x[0-9a-fA-F]{2,4};"
)

# Unicode homograph attack characters
declare -a HOMOGRAPH_CHARS=(
    "а" "е" "о" "р" "с" "у" "х"  # Cyrillic
    "ο" "ρ" "υ" "ν" "α"  # Greek
    "ⅰ" "ⅼ" "ⅽ" "ⅾ" "ⅿ"  # Roman numerals
)

# Enhanced API Key and Secret Patterns
declare -a API_KEY_PATTERNS=(
    # AWS
    "AKIA[0-9A-Z]{16}"
    "aws.*secret.*key"
    # GitHub
    "ghp_[0-9a-zA-Z]{36}"
    "github.*token"
    # Google
    "AIza[0-9A-Za-z_-]{35}"
    # Stripe
    "sk_live_[0-9a-zA-Z]{24,}"
    "pk_live_[0-9a-zA-Z]{24,}"
    # Generic patterns
    "api[_-]?key['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z_-]{20,}"
    "secret[_-]?key['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z_-]{20,}"
    "access[_-]?token['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z_-]{20,}"
    "auth[_-]?token['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z_-]{20,}"
    # Private keys
    "-----BEGIN.*PRIVATE KEY-----"
    # JWT tokens
    "eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
)

################################################################################
# THREAT INTELLIGENCE INTEGRATION
################################################################################

# Known malicious IOC database
declare -A KNOWN_MALICIOUS_DOMAINS
declare -A KNOWN_MALICIOUS_IPS
declare -A KNOWN_MALICIOUS_HASHES
declare -A KNOWN_CRYPTO_SCAM_ADDRESSES

load_threat_intelligence() {
    log_info "Loading threat intelligence feeds..."
    
    # Load from local IOC files if they exist
    if [ -f "${SCRIPT_DIR}/ioc_domains.txt" ]; then
        while IFS= read -r domain; do
            [[ -n "$domain" && ! "$domain" =~ ^# ]] && KNOWN_MALICIOUS_DOMAINS["$domain"]=1
        done < "${SCRIPT_DIR}/ioc_domains.txt"
    fi
    
    if [ -f "${SCRIPT_DIR}/ioc_ips.txt" ]; then
        while IFS= read -r ip; do
            [[ -n "$ip" && ! "$ip" =~ ^# ]] && KNOWN_MALICIOUS_IPS["$ip"]=1
        done < "${SCRIPT_DIR}/ioc_ips.txt"
    fi
    
    if [ -f "${SCRIPT_DIR}/ioc_crypto.txt" ]; then
        while IFS= read -r addr; do
            [[ -n "$addr" && ! "$addr" =~ ^# ]] && KNOWN_CRYPTO_SCAM_ADDRESSES["$addr"]=1
        done < "${SCRIPT_DIR}/ioc_crypto.txt"
    fi
    
    # Load OpenPhish feed
    load_openphish_feed
    
    # Load Abuse.ch feeds
    load_abuseч_feeds
    
    # Load AlienVault OTX indicators
    load_alienvault_otx
    
    log_success "Threat intelligence loaded: ${#KNOWN_MALICIOUS_DOMAINS[@]} domains, ${#KNOWN_MALICIOUS_IPS[@]} IPs, ${#KNOWN_CRYPTO_SCAM_ADDRESSES[@]} crypto addresses"
}

load_openphish_feed() {
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Loading OpenPhish threat feed..."
    local openphish_file="${TEMP_DIR}/openphish_feed.txt"
    
    if curl -sL --max-time 10 "https://openphish.com/feed.txt" -o "$openphish_file" 2>/dev/null; then
        while IFS= read -r url; do
            local domain=$(echo "$url" | awk -F/ '{print $3}')
            [[ -n "$domain" ]] && KNOWN_MALICIOUS_DOMAINS["$domain"]=1
        done < "$openphish_file"
        log_success "OpenPhish feed loaded: $(wc -l < "$openphish_file") entries"
    else
        log_warning "Failed to load OpenPhish feed"
    fi
}

load_abuseч_feeds() {
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Loading Abuse.ch threat feeds..."
    
    # URLhaus
    local urlhaus_file="${TEMP_DIR}/urlhaus_feed.txt"
    if curl -sL --max-time 10 "https://urlhaus.abuse.ch/downloads/text/" -o "$urlhaus_file" 2>/dev/null; then
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            local domain=$(echo "$line" | awk -F/ '{print $3}')
            [[ -n "$domain" ]] && KNOWN_MALICIOUS_DOMAINS["$domain"]=1
        done < "$urlhaus_file"
        log_success "URLhaus feed loaded"
    fi
    
    # SSL Blacklist
    local sslbl_file="${TEMP_DIR}/sslbl_ips.txt"
    if curl -sL --max-time 10 "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" -o "$sslbl_file" 2>/dev/null; then
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -n "$line" ]] && KNOWN_MALICIOUS_IPS["$line"]=1
        done < "$sslbl_file"
        log_success "SSL Blacklist loaded"
    fi
}

load_alienvault_otx() {
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Loading AlienVault OTX indicators..."
    # This would require API key and proper implementation
    # Placeholder for future enhancement
    log_warning "AlienVault OTX integration pending (requires API key)"
}

################################################################################
# YARA-STYLE RULE ENGINE
################################################################################

declare -A YARA_RULES

init_yara_rules() {
    # Rule 1: Phishing URL patterns
    YARA_RULES["phishing_url"]='
        strings:
            $login = /login|signin|verify|account|update/i
            $urgent = /urgent|suspended|action.*required/i
            $brand = /paypal|amazon|netflix|microsoft|apple/i
        condition:
            ($login and $urgent) or ($brand and $urgent)
        severity: HIGH
    '
    
    # Rule 2: Malware distribution
    YARA_RULES["malware_distribution"]='
        strings:
            $exe = /\.(exe|dll|scr|bat|cmd)/i
            $mobile = /\.(apk|ipa|mobileconfig)/i
            $download = /download|install|update/i
        condition:
            ($exe or $mobile) and $download
        severity: CRITICAL
    '
    
    # Rule 3: Cryptocurrency scam
    YARA_RULES["crypto_scam"]='
        strings:
            $btc = /bc1[a-z0-9]{39,87}|1[a-km-zA-HJ-NP-Z1-9]{25,34}/
            $eth = /0x[a-fA-F0-9]{40}/
            $urgency = /limited|exclusive|guaranteed|double|invest/i
        condition:
            ($btc or $eth) and $urgency
        severity: HIGH
    '
    
    # Rule 4: WiFi credential theft
    YARA_RULES["wifi_theft"]='
        strings:
            $wifi = "WIFI:"
            $open = "T:nopass" or "T:None" or "T:"
        condition:
            $wifi
        severity: MEDIUM
    '
    
    # Rule 5: Session hijacking QR
    YARA_RULES["session_hijack"]='
        strings:
            $whatsapp = "whatsapp.com"
            $discord = "discord.com/login"
            $token = "token=" or "session=" or "auth="
        condition:
            ($whatsapp or $discord) and $token
        severity: CRITICAL
    '
}

evaluate_yara_rule() {
    local content="$1"
    local rule_name="$2"
    local rule="${YARA_RULES[$rule_name]}"
    
    # Simple rule evaluation (bash implementation)
    # In production, use actual YARA
    local matched=false
    
    case "$rule_name" in
        "phishing_url")
            if echo "$content" | grep -qi "login\|signin\|verify" && \
               echo "$content" | grep -qi "urgent\|suspended"; then
                matched=true
            fi
            ;;
        "malware_distribution")
            if echo "$content" | grep -qi "\\.exe\\|\\.apk\\|\\.mobileconfig" && \
               echo "$content" | grep -qi "download\|install"; then
                matched=true
            fi
            ;;
        "crypto_scam")
            if echo "$content" | grep -qE "bc1[a-z0-9]{39,87}|1[a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}" && \
               echo "$content" | grep -qi "limited\|exclusive\|invest"; then
                matched=true
            fi
            ;;
    esac
    
    echo "$matched"
}

################################################################################
# MULTI-DECODER SYSTEM
################################################################################

decode_with_zbar() {
    local image="$1"
    local output_file="$2"
    
    zbarimg --quiet --raw "$image" 2>/dev/null | while IFS= read -r line; do
        echo "$line" >> "$output_file"
    done
    
    [ -s "$output_file" ]
}

decode_with_pyzbar() {
    local image="$1"
    local output_file="$2"
    
    python3 << EOF 2>/dev/null
from PIL import Image
from pyzbar.pyzbar import decode

try:
    img = Image.open('$image')
    codes = decode(img)
    with open('$output_file', 'w') as f:
        for code in codes:
            try:
                data = code.data.decode('utf-8')
                f.write(data + '\n')
            except:
                data = code.data.decode('latin-1')
                f.write(data + '\n')
except Exception as e:
    pass
EOF
    
    [ -s "$output_file" ]
}

decode_with_quirc() {
    local image="$1"
    local output_file="$2"
    
    # Quirc decoder if available
    if command -v quirc &> /dev/null; then
        quirc "$image" 2>/dev/null > "$output_file"
        [ -s "$output_file" ]
    else
        return 1
    fi
}

decode_with_zxing() {
    local image="$1"
    local output_file="$2"
    
    # ZXing decoder if available (CLI)
    if command -v zxing &> /dev/null; then
        zxing "$image" 2>/dev/null > "$output_file"
        [ -s "$output_file" ]
    else
        return 1
    fi
}

decode_with_qrdecode() {
    local image="$1"
    local output_file="$2"
    
    # qrdecode from libqrencode - can read damaged QRs
    if command -v qrdecode &> /dev/null; then
        qrdecode "$image" 2>/dev/null > "$output_file"
        [ -s "$output_file" ]
    else
        return 1
    fi
}

decode_with_opencv() {
    local image="$1"
    local output_file="$2"
    
    # OpenCV decoder for advanced geometric/denoising
    python3 << EOF 2>/dev/null
try:
    import cv2
    import numpy as np
    
    img = cv2.imread('$image')
    detector = cv2.QRCodeDetector()
    
    # Try normal detection
    data, bbox, _ = detector.detectAndDecode(img)
    
    if data:
        with open('$output_file', 'w') as f:
            f.write(data + '\n')
    else:
        # Try with preprocessing for damaged QRs
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        denoised = cv2.fastNlMeansDenoising(gray)
        data, bbox, _ = detector.detectAndDecode(denoised)
        
        if data:
            with open('$output_file', 'w') as f:
                f.write(data + '\n')
except Exception as e:
    pass
EOF
    
    [ -s "$output_file" ]
}

multi_decoder_analysis() {
    local image="$1"
    local base_output="$2"
    
    log_info "Attempting multi-decoder analysis on $image..."
    
    local decoders=("zbar" "pyzbar" "quirc" "zxing" "qrdecode" "opencv")
    local success_count=0
    local all_decoded=""
    
    for decoder in "${decoders[@]}"; do
        local decoder_output="${base_output}_${decoder}.txt"
        
        case "$decoder" in
            "zbar")
                decode_with_zbar "$image" "$decoder_output" && ((success_count++))
                ;;
            "pyzbar")
                decode_with_pyzbar "$image" "$decoder_output" && ((success_count++))
                ;;
            "quirc")
                decode_with_quirc "$image" "$decoder_output" && ((success_count++))
                ;;
            "zxing")
                decode_with_zxing "$image" "$decoder_output" && ((success_count++))
                ;;
            "qrdecode")
                decode_with_qrdecode "$image" "$decoder_output" && ((success_count++))
                ;;
            "opencv")
                decode_with_opencv "$image" "$decoder_output" && ((success_count++))
                ;;
        esac
        
        if [ -s "$decoder_output" ]; then
            log_success "  ✓ $decoder: decoded successfully"
            all_decoded+=$(cat "$decoder_output")$'\n'
        else
            log_warning "  ✗ $decoder: failed to decode"
        fi
    done
    
    # Check for decoder inconsistencies (potential evasion)
    if [ $success_count -gt 0 ] && [ $success_count -lt ${#decoders[@]} ]; then
        log_threat 20 "Decoder inconsistency detected - possible evasion technique"
    fi
    
    echo "$all_decoded" | sort -u > "${base_output}_merged.txt"
    
    return $([ $success_count -gt 0 ])
}

################################################################################
# ADVANCED URL ANALYSIS
################################################################################

analyze_url_structure() {
    local url="$1"
    local threats=0
    
    log_info "Deep URL analysis: $url"
    
    # Extract components
    local protocol=$(echo "$url" | grep -oP '^[a-z]+(?=:)')
    local domain=$(echo "$url" | awk -F/ '{print $3}')
    local path=$(echo "$url" | sed 's|^[^/]*//[^/]*/||')
    
    # Check for non-HTTP protocols
    if [[ ! "$protocol" =~ ^https?$ ]] && [ -n "$protocol" ]; then
        log_threat 15 "Non-HTTP protocol detected: $protocol"
        ((threats++))
    fi
    
    # Check for IP-based URLs
    if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_threat 25 "IP-based URL detected (suspicious): $domain"
        ((threats++))
    fi
    
    # Check for suspicious ports
    if [[ "$domain" =~ :[0-9]+$ ]]; then
        local port=$(echo "$domain" | grep -oP ':[0-9]+$' | tr -d ':')
        if [[ ! "$port" =~ ^(80|443|8080|8443)$ ]]; then
            log_threat 10 "Unusual port detected: $port"
            ((threats++))
        fi
    fi
    
    # Check domain against known malicious list
    local clean_domain=$(echo "$domain" | sed 's/:[0-9]*$//')
    if [ -n "${KNOWN_MALICIOUS_DOMAINS[$clean_domain]}" ]; then
        log_threat 100 "KNOWN MALICIOUS DOMAIN: $clean_domain"
        ((threats++))
    fi
    
    # Check for URL shorteners
    for shortener in "${URL_SHORTENERS[@]}"; do
        if echo "$domain" | grep -qE "$shortener"; then
            log_threat 20 "URL shortener detected: $domain"
            ((threats++))
            
            # Attempt to resolve redirect
            resolve_url_redirect "$url"
            break
        fi
    done
    
    # Check for suspicious TLDs
    for tld in "${SUSPICIOUS_TLDS[@]}"; do
        if echo "$domain" | grep -qE "$tld\$"; then
            log_threat 30 "Suspicious TLD detected: $tld"
            ((threats++))
            break
        fi
    done
    
    # Check for homograph attacks (IDN spoofing)
    check_homograph_attack "$domain"
    
    # Check for typosquatting
    check_typosquatting "$domain"
    
    # Analyze path for suspicious patterns
    for pattern in "${SUSPICIOUS_URL_PATTERNS[@]}"; do
        if echo "$path" | grep -qiE "$pattern"; then
            log_threat 15 "Suspicious URL pattern: $pattern in $path"
            ((threats++))
        fi
    done
    
    # Check for encoded parameters
    if echo "$url" | grep -qE "%[0-9a-fA-F]{2}"; then
        log_warning "URL contains encoded characters - analyzing..."
        local decoded_url=$(python3 -c "import urllib.parse; print(urllib.parse.unquote('$url'))" 2>/dev/null)
        if [ "$url" != "$decoded_url" ]; then
            log_info "Decoded URL: $decoded_url"
            # Recursively analyze decoded URL
            analyze_url_structure "$decoded_url"
        fi
    fi
    
    # Perform WHOIS lookup for domain age
    check_domain_whois "$clean_domain"
    
    return $threats
}

resolve_url_redirect() {
    local url="$1"
    
    if [ "$NETWORK_CHECK" = false ]; then
        log_warning "Network check disabled - skipping redirect resolution"
        return
    fi
    
    log_info "Resolving redirects for: $url"
    
    local redirect_chain=$(curl -sIL -w "%{url_effective}\n" -o /dev/null "$url" 2>/dev/null)
    
    if [ -n "$redirect_chain" ] && [ "$redirect_chain" != "$url" ]; then
        log_warning "Redirect chain detected:"
        echo "$redirect_chain"
        
        # Analyze final destination
        analyze_url_structure "$redirect_chain"
    fi
}

check_homograph_attack() {
    local domain="$1"
    
    # Check for mixed scripts
    local has_latin=$(echo "$domain" | grep -P '[a-zA-Z]' | wc -l)
    local has_cyrillic=$(echo "$domain" | grep -P '[а-яА-ЯёЁ]' | wc -l)
    local has_greek=$(echo "$domain" | grep -P '[α-ωΑ-Ω]' | wc -l)
    
    if [ $has_latin -gt 0 ] && ([ $has_cyrillic -gt 0 ] || [ $has_greek -gt 0 ]); then
        log_threat 50 "HOMOGRAPH ATTACK DETECTED: Mixed character sets in domain"
    fi
    
    # Check for lookalike characters
    for char in "${HOMOGRAPH_CHARS[@]}"; do
        if echo "$domain" | grep -qF "$char"; then
            log_threat 40 "Homograph character detected: $char in $domain"
        fi
    done
    
    # Check for punycode (xn--)
    if echo "$domain" | grep -qE 'xn--'; then
        log_threat 30 "Punycode domain detected (potential IDN spoofing): $domain"
        
        # Try to decode punycode
        local decoded=$(python3 -c "print('$domain'.encode('ascii').decode('idna'))" 2>/dev/null)
        [ -n "$decoded" ] && log_info "Decoded IDN: $decoded"
    fi
}

check_typosquatting() {
    local domain="$1"
    
    # Check against known brands
    for brand in "${PHISHING_BRANDS[@]}"; do
        if echo "$domain" | grep -qiE "$brand"; then
            # Check for common typosquatting patterns
            if echo "$domain" | grep -qiE "${brand}[0-9]|${brand}-|${brand}_|${brand}\."; then
                log_threat 35 "Potential typosquatting of $brand: $domain"
            fi
            
            # Check for character substitution
            if echo "$domain" | grep -qiE "${brand/o/0}|${brand/i/1}|${brand/l/1}|${brand/a/4}"; then
                log_threat 40 "Character substitution typosquatting detected: $domain"
            fi
        fi
    done
}

check_domain_whois() {
    local domain="$1"
    
    if ! command -v whois &> /dev/null; then
        return
    fi
    
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking WHOIS information for: $domain"
    
    local whois_file="${TEMP_DIR}/whois_${domain}.txt"
    whois "$domain" > "$whois_file" 2>/dev/null || return
    
    # Check domain age
    local creation_date=$(grep -i "Creation Date\|Registered" "$whois_file" | head -1)
    if [ -n "$creation_date" ]; then
        log_info "  Domain registration: $creation_date"
        
        # Check if domain is very new (less than 30 days)
        if echo "$creation_date" | grep -qE "$(date -v-30d +%Y-%m 2>/dev/null || date -d '30 days ago' +%Y-%m)"; then
            log_threat 25 "Very recently registered domain (less than 30 days old)"
        fi
    fi
    
    # Check registrar
    local registrar=$(grep -i "Registrar:" "$whois_file" | head -1)
    [ -n "$registrar" ] && log_info "  $registrar"
}

################################################################################
# DEEP LINK ANALYSIS
################################################################################

analyze_deep_links() {
    local content="$1"
    
    log_info "Analyzing deep links and app URL schemes..."
    
    for scheme in "${DEEPLINK_SCHEMES[@]}"; do
        if echo "$content" | grep -qiE "^$scheme"; then
            log_threat 25 "Deep link detected: $scheme"
            
            # Extract and analyze parameters
            local params=$(echo "$content" | sed "s/^$scheme//" | tr '&' '\n')
            echo "$params" | while read -r param; do
                log_info "  Parameter: $param"
                
                # Check for suspicious parameters
                if echo "$param" | grep -qiE "token=|auth=|session=|key="; then
                    log_threat 30 "Sensitive parameter in deep link: $param"
                fi
            done
        fi
    done
}

################################################################################
# CRYPTOCURRENCY ANALYSIS
################################################################################

analyze_crypto_addresses() {
    local content="$1"
    
    log_info "Scanning for cryptocurrency addresses..."
    
    local crypto_found=false
    
    for pattern in "${CRYPTO_PATTERNS[@]}"; do
        local matches=$(echo "$content" | grep -oE "$pattern")
        
        if [ -n "$matches" ]; then
            crypto_found=true
            echo "$matches" | while read -r address; do
                log_threat 40 "Cryptocurrency address detected: $address"
                
                # Check against known scam addresses
                if [ -n "${KNOWN_CRYPTO_SCAM_ADDRESSES[$address]}" ]; then
                    log_threat 100 "KNOWN SCAM ADDRESS DETECTED: $address"
                fi
                
                # Log to IOC report
                echo "CRYPTO_ADDRESS,$address,$(date -Iseconds)" >> "$IOC_REPORT"
            done
        fi
    done
    
    if [ "$crypto_found" = true ]; then
        # Check for social engineering around crypto
        if echo "$content" | grep -qiE "send|transfer|invest|giveaway|double|airdrop"; then
            log_threat 35 "Crypto + social engineering keywords detected"
        fi
    fi
}

################################################################################
# WIFI CREDENTIAL ANALYSIS
################################################################################

analyze_wifi_payload() {
    local content="$1"
    
    if ! echo "$content" | grep -qE "^WIFI:"; then
        return
    fi
    
    log_info "Analyzing WiFi QR code..."
    
    # Extract components
    local ssid=$(echo "$content" | grep -oP 'S:\K[^;]+')
    local password=$(echo "$content" | grep -oP 'P:\K[^;]+')
    local encryption=$(echo "$content" | grep -oP 'T:\K[^;]+')
    local hidden=$(echo "$content" | grep -oP 'H:\K[^;]+')
    
    log_info "  SSID: $ssid"
    log_info "  Encryption: ${encryption:-none}"
    log_info "  Hidden: ${hidden:-false}"
    
    # Check for open/weak networks
    if [ -z "$encryption" ] || [[ "$encryption" =~ ^(nopass|None|WEP)$ ]]; then
        log_threat 30 "Weak/no encryption on WiFi: $encryption"
    fi
    
    # Check for suspicious SSIDs
    if echo "$ssid" | grep -qiE "free|public|guest|open|airport|hotel|starbucks"; then
        log_threat 25 "Suspicious SSID pattern (possible evil twin): $ssid"
    fi
    
    # Check for hidden network (potential rogue AP)
    if [ "$hidden" = "true" ]; then
        log_threat 20 "Hidden network detected"
    fi
}

################################################################################
# MOBILE CONFIGURATION PROFILE ANALYSIS
################################################################################

analyze_mobile_config() {
    local content="$1"
    
    log_info "Checking for mobile configuration profiles..."
    
    for pattern in "${MOBILE_CONFIG_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            log_threat 50 "Mobile configuration profile indicator detected: $pattern"
            
            # If it's a URL, attempt to download and analyze
            if echo "$content" | grep -qiE "^https?://.*\.mobileconfig$"; then
                log_critical "mobileconfig profile download URL detected - HIGH RISK"
                
                if [ "$NETWORK_CHECK" = true ]; then
                    download_and_analyze_mobileconfig "$content"
                fi
            fi
        fi
    done
}

download_and_analyze_mobileconfig() {
    local url="$1"
    local profile_file="${TEMP_DIR}/suspicious_profile.mobileconfig"
    
    log_warning "Downloading mobile config profile for analysis..."
    
    if curl -sL --max-time 10 "$url" -o "$profile_file" 2>/dev/null; then
        log_success "Profile downloaded to $profile_file"
        
        # Analyze the plist
        if command -v plutil &> /dev/null; then
            plutil -p "$profile_file" > "${profile_file}.txt" 2>/dev/null
            
            # Check for dangerous payloads
            if grep -qi "VPN\|Root.*Certificate\|MDM\|SCEP" "${profile_file}.txt"; then
                log_threat 80 "CRITICAL: Dangerous mobile config payload detected (VPN/Root Cert/MDM)"
            fi
        fi
        
        # Store as evidence
        cp "$profile_file" "$EVIDENCE_DIR/"
    else
        log_error "Failed to download profile"
    fi
}

################################################################################
# SCRIPT INJECTION DETECTION
################################################################################

analyze_script_injection() {
    local content="$1"
    
    log_info "Scanning for script injection patterns..."
    
    for pattern in "${SCRIPT_INJECTION_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            log_threat 45 "Script injection pattern detected: $pattern"
            
            # Extract and log the context
            local context=$(echo "$content" | grep -ioE ".{0,50}${pattern}.{0,50}" | head -1)
            log_warning "  Context: $context"
        fi
    done
    
    # Check for obfuscated JavaScript
    if echo "$content" | grep -qE "eval\(|Function\(.*\)"; then
        log_threat 40 "Potentially obfuscated JavaScript detected"
    fi
    
    # Check for data URIs
    if echo "$content" | grep -qE "data:text/html|data:application"; then
        log_threat 35 "Data URI detected (potential payload embedding)"
    fi
}

################################################################################
# SOCIAL ENGINEERING DETECTION
################################################################################

analyze_social_engineering() {
    local content="$1"
    
    log_info "Analyzing for social engineering tactics..."
    
    local se_score=0
    
    for keyword in "${SOCIAL_ENGINEERING_KEYWORDS[@]}"; do
        if echo "$content" | grep -qiE "$keyword"; then
            log_threat 15 "Social engineering keyword: $keyword"
            ((se_score += 15))
        fi
    done
    
    # Check for urgency + action combination
    if echo "$content" | grep -qiE "urgent|immediate|now" && \
       echo "$content" | grep -qiE "click|verify|confirm|update"; then
        log_threat 25 "Urgency + action request detected (classic phishing)"
        ((se_score += 25))
    fi
    
    # Check for brand impersonation
    for brand in "${PHISHING_BRANDS[@]}"; do
        if echo "$content" | grep -qiE "$brand"; then
            log_warning "Brand name detected: $brand (verify legitimacy)"
            ((se_score += 10))
        fi
    done
    
    if [ $se_score -gt 50 ]; then
        log_threat 30 "HIGH social engineering score: $se_score"
    fi
}

################################################################################
# STEGANOGRAPHY DETECTION
################################################################################

analyze_steganography() {
    local image="$1"
    local base_name="$2"
    
    log_info "Analyzing image for steganography..."
    
    # Create edge detection image
    if command -v convert &> /dev/null; then
        local edge_file="${EVIDENCE_DIR}/${base_name}_edge.png"
        convert "$image" -normalize -edge 1 "$edge_file" 2>/dev/null
        log_success "Edge detection saved: $edge_file"
        
        # Create multiple enhancement views
        convert "$image" -equalize "${EVIDENCE_DIR}/${base_name}_equalized.png" 2>/dev/null
        convert "$image" -contrast-stretch 0 "${EVIDENCE_DIR}/${base_name}_contrast.png" 2>/dev/null
    fi
    
    # Advanced steganography detection
    detect_steghide "$image" "$base_name"
    detect_zsteg "$image" "$base_name"
    detect_stegdetect "$image" "$base_name"
    
    # Check for LSB steganography indicators
    if command -v xxd &> /dev/null; then
        local hex_analysis="${TEMP_DIR}/${base_name}_hex.txt"
        xxd "$image" | tail -n 1000 > "$hex_analysis"
        
        # Look for patterns in LSBs
        if grep -qE "([0-9a-f]{2} ){16,}" "$hex_analysis"; then
            log_warning "Potential LSB steganography pattern detected"
        fi
    fi
    
    # Check file size anomalies
    local file_size=$(stat -f%z "$image" 2>/dev/null || stat -c%s "$image" 2>/dev/null)
    local expected_size=$((300 * 300))  # Rough estimate for QR code
    
    if [ $file_size -gt $((expected_size * 3)) ]; then
        log_threat 20 "Unusually large file size for QR code: ${file_size} bytes"
    fi
    
    # Image entropy analysis
    analyze_image_entropy "$image" "$base_name"
    
    # Check for multiple embedded QR codes
    detect_multiple_qr_codes "$image"
}

detect_steghide() {
    local image="$1"
    local base_name="$2"
    
    if ! command -v steghide &> /dev/null; then
        return
    fi
    
    log_info "Running steghide analysis..."
    local steg_report="${EVIDENCE_DIR}/${base_name}_steghide.txt"
    
    # Try to extract without password
    steghide extract -sf "$image" -xf "${TEMP_DIR}/${base_name}_extracted.bin" -p "" 2>&1 | tee "$steg_report"
    
    if grep -q "extracted" "$steg_report"; then
        log_threat 60 "STEGANOGRAPHY DETECTED: Hidden data extracted by steghide"
    fi
}

detect_zsteg() {
    local image="$1"
    local base_name="$2"
    
    if ! command -v zsteg &> /dev/null; then
        return
    fi
    
    log_info "Running zsteg analysis (PNG)..."
    local zsteg_report="${EVIDENCE_DIR}/${base_name}_zsteg.txt"
    
    zsteg "$image" --all 2>/dev/null > "$zsteg_report"
    
    if [ -s "$zsteg_report" ] && grep -q "text" "$zsteg_report"; then
        log_threat 50 "STEGANOGRAPHY DETECTED: zsteg found hidden text"
        log_info "See: $zsteg_report"
    fi
}

detect_stegdetect() {
    local image="$1"
    local base_name="$2"
    
    if ! command -v stegdetect &> /dev/null; then
        return
    fi
    
    log_info "Running stegdetect analysis..."
    local stegdetect_report="${EVIDENCE_DIR}/${base_name}_stegdetect.txt"
    
    stegdetect "$image" 2>/dev/null > "$stegdetect_report"
    
    if [ -s "$stegdetect_report" ] && ! grep -q "negative" "$stegdetect_report"; then
        log_threat 55 "STEGANOGRAPHY DETECTED: stegdetect found indicators"
        log_info "See: $stegdetect_report"
    fi
}

analyze_image_entropy() {
    local image="$1"
    local base_name="$2"
    
    log_info "Analyzing image entropy..."
    
    python3 << EOF 2>/dev/null
import numpy as np
from PIL import Image
from collections import Counter
import math

try:
    img = Image.open('$image')
    img_array = np.array(img)
    
    # Calculate entropy for each channel
    if len(img_array.shape) == 3:
        for i, channel in enumerate(['Red', 'Green', 'Blue']):
            channel_data = img_array[:,:,i].flatten()
            counter = Counter(channel_data)
            total = len(channel_data)
            entropy = -sum((count/total) * math.log2(count/total) for count in counter.values())
            print(f"  {channel} channel entropy: {entropy:.2f}")
            
            if entropy > 7.5:
                print(f"  [!] High entropy in {channel} channel - possible hidden data")
    else:
        # Grayscale
        flat_data = img_array.flatten()
        counter = Counter(flat_data)
        total = len(flat_data)
        entropy = -sum((count/total) * math.log2(count/total) for count in counter.values())
        print(f"  Grayscale entropy: {entropy:.2f}")
        
        if entropy > 7.5:
            print(f"  [!] High entropy - possible hidden data")
            
except Exception as e:
    print(f"  Error analyzing image entropy: {e}")
EOF
}

detect_multiple_qr_codes() {
    local image="$1"
    
    log_info "Checking for multiple/split QR codes..."
    
    # Use zbarimg to detect all codes
    local num_codes=$(zbarimg "$image" 2>/dev/null | grep -c "QR-Code")
    
    if [ "$num_codes" -gt 1 ]; then
        log_threat 35 "Multiple QR codes detected in single image: $num_codes codes"
        log_warning "This could indicate split-QR evasion technique"
    fi
    
    # Try to detect split QR by analyzing image quadrants
    if command -v convert &> /dev/null; then
        local width=$(identify -format "%w" "$image" 2>/dev/null)
        local height=$(identify -format "%h" "$image" 2>/dev/null)
        
        if [ -n "$width" ] && [ -n "$height" ]; then
            # Split into quadrants and analyze each
            for quad in "northwest" "northeast" "southwest" "southeast"; do
                local quad_file="${TEMP_DIR}/quad_${quad}.png"
                convert "$image" -gravity "$quad" -crop 50%x50%+0+0 "$quad_file" 2>/dev/null
                
                if zbarimg "$quad_file" 2>/dev/null | grep -q "QR-Code"; then
                    log_info "QR code found in quadrant: $quad"
                fi
            done
        fi
    fi
}

################################################################################
# OCR ANALYSIS
################################################################################

analyze_with_ocr() {
    local image="$1"
    local base_name="$2"
    
    if ! command -v tesseract &> /dev/null; then
        return
    fi
    
    log_info "Running OCR analysis (Tesseract)..."
    local ocr_file="${EVIDENCE_DIR}/${base_name}_ocr.txt"
    
    tesseract "$image" "${ocr_file%.txt}" 2>/dev/null
    
    if [ -s "$ocr_file" ]; then
        log_info "OCR text extracted to: $ocr_file"
        
        # Analyze OCR text for overlays/hidden text
        local ocr_content=$(cat "$ocr_file")
        
        if [ -n "$ocr_content" ]; then
            log_warning "Text overlay detected via OCR - analyzing..."
            
            # Check for phishing keywords in overlay
            for keyword in "${SOCIAL_ENGINEERING_KEYWORDS[@]}"; do
                if echo "$ocr_content" | grep -qiE "$keyword"; then
                    log_threat 20 "Phishing keyword in text overlay: $keyword"
                fi
            done
        fi
    fi
}

################################################################################
# METADATA ANALYSIS
################################################################################

analyze_metadata() {
    local image="$1"
    local base_name="$2"
    
    log_info "Extracting and analyzing metadata..."
    
    if command -v exiftool &> /dev/null; then
        local meta_file="${EVIDENCE_DIR}/${base_name}_metadata.txt"
        exiftool "$image" > "$meta_file" 2>/dev/null
        
        log_success "Metadata extracted to: $meta_file"
        
        # Check for suspicious metadata
        if grep -qiE "Photoshop|GIMP|edited|modified" "$meta_file"; then
            log_warning "Image appears to have been edited (potential tampering)"
        fi
        
        # Extract creation date
        local create_date=$(grep -i "Create Date" "$meta_file" | head -1)
        [ -n "$create_date" ] && log_info "  $create_date"
        
        # Check for GPS coordinates
        if grep -qi "GPS Position" "$meta_file"; then
            log_warning "GPS coordinates embedded in image"
            grep -i "GPS Position" "$meta_file"
        fi
        
        # Check for comments or descriptions
        if grep -qiE "Comment|Description|User Comment" "$meta_file"; then
            log_info "Metadata comments found:"
            grep -iE "Comment|Description|User Comment" "$meta_file"
        fi
    else
        # Fallback to basic file command
        file "$image" | tee -a "$REPORT_FILE"
    fi
}

################################################################################
# HASH AND SIGNATURE ANALYSIS
################################################################################

compute_hashes() {
    local file="$1"
    local base_name="$2"
    
    log_info "Computing file hashes..."
    
    local hash_file="${EVIDENCE_DIR}/${base_name}_hashes.txt"
    
    {
        echo "=== File Hashes for $file ==="
        echo "MD5:    $(md5 -q "$file" 2>/dev/null || md5sum "$file" | awk '{print $1}')"
        echo "SHA1:   $(shasum -a 1 "$file" | awk '{print $1}')"
        echo "SHA256: $(shasum -a 256 "$file" | awk '{print $1}')"
        
        if command -v ssdeep &> /dev/null; then
            echo "SSDeep: $(ssdeep -b "$file" | tail -1)"
        fi
    } | tee "$hash_file" | tee -a "$REPORT_FILE"
    
    # Check hash against known malicious hashes
    local sha256=$(shasum -a 256 "$file" | awk '{print $1}')
    if [ -n "${KNOWN_MALICIOUS_HASHES[$sha256]}" ]; then
        log_threat 100 "KNOWN MALICIOUS FILE HASH DETECTED!"
    fi
    
    # Check file hash on VirusTotal
    if [ "$VT_CHECK" = true ]; then
        check_virustotal_file_hash "$sha256"
    fi
}

################################################################################
# NETWORK THREAT INTELLIGENCE
################################################################################

check_virustotal() {
    local url="$1"
    
    if [ -z "$VT_API_KEY" ]; then
        log_warning "VirusTotal API key not set (set VT_API_KEY environment variable)"
        return
    fi
    
    if [ "$VT_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking VirusTotal for: $url"
    
    # Submit URL
    local vt_response=$(curl -s --request POST \
        --url "https://www.virustotal.com/api/v3/urls" \
        --header "x-apikey: $VT_API_KEY" \
        --form "url=$url")
    
    local analysis_id=$(echo "$vt_response" | jq -r '.data.id' 2>/dev/null)
    
    if [ -z "$analysis_id" ] || [ "$analysis_id" = "null" ]; then
        log_error "VirusTotal submission failed"
        return
    fi
    
    log_success "VirusTotal analysis ID: $analysis_id"
    
    # Wait a bit for analysis
    sleep 2
    
    # Get results
    local vt_result=$(curl -s --request GET \
        --url "https://www.virustotal.com/api/v3/analyses/$analysis_id" \
        --header "x-apikey: $VT_API_KEY")
    
    local malicious=$(echo "$vt_result" | jq -r '.data.attributes.stats.malicious' 2>/dev/null)
    local suspicious=$(echo "$vt_result" | jq -r '.data.attributes.stats.suspicious' 2>/dev/null)
    
    if [ "$malicious" != "null" ] && [ "$malicious" != "0" ]; then
        log_threat 80 "VirusTotal: $malicious engines flagged as MALICIOUS"
    fi
    
    if [ "$suspicious" != "null" ] && [ "$suspicious" != "0" ]; then
        log_threat 30 "VirusTotal: $suspicious engines flagged as SUSPICIOUS"
    fi
    
    if [ "$malicious" = "0" ] && [ "$suspicious" = "0" ]; then
        log_success "VirusTotal: Clean (0 detections)"
    fi
    
    # Save full report
    echo "$vt_result" | jq '.' > "${EVIDENCE_DIR}/virustotal_report.json" 2>/dev/null
}

check_virustotal_file_hash() {
    local hash="$1"
    
    if [ -z "$VT_API_KEY" ]; then
        return
    fi
    
    log_info "Checking VirusTotal for file hash: $hash"
    
    local vt_result=$(curl -s --request GET \
        --url "https://www.virustotal.com/api/v3/files/$hash" \
        --header "x-apikey: $VT_API_KEY")
    
    local malicious=$(echo "$vt_result" | jq -r '.data.attributes.last_analysis_stats.malicious' 2>/dev/null)
    
    if [ "$malicious" != "null" ] && [ "$malicious" != "0" ]; then
        log_threat 90 "VirusTotal FILE HASH: $malicious engines flagged as MALICIOUS"
        echo "$vt_result" | jq '.' > "${EVIDENCE_DIR}/virustotal_file_hash.json" 2>/dev/null
    fi
}

check_urlhaus() {
    local url="$1"
    
    log_info "Checking URLhaus database..."
    
    local urlhaus_response=$(curl -s -X POST "https://urlhaus-api.abuse.ch/v1/url/" \
        --data "url=$url" 2>/dev/null)
    
    local threat=$(echo "$urlhaus_response" | jq -r '.query_status' 2>/dev/null)
    
    if [ "$threat" = "ok" ]; then
        log_threat 90 "URL found in URLhaus malware database!"
        echo "$urlhaus_response" | jq '.' > "${EVIDENCE_DIR}/urlhaus_report.json" 2>/dev/null
    fi
}

check_phishtank() {
    local url="$1"
    
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking PhishTank database..."
    
    # PhishTank requires API key
    if [ -z "$PHISHTANK_API_KEY" ]; then
        log_warning "PhishTank API key not set (set PHISHTANK_API_KEY environment variable)"
        return
    fi
    
    local encoded_url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url'))")
    
    local phishtank_response=$(curl -s -X POST "https://checkurl.phishtank.com/checkurl/" \
        --data "url=${encoded_url}&format=json&app_key=${PHISHTANK_API_KEY}" 2>/dev/null)
    
    local in_database=$(echo "$phishtank_response" | jq -r '.results.in_database' 2>/dev/null)
    local verified=$(echo "$phishtank_response" | jq -r '.results.verified' 2>/dev/null)
    
    if [ "$in_database" = "true" ] && [ "$verified" = "true" ]; then
        log_threat 85 "URL found in PhishTank verified phishing database!"
        echo "$phishtank_response" | jq '.' > "${EVIDENCE_DIR}/phishtank_report.json" 2>/dev/null
    fi
}

check_openphish_direct() {
    local url="$1"
    
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking OpenPhish feed for URL..."
    
    if curl -sL --max-time 5 "https://openphish.com/feed.txt" 2>/dev/null | grep -qF "$url"; then
        log_threat 85 "URL found in OpenPhish phishing feed!"
    fi
}

check_alienvault_otx_domain() {
    local domain="$1"
    
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking AlienVault OTX for domain: $domain"
    
    local otx_response=$(curl -s --max-time 10 \
        "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general" 2>/dev/null)
    
    if [ -n "$otx_response" ]; then
        local pulse_count=$(echo "$otx_response" | jq -r '.pulse_info.count' 2>/dev/null)
        
        if [ "$pulse_count" != "null" ] && [ "$pulse_count" -gt 0 ]; then
            log_threat 60 "Domain found in $pulse_count AlienVault OTX threat pulses"
            echo "$otx_response" | jq '.' > "${EVIDENCE_DIR}/otx_report.json" 2>/dev/null
        fi
    fi
}

################################################################################
# CONTENT-TYPE AND FILE DOWNLOAD ANALYSIS
################################################################################

analyze_url_content_type() {
    local url="$1"
    
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking Content-Type for URL: $url"
    
    local headers=$(curl -sI --max-time 5 "$url" 2>/dev/null)
    local content_type=$(echo "$headers" | grep -i "^Content-Type:" | awk '{print $2}' | tr -d '\r')
    
    if [ -n "$content_type" ]; then
        log_info "  Content-Type: $content_type"
        
        # Check for executable content types
        if echo "$content_type" | grep -qiE "application/x-msdownload|application/x-msdos-program|application/exe|application/x-exe"; then
            log_threat 70 "CRITICAL: Executable content type detected: $content_type"
        fi
        
        # Check for APK
        if echo "$content_type" | grep -qiE "application/vnd.android.package-archive"; then
            log_threat 65 "CRITICAL: Android APK download detected"
        fi
        
        # Check for mobile config
        if echo "$content_type" | grep -qiE "application/x-apple-aspen-config"; then
            log_threat 60 "CRITICAL: iOS configuration profile detected"
        fi
        
        # Download and analyze file if suspicious
        if echo "$content_type" | grep -qiE "application|octet-stream"; then
            download_and_analyze_file "$url" "$content_type"
        fi
    fi
}

download_and_analyze_file() {
    local url="$1"
    local content_type="$2"
    
    log_warning "Downloading file for analysis..."
    
    local download_file="${TEMP_DIR}/downloaded_file"
    
    if curl -sL --max-time 15 "$url" -o "$download_file" 2>/dev/null; then
        local file_size=$(stat -f%z "$download_file" 2>/dev/null || stat -c%s "$download_file" 2>/dev/null)
        log_info "Downloaded file: $file_size bytes"
        
        # Analyze file type
        local file_type=$(file -b "$download_file")
        log_info "File type: $file_type"
        
        # Compute hashes
        local md5=$(md5 -q "$download_file" 2>/dev/null || md5sum "$download_file" | awk '{print $1}')
        local sha256=$(shasum -a 256 "$download_file" | awk '{print $1}')
        
        log_info "MD5: $md5"
        log_info "SHA256: $sha256"
        
        # Check hash on VirusTotal
        if [ "$VT_CHECK" = true ]; then
            check_virustotal_file_hash "$sha256"
        fi
        
        # Scan with strings for indicators
        if command -v strings &> /dev/null; then
            local strings_file="${EVIDENCE_DIR}/downloaded_file_strings.txt"
            strings "$download_file" > "$strings_file"
            
            # Check for API keys/secrets in file
            analyze_api_keys "$strings_file"
        fi
        
        # Save as evidence
        cp "$download_file" "${EVIDENCE_DIR}/downloaded_file_${sha256:0:16}"
    else
        log_error "Failed to download file"
    fi
}

################################################################################
# API KEY AND SECRET DETECTION
################################################################################

analyze_api_keys() {
    local content_source="$1"
    
    log_info "Scanning for API keys and secrets..."
    
    local content
    if [ -f "$content_source" ]; then
        content=$(cat "$content_source")
    else
        content="$content_source"
    fi
    
    for pattern in "${API_KEY_PATTERNS[@]}"; do
        local matches=$(echo "$content" | grep -oE "$pattern")
        
        if [ -n "$matches" ]; then
            echo "$matches" | while read -r key; do
                log_threat 50 "POTENTIAL API KEY/SECRET DETECTED: ${key:0:50}..."
                echo "API_KEY,${key:0:100},$(date -Iseconds)" >> "$IOC_REPORT"
            done
        fi
    done
}

################################################################################
# CONTENT ENTROPY ANALYSIS
################################################################################

calculate_entropy() {
    local content="$1"
    
    # Calculate Shannon entropy
    local entropy=$(python3 << EOF
import math
from collections import Counter

text = '''$content'''
if not text:
    print(0)
else:
    counter = Counter(text)
    length = len(text)
    entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
    print(f"{entropy:.2f}")
EOF
)
    
    echo "$entropy"
}

analyze_entropy() {
    local content="$1"
    
    local entropy=$(calculate_entropy "$content")
    
    log_info "Content entropy: $entropy bits"
    
    # High entropy might indicate encryption/encoding
    if (( $(echo "$entropy > 4.5" | bc -l 2>/dev/null || echo "0") )); then
        log_threat 20 "High entropy detected ($entropy) - possible encrypted/encoded content"
    fi
}

################################################################################
# BEHAVIORAL ANALYSIS
################################################################################

analyze_qr_behavior() {
    local content="$1"
    
    log_info "Performing behavioral analysis..."
    
    local behavior_score=0
    
    # Check for multi-stage attack indicators
    if echo "$content" | grep -qiE "download.*install|install.*run|run.*execute"; then
        log_threat 30 "Multi-stage attack pattern detected"
        ((behavior_score += 30))
    fi
    
    # Check for credential harvesting indicators
    if echo "$content" | grep -qiE "login|password|username|credential"; then
        log_threat 25 "Credential harvesting indicators"
        ((behavior_score += 25))
    fi
    
    # Check for data exfiltration patterns
    if echo "$content" | grep -qiE "upload|submit|send|POST"; then
        log_warning "Potential data exfiltration pattern"
        ((behavior_score += 15))
    fi
    
    # Check for C2 communication patterns
    if echo "$content" | grep -qiE "callback|beacon|checkin|c2|command"; then
        log_threat 40 "C2 communication pattern detected"
        ((behavior_score += 40))
    fi
    
    # Check for persistence mechanisms
    if echo "$content" | grep -qiE "startup|autorun|schedule|cron|launchd"; then
        log_threat 35 "Persistence mechanism detected"
        ((behavior_score += 35))
    fi
    
    if [ $behavior_score -gt 50 ]; then
        log_threat 30 "HIGH behavioral risk score: $behavior_score"
    fi
}

################################################################################
# APT ATTRIBUTION
################################################################################

check_apt_indicators() {
    local content="$1"
    
    log_info "Checking APT indicators..."
    
    for indicator in "${APT_INDICATORS[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 50 "APT infrastructure indicator detected: $indicator"
            
            # Log to IOC report
            echo "APT_INDICATOR,$indicator,$(date -Iseconds)" >> "$IOC_REPORT"
        fi
    done
    
    # Check for known APT TTPs
    if echo "$content" | grep -qiE "pastebin\.com.*raw"; then
        log_threat 40 "Pastebin raw URL (common APT C2 staging)"
    fi
    
    if echo "$content" | grep -qiE "github\.com.*\.txt|gitlab\.com.*\.txt"; then
        log_threat 35 "Code repository text file (potential C2 staging)"
    fi
}

################################################################################
# OBFUSCATION DETECTION
################################################################################

detect_obfuscation() {
    local content="$1"
    
    log_info "Detecting obfuscation techniques..."
    
    for pattern in "${OBFUSCATION_PATTERNS[@]}"; do
        if echo "$content" | grep -qE "$pattern"; then
            log_threat 30 "Obfuscation pattern detected: $pattern"
        fi
    done
    
    # Check for Base64 encoded content
    if echo "$content" | grep -qE "^[A-Za-z0-9+/]{40,}={0,2}$"; then
        log_threat 25 "Possible Base64 encoded payload"
        
        # Attempt to decode
        local decoded=$(echo "$content" | base64 -d 2>/dev/null)
        if [ -n "$decoded" ]; then
            log_info "Decoded Base64 content:"
            echo "$decoded" | head -c 200
            
            # Recursively analyze decoded content
            analyze_decoded_content "$decoded"
        fi
    fi
    
    # Check for hex encoding
    if echo "$content" | grep -qE "^([0-9a-fA-F]{2})+$"; then
        log_threat 25 "Possible hex-encoded payload"
    fi
    
    # Check for URL encoding abuse
    local percent_count=$(echo "$content" | grep -o '%' | wc -l)
    local content_length=${#content}
    
    if [ $content_length -gt 0 ] && [ $(( percent_count * 100 / content_length )) -gt 20 ]; then
        log_threat 20 "Excessive URL encoding detected (${percent_count} percent signs)"
    fi
}

analyze_decoded_content() {
    local content="$1"
    
    log_info "Analyzing decoded/deobfuscated content..."
    
    # Run all analysis functions on decoded content
    analyze_url_structure "$content" 2>/dev/null || true
    analyze_script_injection "$content"
    analyze_social_engineering "$content"
    detect_obfuscation "$content"  # Recursive deobfuscation
    analyze_api_keys "$content"
}

################################################################################
# QR CODE STRUCTURE ANALYSIS
################################################################################

analyze_qr_structure() {
    local image="$1"
    local base_name="$2"
    
    log_info "Analyzing QR code structure..."
    
    if ! command -v python3 &> /dev/null; then
        return
    fi
    
    python3 << EOF
import sys
from PIL import Image
from pyzbar.pyzbar import decode, ZBarSymbol

try:
    img = Image.open('$image')
    codes = decode(img, symbols=[ZBarSymbol.QRCODE])
    
    if not codes:
        print("[!] No QR codes detected in structural analysis")
        sys.exit(0)
    
    for i, code in enumerate(codes):
        print(f"QR Code #{i+1}:")
        print(f"  Type: {code.type}")
        print(f"  Data length: {len(code.data)} bytes")
        print(f"  Quality: {code.quality}")
        print(f"  Position: {code.rect}")
        print(f"  Polygon points: {len(code.polygon)}")
        
        # Check for unusual characteristics
        if len(code.data) > 2000:
            print(f"  [!] UNUSUALLY LARGE QR PAYLOAD: {len(code.data)} bytes")
        
        if code.quality < 10:
            print(f"  [!] LOW QUALITY QR CODE (quality: {code.quality}) - possible tampering")
        
except Exception as e:
    print(f"[ERROR] Structure analysis failed: {e}", file=sys.stderr)
EOF
}

################################################################################
# COMPREHENSIVE PAYLOAD ANALYSIS
################################################################################

comprehensive_payload_analysis() {
    local content="$1"
    local image="$2"
    local base_name="$3"
    
    log_info "========================================="
    log_info "COMPREHENSIVE PAYLOAD ANALYSIS"
    log_info "========================================="
    
    # Save content for analysis
    local content_file="${TEMP_DIR}/${base_name}_content.txt"
    echo "$content" > "$content_file"
    
    # 1. Basic content inspection
    log_info "Content length: ${#content} characters"
    log_info "Content preview:"
    echo "$content" | head -c 200
    echo ""
    
    # 2. Character set analysis
    analyze_charset "$content"
    
    # 3. Entropy analysis
    analyze_entropy "$content"
    
    # 4. API key/secret detection
    analyze_api_keys "$content"
    
    # 5. URL analysis (if URL present)
    if echo "$content" | grep -qiE "^https?://"; then
        analyze_url_structure "$content"
        
        # Check content type for URLs
        analyze_url_content_type "$content"
    fi
    
    # 6. Deep link analysis
    analyze_deep_links "$content"
    
    # 7. Cryptocurrency analysis
    analyze_crypto_addresses "$content"
    
    # 8. WiFi payload analysis
    analyze_wifi_payload "$content"
    
    # 9. Mobile config analysis
    analyze_mobile_config "$content"
    
    # 10. Script injection detection
    analyze_script_injection "$content"
    
    # 11. Social engineering detection
    analyze_social_engineering "$content"
    
    # 12. Obfuscation detection
    detect_obfuscation "$content"
    
    # 13. APT indicators
    check_apt_indicators "$content"
    
    # 14. Behavioral analysis
    analyze_qr_behavior "$content"
    
    # 15. YARA-style rule evaluation
    for rule in "${!YARA_RULES[@]}"; do
        if [ "$(evaluate_yara_rule "$content" "$rule")" = "true" ]; then
            log_threat 40 "YARA rule matched: $rule"
        fi
    done
    
    # 16. Check for action prefixes
    for prefix in "${QR_ACTION_PREFIXES[@]}"; do
        if echo "$content" | grep -qE "^$prefix"; then
            log_warning "Action prefix detected: $prefix"
        fi
    done
    
    # 17. Check for dangerous file extensions
    for ext in "${DANGEROUS_EXTENSIONS[@]}"; do
        if echo "$content" | grep -qiE "$ext"; then
            log_threat 40 "Dangerous file extension detected: $ext"
        fi
    done
    
    log_info "========================================="
}

analyze_charset() {
    local content="$1"
    
    log_info "Character set analysis..."
    
    # Detect encoding
    local encoding=$(python3 << EOF
import chardet
result = chardet.detect('''$content'''.encode())
print(f"{result['encoding']} (confidence: {result['confidence']:.2f})")
EOF
2>/dev/null)
    
    [ -n "$encoding" ] && log_info "  Detected encoding: $encoding"
    
    # Check for non-printable characters
    if echo "$content" | grep -qP '[^\x20-\x7E\n\r\t]'; then
        log_warning "Non-printable characters detected in payload"
    fi
    
    # Check for null bytes
    if echo "$content" | grep -qP '\x00'; then
        log_threat 30 "Null bytes detected (possible binary payload or evasion)"
    fi
}

################################################################################
# MAIN ANALYSIS FUNCTION
################################################################################

analyze_qr_image() {
    local image="$1"
    local base_name=$(basename "$image" | sed 's/\.[^.]*$//')
    
    log_info ""
    log_info "========================================="
    log_info "ANALYZING: $image"
    log_info "========================================="
    
    # Reset threat score for this image
    THREAT_SCORE=0
    
    # 1. Compute hashes
    compute_hashes "$image" "$base_name"
    
    # 2. Extract metadata
    analyze_metadata "$image" "$base_name"
    
    # 3. Steganography analysis
    analyze_steganography "$image" "$base_name"
    
    # 4. OCR analysis
    analyze_with_ocr "$image" "$base_name"
    
    # 5. QR structure analysis
    analyze_qr_structure "$image" "$base_name"
    
    # 6. Multi-decoder analysis
    local decoded_base="${TEMP_DIR}/${base_name}_decoded"
    
    if ! multi_decoder_analysis "$image" "$decoded_base"; then
        log_error "All decoders failed - QR may be corrupted or invalid"
        return 1
    fi
    
    # 7. Analyze merged decoded content
    local merged_content="${decoded_base}_merged.txt"
    
    if [ ! -s "$merged_content" ]; then
        log_error "No decoded content available"
        return 1
    fi
    
    local content=$(cat "$merged_content")
    
    # 8. Comprehensive payload analysis
    comprehensive_payload_analysis "$content" "$image" "$base_name"
    
    # 9. Network-based checks (if enabled)
    if [ "$NETWORK_CHECK" = true ]; then
        if echo "$content" | grep -qiE "^https?://"; then
            local url=$(echo "$content" | grep -oiE "^https?://[^ ]+")
            
            check_virustotal "$url"
            check_urlhaus "$url"
            check_phishtank "$url"
            check_openphish_direct "$url"
            
            # Extract domain for additional checks
            local domain=$(echo "$url" | awk -F/ '{print $3}' | sed 's/:[0-9]*$//')
            check_alienvault_otx_domain "$domain"
        fi
    fi
    
    # 10. Generate threat assessment
    generate_threat_assessment "$image" "$content"
    
    log_info "========================================="
    log_info "Analysis complete for $image"
    log_info "Final Threat Score: $THREAT_SCORE / $MAX_THREAT_SCORE"
    log_info "========================================="
    
    # Save individual report
    generate_individual_report "$image" "$content" "$base_name"
}

################################################################################
# THREAT ASSESSMENT
################################################################################

generate_threat_assessment() {
    local image="$1"
    local content="$2"
    
    local threat_level="UNKNOWN"
    local color=$NC
    
    if [ $THREAT_SCORE -ge 200 ]; then
        threat_level="CRITICAL"
        color=$RED
    elif [ $THREAT_SCORE -ge 100 ]; then
        threat_level="HIGH"
        color=$MAGENTA
    elif [ $THREAT_SCORE -ge 50 ]; then
        threat_level="MEDIUM"
        color=$YELLOW
    elif [ $THREAT_SCORE -ge 20 ]; then
        threat_level="LOW"
        color=$CYAN
    else
        threat_level="MINIMAL"
        color=$GREEN
    fi
    
    echo ""
    echo -e "${color}╔════════════════════════════════════════════╗${NC}"
    echo -e "${color}║         THREAT ASSESSMENT                  ║${NC}"
    echo -e "${color}╠════════════════════════════════════════════╣${NC}"
    echo -e "${color}║ Threat Level: ${threat_level}                     ${NC}"
    echo -e "${color}║ Threat Score: ${THREAT_SCORE}/${MAX_THREAT_SCORE}                      ${NC}"
    echo -e "${color}║ Image: $(basename "$image")                ${NC}"
    echo -e "${color}╚════════════════════════════════════════════╝${NC}"
    echo ""
    
    if [ "$threat_level" = "CRITICAL" ] || [ "$threat_level" = "HIGH" ]; then
        log_critical "⚠️  IMMEDIATE ACTION REQUIRED ⚠️"
        log_critical "This QR code exhibits multiple high-risk indicators"
        log_critical "DO NOT scan this code with a mobile device"
        log_critical "Recommended action: Report to security team"
    fi
}

generate_individual_report() {
    local image="$1"
    local content="$2"
    local base_name="$3"
    
    local report="${EVIDENCE_DIR}/${base_name}_report.txt"
    
    {
        echo "========================================="
        echo "QR CODE ANALYSIS REPORT"
        echo "========================================="
        echo "Generated: $(date)"
        echo "Scanner Version: $VERSION"
        echo "Image: $image"
        echo "Threat Score: $THREAT_SCORE / $MAX_THREAT_SCORE"
        echo ""
        echo "DECODED CONTENT:"
        echo "----------------------------------------"
        echo "$content"
        echo ""
        echo "========================================="
    } > "$report"
    
    log_success "Individual report saved: $report"
}

################################################################################
# JSON REPORT GENERATION
################################################################################

generate_json_report() {
    log_info "Generating JSON report..."
    
    # This would generate a structured JSON report
    # For brevity, creating a simple version
    
    cat > "$JSON_REPORT" << EOF
{
  "scan_metadata": {
    "timestamp": "$(date -Iseconds)",
    "scanner_version": "$VERSION",
    "total_images_scanned": 0,
    "total_threats_detected": 0
  },
  "results": []
}
EOF
    
    log_success "JSON report: $JSON_REPORT"
}

################################################################################
# FINAL SUMMARY REPORT
################################################################################

generate_summary_report() {
    log_info ""
    log_info "========================================="
    log_info "GENERATING SUMMARY REPORT"
    log_info "========================================="
    
    {
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║        QR CODE MALWARE DETECTION - SUMMARY REPORT            ║"
        echo "╠══════════════════════════════════════════════════════════════╣"
        echo "║ Scan Date: $(date)                                           "
        echo "║ Scanner Version: $VERSION                                    "
        echo "║ Output Directory: $OUTPUT_DIR                                "
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "SCAN STATISTICS:"
        echo "  - Total images analyzed: $(find "$OUTPUT_DIR" -name "*_report.txt" | wc -l)"
        echo "  - Evidence files collected: $(find "$EVIDENCE_DIR" -type f | wc -l)"
        echo "  - IOCs detected: $(wc -l < "$IOC_REPORT" 2>/dev/null || echo 0)"
        echo ""
        echo "OUTPUT FILES:"
        echo "  - Main report: $REPORT_FILE"
        echo "  - JSON report: $JSON_REPORT"
        echo "  - IOC report: $IOC_REPORT"
        echo "  - Log file: $LOG_FILE"
        echo "  - Evidence directory: $EVIDENCE_DIR"
        echo ""
        echo "========================================="
    } | tee -a "$REPORT_FILE"
    
    log_success "Summary report generation complete"
}

################################################################################
# INITIALIZATION
################################################################################

initialize() {
    # Create output directories
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR" "$EVIDENCE_DIR"
    
    # Initialize log file
    touch "$LOG_FILE"
    
    # Initialize IOC report with header
    echo "IOC_Type,Indicator,Timestamp,Context" > "$IOC_REPORT"
    
    # Print banner
    echo -e "${CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     ██████╗ ██████╗     ███╗   ███╗ █████╗ ██╗    ██╗    ██╗     ║
║    ██╔═══██╗██╔══██╗    ████╗ ████║██╔══██╗██║    ██║    ██║     ║
║    ██║   ██║██████╔╝    ██╔████╔██║███████║██║ █╗ ██║    ██║     ║
║    ██║▄▄ ██║██╔══██╗    ██║╚██╔╝██║██╔══██║██║███╗██║    ██║     ║
║    ╚██████╔╝██║  ██║    ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝    ███████╗║
║     ╚══▀▀═╝ ╚═╝  ╚═╝    ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝     ╚══════╝║
║                                                                   ║
║            ADVANCED QR CODE MALWARE DETECTION SYSTEM              ║
║                         Version 2.0.0                             ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    log_info "Initializing enhanced QR scanner..."
    log_info "Output directory: $OUTPUT_DIR"
}

################################################################################
# COMMAND LINE ARGUMENT PARSING
################################################################################

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--deep)
                DEEP_ANALYSIS=true
                shift
                ;;
            --no-network)
                NETWORK_CHECK=false
                shift
                ;;
            --vt)
                VT_CHECK=true
                shift
                ;;
            --vt-key)
                export VT_API_KEY="$2"
                VT_CHECK=true
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                # Assume it's a file or directory
                TARGET_PATH="$1"
                shift
                ;;
        esac
    done
}

show_help() {
    cat << EOF
Enhanced QR Code Malware Detection System

Usage: $0 [OPTIONS] [PATH]

OPTIONS:
    -v, --verbose       Verbose output
    -d, --deep          Enable deep analysis (slower, more thorough)
    --no-network        Disable network-based checks
    --vt                Enable VirusTotal checks
    --vt-key KEY        Set VirusTotal API key
    -h, --help          Show this help message

PATH:
    Directory containing QR code images, or specific image file
    If not specified, scans current directory

EXAMPLES:
    $0                              # Scan current directory
    $0 /path/to/qr_codes/          # Scan specific directory
    $0 --vt --vt-key ABC123 image.png  # Scan with VirusTotal
    $0 --deep --verbose /path/     # Deep scan with verbose output

ENVIRONMENT VARIABLES:
    VT_API_KEY          VirusTotal API key
    PHISHTANK_API_KEY   PhishTank API key

OUTPUT:
    All results are saved to: qr_analysis_TIMESTAMP/

FEATURES:
    - Multiple QR decoders (zbar, pyzbar, quirc, zxing, qrdecode, opencv)
    - Steganography detection (steghide, zsteg, stegdetect)
    - OCR analysis for text overlays
    - Comprehensive threat intelligence (OpenPhish, URLhaus, PhishTank, OTX)
    - API key and secret detection
    - File download and analysis
    - WHOIS and domain age checking
    - Image entropy analysis
    - Multi-layer obfuscation detection

EOF
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Initialize
    initialize
    
    # Check dependencies
    check_dependencies
    
    # Load threat intelligence
    load_threat_intelligence
    
    # Initialize YARA rules
    init_yara_rules
    
    # Determine target path
    local target_path="${TARGET_PATH:-.}"
    
    if [ ! -e "$target_path" ]; then
        log_error "Path does not exist: $target_path"
        exit 1
    fi
    
    # Collect images to analyze
    local images=()
    
    if [ -f "$target_path" ]; then
        # Single file
        images=("$target_path")
    elif [ -d "$target_path" ]; then
        # Directory - find all image files
        while IFS= read -r -d '' file; do
            images+=("$file")
        done < <(find "$target_path" -type f \( -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.gif" -o -iname "*.bmp" \) -print0)
    fi
    
    if [ ${#images[@]} -eq 0 ]; then
        log_error "No images found to analyze"
        exit 1
    fi
    
    log_info "Found ${#images[@]} image(s) to analyze"
    echo ""
    
    # Analyze each image
    for image in "${images[@]}"; do
        analyze_qr_image "$image"
        echo ""
    done
    
    # Generate final reports
    generate_json_report
    generate_summary_report
    
    # Print final output locations
    echo ""
    log_success "Analysis complete!"
    log_info "Results saved to: $OUTPUT_DIR"
    log_info "  - Main report: $REPORT_FILE"
    log_info "  - Evidence: $EVIDENCE_DIR"
    log_info "  - IOCs: $IOC_REPORT"
    echo ""
}

# Run main function
main "$@"
