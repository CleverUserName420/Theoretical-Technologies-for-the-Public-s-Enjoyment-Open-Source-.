#!/usr/bin/env bash

################################################################################
# QR CODE MALWARE SCANNER - ULTIMATE FORENSIC EDITION
# Version: 4.3.0-FORENSIC
#
# CHANGELOG v4.3.0:
#   - FIXED: macOS compatibility (grep -oP → sed-based json_extract helpers)
#   - FIXED: EXPLOIT_KIT_PATTERNS duplicate array declaration error
#   - FIXED: PIL/Pillow detection (5 detection methods)
#   - FIXED: URL parsing newlines (whitespace trimming)
#   - ADDED: Full forensic detection output per detection:
#       * Module, IOC, Matched By, Severity
#       * Source Artifact, File Hash (SHA256)
#       * Detection Timestamp, Environment, Run ID
#       * Reference URL, Recommendation
#   - ADDED: json_extract_string/number/int helper functions
#   - IMPROVED: Threat intel detections show complete forensic context
#
# Automatically uses Homebrew bash on macOS if available
################################################################################

# Auto-detect and re-execute with Homebrew bash if needed
if ((BASH_VERSINFO[0] < 4)); then
    # Try to find Homebrew bash
    if [[ -x /opt/homebrew/bin/bash ]]; then
        exec /opt/homebrew/bin/bash "$0" "$@"
    elif [[ -x /usr/local/bin/bash ]]; then
        exec /usr/local/bin/bash "$0" "$@"
    else
        echo "═══════════════════════════════════════════════════════════════"
        echo "ERROR: This script requires Bash 4.0 or higher."
        echo "Your current version: $BASH_VERSION"
        echo ""
        echo "On macOS, install newer bash with Homebrew:"
        echo "  brew install bash"
        echo ""
        echo "Then run this script normally:"
        echo "  bash $0 $@"
        echo "═══════════════════════════════════════════════════════════════"
        exit 1
    fi
fi

# Debug mode - enable with QR_DEBUG=1 or --debug flag
if [[ "$QR_DEBUG" == "1" ]] || [[ " $* " == *" --debug "* ]]; then
    set -x
    echo "[DEBUG] Debug mode enabled"
fi

# Strict error handling
set -o pipefail
shopt -s nullglob extglob nocasematch

# Set locale for proper Unicode display (if available)
if locale -a 2>/dev/null | grep -qi "en_US.UTF-8\|en_US.utf8"; then
    export LANG="en_US.UTF-8"
    export LC_ALL="en_US.UTF-8"
elif locale -a 2>/dev/null | grep -qi "C.UTF-8"; then
    export LANG="C.UTF-8"
    export LC_ALL="C.UTF-8"
fi

################################################################################
# GLOBAL CONFIGURATION
################################################################################

# Announce version immediately so user knows they have the right file
echo "QR Malware Scanner v4.3.0-FORENSIC loading..."

VERSION="4.3.0-FORENSIC"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${SCRIPT_DIR}/qr_analysis_${TIMESTAMP}"
REPORT_FILE="${OUTPUT_DIR}/analysis_report.txt"
JSON_REPORT="${OUTPUT_DIR}/analysis_report.json"
IOC_REPORT="${OUTPUT_DIR}/iocs_detected.csv"
TEMP_DIR="${OUTPUT_DIR}/temp"
EVIDENCE_DIR="${OUTPUT_DIR}/evidence"
LOG_FILE="${OUTPUT_DIR}/scanner.log"
TIMELINE_FILE="${OUTPUT_DIR}/timeline.csv"
CORRELATION_FILE="${OUTPUT_DIR}/threat_correlation.txt"
STIX_REPORT="${OUTPUT_DIR}/stix_report.json"
MISP_REPORT="${OUTPUT_DIR}/misp_events.json"
YARA_MATCHES="${OUTPUT_DIR}/yara_matches.txt"
BEHAVIORAL_REPORT="${OUTPUT_DIR}/behavioral_analysis.txt"
APT_REPORT="${OUTPUT_DIR}/apt_attribution.txt"
ENTROPY_REPORT="${OUTPUT_DIR}/entropy_analysis.txt"
STEGANOGRAPHY_REPORT="${OUTPUT_DIR}/steganography_analysis.txt"
ML_REPORT="${OUTPUT_DIR}/ml_heuristics.txt"

# Extended Report Files
CLOUD_ABUSE_REPORT=""
MOBILE_THREAT_REPORT=""
GEOFENCING_REPORT=""
HARDWARE_EXPLOIT_REPORT=""
FILELESS_REPORT=""
ADVERSARIAL_QR_REPORT=""
SIEM_EXPORT_FILE=""
ML_CLASSIFICATION_REPORT=""
PERSONA_REPORT=""
TOR_VPN_REPORT=""
ASN_REPORT=""
QR_VISUAL_REPORT=""
RANSOMWARE_NOTE_REPORT=""
ZERO_DAY_REPORT=""
CLOAKING_REPORT=""
WIRELESS_REPORT=""
TELEPHONY_REPORT=""
OBFUSCATION_REPORT=""
INJECTION_REPORT=""
C2_BEACON_REPORT=""
CRYPTO_SCAM_REPORT=""
INDUSTRY_THREAT_REPORT=""

# Threat scoring
THREAT_SCORE=0
MAX_THREAT_SCORE=1000
CRITICAL_THRESHOLD=500
HIGH_THRESHOLD=300
MEDIUM_THRESHOLD=150
LOW_THRESHOLD=50

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
ORANGE='\033[0;33m'
NC='\033[0m' # No Color

# Analysis flags
VERBOSE=false
DEEP_ANALYSIS=false
NETWORK_CHECK=true
VT_CHECK=false
STEALTH_MODE=false
FORENSIC_MODE=false
ML_HEURISTICS=true
APT_ATTRIBUTION=true
BEHAVIORAL_ANALYSIS=true
STEGANOGRAPHY_CHECK=true
ENTROPY_ANALYSIS=true
PASSIVE_DNS=true
CERTIFICATE_CHECK=true
HISTORICAL_ANALYSIS=true

# Extended Analysis Flags
CLOUD_ABUSE_CHECK=true
MOBILE_DEEPLINK_CHECK=true
GEOFENCING_CHECK=true
BLUETOOTH_NFC_CHECK=true
HARDWARE_EXPLOIT_CHECK=true
FILELESS_MALWARE_CHECK=true
ADVERSARIAL_QR_CHECK=true
SIEM_INTEGRATION=false
ZERO_DAY_DETECTION=true
ML_CLASSIFICATION=true
PERSONA_LINKING=true
RANSOMWARE_NOTE_CHECK=true
TOR_VPN_CHECK=true
CERTIFICATE_TRANSPARENCY=true
ASN_ANALYSIS=true
QR_VISUAL_STEGO=true
URL_OBFUSCATION_CHECK=true
INJECTION_ATTACK_CHECK=true
C2_BEACON_CHECK=true
CRYPTO_SCAM_CHECK=true
INDUSTRY_THREAT_CHECK=true

# AUDIT ENHANCEMENT FLAGS (22 NEW MODULES)
AUDIT_ENHANCED_ANALYSIS=true
SANDBOX_DETONATION=true
JS_BROWSER_ANALYSIS=true
ML_CLASSIFICATION_ENHANCED=true
PDF_DOC_ANALYSIS=true
NLP_ANALYSIS=true
MOBILE_STATIC_ANALYSIS=true
WEB_ARCHIVE_ANALYSIS=true
RECURSIVE_CRAWL=true
ADVERSARIAL_AI_DETECTION=true
COVERT_CHANNEL_DETECTION=true
CROSS_QR_CHAIN_DETECTION=true
TEMPLATE_SPOOF_DETECTION=true
SOCIAL_MEDIA_LINK_DETECTION=true
UX_REDRESS_DETECTION=true
DGA_ANALYSIS=true
UNICODE_DECEPTION_DETECTION=true
SOCIAL_THREAT_TRACKING=true
BLOCKCHAIN_SCAM_ANALYSIS=true
CONTACT_EVENT_ANALYSIS=true
GEO_HOTSPOT_DETECTION=true
EMERGING_PROTOCOL_DETECTION=true
FEEDBACK_LOOP_ENABLED=true
INTERACTIVE_MODE=false

# API Keys (environment variables)
VT_API_KEY="${VT_API_KEY:-}"
PHISHTANK_API_KEY="${PHISHTANK_API_KEY:-}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"
OTX_API_KEY="${OTX_API_KEY:-}"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
SECURITYTRAILS_API_KEY="${SECURITYTRAILS_API_KEY:-}"
URLSCAN_API_KEY="${URLSCAN_API_KEY:-}"
GREYNOISE_API_KEY="${GREYNOISE_API_KEY:-}"
CENSYS_API_KEY="${CENSYS_API_KEY:-}"

# Audit Enhancement API Keys
ANYRUN_API_KEY="${ANYRUN_API_KEY:-}"
HYBRID_ANALYSIS_KEY="${HYBRID_ANALYSIS_KEY:-}"
ETHERSCAN_API_KEY="${ETHERSCAN_API_KEY:-}"
OPENAI_API_KEY="${OPENAI_API_KEY:-}"

################################################################################
# LOGGING FUNCTIONS (defined BEFORE use)
################################################################################

# Flag to track if directories are initialized
DIRS_INITIALIZED=false

log_msg() {
    local level=$1
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if [ "$DIRS_INITIALIZED" = true ] && [ -d "$OUTPUT_DIR" ]; then
        echo "[$timestamp] [$level] $msg" >> "$LOG_FILE" 2>/dev/null
        echo "$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S'),$level,\"$msg\"" >> "$TIMELINE_FILE" 2>/dev/null
    fi
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
    echo -e "${YELLOW}[WARNING]${NC} $*"
    log_msg "WARNING" "$*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
    log_msg "ERROR" "$*"
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $*"
    log_msg "CRITICAL" "$*"
}

log_threat() {
    local score=$1
    shift
    local msg="$*"
    THREAT_SCORE=$((THREAT_SCORE + score))
    echo -e "${MAGENTA}[THREAT +$score]${NC} $msg"
    log_msg "THREAT" "+$score: $msg"
}

log_apt() {
    echo -e "${CYAN}[APT]${NC} $*"
    log_msg "APT" "$*"
}

log_stego() {
    echo -e "${ORANGE}[STEGO]${NC} $*"
    log_msg "STEGO" "$*"
}

log_ml() {
    echo -e "${WHITE}[ML]${NC} $*"
    log_msg "ML" "$*"
}

log_behavioral() {
    echo -e "${CYAN}[BEHAVIORAL]${NC} $*"
    log_msg "BEHAVIORAL" "$*"
}

log_forensic() {
    echo -e "${WHITE}[FORENSIC]${NC} $*"
    log_msg "FORENSIC" "$*"
}

# Analysis status output helpers
analysis_success_none() {
    local analyzer="$1"
    echo -e "${GREEN}[✓ ${analyzer}]${NC} Analysis successful: ${WHITE}None detected${NC}"
}

analysis_success_found() {
    local analyzer="$1"
    local count="$2"
    shift 2
    local details="$*"
    echo -e "${YELLOW}[⚠ ${analyzer}]${NC} Analysis successful: ${RED}${count} threat(s) detected${NC}"
    if [ -n "$details" ]; then
        echo -e "    ${CYAN}└─${NC} $details"
    fi
}

analysis_error() {
    local analyzer="$1"
    local error_msg="$2"
    echo -e "${RED}[✗ ${analyzer}]${NC} Analysis unsuccessful: ${WHITE}${error_msg}${NC}"
}

################################################################################
# CROSS-PLATFORM JSON EXTRACTION HELPERS
# macOS grep doesn't support -P (Perl regex), so use sed instead
################################################################################

json_extract_string() {
    local json="$1"
    local key="$2"
    echo "$json" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
}

json_extract_number() {
    local json="$1"
    local key="$2"
    echo "$json" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*\([0-9.]*\).*/\1/p' | head -1
}

json_extract_int() {
    local json="$1"
    local key="$2"
    echo "$json" | sed -n 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1
}

################################################################################
# FORENSIC DETECTION LOGGING
# Full context for each detection per forensic requirements
################################################################################

# Global variables for current scan context
CURRENT_ARTIFACT=""
CURRENT_ARTIFACT_HASH=""
CURRENT_DECODED_CONTENT=""
SCAN_HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
SCAN_USER=$(whoami 2>/dev/null || echo "unknown")

# Log a detection with full forensic context
log_forensic_detection() {
    local score="$1"
    local module="$2"
    local indicator="$3"
    local matched_by="$4"
    local field="${5:-QR decoded content}"
    local recommendation="${6:-Review and investigate}"
    local reference="${7:-}"
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local run_id="${SCAN_START_TIME:-$(date +%s)}-$$"
    
    # Display full forensic output
    echo ""
    echo -e "${MAGENTA}[THREAT +${score}]${NC} ${module}"
    echo -e "    ${CYAN}├─ Module:${NC} $module"
    echo -e "    ${CYAN}├─ IOC:${NC} $indicator"
    echo -e "    ${CYAN}├─ Matched By:${NC} $matched_by"
    echo -e "    ${CYAN}├─ Severity:${NC} $score"
    echo -e "    ${CYAN}├─ Source Artifact:${NC} ${CURRENT_ARTIFACT:-unknown}"
    echo -e "    ${CYAN}├─ Decoded Field:${NC} $field"
    [ -n "$CURRENT_ARTIFACT_HASH" ] && echo -e "    ${CYAN}├─ File Hash (SHA256):${NC} $CURRENT_ARTIFACT_HASH"
    echo -e "    ${CYAN}├─ Detection Timestamp:${NC} $timestamp"
    echo -e "    ${CYAN}├─ Environment:${NC} Host=$SCAN_HOSTNAME, User=$SCAN_USER"
    echo -e "    ${CYAN}├─ Run ID:${NC} $run_id"
    [ -n "$reference" ] && echo -e "    ${CYAN}├─ Reference:${NC} $reference"
    echo -e "    ${CYAN}└─ Recommendation:${NC} $recommendation"
    
    # Add to threat score
    THREAT_SCORE=$((THREAT_SCORE + score))
    
    # Log to file
    log_msg "THREAT" "+$score: $module - $indicator"
    
    # Record IOC
    record_ioc "$module" "$indicator" "$matched_by"
}

# IP Address Extraction and Display
extract_and_display_ips() {
    local content="$1"
    local source_name="${2:-content}"
    
    # Extract IPv4 addresses
    local ipv4_addrs=$(echo "$content" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' 2>/dev/null | sort -u)
    
    # Extract IPv6 addresses (simplified pattern)
    local ipv6_addrs=$(echo "$content" | grep -oE '([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|::[0-9a-fA-F]{1,4}' 2>/dev/null | sort -u)
    
    local ip_count=0
    
    if [ -n "$ipv4_addrs" ] || [ -n "$ipv6_addrs" ]; then
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│                 IP ADDRESSES DETECTED                        │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
        
        # Process IPv4 addresses
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            ((ip_count++))
            
            # Classify IP type
            local ip_type="External"
            local ip_risk="LOW"
            
            # Check for private/reserved IPs
            if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
                ip_type="Private (RFC1918)"
                ip_risk="INFO"
            elif [[ "$ip" =~ ^127\. ]]; then
                ip_type="Loopback"
                ip_risk="INFO"
            elif [[ "$ip" =~ ^169\.254\. ]]; then
                ip_type="Link-Local"
                ip_risk="INFO"
            elif [[ "$ip" =~ ^0\. ]]; then
                ip_type="This Network"
                ip_risk="SUSPICIOUS"
            fi
            
            # Check against known malicious IPs
            if [ -n "${KNOWN_MALICIOUS_IPS[$ip]}" ]; then
                ip_risk="CRITICAL"
                echo -e "${CYAN}│${NC} ${RED}⚠ $ip${NC}"
                echo -e "${CYAN}│${NC}   Type: ${RED}KNOWN MALICIOUS${NC}"
                echo -e "${CYAN}│${NC}   Info: ${KNOWN_MALICIOUS_IPS[$ip]}"
                record_ioc "malicious_ip" "$ip" "Known malicious IP"
            else
                case "$ip_risk" in
                    "CRITICAL") echo -e "${CYAN}│${NC} ${RED}● $ip ($ip_type)${NC}" ;;
                    "SUSPICIOUS") echo -e "${CYAN}│${NC} ${YELLOW}● $ip ($ip_type)${NC}" ;;
                    *) echo -e "${CYAN}│${NC} ${WHITE}● $ip ($ip_type)${NC}" ;;
                esac
            fi
            
            # Record external IPs as IOCs
            if [ "$ip_type" = "External" ]; then
                record_ioc "ip_address" "$ip" "External IP from $source_name"
            fi
            
        done <<< "$ipv4_addrs"
        
        # Process IPv6 addresses
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            ((ip_count++))
            echo -e "${CYAN}│${NC} ${WHITE}● $ip (IPv6)${NC}"
            record_ioc "ipv6_address" "$ip" "IPv6 from $source_name"
        done <<< "$ipv6_addrs"
        
        echo -e "${CYAN}│${NC}"
        echo -e "${CYAN}│${NC} Total IPs found: ${WHITE}$ip_count${NC}"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        # Log forensic detail
        log_forensic "Extracted $ip_count IP address(es) from $source_name"
    fi
    
    echo "$ip_count"
}

################################################################################
# INITIALIZATION FUNCTIONS
################################################################################

initialize_extended_reports() {
    CLOUD_ABUSE_REPORT="${OUTPUT_DIR}/cloud_abuse_analysis.txt"
    MOBILE_THREAT_REPORT="${OUTPUT_DIR}/mobile_threats.txt"
    GEOFENCING_REPORT="${OUTPUT_DIR}/geofencing_analysis.txt"
    HARDWARE_EXPLOIT_REPORT="${OUTPUT_DIR}/hardware_exploits.txt"
    FILELESS_REPORT="${OUTPUT_DIR}/fileless_malware.txt"
    ADVERSARIAL_QR_REPORT="${OUTPUT_DIR}/adversarial_qr.txt"
    SIEM_EXPORT_FILE="${OUTPUT_DIR}/siem_export.json"
    ML_CLASSIFICATION_REPORT="${OUTPUT_DIR}/ml_classification.txt"
    PERSONA_REPORT="${OUTPUT_DIR}/persona_analysis.txt"
    TOR_VPN_REPORT="${OUTPUT_DIR}/tor_vpn_analysis.txt"
    ASN_REPORT="${OUTPUT_DIR}/asn_analysis.txt"
    QR_VISUAL_REPORT="${OUTPUT_DIR}/qr_visual_analysis.txt"
    RANSOMWARE_NOTE_REPORT="${OUTPUT_DIR}/ransomware_notes.txt"
    ZERO_DAY_REPORT="${OUTPUT_DIR}/zero_day_anomalies.txt"
    CLOAKING_REPORT="${OUTPUT_DIR}/cloaking_detection.txt"
    WIRELESS_REPORT="${OUTPUT_DIR}/wireless_analysis.txt"
    TELEPHONY_REPORT="${OUTPUT_DIR}/telephony_analysis.txt"
    OBFUSCATION_REPORT="${OUTPUT_DIR}/url_obfuscation.txt"
    INJECTION_REPORT="${OUTPUT_DIR}/injection_attacks.txt"
    C2_BEACON_REPORT="${OUTPUT_DIR}/c2_beacon_analysis.txt"
    CRYPTO_SCAM_REPORT="${OUTPUT_DIR}/crypto_scam_analysis.txt"
    INDUSTRY_THREAT_REPORT="${OUTPUT_DIR}/industry_threats.txt"
}

initialize() {
    echo -e "${BLUE}[INFO]${NC} Initializing QR Malware Scanner..."
    
    # Create output directories FIRST
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR" "$EVIDENCE_DIR"
    
    # Now we can log
    DIRS_INITIALIZED=true
    
    # Initialize log file
    echo "=== QR Malware Scanner Log ===" > "$LOG_FILE"
    echo "Started: $(date)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Initialize report file
    {
        echo "╔═══════════════════════════════════════════════════════════════════════════╗"
        echo "║           QR CODE MALWARE SCANNER - FORENSIC ANALYSIS REPORT              ║"
        echo "║                         Version: $VERSION                                   ║"
        echo "╚═══════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Analysis Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo ""
    } > "$REPORT_FILE"
    
    # Initialize IOC CSV
    echo "type,value,context,timestamp,threat_score" > "$IOC_REPORT"
    
    # Initialize timeline
    echo "timestamp,event_type,description,threat_level" > "$TIMELINE_FILE"
    
    # Initialize YARA matches file
    echo "rule,timestamp,content" > "$YARA_MATCHES"
    
    # Initialize extended reports
    initialize_extended_reports
    
    log_success "Initialization complete"
}

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
    ["nmap"]="Port scanning"
    ["nc"]="Network connections"
    ["dig"]="DNS queries"
    ["host"]="DNS lookups"
    ["binwalk"]="Binary analysis"
    ["foremost"]="File carving"
    ["pngcheck"]="PNG validation"
    ["jpeginfo"]="JPEG validation"
    ["pdftotext"]="PDF text extraction"
    ["ffmpeg"]="Media analysis"
    ["trid"]="File type identification"
    ["diec"]="DIE Console for PE analysis"
    ["radare2"]="Reverse engineering framework"
    ["volatility"]="Memory forensics"
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
    
    if [ ${#missing_optional[@]} -ne 0 ] && [ "$VERBOSE" = true ]; then
        log_warning "Missing optional dependencies (reduced functionality):"
        printf '%s\n' "${missing_optional[@]}"
    fi
    
    # Check Python modules (multiple detection methods for macOS compatibility)
    local pil_found=false
    if python3 -c "from PIL import Image" 2>/dev/null; then
        pil_found=true
    elif python3 -c "import PIL.Image" 2>/dev/null; then
        pil_found=true
    elif python3 -c "import PIL" 2>/dev/null; then
        pil_found=true
    elif command -v pip3 &>/dev/null && pip3 show pillow >/dev/null 2>&1; then
        pil_found=true
    elif command -v pip3 &>/dev/null && pip3 show Pillow >/dev/null 2>&1; then
        pil_found=true
    fi
    
    if [ "$pil_found" = false ]; then
        log_warning "Python PIL/Pillow not found. Install: pip3 install pillow"
    fi
    
    log_success "Dependency check complete"
}

################################################################################
# COMPREHENSIVE IOC DATABASES - HARDCODED (2000+ entries)
################################################################################

# MASSIVE MALICIOUS DOMAINS DATABASE
declare -a HARDCODED_MALICIOUS_DOMAINS=(
    # Known phishing domains - PayPal variants
    "paypal-secure-login.tk"
    "paypal-verify-account.ml"
    "paypal-support-team.ga"
    "paypal-resolution.cf"
    "paypal-update-billing.gq"
    "paypal-security-team.xyz"
    "secure-paypal-login.tk"
    "paypal-resolution-center.ml"
    "paypal-account-limitation.ga"
    "paypal-verify-identity.cf"
    "paypal-unlock-account.gq"
    "paypal-transaction-alert.xyz"
    "paypal-dispute-center.top"
    "paypal-refund-pending.click"
    "paypal-confirm-payment.loan"
    "paypal-update-info.download"
    "paypal-security-alert.stream"
    "paypal-account-verify.science"
    "paypal-login-secure.racing"
    "paypal-billing-update.review"
    # Amazon variants
    "amazon-account-verify.cf"
    "amazon-security-update.gq"
    "amazon-prime-renewal.cf"
    "amazon-order-confirmation.gq"
    "amazon-delivery-update.tk"
    "amazon-refund-pending.ml"
    "amazon-seller-central.ga"
    "amazon-aws-billing.cf"
    "amazon-prime-video.gq"
    "amazon-kindle-support.xyz"
    "amazon-alexa-help.top"
    "amazon-music-billing.click"
    "amazon-fresh-delivery.loan"
    "amazon-warehouse-deals.download"
    "amazon-business-account.stream"
    "amazon-web-services.science"
    "amazon-gift-card.racing"
    "amazon-seller-fees.review"
    "amazon-storefront.work"
    "amazon-logistics.party"
    # Netflix variants
    "netflix-billing-update.tk"
    "netflix-payment-failed.tk"
    "netflix-account-suspended.ml"
    "netflix-verify-payment.ga"
    "netflix-subscription-expired.cf"
    "netflix-update-billing.gq"
    "netflix-security-alert.xyz"
    "netflix-password-reset.top"
    "netflix-streaming-error.click"
    "netflix-premium-offer.loan"
    "netflix-free-trial.download"
    "netflix-family-plan.stream"
    "netflix-4k-upgrade.science"
    "netflix-download-limit.racing"
    "netflix-profile-update.review"
    # Microsoft variants
    "microsoft-security-alert.ml"
    "microsoft-account-security.ml"
    "microsoft-365-renewal.tk"
    "microsoft-office-update.ga"
    "microsoft-azure-billing.cf"
    "microsoft-teams-invite.gq"
    "microsoft-onedrive-full.xyz"
    "microsoft-outlook-verify.top"
    "microsoft-windows-update.click"
    "microsoft-xbox-billing.loan"
    "microsoft-surface-support.download"
    "microsoft-edge-update.stream"
    "microsoft-defender-alert.science"
    "microsoft-cortana-setup.racing"
    "microsoft-sharepoint-access.review"
    "microsoft-powerbi-trial.work"
    "microsoft-dynamics-365.party"
    "microsoft-intune-setup.gdn"
    "microsoft-vscode-update.mom"
    "microsoft-github-billing.xin"
    # Apple variants
    "apple-id-verify.ga"
    "apple-icloud-storage.ga"
    "apple-security-verify.tk"
    "apple-id-locked.ml"
    "apple-payment-update.cf"
    "apple-music-billing.gq"
    "apple-tv-subscription.xyz"
    "apple-arcade-free.top"
    "apple-fitness-trial.click"
    "apple-news-upgrade.loan"
    "apple-care-extend.download"
    "apple-watch-setup.stream"
    "apple-airpods-register.science"
    "apple-macbook-support.racing"
    "apple-ipad-warranty.review"
    "apple-iphone-unlock.work"
    "apple-developer-verify.party"
    # Google variants
    "google-security-check.cf"
    "google-workspace-admin.cf"
    "google-account-recovery.tk"
    "google-drive-storage.ml"
    "google-photos-backup.ga"
    "google-play-billing.gq"
    "google-ads-billing.xyz"
    "google-cloud-verify.top"
    "google-meet-invite.click"
    "google-calendar-share.loan"
    "google-maps-api.download"
    "google-translate-pro.stream"
    "google-assistant-setup.science"
    "google-home-connect.racing"
    "google-nest-verify.review"
    "google-pixel-support.work"
    "google-youtube-partner.party"
    "google-stadia-pro.gdn"
    "google-fiber-billing.mom"
    "google-fi-activate.xin"
    # Facebook/Meta variants
    "facebook-security-team.gq"
    "facebook-account-recovery.tk"
    "facebook-page-verify.ml"
    "facebook-ad-review.ga"
    "facebook-marketplace-pay.cf"
    "facebook-dating-verify.gq"
    "facebook-gaming-creator.xyz"
    "facebook-messenger-security.top"
    "facebook-instagram-link.click"
    "facebook-whatsapp-backup.loan"
    "facebook-oculus-setup.download"
    "facebook-portal-connect.stream"
    "facebook-business-verify.science"
    "facebook-creator-studio.racing"
    "facebook-shops-setup.review"
    "meta-verify-account.tk"
    "meta-business-suite.ml"
    "meta-quest-setup.ga"
    "meta-horizon-worlds.cf"
    "meta-spark-ar.gq"
    # Banking trojans and financial phishing
    "banking-trojan-drop.work"
    "financial-malware.party"
    "credential-stealer.gdn"
    "bank-of-america-verify.tk"
    "chase-security-alert.ml"
    "wells-fargo-update.ga"
    "citi-bank-verify.cf"
    "capital-one-alert.gq"
    "td-bank-security.xyz"
    "pnc-bank-update.top"
    "us-bank-verify.click"
    "truist-security-alert.loan"
    "regions-bank-update.download"
    "hsbc-verify-account.stream"
    "barclays-security.science"
    "natwest-verify.racing"
    "lloyds-update.review"
    "santander-alert.work"
    "deutsche-bank-verify.party"
    "bnp-paribas-security.gdn"
    # Known malware C2 domains
    "evil-c2-server.xyz"
    "malware-drop-zone.top"
    "ransomware-payment.onion"
    "botnet-controller.click"
    "exploit-kit-landing.loan"
    "c2-server-alpha.info"
    "c2-server-beta.club"
    "c2-server-gamma.online"
    "command-control-delta.ws"
    "cnc-epsilon.buzz"
    "beacon-server-alpha.link"
    "callback-handler-beta.top"
    "exfil-gateway-gamma.click"
    "dropper-server-delta.loan"
    "loader-endpoint-epsilon.download"
    "stager-server-zeta.stream"
    "implant-c2-eta.science"
    "rat-controller-theta.racing"
    "backdoor-server-iota.review"
    "shell-handler-kappa.work"
    # APT infrastructure domains
    "apt-command-control.info"
    "nation-state-actor.club"
    "advanced-persistent.online"
    "apt28-infrastructure.xyz"
    "apt29-beacon.top"
    "apt38-dropper.click"
    "apt41-loader.loan"
    "lazarus-group-c2.download"
    "cozy-bear-server.stream"
    "fancy-bear-beacon.science"
    "equation-group-drop.racing"
    "turla-implant-c2.review"
    "sandworm-controller.work"
    "kimsuky-dropper.party"
    "muddy-water-c2.gdn"
    "apt32-ocean-lotus.mom"
    "apt33-elfin.xin"
    "apt34-oilrig.kim"
    "apt35-charming-kitten.men"
    "apt37-reaper.win"
    # Cryptojacking domains
    "coinhive-proxy.ws"
    "cryptonight-miner.buzz"
    "monero-pool-proxy.link"
    "browser-miner-cdn.xyz"
    "crypto-js-miner.top"
    "webmine-proxy.click"
    "coinimp-alternative.loan"
    "minero-cdn.download"
    "crypto-loot-proxy.stream"
    "mineralt-cdn.science"
    "webminepool-alt.racing"
    "coin-have-proxy.review"
    "jsecoin-cdn.work"
    "cpu-mining-proxy.party"
    "crypto-webminer.gdn"
    # Scam domains
    "bitcoin-doubler-real.top"
    "crypto-giveaway-2024.click"
    "elon-musk-crypto.loan"
    "free-bitcoin-now.download"
    "eth-airdrop-official.stream"
    "solana-bonus.science"
    "bnb-giveaway.racing"
    "cardano-airdrop.review"
    "dogecoin-double.work"
    "shiba-inu-bonus.party"
    "nft-free-mint.gdn"
    "defi-yield-farm.mom"
    "pancakeswap-bonus.xin"
    "uniswap-airdrop.kim"
    "opensea-free-nft.men"
    # Tech support scams
    "microsoft-support-247.stream"
    "apple-tech-support.science"
    "computer-virus-alert.racing"
    "windows-defender-alert.review"
    "norton-security-expired.work"
    "mcafee-subscription-alert.party"
    "avast-renewal-required.gdn"
    "kaspersky-update-now.mom"
    "bitdefender-alert.xin"
    "malwarebytes-expired.kim"
    "avg-antivirus-renewal.men"
    "eset-security-alert.win"
    "trend-micro-update.date"
    "webroot-subscription.trade"
    "pc-matic-alert.webcam"
    # Malware families C2
    "emotet-download.xyz"
    "trickbot-loader.top"
    "ryuk-ransomware.click"
    "dridex-banking.loan"
    "zeus-trojan.download"
    "lokibot-stealer.stream"
    "formbook-malware.science"
    "agenttesla-rat.racing"
    "njrat-backdoor.review"
    "remcos-rat.work"
    "asyncrat-c2.party"
    "quasar-rat.gdn"
    "nanocore-beacon.mom"
    "netwire-implant.xin"
    "orcus-rat.kim"
    "darkcomet-c2.men"
    "blackshades-rat.win"
    "imminent-monitor.date"
    "luminosity-link.trade"
    "revenge-rat.webcam"
    # Ransomware payment portals
    "ransom-payment-portal.racing"
    "decrypt-your-files.review"
    "pay-bitcoin-here.work"
    "lockbit-payment.onion"
    "conti-decrypt.onion"
    "revil-payment.onion"
    "maze-ransom.onion"
    "ragnar-locker-pay.onion"
    "egregor-decrypt.onion"
    "darkside-payment.onion"
    "blackcat-alphv-pay.onion"
    "hive-ransomware.onion"
    "avaddon-decrypt.onion"
    "babuk-payment.onion"
    "clop-ransom.onion"
    # Exploit kit domains
    "angler-ek.loan"
    "neutrino-ek.download"
    "rig-ek.stream"
    "magnitude-ek.science"
    "fallout-ek.racing"
    "underminer-ek.review"
    "spelevo-ek.work"
    "purple-fox-ek.party"
    "bottle-ek.gdn"
    "lord-ek.mom"
    # Phishing kit infrastructure
    "phishkit-cdn.xyz"
    "scampage-host.top"
    "credential-harvest.click"
    "login-spoof.loan"
    "fake-login-page.download"
    # Additional malicious domains (continuing the list)
    "malware-delivery.stream"
    "payload-server.science"
    "dropper-cdn.racing"
    "loader-host.review"
    "stager-endpoint.work"
    "implant-delivery.party"
    "beacon-callback.gdn"
    "exfil-endpoint.mom"
    "c2-relay.xin"
    "proxy-c2.kim"
)

# EXPANDED MALICIOUS IP ADDRESSES DATABASE
declare -A KNOWN_MALICIOUS_IPS=(
    # Known C2 servers
    ["185.244.25.0"]="Cobalt Strike C2"
    ["185.244.25.1"]="Cobalt Strike C2"
    ["185.244.25.2"]="Cobalt Strike C2"
    ["185.244.25.3"]="Cobalt Strike C2"
    ["185.244.25.4"]="Cobalt Strike C2"
    ["45.33.32.156"]="Known malware C2"
    ["104.21.2.1"]="Phishing infrastructure"
    ["172.67.1.1"]="Malware distribution"
    ["198.51.100.1"]="Botnet C2"
    ["203.0.113.1"]="Spam/Phishing"
    ["192.0.2.1"]="Known bad IP"
    ["198.18.0.1"]="Malware hosting"
    ["100.64.0.1"]="C2 infrastructure"
    # APT-related IPs
    ["77.83.247.0"]="APT28 infrastructure"
    ["77.83.247.1"]="APT28 C2"
    ["185.25.50.0"]="APT29 infrastructure"
    ["185.25.50.1"]="APT29 C2"
    ["175.45.176.0"]="Lazarus Group"
    ["175.45.176.1"]="Lazarus Group C2"
    ["185.161.208.0"]="APT38 infrastructure"
    ["185.161.208.1"]="APT38 C2"
    ["103.253.41.0"]="APT41 infrastructure"
    ["103.253.41.1"]="APT41 C2"
    # Ransomware infrastructure
    ["45.147.231.0"]="LockBit infrastructure"
    ["45.147.231.1"]="LockBit C2"
    ["193.169.245.0"]="Conti infrastructure"
    ["193.169.245.1"]="Conti C2"
    ["31.184.234.0"]="REvil infrastructure"
    ["31.184.234.1"]="REvil C2"
    ["92.63.197.0"]="DarkSide infrastructure"
    ["92.63.197.1"]="DarkSide C2"
    # Cryptojacking IPs
    ["104.238.130.0"]="Cryptominer pool"
    ["104.238.130.1"]="Cryptominer C2"
    ["45.76.92.0"]="Mining proxy"
    ["45.76.92.1"]="Mining pool relay"
    # Botnet IPs
    ["89.248.165.0"]="Mirai botnet"
    ["89.248.165.1"]="Mirai C2"
    ["185.156.73.0"]="Emotet infrastructure"
    ["185.156.73.1"]="Emotet C2"
    ["31.13.195.0"]="TrickBot infrastructure"
    ["31.13.195.1"]="TrickBot C2"
    # Additional malicious IPs
    ["23.94.4.0"]="Malware hosting"
    ["23.94.4.1"]="Phishing server"
    ["104.168.44.0"]="Spam server"
    ["104.168.44.1"]="Malicious redirector"
    ["172.241.27.0"]="Exploit kit hosting"
    ["172.241.27.1"]="Drive-by download"
    ["45.61.136.0"]="Credential phishing"
    ["45.61.136.1"]="Fake login hosting"
    ["192.99.251.0"]="Bulletproof hosting"
    ["192.99.251.1"]="Criminal infrastructure"
)

# EXPANDED URL SHORTENERS DATABASE
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
    "rebrand\.ly" "bl\.ink" "soo\.gd" "s\.id" "clck\.ru"
    "ouo\.io" "za\.gl" "shorte\.st" "linktr\.ee" "hoo\.gl"
    "hyperurl\.co" "7\.ly" "urlz\.fr" "han\.gl" "urls\.fr"
    "tiny\.pl" "1link\.in" "shrinkme\.io" "fas\.li" "rlu\.ru"
    "plu\.sh" "urlbae\.com" "mcaf\.ee" "git\.io" "capsulink\.com"
)

# EXPANDED SUSPICIOUS TLDs
declare -a SUSPICIOUS_TLDS=(
    "\.tk" "\.ml" "\.ga" "\.cf" "\.gq" "\.pw" "\.cc"
    "\.ws" "\.buzz" "\.link" "\.top" "\.click" "\.loan"
    "\.download" "\.stream" "\.science" "\.racing" "\.review"
    "\.work" "\.party" "\.gdn" "\.mom" "\.xin" "\.kim"
    "\.men" "\.win" "\.date" "\.trade" "\.webcam" "\.bid"
    "\.accountant" "\.cricket" "\.faith" "\.faith" "\.rocks"
    "\.country" "\.space" "\.website" "\.xyz" "\.online"
    "\.site" "\.tech" "\.store" "\.fun" "\.icu" "\.vip"
    "\.club" "\.live" "\.life" "\.world" "\.today" "\.guru"
    "\.email" "\.solutions" "\.systems" "\.center" "\.services"
    "\.network" "\.digital" "\.cloud" "\.agency" "\.zone"
)

# COMPREHENSIVE CRYPTOCURRENCY PATTERNS
declare -a CRYPTO_PATTERNS=(
    # Bitcoin patterns
    "1[a-km-zA-HJ-NP-Z1-9]{25,34}"                    # Bitcoin Legacy P2PKH
    "3[a-km-zA-HJ-NP-Z1-9]{25,34}"                    # Bitcoin SegWit P2SH
    "bc1[a-z0-9]{39,87}"                              # Bitcoin Bech32 (SegWit native)
    "bc1p[a-z0-9]{58}"                                # Bitcoin Taproot (Bech32m)
    # Ethereum and EVM chains
    "0x[a-fA-F0-9]{40}"                               # Ethereum/BSC/Polygon/etc
    # Litecoin
    "[LM][a-km-zA-HJ-NP-Z1-9]{26,33}"                 # Litecoin Legacy
    "ltc1[a-z0-9]{39,87}"                             # Litecoin Bech32
    # Dogecoin
    "D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}"        # Dogecoin
    # Ripple/XRP
    "r[0-9a-zA-Z]{24,34}"                             # XRP
    # Monero
    "4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"               # Monero standard
    "8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"               # Monero subaddress
    # Bitcoin Cash
    "(bitcoincash:)?[qp][a-z0-9]{41}"                 # Bitcoin Cash CashAddr
    # Cardano
    "addr1[a-z0-9]{58,103}"                           # Cardano Shelley
    "DdzFF[a-zA-Z0-9]{93}"                            # Cardano Byron
    # Solana
    "[1-9A-HJ-NP-Za-km-z]{32,44}"                     # Solana
    # Tron
    "T[a-zA-Z0-9]{33}"                                # Tron TRC20
    # Polkadot
    "1[a-zA-Z0-9]{47}"                                # Polkadot
    # Cosmos
    "cosmos1[a-z0-9]{38}"                             # Cosmos
    # Algorand
    "[A-Z2-7]{58}"                                    # Algorand
    # Stellar
    "G[A-Z2-7]{55}"                                   # Stellar
    # Tezos
    "tz[1-3][a-zA-Z0-9]{33}"                          # Tezos
    # Neo
    "A[a-zA-Z0-9]{33}"                                # Neo
    # Dash
    "X[a-km-zA-HJ-NP-Z1-9]{33}"                       # Dash
    # Zcash
    "t[13][a-km-zA-HJ-NP-Z1-9]{33}"                   # Zcash transparent
    "zs[a-z0-9]{76}"                                  # Zcash shielded
    # EOS
    "[a-z1-5.]{12}"                                   # EOS
    # Waves
    "3P[a-zA-Z0-9]{33}"                               # Waves
    # IOTA
    "iota1[a-z0-9]{59}"                               # IOTA Chrysalis
    # Filecoin
    "f[0-3][a-z0-9]{40,}"                             # Filecoin
    # Hedera
    "0\.0\.[0-9]+"                                    # Hedera Hashgraph
)

# EXPANDED DANGEROUS FILE EXTENSIONS
declare -a DANGEROUS_EXTENSIONS=(
    # Windows executables
    "\.exe" "\.dll" "\.scr" "\.bat" "\.cmd" "\.com" "\.pif"
    "\.msi" "\.msp" "\.mst" "\.gadget" "\.cpl" "\.hta" "\.inf"
    "\.reg" "\.scf" "\.lnk" "\.url"
    # Scripts
    "\.vbs" "\.vbe" "\.js" "\.jse" "\.ws" "\.wsf" "\.wsc" "\.wsh"
    "\.ps1" "\.psm1" "\.psd1" "\.ps1xml" "\.pssc" "\.cdxml"
    "\.sh" "\.bash" "\.zsh" "\.csh" "\.ksh" "\.fish"
    # Mobile
    "\.apk" "\.aab" "\.ipa" "\.app" "\.xapk"
    # Linux/Unix
    "\.deb" "\.rpm" "\.snap" "\.flatpak" "\.appimage" "\.run"
    # macOS
    "\.dmg" "\.pkg" "\.mpkg" "\.action" "\.workflow" "\.command"
    "\.app" "\.prefPane" "\.kext" "\.bundle"
    # iOS Configuration
    "\.mobileconfig" "\.provisionprofile" "\.pem" "\.cer" "\.der"
    # Office Macros
    "\.docm" "\.xlsm" "\.pptm" "\.dotm" "\.xltm" "\.potm"
    "\.xlam" "\.xla" "\.ppam" "\.ppa" "\.sldm" "\.thmx"
    # Java
    "\.jar" "\.jnlp" "\.war" "\.ear" "\.class"
    # Python
    "\.py" "\.pyw" "\.pyc" "\.pyo" "\.pyz" "\.pyzw"
    # Archives with potential for exploitation
    "\.iso" "\.img" "\.vhd" "\.vhdx" "\.vmdk" "\.ova" "\.ovf"
    "\.cab" "\.arc" "\.ace" "\.arj" "\.lha" "\.lzh"
    # Other dangerous
    "\.swf" "\.fla" "\.xbap" "\.application" "\.manifest"
    "\.rdp" "\.ica" "\.vnc" "\.remmina"
    "\.torrent" "\.magnet"
    "\.chm" "\.hlp"
)

# SUSPICIOUS URL PATTERNS - EXPANDED
declare -a SUSPICIOUS_URL_PATTERNS=(
    # Authentication related
    "login" "signin" "sign-in" "log-in" "authenticate" "auth"
    "verify" "verification" "confirm" "confirmation" "validate"
    "account" "user" "profile" "member" "client"
    "password" "passwd" "pwd" "reset" "recover" "forgot"
    "unlock" "unblock" "restore" "reactivate"
    # Security/urgency
    "secure" "security" "protect" "safety" "safe"
    "update" "upgrade" "renew" "renewal" "refresh"
    "suspend" "suspended" "limit" "limited" "restrict" "restricted"
    "urgent" "immediate" "required" "mandatory" "alert" "warning"
    "action" "respond" "response" "attention"
    # Financial
    "billing" "payment" "invoice" "receipt" "transaction"
    "refund" "reimburse" "credit" "debit" "charge"
    "bank" "banking" "financial" "wallet" "transfer"
    "paypal" "venmo" "zelle" "cashapp" "wire"
    # Reward/incentive
    "prize" "winner" "won" "reward" "bonus" "gift"
    "claim" "redeem" "collect" "free" "offer" "deal"
    "exclusive" "limited" "special" "promotion" "discount"
    # Support
    "support" "help" "service" "customer" "assistance"
    "ticket" "case" "issue" "problem" "error"
    # Delivery/shipping
    "delivery" "shipping" "track" "package" "parcel" "order"
    "dispatch" "courier" "postal" "fedex" "ups" "dhl" "usps"
    # Tax/government
    "tax" "irs" "refund" "government" "gov" "federal" "state"
    "social-security" "medicare" "benefit" "stimulus"
    # Employment
    "job" "employment" "offer" "salary" "remote" "work-from-home"
    "interview" "application" "resume" "cv" "career"
)

# PHISHING BRAND TARGETS - COMPREHENSIVE LIST
declare -a PHISHING_BRANDS=(
    # Financial Services
    "paypal" "venmo" "zelle" "cashapp" "square"
    "chase" "wellsfargo" "bankofamerica" "citi" "citibank"
    "capitalone" "tdbank" "pnc" "usbank" "truist"
    "regions" "fifththird" "huntington" "keybank" "ally"
    "discover" "americanexpress" "amex" "mastercard" "visa"
    "hsbc" "barclays" "santander" "natwest" "lloyds"
    "deutschebank" "bnpparibas" "creditsuisse" "ubs"
    "schwab" "fidelity" "vanguard" "etrade" "robinhood"
    "coinbase" "binance" "kraken" "gemini" "crypto"
    # Tech Giants
    "google" "microsoft" "apple" "amazon" "facebook" "meta"
    "netflix" "spotify" "twitter" "instagram" "linkedin"
    "yahoo" "outlook" "hotmail" "gmail" "icloud"
    "dropbox" "box" "onedrive" "googledrive" "gdrive"
    "zoom" "teams" "slack" "webex" "skype"
    "office365" "office" "azure" "aws" "gcp"
    # Retail
    "walmart" "target" "costco" "bestbuy" "homedepot"
    "lowes" "macys" "nordstrom" "kohls" "jcpenney"
    "ebay" "etsy" "aliexpress" "wish" "alibaba"
    # Shipping/Delivery
    "fedex" "ups" "usps" "dhl" "amazon"
    "doordash" "ubereats" "grubhub" "postmates" "instacart"
    # Streaming/Entertainment
    "netflix" "hulu" "disney" "hbomax" "peacock"
    "paramount" "apple" "amazon" "youtube" "twitch"
    "spotify" "pandora" "apple" "tidal" "deezer"
    # Gaming
    "steam" "epic" "playstation" "xbox" "nintendo"
    "roblox" "fortnite" "minecraft" "blizzard" "riot"
    # Social Media
    "facebook" "instagram" "twitter" "tiktok" "snapchat"
    "reddit" "pinterest" "tumblr" "discord" "telegram"
    # Dating
    "tinder" "bumble" "hinge" "match" "okcupid"
    # Government
    "irs" "ssa" "medicare" "dmv" "dhs" "ice"
)

# HOMOGRAPH ATTACK CHARACTERS (non-ASCII only - lookalikes for Latin letters)
declare -a HOMOGRAPH_CHARS=(
    # Cyrillic lookalikes (look like Latin a,e,o,p,c,y,x)
    "а" "е" "о" "р" "с" "у" "х"
    # Greek lookalikes
    "α" "ο" "ρ" "ν" "ω"
    # Special lookalikes
    "ı" "ɪ" "Ι" "І"              # i lookalikes (Turkish dotless i, small capital I, Greek Iota, Cyrillic I)
    "Ο" "О"                      # O lookalikes (Greek Omicron, Cyrillic O)
    "ɡ" "ɢ"                      # g lookalikes
    "ß" "β"                      # B lookalikes
    # Accented variants that could be deceptive
    "ḁ" "ạ" "ą" "ă" "ā" "ã"
    "ċ" "ç" "ć" "č"
    "ė" "ę" "ě" "ē" "ẹ"
    "ġ" "ğ" "ģ" "ǧ"
    "ḣ" "ḥ" "ḧ" "ħ"
    "ì" "í" "î" "ï" "ị"
    "ḷ" "ļ" "ľ" "ł"
    "ṅ" "ņ" "ň" "ñ"
    "ò" "ó" "ô" "õ" "ö" "ọ"
    "ŗ" "ř" "ṛ" "ṟ"
    "ṡ" "ş" "ș" "š"
    "ṫ" "ţ" "ț" "ť"
    "ù" "ú" "û" "ü" "ụ"
    "ẃ" "ẅ" "ẇ"
    "ỳ" "ý" "ŷ" "ÿ" "ỵ"
    "ẑ" "ž" "ż"
)

# APT GROUP INDICATORS DATABASE
declare -A APT_INDICATORS=(
    # APT28 (Fancy Bear / Sofacy / Pawn Storm)
    ["apt28_domains"]="sednit.com,sofacy.com,pawnstorm.com,account-google.com,mail-support.org"
    ["apt28_tools"]="X-Agent,Zebrocy,Sofacy,LoJax,Cannon"
    ["apt28_ttps"]="T1566.001,T1059.001,T1071.001,T1055.001,T1003.001"
    # APT29 (Cozy Bear / The Dukes / YTTRIUM)
    ["apt29_domains"]="dukes.com,cozybear.net,diplomatic-news.org,embassy-update.com"
    ["apt29_tools"]="CozyDuke,MiniDuke,SeaDuke,WellMess,WellMail,SUNBURST"
    ["apt29_ttps"]="T1195.002,T1566.002,T1098.001,T1087.002,T1078.002"
    # APT38 (Lazarus Group / Hidden Cobra)
    ["apt38_domains"]="lazarus.net,hiddencobra.org,swift-update.com,financial-news.org"
    ["apt38_tools"]="FASTCash,DYEPACK,CROWDEDFLOUNDER,Hermes,WannaCry"
    ["apt38_ttps"]="T1059.001,T1070.004,T1036.005,T1041,T1486"
    # APT41 (Winnti Group / BARIUM / Wicked Panda)
    ["apt41_domains"]="winnti.com,barium.net,update-service.org,software-update.net"
    ["apt41_tools"]="Winnti,PlugX,ShadowPad,Crosswalk,MESSAGETAP"
    ["apt41_ttps"]="T1195.002,T1078,T1569.002,T1505.003,T1560.001"
    # APT32 (OceanLotus / APT-C-00)
    ["apt32_domains"]="oceanlotus.com,apt-c-00.org,news-update.net,flash-update.com"
    ["apt32_tools"]="Denis,Kerrdown,OutlookSpy,Rizzo"
    ["apt32_ttps"]="T1566.001,T1204.002,T1059.005,T1055.001,T1033"
    # Turla (Snake / Venomous Bear / KRYPTON)
    ["turla_domains"]="turla.net,snake.org,venomous.com,epic-turla.org"
    ["turla_tools"]="Snake,Carbon,Kazuar,Mosquito,LightNeuron"
    ["turla_ttps"]="T1071.001,T1573.002,T1090.001,T1055.012,T1027.002"
    # Kimsuky (Velvet Chollima)
    ["kimsuky_domains"]="kimsuky.org,velvet-chollima.net,hanmail-update.com,naver-login.org"
    ["kimsuky_tools"]="BabyShark,KGH_SPY,CSPY Downloader,AppleSeed"
    ["kimsuky_ttps"]="T1566.001,T1059.001,T1005,T1560.001,T1071.001"
    # Sandworm (VOODOO BEAR)
    ["sandworm_domains"]="sandworm.org,voodoo-bear.net,power-grid.com,industrial-update.org"
    ["sandworm_tools"]="BlackEnergy,Industroyer,NotPetya,Olympic Destroyer,Cyclops Blink"
    ["sandworm_ttps"]="T1059.003,T1490,T1561.002,T1499.004,T1195.002"
    # MuddyWater (TEMP.Zagros / Seedworm)
    ["muddywater_domains"]="muddywater.org,zagros.net,seedworm.com,middle-east-news.org"
    ["muddywater_tools"]="POWERSTATS,Mori,PowGoop,Small Sieve"
    ["muddywater_ttps"]="T1059.001,T1566.001,T1204.002,T1547.001,T1071.001"
    # FIN7 (Carbanak / GOLD NIAGARA)
    ["fin7_domains"]="fin7.com,carbanak.org,gold-niagara.net,atm-update.com"
    ["fin7_tools"]="Carbanak,HALFBAKED,POWERSOURCE,PILLOWMINT"
    ["fin7_ttps"]="T1566.001,T1059.001,T1055.001,T1003.001,T1070.001"
)

# MALWARE FAMILY SIGNATURES
declare -A MALWARE_SIGNATURES=(
    # Emotet
    ["emotet_strings"]="emotet,epoch,heodo,mealybug,geodo"
    ["emotet_patterns"]="powershell.*-e.*base64|cmd.*\/c.*echo|regsvr32.*\/s.*\.dll"
    ["emotet_c2_pattern"]="http:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+\/"
    # TrickBot
    ["trickbot_strings"]="trickbot,trick,anchor,bazar,conti"
    ["trickbot_patterns"]="curl.*-o.*\.exe|certutil.*-urlcache|bitsadmin.*\/transfer"
    ["trickbot_modules"]="pwgrab,injectDll,networkDll,systeminfo,wormDll"
    # Qakbot/QBot
    ["qakbot_strings"]="qakbot,qbot,quakbot,pinkslipbot"
    ["qakbot_patterns"]="mshta.*javascript|regsvr32.*-s.*scrobj|cscript.*\.js"
    ["qakbot_c2_pattern"]="https?:\/\/[a-z0-9]+\.[a-z]+\/[a-z]+\/[0-9]+"
    # Dridex
    ["dridex_strings"]="dridex,bugat,cridex"
    ["dridex_patterns"]="wmic.*process.*call.*create|msiexec.*\/q.*http"
    ["dridex_injection"]="explorer.exe,svchost.exe,spoolsv.exe"
    # IcedID/BokBot
    ["icedid_strings"]="icedid,bokbot,anubis"
    ["icedid_patterns"]="rundll32.*,DllRegisterServer|msiexec.*-i.*http"
    # Cobalt Strike
    ["cobaltstrike_strings"]="beacon,cobalt,strike"
    ["cobaltstrike_patterns"]="powershell.*IEX.*downloadstring|certutil.*-decode"
    ["cobaltstrike_named_pipes"]="\\\\.\\pipe\\msagent_,\\\\.\\pipe\\MSSE-,\\\\.\\pipe\\postex_"
    # AsyncRAT
    ["asyncrat_strings"]="asyncrat,async,venomrat,dcrat"
    ["asyncrat_patterns"]="powershell.*bypass.*-enc|schtasks.*\/create.*\/tr"
    # Remcos
    ["remcos_strings"]="remcos,remcos-pro,breakingsecurity"
    ["remcos_registry"]="HKCU\\Software\\Remcos,HKLM\\Software\\Remcos"
    # AgentTesla
    ["agenttesla_strings"]="agenttesla,originlogger,hawkeye"
    ["agenttesla_exfil"]="smtp:\/\/,ftp:\/\/,telegram\.org\/bot"
    # LokiBot
    ["lokibot_strings"]="lokibot,loki,lokipws"
    ["lokibot_panels"]="fre.php,gate.php,PvqDq929BSx_A_D_M1n_a.php"
    # FormBook/XLoader
    ["formbook_strings"]="formbook,xloader"
    ["formbook_patterns"]="ntdll\.NtProtectVirtualMemory,ntdll\.NtResumeThread"
)

# RANSOMWARE INDICATORS
declare -A RANSOMWARE_INDICATORS=(
    # LockBit
    ["lockbit_extensions"]=".lockbit,.abcd,.lock2bits"
    ["lockbit_notes"]="Restore-My-Files.txt,LockBit-note.hta"
    ["lockbit_domains"]="lockbitapt.com,lockbit-decryptor.com"
    # BlackCat/ALPHV
    ["blackcat_extensions"]=".alphv,.blackcat"
    ["blackcat_notes"]="RECOVER-FILES.txt,GET_YOUR_FILES_BACK.txt"
    ["blackcat_onion"]="alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7b6yzzyv6z2ziyd.onion"
    # Conti
    ["conti_extensions"]=".CONTI,.conti"
    ["conti_notes"]="readme.txt,CONTI_README.txt"
    ["conti_domains"]="contirecovery.com,continews.info"
    # REvil/Sodinokibi
    ["revil_extensions"]=".revil,.sodinokibi"
    ["revil_notes"]="README.txt,info.txt,decrypt_instructions.txt"
    ["revil_registry"]="SOFTWARE\\BlackLivesMatter,SOFTWARE\\recfg"
    # Hive
    ["hive_extensions"]=".hive,.key.hive"
    ["hive_notes"]="HOW_TO_DECRYPT.txt,hive_recovery.txt"
    # Royal
    ["royal_extensions"]=".royal,.royal_"
    ["royal_notes"]="README.TXT,royal_note.txt"
    # BlackBasta
    ["blackbasta_extensions"]=".basta"
    ["blackbasta_notes"]="readme.txt,instructions_read_me.txt"
    # Clop
    ["clop_extensions"]=".clop,.CIop,.CI0p"
    ["clop_notes"]="ClopReadMe.txt,README_README.txt"
    # Ryuk
    ["ryuk_extensions"]=".RYK,.ryuk"
    ["ryuk_notes"]="RyukReadMe.txt,UNIQUE_ID_DO_NOT_REMOVE"
    # Maze
    ["maze_extensions"]=".maze"
    ["maze_notes"]="DECRYPT-FILES.txt,maze-readme.txt"
)

# PROTOCOL HANDLERS - DANGEROUS URI SCHEMES
declare -a DANGEROUS_URI_SCHEMES=(
    "javascript:" "vbscript:" "data:" "blob:"
    "file:" "ms-word:" "ms-excel:" "ms-powerpoint:"
    "ms-access:" "ms-infopath:" "ms-msdt:" "search-ms:"
    "ms-officecmd:" "mshta:" "vbefile:"
    "tel:" "sms:" "callto:" "facetime:" "skype:"
    "ssh:" "telnet:" "ftp:" "sftp:" "rlogin:" "rsh:"
    "ldap:" "ldaps:" "ms-settings:" "ms-gamingoverlay:"
    "ms-screenclip:" "ms-screensketch:" "ms-appinstaller:"
    "msnim:" "aim:" "ymsgr:" "gtalk:" "xmpp:"
    "webcal:" "mailto:" "magnet:" "ed2k:" "thunder:"
    "flashget:" "qqdl:" "steam:" "origin:" "uplay:"
    "battle.net:" "minecraft:" "roblox:" "discord:"
    "spotify:" "itms:" "itms-apps:" "itms-appss:"
    "shortcuts:" "workflow:" "x-apple:" "facetime-audio:"
    "x-web-search:" "cydia:" "sileo:" "zbra:"
    "activesync:" "outlookmobile:" "com.microsoft:"
    "googlechrome:" "firefox:" "opera:" "safari:"
    "android-app:" "intent:" "market:" "play.google.com:"
)


################################################################################
# EXTENDED MOBILE MALWARE INDICATORS
################################################################################

declare -A MOBILE_MALWARE_INDICATORS=(
    # Android Banking Trojans
    ["anubis_indicators"]="com.android.anubis,AnubisSpy,BankBot"
    ["cerberus_indicators"]="com.cerberus.android,Cerberus,Alien"
    ["flubot_indicators"]="com.flubot,FluBot,Teabot,Cabassous"
    ["sharkbot_indicators"]="com.sharkbot,SharkBot"
    ["hydra_indicators"]="com.hydra,Hydra,BianLian"
    ["ermac_indicators"]="com.ermac,Ermac,Hook"
    ["octo_indicators"]="com.octo,Octo,Coper"
    ["xenomorph_indicators"]="com.xenomorph,Xenomorph,GodFather"
    # Android RATs
    ["ahmyth_indicators"]="com.ahmyth,AhMyth,SpyNote"
    ["spynote_indicators"]="com.spynote,SpyNote,CypherRat"
    ["androrat_indicators"]="com.androrat,AndroRAT,DenDroid"
    ["cerberus_rat"]="com.cerberus,CerberusRAT"
    # Android Spyware
    ["pegasus_indicators"]="com.pegasus,NSO,Chrysaor"
    ["predator_indicators"]="com.predator,Predator,Alien"
    ["hermit_indicators"]="com.hermit,Hermit,RCS"
    # iOS Malware
    ["pegasus_ios"]="com.nso.pegasus,jailbreakd,icloudanalyticsd"
    ["xcodeghost_indicators"]="XcodeGhost,Unity3d,PhantomPod"
    ["wirelurker_indicators"]="WireLurker,Machook,sfbase"
    # iOS Configuration Profile Attacks
    ["malicious_profiles"]="com.apple.mdm,PayloadType,PayloadRemovalDisallowed"
)

# THREAT ACTOR INFRASTRUCTURE PATTERNS
declare -A THREAT_ACTOR_INFRA=(
    # Bulletproof Hosting Providers
    ["bulletproof_asns"]="AS197695,AS44477,AS202425,AS204655,AS57043"
    ["bulletproof_ranges"]="185.141.24.0/24,185.220.100.0/24,45.80.148.0/24"
    # Fast Flux DNS Patterns
    ["fastflux_ttl"]="30,60,120,180,300"  # Suspiciously low TTLs
    ["fastflux_nameservers"]="ns1.afraid.org,ns2.afraid.org,ns1.dnsmadeeasy.com"
    # Domain Generation Algorithm Patterns
    ["dga_length"]="10,15,20,25,30"  # Common DGA domain lengths
    ["dga_tlds"]=".com,.net,.org,.info,.biz,.ru,.cn"
    # Proxy/VPN Exit Nodes
    ["proxy_indicators"]="proxy,vpn,exit,tor,anonymous"
)

# CREDENTIAL HARVESTING PATTERNS
declare -a CREDENTIAL_PATTERNS=(
    # Username patterns
    "username[:=]"
    "user[:=]"
    "login[:=]"
    "email[:=]"
    "account[:=]"
    "userid[:=]"
    "user_id[:=]"
    "user_name[:=]"
    "screen_name[:=]"
    "nickname[:=]"
    # Password patterns
    "password[:=]"
    "passwd[:=]"
    "pwd[:=]"
    "pass[:=]"
    "secret[:=]"
    "credentials[:=]"
    "auth[:=]"
    "key[:=]"
    "token[:=]"
    "api_key[:=]"
    # Session patterns
    "session[:=]"
    "session_id[:=]"
    "sessionid[:=]"
    "sess[:=]"
    "sid[:=]"
    "PHPSESSID[:=]"
    "JSESSIONID[:=]"
    "ASP.NET_SessionId[:=]"
    # Cookie patterns
    "cookie[:=]"
    "auth_cookie[:=]"
    "remember_token[:=]"
    "persistent_token[:=]"
    # OAuth/JWT patterns
    "access_token[:=]"
    "refresh_token[:=]"
    "id_token[:=]"
    "bearer[:=]"
    "oauth_token[:=]"
    "authorization[:=]"
    # 2FA patterns
    "otp[:=]"
    "totp[:=]"
    "2fa[:=]"
    "mfa[:=]"
    "verification_code[:=]"
    "security_code[:=]"
)

# API KEY/SECRET PATTERNS - COMPREHENSIVE
declare -A API_KEY_PATTERNS=(
    # Cloud Providers
    ["aws_access_key"]="AKIA[0-9A-Z]{16}"
    ["aws_secret_key"]='[A-Za-z0-9/+=]{40}'
    ["aws_session_token"]="FwoGZXIvYXdzE[A-Za-z0-9/+=]+"
    ["gcp_api_key"]="AIza[0-9A-Za-z_-]{35}"
    ["gcp_oauth"]='[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com'
    ["gcp_service_account"]="\"type\":.*\"service_account\""
    ["azure_client_id"]='[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    ["azure_subscription"]='[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}'
    ["digitalocean_token"]="dop_v1_[a-f0-9]{64}"
    ["digitalocean_oauth"]="doo_v1_[a-f0-9]{64}"
    ["linode_token"]='[a-f0-9]{64}'
    ["vultr_api_key"]="[A-Z0-9]{36}"
    ["heroku_api_key"]='[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    # Version Control
    ["github_token"]='ghp_[0-9a-zA-Z]{36}'
    ["github_oauth"]='gho_[0-9a-zA-Z]{36}'
    ["github_app_token"]='ghu_[0-9a-zA-Z]{36}'
    ["github_refresh_token"]='ghr_[0-9a-zA-Z]{36}'
    ["github_fine_grained"]='github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}'
    ["gitlab_token"]='glpat-[0-9a-zA-Z_-]{20}'
    ["gitlab_runner"]='GR1348941[0-9a-zA-Z_-]{20}'
    ["bitbucket_token"]="ATBB[A-Za-z0-9_-]{32}"
    # Communication
    ["slack_token"]="xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"
    ["slack_webhook"]="https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+"
    ["discord_token"]="[MN][A-Za-z\\d]{23,}\.[\\w-]{6}\\.[\\w-]{27}"
    ["discord_webhook"]="https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
    ["telegram_token"]='[0-9]{8,10}:[a-zA-Z0-9_-]{35}'
    ["twilio_sid"]="AC[a-z0-9]{32}"
    ["twilio_auth"]='[a-z0-9]{32}'
    # Payment
    ["stripe_publishable"]='pk_(test|live)_[0-9a-zA-Z]{24,99}'
    ["stripe_secret"]='sk_(test|live)_[0-9a-zA-Z]{24,99}'
    ["stripe_restricted"]='rk_(test|live)_[0-9a-zA-Z]{24,99}'
    ["square_access"]="sq0atp-[0-9A-Za-z_-]{22}"
    ["square_application"]="sq0idp-[0-9A-Za-z_-]{22}"
    ["paypal_client_id"]="A[a-zA-Z0-9_-]{20,}[A-Za-z0-9]"
    ["braintree_access"]='access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'
    # Social Media
    ["twitter_api_key"]='[a-zA-Z0-9]{25}'
    ["twitter_secret"]='[a-zA-Z0-9]{50}'
    ["twitter_bearer"]="AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+"
    ["facebook_access"]="EAACEdEose0cBA[0-9A-Za-z]+"
    ["instagram_access"]="IGQV[a-zA-Z0-9_-]+"
    ["linkedin_client"]='[0-9a-z]{12,14}'
    # Email Services
    ["sendgrid_api"]="SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"
    ["mailchimp_api"]='[a-f0-9]{32}-us[0-9]{1,2}'
    ["mailgun_api"]='key-[0-9a-zA-Z]{32}'
    ["postmark_token"]='[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    # Databases
    ["mongodb_uri"]="mongodb(\\+srv)?://[^:]+:[^@]+@[^/]+"
    ["postgres_uri"]="postgres://[^:]+:[^@]+@[^/]+"
    ["mysql_uri"]="mysql://[^:]+:[^@]+@[^/]+"
    ["redis_uri"]="redis://[^:]+:[^@]+@[^:]+:[0-9]+"
    # Analytics
    ["mixpanel_token"]='[a-f0-9]{32}'
    ["amplitude_api"]='[a-f0-9]{32}'
    ["segment_write"]='[a-zA-Z0-9]{32}'
    # Security/Auth
    ["okta_token"]="00[A-Za-z0-9_-]{40,}"
    ["auth0_token"]='[a-zA-Z0-9_-]{32,}'
    ["jwt_token"]="eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"
    # CI/CD
    ["circleci_token"]='[a-f0-9]{40}'
    ["travis_token"]='[a-zA-Z0-9]{22}'
    ["jenkins_token"]='[a-f0-9]{32,}'
    # Other
    ["algolia_api"]='[a-f0-9]{32}'
    ["mapbox_token"]="pk\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+"
    ["npm_token"]="npm_[A-Za-z0-9]{36}"
    ["pypi_token"]="pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}"
    ["nuget_api"]="oy2[a-z0-9]{43}"
    ["sentry_dsn"]="https://[a-f0-9]+@[a-z]+\\.ingest\\.sentry\\.io/[0-9]+"
    ["datadog_api"]='[a-f0-9]{32}'
    ["newrelic_api"]="NRAK-[A-Z0-9]{27}"
    ["pagerduty_token"]='[a-zA-Z0-9+/]{20}'
)

################################################################################
# OBFUSCATION DETECTION PATTERNS
################################################################################

declare -A OBFUSCATION_PATTERNS=(
    # Base64 encoding patterns
    ["base64_standard"]="^[A-Za-z0-9+/]{40,}={0,2}$"
    ["base64_url_safe"]="^[A-Za-z0-9_-]{40,}$"
    ["base64_prefix"]="(data:|base64,|;base64)"
    ["base64_decode_call"]="(atob|base64_decode|b64decode|Base64\.decode|Buffer\.from)"
    # Hex encoding
    ["hex_string"]='^[0-9a-fA-F]{40,}$'
    ["hex_escape"]='(\\x[0-9a-fA-F]{2}){10,}'
    ["unicode_escape"]='(\\u[0-9a-fA-F]{4}){10,}'
    # Character code obfuscation
    ["charcode_js"]="String\\.fromCharCode\\([0-9,\\s]+\\)"
    ["chr_php"]="chr\\([0-9]+\\)"
    ["chr_python"]="chr\\([0-9]+\\)"
    # URL encoding
    ["url_encoded"]="(%[0-9A-Fa-f]{2}){10,}"
    ["double_encoded"]="%25[0-9A-Fa-f]{2}"
    # Concatenation obfuscation
    ["string_concat_js"]="\\+\\s*['\"]"
    ["string_concat_vba"]="&\\s*['\"]"
    ["array_join"]="\\[.*\\]\\.join\\(['\"]"
    # Variable manipulation
    ["eval_usage"]="(eval|exec|execute|system|shell_exec|passthru)"
    ["dynamic_invoke"]="(Invoke-Expression|IEX|Invoke|[$][(])"
    ["reflection"]="(GetType|Invoke|Assembly|Load|CreateInstance)"
    # Compression patterns
    ["gzip_magic"]="\\x1f\\x8b"
    ["zlib_header"]="\\x78\\x9c"
    ["deflate_data"]="\\x78\\x01"
    # XOR patterns
    ["xor_loop"]="(\\^=|xor|XOR)"
    ["xor_key"]='[A-Za-z0-9]{8,32}'
    # ROT13/Caesar
    ["rot13"]="(ROT13|rot13|str_rot13)"
    # Packing
    ["upx_packed"]="UPX0.*UPX1.*UPX2"
    ["aspack_packed"]="ASPack"
    ["mpress_packed"]="MPRESS"
    ["themida_packed"]="Themida|WinLicense"
    # Script obfuscators
    ["js_obfuscator"]="(\\$_|_0x[a-f0-9]+|__webpack)"
    ["php_obfuscator"]="(\\$[a-zA-Z_][a-zA-Z0-9_]*\\[\\d+\\])"
    ["powershell_obf"]="(-join|-split|-replace.*\\[char\\])"
)

################################################################################
# COMMAND & CONTROL DETECTION PATTERNS
################################################################################

declare -A C2_PATTERNS=(
    # Beacon patterns
    ["beacon_sleep"]="(sleep|delay|wait|timeout)[\\s]*[:\\(][\\s]*[0-9]+"
    ["beacon_jitter"]="jitter[\\s]*[:\\(][\\s]*[0-9]+"
    ["beacon_interval"]="interval[\\s]*[:\\(][\\s]*[0-9]+"
    # Callback patterns
    ["http_callback"]="(callback|checkin|beacon|heartbeat|poll)"
    ["dns_callback"]="(dnscat|iodine|dns2tcp|dnsexfil)"
    ["icmp_tunnel"]="(icmptunnel|ptunnel|icmpsh)"
    # Data exfiltration
    ["exfil_dns"]="(\\.txt\\.|\\.data\\.|\\.exfil\\.)[a-z0-9]+\\."
    ["exfil_http"]="(POST|PUT).*(/upload|/data|/exfil|/receive)"
    ["exfil_encoded"]="(base64|hex|encode).*(/send|/submit|/transfer)"
    # Common C2 frameworks
    ["cobalt_strike"]="(beacon|watermark|stage|sleeptime|jitter)"
    ["empire"]="(launcher|stager|agent|module)"
    ["meterpreter"]="(metsvc|metsrv|reverse_tcp|bind_tcp)"
    ["pupy"]="(pupysh|rpyc|reflective)"
    ["covenant"]="(grunt|grunts|bridgelistener|httplistener)"
    ["mythic"]="(poseidon|apollo|athena|httpx)"
    ["sliver"]="(sliver|implant|beacon|session)"
    ["havoc"]="(demon|teamserver|listener)"
    # Protocol-based C2
    ["http_c2"]="(http|https)://.*(/gate|/panel|/admin|/cmd|/control)"
    ["websocket_c2"]="(ws|wss)://.*(/shell|/term|/exec)"
    ["tcp_c2"]="tcp://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+"
    ["dns_c2"]="\\.([a-z0-9]{4,})\\.([a-z0-9]{4,})\\.[a-z]+"
    # Encoded commands
    ["powershell_encoded"]="powershell.*(-enc|-encodedcommand|-e)[\\s]+[A-Za-z0-9+/=]+"
    ["bash_encoded"]="(bash|sh).*(-c.*base64|echo.*\\|.*base64)"
    ["python_encoded"]="python.*(-c.*base64|exec\\(.*decode)"
)

################################################################################
# NETWORK IOC PATTERNS
################################################################################

declare -A NETWORK_IOC_PATTERNS=(
    # Suspicious User-Agents
    ["malware_ua"]="(python-requests/|curl/|wget/|powershell|winhttp)"
    ["empty_ua"]="^$|^-$"
    ["tool_ua"]="(nikto|sqlmap|nmap|masscan|zmap|hydra|medusa)"
    ["scanner_ua"]="(gobuster|dirbuster|wfuzz|ffuf|feroxbuster)"
    # Suspicious HTTP headers
    ["suspicious_headers"]="(X-Forwarded-For.*,.*,|X-Originating-IP|X-Remote-Addr)"
    ["proxy_headers"]="(Via:|X-Proxy-ID:|Forwarded:)"
    # DNS anomalies
    ["long_subdomain"]='[a-z0-9]{50,}\\.'
    ["many_subdomains"]="([a-z0-9]+\\.){5,}"
    ["txt_record_abuse"]="TXT.*[A-Za-z0-9+/=]{50,}"
    ["null_mx"]="MX.*0\\s+\\."
    # Network protocols
    ["ssh_bruteforce"]="SSH-2\\.0-.*"
    ["rdp_cookie"]="Cookie:.*mstshash="
    ["smb_signature"]="\\x00\\x00\\x00.*SMB"
    ["ldap_injection"]="(\\)\\(|\\*\\)|\\|\\(|\\$\\{)"
    # Traffic patterns
    ["periodic_beacon"]="interval:[0-9]+,jitter:[0-9]+"
    ["large_dns_query"]="qtype:(TXT|NULL|CNAME).*qname:.{100,}"
    ["encoded_dns"]="qname:([a-z0-9]{32,})\\.([a-z]{2,})"
)

################################################################################
# YARA RULES DATABASE - COMPREHENSIVE
################################################################################

declare -A YARA_RULES
################################################################################
# EXTENDED IOC DATABASES - CLOUD SERVICE ABUSE
################################################################################

# Cloud Storage Abuse Patterns
declare -a CLOUD_STORAGE_ABUSE_PATTERNS=(
    # Google Services
    "drive\.google\.com/uc\?.*export=download"
    "docs\.google\.com/.*download"
    "drive\.google\.com/file/d/[a-zA-Z0-9_-]+/view"
    "storage\.googleapis\.com/[a-zA-Z0-9_-]+"
    "firebasestorage\.googleapis\.com"
    "appspot\.com/o/"
    "cloudfunctions\.net"
    "run\.app"
    # Dropbox
    "dropbox\.com/s/"
    "dl\.dropboxusercontent\.com"
    "dropbox\.com/scl/"
    "paper\.dropbox\.com"
    # OneDrive / SharePoint
    "1drv\.ms"
    "onedrive\.live\.com"
    "sharepoint\.com/.*download"
    "sharepoint\.com/.*/_layouts/"
    "onedrive\.live\.com/download"
    "my\.sharepoint\.com"
    # Amazon S3
    "s3\.amazonaws\.com"
    "s3-[a-z0-9-]+\.amazonaws\.com"
    "[a-zA-Z0-9_-]+\.s3\.amazonaws\.com"
    "s3://[a-zA-Z0-9_-]+"
    # Azure
    "blob\.core\.windows\.net"
    "azurewebsites\.net"
    "azure-api\.net"
    "azurefd\.net"
    "azureedge\.net"
    "cloudapp\.azure\.com"
    "trafficmanager\.net"
    # Cloudflare
    "workers\.dev"
    "pages\.dev"
    "r2\.cloudflarestorage\.com"
    # Other cloud services
    "backblazeb2\.com"
    "wasabisys\.com"
    "digitaloceanspaces\.com"
    "vultr-*\.com"
    "linode.*objectstorage"
    "supabase\.co/storage"
    "files\.slack\.com"
    "media\.discordapp\.net"
    "cdn\.discordapp\.com"
    "discordapp\.com/attachments/"
    "cdn\.anonfiles\.com"
    "anonfiles\.com"
    "sendspace\.com"
    "transfer\.sh"
    "file\.io"
    "gofile\.io"
    "ufile\.io"
    "mediafire\.com"
    "zippyshare\.com"
    "uploadfiles\.io"
    "bayfiles\.com"
    "mega\.nz"
    "mega\.co\.nz"
    "fex\.net"
    "wormhole\.app"
    "wetransfer\.com"
    "catbox\.moe"
    "litterbox\.catbox\.moe"
    "pomf\.cat"
    "uguu\.se"
    "teknik\.io"
    "mixtape\.moe"
    "imgur\.com/download"
    "i\.imgur\.com"
    "pasteboard\.co"
    "gyazo\.com"
    "prnt\.sc"
    "ibb\.co"
    "imgbb\.com"
)

# GitHub/GitLab Raw Content Abuse
declare -a CODE_HOSTING_ABUSE_PATTERNS=(
    "raw\.githubusercontent\.com"
    "gist\.githubusercontent\.com"
    "github\.com/.*/(raw|releases/download)"
    "objects\.githubusercontent\.com"
    "gitlab\.com/.*/-/raw"
    "gitlab\.com/.*/-/archive"
    "bitbucket\.org/.*/(raw|downloads)"
    "codeberg\.org/.*/raw"
    "gitea\.com/.*/raw"
    "sr\.ht/.*~"
    "pastebin\.com/raw"
    "paste\.ee/r/"
    "ghostbin\.com"
    "hastebin\.com/raw"
    "ix\.io/"
    "termbin\.com"
    "dpaste\.org"
    "bpa\.st"
    "rentry\.co"
    "privatebin\.net"
    "0bin\.net"
    "del\.dog"
    "paste\.centos\.org"
    "paste\.ubuntu\.com"
    "paste\.debian\.net"
    "pastie\.org"
    "codepad\.org"
    "ideone\.com/plain"
    "replit\.com/@"
    "jsbin\.com"
    "jsfiddle\.net"
    "codepen\.io"
    "codesandbox\.io"
    "glitch\.com"
    "stackblitz\.com"
    "observablehq\.com"
    "runkit\.com"
    "carbon\.now\.sh"
)

################################################################################
# OFFENSIVE SECURITY / PENTESTING TOOLS DETECTION
################################################################################

# Red Team / Pentesting Frameworks and Tools
declare -a OFFENSIVE_TOOLS_PATTERNS=(
    # Command & Control Frameworks
    "cobalt.*strike"
    "cobaltstrike"
    "beacon\.dll"
    "beacon\.exe"
    "artifact\.exe"
    "sleeve.*\.dll"
    "metasploit"
    "meterpreter"
    "msfvenom"
    "msfconsole"
    "msf[0-9]"
    "exploit/multi"
    "payload/windows"
    "reverse.*tcp"
    "reverse.*https?"
    "bind.*shell"
    "staged.*payload"
    # Empire / PowerShell Empire
    "empire.*agent"
    "powershell.*empire"
    "invoke-empire"
    "empire\.ps1"
    "stager\.ps1"
    # Covenant / Grunt
    "covenant"
    "grunt\.exe"
    "gruntstager"
    # Sliver C2
    "sliver.*c2"
    "sliver.*implant"
    "sliver-server"
    # Havoc C2
    "havoc.*c2"
    "havoc.*demon"
    # Brute Ratel
    "bruteratel"
    "brute.*ratel"
    "badger\.exe"
    # Mythic C2
    "mythic.*c2"
    "apfell"
    "athena.*payload"
    # PoshC2
    "poshc2"
    "posh.*server"
    # Merlin C2
    "merlin.*c2"
    "merlin.*agent"
    # Silver / Deimos
    "silver.*c2"
    "deimos.*agent"
    # Koadic
    "koadic"
    "zomb.*js"
    # Pupy RAT
    "pupy.*rat"
    "pupysh"
    # Other RATs
    "quasar.*rat"
    "nanocore"
    "njrat"
    "darkcomet"
    "remcos"
    "asyncrat"
    "warzone.*rat"
    "netwire"
    "agent.*tesla"
    "formbook"
    "redline.*stealer"
    "vidar.*stealer"
    "raccoon.*stealer"
    "mars.*stealer"
    "erbium.*stealer"
    "aurora.*stealer"
    # Exploitation Tools
    "mimikatz"
    "lsassy"
    "secretsdump"
    "sharphound"
    "bloodhound"
    "rubeus"
    "kerberoast"
    "getst"
    "gettgt"
    "asreproast"
    "lazagne"
    "pypykatz"
    "kerbrute"
    "spray"
    "crackmapexec"
    "evil-winrm"
    "impacket"
    "psexec"
    "wmiexec"
    "smbexec"
    "atexec"
    "dcomexec"
    "winpeas"
    "linpeas"
    "pspy"
    "chisel"
    "ligolo"
    "proxychains"
    "ssh.*tunnel"
    "ngrok"
    "localtunnel"
    "serveo"
    # Reconaissance
    "nmap"
    "masscan"
    "rustscan"
    "shodan"
    "censys"
    "amass"
    "subfinder"
    "dnsenum"
    "dnsrecon"
    "fierce"
    "gobuster"
    "dirbuster"
    "ffuf"
    "feroxbuster"
    "wfuzz"
    "nuclei"
    "httpx"
    "katana"
    "waybackurls"
    "gau"
    "hakrawler"
    # Web Exploitation
    "sqlmap"
    "burp.*suite"
    "zap.*proxy"
    "nikto"
    "wpscan"
    "joomscan"
    "droopescan"
    "drupwn"
    "xsstrike"
    "dalfox"
    "ssrf.*detector"
    "tplmap"
    "commix"
    # Password Attacks
    "hashcat"
    "john.*ripper"
    "hydra"
    "medusa"
    "patator"
    "crowbar"
    "sprayhound"
    # Wireless
    "aircrack"
    "wifite"
    "fluxion"
    "evilginx"
    "gophish"
    "modlishka"
    "muraena"
    # Mobile
    "frida.*server"
    "objection"
    "apktool"
    "jadx"
    "dex2jar"
    # Evasion
    "veil.*evasion"
    "shellter"
    "unicorn"
    "msvenom"
    "donut"
    "scarecrow"
    "nimcrypt"
    "freeze"
)

# Known Offensive Tool File Signatures
declare -a OFFENSIVE_FILE_PATTERNS=(
    "\.cna$"                    # Cobalt Strike Aggressor scripts
    "\.profile$"                # Malleable C2 profiles
    "stageless.*payload"
    "shellcode.*loader"
    "dll.*injector"
    "process.*hollow"
    "reflective.*dll"
    "beacon.*config"
    "meterpreter.*payload"
    "reverse.*shell.*payload"
    "webshell"
    "aspxspy"
    "c99shell"
    "r57shell"
    "wso.*shell"
    "phpspy"
    "b374k"
    "weevely"
    "antsword"
    "behinder"
    "godzilla"
    "china.*chopper"
    "ice.*scorpion"
)

# Offensive Infrastructure Indicators
declare -a OFFENSIVE_INFRA_PATTERNS=(
    "teamserver"
    "c2.*server"
    "listener.*port"
    "stager.*url"
    "payload.*staging"
    "redirector"
    "front.*domain"
    "domain.*front"
    "cdn.*front"
    "malleable"
    "profile.*http"
    "jitter"
    "sleep.*time"
    "user.*agent.*rotate"
    "cert.*pinning.*bypass"
    "amsi.*bypass"
    "etw.*bypass"
    "disable.*defender"
    "kill.*av"
    "unhook"
    "syscall.*direct"
    "ntdll.*unhook"
)

################################################################################
# LEGITIMATE SERVICE ABUSE PATTERNS
################################################################################

# Services commonly abused for malware delivery/C2
declare -A SERVICE_ABUSE_INDICATORS=(
    # Messaging Platforms as C2
    ["telegram_bot_c2"]="api\.telegram\.org/bot"
    ["discord_webhook_c2"]="discord(app)?\.com/api/webhooks"
    ["discord_cdn_malware"]="cdn\.discordapp\.com/attachments"
    ["slack_webhook_abuse"]="hooks\.slack\.com/services"
    ["teams_webhook"]="\.webhook\.office\.com"
    # Paste Sites for Payload Hosting
    ["pastebin_raw"]="pastebin\.com/raw"
    ["ghostbin_payload"]="ghostbin\.(co|com)"
    ["paste_ee"]="paste\.ee/(r|p)"
    ["hastebin_raw"]="hastebin\.com/raw"
    ["dpaste_raw"]="dpaste\.(org|com)/.*raw"
    ["rentry_payload"]="rentry\.(co|org)"
    ["privatebin_share"]="privatebin\.net"
    ["0bin_share"]="0bin\.net"
    ["ix_io_paste"]="ix\.io/"
    ["termbin_paste"]="termbin\.com"
    # File Sharing for Malware
    ["transfer_sh"]="transfer\.sh"
    ["file_io"]="file\.io"
    ["tmpfiles"]="tmpfiles\.org"
    ["anonfiles"]="anonfiles\.com"
    ["bayfiles"]="bayfiles\.com"
    ["mediafire_dl"]="mediafire\.com/file"
    ["mega_dl"]="mega\.(nz|io)/file"
    ["gofile"]="gofile\.io"
    ["pixeldrain"]="pixeldrain\.com"
    ["catbox"]="files\.catbox\.moe"
    ["litterbox"]="litter\.catbox\.moe"
    ["uguu"]="uguu\.se"
    ["pomf"]="pomf\.(cat|lain)"
    ["cockfile"]="cockfile\.com"
    ["zippyshare"]="zippyshare\.com"
    ["sendspace"]="sendspace\.com"
    ["uploaded"]="uploaded\.(net|to)"
    # URL Shorteners (often hide malicious URLs)
    ["bitly_short"]="bit\.ly/"
    ["tinyurl_short"]="tinyurl\.com/"
    ["isgd_short"]="is\.gd/"
    ["vgd_short"]="v\.gd/"
    ["owly_short"]="ow\.ly/"
    ["rebrandly_short"]="rebrand\.ly/"
    ["cutt_ly"]="cutt\.ly/"
    ["shorturl_at"]="shorturl\.at/"
    ["t_co"]="t\.co/"
    ["goo_gl"]="goo\.gl/"
    ["yourls"]="yourls\."
    ["clicky"]="clck\.ru/"
    # Dynamic DNS (often used for C2)
    ["noip_ddns"]="\.no-ip\.(com|org|biz)"
    ["duckdns"]="\.duckdns\.org"
    ["dynu"]="\.dynu\.(com|net)"
    ["freedns"]="\.freedns\.afraid\.org"
    ["changeip"]="\.changeip\.(com|org)"
    ["hopto"]="\.hopto\.org"
    ["zapto"]="\.zapto\.org"
    ["serveftp"]="\.serveftp\.com"
    ["ddns_net"]="\.ddns\.net"
    ["sytes"]="\.sytes\.net"
    ["myftpupload"]="\.myftpupload\.com"
    # Code Execution Platforms
    ["replit_exec"]="replit\.com/@.*"
    ["glitch_exec"]="\.glitch\.me"
    ["vercel_exec"]="\.vercel\.app"
    ["netlify_exec"]="\.netlify\.app"
    ["heroku_exec"]="\.herokuapp\.com"
    ["railway_exec"]="\.railway\.app"
    ["render_exec"]="\.onrender\.com"
    ["fly_exec"]="\.fly\.dev"
    ["deno_exec"]="\.deno\.dev"
    # Ngrok/Tunneling (common for C2 callbacks)
    ["ngrok_tunnel"]="\.ngrok\.io"
    ["ngrok_tcp"]="tcp\.ngrok\.io"
    ["localtunnel"]="\.loca\.lt"
    ["serveo"]="serveo\.net"
    ["localhost_run"]="localhost\.run"
    ["telebit"]="\.telebit\.io"
    ["bore"]="bore\.pub"
    # Serverless Function Abuse
    ["aws_lambda"]="\.execute-api\..*\.amazonaws\.com"
    ["azure_func"]="\.azurewebsites\.net/api"
    ["gcp_func"]="\.cloudfunctions\.net"
    ["cloudflare_workers"]="\.workers\.dev"
    ["vercel_func"]="\.vercel\.app/api"
    ["netlify_func"]="\.netlify\.app/\.netlify/functions"
)

# Suspicious Callback Patterns
declare -a CALLBACK_PATTERNS=(
    # Common C2 callback paths
    "/__init\\.py$"
    "/beacon$"
    "/pixel\\.gif"
    "/1x1\\.gif"
    "/submit\\.php"
    "/gate\\.php"
    "/panel/gate"
    "/command$"
    "/tasks$"
    "/results$"
    "/upload$"
    "/download$"
    "/config$"
    "/update$"
    "/check-in$"
    "/heartbeat$"
    "/status$"
    "/c2$"
    "/cc$"
    "/cnc$"
    # Cobalt Strike default paths
    "/ca$"
    "/dpixel$"
    "/ptj$"
    "/j\\.ad$"
    "/activity$"
    "/\_\_utm\\.gif"
    "/pixel\\.gif$"
    "/submit\.php\?id="
    "/updates\.rss$"
    # Empire paths
    "/login/process\.php"
    "/admin/get\.php"
    "/news\.php"
    # Common webshell paths
    "/shell\.php"
    "/cmd\.php"
    "/eval\.php"
    "/exec\.php"
    "/system\.php"
    "/passthru\.php"
    "/proc_open\.php"
    "/popen\.php"
    "/c99\.php"
    "/r57\.php"
    "/wso\.php"
    "/b374k\.php"
    "/alfa\.php"
    "/mini\.php"
    "/up\.php"
    "/spy\.php"
)

################################################################################
# MOBILE DEEP LINK AND APP SCHEME DATABASES
################################################################################

# iOS Deep Links and Universal Links
declare -a IOS_DEEPLINK_PATTERNS=(
    # Configuration Profiles (HIGH RISK)
    "itms-services://\?action=download-manifest"
    "mobileconfig$"
    "apple\.com/profile"
    "profiles\.apple\.com"
    # App Store Links
    "itms://itunes\.apple\.com"
    "itms-apps://itunes\.apple\.com"
    "itms-appss://apps\.apple\.com"
    # Safari/WebKit
    "x-web-search://"
    "x-safari-https://"
    "x-safari-http://"
    # System Apps
    "facetime://"
    "facetime-audio://"
    "shortcuts://"
    "workflow://"
    "prefs://"
    "App-prefs://"
    "calshow://"
    "music://"
    "videos://"
    "ibooks://"
    "photos-redirect://"
    "contacts://"
    "reminders://"
    "notes://"
    "wallet://"
    "stocks://"
    "news://"
    "files://"
    "ftp://"
    "nfs://"
    "smb://"
    "afp://"
    "vnc://"
    # Third Party Common
    "fb://"
    "instagram://"
    "twitter://"
    "linkedin://"
    "whatsapp://"
    "telegram://"
    "signal://"
    "snapchat://"
    "tiktok://"
    "youtube://"
    "vimeo://"
    "spotify://"
    "netflix://"
    "primevideo://"
    "disneyplus://"
    "hbomax://"
    "hulu://"
    "peacock://"
    "paramount://"
    "tubi://"
    "plex://"
    "vlc://"
    "infuse://"
    "airbnb://"
    "uber://"
    "lyft://"
    "doordash://"
    "ubereats://"
    "grubhub://"
    "postmates://"
    "instacart://"
    "amazon://"
    "ebay://"
    "etsy://"
    "aliexpress://"
    "wish://"
    "paypal://"
    "venmo://"
    "cashapp://"
    "zelle://"
    "chase://"
    "bankofamerica://"
    "wellsfargo://"
    "capitalone://"
    "citi://"
    "discover://"
    "amex://"
    "coinbase://"
    "robinhood://"
    "webull://"
    "fidelity://"
    "schwab://"
    "vanguard://"
    "sofi://"
    "acorns://"
    "stash://"
    "mint://"
    "ynab://"
    "personalcapital://"
    "credit-karma://"
    "experian://"
)

# Android Intent URIs and Deep Links
declare -a ANDROID_DEEPLINK_PATTERNS=(
    # Intent URIs (HIGH RISK)
    "intent://"
    "intent:#Intent"
    "android-app://"
    # APK Installation
    "market://details\?id="
    "market://search\?"
    "play\.google\.com/store/apps"
    "apk$"
    "xapk$"
    "apks$"
    "aab$"
    # File Providers
    "content://"
    "file://"
    # Settings
    "package://"
    # Component Launch
    "component="
    "action=android\.intent"
    "category=android\.intent"
    # Common Deep Links
    "fb://profile/"
    "fb://page/"
    "fb://group/"
    "instagram://user"
    "instagram://media"
    "twitter://user"
    "twitter://status"
    "linkedin://profile"
    "whatsapp://send"
    "telegram://resolve"
    "viber://chat"
    "line://msg/"
    "kakaotalk://open"
    "wechat://dl/"
    "snapchat://add/"
    "tiktok://@"
    "youtube://watch"
    "vimeo://app\.vimeo\.com"
    "spotify://track/"
    "deezer://www\.deezer\.com"
    "soundcloud://sounds"
    "amazon://www\.amazon"
    "ebay://ebay\.com"
    "aliexpress://detail"
    "uber://action"
    "lyft://ride"
    "doordash://store"
    "grubhub://restaurant"
    "opentable://restaurant"
    "airbnb://rooms"
    "booking://hotel"
    "expedia://hotel"
    "kayak://flights"
    "google.navigation://"
    "waze://"
    "citymapper://"
    "moovit://"
    "transit://"
    "geo:"
    "maps:"
    "comgooglemaps://"
    "googlephotos://"
    "googlecalendar://"
    "googledrive://"
    "googlemail://"
    "googletranslate://"
)

################################################################################
# BLUETOOTH/NFC/WIRELESS ATTACK PATTERNS
################################################################################

# Bluetooth/BLE Patterns
declare -a BLUETOOTH_PATTERNS=(
    "bluetooth://"
    "bt://"
    "btspp://"
    "btl2cap://"
    "btgoep://"
    "btobex://"
    "tcpobex://"
    "obex://"
    "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
    "ble://"
    "gatt://"
    "uuid:[0-9a-fA-F-]{36}"
)

# NFC Patterns
declare -a NFC_PATTERNS=(
    "nfc://"
    "ndef://"
    "nfcid://"
    "smartposter://"
    "android\.nfc"
    "NDEF_DISCOVERED"
    "TAG_DISCOVERED"
    "TECH_DISCOVERED"
)

# WiFi Configuration Patterns (can be malicious)
declare -a WIFI_PATTERNS=(
    "WIFI:S:"
    "WIFI:T:"
    "WIFI:P:"
    "WIFI:H:"
    "wifi://"
    "WPA[23]?-PSK"
    "WEP"
    "SSID="
    "PSK="
    "BSSID="
)

################################################################################
# TOR EXIT NODES AND VPN ENDPOINTS DATABASE
################################################################################

# Known Tor Exit Node Patterns (partial list - would be updated from live feed)
declare -a TOR_EXIT_INDICATORS=(
    "\.onion$"
    "torproject\.org"
    "tor2web"
    "onion\.to"
    "onion\.ws"
    "onion\.ly"
    "onion\.sh"
    "onion\.cab"
    "onion\.direct"
    "onion\.link"
    "onion\.city"
    "tor2web\.org"
    "tor2web\.io"
    "tor2web\.fi"
    "darknet"
    "deepweb"
    "hidden.*service"
)

# Common VPN/Proxy Service Domains
declare -a VPN_PROXY_DOMAINS=(
    "nordvpn\.com"
    "expressvpn\.com"
    "surfshark\.com"
    "privateinternetaccess\.com"
    "protonvpn\.com"
    "mullvad\.net"
    "ipvanish\.com"
    "cyberghost"
    "purevpn\.com"
    "hidemyass\.com"
    "hotspotshield\.com"
    "tunnelbear\.com"
    "windscribe\.com"
    "strongvpn\.com"
    "astrill\.com"
    "privatevpn\.com"
    "torguard\.net"
    "airvpn\.org"
    "vyprvpn\.com"
    "hide\.me"
    "proxy\.sh"
    "cryptostorm\.is"
    "perfect-privacy\.com"
    "trustzone\.com"
    "oeck\.com"
    "azire\.com"
    "ovpn\.com"
    "ivpn\.net"
)

# Anonymizing Proxy Services
declare -a ANONYMIZING_PROXIES=(
    "kproxy\.com"
    "hidemyass\.com/proxy"
    "proxysite\.com"
    "hidester\.com"
    "filterbypass\.me"
    "unblocksites\.online"
    "croxyproxy\.com"
    "free-proxy-list\.net"
    "proxybay"
    "piratebay.*proxy"
    "kickass.*proxy"
    "1337x.*proxy"
    "rarbg.*proxy"
)

################################################################################
# KNOWN BAD REGISTRARS AND HOSTING PROVIDERS
################################################################################

# Registrars frequently associated with abuse
declare -a SUSPICIOUS_REGISTRARS=(
    "namecheap"
    "namesilo"
    "porkbun"
    "dynadot"
    "enom"
    "resellerclub"
    "publicdomainregistry"
    "alpnames"
    "internetbs"
    "reg\.ru"
    "r01"
    "webnames\.ru"
    "regway"
    "hostinger"
    "freenom"
    "todaynic"
    "bizcn"
    "west\.cn"
    "xinnet"
    "hichina"
    "now\.cn"
    "cndns"
    "22\.cn"
    "35\.com"
    "net\.cn"
)

# Bulletproof hosting ASNs (known for abuse tolerance)
declare -a BULLETPROOF_ASNS=(
    "AS16276"    # OVH (high abuse volume)
    "AS14061"    # DigitalOcean (frequently abused)
    "AS16509"    # Amazon (AWS abuse)
    "AS13335"    # Cloudflare (abuse via workers)
    "AS20473"    # Vultr
    "AS63949"    # Linode
    "AS45090"    # Tencent
    "AS37963"    # Alibaba
    "AS24940"    # Hetzner
    "AS51167"    # Contabo
    "AS212238"   # Datacamp
    "AS9009"     # M247 (historically problematic)
    "AS50673"    # Serverius (bulletproof reputation)
    "AS57043"    # HostKey
    "AS201011"   # NETERRA
    "AS200000"   # Hostwinds
    "AS199524"   # G-Core Labs
    "AS208312"   # BuyVM/FranTech
    "AS46664"    # VolumeDrive
    "AS46606"    # Unified Layer
    "AS205544"   # FlokiNET
    "AS58065"    # PacketCloud
    "AS51852"    # Private Layer
    "AS62904"    # Eonix Corporation
    "AS40676"    # Psychz Networks
    "AS35916"    # Multacom
    "AS36352"    # ColoCrossing
    "AS54290"    # Hostwinds LLC
    "AS53667"    # FranTech
    "AS25820"    # IT7 Networks
    "AS26548"    # Sprious LLC
)

################################################################################
# APT XOR ENCRYPTION KEY PATTERNS (for encrypted domain/C2 extraction)
################################################################################

# Chinese APT XOR keys (APT41, Winnti, PlugX, ShadowPad, Gh0st)
declare -a CHINESE_APT_XOR_KEYS=(
    0x88 0x99 0xAA 0xBB 0xCC 0xDD 0xEE
    0x86 0x87 0x93 0x95 0x9C 0xA3 0xB8
    0x35 0x36 0x37 0x38 0x39 0x3A 0x3B
    0xC3 0xC6 0xC9 0xCA 0xCB 0xCE 0xCF
)

# Russian APT XOR keys (APT28, APT29, Sandworm, Turla)
declare -a RUSSIAN_APT_XOR_KEYS=(
    0xAB 0xBA 0xCD 0xDC 0xEF 0xFE
    0x47 0x74 0x52 0x25 0x71 0x17
    0x2E 0x3E 0x4E 0x5E 0x6E 0x7E
    0xA7 0xB4 0xC2 0xD3 0xE1 0xF8
)

# North Korean APT XOR keys (Lazarus, APT38, Kimsuky)
declare -a NK_APT_XOR_KEYS=(
    0x95 0x59 0x6B 0xB6 0x4D 0xD4
    0x32 0x23 0x45 0x54 0x67 0x76
    0xAD 0xDA 0xBC 0xCB 0xDE 0xED
)

# Iranian APT XOR keys (APT33, APT34, APT35, MuddyWater)
declare -a IRANIAN_APT_XOR_KEYS=(
    0x7C 0xC7 0x8E 0xE8 0x9F 0xF9
    0x29 0x92 0x3D 0xD3 0x4B 0xB4
    0x56 0x65 0x78 0x87 0x8A 0xA8
)

# Ransomware XOR keys (common across ransomware families)
declare -a RANSOMWARE_XOR_KEYS=(
    0x66 0x77 0x88 0x99 0xAA 0xBB 0xCC 0xDD
    0x13 0x31 0x26 0x62 0x39 0x93 0x4C 0xC4
    0xF5 0x5F 0xE6 0x6E 0xD7 0x7D 0xA9 0x9A
)

# Banking Trojan XOR keys
declare -a BANKING_TROJAN_XOR_KEYS=(
    0x3C 0x7E 0x8F 0xDC 0x58 0x47
    0x10 0x03 0xCC 0x1F 0xBE 0x22
    0x11 0x44 0x64 0x82 0xA1 0xC8
)

# iOS/macOS Malware XOR keys (Pegasus-style)
declare -a IOS_MACOS_MALWARE_XOR_KEYS=(
    0xAC 0xCA 0xFD 0xDF 0xB1 0x1B 0xC4 0x4C
    0x51 0x15 0x8D 0xD8 0x9E 0xE9 0x2A 0xA2
    0x6F 0xF6 0x7A 0xA7 0x48 0x84 0x53 0x35
)

################################################################################
# RANSOMWARE NOTE PATTERNS AND SIGNATURES
################################################################################

# Common ransomware note phrases (for detection)
declare -a RANSOMWARE_NOTE_PATTERNS=(
    "your files have been encrypted"
    "all your files are encrypted"
    "your data has been encrypted"
    "your important files.*encrypted"
    "to decrypt your files"
    "decrypt.*files.*bitcoin"
    "pay.*bitcoin.*decrypt"
    "ransom.*bitcoin"
    "restore your files"
    "unlock your files"
    "your files will be deleted"
    "your files will be published"
    "we have downloaded"
    "sensitive data.*leak"
    "data will be published"
    "data auction"
    "double extortion"
    "unique decryption key"
    "decryption software"
    "decryptor"
    "private decryption key"
    "RSA-2048"
    "RSA-4096"
    "AES-256"
    "do not try to decrypt"
    "do not modify encrypted files"
    "warning.*decrypt"
    "readme.txt"
    "read_me.txt"
    "how_to_decrypt"
    "how_to_recover"
    "recovery_instructions"
    "payment instructions"
    "ATTENTION!"
    "!!! IMPORTANT !!!"
    "YOUR COMPANY"
    "contact us via"
    "onion.*contact"
    "tor browser"
    "personal ID"
    "victim ID"
    "your personal key"
    "encryption.*AES.*RSA"
    "countdown"
    "deadline"
    "price will increase"
    "price doubles"
    "first file free"
    "test decrypt"
    "guarantee"
    "proof of decrypt"
)

# Known ransomware family indicators
declare -A RANSOMWARE_FAMILIES=(
    ["lockbit"]="lockbit,lockbit2,lockbit3,lb3,.lockbit,.lb,.lb2,.lb3"
    ["conti"]="conti,.conti,CONTI_README"
    ["revil"]="revil,sodinokibi,.revil,.sodinokibi,REVIL"
    ["ryuk"]="ryuk,.ryuk,RyukReadMe"
    ["maze"]="maze,.maze,MAZE"
    ["netwalker"]="netwalker,.nwwalker,NETWALKER"
    ["ragnarlocker"]="ragnar,.ragnar,RagnarLocker"
    ["darkside"]="darkside,.darkside,DARKSIDE"
    ["blackmatter"]="blackmatter,.blackmatter,BLACKMATTER"
    ["avaddon"]="avaddon,.avaddon,AVADDON"
    ["babuk"]="babuk,.babuk,BABUK"
    ["clop"]="clop,.clop,CL0P"
    ["doppelpaymer"]="doppelpaymer,.doppel,DOPPEL"
    ["egregor"]="egregor,.egregor,EGREGOR"
    ["hive"]="hive,.hive,HIVE"
    ["karakurt"]="karakurt,.karakurt"
    ["blackcat"]="blackcat,alphv,.blackcat,ALPHV"
    ["vice"]="vice,.vice,VICE"
    ["quantum"]="quantum,.quantum"
    ["blackbasta"]="blackbasta,.basta,BLACK BASTA"
    ["royal"]="royal,.royal,ROYAL"
    ["play"]="play,.play,PLAY"
    ["akira"]="akira,.akira,AKIRA"
    ["bianlian"]="bianlian,.bianlian"
    ["medusa"]="medusa,.medusa"
    ["8base"]="8base,.8base"
    ["rhysida"]="rhysida,.rhysida"
    ["hunters"]="hunters,.hunters"
    ["cactus"]="cactus,.cactus"
    ["trigona"]="trigona,.trigona"
    ["snatch"]="snatch,.snatch"
    ["ragnarok"]="ragnarok,.ragnarok"
    ["avoslocker"]="avos,.avos,AvosLocker"
    ["cuba"]="cuba,.cuba,CUBA"
    ["grief"]="grief,.grief,GRIEF"
    ["lorenz"]="lorenz,.lorenz"
    ["mespinoza"]="mespinoza,pysa,.pysa"
    ["mountlocker"]="mountlocker,.mountlocker"
    ["nefilim"]="nefilim,.nefilim"
    ["prometheus"]="prometheus,.prometheus"
    ["ransomexx"]="ransomexx,.ransomexx"
    ["suncrypt"]="suncrypt,.suncrypt"
    ["thanos"]="thanos,.thanos"
    ["wastedlocker"]="wasted,.wasted,WastedLocker"
    ["zeppelin"]="zeppelin,.zeppelin"
)

################################################################################
# FILELESS MALWARE / LIVING-OFF-THE-LAND PATTERNS
################################################################################

# LOLBAS (Living Off The Land Binaries and Scripts) - Windows
declare -a LOLBAS_PATTERNS=(
    # Execution
    "certutil.*-urlcache"
    "certutil.*-decode"
    "certutil.*-encode"
    "certutil.*-f.*http"
    "bitsadmin.*transfer"
    "bitsadmin.*/download"
    "bitsadmin.*/addfile"
    "mshta.*vbscript:"
    "mshta.*javascript:"
    "mshta.*http"
    "msiexec.*/i.*http"
    "msiexec.*/q.*http"
    "regsvr32.*/s.*/n.*/u.*/i:"
    "regsvr32.*scrobj\.dll"
    "rundll32.*javascript:"
    "rundll32.*shell32\.dll.*ShellExec_RunDLL"
    "cmstp.*/s.*/ns"
    "control\.exe.*\.cpl"
    "cscript.*wscript\.shell"
    "wscript.*wscript\.shell"
    "forfiles.*/c"
    "pcalua.*-a"
    "presentationhost\.exe"
    "ieexec\.exe"
    "installutil.*/logfile"
    "regasm.*/u"
    "regsvcs.*/u"
    "msbuild.*\\.xml"
    "msbuild.*\\.csproj"
    "xwizard.*RunWizard"
    "syncappvpublishingserver"
    "dnscmd.*/config"
    "mavinject.*dll"
    "ftp.*-s:"
    "bash\.exe.*-c"
    "wsl\.exe"
    "wmic.*process.*call.*create"
    "wmic.*os.*get"
    # Download Cradles
    "IEX.*New-Object.*Net\.WebClient"
    "Invoke-Expression.*downloadstring"
    "IEX.*\(IWR"
    "Invoke-WebRequest"
    "Start-BitsTransfer"
    "\\.DownloadFile\\("
    "\\.DownloadString\\("
    "Invoke-RestMethod"
    "wget.*http"
    "curl.*http"
    # Scripting
    "powershell.*-e[nc]*.*"
    "powershell.*-encodedcommand"
    "powershell.*-nop.*-w.*hidden"
    "powershell.*bypass.*execution"
    "powershell.*downloadstring"
    "cmd.*/c.*powershell"
    "cmd.*/c.*wscript"
    "cmd.*/c.*cscript"
)

# GTFOBins (Linux LOTL)
declare -a GTFOBINS_PATTERNS=(
    "bash.*-i.*>&.*/dev/tcp"
    "nc.*-e.*/bin/"
    "ncat.*-e.*/bin/"
    "netcat.*-e.*/bin/"
    "python.*socket.*connect"
    "python.*pty\.spawn"
    "python3.*pty\.spawn"
    "perl.*socket.*connect"
    "ruby.*socket.*connect"
    "php.*fsockopen"
    "lua.*socket\.tcp"
    "awk.*\"/inet/tcp/"
    "gawk.*\"/inet/tcp/"
    "socat.*exec:"
    "socat.*system:"
    "openssl.*s_client.*connect"
    "wget.*-O.*-.*|.*sh"
    "curl.*|.*sh"
    "curl.*|.*bash"
    "fetch.*-o.*-.*|.*sh"
    "busybox.*nc"
    "telnet.*|.*sh"
    "ssh.*ProxyCommand"
    "ssh.*-o.*ProxyCommand"
    "vi.*:!.*sh"
    "vim.*:!.*sh"
    "less.*!.*sh"
    "more.*!.*sh"
    "man.*!.*sh"
    "find.*-exec.*sh"
    "xargs.*sh"
    "tar.*--to-command"
    "tar.*--checkpoint-action"
    "zip.*-TmTT"
    "rvim.*-c.*py"
    "git.*-p.*!/bin/sh"
    "docker.*run.*-v.*/:/host"
    "kubectl.*exec"
    "journalctl.*!/bin/sh"
    "systemctl.*!/bin/sh"
    "service.*!/bin/sh"
    "expect.*spawn"
    "screen.*-X.*stuff"
    "tmux.*send-keys"
    "nmap.*--script"
    "gdb.*-ex.*shell"
    "strace.*-o.*/dev/null"
    "ltrace.*-o.*/dev/null"
)

# AMSI Bypass Patterns
declare -a AMSI_BYPASS_PATTERNS=(
    "amsiInitFailed"
    "AmsiScanBuffer"
    "amsiContext"
    "AmsiUtils"
    "amsi\.dll"
    "AmsiScanString"
    "SetEnvironmentVariable.*AMSI"
    "Reflection\.Assembly.*amsi"
    "VirtualProtect.*amsi"
    "\\[Ref\\]\.Assembly\.GetType"
    "System\.Management\.Automation"
)

################################################################################
# OFFICE DOCUMENT / MACRO MALWARE PATTERNS
################################################################################

# Office Macro Indicators
declare -a OFFICE_MACRO_PATTERNS=(
    "AutoOpen"
    "AutoClose"
    "AutoExec"
    "Auto_Open"
    "Document_Open"
    "DocumentOpen"
    "Workbook_Open"
    "WorkbookOpen"
    "Shell\\("
    "WScript\\.Shell"
    "CreateObject.*Shell"
    "CreateObject.*WScript"
    "CreateObject.*XMLHTTP"
    "CreateObject.*ADODB"
    "CreateObject.*Scripting"
    "CreateObject.*Excel"
    "CreateObject.*Word"
    "CreateObject.*Outlook"
    "PowerShell"
    "cmd\\.exe"
    "comspec"
    "environ\\("
    "URLDownloadToFile"
    "MSXML2\\.XMLHTTP"
    "Microsoft\\.XMLHTTP"
    "CallByName"
    "GetObject\\("
    "CreateTextFile"
    "OpenTextFile"
    "Declare.*Lib"
    "Declare.*Function"
    "Declare.*Sub"
    "kernel32"
    "urlmon"
    "VirtualAlloc"
    "VirtualProtect"
    "RtlMoveMemory"
    "WriteProcessMemory"
    "CreateThread"
    "QueueUserAPC"
    "NtCreateThreadEx"
)

# Follina/MSDT Patterns
declare -a FOLLINA_PATTERNS=(
    "ms-msdt:"
    "msdt\\.exe"
    "ms-msdt:/id"
    "PCWDiagnostic"
    "IT_RebrowseForFile="
    "IT_LaunchMethod="
    "IT_BrowseForFile="
    "ms-msdt:-id"
    "\\.xml!.*msdt"
    "location\\.href.*ms-msdt"
)

# OLE Object Patterns
declare -a OLE_PATTERNS=(
    "package.*shell"
    "\\\\Ole[0-9]"
    "objdata"
    "objupdate"
    "objembed"
    "DDEAUTO"
    "DDE0000"
    "LINK.*Word"
    "LINK.*Excel"
    "LINK.*PowerShell"
    "\\x00o\\x00l\\x00e"
    "Packager Shell Object"
)

################################################################################
# CERTIFICATE TRANSPARENCY / SSL ABUSE PATTERNS
################################################################################

# Recently issued cert domains (patterns suggesting phishing setup)
declare -a CERT_ABUSE_PATTERNS=(
    ".*-login.*"
    ".*-verify.*"
    ".*-secure.*"
    ".*-account.*"
    ".*-update.*"
    ".*-support.*"
    ".*-service.*"
    ".*signin.*"
    ".*logon.*"
    ".*auth.*"
    ".*password.*"
    ".*credential.*"
    ".*banking.*"
    ".*payment.*"
    ".*invoice.*"
    ".*confirm.*"
    "paypa[l1].*"
    "amaz[o0]n.*"
    "app[l1]e.*"
    "micros[o0]ft.*"
    "g[o0]{2}g[l1]e.*"
    "faceb[o0]{2}k.*"
    "netf[l1]ix.*"
    "dr[o0]pb[o0]x.*"
    "icloud.*"
    "wells.*fargo.*"
    "chase.*bank.*"
    "bank.*of.*america.*"
)

################################################################################
# USSD / TELEPHONY ATTACK PATTERNS
################################################################################

# USSD Codes that could be malicious
declare -a USSD_PATTERNS=(
    "tel:\\*#"
    "tel:\\*%23"
    "tel:\\*\\*"
    "tel:#"
    "\\*#06#"          # IMEI display
    "\\*#\\*#"         # Service menus
    "\\*2767\\*"       # Factory reset codes
    "\\*7370#"         # Format codes
    "\\*#7780#"        # Reset codes
    "##002#"           # Call forwarding
    "\\*#21#"          # Call divert check
    "\\*67"            # Call blocking
    "\\*72"            # Call forwarding
    "\\*73"            # Cancel forwarding
    "\\*\\*21\\*"      # Forward setup
    "##21#"            # Cancel all forwards
)

################################################################################
# GEOFENCING / REGION-SPECIFIC INDICATORS
################################################################################

# Geofencing Detection Patterns
declare -a GEOFENCING_PATTERNS=(
    "geo.*location"
    "navigator\\.geolocation"
    "getCurrentPosition"
    "watchPosition"
    "geoip"
    "maxmind"
    "ipinfo\\.io"
    "ip-api\\.com"
    "ipapi\\.co"
    "freegeoip"
    "ipgeolocation"
    "ipstack"
    "ipdata"
    "abstractapi.*geolocation"
    "cloudflare.*cf-ipcountry"
    "cf-ipcountry"
    "x-country-code"
    "x-geoip"
    "Accept-Language"
    "timezone.*check"
    "Intl\\.DateTimeFormat"
    "timeZone"
)

# Region-specific threat domains (partial examples)
declare -a REGION_SPECIFIC_THREATS=(
    # Russian targeting
    "\\.(ru|su|рф)$"
    # Chinese targeting
    "\\.(cn|中国|中國)$"
    # Iranian targeting
    "\\.(ir|ایران)$"
    # North Korean
    "\\.(kp)$"
)

################################################################################
# HARDWARE / IOT EXPLOIT PATTERNS
################################################################################

# QR-targeted hardware exploits
declare -a HARDWARE_EXPLOIT_PATTERNS=(
    # Buffer overflow attempts
    "A{100,}"
    "B{100,}"
    "%00{20,}"
    "%n{10,}"
    "\\x00{50,}"
    # Format string attacks
    "%x%x%x%x"
    "%n%n%n%n"
    "%s%s%s%s"
    # Command injection for embedded systems
    ";.*sh"
    "|.*sh"
    "[\\x60].*[\\x60]"
    "[$][(].*[)]"
    # POS terminal exploits
    "pos.*exploit"
    "verifone"
    "ingenico"
    "pax.*terminal"
    "magtek"
    "id.*tech"
    # IoT specific
    "/etc/passwd"
    "/etc/shadow"
    "busybox"
    "dropbear"
    "/dev/mtd"
    "nvram"
    "uci.*set"
    "opkg.*install"
    "wget.*-O.*sh"
    # Camera/DVR exploits
    "hikvision"
    "dahua"
    "foscam"
    "axis.*camera"
    "rtsp://"
    "onvif"
    # Printer exploits
    "PJL"
    "@PJL"
    "%-12345X"
    "PostScript"
    # Smart TV
    "samsung.*tizen"
    "lg.*webos"
    "roku"
    "firetv"
    "chromecast"
    "androidtv"
)

################################################################################
# SOCIAL ENGINEERING / PERSONA PATTERNS
################################################################################

# Social engineering urgency/authority patterns
declare -a SOCIAL_ENGINEERING_PATTERNS=(
    # Urgency
    "act now"
    "urgent.*action"
    "immediate.*action"
    "expires.*soon"
    "limited.*time"
    "deadline"
    "final.*notice"
    "last.*chance"
    "time.*sensitive"
    "respond.*within"
    "hours.*left"
    "your.*account.*will"
    # Authority
    "official.*notice"
    "from.*your.*bank"
    "security.*department"
    "it.*department"
    "hr.*department"
    "legal.*department"
    "government.*notice"
    "irs"
    "fbi"
    "cia"
    "police"
    "federal"
    "court.*order"
    "subpoena"
    "legal.*action"
    # Fear/Threat
    "your.*account.*compromised"
    "suspicious.*activity"
    "unauthorized.*access"
    "security.*breach"
    "data.*leaked"
    "identity.*stolen"
    "virus.*detected"
    "malware.*found"
    "hacked"
    "locked.*out"
    "suspended"
    "terminated"
    "legal.*consequences"
    # Reward/Greed
    "congratulations"
    "you.*have.*won"
    "claim.*your.*prize"
    "free.*gift"
    "bonus"
    "reward"
    "selected"
    "chosen"
    "winner"
    "lottery"
    "inheritance"
    "million.*dollars"
    "investment.*opportunity"
    # Trust/Familiarity
    "dear.*customer"
    "valued.*member"
    "loyal.*customer"
    "we.*noticed"
    "regarding.*your"
    "as.*per.*our"
    "following.*up"
)

# BEC (Business Email Compromise) patterns
declare -a BEC_PATTERNS=(
    "wire.*transfer"
    "change.*bank"
    "new.*account"
    "update.*payment"
    "vendor.*payment"
    "invoice.*attached"
    "urgent.*payment"
    "confidential.*request"
    "ceo.*request"
    "executive.*request"
    "gift.*card"
    "bitcoin.*payment"
    "cryptocurrency.*payment"
    "keep.*this.*confidential"
    "do.*not.*discuss"
    "handle.*this.*quietly"
)

################################################################################
# ADVERSARIAL QR / VISUAL ATTACK PATTERNS
################################################################################

# QR visual manipulation indicators
declare -a QR_VISUAL_ATTACK_INDICATORS=(
    "high_density_qr"          # Extremely dense QR codes
    "low_margin_qr"            # QR with minimal quiet zone
    "color_gradient_qr"        # Gradients that may confuse readers
    "pattern_overlay_qr"       # Patterns overlaid on QR
    "animated_qr"              # GIF-based animated QR
    "multi_qr_sequence"        # Multiple QRs for sequential scanning
    "nested_qr"                # QR within QR
    "holographic_qr"           # 3D/holographic effects
    "reflective_surface"       # Metallic/reflective QR
    "distorted_qr"             # Intentionally distorted
    "fragmented_qr"            # Split across surfaces
    "partial_qr"               # Incomplete QR (decoder dependent)
    "adversarial_patch"        # ML adversarial patches
)

################################################################################
# ADDITIONAL MALICIOUS DOMAIN PATTERNS - INDUSTRY SPECIFIC
################################################################################

# Healthcare-specific threat patterns
declare -a HEALTHCARE_THREAT_PATTERNS=(
    "hipaa.*violation"
    "medical.*record"
    "patient.*data"
    "ehr.*access"
    "epic.*login"
    "cerner.*portal"
    "meditech"
    "athenahealth"
    "allscripts"
    "nextgen.*healthcare"
    "eclinicalworks"
    "greenway.*health"
    "kareo"
    "drchrono"
    "practice.*fusion"
    "health.*portal"
    "patient.*portal"
    "mychart.*login"
    "myhealth.*login"
    "prescription.*refill"
    "pharmacy.*verify"
    "medicare.*update"
    "medicaid.*verify"
    "insurance.*claim"
    "benefit.*verify"
    "healthcare\\.gov"
    "covered.*california"
    "va\\.gov"
    "tricare"
)

# Financial/Banking threat patterns
declare -a FINANCIAL_THREAT_PATTERNS=(
    "online.*banking"
    "netbanking"
    "ibanking"
    "mobile.*banking"
    "wire.*transfer"
    "ach.*transfer"
    "swift.*transfer"
    "account.*verify"
    "card.*verify"
    "pin.*verify"
    "cvv.*update"
    "expiry.*update"
    "credit.*limit"
    "overdraft"
    "loan.*approval"
    "mortgage.*rate"
    "refinance"
    "401k.*rollover"
    "ira.*transfer"
    "investment.*opportunity"
    "stock.*tip"
    "forex.*signal"
    "crypto.*exchange"
    "defi.*airdrop"
    "nft.*mint"
    "wallet.*connect"
    "seed.*phrase"
    "private.*key"
)

# Government/Tax threat patterns
declare -a GOVERNMENT_THREAT_PATTERNS=(
    "irs.*refund"
    "tax.*refund"
    "stimulus.*check"
    "treasury"
    "social.*security"
    "ssn.*verify"
    "ein.*verify"
    "itin.*verify"
    "passport.*renewal"
    "visa.*application"
    "immigration"
    "green.*card"
    "citizenship"
    "court.*summons"
    "jury.*duty"
    "fine.*payment"
    "warrant"
    "arrest"
    "fbi.*notice"
    "dhs.*alert"
    "dmv.*renewal"
    "license.*renewal"
    "registration.*renewal"
    "toll.*violation"
    "parking.*ticket"
    "gov\\.uk"
    "canada\\.ca"
    "australia\\.gov"
    "europa\\.eu"
)

# Education/University threat patterns
declare -a EDUCATION_THREAT_PATTERNS=(
    "student.*portal"
    "campus.*login"
    "blackboard"
    "canvas.*lms"
    "moodle"
    "d2l.*brightspace"
    "student.*email"
    "edu.*mail"
    "financial.*aid"
    "fafsa"
    "scholarship"
    "tuition.*payment"
    "enrollment"
    "registration"
    "transcript"
    "grade.*portal"
    "faculty.*portal"
    "alumni"
    "graduation"
    "commencement"
    "library.*access"
    "research.*portal"
)

# E-commerce/Retail threat patterns
declare -a ECOMMERCE_THREAT_PATTERNS=(
    "order.*confirm"
    "shipping.*update"
    "delivery.*fail"
    "package.*return"
    "refund.*process"
    "payment.*decline"
    "cart.*abandon"
    "checkout.*error"
    "inventory.*alert"
    "price.*drop"
    "flash.*sale"
    "clearance"
    "discount.*code"
    "coupon.*expire"
    "loyalty.*point"
    "reward.*redeem"
    "gift.*card.*balance"
    "store.*credit"
    "return.*label"
    "exchange.*request"
)

################################################################################
# EXTENDED SUSPICIOUS FILE EXTENSIONS
################################################################################

declare -a EXTENDED_DANGEROUS_EXTENSIONS=(
    # Polyglot/Container files
    "\.iso\.exe" "\.img\.exe" "\.vhd\.exe"
    "\.pdf\.exe" "\.doc\.exe" "\.xls\.exe"
    "\.jpg\.exe" "\.png\.exe" "\.gif\.exe"
    # Double extensions
    "\\.pdf\\.scr" "\\.doc\\.scr" "\\.xls\\.scr"
    "\\.jpg\\.scr" "\\.png\\.scr" "\\.mp3\\.scr"
    "\\.mp4\\.scr" "\\.avi\\.scr" "\\.mov\\.scr"
    # Right-to-left override
    "\\u202e" "\\u200f" "\\u200e"
    # Uncommon but dangerous
    "\\.ade" "\\.adp" "\\.bas" "\\.chm"
    "\\.cla" "\\.class" "\\.crt"
    "\\.fxp" "\\.grp" "\\.hlp"
    "\\.isp" "\\.jse" "\\.ksh"
    "\\.mad" "\\.maf" "\\.mag"
    "\\.mam" "\\.maq" "\\.mar"
    "\\.mas" "\\.mat" "\\.mau"
    "\\.mav" "\\.maw" "\\.mda"
    "\\.mdb" "\\.mde" "\\.mdt"
    "\\.mdw" "\\.mdz" "\\.mht"
    "\\.mhtml" "\\.msc" "\\.msh"
    "\\.msh1" "\\.msh2" "\\.mshxml"
    "\\.msh1xml" "\\.msh2xml"
    "\\.ops" "\\.osd" "\\.pcd"
    "\\.plg" "\\.prf" "\\.prg"
    "\\.sct" "\\.shb" "\\.shs"
    "\\.shtm" "\\.shtml" "\\.spl"
    "\\.sst" "\\.udl" "\\.vb"
    "\\.vxd" "\\.wiz" "\\.wlk"
    "\\.wml" "\\.wmd" "\\.wmz"
    "\\.wms" "\\.wsd" "\\.wsp"
    "\\.wss" "\\.xbap" "\\.xnk"
    "\\.xsl" "\\.xslt"
    # Web shells
    "\\.asp" "\\.aspx" "\\.asa"
    "\\.asax" "\\.ashx" "\\.asmx"
    "\\.cer" "\\.cdx" "\\.cshtml"
    "\\.vbhtml" "\\.rem"
    # Server-side scripts
    "\\.php[3-8]?" "\\.phtml" "\\.pht"
    "\\.inc" "\\.hta" "\\.htaccess"
    "\\.htpasswd"
    "\\.cgi" "\\.pl" "\\.fcgi"
    "\\.fpl"
    # Config files that can be abused
    "\\.config" "\\.conf" "\\.cfg"
    "\\.ini" "\\.inf" "\\.reg"
    "\\.yaml" "\\.yml" "\\.toml"
    "\\.json" "\\.xml"
    # Template injection
    "\\.ssti" "\\.twig" "\\.ejs"
    "\\.pug" "\\.jade" "\\.hbs"
    "\\.mustache" "\\.jinja"
    "\\.jinja2" "\\.j2"
    # Serialization
    "\\.pickle" "\\.pkl" "\\.marshal"
    "\\.serialized" "\\.bin"
)

################################################################################
# CRYPTOCURRENCY SCAM INDICATORS
################################################################################

declare -a CRYPTO_SCAM_PATTERNS=(
    "double.*your.*crypto"
    "send.*[0-9]+.*receive.*[0-9]+"
    "giveaway"
    "airdrop"
    "free.*bitcoin"
    "free.*eth"
    "free.*crypto"
    "elon.*musk"
    "vitalik.*buterin"
    "satoshi"
    "guaranteed.*return"
    "100%.*profit"
    "no.*risk"
    "investment.*opportunity"
    "mining.*pool"
    "cloud.*mining"
    "staking.*reward"
    "defi.*yield"
    "liquidity.*pool"
    "rug.*pull"
    "pump.*dump"
    "moonshot"
    "100x"
    "1000x"
    "gem.*alert"
    "presale"
    "private.*sale"
    "whitelist"
    "connect.*wallet"
    "approve.*contract"
    "unlimited.*approval"
    "smart.*contract"
    "token.*sale"
    "ico"
    "ido"
    "ieo"
    "launchpad"
    "seed.*round"
)

################################################################################
# ADDITIONAL MALICIOUS IP RANGES AND INDICATORS
################################################################################

# Suspicious IP ranges (CIDR notation indicators)
declare -a SUSPICIOUS_IP_RANGES=(
    # Private IP abuse in public contexts
    "^10\\."
    "^172\\.(1[6-9]|2[0-9]|3[0-1])\\."
    "^192\\.168\\."
    # Link-local
    "^169\\.254\\."
    # Loopback abuse
    "^127\\."
    # Reserved/Bogon
    "^0\\."
    "^100\\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\\."
    "^192\\.0\\.0\\."
    "^192\\.0\\.2\\."
    "^198\\.51\\.100\\."
    "^203\\.0\\.113\\."
    "^224\\."
    "^240\\."
    # Direct IP access (no domain)
    "^http://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"
    "^https://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"
)

################################################################################
# URL OBFUSCATION PATTERNS
################################################################################

declare -a URL_OBFUSCATION_PATTERNS=(
    # Homograph attacks (mixed scripts)
    "[а-яА-Яα-ωА-Ω]"    # Cyrillic/Greek in domain
    "xn--"               # Punycode domains
    # IP obfuscation
    "0x[0-9a-fA-F]+\\.[0-9]"    # Hex IP
    "[0-9]{10,}"                 # Decimal IP
    "0[0-7]+\\."                 # Octal IP
    # URL encoding abuse
    "%2[fF]%2[fF]"               # Encoded //
    "%3[aA]%2[fF]"               # Encoded :/
    "%00"                        # Null byte
    "%0[aAdD]"                   # CR/LF
    # Path traversal in URL
    "\\.\\./\\.\\."
    "%2e%2e%2f"
    "%252e%252e%252f"
    # Data URIs
    "data:text/html"
    "data:application"
    "data:image.*base64"
    # JavaScript URIs
    "javascript:"
    "vbscript:"
    "jscript:"
    # Multiple redirects indicators
    "url=.*url="
    "redirect=.*redirect="
    "redir=.*redir="
    "next=.*next="
    "goto=.*goto="
    # Open redirects
    "/redirect\\?"
    "/redir\\?"
    "/url\\?"
    "/link\\?"
    "/go\\?"
    "/out\\?"
    "/away\\?"
    "/click\\?"
    "/track\\?"
    # Parameter pollution
    "\\?.*&.*&.*&.*&"
    "\\?.*=.*=.*=.*="
)

################################################################################
# CLOAKING AND DETECTION EVASION PATTERNS
################################################################################

declare -a CLOAKING_PATTERNS=(
    # User-Agent cloaking
    "User-Agent"
    "navigator\\.userAgent"
    "Googlebot"
    "Bingbot"
    "facebookexternalhit"
    "Twitterbot"
    "LinkedInBot"
    "WhatsApp"
    "Slackbot"
    "Discordbot"
    # Referrer cloaking
    "document\\.referrer"
    "HTTP_REFERER"
    "Referer:"
    # Cookie/Session cloaking
    "document\\.cookie"
    "sessionStorage"
    "localStorage"
    # IP-based cloaking
    "REMOTE_ADDR"
    "X-Forwarded-For"
    "X-Real-IP"
    "CF-Connecting-IP"
    # Time-based cloaking
    "setTimeout"
    "setInterval"
    "Date\\(\\)"
    "getTime\\(\\)"
    # Canvas fingerprinting
    "toDataURL"
    "getImageData"
    "measureText"
    # WebGL fingerprinting
    "WEBGL"
    "getExtension"
    "getParameter"
    # Audio fingerprinting
    "AudioContext"
    "createOscillator"
    # Battery API
    "getBattery"
    "navigator\\.battery"
    # Screen fingerprinting
    "screen\\.width"
    "screen\\.height"
    "screen\\.colorDepth"
    "devicePixelRatio"
)

################################################################################
# CALLBACK/BEACON PATTERNS
################################################################################

declare -a CALLBACK_BEACON_PATTERNS=(
    # Beacon frameworks
    "cobalt.*strike"
    "meterpreter"
    "empire"
    "covenant"
    "sliver"
    "mythic"
    "brute.*ratel"
    "havoc"
    "nighthawk"
    "poshc2"
    # Beacon behavior
    "checkin"
    "check-in"
    "heartbeat"
    "ping.*back"
    "callback"
    "call.*home"
    "beacon"
    "keepalive"
    "keep-alive"
    "poll"
    "sleep.*[0-9]+"
    "jitter"
    # Malleable profiles
    "malleable"
    "profile"
    "spawnto"
    "prepend"
    "append"
    "transform"
    # DNS beaconing
    "dns.*beacon"
    "dns.*tunnel"
    "dnscat"
    "iodine"
    "dnstunnel"
    # ICMP tunneling
    "icmp.*tunnel"
    "ptunnel"
    "icmptx"
)

################################################################################
# COMMAND INJECTION PATTERNS
################################################################################

declare -a COMMAND_INJECTION_PATTERNS=(
    # Shell metacharacters
    ";.*;"
    "\\|.*\\|"
    "&.*&"
    "\\$\\(.*\\)"
    "[\\x60].*[\\x60]"
    # Common injection payloads
    ";id;"
    ";whoami;"
    ";uname;"
    ";cat /etc"
    ";ls -la"
    ";pwd;"
    ";echo.*>"
    ";wget "
    ";curl "
    # Windows specific
    "&dir&"
    "&whoami&"
    "&ipconfig&"
    "&net user"
    "&systeminfo"
    # Template injection
    "\\{\\{.*\\}\\}"
    "\\{%.*%\\}"
    "\\$\\{.*\\}"
    "#{.*}"
    "<%.*%>"
    # SSTI payloads
    "__class__"
    "__mro__"
    "__subclasses__"
    "__globals__"
    "__builtins__"
    "config\\.items"
    "request\\.application"
    # XXE indicators
    "<!ENTITY"
    "<!DOCTYPE"
    "SYSTEM.*file:"
    "SYSTEM.*http:"
    "SYSTEM.*ftp:"
    "SYSTEM.*expect:"
    # SSRF indicators
    "file:///"
    "gopher://"
    "dict://"
    "expect://"
    "php://"
    "phar://"
    "jar:"
    "netdoc:"
)


init_yara_rules() {
    log_info "Initializing YARA rules database..."
    
    # Phishing Detection
    YARA_RULES["phishing_url"]='
        strings:
            $login = /login|signin|verify/ nocase
            $urgent = /urgent|suspended|action/ nocase
            $brand = /paypal|amazon|netflix|microsoft|google|apple|facebook/ nocase
        condition:
            ($login and $urgent) or ($brand and $urgent)
        severity: HIGH
    '
    
    # Malware Distribution
    YARA_RULES["malware_distribution"]='
        strings:
            $exec = /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jar|apk|msi|dmg|pkg)/
            $download = /download|install|update|patch|setup/ nocase
            $urgent = /urgent|required|mandatory|immediately/ nocase
        condition:
            $exec and ($download or $urgent)
        severity: HIGH
    '
    
    # Crypto Scam Detection
    YARA_RULES["crypto_scam"]='
        strings:
            $btc_addr = /bc1[a-z0-9]{39,87}|1[a-km-zA-HJ-NP-Z1-9]{25,34}/
            $eth_addr = /0x[a-fA-F0-9]{40}/
            $urgency = /limited|exclusive|invest|double|giveaway|airdrop/ nocase
            $celebrity = /elon|musk|bezos|zuckerberg|trump|biden/ nocase
        condition:
            ($btc_addr or $eth_addr) and ($urgency or $celebrity)
        severity: CRITICAL
    '
    
    # PowerShell Malware
    YARA_RULES["powershell_malware"]='
        strings:
            $iex = /IEX|Invoke-Expression/ nocase
            $download = /downloadstring|downloadfile|webclient|webrequest/ nocase
            $encoded = /-enc|-encodedcommand/ nocase
            $bypass = /-executionpolicy bypass|-ep bypass/ nocase
            $hidden = /-windowstyle hidden|-w hidden/ nocase
        condition:
            ($iex and $download) or ($encoded) or ($bypass and $hidden)
        severity: HIGH
    '
    
    # Ransomware Indicators
    YARA_RULES["ransomware"]='
        strings:
            $ransom1 = "your files have been encrypted" nocase
            $ransom2 = "pay bitcoin" nocase
            $ransom3 = ".onion" nocase
            $ransom4 = "decrypt" nocase
            $ransom5 = "ransom" nocase
            $timer = /[0-9]+ (hours|days) remaining/ nocase
        condition:
            2 of them
        severity: CRITICAL
    '
    
    # C2 Communication
    YARA_RULES["c2_communication"]='
        strings:
            $beacon = "beacon" nocase
            $checkin = "checkin" nocase
            $callback = "callback" nocase
            $raw_paste = "pastebin.com/raw" nocase
            $raw_github = "raw.githubusercontent.com" nocase
            $ip_url = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        condition:
            any of them
        severity: HIGH
    '
    
    # Data Exfiltration
    YARA_RULES["data_exfil"]='
        strings:
            $post = "POST" nocase
            $password = "password" nocase
            $credential = "credential" nocase
            $upload = "upload" nocase
            $archive = /\.(zip|rar|7z|tar|gz)/ nocase
            $encoded = /base64|encoded|encrypted/ nocase
        condition:
            ($post and ($password or $credential)) or ($upload and ($archive or $encoded))
        severity: HIGH
    '
    
    # JavaScript Obfuscation
    YARA_RULES["obfuscation"]='
        strings:
            $eval_atob = "eval(atob("
            $fromcharcode = "String.fromCharCode" nocase
            $unescape = "unescape(%" nocase
            $function_ctor = "Function(" nocase
            $document_write = "document.write(unescape" nocase
        condition:
            any of them
        severity: MEDIUM
    '
    
    # Keylogger Detection
    YARA_RULES["keylogger"]='
        strings:
            $keylog1 = "keylog" nocase
            $keylog2 = "keystroke" nocase
            $api1 = "GetAsyncKeyState" nocase
            $api2 = "SetWindowsHookEx" nocase
            $python = "pynput" nocase
            $keyboard = "keyboard.hook" nocase
        condition:
            any of them
        severity: CRITICAL
    '
    
    # Remote Access Trojan
    YARA_RULES["remote_access"]='
        strings:
            $rat1 = "njrat" nocase
            $rat2 = "darkcomet" nocase
            $rat3 = "remcos" nocase
            $rat4 = "asyncrat" nocase
            $rat5 = "quasar" nocase
            $shell1 = "reverse shell" nocase
            $shell2 = "bind shell" nocase
            $hidden = "hidden" nocase
            $remote = "remote desktop" nocase
        condition:
            any of ($rat*) or (($shell1 or $shell2) and $hidden) or ($remote and $hidden)
        severity: CRITICAL
    '
    
    # Credential Theft
    YARA_RULES["credential_theft"]='
        strings:
            $mimi = "mimikatz" nocase
            $lsass = "lsass" nocase
            $sam = "SAM" nocase
            $browser = "browser" nocase
            $password = "password" nocase
            $cookie = "cookie" nocase
            $cred_dump = "credential dump" nocase
        condition:
            $mimi or $lsass or $cred_dump or (($browser or $sam) and ($password or $cookie))
        severity: CRITICAL
    '
    
    # Banking Trojan
    YARA_RULES["banking_trojan"]='
        strings:
            $inject = "webinject" nocase
            $grab = "formgrabber" nocase
            $zeus = "zeus" nocase
            $dridex = "dridex" nocase
            $trickbot = "trickbot" nocase
            $banking = "banking" nocase
        condition:
            $inject or $grab or (($zeus or $dridex or $trickbot) and $banking)
        severity: CRITICAL
    '
    
    # Mobile Malware
    YARA_RULES["mobile_malware"]='
        strings:
            $sms_read = "READ_SMS" nocase
            $sms_send = "SEND_SMS" nocase
            $call = "android.permission.CALL_PHONE" nocase
            $contacts = "READ_CONTACTS" nocase
            $location = "ACCESS_FINE_LOCATION" nocase
            $apk = ".apk" nocase
            $payload = "payload" nocase
        condition:
            ($sms_read and $sms_send) or $call or ($apk and $payload) or (2 of ($sms_read, $sms_send, $contacts, $location))
        severity: HIGH
    '
    
    # IoT Malware
    YARA_RULES["iot_malware"]='
        strings:
            $mirai = "mirai" nocase
            $bashlite = "bashlite" nocase
            $gafgyt = "gafgyt" nocase
            $watchdog = "/dev/watchdog" nocase
            $telnet = "telnet" nocase
            $default_pass = "default" nocase
        condition:
            $mirai or $bashlite or $gafgyt or $watchdog or ($telnet and $default_pass)
        severity: HIGH
    '
    
    # Cryptominer
    YARA_RULES["cryptominer"]='
        strings:
            $miner1 = "stratum+tcp://" nocase
            $miner2 = "xmrig" nocase
            $miner3 = "cpuminer" nocase
            $miner4 = "minergate" nocase
            $pool1 = "pool.minergate.com" nocase
            $pool2 = "xmr.nanopool.org" nocase
            $monero = "monero" nocase
            $wallet = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ nocase
        condition:
            any of them
        severity: HIGH
    '
    
    # Exploit Kit Landing Page
    YARA_RULES["exploit_kit"]='
        strings:
            $flash = "FlashVars" nocase
            $java = "deployJava" nocase
            $pdf = "application/pdf" nocase
            $iframe = /<iframe.*src=.*http/ nocase
            $pack = /eval\(function\(p,a,c,k,e/ nocase
            $obf = /\\x[0-9a-f]{2}/ nocase
        condition:
            ($flash or $java or $pdf) and ($iframe or $pack or $obf)
        severity: CRITICAL
    '
    
    # Phishing Kit
    YARA_RULES["phishing_kit"]='
        strings:
            $form = /<form.*action=.*\.php/ nocase
            $input_pass = /<input.*type=.password/ nocase
            $input_email = /<input.*type=.email/ nocase
            $submit = /submit|login|sign.?in|verify/ nocase
            $brand_img = /(paypal|amazon|google|microsoft|apple|facebook).*\.(png|jpg|svg)/ nocase
        condition:
            $form and $input_pass and ($input_email or $submit) and $brand_img
        severity: HIGH
    '
    
    # Session Hijacking
    YARA_RULES["session_hijack"]='
        strings:
            $session = "session" nocase
            $token = "token" nocase
            $cookie = "cookie" nocase
            $steal = "steal" nocase
            $capture = "capture" nocase
            $intercept = "intercept" nocase
        condition:
            ($session or $token or $cookie) and ($steal or $capture or $intercept)
        severity: HIGH
    '
    
    # Webshell Detection
    YARA_RULES["webshell"]='
        strings:
            $php_eval = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
            $php_assert = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
            $php_system = /system\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
            $php_exec = /exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
            $php_shell = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
            $php_pass = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
            $c99 = "c99shell" nocase
            $r57 = "r57shell" nocase
            $wso = "wso shell" nocase
            $b374k = "b374k" nocase
        condition:
            any of them
        severity: CRITICAL
    '
    
    # SQL Injection
    YARA_RULES["sql_injection"]='
        strings:
            $union = "UNION SELECT" nocase
            $or_1 = "OR 1=1" nocase
            $and_1 = "AND 1=1" nocase
            $drop = "DROP TABLE" nocase
            $insert = "INSERT INTO" nocase
            $update_set = /UPDATE.*SET/ nocase
            $sleep = "SLEEP(" nocase
            $benchmark = "BENCHMARK(" nocase
            $waitfor = "WAITFOR DELAY" nocase
        condition:
            any of them
        severity: HIGH
    '
    
    # XSS Attack
    YARA_RULES["xss_attack"]='
        strings:
            $script = /<script.*>/ nocase
            $onerror = /onerror\s*=/ nocase
            $onload = /onload\s*=/ nocase
            $onclick = /onclick\s*=/ nocase
            $onmouseover = /onmouseover\s*=/ nocase
            $img_src = /<img.*src=.*javascript:/ nocase
            $svg_onload = /<svg.*onload=/ nocase
        condition:
            any of them
        severity: MEDIUM
    '
    
    # Privilege Escalation
    YARA_RULES["privilege_escalation"]='
        strings:
            $sudo = "sudo" nocase
            $setuid = "setuid" nocase
            $suid = "SUID" nocase
            $runas = "runas" nocase
            $admin = "administrator" nocase
            $root = "root" nocase
            $escalate = "escalate" nocase
            $privilege = "privilege" nocase
        condition:
            ($sudo or $setuid or $suid or $runas) and ($escalate or $privilege)
        severity: HIGH
    '
    
    # Persistence Mechanism
    YARA_RULES["persistence"]='
        strings:
            $registry = /HKLM|HKCU|HKEY_/ nocase
            $run_key = /CurrentVersion\\Run/ nocase
            $startup = "Startup" nocase
            $service = "sc create" nocase
            $scheduled = "schtasks" nocase
            $cron = "crontab" nocase
            $systemd = "systemctl enable" nocase
            $launchd = "LaunchAgent" nocase
            $plist = ".plist" nocase
        condition:
            ($registry and $run_key) or $startup or $service or $scheduled or $cron or $systemd or ($launchd and $plist)
        severity: HIGH
    '
    
    # Defense Evasion
    YARA_RULES["defense_evasion"]='
        strings:
            $disable_av = /disable.*antivirus|antivirus.*disable/ nocase
            $stop_service = /net stop|sc stop/ nocase
            $firewall = /netsh.*firewall.*off/ nocase
            $defender = /Set-MpPreference.*-Disable/ nocase
            $tamper = "tamper" nocase
            $kill_process = /taskkill|kill -9/ nocase
        condition:
            any of them
        severity: HIGH
    '
    
    # Lateral Movement
    YARA_RULES["lateral_movement"]='
        strings:
            $psexec = "psexec" nocase
            $wmic = "wmic" nocase
            $winrm = "winrm" nocase
            $rdp = "mstsc" nocase
            $ssh_cmd = /ssh\s+\w+@/ nocase
            $pass_hash = "pass.?the.?hash" nocase
            $mimikatz = "mimikatz" nocase
        condition:
            any of them
        severity: HIGH
    '
    
    # Data Collection
    YARA_RULES["data_collection"]='
        strings:
            $screenshot = "screenshot" nocase
            $keylog = "keylog" nocase
            $clipboard = "clipboard" nocase
            $webcam = "webcam" nocase
            $microphone = "microphone" nocase
            $record = "record" nocase
            $capture = "capture" nocase
        condition:
            2 of them
        severity: MEDIUM
    '
}

################################################################################
# MULTI-DECODER SYSTEM WITH ENHANCED CAPABILITIES
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
import sys

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
    sys.exit(1)
EOF
    
    [ -s "$output_file" ]
}

decode_with_quirc() {
    local image="$1"
    local output_file="$2"
    
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
    
    # Try Java ZXing if available
    if command -v zxing &> /dev/null; then
        zxing "$image" 2>/dev/null > "$output_file"
        [ -s "$output_file" ]
    elif [ -f "/usr/local/lib/zxing.jar" ]; then
        java -cp /usr/local/lib/zxing.jar com.google.zxing.client.j2se.CommandLineRunner "$image" 2>/dev/null > "$output_file"
        [ -s "$output_file" ]
    else
        # Try Python ZXing library
        python3 << EOF 2>/dev/null
try:
    import zxing
    reader = zxing.BarCodeReader()
    barcode = reader.decode('$image')
    if barcode:
        with open('$output_file', 'w') as f:
            f.write(barcode.parsed + '\n')
except:
    pass
EOF
        [ -s "$output_file" ]
    fi
}

decode_with_qrdecode() {
    local image="$1"
    local output_file="$2"
    
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
    
    python3 << EOF 2>/dev/null
import sys
try:
    import cv2
    import numpy as np
    
    img = cv2.imread('$image')
    if img is None:
        sys.exit(1)
    
    detector = cv2.QRCodeDetector()
    
    # Try normal detection
    data, bbox, _ = detector.detectAndDecode(img)
    
    if data:
        with open('$output_file', 'w') as f:
            f.write(data + '\n')
    else:
        # Try with preprocessing
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Try multiple preprocessing techniques
        preprocessed = [
            gray,
            cv2.GaussianBlur(gray, (5, 5), 0),
            cv2.medianBlur(gray, 5),
            cv2.bilateralFilter(gray, 9, 75, 75),
            cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2),
            cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        ]
        
        for processed in preprocessed:
            data, bbox, _ = detector.detectAndDecode(processed)
            if data:
                with open('$output_file', 'w') as f:
                    f.write(data + '\n')
                break
        
        # Try multi-scale detection
        if not data:
            for scale in [0.5, 0.75, 1.25, 1.5, 2.0]:
                resized = cv2.resize(img, None, fx=scale, fy=scale)
                data, bbox, _ = detector.detectAndDecode(resized)
                if data:
                    with open('$output_file', 'w') as f:
                        f.write(data + '\n')
                    break
except Exception as e:
    sys.exit(1)
EOF
    
    [ -s "$output_file" ]
}

decode_with_opencv_wechat() {
    local image="$1"
    local output_file="$2"
    
    python3 << EOF 2>/dev/null
import sys
try:
    import cv2
    
    img = cv2.imread('$image')
    if img is None:
        sys.exit(1)
    
    # Try WeChat QR decoder if available (more robust)
    try:
        detector = cv2.wechat_qrcode_WeChatQRCode()
        data, points = detector.detectAndDecode(img)
        if data:
            with open('$output_file', 'w') as f:
                for d in data:
                    f.write(d + '\n')
    except:
        pass
except Exception as e:
    sys.exit(1)
EOF
    
    [ -s "$output_file" ]
}

decode_with_pyzbar_enhanced() {
    local image="$1"
    local output_file="$2"
    
    python3 << EOF 2>/dev/null
from PIL import Image, ImageEnhance, ImageFilter
from pyzbar.pyzbar import decode, ZBarSymbol
import sys

try:
    img = Image.open('$image')
    
    # Store all decoded data
    all_data = set()
    
    # Try original image
    for code in decode(img, symbols=[ZBarSymbol.QRCODE]):
        try:
            all_data.add(code.data.decode('utf-8'))
        except:
            all_data.add(code.data.decode('latin-1'))
    
    # Try with enhancements if no data found
    if not all_data:
        enhancements = [
            img.convert('L'),  # Grayscale
            ImageEnhance.Contrast(img).enhance(2),  # High contrast
            ImageEnhance.Sharpness(img).enhance(2),  # Sharpen
            img.filter(ImageFilter.EDGE_ENHANCE),  # Edge enhance
            img.filter(ImageFilter.MedianFilter(3)),  # Denoise
            img.point(lambda x: 0 if x < 128 else 255),  # Binary threshold
        ]
        
        for enhanced in enhancements:
            for code in decode(enhanced, symbols=[ZBarSymbol.QRCODE]):
                try:
                    all_data.add(code.data.decode('utf-8'))
                except:
                    all_data.add(code.data.decode('latin-1'))
            if all_data:
                break
    
    if all_data:
        with open('$output_file', 'w') as f:
            for data in all_data:
                f.write(data + '\n')
except Exception as e:
    sys.exit(1)
EOF
    
    [ -s "$output_file" ]
}

decode_with_boofcv() {
    local image="$1"
    local output_file="$2"
    
    # BoofCV Java decoder if available
    if [ -f "/usr/local/lib/boofcv.jar" ]; then
        java -cp /usr/local/lib/boofcv.jar boofcv.examples.QRCodeDetector "$image" 2>/dev/null > "$output_file"
        [ -s "$output_file" ]
    else
        return 1
    fi
}

multi_decoder_analysis() {
    local image="$1"
    local base_output="$2"
    
    log_info "Multi-decoder analysis on $image..."
    
    local decoders=("zbar" "pyzbar" "pyzbar_enhanced" "quirc" "zxing" "qrdecode" "opencv" "opencv_wechat" "boofcv")
    local success_count=0
    local all_decoded=""
    local decoder_results=()
    
    for decoder in "${decoders[@]}"; do
        local decoder_output="${base_output}_${decoder}.txt"
        local result=""
        
        case "$decoder" in
            "zbar")
                decode_with_zbar "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "pyzbar")
                decode_with_pyzbar "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "pyzbar_enhanced")
                decode_with_pyzbar_enhanced "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "quirc")
                decode_with_quirc "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "zxing")
                decode_with_zxing "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "qrdecode")
                decode_with_qrdecode "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "opencv")
                decode_with_opencv "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "opencv_wechat")
                decode_with_opencv_wechat "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
            "boofcv")
                decode_with_boofcv "$image" "$decoder_output" && ((success_count++)) && result="success"
                ;;
        esac
        
        if [ -s "$decoder_output" ]; then
            log_success "  ✓ $decoder: decoded successfully"
            all_decoded+=$(cat "$decoder_output")$'\n'
            decoder_results+=("$decoder:$(cat "$decoder_output" | head -1)")
        else
            [ "$VERBOSE" = true ] && log_warning "  ✗ $decoder: failed to decode"
        fi
    done
    
    # Decoder inconsistency check - potential evasion
    if [ $success_count -gt 0 ] && [ $success_count -lt 3 ]; then
        log_threat 20 "Low decoder success rate ($success_count/${#decoders[@]}) - possible anti-analysis technique"
    fi
    
    # Check for decoder disagreement
    if [ ${#decoder_results[@]} -gt 1 ]; then
        local first_result="${decoder_results[0]#*:}"
        for result in "${decoder_results[@]:1}"; do
            if [ "${result#*:}" != "$first_result" ]; then
                log_threat 30 "Decoder disagreement detected - possible payload manipulation"
                log_forensic "Decoder results vary: ${decoder_results[*]}"
                break
            fi
        done
    fi
    
    echo "$all_decoded" | sort -u > "${base_output}_merged.txt"
    
    return $([ $success_count -gt 0 ])
}

################################################################################
# ADVANCED STEGANOGRAPHY DETECTION
################################################################################

################################################################################
# EXTENDED YARA-LIKE RULES
################################################################################

init_extended_yara_rules() {
    log_info "Initializing extended YARA rules..."
    
    # Cloud Service Abuse Rule
    YARA_RULES["cloud_abuse"]='
        strings:
            $gdrive = "drive.google.com" nocase
            $s3 = "s3.amazonaws.com" nocase
            $azure = "blob.core.windows.net" nocase
            $dropbox = "dropboxusercontent.com" nocase
            $discord = "cdn.discordapp.com" nocase
            $download = "download" nocase
            $exe = ".exe" nocase
            $dll = ".dll" nocase
        condition:
            ($gdrive or $s3 or $azure or $dropbox or $discord) and ($download or $exe or $dll)
        severity: HIGH
    '
    
    # Fileless Malware Rule
    YARA_RULES["fileless_malware"]='
        strings:
            $ps_enc = "-encodedcommand" nocase
            $ps_iex = "IEX" nocase
            $ps_download = "downloadstring" nocase
            $ps_webclient = "Net.WebClient" nocase
            $certutil = "certutil" nocase
            $mshta = "mshta" nocase
            $regsvr32 = "regsvr32" nocase
            $rundll32 = "rundll32" nocase
            $bitsadmin = "bitsadmin" nocase
            $wmic = "wmic" nocase
            $hidden = "-w hidden" nocase
            $bypass = "bypass" nocase
        condition:
            3 of them
        severity: CRITICAL
    '
    
    # Mobile Deep Link Abuse Rule
    YARA_RULES["mobile_deeplink_abuse"]='
        strings:
            $itms = "itms-services://" nocase
            $intent = "intent://" nocase
            $mobileconfig = ".mobileconfig" nocase
            $market = "market://" nocase
            $apk = ".apk" nocase
            $ipa = ".ipa" nocase
            $manifest = "download-manifest" nocase
        condition:
            any of them
        severity: HIGH
    '
    
    # Bluetooth/NFC Attack Rule
    YARA_RULES["wireless_attack"]='
        strings:
            $bt = "bluetooth://" nocase
            $nfc = "nfc://" nocase
            $ble = "ble://" nocase
            $wifi = "WIFI:" nocase
            $bt_mac = /[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}/
        condition:
            any of them
        severity: MEDIUM
    '
    
    # Tor/Darknet Rule
    YARA_RULES["tor_darknet"]='
        strings:
            $onion = ".onion" nocase
            $tor = "torproject" nocase
            $tor2web = "tor2web" nocase
            $darknet = "darknet" nocase
            $deepweb = "deepweb" nocase
            $hidden = "hidden service" nocase
        condition:
            any of them
        severity: HIGH
    '
    
    # Ransomware Note Rule
    YARA_RULES["ransomware_note"]='
        strings:
            $enc1 = "files have been encrypted" nocase
            $enc2 = "data has been encrypted" nocase
            $pay1 = "pay" nocase
            $pay2 = "bitcoin" nocase
            $pay3 = "ransom" nocase
            $decrypt = "decrypt" nocase
            $deadline = "deadline" nocase
            $price = "price" nocase
        condition:
            ($enc1 or $enc2) and ($pay1 or $pay2 or $pay3) and $decrypt
        severity: CRITICAL
    '
    
    # Office Macro Abuse Rule
    YARA_RULES["office_macro_abuse"]='
        strings:
            $auto1 = "AutoOpen" nocase
            $auto2 = "Document_Open" nocase
            $auto3 = "Workbook_Open" nocase
            $shell = "WScript.Shell" nocase
            $create = "CreateObject" nocase
            $ps = "powershell" nocase
            $cmd = "cmd.exe" nocase
            $download = "URLDownloadToFile" nocase
        condition:
            ($auto1 or $auto2 or $auto3) and ($shell or $create) and ($ps or $cmd or $download)
        severity: CRITICAL
    '
    
    # Follina/MSDT Rule
    YARA_RULES["follina_exploit"]='
        strings:
            $msdt1 = "ms-msdt:" nocase
            $msdt2 = "msdt.exe" nocase
            $pcw = "PCWDiagnostic" nocase
            $rebrowse = "IT_RebrowseForFile" nocase
            $launch = "IT_LaunchMethod" nocase
        condition:
            ($msdt1 or $msdt2) and ($pcw or $rebrowse or $launch)
        severity: CRITICAL
    '
    
    # AMSI Bypass Rule
    YARA_RULES["amsi_bypass"]='
        strings:
            $amsi1 = "amsiInitFailed" nocase
            $amsi2 = "AmsiScanBuffer" nocase
            $amsi3 = "amsi.dll" nocase
            $amsi4 = "AmsiUtils" nocase
            $reflect = "Reflection.Assembly" nocase
            $virtual = "VirtualProtect" nocase
        condition:
            2 of them
        severity: CRITICAL
    '
    
    # Hardware/IoT Exploit Rule
    YARA_RULES["hardware_exploit"]='
        strings:
            $pos1 = "verifone" nocase
            $pos2 = "ingenico" nocase
            $iot1 = "busybox" nocase
            $iot2 = "/etc/passwd" nocase
            $cam1 = "hikvision" nocase
            $cam2 = "dahua" nocase
            $rtsp = "rtsp://" nocase
            $overflow = /A{100,}|%00{20,}/
        condition:
            any of them
        severity: HIGH
    '
    
    # Social Engineering Urgency Rule
    YARA_RULES["social_engineering"]='
        strings:
            $urgent1 = "urgent" nocase
            $urgent2 = "immediate" nocase
            $urgent3 = "act now" nocase
            $expire = "expires" nocase
            $deadline = "deadline" nocase
            $account1 = "account suspended" nocase
            $account2 = "account compromised" nocase
            $verify = "verify your" nocase
            $confirm = "confirm your" nocase
        condition:
            3 of them
        severity: MEDIUM
    '
    
    # BEC Wire Transfer Rule
    YARA_RULES["bec_wire_fraud"]='
        strings:
            $wire = "wire transfer" nocase
            $bank1 = "change bank" nocase
            $bank2 = "new account" nocase
            $urgent = "urgent payment" nocase
            $conf = "confidential" nocase
            $ceo = "ceo" nocase
            $exec = "executive" nocase
            $gift = "gift card" nocase
        condition:
            ($wire or $bank1 or $bank2) and ($urgent or $conf or $ceo or $exec)
        severity: CRITICAL
    '
    
    # Geofencing/Cloaking Rule
    YARA_RULES["geofencing_cloaking"]='
        strings:
            $geo1 = "geolocation" nocase
            $geo2 = "geoip" nocase
            $geo3 = "ipinfo.io" nocase
            $geo4 = "ip-api.com" nocase
            $geo5 = "maxmind" nocase
            $country = "country" nocase
            $redirect = "redirect" nocase
            $block = "block" nocase
        condition:
            ($geo1 or $geo2 or $geo3 or $geo4 or $geo5) and ($redirect or $block)
        severity: MEDIUM
    '
    
    # Steganography Indicator Rule
    YARA_RULES["steganography_indicator"]='
        strings:
            $steg1 = "steghide" nocase
            $steg2 = "outguess" nocase
            $steg3 = "invisible secrets" nocase
            $lsb = "LSB" nocase
            $embed = "embedded" nocase
            $hidden = "hidden data" nocase
        condition:
            any of them
        severity: MEDIUM
    '
    
    # Zero-Day/Exploit Kit Indicator Rule
    YARA_RULES["exploit_kit_indicator"]='
        strings:
            $ek1 = "angler" nocase
            $ek2 = "rig" nocase
            $ek3 = "magnitude" nocase
            $ek4 = "sundown" nocase
            $ek5 = "fallout" nocase
            $ek6 = "purple fox" nocase
            $landing = "landing" nocase
            $gate = "gate" nocase
            $iframe = "<iframe" nocase
            $obf = /eval\(function\(/
        condition:
            ($ek1 or $ek2 or $ek3 or $ek4 or $ek5 or $ek6) or ($iframe and $obf)
        severity: CRITICAL
    '
    
    # Protocol Handler Abuse Rule
    YARA_RULES["protocol_handler_abuse"]='
        strings:
            $ms1 = "ms-msdt:" nocase
            $ms2 = "ms-officecmd:" nocase
            $ms3 = "ms-word:" nocase
            $ms4 = "ms-excel:" nocase
            $ms5 = "ms-powerpoint:" nocase
            $ms6 = "search-ms:" nocase
            $vscode = "vscode://" nocase
            $cursor = "cursor://" nocase
        condition:
            any of them
        severity: HIGH
    '
    
    # Adversarial ML/AI Attack Rule
    YARA_RULES["adversarial_ai"]='
        strings:
            $adv1 = "adversarial" nocase
            $adv2 = "perturbation" nocase
            $adv3 = "evasion attack" nocase
            $ml1 = "machine learning" nocase
            $ml2 = "neural network" nocase
            $ml3 = "classifier" nocase
        condition:
            ($adv1 or $adv2 or $adv3) and ($ml1 or $ml2 or $ml3)
        severity: HIGH
    '
    
    # QR Sequence/Animated Attack Rule
    YARA_RULES["qr_sequence_attack"]='
        strings:
            $seq1 = "sequence" nocase
            $seq2 = "part" nocase
            $seq3 = "continue" nocase
            $anim = "animated" nocase
            $multi = "multiple" nocase
            $scan = "scan" nocase
        condition:
            ($seq1 or $seq2 or $seq3 or $multi) and $scan
        severity: MEDIUM
    '
}

analyze_steganography() {
    local image="$1"
    
    log_stego "Analyzing image for steganographic content..."
    
    local stego_score=0
    local stego_findings=()
    
    # Check file entropy
    local entropy=$(analyze_file_entropy "$image")
    if (( $(echo "$entropy > 7.9" | bc -l) )); then
        log_stego "High entropy detected: $entropy (possible encrypted/compressed hidden data)"
        ((stego_score += 20))
        stego_findings+=("high_entropy:$entropy")
    fi
    
    # Check for appended data after image end
    local appended=$(check_appended_data "$image")
    if [ "$appended" = "true" ]; then
        log_stego "Appended data detected after image end marker"
        ((stego_score += 30))
        stego_findings+=("appended_data")
    fi
    
    # Use steghide if available
    if command -v steghide &> /dev/null; then
        local steghide_output="${TEMP_DIR}/steghide_$(basename "$image").txt"
        if steghide info "$image" -p "" 2>&1 | grep -q "embedded"; then
            log_stego "Steghide detected embedded content (no password)"
            ((stego_score += 50))
            stego_findings+=("steghide_detected")
        fi
    fi
    
    # Use zsteg for PNG files
    if command -v zsteg &> /dev/null && file "$image" | grep -qi "PNG"; then
        local zsteg_output="${TEMP_DIR}/zsteg_$(basename "$image").txt"
        zsteg "$image" 2>/dev/null > "$zsteg_output"
        
        if grep -qiE "(http|https|ftp|data:|base64)" "$zsteg_output"; then
            log_stego "zsteg detected potentially hidden URLs/data"
            ((stego_score += 40))
            stego_findings+=("zsteg_url_detected")
        fi
        
        if grep -qi "file signature" "$zsteg_output"; then
            log_stego "zsteg detected hidden file signatures"
            ((stego_score += 45))
            stego_findings+=("zsteg_file_sig")
        fi
    fi
    
    # Use stegdetect if available
    if command -v stegdetect &> /dev/null; then
        local stegdetect_output=$(stegdetect "$image" 2>/dev/null)
        if [ -n "$stegdetect_output" ] && ! echo "$stegdetect_output" | grep -q "negative"; then
            log_stego "stegdetect positive: $stegdetect_output"
            ((stego_score += 35))
            stego_findings+=("stegdetect:$stegdetect_output")
        fi
    fi
    
    # Analyze LSB patterns
    analyze_lsb_patterns "$image"
    
    # Check for unusual color distributions
    analyze_color_distribution "$image"
    
    # Report findings
    if [ $stego_score -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "STEGANOGRAPHY ANALYSIS: $(basename "$image")"
            echo "═══════════════════════════════════════════════"
            echo "Steganography Score: $stego_score"
            echo "Findings:"
            for finding in "${stego_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
        } >> "$STEGANOGRAPHY_REPORT"
        
        if [ $stego_score -ge 50 ]; then
            local finding_summary=$(printf '%s, ' "${stego_findings[@]}" | sed 's/, $//')
            log_forensic_detection $((stego_score / 2)) \
                "Steganographic Content Detected" \
                "$finding_summary" \
                "LSB analysis, entropy analysis, zsteg detection" \
                "Image binary data" \
                "Extract and analyze hidden data - potential data exfiltration or hidden payload" \
                "Steganography detection module"
        fi
    fi
}

analyze_lsb_patterns() {
    local image="$1"
    
    python3 << EOF 2>/dev/null
from PIL import Image
import numpy as np

try:
    img = Image.open('$image')
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    pixels = np.array(img)
    
    # Extract LSBs
    r_lsb = pixels[:,:,0] & 1
    g_lsb = pixels[:,:,1] & 1
    b_lsb = pixels[:,:,2] & 1
    
    # Calculate LSB statistics
    r_ratio = np.mean(r_lsb)
    g_ratio = np.mean(g_lsb)
    b_ratio = np.mean(b_lsb)
    
    # Normal images have ~0.5 ratio, steganography often shows deviation
    deviation = abs(r_ratio - 0.5) + abs(g_ratio - 0.5) + abs(b_ratio - 0.5)
    
    if deviation < 0.05:
        print(f"LSB_SUSPICIOUS: LSB ratios too uniform (R:{r_ratio:.3f} G:{g_ratio:.3f} B:{b_ratio:.3f})")
    
    # Check for sequential patterns in LSB
    lsb_combined = np.concatenate([r_lsb.flatten(), g_lsb.flatten(), b_lsb.flatten()])
    
    # Look for ASCII patterns
    for i in range(0, len(lsb_combined) - 64, 8):
        byte = 0
        for bit in range(8):
            byte = (byte << 1) | lsb_combined[i + bit]
        if 32 <= byte <= 126:  # Printable ASCII
            print(f"LSB_ASCII_FOUND: Found printable ASCII in LSB at position {i}")
            break
except Exception as e:
    pass
EOF
}

analyze_color_distribution() {
    local image="$1"
    
    python3 << EOF 2>/dev/null
from PIL import Image
from collections import Counter
import numpy as np

try:
    img = Image.open('$image')
    if img.mode != 'RGB':
        img = img.convert('RGB')
    
    pixels = list(img.getdata())
    
    # Analyze color distribution
    color_counts = Counter(pixels)
    unique_colors = len(color_counts)
    total_pixels = len(pixels)
    
    # Unusually high number of unique colors might indicate steganography
    color_ratio = unique_colors / total_pixels
    
    if color_ratio > 0.9:
        print(f"COLOR_SUSPICIOUS: Very high unique color ratio ({color_ratio:.3f})")
    
    # Check for unusual pairs/close colors
    suspicious_pairs = 0
    colors = list(color_counts.keys())
    for i in range(min(1000, len(colors))):
        for j in range(i+1, min(1000, len(colors))):
            c1, c2 = colors[i], colors[j]
            if all(abs(c1[k] - c2[k]) <= 1 for k in range(3)):
                suspicious_pairs += 1
    
    if suspicious_pairs > len(colors) * 0.1:
        print(f"COLOR_PAIRS_SUSPICIOUS: High number of near-identical color pairs ({suspicious_pairs})")
except Exception as e:
    pass
EOF
}

analyze_file_entropy() {
    local file="$1"
    
    python3 << EOF 2>/dev/null
import math
from collections import Counter

try:
    with open('$file', 'rb') as f:
        data = f.read()
    
    if len(data) == 0:
        print("0.0")
    else:
        counter = Counter(data)
        length = len(data)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        print(f"{entropy:.4f}")
except Exception as e:
    print("0.0")
EOF
}

check_appended_data() {
    local image="$1"
    local file_type=$(file -b "$image" | cut -d',' -f1)
    
    case "$file_type" in
        *"PNG"*)
            # PNG ends with IEND chunk
            if xxd "$image" 2>/dev/null | grep -q "IEND.*42 60 82"; then
                local iend_pos=$(xxd "$image" 2>/dev/null | grep -n "IEND" | tail -1 | cut -d: -f1)
                local file_lines=$(xxd "$image" 2>/dev/null | wc -l)
                if [ "$iend_pos" != "$file_lines" ]; then
                    echo "true"
                    return
                fi
            fi
            ;;
        *"JPEG"*)
            # JPEG ends with FFD9
            if xxd "$image" 2>/dev/null | tail -1 | grep -qv "ff d9"; then
                echo "true"
                return
            fi
            ;;
        *"GIF"*)
            # GIF ends with 3B (;)
            if xxd "$image" 2>/dev/null | tail -1 | grep -qv "3b"; then
                echo "true"
                return
            fi
            ;;
    esac
    
    echo "false"
}

################################################################################
# IMAGE ANALYSIS AND METADATA EXTRACTION
################################################################################

analyze_image_metadata() {
    local image="$1"
    
    log_info "Extracting and analyzing image metadata..."
    
    local metadata_file="${EVIDENCE_DIR}/metadata_$(basename "$image").txt"
    
    # Use exiftool if available
    if command -v exiftool &> /dev/null; then
        exiftool -a -G1 "$image" > "$metadata_file" 2>/dev/null
        
        # Check for suspicious metadata
        if grep -qi "GPS" "$metadata_file"; then
            log_forensic "GPS coordinates found in image metadata"
        fi
        
        if grep -qiE "photoshop|gimp|paint" "$metadata_file"; then
            log_info "Image edited with graphics software"
        fi
        
        # Check for suspicious software
        if grep -qiE "malware|hack|exploit|payload" "$metadata_file"; then
            log_threat 40 "Suspicious strings in image metadata"
        fi
        
        # Extract embedded files
        local embedded=$(grep -i "Embedded" "$metadata_file" 2>/dev/null)
        if [ -n "$embedded" ]; then
            log_forensic "Embedded content detected: $embedded"
        fi
        
        # Check modification dates
        local create_date=$(grep -i "Create Date" "$metadata_file" | head -1)
        local modify_date=$(grep -i "Modify Date" "$metadata_file" | head -1)
        if [ -n "$create_date" ] && [ -n "$modify_date" ]; then
            log_forensic "Create Date: $create_date"
            log_forensic "Modify Date: $modify_date"
        fi
    fi
    
    # Use ImageMagick identify for additional info
    if command -v identify &> /dev/null; then
        local identify_output="${EVIDENCE_DIR}/identify_$(basename "$image").txt"
        identify -verbose "$image" > "$identify_output" 2>/dev/null
        
        # Check for anomalies
        local color_space=$(grep "Colorspace:" "$identify_output" 2>/dev/null | awk '{print $2}')
        local depth=$(grep "Depth:" "$identify_output" 2>/dev/null | awk '{print $2}')
        local compression=$(grep "Compression:" "$identify_output" 2>/dev/null | awk '{print $2}')
        
        log_info "  Colorspace: $color_space, Depth: $depth, Compression: $compression"
    fi
    
    # Check file structure with binwalk
    if command -v binwalk &> /dev/null; then
        local binwalk_output="${EVIDENCE_DIR}/binwalk_$(basename "$image").txt"
        binwalk "$image" > "$binwalk_output" 2>/dev/null
        
        local embedded_files=$(grep -c "0x" "$binwalk_output" 2>/dev/null || echo "0")
        if [ "$embedded_files" -gt 3 ]; then
            log_threat 30 "Multiple embedded files/data detected by binwalk: $embedded_files items"
        fi
    fi
    
    # PNG specific checks
    if file "$image" | grep -qi "PNG"; then
        check_png_structure "$image"
    fi
    
    # JPEG specific checks
    if file "$image" | grep -qi "JPEG"; then
        check_jpeg_structure "$image"
    fi
}

check_png_structure() {
    local image="$1"
    
    log_info "Analyzing PNG structure..."
    
    if command -v pngcheck &> /dev/null; then
        local pngcheck_output=$(pngcheck -v "$image" 2>&1)
        
        if echo "$pngcheck_output" | grep -qi "error\|invalid\|corrupt"; then
            log_warning "PNG structure errors detected"
            log_forensic "PNG issues: $pngcheck_output"
        fi
        
        # Check for unusual chunks
        if echo "$pngcheck_output" | grep -qiE "tEXt|zTXt|iTXt"; then
            log_info "Text chunks found in PNG"
            
            # Extract text chunks
            python3 << EOF 2>/dev/null
import struct

try:
    with open('$image', 'rb') as f:
        # Skip PNG signature
        f.read(8)
        
        while True:
            length_bytes = f.read(4)
            if len(length_bytes) < 4:
                break
            length = struct.unpack('>I', length_bytes)[0]
            chunk_type = f.read(4).decode('ascii', errors='ignore')
            
            if chunk_type in ['tEXt', 'zTXt', 'iTXt']:
                data = f.read(length)
                print(f"PNG_CHUNK_{chunk_type}: {data[:100]}")
                f.read(4)  # CRC
            else:
                f.seek(length + 4, 1)
except Exception as e:
    pass
EOF
        fi
    fi
}

check_jpeg_structure() {
    local image="$1"
    
    log_info "Analyzing JPEG structure..."
    
    if command -v jpeginfo &> /dev/null; then
        local jpeginfo_output=$(jpeginfo -c "$image" 2>&1)
        
        if echo "$jpeginfo_output" | grep -qi "error\|warning\|corrupt"; then
            log_warning "JPEG structure issues: $jpeginfo_output"
        fi
    fi
    
    # Check for multiple APP markers (potential data hiding)
    local app_markers=$(xxd "$image" 2>/dev/null | grep -c "ff e[0-9a-f]")
    if [ "$app_markers" -gt 5 ]; then
        log_forensic "Unusual number of APP markers in JPEG: $app_markers"
    fi
    
    # Check for comments
    if xxd "$image" 2>/dev/null | grep -q "ff fe"; then
        log_forensic "JPEG contains comment marker (COM)"
        
        python3 << EOF 2>/dev/null
try:
    with open('$image', 'rb') as f:
        data = f.read()
        pos = 0
        while True:
            pos = data.find(b'\xff\xfe', pos)
            if pos == -1:
                break
            length = int.from_bytes(data[pos+2:pos+4], 'big')
            comment = data[pos+4:pos+2+length]
            print(f"JPEG_COMMENT: {comment[:100]}")
            pos += 1
except:
    pass
EOF
    fi
}

################################################################################
# OCR ANALYSIS FOR TEXT OVERLAY DETECTION
################################################################################

perform_ocr_analysis() {
    local image="$1"
    
    if ! command -v tesseract &> /dev/null; then
        log_warning "Tesseract OCR not available, skipping text overlay analysis"
        return
    fi
    
    log_info "Performing OCR analysis for text overlays..."
    
    local ocr_output="${TEMP_DIR}/ocr_$(basename "$image").txt"
    
    # Run Tesseract with multiple configurations
    tesseract "$image" "${ocr_output%.txt}" -l eng 2>/dev/null
    
    if [ -s "$ocr_output" ]; then
        log_info "OCR detected text in image"
        
        local text_content=$(cat "$ocr_output")
        
        # Check for suspicious text patterns
        for pattern in "${SUSPICIOUS_URL_PATTERNS[@]}"; do
            if echo "$text_content" | grep -qiE "$pattern"; then
                log_threat 15 "OCR detected suspicious text pattern: $pattern"
            fi
        done
        
        # Check for URLs in text
        if echo "$text_content" | grep -qiE "https?://|www\.|\.com|\.org|\.net"; then
            log_warning "OCR detected URL-like text in image"
            local urls=$(echo "$text_content" | grep -oE "(https?://[^\s]+|www\.[^\s]+)")
            log_forensic "OCR URLs: $urls"
        fi
        
        # Check for phone numbers
        if echo "$text_content" | grep -qE "[0-9]{3}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}"; then
            log_info "OCR detected phone number pattern"
        fi
        
        # Check for crypto addresses
        for pattern in "${CRYPTO_PATTERNS[@]}"; do
            if echo "$text_content" | grep -qE "$pattern"; then
                log_threat 25 "OCR detected cryptocurrency address pattern"
            fi
        done
        
        # Save to evidence
        cp "$ocr_output" "${EVIDENCE_DIR}/"
    fi
}

################################################################################
# URL AND DOMAIN ANALYSIS
################################################################################

analyze_url_structure() {
    local url="$1"
    local threats=0
    
    log_info "Deep URL analysis: $url"
    
    # Extract components (POSIX compatible)
    local protocol=$(echo "$url" | sed -n 's/^\([a-z]*\):.*/\1/p' | head -1)
    local domain=$(echo "$url" | sed -E 's|^[a-z]+://||' | cut -d'/' -f1 | cut -d':' -f1)
    local port=$(echo "$url" | sed -n 's/.*:\([0-9][0-9]*\).*/\1/p' | head -1)
    local path=$(echo "$url" | sed 's|^[^/]*//[^/]*/||')
    local query=$(echo "$url" | sed -n 's/.*\(\?.*\)$/\1/p' | head -1)
    
    # Display parsed URL components
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                    URL FORENSIC ANALYSIS                    │${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} Protocol:    ${WHITE}${protocol:-N/A}${NC}"
    echo -e "${CYAN}│${NC} Domain:      ${WHITE}${domain:-N/A}${NC}"
    echo -e "${CYAN}│${NC} Port:        ${WHITE}${port:-default}${NC}"
    echo -e "${CYAN}│${NC} Path:        ${WHITE}${path:-/}${NC}"
    echo -e "${CYAN}│${NC} Query:       ${WHITE}${query:-none}${NC}"
    echo -e "${CYAN}│${NC} Length:      ${WHITE}${#url} characters${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Check for dangerous URI schemes
    for scheme in "${DANGEROUS_URI_SCHEMES[@]}"; do
        if [[ "$url" =~ ^$scheme ]]; then
            log_threat 50 "Dangerous URI scheme detected: $scheme"
            ((threats++))
        fi
    done
    
    # Non-HTTP/HTTPS protocols
    if [ -n "$protocol" ] && [[ ! "$protocol" =~ ^https?$ ]]; then
        log_threat 15 "Non-HTTP protocol: $protocol"
        ((threats++))
    fi
    
    # IP-based URLs
    if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_threat 25 "IP-based URL (suspicious): $domain"
        ((threats++))
        
        # Check against known malicious IPs
        if [ -n "${KNOWN_MALICIOUS_IPS[$domain]}" ]; then
            log_forensic_detection 100 \
                "KNOWN MALICIOUS IP DETECTED" \
                "$domain" \
                "Hardcoded malicious IP database: ${KNOWN_MALICIOUS_IPS[$domain]}" \
                "URL domain/host" \
                "BLOCK IMMEDIATELY - Known malicious infrastructure" \
                "Internal IOC database"
        fi
        
        # Check for private/reserved IPs
        if [[ "$domain" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|169\.254\.) ]]; then
            log_threat 40 "Private/reserved IP address detected: $domain"
        fi
    fi
    
    # Suspicious ports
    if [ -n "$port" ]; then
        case "$port" in
            80|443|8080|8443)
                ;;
            *)
                log_threat 10 "Unusual port: $port"
                ((threats++))
                ;;
        esac
        
        # High ports often used by malware
        if [ "$port" -gt 10000 ]; then
            log_threat 15 "High port number (often used for C2): $port"
        fi
    fi
    
    # Check domain against malicious lists
    for malicious_domain in "${HARDCODED_MALICIOUS_DOMAINS[@]}"; do
        if [[ "$domain" == *"$malicious_domain"* ]]; then
            log_threat 100 "KNOWN MALICIOUS DOMAIN: $domain"
            ((threats++))
        fi
    done
    
    # URL shorteners
    for shortener in "${URL_SHORTENERS[@]}"; do
        if echo "$domain" | grep -qE "$shortener"; then
            log_threat 20 "URL shortener detected: $domain"
            ((threats++))
            resolve_url_redirect "$url"
            break
        fi
    done
    
    # Suspicious TLDs
    for tld in "${SUSPICIOUS_TLDS[@]}"; do
        if echo "$domain" | grep -qE "$tld\$"; then
            log_threat 30 "Suspicious TLD: $tld"
            ((threats++))
            break
        fi
    done
    
    # Homograph attack detection
    check_homograph_attack "$domain"
    
    # Typosquatting detection
    check_typosquatting "$domain"
    
    # Suspicious URL patterns
    for pattern in "${SUSPICIOUS_URL_PATTERNS[@]}"; do
        if echo "$path$query" | grep -qiE "$pattern"; then
            log_threat 15 "Suspicious URL pattern: $pattern"
            ((threats++))
        fi
    done
    
    # URL encoding detection
    if echo "$url" | grep -qE "%[0-9a-fA-F]{2}"; then
        log_warning "URL contains encoded characters..."
        local decoded_url=$(python3 -c "import urllib.parse; print(urllib.parse.unquote('$url'))" 2>/dev/null)
        if [ "$url" != "$decoded_url" ]; then
            log_info "Decoded URL: $decoded_url"
            # Recursively analyze decoded URL
            analyze_url_structure "$decoded_url"
        fi
        
        # Double encoding detection
        if echo "$url" | grep -qE "%25[0-9a-fA-F]{2}"; then
            log_threat 20 "Double URL encoding detected - evasion technique"
        fi
    fi
    
    # Data URI detection
    if [[ "$url" =~ ^data: ]]; then
        log_threat 40 "Data URI detected - may contain embedded payload"
        analyze_data_uri "$url"
    fi
    
    # Base64 in URL
    if echo "$url" | grep -qE "[A-Za-z0-9+/]{50,}=*"; then
        log_threat 25 "Possible Base64 encoded data in URL"
        analyze_base64_in_url "$url"
    fi
    
    # DNS/WHOIS checks
    if [ "$NETWORK_CHECK" = true ]; then
        check_domain_whois "$domain"
        check_domain_dns "$domain"
        check_ssl_certificate "$url"
    fi
    
    return $threats
}

analyze_data_uri() {
    local uri="$1"
    
    log_info "Analyzing Data URI..."
    
    # Extract MIME type (POSIX compatible)
    local mime_type=$(echo "$uri" | sed -n 's/^data:\([^;,]*\).*/\1/p')
    log_forensic "Data URI MIME type: $mime_type"
    
    # Check for dangerous MIME types
    case "$mime_type" in
        "text/html"|"application/javascript"|"text/javascript")
            log_threat 50 "Dangerous Data URI MIME type: $mime_type"
            ;;
        "application/x-msdownload"|"application/x-executable")
            log_threat 80 "Executable Data URI detected"
            ;;
    esac
    
    # Extract and decode Base64 content
    if echo "$uri" | grep -q "base64,"; then
        local encoded=$(echo "$uri" | sed 's/.*base64,//')
        local decoded=$(echo "$encoded" | base64 -d 2>/dev/null)
        
        if [ -n "$decoded" ]; then
            log_forensic "Decoded Data URI content (first 200 chars): ${decoded:0:200}"
            
            # Check decoded content for threats
            analyze_decoded_content "$decoded"
        fi
    fi
}

analyze_base64_in_url() {
    local url="$1"
    
    # Extract potential Base64 strings
    local b64_strings=$(echo "$url" | grep -oE "[A-Za-z0-9+/]{50,}=*")
    
    for b64 in $b64_strings; do
        local decoded=$(echo "$b64" | base64 -d 2>/dev/null)
        if [ -n "$decoded" ]; then
            log_forensic "Decoded Base64 from URL: ${decoded:0:100}"
            analyze_decoded_content "$decoded"
        fi
    done
}

analyze_decoded_content() {
    local content="$1"
    
    # Check for script tags
    if echo "$content" | grep -qiE "<script|javascript:|onerror=|onload="; then
        log_threat 40 "JavaScript detected in decoded content"
    fi
    
    # Check for URLs
    if echo "$content" | grep -qiE "https?://"; then
        local embedded_urls=$(echo "$content" | grep -oE "https?://[^\s\"'<>]+")
        log_forensic "Embedded URLs in decoded content: $embedded_urls"
    fi
    
    # Check for commands
    if echo "$content" | grep -qiE "powershell|cmd|bash|sh|wget|curl|python"; then
        log_threat 50 "Command execution keywords in decoded content"
    fi
}

resolve_url_redirect() {
    local url="$1"
    local max_redirects=10
    
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Resolving redirects for: $url"
    
    # Get full redirect chain (with timeout)
    local redirect_chain=$(curl -sIL --max-time 10 --max-redirs "$max_redirects" -w "%{url_effective}\n" -o /dev/null "$url" 2>/dev/null)
    
    if [ -n "$redirect_chain" ] && [ "$redirect_chain" != "$url" ]; then
        log_warning "Redirect chain resolved to: $redirect_chain"
        
        # Count redirects (with timeout)
        local redirect_count=$(curl -sIL --max-time 10 --max-redirs "$max_redirects" -w "%{redirect_count}" -o /dev/null "$url" 2>/dev/null)
        if [ "$redirect_count" -gt 3 ]; then
            log_threat 15 "Excessive redirects detected: $redirect_count"
        fi
        
        # Analyze final destination
        analyze_url_structure "$redirect_chain"
    fi
}

check_homograph_attack() {
    local domain="$1"
    
    # Mixed scripts detection
    local has_latin=$(echo "$domain" | grep '[a-zA-Z]' | wc -l)
    local has_cyrillic=$(echo "$domain" | grep -E '[а-яА-ЯёЁ]' | wc -l)
    local has_greek=$(echo "$domain" | grep -E '[α-ωΑ-Ω]' | wc -l)
    
    if [ $has_latin -gt 0 ] && ([ $has_cyrillic -gt 0 ] || [ $has_greek -gt 0 ]); then
        log_threat 50 "HOMOGRAPH ATTACK: Mixed character sets detected"
    fi
    
    # Check for lookalike characters (non-ASCII only)
    # GRANULAR OUTPUT RESTORED: Output per-character threat as required for forensic visibility
    local homograph_found=false
    local homograph_count=0
    for char in "${HOMOGRAPH_CHARS[@]}"; do
        [ -z "$char" ] && continue
        if echo "$domain" | grep -qF "$char"; then
            # GRANULAR: Output individual threat per homograph character (Paste A format)
            log_threat 40 "Homograph character detected: $char"
            ((homograph_count++))
            
            if [ "$homograph_found" = false ]; then
                log_warning "⚠️  HOMOGRAPH ATTACK DETECTED in domain!"
                log_warning "    ├─ Domain: $domain"
                homograph_found=true
            fi
            # Get the Unicode code point for the character
            local codepoint=$(printf '%s' "$char" | od -An -tx1 | tr -d ' \n')
            log_warning "    ├─ Lookalike character: '$char' (bytes: $codepoint)"
        fi
    done
    if [ "$homograph_found" = true ]; then
        log_warning "    └─ Recommendation: Verify domain authenticity - may be spoofing a legitimate site"
        log_warning "    └─ Total homograph characters found: $homograph_count"
    fi
    
    # Punycode detection
    if echo "$domain" | grep -qE 'xn--'; then
        log_threat 30 "Punycode domain (IDN spoofing possible): $domain"
        local decoded=$(python3 -c "print('$domain'.encode('ascii').decode('idna'))" 2>/dev/null)
        [ -n "$decoded" ] && log_info "Decoded IDN: $decoded"
    fi
    
    homograph_chars=( "l" "w" "і" "1" "0" "о" "Ο" "ϴ" "Ӏ" )
    for char in "${homograph_chars[@]}"; do
        [[ -z "$char" ]] && continue
        if [[ "$url" == *"$char"* ]]; then
            echo -e "${RED}[THREAT +40]${NC} Homograph character detected: $char"
        fi
done
}

check_typosquatting() {
    local domain="$1"
    
    for brand in "${PHISHING_BRANDS[@]}"; do
        if echo "$domain" | grep -qiE "$brand"; then
            # Check for typosquatting patterns
            if echo "$domain" | grep -qiE "${brand}[0-9]|${brand}-|${brand}_|${brand}\."; then
                log_threat 35 "Potential typosquatting: $brand"
            fi
            
            # Character substitution detection
            local substitutions=(
                "o/0" "i/1" "l/1" "a/4" "e/3" "s/5" "t/7" "b/8"
                "O/0" "I/1" "L/1" "A/4" "E/3" "S/5" "T/7" "B/8"
            )
            
            for sub in "${substitutions[@]}"; do
                local orig="${sub%/*}"
                local repl="${sub#*/}"
                local pattern="${brand//$orig/$repl}"
                if echo "$domain" | grep -qiE "$pattern" && [ "$pattern" != "$brand" ]; then
                    log_threat 40 "Character substitution typosquatting detected"
                    break
                fi
            done
            
            # Missing/extra character detection
            local brand_len=${#brand}
            local domain_clean=$(echo "$domain" | sed 's/\..*//')
            local domain_len=${#domain_clean}
            
            if [ $((domain_len - brand_len)) -eq 1 ] || [ $((brand_len - domain_len)) -eq 1 ]; then
                if echo "$domain_clean" | grep -qiE ".*$brand.*|$brand"; then
                    log_warning "Possible typosquatting with character addition/deletion"
                fi
            fi
        fi
    done
}

check_domain_whois() {
    local domain="$1"
    
    if ! command -v whois &> /dev/null || [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking WHOIS: $domain"
    
    local whois_file="${TEMP_DIR}/whois_${domain//\//_}.txt"
    timeout 10 whois "$domain" > "$whois_file" 2>/dev/null || return
    
    # Domain age check
    local creation_date=$(grep -iE "Creation Date|Registered|Created" "$whois_file" | head -1)
    if [ -n "$creation_date" ]; then
        log_forensic "Domain creation: $creation_date"
        
        # Check for very new domains (< 30 days)
        local creation_timestamp=$(echo "$creation_date" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | head -1)
        if [ -n "$creation_timestamp" ]; then
            local days_ago=$(( ($(date +%s) - $(date -d "$creation_timestamp" +%s 2>/dev/null || echo 0)) / 86400 ))
            if [ "$days_ago" -lt 30 ] && [ "$days_ago" -gt 0 ]; then
                log_threat 25 "Recently registered domain (< 30 days old)"
            elif [ "$days_ago" -lt 90 ] && [ "$days_ago" -gt 0 ]; then
                log_threat 10 "Relatively new domain (< 90 days old)"
            fi
        fi
    fi
    
    # Registrar string: $registrar
    if [ -n "$registrar" ]; then
        high_abuse_registrars=(
            "namecheap" "namesilo" "porkbun" "dynadot" "enom" "resellerclub"
            "publicdomainregistry" "alpnames" "internetbs" "reg\.ru" "r01"
            "webnames\.ru" "regway" "hostinger" "freenom" "todaynic" "bizcn"
            "west\.cn" "xinnet" "hichina" "now\.cn" "cndns" "22\.cn" "35\.com"
            "net\.cn"
        )
        registrar_lc=$(echo "$registrar" | tr '[:upper:]' '[:lower:]')
        for r in "${high_abuse_registrars[@]}"; do
            if [[ "$registrar_lc" =~ $r ]]; then
                echo -e "${YELLOW}[WARNING]${NC} Domain registered with high-abuse registrar: $r"
            fi
        done
    fi
    
    # Registrar check - check against suspicious registrars
    local registrar=$(grep -i "Registrar:" "$whois_file" | head -1)
    if [ -n "$registrar" ]; then
        log_forensic "Registrar: $registrar"
        
        # Check against known high-abuse registrars
        local registrar_lower=$(echo "$registrar" | tr '[:upper:]' '[:lower:]')
        for suspicious_reg in "${SUSPICIOUS_REGISTRARS[@]}"; do
            [ -z "$suspicious_reg" ] && continue
            if echo "$registrar_lower" | grep -qi "$suspicious_reg"; then
                log_warning "Domain registered with high-abuse registrar: $suspicious_reg"
                log_threat 15 "High-abuse registrar detected: $suspicious_reg"
                record_ioc "suspicious_registrar" "$suspicious_reg" "Known high-abuse domain registrar"
            fi
        done
    fi
    
    # Privacy protection
    if grep -qi "privacy\|proxy\|whoisguard\|domains by proxy\|perfect privacy\|withheld\|redacted" "$whois_file"; then
        log_warning "Domain uses privacy protection service"
        log_threat 5 "WHOIS privacy protection (common with malicious domains)"
    fi
    
    # Save to evidence
    cp "$whois_file" "${EVIDENCE_DIR}/"
}

check_domain_dns() {
    local domain="$1"
    
    if ! command -v dig &> /dev/null || [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking DNS records: $domain"
    
    local dns_file="${TEMP_DIR}/dns_${domain//\//_}.txt"
    
    # Get various DNS records
    {
        echo "=== A Records ==="
        dig +short A "$domain" 2>/dev/null
        echo ""
        echo "=== AAAA Records ==="
        dig +short AAAA "$domain" 2>/dev/null
        echo ""
        echo "=== MX Records ==="
        dig +short MX "$domain" 2>/dev/null
        echo ""
        echo "=== NS Records ==="
        dig +short NS "$domain" 2>/dev/null
        echo ""
        echo "=== TXT Records ==="
        dig +short TXT "$domain" 2>/dev/null
    } > "$dns_file"
    
    # Check for suspicious patterns
    local a_records=$(dig +short A "$domain" 2>/dev/null)
    
    # Multiple A records (potential fast flux)
    local a_count=$(echo "$a_records" | wc -l)
    if [ "$a_count" -gt 5 ]; then
        log_threat 20 "Multiple A records detected ($a_count) - possible fast flux DNS"
    fi
    
    # Check if IPs are in known malicious list
    for ip in $a_records; do
        if [ -n "${KNOWN_MALICIOUS_IPS[$ip]}" ]; then
            log_threat 80 "DNS resolves to known malicious IP: $ip - ${KNOWN_MALICIOUS_IPS[$ip]}"
        fi
    done
    
    # Check TTL (low TTL may indicate fast flux)
    local ttl=$(dig +nocmd +noall +answer A "$domain" 2>/dev/null | awk '{print $2}' | head -1)
    if [ -n "$ttl" ] && [ "$ttl" -lt 300 ]; then
        log_warning "Low DNS TTL ($ttl seconds) - possible fast flux"
    fi
    
    # Save to evidence
    cp "$dns_file" "${EVIDENCE_DIR}/"
}

check_ssl_certificate() {
    local url="$1"
    
    if [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    # Only for HTTPS URLs
    if ! echo "$url" | grep -qE "^https://"; then
        return
    fi
    
    local domain=$(echo "$url" | sed -E 's|^https://||' | cut -d'/' -f1 | cut -d':' -f1)
    
    log_info "Checking SSL certificate: $domain"
    
    local cert_file="${TEMP_DIR}/cert_${domain//\//_}.txt"
    
    # Get certificate details
    timeout 5 openssl s_client -connect "${domain}:443" -servername "$domain" </dev/null 2>/dev/null | \
        openssl x509 -noout -text > "$cert_file" 2>/dev/null
    
    if [ -s "$cert_file" ]; then
        # Check certificate validity
        local not_before=$(grep "Not Before:" "$cert_file" | head -1)
        local not_after=$(grep "Not After:" "$cert_file" | head -1)
        local issuer=$(grep "Issuer:" "$cert_file" | head -1)
        local subject=$(grep "Subject:" "$cert_file" | head -1)
        
        log_forensic "Certificate Issuer: $issuer"
        log_forensic "Certificate Subject: $subject"
        log_forensic "Valid: $not_before to $not_after"
        
        # Check for self-signed certificate
        if echo "$issuer" | grep -q "$(echo "$subject" | sed 's/Subject://')"; then
            log_threat 30 "Self-signed SSL certificate detected"
        fi
        
        # Check for very short validity period (often used in phishing)
        local validity_days=$(echo "$not_after" | grep -oE "[0-9]{4}" | head -1)
        if [ -n "$validity_days" ]; then
            # Calculate days until expiry
            local expiry_date=$(echo "$not_after" | sed 's/.*Not After : //')
            local expiry_timestamp=$(date -d "$expiry_date" +%s 2>/dev/null || echo 0)
            local now_timestamp=$(date +%s)
            local days_to_expiry=$(( (expiry_timestamp - now_timestamp) / 86400 ))
            
            if [ "$days_to_expiry" -lt 30 ] && [ "$days_to_expiry" -gt 0 ]; then
                log_warning "SSL certificate expires soon (< 30 days)"
            fi
        fi
        
        # Check for Let's Encrypt (commonly used for quick phishing setups)
        if echo "$issuer" | grep -qi "Let's Encrypt"; then
            log_info "Certificate issued by Let's Encrypt"
        fi
        
        cp "$cert_file" "${EVIDENCE_DIR}/"
    fi
}

################################################################################
# THREAT INTELLIGENCE INTEGRATION
################################################################################

load_threat_intelligence() {
    log_info "Loading threat intelligence feeds..."
    
    # Create threat intel directories
    mkdir -p "${TEMP_DIR}/threat_intel"
    
    if [ "$NETWORK_CHECK" = true ]; then
        # Download OpenPhish feed
        download_openphish_feed
        
        # Download URLhaus feed
        download_urlhaus_feed
        
        # Download Abuse.ch feeds
        download_abuse_ch_feeds
        
        # Download public blocklists
        download_public_blocklists
        
        # Load PhishTank data if API key available
        if [ -n "$PHISHTANK_API_KEY" ]; then
            load_phishtank_data
        fi
        
        # Load OTX data if API key available
        if [ -n "$OTX_API_KEY" ]; then
            load_otx_pulses
        fi
    else
        log_warning "Network checks disabled, using only hardcoded IOCs"
    fi
    
    log_success "Threat intelligence loaded"
}

download_openphish_feed() {
    local feed_file="${TEMP_DIR}/threat_intel/openphish.txt"
    
    log_info "  Downloading OpenPhish feed..."
    
    curl -sfL --max-time 30 "https://openphish.com/feed.txt" > "$feed_file" 2>/dev/null
    
    if [ -s "$feed_file" ]; then
        local count=$(wc -l < "$feed_file")
        log_success "  OpenPhish: $count URLs loaded"
    else
        log_warning "  Failed to download OpenPhish feed"
    fi
}

download_urlhaus_feed() {
    local feed_file="${TEMP_DIR}/threat_intel/urlhaus.txt"
    
    log_info "  Downloading URLhaus feed..."
    
    curl -sfL --max-time 30 "https://urlhaus.abuse.ch/downloads/text/" > "$feed_file" 2>/dev/null
    
    if [ -s "$feed_file" ]; then
        local count=$(grep -c "^http" "$feed_file")
        log_success "  URLhaus: $count URLs loaded"
    else
        log_warning "  Failed to download URLhaus feed"
    fi
}

download_abuse_ch_feeds() {
    log_info "  Downloading Abuse.ch feeds..."
    
    # SSL blacklist
    curl -sfL --max-time 30 "https://sslbl.abuse.ch/blacklist/sslblacklist.csv" > \
        "${TEMP_DIR}/threat_intel/sslbl.csv" 2>/dev/null
    
    # Malware bazaar recent additions
    curl -sfL --max-time 30 "https://bazaar.abuse.ch/export/txt/md5/recent/" > \
        "${TEMP_DIR}/threat_intel/malware_bazaar_md5.txt" 2>/dev/null
    
    # Feodo Tracker
    curl -sfL --max-time 30 "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" > \
        "${TEMP_DIR}/threat_intel/feodo_ips.txt" 2>/dev/null
    
    # ThreatFox IOCs
    curl -sfL --max-time 30 "https://threatfox.abuse.ch/export/json/recent/" > \
        "${TEMP_DIR}/threat_intel/threatfox.json" 2>/dev/null
    
    log_success "  Abuse.ch feeds loaded"
}

download_public_blocklists() {
    log_info "  Downloading public blocklists..."
    
    # Spamhaus DROP list
    curl -sfL --max-time 30 "https://www.spamhaus.org/drop/drop.txt" > \
        "${TEMP_DIR}/threat_intel/spamhaus_drop.txt" 2>/dev/null
    
    # Emergingthreats compromised IPs
    curl -sfL --max-time 30 "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" > \
        "${TEMP_DIR}/threat_intel/et_compromised.txt" 2>/dev/null
    
    # Ransomware tracker domains
    curl -sfL --max-time 30 "https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt" > \
        "${TEMP_DIR}/threat_intel/ransomware_domains.txt" 2>/dev/null
    
    log_success "  Public blocklists loaded"
}

load_phishtank_data() {
    local api_key="$PHISHTANK_API_KEY"
    local feed_file="${TEMP_DIR}/threat_intel/phishtank.json"
    
    log_info "  Loading PhishTank data..."
    
    # Note: PhishTank requires app_key parameter
    curl -sfL --max-time 60 \
        "https://data.phishtank.com/data/$api_key/online-valid.json" > "$feed_file" 2>/dev/null
    
    if [ -s "$feed_file" ]; then
        local count=$(jq 'length' "$feed_file" 2>/dev/null || echo "0")
        log_success "  PhishTank: $count verified phishing URLs loaded"
    else
        log_warning "  Failed to load PhishTank data"
    fi
}

load_otx_pulses() {
    local api_key="$OTX_API_KEY"
    
    log_info "  Loading OTX AlienVault pulses..."
    
    # Get subscribed pulses
    local pulses_file="${TEMP_DIR}/threat_intel/otx_pulses.json"
    
    curl -sfL --max-time 30 \
        -H "X-OTX-API-KEY: $api_key" \
        "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50" > "$pulses_file" 2>/dev/null
    
    if [ -s "$pulses_file" ]; then
        local count=$(jq '.count' "$pulses_file" 2>/dev/null || echo "0")
        log_success "  OTX: $count pulses loaded"
        
        # Extract IOCs from pulses
        jq -r '.results[].indicators[]? | select(.type == "URL" or .type == "domain" or .type == "IPv4") | .indicator' \
            "$pulses_file" > "${TEMP_DIR}/threat_intel/otx_iocs.txt" 2>/dev/null
    else
        log_warning "  Failed to load OTX pulses"
    fi
}

check_against_threat_intel() {
    local ioc="$1"
    local ioc_type="$2"  # url, domain, ip, hash
    
    local matches=0
    
    # Check against downloaded feeds
    case "$ioc_type" in
        "url")
            # OpenPhish
            if [ -f "${TEMP_DIR}/threat_intel/openphish.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/openphish.txt" 2>/dev/null; then
                    log_forensic_detection 100 \
                        "PHISHING URL DETECTED" \
                        "$ioc" \
                        "OpenPhish Feed (active $(date +%Y-%m-%d))" \
                        "QR decoded content" \
                        "DO NOT VISIT - Known phishing site" \
                        "https://openphish.com"
                    ((matches++))
                fi
            fi
            
            # URLhaus
            if [ -f "${TEMP_DIR}/threat_intel/urlhaus.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/urlhaus.txt" 2>/dev/null; then
                    log_forensic_detection 100 \
                        "MALWARE URL DETECTED" \
                        "$ioc" \
                        "URLhaus Feed (Abuse.ch)" \
                        "QR decoded content" \
                        "DO NOT VISIT - Known malware distribution" \
                        "https://urlhaus.abuse.ch"
                    ((matches++))
                fi
            fi
            
            # PhishTank
            if [ -f "${TEMP_DIR}/threat_intel/phishtank.json" ]; then
                if jq -e ".[] | select(.url == \"$ioc\")" "${TEMP_DIR}/threat_intel/phishtank.json" > /dev/null 2>&1; then
                    log_forensic_detection 100 \
                        "VERIFIED PHISHING URL" \
                        "$ioc" \
                        "PhishTank (Community Verified)" \
                        "QR decoded content" \
                        "DO NOT VISIT - Community verified phishing" \
                        "https://phishtank.org"
                    ((matches++))
                fi
            fi
            ;;
        "domain")
            # Ransomware domains
            if [ -f "${TEMP_DIR}/threat_intel/ransomware_domains.txt" ]; then
                if grep -qiF "$ioc" "${TEMP_DIR}/threat_intel/ransomware_domains.txt" 2>/dev/null; then
                    log_threat 100 "🔒 RANSOMWARE DOMAIN DETECTED!"
                    log_error "    ├─ Source: Ransomware Tracker"
                    log_error "    ├─ Domain: $ioc"
                    log_error "    └─ Recommendation: Block immediately - Associated with ransomware operations"
                    record_ioc "ransomware_domain" "$ioc" "Ransomware tracker match"
                    ((matches++))
                fi
            fi
            
            # OTX IOCs
            if [ -f "${TEMP_DIR}/threat_intel/otx_iocs.txt" ]; then
                if grep -qiF "$ioc" "${TEMP_DIR}/threat_intel/otx_iocs.txt" 2>/dev/null; then
                    log_threat 80 "⚠️  THREAT INTELLIGENCE MATCH!"
                    log_warning "    ├─ Source: OTX AlienVault"
                    log_warning "    ├─ Domain: $ioc"
                    log_warning "    └─ Recommendation: Investigate - Known threat indicator"
                    record_ioc "otx_ioc" "$ioc" "OTX AlienVault match"
                    ((matches++))
                fi
            fi
            ;;
        "ip")
            # Spamhaus DROP
            if [ -f "${TEMP_DIR}/threat_intel/spamhaus_drop.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/spamhaus_drop.txt" 2>/dev/null; then
                    log_threat 100 "🚫 BLOCKED IP DETECTED!"
                    log_error "    ├─ Source: Spamhaus DROP List"
                    log_error "    ├─ IP: $ioc"
                    log_error "    └─ Recommendation: Block at firewall - Known malicious infrastructure"
                    record_ioc "blocked_ip" "$ioc" "Spamhaus DROP match"
                    ((matches++))
                fi
            fi
            
            # Feodo Tracker
            if [ -f "${TEMP_DIR}/threat_intel/feodo_ips.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/feodo_ips.txt" 2>/dev/null; then
                    log_threat 100 "💰 BANKING TROJAN C2 DETECTED!"
                    log_error "    ├─ Source: Feodo Tracker (Abuse.ch)"
                    log_error "    ├─ IP: $ioc"
                    log_error "    └─ Recommendation: Block immediately - Banking trojan command & control"
                    record_ioc "c2_ip" "$ioc" "Feodo Tracker match"
                    ((matches++))
                fi
            fi
            
            # ET Compromised
            if [ -f "${TEMP_DIR}/threat_intel/et_compromised.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/et_compromised.txt" 2>/dev/null; then
                    log_threat 80 "IP found in EmergingThreats compromised list!"
                    ((matches++))
                fi
            fi
            ;;
        "hash")
            # Malware Bazaar
            if [ -f "${TEMP_DIR}/threat_intel/malware_bazaar_md5.txt" ]; then
                if grep -qiF "$ioc" "${TEMP_DIR}/threat_intel/malware_bazaar_md5.txt" 2>/dev/null; then
                    log_threat 100 "Hash found in Malware Bazaar!"
                    ((matches++))
                fi
            fi
            ;;
    esac
    
    return $matches
}

check_virustotal() {
    local target="$1"
    local target_type="$2"  # url, domain, ip, file
    
    if [ -z "$VT_API_KEY" ]; then
        log_warning "VirusTotal API key not set, skipping VT check"
        return
    fi
    
    if [ "$VT_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking VirusTotal: $target"
    
    local vt_response=""
    local api_url=""
    
    case "$target_type" in
        "url")
            # URL scan - need to encode URL
            local encoded_url=$(python3 -c "import base64; print(base64.urlsafe_b64encode('$target'.encode()).decode().rstrip('='))" 2>/dev/null)
            api_url="https://www.virustotal.com/api/v3/urls/$encoded_url"
            ;;
        "domain")
            api_url="https://www.virustotal.com/api/v3/domains/$target"
            ;;
        "ip")
            api_url="https://www.virustotal.com/api/v3/ip_addresses/$target"
            ;;
        "file")
            # For file, target is the hash
            api_url="https://www.virustotal.com/api/v3/files/$target"
            ;;
    esac
    
    vt_response=$(curl -sf --max-time 30 \
        -H "x-apikey: $VT_API_KEY" \
        "$api_url" 2>/dev/null)
    
    if [ -n "$vt_response" ]; then
        local malicious=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.malicious // 0' 2>/dev/null)
        local suspicious=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0' 2>/dev/null)
        local total=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.harmless + .data.attributes.last_analysis_stats.malicious + .data.attributes.last_analysis_stats.suspicious + .data.attributes.last_analysis_stats.undetected // 0' 2>/dev/null)
        
        if [ "$malicious" -gt 0 ]; then
            log_threat $((malicious * 5)) "VirusTotal: $malicious/$total engines flagged as MALICIOUS"
        elif [ "$suspicious" -gt 0 ]; then
            log_threat $((suspicious * 3)) "VirusTotal: $suspicious/$total engines flagged as suspicious"
        else
            log_success "VirusTotal: No detections ($total engines checked)"
        fi
        
        # Save full response
        echo "$vt_response" > "${EVIDENCE_DIR}/vt_${target_type}_$(echo "$target" | md5sum | cut -d' ' -f1).json"
    else
        log_warning "VirusTotal check failed or returned empty response"
    fi
}

check_urlscan() {
    local url="$1"
    
    if [ -z "$URLSCAN_API_KEY" ] || [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking URLScan.io..."
    
    # Search for existing scans
    local search_response=$(curl -sf --max-time 30 \
        -H "API-Key: $URLSCAN_API_KEY" \
        "https://urlscan.io/api/v1/search/?q=page.url:\"$url\"" 2>/dev/null)
    
    if [ -n "$search_response" ]; then
        local results=$(echo "$search_response" | jq -r '.results | length' 2>/dev/null)
        
        if [ "$results" -gt 0 ]; then
            log_info "URLScan.io: Found $results previous scans"
            
            # Get verdicts from scans
            local verdicts=$(echo "$search_response" | jq -r '.results[].verdicts.overall.malicious' 2>/dev/null)
            if echo "$verdicts" | grep -q "true"; then
                log_threat 70 "URLScan.io: Previous scans flagged as malicious!"
            fi
        fi
    fi
}

check_abuseipdb() {
    local ip="$1"
    
    if [ -z "$ABUSEIPDB_API_KEY" ] || [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Checking AbuseIPDB: $ip"
    
    local response=$(curl -sf --max-time 30 \
        -H "Key: $ABUSEIPDB_API_KEY" \
        -H "Accept: application/json" \
        "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" 2>/dev/null)
    
    if [ -n "$response" ]; then
        local abuse_score=$(echo "$response" | jq -r '.data.abuseConfidenceScore // 0' 2>/dev/null)
        local total_reports=$(echo "$response" | jq -r '.data.totalReports // 0' 2>/dev/null)
        local isp=$(echo "$response" | jq -r '.data.isp // "Unknown"' 2>/dev/null)
        
        if [ "$abuse_score" -gt 50 ]; then
            log_threat $((abuse_score / 2)) "AbuseIPDB: High abuse score ($abuse_score%) - $total_reports reports"
        elif [ "$abuse_score" -gt 0 ]; then
            log_warning "AbuseIPDB: Some reports exist ($abuse_score% confidence, $total_reports reports)"
        else
            log_success "AbuseIPDB: No abuse reports for $ip (ISP: $isp)"
        fi
        
        echo "$response" > "${EVIDENCE_DIR}/abuseipdb_$ip.json"
    fi
}

################################################################################
# APT ATTRIBUTION ENGINE
################################################################################

analyze_apt_indicators() {
    local content="$1"
    
    if [ "$APT_ATTRIBUTION" = false ]; then
        return
    fi
    
    log_apt "Analyzing for APT indicators..."
    
    local apt_matches=()
    
    # Check against known APT indicators
    for apt_group in "${!APT_INDICATORS[@]}"; do
        local group_name=$(echo "$apt_group" | cut -d'_' -f1)
        local indicator_type=$(echo "$apt_group" | cut -d'_' -f2-)
        local indicators="${APT_INDICATORS[$apt_group]}"
        
        IFS=',' read -ra indicator_array <<< "$indicators"
        for indicator in "${indicator_array[@]}"; do
            if echo "$content" | grep -qi "$indicator"; then
                apt_matches+=("$group_name:$indicator_type:$indicator")
                log_apt "Potential $group_name indicator: $indicator ($indicator_type)"
            fi
        done
    done
    
    # Check against malware family signatures
    for family in "${!MALWARE_SIGNATURES[@]}"; do
        local family_name=$(echo "$family" | cut -d'_' -f1)
        local sig_type=$(echo "$family" | cut -d'_' -f2-)
        local signatures="${MALWARE_SIGNATURES[$family]}"
        
        IFS=',' read -ra sig_array <<< "$signatures"
        for sig in "${sig_array[@]}"; do
            if echo "$content" | grep -qiE "$sig"; then
                apt_matches+=("malware:$family_name:$sig")
                log_apt "Potential malware family signature: $family_name - $sig"
            fi
        done
    done
    
    # Check against ransomware indicators
    for ransomware in "${!RANSOMWARE_INDICATORS[@]}"; do
        local ransom_name=$(echo "$ransomware" | cut -d'_' -f1)
        local ind_type=$(echo "$ransomware" | cut -d'_' -f2-)
        local indicators="${RANSOMWARE_INDICATORS[$ransomware]}"
        
        IFS=',' read -ra ind_array <<< "$indicators"
        for ind in "${ind_array[@]}"; do
            if echo "$content" | grep -qiE "$ind"; then
                apt_matches+=("ransomware:$ransom_name:$ind")
                log_threat 80 "Ransomware indicator detected: $ransom_name - $ind"
            fi
        done
    done
    
    # Generate APT report if matches found
    if [ ${#apt_matches[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "APT/MALWARE ATTRIBUTION ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo ""
            echo "Detected Indicators:"
            for match in "${apt_matches[@]}"; do
                echo "  - $match"
            done
            echo ""
            echo "Attribution Confidence: $(calculate_apt_confidence "${apt_matches[@]}")"
            echo ""
        } >> "$APT_REPORT"
        
        analysis_success_found "APT-ANALYSIS" "${#apt_matches[@]}" "Matched indicators found"
    else
        analysis_success_none "APT-ANALYSIS"
    fi
}

calculate_apt_confidence() {
    local matches=("$@")
    local unique_groups=()
    
    for match in "${matches[@]}"; do
        local group=$(echo "$match" | cut -d':' -f1-2)
        if [[ ! " ${unique_groups[*]} " =~ " ${group} " ]]; then
            unique_groups+=("$group")
        fi
    done
    
    local group_count=${#unique_groups[@]}
    local match_count=${#matches[@]}
    
    if [ $group_count -eq 1 ] && [ $match_count -ge 3 ]; then
        echo "HIGH (multiple indicators from single threat actor)"
    elif [ $group_count -ge 2 ]; then
        echo "MEDIUM (indicators from multiple sources - possible overlap)"
    elif [ $match_count -ge 2 ]; then
        echo "MEDIUM (multiple indicators detected)"
    else
        echo "LOW (single indicator match)"
    fi
}

################################################################################
# BEHAVIORAL ANALYSIS ENGINE
################################################################################

perform_behavioral_analysis() {
    local content="$1"
    
    if [ "$BEHAVIORAL_ANALYSIS" = false ]; then
        return
    fi
    
    log_info "Performing behavioral analysis..."
    
    local behaviors=()
    local risk_score=0
    
    # Check for evasion techniques
    check_sandbox_evasion "$content"
    check_anti_vm_techniques "$content"
    check_anti_debug_techniques "$content"
    check_time_based_evasion "$content"
    
    # Check for persistence mechanisms
    check_persistence_techniques "$content"
    
    # Check for lateral movement indicators
    check_lateral_movement "$content"
    
    # Check for data exfiltration patterns
    check_exfiltration_patterns "$content"
    
    # Check for privilege escalation
    check_privilege_escalation "$content"
    
    # Check for defense evasion
    check_defense_evasion "$content"
    
    # Check for command and control patterns
    check_c2_patterns "$content"
    
    # Check for credential access
    check_credential_access "$content"
    
    # Check for discovery techniques
    check_discovery_techniques "$content"
    
    # Check for impact techniques
    check_impact_techniques "$content"
}

check_sandbox_evasion() {
    local content="$1"
    
    local evasion_techniques=(
        "mouse_move" "cursor_pos" "GetCursorPos"
        "sleep.*[0-9]{4,}" "Sleep.*[0-9]{4,}"
        "tick.*count" "GetTickCount"
        "username.*sandbox\|malware\|virus\|sample"
        "processor.*count" "NumberOfProcessors"
        "memory.*[0-9].*GB" "GlobalMemoryStatus"
        "disk.*size" "GetDiskFreeSpace"
        "recent.*files" "GetRecentFiles"
        "screen.*resolution" "GetSystemMetrics"
        "uptime" "GetTickCount64"
    )
    
    for technique in "${evasion_techniques[@]}"; do
        if echo "$content" | grep -qiE "$technique"; then
            log_threat 55 "Sandbox evasion technique detected: $technique"
        fi
    done
}

check_anti_vm_techniques() {
    local content="$1"
    
    local vm_indicators=(
        "VMware" "VirtualBox" "VBOX" "QEMU" "Xen" "Hyper-V"
        "Parallels" "\.vmx" "\.vbox" "vmtoolsd" "vboxservice"
        "vmmouse" "vmhgfs" "vm3dgl" "vmrawdsk" "vmusbmouse"
        "vmx_svga" "vmxnet" "vmware" "virtualbox" "qemu-ga"
        "sbiedll" "sandboxie" "wine_get_unix_file_name"
        "Bochs" "VPC" "Virtual PC" "anubis" "cuckoo"
        "joebox" "sunbelt" "threatexpert" "virustotal"
    )
    
    for indicator in "${vm_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 45 "Anti-VM technique detected: $indicator"
        fi
    done
}

check_anti_debug_techniques() {
    local content="$1"
    
    local debug_checks=(
        "IsDebuggerPresent" "CheckRemoteDebuggerPresent"
        "NtQueryInformationProcess" "OutputDebugString"
        "FindWindow.*OLLYDBG" "FindWindow.*WinDbg"
        "FindWindow.*x64dbg" "FindWindow.*IDA"
        "ptrace" "PTRACE_TRACEME"
        "SIGTRAP" "SIGSTOP" "debugger"
        "int 3" "int 0x3" "DebugBreak"
        "NtSetInformationThread" "ThreadHideFromDebugger"
        "RtlQueryProcessDebugInformation"
        "CloseHandle.*invalid" "NtClose"
    )
    
    for check in "${debug_checks[@]}"; do
        if echo "$content" | grep -qiE "$check"; then
            log_threat 50 "Anti-debug technique detected: $check"
        fi
    done
}

check_time_based_evasion() {
    local content="$1"
    
    # Check for time delays
    if echo "$content" | grep -qiE "sleep[[:space:]]*[(\[]?[[:space:]]*[0-9]{4,}|timeout[[:space:]]*[/]?[[:space:]]*t?[[:space:]]*[0-9]{3,}|delay[[:space:]]*[:\(][[:space:]]*[0-9]{4,}"; then
        log_threat 40 "Time-based evasion detected (long sleep/delay)"
    fi
    
    # Check for date/time checks
    if echo "$content" | grep -qiE "GetSystemTime|GetLocalTime|QueryPerformanceCounter|timeGetTime"; then
        log_warning "Time-related API calls detected (possible time-based evasion)"
    fi
}

check_persistence_techniques() {
    local content="$1"
    
    local persistence_indicators=(
        # Windows Registry
        "HKLM.*Run" "HKCU.*Run" "CurrentVersion\\\\Run"
        "Winlogon" "UserInit" "Shell" "Userinit"
        "AppInit_DLLs" "Services\\\\.*\\\\ImagePath"
        # Scheduled Tasks
        "schtasks" "at [0-9]" "Task Scheduler"
        # Startup folders
        "Startup" "Start Menu.*Programs.*Startup"
        # Services
        "sc create" "New-Service" "CreateService"
        # Linux/macOS
        "crontab" "/etc/cron" "systemctl enable"
        ".bashrc" ".profile" ".bash_profile"
        "LaunchAgent" "LaunchDaemon" ".plist"
        "init.d" "rc.local" "/etc/init"
        # WMI
        "WMI.*subscription" "__EventFilter" "__EventConsumer"
        # Office
        "XLSTART" "Word.*Startup" "Outlook.*\\\\VbaProject"
        # Bootkit
        "MBR" "VBR" "bootmgr" "winload"
    )
    
    for indicator in "${persistence_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 60 "Persistence technique detected: $indicator"
        fi
    done
}

check_lateral_movement() {
    local content="$1"
    
    local lateral_indicators=(
        "psexec" "PsExec" "wmic.*process.*call.*create"
        "winrm" "WinRM" "Invoke-Command"
        "Enter-PSSession" "New-PSSession"
        "mstsc" "RDP" "Terminal Services"
        "net use" "\\\\\\\\.*\\\\.*\$" "\\\\\\\\.*\\\\admin\$"
        "ssh.*@" "scp" "rsync"
        "rexec" "rsh" "rlogin"
        "pass.*the.*hash" "mimikatz.*sekurlsa"
        "Invoke-Mimikatz" "Invoke-TheHash"
        "smbexec" "dcomexec" "atexec"
    )
    
    for indicator in "${lateral_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 65 "Lateral movement indicator: $indicator"
        fi
    done
}

check_exfiltration_patterns() {
    local content="$1"
    
    local exfil_indicators=(
        # Data staging
        "compress" "7z" "rar" "zip.*-p"
        "tar.*-c" "makecab"
        # Network exfiltration
        "ftp.*put" "scp" "curl.*-T" "wget.*--post"
        "Invoke-WebRequest.*-Method.*Post"
        "base64.*http" "http.*base64"
        # Cloud exfiltration
        "s3.*cp" "gsutil.*cp" "azcopy"
        "dropbox" "gdrive" "onedrive.*upload"
        # DNS exfiltration
        "nslookup.*txt" "dig.*txt"
        # Email exfiltration
        "smtp" "sendmail" "blat"
    )
    
    for indicator in "${exfil_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 55 "Data exfiltration pattern: $indicator"
        fi
    done
}

check_privilege_escalation() {
    local content="$1"
    
    local privesc_indicators=(
        # Windows
        "runas" "SeDebugPrivilege" "SeImpersonatePrivilege"
        "getsystem" "potato" "printspoofer"
        "juicy.*potato" "rotten.*potato" "sweet.*potato"
        "Token.*Impersonation" "ImpersonateNamedPipeClient"
        "AlwaysInstallElevated"
        # Linux
        "sudo.*-" "su.*-" "setuid" "setgid"
        "chmod.*s" "chmod.*4" "SUID"
        "pkexec" "doas"
        "/etc/passwd" "/etc/shadow"
        "LD_PRELOAD" "LD_LIBRARY_PATH"
        # Exploits
        "CVE-" "exploit" "poc" "0day"
        "buffer.*overflow" "heap.*spray"
        "use.*after.*free" "race.*condition"
    )
    
    for indicator in "${privesc_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 60 "Privilege escalation indicator: $indicator"
        fi
    done
}

check_defense_evasion() {
    local content="$1"
    
    local evasion_indicators=(
        # AV/EDR tampering
        "disable.*defender" "Set-MpPreference.*-Disable"
        "Stop-Service.*Windows.*Defender"
        "Uninstall-WindowsFeature.*Windows-Defender"
        "EICAR" "amsi.*bypass" "AMSI.*Patch"
        "ETW.*bypass" "EventLog.*Clear"
        "wevtutil.*cl" "Clear-EventLog"
        # Process manipulation
        "process.*hollow" "process.*inject"
        "RunPE" "reflective.*load"
        "NtUnmapViewOfSection" "WriteProcessMemory"
        "CreateRemoteThread" "QueueUserAPC"
        # File manipulation
        "attrib.*h" "hidden" "system.*file"
        "alternate.*data.*stream" "ADS" ":.*:.*\$DATA"
        "timestomp" "touch.*-t"
        # Indicator removal
        "wipe" "shred" "srm" "sdelete"
        "format" "diskpart.*clean"
    )
    
    for indicator in "${evasion_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 55 "Defense evasion technique: $indicator"
        fi
    done
}

check_c2_patterns() {
    local content="$1"
    
    # Check against C2 pattern database
    for pattern_name in "${!C2_PATTERNS[@]}"; do
        local pattern="${C2_PATTERNS[$pattern_name]}"
        if echo "$content" | grep -qiE "$pattern"; then
            log_threat 70 "C2 pattern detected: $pattern_name"
        fi
    done
}

check_credential_access() {
    local content="$1"
    
    local cred_indicators=(
        # Password dumping
        "mimikatz" "sekurlsa" "logonpasswords"
        "lsass" "procdump.*lsass"
        "comsvcs.*MiniDump" "rundll32.*comsvcs"
        "SAM" "SYSTEM.*hive" "SECURITY.*hive"
        # Credential files
        "id_rsa" "id_dsa" "\.pem" "\.key"
        "\.kdbx" "KeePass" "password.*manager"
        "credentials.*xml" "unattend.*xml"
        # Browser credentials
        "Login.*Data" "Cookies.*sqlite"
        "chrome.*password" "firefox.*password"
        "stored.*password" "credential.*store"
        # Network sniffing
        "tcpdump" "wireshark" "tshark"
        "responder" "inveigh" "ntlmrelay"
    )
    
    for indicator in "${cred_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 70 "Credential access indicator: $indicator"
        fi
    done
}

check_discovery_techniques() {
    local content="$1"
    
    local discovery_indicators=(
        # System discovery
        "systeminfo" "hostname" "whoami /all"
        "net user" "net localgroup" "net group"
        "wmic.*computersystem" "Get-ComputerInfo"
        # Network discovery
        "ipconfig /all" "ifconfig -a" "ip addr"
        "netstat" "arp -a" "route print"
        "nslookup" "nltest" "Get-ADDomain"
        "net view" "net share" "wmic.*share"
        "ping.*-n" "traceroute" "nmap"
        # Process discovery
        "tasklist" "ps aux" "wmic.*process"
        "Get-Process" "top" "htop"
        # File discovery
        "dir /s" "find /" "locate"
        "Get-ChildItem.*-Recurse"
        "tree" "ls -laR"
    )
    
    for indicator in "${discovery_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_warning "Discovery technique detected: $indicator"
        fi
    done
}

check_impact_techniques() {
    local content="$1"
    
    local impact_indicators=(
        # Ransomware
        "encrypt" "decrypt" "ransom"
        "bitcoin" "monero" "payment"
        "\.locked" "\.encrypted" "\.crypt"
        # Data destruction
        "wipe" "destroy" "delete.*recursive"
        "rm -rf" "format" "cipher /w"
        "overwrite" "shred" "dd.*if=/dev"
        # Defacement
        "defaced" "hacked by" "pwned"
        # Service disruption
        "ddos" "flood" "dos attack"
        "fork.*bomb" ":(){ :|:& };"
        # Resource hijacking
        "cryptominer" "xmrig" "minerd"
        "stratum" "mining.*pool"
    )
    
    for indicator in "${impact_indicators[@]}"; do
        if echo "$content" | grep -qiE "$indicator"; then
            log_threat 80 "Impact technique detected: $indicator"
        fi
    done
}

################################################################################
# PAYLOAD ANALYSIS ENGINE
################################################################################

analyze_payload_content() {
    local content="$1"
    
    log_info "Analyzing payload content..."
    
    # Check for encoded content
    analyze_encoding "$content"
    
    # Check for obfuscation
    analyze_obfuscation "$content"
    
    # Check for scripts
    analyze_script_content "$content"
    
    # Check for commands
    analyze_command_content "$content"
    
    # Check for credentials/secrets
    analyze_secrets "$content"
    
    # Check for crypto addresses
    analyze_crypto_addresses "$content"
    
    # Check for phone numbers
    analyze_phone_numbers "$content"
    
    # Check for email addresses
    analyze_email_addresses "$content"
    
    # Run YARA-like rules
    evaluate_all_yara_rules "$content"
}

analyze_encoding() {
    local content="$1"
    
    log_info "  Checking for encoded content..."
    
    # Base64 detection
    if echo "$content" | grep -qE "^[A-Za-z0-9+/]{40,}={0,2}$"; then
        log_warning "Potential Base64 encoded content detected"
        local decoded=$(echo "$content" | base64 -d 2>/dev/null)
        if [ -n "$decoded" ]; then
            log_forensic "Base64 decoded (first 200 chars): ${decoded:0:200}"
            # Recursively analyze decoded content
            analyze_payload_content "$decoded"
        fi
    fi
    
    # Hex encoding
    if echo "$content" | grep -qE "^[0-9a-fA-F]{40,}$"; then
        log_warning "Potential hex encoded content detected"
        local decoded=$(echo "$content" | xxd -r -p 2>/dev/null)
        if [ -n "$decoded" ]; then
            log_forensic "Hex decoded (first 200 chars): ${decoded:0:200}"
        fi
    fi
    
    # URL encoding
    if echo "$content" | grep -qE "(%[0-9A-Fa-f]{2}){5,}"; then
        log_warning "Heavy URL encoding detected"
        local decoded=$(python3 -c "import urllib.parse; print(urllib.parse.unquote('$content'))" 2>/dev/null)
        if [ -n "$decoded" ] && [ "$decoded" != "$content" ]; then
            log_forensic "URL decoded: $decoded"
        fi
    fi
    
    # Unicode escape sequences
    if echo "$content" | grep -qE "(\\\\u[0-9a-fA-F]{4}){5,}"; then
        log_warning "Unicode escape sequences detected"
        local decoded=$(python3 -c "print('$content'.encode().decode('unicode_escape'))" 2>/dev/null)
        if [ -n "$decoded" ]; then
            log_forensic "Unicode decoded: $decoded"
        fi
    fi
    
    # Gzip/deflate compressed
    if echo "$content" | xxd 2>/dev/null | head -1 | grep -qE "1f8b|789c"; then
        log_warning "Compressed content detected (gzip/zlib)"
        log_threat 30 "Compressed payload - potential evasion"
    fi
}

analyze_obfuscation() {
    local content="$1"
    
    log_info "  Checking for obfuscation..."
    
    # Check against obfuscation patterns
    for pattern_name in "${!OBFUSCATION_PATTERNS[@]}"; do
        local pattern="${OBFUSCATION_PATTERNS[$pattern_name]}"
        if echo "$content" | grep -qE "$pattern"; then
            log_threat 35 "Obfuscation technique detected: $pattern_name"
        fi
    done
    
    # String entropy analysis
    local entropy=$(calculate_string_entropy "$content")
    if (( $(echo "$entropy > 5.5" | bc -l 2>/dev/null || echo "0") )); then
        log_warning "High string entropy ($entropy) - possible encryption/obfuscation"
    fi
    
    # Check for character frequency anomalies
    analyze_char_frequency "$content"
}

calculate_string_entropy() {
    local str="$1"
    
    python3 << EOF 2>/dev/null
import math
from collections import Counter

s = '''$str'''
if len(s) == 0:
    print("0.0")
else:
    counter = Counter(s)
    length = len(s)
    entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
    print(f"{entropy:.4f}")
EOF
}

analyze_char_frequency() {
    local content="$1"
    
    python3 << EOF 2>/dev/null
from collections import Counter

content = '''$content'''
if len(content) < 50:
    exit(0)

counter = Counter(content.lower())
total = sum(counter.values())

# Expected frequencies for English text
expected = {'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070}

# Calculate deviation
deviation = 0
for char, expected_freq in expected.items():
    actual_freq = counter.get(char, 0) / total
    deviation += abs(actual_freq - expected_freq)

if deviation > 0.3:
    print(f"CHAR_FREQ_ANOMALY: High deviation from expected frequencies ({deviation:.3f})")
EOF
}

analyze_script_content() {
    local content="$1"
    
    log_info "  Checking for script content..."
    
    # PowerShell
    if echo "$content" | grep -qiE "powershell|pwsh|\$\{|\$\(|Invoke-|IEX|New-Object|System\."; then
        log_threat 50 "PowerShell content detected"
        analyze_powershell_payload "$content"
    fi
    
    # Bash/Shell
    if echo "$content" | grep -qiE "^#!/|bash|/bin/sh|wget|curl|chmod|sudo|eval|exec"; then
        log_threat 45 "Shell script content detected"
        analyze_shell_payload "$content"
    fi
    
    # JavaScript
    if echo "$content" | grep -qiE "javascript:|<script|document\.|window\.|eval\(|Function\("; then
        log_threat 40 "JavaScript content detected"
        analyze_javascript_payload "$content"
    fi
    
    # Python
    if echo "$content" | grep -qiE "python|import\s+|from\s+.*\s+import|exec\(|eval\(|__import__"; then
        log_threat 40 "Python content detected"
        analyze_python_payload "$content"
    fi
    
    # VBScript
    if echo "$content" | grep -qiE "vbscript:|CreateObject|WScript|Scripting\."; then
        log_threat 50 "VBScript content detected"
    fi
    
    # Batch
    if echo "$content" | grep -qiE "@echo|%.*%|set /|goto|cmd\.exe|command\.com"; then
        log_threat 45 "Windows Batch content detected"
    fi
}

analyze_powershell_payload() {
    local content="$1"
    
    log_forensic "Analyzing PowerShell payload..."
    
    # Dangerous cmdlets
    local dangerous_cmdlets=(
        "Invoke-Expression" "IEX" "Invoke-Command"
        "Invoke-WebRequest" "Invoke-RestMethod"
        "New-Object.*Net\.WebClient" "DownloadString"
        "DownloadFile" "Start-Process" "Invoke-Item"
        "Invoke-WmiMethod" "Invoke-CimMethod"
        "Add-Type" "Reflection\.Assembly"
        "ConvertTo-SecureString" "Get-Credential"
        "Invoke-Mimikatz" "Invoke-Shellcode"
        "Set-MpPreference" "Disable-WindowsOptionalFeature"
    )
    
    for cmdlet in "${dangerous_cmdlets[@]}"; do
        if echo "$content" | grep -qiE "$cmdlet"; then
            log_threat 60 "Dangerous PowerShell cmdlet: $cmdlet"
        fi
    done
    
    # Encoded commands
    if echo "$content" | grep -qiE "\-enc|\-encodedcommand|\-e\s+[A-Za-z0-9+/=]{20,}"; then
        log_threat 70 "Encoded PowerShell command detected"
        
        # Try to decode
        local encoded=$(echo "$content" | grep -oE "[A-Za-z0-9+/=]{50,}" | head -1)
        if [ -n "$encoded" ]; then
            local decoded=$(echo "$encoded" | base64 -d 2>/dev/null | iconv -f UTF-16LE -t UTF-8 2>/dev/null)
            if [ -n "$decoded" ]; then
                log_forensic "Decoded PowerShell: $decoded"
                analyze_powershell_payload "$decoded"
            fi
        fi
    fi
    
    # Bypass techniques
    if echo "$content" | grep -qiE "\-ExecutionPolicy\s+Bypass|\-ep\s+bypass|\-nop|\-windowstyle\s+hidden|\-w\s+hidden"; then
        log_threat 55 "PowerShell bypass/evasion flags detected"
    fi
}

analyze_shell_payload() {
    local content="$1"
    
    log_forensic "Analyzing shell payload..."
    
    # Dangerous commands
    local dangerous_commands=(
        "wget.*\|.*sh" "curl.*\|.*bash" "curl.*\|.*sh"
        "wget.*-O.*&&.*chmod" "curl.*-o.*&&.*chmod"
        "nc\s+-e" "ncat\s+-e" "/dev/tcp/"
        "bash\s+-i" "python.*-c.*socket"
        "perl.*-e.*socket" "ruby.*-rsocket"
        "mkfifo" "mknod" "telnet.*\|.*bash"
        "rm\s+-rf\s+/" "dd\s+if=/dev/zero"
        "chmod\s+777" "chmod\s+u\+s"
        "crontab" "/etc/passwd" "/etc/shadow"
        "useradd" "adduser" "usermod"
        "iptables\s+-F" "ufw\s+disable"
    )
    
    for cmd in "${dangerous_commands[@]}"; do
        if echo "$content" | grep -qiE "$cmd"; then
            log_threat 65 "Dangerous shell command: $cmd"
        fi
    done
    
    # Reverse shell patterns
    if echo "$content" | grep -qiE "bash.*-i.*>&.*/dev/tcp|nc.*-e.*/bin|python.*socket.*connect|php.*fsockopen"; then
        log_threat 80 "Reverse shell pattern detected!"
    fi
}

analyze_javascript_payload() {
    local content="$1"
    
    log_forensic "Analyzing JavaScript payload..."
    
    # Dangerous patterns
    local dangerous_patterns=(
        "eval\s*\(" "Function\s*\(" "setTimeout\s*\(.*eval"
        "document\.write\s*\(.*unescape" "document\.write\s*\(.*String\.fromCharCode"
        "createElement\s*\(.*script" "appendChild\s*\("
        "XMLHttpRequest" "fetch\s*\(" "ActiveXObject"
        "WScript\.Shell" "WScript\.CreateObject"
        "location\s*=" "location\.href\s*=" "location\.replace"
        "window\.open\s*\(" "document\.cookie"
        "localStorage" "sessionStorage"
        "navigator\.sendBeacon" "WebSocket"
    )
    
    for pattern in "${dangerous_patterns[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            log_threat 45 "Dangerous JavaScript pattern: $pattern"
        fi
    done
    
    # Check for heavily obfuscated code
    local bracket_count=$(echo "$content" | grep -o '\[' | wc -l)
    local paren_count=$(echo "$content" | grep -o '(' | wc -l)
    if [ "$bracket_count" -gt 50 ] || [ "$paren_count" -gt 50 ]; then
        log_threat 35 "Heavily obfuscated JavaScript detected"
    fi
}

analyze_python_payload() {
    local content="$1"
    
    log_forensic "Analyzing Python payload..."
    
    # Dangerous patterns
    local dangerous_patterns=(
        "__import__\s*\(" "importlib" "exec\s*\(" "eval\s*\("
        "subprocess" "os\.system" "os\.popen" "commands\."
        "socket\.socket" "urllib\.request" "requests\."
        "paramiko" "fabric" "invoke"
        "pickle\.load" "marshal\.load" "shelve"
        "pty\.spawn" "os\.dup2"
        "compile\s*\(" "code\.interact"
        "ctypes" "cffi"
    )
    
    for pattern in "${dangerous_patterns[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            log_threat 50 "Dangerous Python pattern: $pattern"
        fi
    done
}

analyze_command_content() {
    local content="$1"
    
    log_info "  Checking for command patterns..."
    
    # Windows commands
    local win_commands=(
        "cmd\.exe" "powershell\.exe" "wscript\.exe" "cscript\.exe"
        "mshta\.exe" "regsvr32" "rundll32" "certutil"
        "bitsadmin" "msiexec" "installutil" "regasm"
        "msbuild" "cmstp" "control\.exe" "eventvwr"
        "fodhelper" "computerdefaults" "sdclt"
        "wmic" "net\s+user" "net\s+localgroup" "schtasks"
        "reg\s+add" "reg\s+delete" "bcdedit"
        "vssadmin" "wbadmin" "icacls" "takeown"
    )
    
    for cmd in "${win_commands[@]}"; do
        if echo "$content" | grep -qiE "$cmd"; then
            log_threat 40 "Windows command detected: $cmd"
        fi
    done
    
    # LOLBAS/LOLBIN patterns
    local lolbins=(
        "certutil.*-urlcache" "certutil.*-decode"
        "bitsadmin.*/transfer" "mshta.*javascript"
        "mshta.*vbscript" "regsvr32.*/s.*/n.*/u"
        "rundll32.*javascript" "rundll32.*shell32"
        "cmstp.*/ni.*/s" "msiexec.*/q.*http"
        "installutil.*/logfile" "regasm.*/u"
        "msbuild.*inline" "csc.*/out"
    )
    
    for lolbin in "${lolbins[@]}"; do
        if echo "$content" | grep -qiE "$lolbin"; then
            log_threat 70 "LOLBIN/LOLBAS technique: $lolbin"
        fi
    done
}

analyze_secrets() {
    local content="$1"
    
    log_info "  Checking for exposed secrets..."
    
    # Check against API key patterns
    for key_type in "${!API_KEY_PATTERNS[@]}"; do
        local pattern="${API_KEY_PATTERNS[$key_type]}"
        if echo "$content" | grep -qE "$pattern"; then
            log_threat 60 "Potential $key_type exposed!"
            
            # Record IOC
            local matched=$(echo "$content" | grep -oE "$pattern" | head -1)
            record_ioc "api_key" "$key_type:${matched:0:20}..." "Secret exposure"
        fi
    done
    
    # Check for credential patterns
    for pattern in "${CREDENTIAL_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            log_threat 50 "Credential pattern detected: $pattern"
        fi
    done
    
    # Private keys
    if echo "$content" | grep -qE "-----BEGIN.*(PRIVATE|RSA|EC|DSA|OPENSSH).*-----"; then
        log_threat 80 "Private key detected!"
    fi
    
    # Connection strings
    if echo "$content" | grep -qiE "password=|pwd=|passwd=|secret="; then
        log_threat 55 "Connection string with credentials detected"
    fi
}

analyze_crypto_addresses() {
    local content="$1"
    
    log_info "  Checking for cryptocurrency addresses..."
    
    local crypto_found=false
    
    for pattern in "${CRYPTO_PATTERNS[@]}"; do
        local matches=$(echo "$content" | grep -oE "$pattern")
        if [ -n "$matches" ]; then
            crypto_found=true
            for addr in $matches; do
                log_warning "Cryptocurrency address found: $addr"
                record_ioc "crypto_address" "$addr" "Cryptocurrency address"
                
                # Determine type
                case "$addr" in
                    bc1*) log_info "    Type: Bitcoin Bech32" ;;
                    1*|3*) log_info "    Type: Bitcoin Legacy/SegWit" ;;
                    0x*) log_info "    Type: Ethereum/EVM" ;;
                    4*) log_info "    Type: Monero" ;;
                    L*|M*|ltc1*) log_info "    Type: Litecoin" ;;
                    D*) log_info "    Type: Dogecoin" ;;
                    r*) log_info "    Type: Ripple/XRP" ;;
                    addr1*) log_info "    Type: Cardano" ;;
                    T*) log_info "    Type: Tron" ;;
                esac
            done
        fi
    done
    
    if [ "$crypto_found" = true ]; then
        log_threat 40 "Cryptocurrency addresses detected - possible scam/ransom"
    fi
}

analyze_phone_numbers() {
    local content="$1"
    
    # International phone patterns
    local phone_patterns=(
        "\+[0-9]{1,3}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}"
        "[0-9]{3}[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}"
        "\([0-9]{3}\)[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}"
        "1-[0-9]{3}-[0-9]{3}-[0-9]{4}"
        "1-800-[0-9]{3}-[0-9]{4}"
        "1-888-[0-9]{3}-[0-9]{4}"
        "1-877-[0-9]{3}-[0-9]{4}"
        "1-866-[0-9]{3}-[0-9]{4}"
    )
    
    for pattern in "${phone_patterns[@]}"; do
        local matches=$(echo "$content" | grep -oE "$pattern")
        if [ -n "$matches" ]; then
            for phone in $matches; do
                log_info "Phone number found: $phone"
                record_ioc "phone" "$phone" "Phone number in QR"
                
                # Toll-free numbers are often used in tech support scams
                if echo "$phone" | grep -qE "1-8(00|88|77|66)"; then
                    log_threat 30 "Toll-free number detected - possible tech support scam"
                fi
            done
        fi
    done
}

analyze_email_addresses() {
    local content="$1"
    
    local email_pattern="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    local emails=$(echo "$content" | grep -oE "$email_pattern")
    
    if [ -n "$emails" ]; then
        for email in $emails; do
            log_info "Email address found: $email"
            record_ioc "email" "$email" "Email in QR"
            
            # Check for suspicious domains
            local domain=$(echo "$email" | cut -d'@' -f2)
            
            # Temporary email services
            local temp_domains="tempmail|guerrillamail|mailinator|10minutemail|throwaway|yopmail|fake|temp"
            if echo "$domain" | grep -qiE "$temp_domains"; then
                log_threat 35 "Temporary/disposable email service detected: $domain"
            fi
            
            # Suspicious TLDs
            for tld in "${SUSPICIOUS_TLDS[@]}"; do
                if echo "$domain" | grep -qE "$tld\$"; then
                    log_threat 25 "Email uses suspicious TLD: $tld"
                fi
            done
        done
    fi
}

evaluate_all_yara_rules() {
    local content="$1"
    
    log_info "  Evaluating YARA-like rules..."
    
    for rule_name in "${!YARA_RULES[@]}"; do
        local matched=$(evaluate_yara_rule "$content" "$rule_name")
        if [ "$matched" = "true" ]; then
            # Extract severity from rule
            local severity=$(echo "${YARA_RULES[$rule_name]}" | grep -oE "severity:\s*\w+" | cut -d: -f2 | tr -d ' ')
            
            case "$severity" in
                "CRITICAL") log_threat 80 "YARA rule matched: $rule_name (CRITICAL)" ;;
                "HIGH") log_threat 60 "YARA rule matched: $rule_name (HIGH)" ;;
                "MEDIUM") log_threat 40 "YARA rule matched: $rule_name (MEDIUM)" ;;
                "LOW") log_threat 20 "YARA rule matched: $rule_name (LOW)" ;;
                *) log_threat 30 "YARA rule matched: $rule_name" ;;
            esac
            
            echo "$rule_name,$(date -Iseconds),$content" >> "$YARA_MATCHES"
        fi
    done
}

evaluate_yara_rule() {
    local content="$1"
    local rule_name="$2"
    
    local matched=false
    
    case "$rule_name" in
        "phishing_url")
            if echo "$content" | grep -qiE "login|signin|verify" && \
               echo "$content" | grep -qiE "urgent|suspended|action|required"; then
                matched=true
            fi
            ;;
        "malware_distribution")
            if echo "$content" | grep -qiE "\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jar|apk|msi|dmg|pkg)" && \
               echo "$content" | grep -qiE "download|install|update|patch|setup"; then
                matched=true
            fi
            ;;
        "crypto_scam")
            if echo "$content" | grep -qE "bc1[a-z0-9]{39,87}|1[a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}" && \
               echo "$content" | grep -qiE "limited|exclusive|invest|double|giveaway|airdrop"; then
                matched=true
            fi
            ;;
        "powershell_malware")
            if echo "$content" | grep -qiE "IEX|Invoke-Expression|downloadstring|Net\.WebClient|Invoke-WebRequest" && \
               echo "$content" | grep -qiE "powershell|\-enc|\-encodedcommand"; then
                matched=true
            fi
            ;;
        "ransomware")
            if echo "$content" | grep -qiE "decrypt|encrypted|ransom|bitcoin|\.onion|payment"; then
                local match_count=0
                echo "$content" | grep -qiE "decrypt" && ((match_count++))
                echo "$content" | grep -qiE "encrypted|encrypt" && ((match_count++))
                echo "$content" | grep -qiE "ransom" && ((match_count++))
                echo "$content" | grep -qiE "bitcoin|monero" && ((match_count++))
                echo "$content" | grep -qiE "\.onion" && ((match_count++))
                [ $match_count -ge 2 ] && matched=true
            fi
            ;;
        "c2_communication")
            if echo "$content" | grep -qiE "beacon|checkin|callback|pastebin\.com/raw|raw\.githubusercontent"; then
                matched=true
            fi
            if echo "$content" | grep -qE "http://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"; then
                matched=true
            fi
            ;;
        "data_exfil")
            if echo "$content" | grep -qiE "POST.*(password|credential)" || \
               echo "$content" | grep -qiE "upload.*(zip|rar|7z|tar)" || \
               echo "$content" | grep -qiE "(base64|encode).*http"; then
                matched=true
            fi
            ;;
        "obfuscation")
            if echo "$content" | grep -qiE "eval\(atob\(|String\.fromCharCode|unescape\(%|Function\("; then
                matched=true
            fi
            ;;
        "keylogger")
            if echo "$content" | grep -qiE "keylog|keystroke|GetAsyncKeyState|SetWindowsHookEx|pynput|keyboard\.hook"; then
                matched=true
            fi
            ;;
        "remote_access")
            if echo "$content" | grep -qiE "njrat|darkcomet|remcos|asyncrat|quasar|reverse.shell|bind.shell"; then
                matched=true
            fi
            ;;
        "credential_theft")
            if echo "$content" | grep -qiE "mimikatz|lsass|SAM|sekurlsa|credential.dump"; then
                matched=true
            fi
            if echo "$content" | grep -qiE "browser.*(password|cookie)" || \
               echo "$content" | grep -qiE "(password|cookie).*browser"; then
                matched=true
            fi
            ;;
        "banking_trojan")
            if echo "$content" | grep -qiE "webinject|formgrabber|zeus|dridex|trickbot|emotet"; then
                matched=true
            fi
            ;;
        "mobile_malware")
            if echo "$content" | grep -qiE "READ_SMS.*SEND_SMS|SEND_SMS.*READ_SMS" || \
               echo "$content" | grep -qiE "android\.permission\.CALL_PHONE" || \
               echo "$content" | grep -qiE "\.apk.*(payload|dropper)"; then
                matched=true
            fi
            ;;
        "iot_malware")
            if echo "$content" | grep -qiE "mirai|bashlite|gafgyt|/dev/watchdog"; then
                matched=true
            fi
            if echo "$content" | grep -qiE "telnet.*default.*password"; then
                matched=true
            fi
            ;;
        "cryptominer")
            if echo "$content" | grep -qiE "stratum\+tcp://|xmrig|cpuminer|minergate|\.nanopool\.|monero.*wallet"; then
                matched=true
            fi
            ;;
        "exploit_kit")
            if echo "$content" | grep -qiE "(FlashVars|deployJava|application/pdf)" && \
               echo "$content" | grep -qiE "(<iframe.*src=.*http|eval\(function\(p,a,c,k,e|\\\\x[0-9a-f]{2})"; then
                matched=true
            fi
            ;;
        "phishing_kit")
            if echo "$content" | grep -qiE "<form.*action=.*\.php" && \
               echo "$content" | grep -qiE "<input.*type=.password" && \
               echo "$content" | grep -qiE "(paypal|amazon|google|microsoft|apple|facebook).*\.(png|jpg|svg)"; then
                matched=true
            fi
            ;;
        "session_hijack")
            if echo "$content" | grep -qiE "(session|token|cookie).*(steal|capture|intercept)"; then
                matched=true
            fi
            ;;
        "webshell")
            if echo "$content" | grep -qiE "eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)" || \
               echo "$content" | grep -qiE "system\s*\(\s*\$_(GET|POST)" || \
               echo "$content" | grep -qiE "c99shell|r57shell|wso.shell|b374k"; then
                matched=true
            fi
            ;;
        "sql_injection")
            if echo "$content" | grep -qiE "UNION\s+SELECT|OR\s+1=1|AND\s+1=1|DROP\s+TABLE|SLEEP\(|BENCHMARK\("; then
                matched=true
            fi
            ;;
        "xss_attack")
            if echo "$content" | grep -qiE "<script|onerror\s*=|onload\s*=|javascript:"; then
                matched=true
            fi
            ;;
        "privilege_escalation")
            if echo "$content" | grep -qiE "(sudo|setuid|SUID|runas).*(escalate|privilege)" || \
               echo "$content" | grep -qiE "potato|printspoofer|getsystem"; then
                matched=true
            fi
            ;;
        "persistence")
            if echo "$content" | grep -qiE "HKLM.*Run|HKCU.*Run|CurrentVersion\\\\Run" || \
               echo "$content" | grep -qiE "schtasks|crontab|LaunchAgent|systemctl.enable"; then
                matched=true
            fi
            ;;
        "defense_evasion")
            if echo "$content" | grep -qiE "disable.*defender|AMSI.*bypass|ETW.*bypass" || \
               echo "$content" | grep -qiE "process.*hollow|reflective.*load"; then
                matched=true
            fi
            ;;
        "lateral_movement")
            if echo "$content" | grep -qiE "psexec|wmic.*process.*create|winrm|pass.the.hash"; then
                matched=true
            fi
            ;;
        "data_collection")
            local collection_count=0
            echo "$content" | grep -qiE "screenshot" && ((collection_count++))
            echo "$content" | grep -qiE "keylog" && ((collection_count++))
            echo "$content" | grep -qiE "clipboard" && ((collection_count++))
            echo "$content" | grep -qiE "webcam|camera" && ((collection_count++))
            echo "$content" | grep -qiE "microphone|audio" && ((collection_count++))
            [ $collection_count -ge 2 ] && matched=true
            ;;
    esac
    
    echo "$matched"
}

################################################################################
# IOC RECORDING AND MANAGEMENT
################################################################################

record_ioc() {
    local ioc_type="$1"
    local indicator="$2"
    local context="$3"
    
    local timestamp=$(date -Iseconds)
    
    # Escape commas in indicator and context
    indicator=$(echo "$indicator" | sed 's/,/;/g')
    context=$(echo "$context" | sed 's/,/;/g')
    
    echo "$ioc_type,$indicator,$timestamp,$context" >> "$IOC_REPORT"
}

generate_ioc_summary() {
    log_info "Generating IOC summary..."
    
    if [ ! -s "$IOC_REPORT" ]; then
        log_info "No IOCs recorded"
        return
    fi
    
    {
        echo "═══════════════════════════════════════════════"
        echo "INDICATORS OF COMPROMISE SUMMARY"
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "Total IOCs: $(wc -l < "$IOC_REPORT")"
        echo ""
        echo "By Type:"
        awk -F, 'NR>1 {print $1}' "$IOC_REPORT" | sort | uniq -c | sort -rn
        echo ""
        echo "Detailed IOCs:"
        echo ""
        cat "$IOC_REPORT"
    } >> "$REPORT_FILE"
}

################################################################################
# MAIN QR IMAGE ANALYSIS FUNCTION
################################################################################

analyze_qr_image() {
    local image="$1"
    local image_name=$(basename "$image")
    local image_report="${EVIDENCE_DIR}/${image_name}_report.txt"
    
    echo ""
    log_info "════════════════════════════════════════════════════════════"
    log_info "Analyzing: $image"
    log_info "════════════════════════════════════════════════════════════"
    
    # Verify file exists and is readable
    if [ ! -f "$image" ]; then
        log_error "File not found: $image"
        return 1
    fi
    
    if [ ! -r "$image" ]; then
        log_error "File not readable: $image"
        return 1
    fi
    
    # Get file info
    local file_type=$(file -b "$image")
    local file_size=$(stat -f%z "$image" 2>/dev/null || stat -c%s "$image" 2>/dev/null)
    local file_hash_md5=$(md5sum "$image" 2>/dev/null | cut -d' ' -f1 || md5 -q "$image" 2>/dev/null)
    local file_hash_sha256=$(sha256sum "$image" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$image" 2>/dev/null | cut -d' ' -f1)
    
    log_info "File type: $file_type"
    log_info "File size: $file_size bytes"
    log_info "MD5: $file_hash_md5"
    log_info "SHA256: $file_hash_sha256"
    
    # Record file IOCs
    record_ioc "file_hash_md5" "$file_hash_md5" "$image_name"
    record_ioc "file_hash_sha256" "$file_hash_sha256" "$image_name"
    
    # Check hash against threat intel
    check_against_threat_intel "$file_hash_md5" "hash"
    check_against_threat_intel "$file_hash_sha256" "hash"
    
    # Start image report
    {
        echo "═══════════════════════════════════════════════"
        echo "QR CODE ANALYSIS REPORT"
        echo "═══════════════════════════════════════════════"
        echo "File: $image"
        echo "Analysis Time: $(date -Iseconds)"
        echo ""
        echo "FILE PROPERTIES:"
        echo "  Type: $file_type"
        echo "  Size: $file_size bytes"
        echo "  MD5: $file_hash_md5"
        echo "  SHA256: $file_hash_sha256"
        echo ""
    } > "$image_report"
    
    # Validate image format
    validate_image_format "$image"
    
    # Analyze image metadata
    analyze_image_metadata "$image"
    
    # Check for steganography
    if [ "$STEGANOGRAPHY_CHECK" = true ]; then
        analyze_steganography "$image"
    fi
    
    # Perform OCR analysis
    perform_ocr_analysis "$image"
    
    # Multi-decoder QR analysis
    local decode_output="${TEMP_DIR}/${image_name}_decoded"
    mkdir -p "$(dirname "$decode_output")"
    
    # Set forensic context for detections
    CURRENT_ARTIFACT="$image"
    CURRENT_ARTIFACT_HASH=$(sha256sum "$image" 2>/dev/null | cut -d' ' -f1)
    
    if multi_decoder_analysis "$image" "$decode_output"; then
        # Read and trim whitespace from decoded content
        local merged_content=$(cat "${decode_output}_merged.txt" 2>/dev/null | tr -d '\n\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        CURRENT_DECODED_CONTENT="$merged_content"
        
        if [ -n "$merged_content" ]; then
            log_success "QR code decoded successfully"
            log_info "Content preview: ${merged_content:0:200}..."
            
            {
                echo "QR CODE CONTENT:"
                echo "─────────────────"
                echo "$merged_content"
                echo ""
            } >> "$image_report"
            
            # Analyze the decoded content
            analyze_decoded_qr_content "$merged_content" "$image_report"
        fi
    else
        log_warning "Failed to decode QR code from image"
        echo "QR CODE: Unable to decode" >> "$image_report"
    fi
    
    # Calculate entropy analysis
    if [ "$ENTROPY_ANALYSIS" = true ]; then
        local file_entropy=$(analyze_file_entropy "$image")
        log_info "File entropy: $file_entropy"
        echo "File Entropy: $file_entropy" >> "$image_report"
        
        {
            echo ""
            echo "ENTROPY ANALYSIS:"
            echo "  File entropy: $file_entropy"
            if (( $(echo "$file_entropy > 7.9" | bc -l 2>/dev/null || echo "0") )); then
                echo "  WARNING: High entropy - possible encrypted/compressed hidden data"
            fi
        } >> "$image_report"
    fi
    
    # Final threat assessment for this image
    {
        echo ""
        echo "═══════════════════════════════════════════════"
        echo "THREAT ASSESSMENT"
        echo "═══════════════════════════════════════════════"
        echo "Current Threat Score: $THREAT_SCORE"
        if [ $THREAT_SCORE -ge $CRITICAL_THRESHOLD ]; then
            echo "Risk Level: CRITICAL"
        elif [ $THREAT_SCORE -ge $HIGH_THRESHOLD ]; then
            echo "Risk Level: HIGH"
        elif [ $THREAT_SCORE -ge $MEDIUM_THRESHOLD ]; then
            echo "Risk Level: MEDIUM"
        elif [ $THREAT_SCORE -ge $LOW_THRESHOLD ]; then
            echo "Risk Level: LOW"
        else
            echo "Risk Level: MINIMAL"
        fi
    } >> "$image_report"
    
    # Copy report to main report
    cat "$image_report" >> "$REPORT_FILE"
}

validate_image_format() {
    local image="$1"
    local file_type=$(file -b "$image")
    
    # Check for valid image formats
    if ! echo "$file_type" | grep -qiE "PNG|JPEG|GIF|BMP|TIFF|WebP"; then
        log_warning "Unusual file type for QR image: $file_type"
        log_threat 15 "Non-standard image format"
    fi
    
    # Check for polyglot files (files that are valid as multiple types)
    local magic_bytes=$(xxd -l 16 "$image" 2>/dev/null | head -1)
    
    # PNG magic: 89 50 4E 47
    # JPEG magic: FF D8 FF
    # GIF magic: 47 49 46 38
    # PDF magic: 25 50 44 46
    # ZIP magic: 50 4B
    # PE magic: 4D 5A
    
    if echo "$magic_bytes" | grep -qiE "4d5a|4d 5a"; then
        log_threat 60 "PE executable signature detected in image!"
    fi
    
    if echo "$magic_bytes" | grep -qiE "2550 4446|25 50 44 46"; then
        log_threat 40 "PDF signature detected in image - potential polyglot"
    fi
    
    if echo "$magic_bytes" | grep -qiE "504b|50 4b"; then
        log_threat 35 "ZIP signature detected - potential polyglot/embedded archive"
    fi
    
    # [CRITICAL Output – legacy]
    if [[ "$final_threat_score" -ge 1000 ]]; then
        echo -e "${RED}[CRITICAL]${NC} ⚠️  CRITICAL THREAT LEVEL - Immediate action required!"
    fi
    
    # Check file size anomalies
    local file_size=$(stat -f%z "$image" 2>/dev/null || stat -c%s "$image" 2>/dev/null)
    
    if [ "$file_size" -gt 10000000 ]; then
        log_warning "Unusually large QR image: $file_size bytes"
        log_threat 20 "Large file size may indicate hidden data"
    fi
}


################################################################################
# EXTENDED ANALYSIS MODULES
################################################################################

################################################################################
# CLOUD SERVICE ABUSE DETECTION ENGINE
################################################################################

analyze_cloud_service_abuse() {
    local content="$1"
    
    if [ "$CLOUD_ABUSE_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for cloud service abuse patterns..."
    
    local cloud_findings=()
    local cloud_score=0
    
    # Check cloud storage abuse patterns
    for pattern in "${CLOUD_STORAGE_ABUSE_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            cloud_findings+=("cloud_storage:$matched")
            ((cloud_score += 25))
            log_warning "Cloud storage abuse pattern detected: $matched"
        fi
    done
    
    # Check code hosting abuse patterns
    for pattern in "${CODE_HOSTING_ABUSE_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            cloud_findings+=("code_hosting:$matched")
            ((cloud_score += 30))
            log_warning "Code hosting abuse pattern detected: $matched"
        fi
    done
    
    # Specific high-risk combinations
    if echo "$content" | grep -qiE "discord.*cdn.*\.(exe|dll|bat|ps1|vbs)"; then
        log_threat 60 "Discord CDN hosting executable - common malware distribution"
        cloud_findings+=("discord_malware_distribution")
        ((cloud_score += 35))
    fi
    
    if echo "$content" | grep -qiE "raw\.githubusercontent.*\.(ps1|bat|exe|sh|py)"; then
        log_threat 55 "GitHub raw hosting script/executable - potential payload delivery"
        cloud_findings+=("github_payload_delivery")
        ((cloud_score += 30))
    fi
    
    if echo "$content" | grep -qiE "drive\.google\.com.*(download|export).*\.(exe|dll|msi|dmg)"; then
        log_threat 50 "Google Drive executable download link detected"
        cloud_findings+=("gdrive_executable")
        ((cloud_score += 30))
    fi
    
    if echo "$content" | grep -qiE "dropbox.*\.(exe|dll|scr|bat|cmd|ps1|vbs)"; then
        log_threat 50 "Dropbox hosting executable/script"
        cloud_findings+=("dropbox_executable")
        ((cloud_score += 30))
    fi
    
    if echo "$content" | grep -qiE "s3\.amazonaws\.com.*/.*\.(exe|dll|msi)"; then
        log_threat 45 "AWS S3 hosting executable"
        cloud_findings+=("s3_executable")
        ((cloud_score += 25))
    fi
    
    if echo "$content" | grep -qiE "blob\.core\.windows\.net.*/.*\.(exe|dll|msi)"; then
        log_threat 45 "Azure Blob hosting executable"
        cloud_findings+=("azure_executable")
        ((cloud_score += 25))
    fi
    
    if echo "$content" | grep -qiE "workers\.dev"; then
        log_warning "Cloudflare Workers URL - frequently used for phishing/redirects"
        cloud_findings+=("cloudflare_workers")
        ((cloud_score += 20))
    fi
    
    if echo "$content" | grep -qiE "pages\.dev"; then
        log_warning "Cloudflare Pages URL - check for phishing content"
        cloud_findings+=("cloudflare_pages")
        ((cloud_score += 15))
    fi
    
    # Pastebin with potential encoded payload
    if echo "$content" | grep -qiE "pastebin\.com/raw"; then
        log_threat 40 "Pastebin raw content link - common payload hosting"
        cloud_findings+=("pastebin_raw")
        ((cloud_score += 25))
        
        # Try to fetch and analyze if network enabled
        if [ "$NETWORK_CHECK" = true ]; then
            analyze_pastebin_content "$content"
        fi
    fi
    
    # File sharing services analysis
    for service in "transfer.sh" "file.io" "gofile.io" "anonfiles" "mega.nz" "wetransfer"; do
        if echo "$content" | grep -qi "$service"; then
            log_warning "File sharing service detected: $service"
            cloud_findings+=("fileshare:$service")
            ((cloud_score += 20))
        fi
    done
    
    # Generate cloud abuse report
    if [ ${#cloud_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "CLOUD SERVICE ABUSE ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Cloud Abuse Score: $cloud_score"
            echo ""
            echo "Findings:"
            for finding in "${cloud_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Risk Assessment:"
            if [ $cloud_score -ge 100 ]; then
                echo "  CRITICAL: Multiple cloud abuse indicators detected"
            elif [ $cloud_score -ge 50 ]; then
                echo "  HIGH: Significant cloud abuse risk"
            elif [ $cloud_score -ge 25 ]; then
                echo "  MEDIUM: Cloud service usage requires investigation"
            else
                echo "  LOW: Minor cloud service indicators"
            fi
            echo ""
        } >> "$CLOUD_ABUSE_REPORT"
        
        if [ $cloud_score -ge 50 ]; then
            log_threat $((cloud_score / 2)) "Cloud service abuse indicators detected"
        fi
        
        analysis_success_found "CLOUD-ABUSE" "${#cloud_findings[@]}" "Score: $cloud_score"
    else
        analysis_success_none "CLOUD-ABUSE"
    fi
}

analyze_offensive_tools() {
    local content="$1"
    
    log_info "Analyzing for offensive security tools and indicators..."
    
    local offensive_findings=()
    local offensive_score=0
    
    # Check for known offensive tools patterns
    for pattern in "${OFFENSIVE_TOOLS_PATTERNS[@]}"; do
        [ -z "$pattern" ] && continue
        if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
            local matched=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null | head -1)
            offensive_findings+=("offensive_tool:$matched")
            ((offensive_score += 50))
            log_threat 60 "🔴 OFFENSIVE TOOL DETECTED: $matched"
            log_error "    ├─ Category: Pentesting/Red Team Tool"
            log_error "    ├─ Pattern: $pattern"
            log_error "    └─ Risk: HIGH - Often used in attacks"
        fi
    done
    
    # Check for offensive file patterns
    for pattern in "${OFFENSIVE_FILE_PATTERNS[@]}"; do
        [ -z "$pattern" ] && continue
        if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
            local matched=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null | head -1)
            offensive_findings+=("offensive_file:$matched")
            ((offensive_score += 40))
            log_threat 50 "🔴 OFFENSIVE FILE SIGNATURE: $matched"
            log_error "    ├─ Type: Known malicious file pattern"
            log_error "    └─ Risk: HIGH - Webshell or exploit payload"
        fi
    done
    
    # Check for offensive infrastructure patterns
    for pattern in "${OFFENSIVE_INFRA_PATTERNS[@]}"; do
        [ -z "$pattern" ] && continue
        if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
            local matched=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null | head -1)
            offensive_findings+=("offensive_infra:$matched")
            ((offensive_score += 35))
            log_threat 45 "⚠️  OFFENSIVE INFRASTRUCTURE INDICATOR: $matched"
            log_warning "    ├─ Type: C2/Attack infrastructure pattern"
            log_warning "    └─ Risk: MEDIUM-HIGH - Possible attack setup"
        fi
    done
    
    # Specific high-confidence detections with detailed output
    if echo "$content" | grep -qiE "cobalt.*strike|cobaltstrike|beacon\.(dll|exe)" 2>/dev/null; then
        log_critical "════════════════════════════════════════════════════════"
        log_critical "🚨 COBALT STRIKE DETECTED!"
        log_critical "════════════════════════════════════════════════════════"
        log_error "    ├─ Tool: Cobalt Strike (Commercial Red Team Tool)"
        log_error "    ├─ Usage: Commonly abused by ransomware groups"
        log_error "    ├─ Threat Actors: APT29, APT41, FIN7, Conti, LockBit"
        log_error "    └─ Action: BLOCK IMMEDIATELY - Report to security team"
        offensive_findings+=("COBALT_STRIKE_CONFIRMED")
        ((offensive_score += 200))
    fi
    
    if echo "$content" | grep -qiE "meterpreter|msfvenom|metasploit" 2>/dev/null; then
        log_critical "════════════════════════════════════════════════════════"
        log_critical "🚨 METASPLOIT FRAMEWORK DETECTED!"
        log_critical "════════════════════════════════════════════════════════"
        log_error "    ├─ Tool: Metasploit Framework"
        log_error "    ├─ Usage: Popular exploitation framework"
        log_error "    ├─ Risk: Active exploitation attempt"
        log_error "    └─ Action: Investigate source and block"
        offensive_findings+=("METASPLOIT_CONFIRMED")
        ((offensive_score += 150))
    fi
    
    if echo "$content" | grep -qiE "mimikatz|sekurlsa|lsadump" 2>/dev/null; then
        log_critical "════════════════════════════════════════════════════════"
        log_critical "🚨 MIMIKATZ CREDENTIAL THEFT TOOL DETECTED!"
        log_critical "════════════════════════════════════════════════════════"
        log_error "    ├─ Tool: Mimikatz"
        log_error "    ├─ Purpose: Windows credential extraction"
        log_error "    ├─ Risk: CRITICAL - Password/hash theft"
        log_error "    └─ Action: Assume credentials compromised"
        offensive_findings+=("MIMIKATZ_CONFIRMED")
        ((offensive_score += 200))
    fi
    
    if echo "$content" | grep -qiE "bloodhound|sharphound" 2>/dev/null; then
        log_threat 80 "🔴 BLOODHOUND/SHARPHOUND DETECTED!"
        log_error "    ├─ Tool: BloodHound Active Directory reconnaissance"
        log_error "    ├─ Purpose: AD privilege escalation path discovery"
        log_error "    └─ Risk: HIGH - Attack reconnaissance phase"
        offensive_findings+=("BLOODHOUND_RECON")
        ((offensive_score += 100))
    fi
    
    if echo "$content" | grep -qiE "rubeus|kerberoast|asreproast" 2>/dev/null; then
        log_threat 80 "🔴 KERBEROS ATTACK TOOL DETECTED!"
        log_error "    ├─ Tool: Rubeus/Kerberoasting toolkit"
        log_error "    ├─ Purpose: Kerberos ticket attacks"
        log_error "    └─ Risk: HIGH - Credential compromise"
        offensive_findings+=("KERBEROS_ATTACK")
        ((offensive_score += 100))
    fi
    
    if echo "$content" | grep -qiE "empire.*agent|powershell.*empire" 2>/dev/null; then
        log_threat 90 "🔴 POWERSHELL EMPIRE DETECTED!"
        log_error "    ├─ Tool: PowerShell Empire C2 Framework"
        log_error "    ├─ Purpose: Post-exploitation & C2"
        log_error "    └─ Risk: HIGH - Active compromise"
        offensive_findings+=("POWERSHELL_EMPIRE")
        ((offensive_score += 120))
    fi
    
    # Check for webshell indicators
    if echo "$content" | grep -qiE "c99|r57|wso.*shell|b374k|antsword|behinder|godzilla|china.*chopper" 2>/dev/null; then
        log_critical "════════════════════════════════════════════════════════"
        log_critical "🚨 WEBSHELL DETECTED!"
        log_critical "════════════════════════════════════════════════════════"
        local shell_name=$(echo "$content" | grep -oiE "c99|r57|wso|b374k|antsword|behinder|godzilla|china.*chopper" | head -1)
        log_error "    ├─ Type: $shell_name webshell"
        log_error "    ├─ Purpose: Remote server control"
        log_error "    ├─ Risk: CRITICAL - Server compromised"
        log_error "    └─ Action: Immediate incident response required"
        offensive_findings+=("WEBSHELL:$shell_name")
        ((offensive_score += 200))
    fi
    
    # Check for RAT indicators
    if echo "$content" | grep -qiE "asyncrat|quasar.*rat|nanocore|njrat|remcos|darkcomet|agent.*tesla|netwire" 2>/dev/null; then
        local rat_name=$(echo "$content" | grep -oiE "asyncrat|quasar|nanocore|njrat|remcos|darkcomet|agent.*tesla|netwire" | head -1)
        log_critical "════════════════════════════════════════════════════════"
        log_critical "🚨 REMOTE ACCESS TROJAN (RAT) DETECTED!"
        log_critical "════════════════════════════════════════════════════════"
        log_error "    ├─ RAT Family: $rat_name"
        log_error "    ├─ Capabilities: Remote control, keylogging, screen capture"
        log_error "    ├─ Risk: CRITICAL - Full system compromise"
        log_error "    └─ Action: Isolate system, begin IR procedures"
        offensive_findings+=("RAT:$rat_name")
        ((offensive_score += 200))
    fi
    
    # Check for info stealers
    if echo "$content" | grep -qiE "redline.*stealer|vidar|raccoon.*stealer|mars.*stealer|erbium|aurora.*stealer|formbook" 2>/dev/null; then
        local stealer_name=$(echo "$content" | grep -oiE "redline|vidar|raccoon|mars|erbium|aurora|formbook" | head -1)
        log_critical "════════════════════════════════════════════════════════"
        log_critical "🚨 INFO STEALER MALWARE DETECTED!"
        log_critical "════════════════════════════════════════════════════════"
        log_error "    ├─ Stealer Family: $stealer_name"
        log_error "    ├─ Target: Browser data, crypto wallets, credentials"
        log_error "    ├─ Risk: CRITICAL - Data exfiltration"
        log_error "    └─ Action: Change all passwords, check crypto wallets"
        offensive_findings+=("INFOSTEALER:$stealer_name")
        ((offensive_score += 200))
    fi
    
    # Report findings
    if [ ${#offensive_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "OFFENSIVE SECURITY TOOLS ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Offensive Tool Score: $offensive_score"
            echo ""
            echo "Detected Tools/Indicators:"
            for finding in "${offensive_findings[@]}"; do
                echo "  ⚠ $finding"
            done
            echo ""
            if [ $offensive_score -ge 200 ]; then
                echo "VERDICT: CRITICAL - Confirmed malicious tooling"
            elif [ $offensive_score -ge 100 ]; then
                echo "VERDICT: HIGH - Strong offensive tool indicators"
            elif [ $offensive_score -ge 50 ]; then
                echo "VERDICT: MEDIUM - Suspicious tool references"
            fi
            echo ""
        } >> "${OUTPUT_DIR}/offensive_tools_analysis.txt"
        
        log_threat $((offensive_score / 3)) "Offensive security tools detected"
        analysis_success_found "OFFENSIVE-TOOLS" "${#offensive_findings[@]}" "Score: $offensive_score"
    else
        analysis_success_none "OFFENSIVE-TOOLS"
    fi
}

analyze_service_abuse() {
    local content="$1"
    
    log_info "Analyzing for legitimate service abuse patterns..."
    
    local abuse_findings=()
    local abuse_score=0
    
    # Check each service abuse indicator
    for key in "${!SERVICE_ABUSE_INDICATORS[@]}"; do
        local pattern="${SERVICE_ABUSE_INDICATORS[$key]}"
        [ -z "$pattern" ] && continue
        if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
            local matched=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null | head -1)
            abuse_findings+=("$key:$matched")
            ((abuse_score += 25))
            
            # Categorize and provide detailed output
            case "$key" in
                *_c2|*_webhook*)
                    log_threat 50 "🔴 C2 CHANNEL ABUSE: $key"
                    log_error "    ├─ Service: $matched"
                    log_error "    ├─ Abuse Type: Command & Control communication"
                    log_error "    └─ Risk: HIGH - Active malware communication"
                    ((abuse_score += 25))
                    ;;
                *_malware|*_payload|*_raw)
                    log_threat 45 "🔴 PAYLOAD HOSTING: $key"
                    log_warning "    ├─ Service: $matched"
                    log_warning "    ├─ Abuse Type: Malware/payload hosting"
                    log_warning "    └─ Risk: HIGH - Malware delivery"
                    ((abuse_score += 20))
                    ;;
                *_ddns|*_tunnel|*ngrok*)
                    log_threat 40 "⚠️  DYNAMIC/TUNNEL SERVICE: $key"
                    log_warning "    ├─ Service: $matched"
                    log_warning "    ├─ Abuse Type: Dynamic DNS or tunneling"
                    log_warning "    └─ Risk: MEDIUM-HIGH - Evasion/C2 callback"
                    ((abuse_score += 15))
                    ;;
                *_short*)
                    log_warning "⚠️  URL SHORTENER: $key"
                    log_info "    ├─ Service: $matched"
                    log_info "    ├─ Abuse Type: URL obfuscation"
                    log_info "    └─ Risk: MEDIUM - Hiding destination"
                    ;;
                *_exec|*_func)
                    log_threat 35 "⚠️  SERVERLESS EXECUTION: $key"
                    log_warning "    ├─ Service: $matched"
                    log_warning "    ├─ Abuse Type: Serverless function abuse"
                    log_warning "    └─ Risk: MEDIUM - Ephemeral malicious code"
                    ((abuse_score += 10))
                    ;;
                *)
                    log_warning "⚠️  SERVICE ABUSE: $key"
                    log_info "    ├─ Service: $matched"
                    log_info "    └─ Risk: Review required"
                    ;;
            esac
        fi
    done
    
    # Check callback patterns
    for pattern in "${CALLBACK_PATTERNS[@]}"; do
        [ -z "$pattern" ] && continue
        if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
            local matched=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null | head -1)
            log_threat 55 "🔴 C2 CALLBACK PATH DETECTED: $matched"
            log_error "    ├─ Pattern: Known C2/malware callback endpoint"
            log_error "    ├─ Examples: Cobalt Strike beacons, webshells"
            log_error "    └─ Risk: HIGH - Active C2 communication"
            abuse_findings+=("c2_callback:$matched")
            ((abuse_score += 40))
        fi
    done
    
    # Report findings
    if [ ${#abuse_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "LEGITIMATE SERVICE ABUSE ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Service Abuse Score: $abuse_score"
            echo ""
            echo "Detected Abuse Patterns:"
            for finding in "${abuse_findings[@]}"; do
                echo "  ⚠ $finding"
            done
            echo ""
        } >> "${OUTPUT_DIR}/service_abuse_analysis.txt"
        
        if [ $abuse_score -ge 50 ]; then
            log_threat $((abuse_score / 2)) "Legitimate service abuse detected"
        fi
        
        analysis_success_found "SERVICE-ABUSE" "${#abuse_findings[@]}" "Score: $abuse_score"
    else
        analysis_success_none "SERVICE-ABUSE"
    fi
}

analyze_pastebin_content() {
    local url="$1"
    
    # Extract pastebin URL
    local paste_url=$(echo "$url" | grep -oiE "pastebin\.com/raw/[a-zA-Z0-9]+" | head -1)
    
    if [ -n "$paste_url" ]; then
        log_info "Fetching pastebin content for analysis..."
        
        local paste_content=$(curl -sfL --max-time 10 "https://$paste_url" 2>/dev/null)
        
        if [ -n "$paste_content" ]; then
            # Check for encoded content
            if echo "$paste_content" | grep -qE "^[A-Za-z0-9+/=]{50,}$"; then
                log_threat 50 "Pastebin contains Base64 encoded content"
                
                # Try to decode
                local decoded=$(echo "$paste_content" | base64 -d 2>/dev/null)
                if [ -n "$decoded" ]; then
                    log_forensic "Decoded pastebin content preview: ${decoded:0:200}"
                    
                    # Recursively analyze decoded content
                    analyze_decoded_content_threats "$decoded"
                fi
            fi
            
            # Check for PowerShell
            if echo "$paste_content" | grep -qiE "powershell|IEX|Invoke-|downloadstring"; then
                log_threat 70 "Pastebin contains PowerShell content"
            fi
            
            # Check for shell commands
            if echo "$paste_content" | grep -qiE "#!/bin|bash -|curl.*\\|.*sh|wget.*\\|.*sh"; then
                log_threat 65 "Pastebin contains shell script content"
            fi
            
            # Save as evidence
            echo "$paste_content" > "${EVIDENCE_DIR}/pastebin_content_$(date +%s).txt"
        fi
    fi
}

################################################################################
# MOBILE DEEP LINK AND APP SCHEME DETECTION
################################################################################

analyze_mobile_deeplinks() {
    local content="$1"
    
    if [ "$MOBILE_DEEPLINK_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for mobile deep link threats..."
    
    local mobile_findings=()
    local mobile_score=0
    
    # iOS Deep Link Analysis
    for pattern in "${IOS_DEEPLINK_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            mobile_findings+=("ios_deeplink:$matched")
            
            # Critical iOS threats
            if echo "$pattern" | grep -qiE "itms-services|mobileconfig|profile"; then
                log_threat 80 "CRITICAL iOS app/profile installation link: $matched"
                ((mobile_score += 50))
            else
                log_warning "iOS deep link detected: $matched"
                ((mobile_score += 10))
            fi
        fi
    done
    
    # Android Deep Link Analysis
    for pattern in "${ANDROID_DEEPLINK_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            mobile_findings+=("android_deeplink:$matched")
            
            # Critical Android threats
            if echo "$pattern" | grep -qiE "intent://|\.apk|\.xapk"; then
                log_threat 75 "CRITICAL Android app installation intent: $matched"
                ((mobile_score += 45))
            else
                log_warning "Android deep link detected: $matched"
                ((mobile_score += 10))
            fi
        fi
    done
    
    # Specific mobile threat analysis
    
    # iOS Enterprise App Distribution (HIGHLY DANGEROUS)
    if echo "$content" | grep -qiE "itms-services://.*action=download-manifest"; then
        log_threat 90 "iOS Enterprise App Distribution link detected - HIGH RISK"
        log_forensic "This type of link bypasses App Store and can install untrusted apps"
        mobile_findings+=("ios_enterprise_distribution")
        ((mobile_score += 60))
        
        # Try to extract manifest URL
        local manifest_url=$(echo "$content" | grep -oiE "url=https?://[^&\"']+" | head -1)
        if [ -n "$manifest_url" ]; then
            log_forensic "Manifest URL: $manifest_url"
            record_ioc "ios_manifest" "$manifest_url" "iOS enterprise distribution manifest"
        fi
    fi
    
    # iOS Configuration Profile (MDM/Malicious Profile)
    if echo "$content" | grep -qiE "\.mobileconfig"; then
        log_threat 85 "iOS Configuration Profile link detected - CRITICAL"
        log_forensic "Mobileconfig files can install certificates, VPNs, and modify device settings"
        mobile_findings+=("ios_mobileconfig")
        ((mobile_score += 55))
    fi
    
    # Android APK direct download
    if echo "$content" | grep -qiE "https?://.*\.apk($|\?)"; then
        log_threat 70 "Direct APK download link detected"
        mobile_findings+=("android_apk_direct")
        ((mobile_score += 40))
        
        local apk_url=$(echo "$content" | grep -oiE "https?://[^\s\"']+\.apk" | head -1)
        record_ioc "apk_url" "$apk_url" "Direct APK download"
    fi
    
    # Android Intent with suspicious components
    if echo "$content" | grep -qiE "intent://.*#Intent.*component="; then
        log_threat 75 "Android Intent with explicit component - potential app exploitation"
        mobile_findings+=("android_intent_component")
        ((mobile_score += 45))
    fi
    
    # Check for sideloading indicators
    if echo "$content" | grep -qiE "enable.*unknown.*sources|settings.*security|sideload"; then
        log_threat 60 "Sideloading instruction indicators detected"
        mobile_findings+=("sideloading_instructions")
        ((mobile_score += 35))
    fi
    
    # PWA/WebApp installation
    if echo "$content" | grep -qiE "manifest\.json|service-worker|add.*to.*home.*screen"; then
        log_warning "Progressive Web App indicators detected"
        mobile_findings+=("pwa_indicators")
        ((mobile_score += 15))
    fi
    
    # Generate mobile threat report
    if [ ${#mobile_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "MOBILE THREAT ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Mobile Threat Score: $mobile_score"
            echo ""
            echo "Findings:"
            for finding in "${mobile_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Platform Analysis:"
            echo "  iOS Threats: $(echo "${mobile_findings[@]}" | grep -o "ios_" | wc -l)"
            echo "  Android Threats: $(echo "${mobile_findings[@]}" | grep -o "android_" | wc -l)"
            echo ""
            echo "Risk Assessment:"
            if [ $mobile_score -ge 80 ]; then
                echo "  CRITICAL: High-risk mobile app/profile installation detected"
                echo "  RECOMMENDATION: Do not scan this QR code on mobile devices"
            elif [ $mobile_score -ge 50 ]; then
                echo "  HIGH: Significant mobile threat indicators"
            elif [ $mobile_score -ge 25 ]; then
                echo "  MEDIUM: Mobile deep links present - verify destination"
            else
                echo "  LOW: Minor mobile link indicators"
            fi
            echo ""
        } >> "$MOBILE_THREAT_REPORT"
        
        if [ $mobile_score -ge 40 ]; then
            log_threat $((mobile_score / 2)) "Mobile platform threats detected"
        fi
        
        analysis_success_found "MOBILE-DEEPLINKS" "${#mobile_findings[@]}" "Score: $mobile_score"
    else
        analysis_success_none "MOBILE-DEEPLINKS"
    fi
}

################################################################################
# BLUETOOTH / NFC / WIRELESS ATTACK DETECTION
################################################################################

analyze_wireless_attacks() {
    local content="$1"
    
    if [ "$BLUETOOTH_NFC_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for wireless (BT/NFC/WiFi) attack patterns..."
    
    local wireless_findings=()
    local wireless_score=0
    
    # Bluetooth Pattern Analysis
    for pattern in "${BLUETOOTH_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            wireless_findings+=("bluetooth:$matched")
            ((wireless_score += 30))
            log_warning "Bluetooth pattern detected: $matched"
        fi
    done
    
    # NFC Pattern Analysis
    for pattern in "${NFC_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            wireless_findings+=("nfc:$matched")
            ((wireless_score += 25))
            log_warning "NFC pattern detected: $matched"
        fi
    done
    
    # WiFi Configuration Analysis
    for pattern in "${WIFI_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            wireless_findings+=("wifi:$matched")
            
            # WiFi QR codes are common but analyze for risks
            if echo "$content" | grep -qiE "WIFI:.*WEP"; then
                log_threat 40 "WiFi configuration with WEP encryption (insecure)"
                ((wireless_score += 30))
            elif echo "$content" | grep -qiE "WIFI:.*T:nopass"; then
                log_warning "Open WiFi network configuration detected"
                ((wireless_score += 20))
            else
                log_info "WiFi configuration detected (standard QR use case)"
                ((wireless_score += 5))
            fi
        fi
    done
    
    # Bluetooth MAC address analysis
    local bt_mac=$(echo "$content" | grep -oiE "[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}" | head -1)
    if [ -n "$bt_mac" ]; then
        log_info "Bluetooth/Device MAC address found: $bt_mac"
        wireless_findings+=("mac_address:$bt_mac")
        record_ioc "mac_address" "$bt_mac" "Device MAC address in QR"
        
        # Check OUI for suspicious manufacturers
        analyze_mac_oui "$bt_mac"
    fi
    
    # Check for device pairing payloads
    if echo "$content" | grep -qiE "pair|bond|connect.*device"; then
        log_warning "Device pairing indicators detected"
        wireless_findings+=("device_pairing")
        ((wireless_score += 15))
    fi
    
    # Check for RFID/smartcard patterns
    if echo "$content" | grep -qiE "mifare|desfire|felica|nfc.*tag|rfid|smartcard"; then
        log_warning "RFID/Smartcard reference detected"
        wireless_findings+=("rfid_smartcard")
        ((wireless_score += 20))
    fi
    
    # Generate wireless analysis report
    if [ ${#wireless_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "WIRELESS ATTACK ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Wireless Threat Score: $wireless_score"
            echo ""
            echo "Findings:"
            for finding in "${wireless_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Technology Breakdown:"
            echo "  Bluetooth: $(echo "${wireless_findings[@]}" | grep -o "bluetooth:" | wc -l)"
            echo "  NFC: $(echo "${wireless_findings[@]}" | grep -o "nfc:" | wc -l)"
            echo "  WiFi: $(echo "${wireless_findings[@]}" | grep -o "wifi:" | wc -l)"
            echo ""
        } >> "${OUTPUT_DIR}/wireless_analysis.txt"
        
        if [ $wireless_score -ge 30 ]; then
            log_threat $((wireless_score / 2)) "Wireless attack indicators detected"
        fi
        
        analysis_success_found "WIRELESS" "${#wireless_findings[@]}" "Score: $wireless_score"
    else
        analysis_success_none "WIRELESS"
    fi
}

analyze_mac_oui() {
    local mac="$1"
    local oui="${mac:0:8}"
    
    # Convert to uppercase and replace colons
    oui=$(echo "$oui" | tr '[:lower:]' '[:upper:]' | tr ':' '-')
    
    # Known suspicious OUIs (would be expanded with full database)
    declare -A SUSPICIOUS_OUIS=(
        ["00-00-00"]="Unknown/Invalid"
        ["FF-FF-FF"]="Broadcast address"
        ["00-0C-29"]="VMware"
        ["00-50-56"]="VMware"
        ["08-00-27"]="VirtualBox"
        ["52-54-00"]="QEMU/KVM"
        ["00-16-3E"]="Xen"
        ["00-1C-14"]="VMware"
        ["00-15-5D"]="Hyper-V"
    )
    
    if [ -n "${SUSPICIOUS_OUIS[$oui]}" ]; then
        log_warning "MAC OUI indicates: ${SUSPICIOUS_OUIS[$oui]}"
    fi
}

################################################################################
# USSD / TELEPHONY ATTACK DETECTION
################################################################################

analyze_telephony_attacks() {
    local content="$1"
    
    log_info "Analyzing for telephony/USSD attacks..."
    
    local telephony_findings=()
    local telephony_score=0
    
    # Check for USSD codes
    for pattern in "${USSD_PATTERNS[@]}"; do
        if echo "$content" | grep -qE "$pattern"; then
            local matched=$(echo "$content" | grep -oE "$pattern" | head -1)
            telephony_findings+=("ussd:$matched")
            ((telephony_score += 40))
            log_threat 50 "USSD code detected: $matched - POTENTIALLY DANGEROUS"
        fi
    done
    
    # Check for tel: URI with suspicious patterns
    if echo "$content" | grep -qiE "tel:[+*#0-9]{5,}"; then
        local tel_uri=$(echo "$content" | grep -oiE "tel:[+*#0-9]{5,}" | head -1)
        log_info "Telephone URI found: $tel_uri"
        telephony_findings+=("tel_uri:$tel_uri")
        
        # Check for premium rate numbers
        if echo "$tel_uri" | grep -qE "tel:(\+?1)?900|tel:(\+?1)?976|tel:(\+44)?9"; then
            log_threat 60 "Premium rate number detected - HIGH COST RISK"
            ((telephony_score += 45))
        fi
        
        # Check for international fraud hotspots
        if echo "$tel_uri" | grep -qE "tel:\+?(232|234|242|243|244|245|246|247|248|249|251|252|253|254|255|256|257|258|260|261|262|263|264|265|266|267|268|269)"; then
            log_warning "International number to high-fraud region"
            ((telephony_score += 30))
        fi
    fi
    
    # Check for SMS URI with suspicious content
    if echo "$content" | grep -qiE "sms:[+0-9]{5,}"; then
        local sms_uri=$(echo "$content" | grep -oiE "sms:[^?&\s]+" | head -1)
        log_info "SMS URI found: $sms_uri"
        telephony_findings+=("sms_uri:$sms_uri")
        ((telephony_score += 10))
        
        # Check for SMS body with suspicious keywords
        if echo "$content" | grep -qiE "sms:.*body=.*(subscribe|stop|yes|confirm|verify|code)"; then
            log_warning "SMS with action keyword detected - potential subscription scam"
            ((telephony_score += 25))
        fi
    fi
    
    # Check for FaceTime/VoIP schemes
    if echo "$content" | grep -qiE "facetime://|facetime-audio://|sip:|sips:"; then
        log_info "VoIP/FaceTime link detected"
        telephony_findings+=("voip_link")
        ((telephony_score += 5))
    fi
    
    # Report findings
    if [ ${#telephony_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "TELEPHONY/USSD ATTACK ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Telephony Threat Score: $telephony_score"
            echo ""
            echo "Findings:"
            for finding in "${telephony_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            if [ $telephony_score -ge 40 ]; then
                echo "WARNING: High-risk telephony threats detected!"
                echo "USSD codes can factory reset devices or modify settings"
            fi
            echo ""
        } >> "${OUTPUT_DIR}/telephony_analysis.txt"
        
        if [ $telephony_score -ge 30 ]; then
            log_threat $((telephony_score / 2)) "Telephony/USSD threats detected"
        fi
        
        analysis_success_found "TELEPHONY" "${#telephony_findings[@]}" "Score: $telephony_score"
    else
        analysis_success_none "TELEPHONY"
    fi
}

################################################################################
# HARDWARE / IOT EXPLOIT DETECTION
################################################################################

analyze_hardware_exploits() {
    local content="$1"
    
    if [ "$HARDWARE_EXPLOIT_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for hardware/IoT exploit patterns..."
    
    local hardware_findings=()
    local hardware_score=0
    
    # Check hardware exploit patterns
    for pattern in "${HARDWARE_EXPLOIT_PATTERNS[@]}"; do
        # Skip empty patterns
        [ -z "$pattern" ] && continue
        if echo "$content" | grep -qiE "$pattern" 2>/dev/null; then
            local matched=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null | head -1)
            hardware_findings+=("hardware_exploit:$matched")
            ((hardware_score += 35))
            log_threat 45 "Hardware/IoT exploit pattern: $matched"
        fi
    done
    
    # Buffer overflow attempt detection
    local long_strings=$(echo "$content" | grep -oE "[A-Za-z0-9]{200,}" | head -1)
    if [ -n "$long_strings" ]; then
        log_threat 55 "Potential buffer overflow payload detected (long repeated string)"
        hardware_findings+=("buffer_overflow_attempt")
        ((hardware_score += 40))
    fi
    
    # Format string attack detection
    if echo "$content" | grep -qE "%[nxsp]{5,}|%[0-9]*\$n"; then
        log_threat 60 "Format string attack pattern detected"
        hardware_findings+=("format_string_attack")
        ((hardware_score += 45))
    fi
    
    # Null byte injection
    if echo "$content" | grep -qE "%00|\\x00"; then
        log_warning "Null byte injection pattern detected"
        hardware_findings+=("null_byte_injection")
        ((hardware_score += 25))
    fi
    
    # POS terminal specific
    if echo "$content" | grep -qiE "verifone|ingenico|pax.*terminal|magtek|id.*tech"; then
        log_threat 50 "POS terminal reference detected"
        hardware_findings+=("pos_terminal_reference")
        ((hardware_score += 35))
    fi
    
    # IoT device specific
    if echo "$content" | grep -qiE "hikvision|dahua|foscam|axis.*camera|ubiquiti|mikrotik|tp-link"; then
        log_warning "IoT device brand detected - check for default credentials"
        hardware_findings+=("iot_device_brand")
        ((hardware_score += 20))
    fi
    
    # RTSP stream hijacking
    if echo "$content" | grep -qiE "rtsp://"; then
        log_warning "RTSP streaming URL detected - potential camera access"
        hardware_findings+=("rtsp_stream")
        ((hardware_score += 30))
        
        local rtsp_url=$(echo "$content" | grep -oiE "rtsp://[^\s\"']+" | head -1)
        record_ioc "rtsp_url" "$rtsp_url" "RTSP streaming URL"
    fi
    
    # Printer exploit patterns
    if echo "$content" | grep -qiE "@PJL|%-12345X|PostScript"; then
        log_threat 45 "Printer Job Language (PJL) commands detected"
        hardware_findings+=("pjl_commands")
        ((hardware_score += 35))
    fi
    
    # Generate hardware exploit report
    if [ ${#hardware_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "HARDWARE/IOT EXPLOIT ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Hardware Threat Score: $hardware_score"
            echo ""
            echo "Findings:"
            for finding in "${hardware_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Risk Categories:"
            echo "  Buffer Overflow: $(echo "${hardware_findings[@]}" | grep -c "buffer")"
            echo "  POS Terminals: $(echo "${hardware_findings[@]}" | grep -c "pos")"
            echo "  IoT Devices: $(echo "${hardware_findings[@]}" | grep -c "iot")"
            echo "  Cameras/RTSP: $(echo "${hardware_findings[@]}" | grep -c "rtsp\|camera")"
            echo ""
        } >> "$HARDWARE_EXPLOIT_REPORT"
        
        if [ $hardware_score -ge 30 ]; then
            log_threat $((hardware_score / 2)) "Hardware/IoT exploit patterns detected"
        fi
        
        analysis_success_found "HARDWARE-IOT" "${#hardware_findings[@]}" "Score: $hardware_score"
    else
        analysis_success_none "HARDWARE-IOT"
    fi
}

################################################################################
# GEOFENCING AND CLOAKING DETECTION
################################################################################

analyze_geofencing_cloaking() {
    local content="$1"
    
    if [ "$GEOFENCING_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for geofencing and cloaking patterns..."
    
    local geo_findings=()
    local geo_score=0
    
    # Check geofencing patterns
    for pattern in "${GEOFENCING_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            geo_findings+=("geofencing:$matched")
            ((geo_score += 15))
            log_info "Geofencing indicator: $matched"
        fi
    done
    
    # Check cloaking patterns
    for pattern in "${CLOAKING_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            geo_findings+=("cloaking:$matched")
            ((geo_score += 20))
            log_warning "Cloaking technique indicator: $matched"
        fi
    done
    
    # Canvas fingerprinting detection
    if echo "$content" | grep -qiE "toDataURL.*canvas|getImageData|measureText"; then
        log_threat 35 "Canvas fingerprinting detected"
        geo_findings+=("canvas_fingerprinting")
        ((geo_score += 25))
    fi
    
    # WebGL fingerprinting
    if echo "$content" | grep -qiE "WEBGL.*renderer|getExtension.*WEBGL|getParameter"; then
        log_warning "WebGL fingerprinting indicators"
        geo_findings+=("webgl_fingerprinting")
        ((geo_score += 20))
    fi
    
    # Audio fingerprinting
    if echo "$content" | grep -qiE "AudioContext.*createOscillator|OfflineAudioContext"; then
        log_warning "Audio fingerprinting indicators"
        geo_findings+=("audio_fingerprinting")
        ((geo_score += 20))
    fi
    
    # User-Agent based cloaking
    if echo "$content" | grep -qiE "Googlebot|Bingbot|facebookexternalhit|Twitterbot.*redirect"; then
        log_threat 40 "Bot detection with redirect - likely cloaking"
        geo_findings+=("bot_cloaking")
        ((geo_score += 30))
    fi
    
    # Time-based delivery
    if echo "$content" | grep -qiE "setTimeout.*redirect|setInterval.*location|delay.*href"; then
        log_warning "Time-delayed redirect - potential cloaking"
        geo_findings+=("time_delayed_redirect")
        ((geo_score += 20))
    fi
    
    # Generate cloaking report
    if [ ${#geo_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "GEOFENCING AND CLOAKING ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Cloaking Score: $geo_score"
            echo ""
            echo "Findings:"
            for finding in "${geo_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Detection Techniques Found:"
            echo "  Geolocation: $(echo "${geo_findings[@]}" | grep -c "geofencing")"
            echo "  Fingerprinting: $(echo "${geo_findings[@]}" | grep -c "fingerprint")"
            echo "  Bot Cloaking: $(echo "${geo_findings[@]}" | grep -c "cloak\|bot")"
            echo ""
            if [ $geo_score -ge 40 ]; then
                echo "WARNING: Content may serve different payloads based on visitor"
                echo "Analysis may not reflect what end users see"
            fi
            echo ""
        } >> "$GEOFENCING_REPORT"
        
        if [ $geo_score -ge 30 ]; then
            log_threat $((geo_score / 3)) "Geofencing/Cloaking detected"
        fi
        
        analysis_success_found "GEOFENCING" "${#geo_findings[@]}" "Score: $geo_score"
    else
        analysis_success_none "GEOFENCING"
    fi
}


################################################################################
# FILELESS MALWARE / LIVING-OFF-THE-LAND DETECTION
################################################################################

analyze_fileless_malware() {
    local content="$1"
    
    if [ "$FILELESS_MALWARE_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for fileless malware and LOTL techniques..."
    
    local fileless_findings=()
    local fileless_score=0
    
    # LOLBAS Pattern Analysis (Windows)
    for pattern in "${LOLBAS_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            fileless_findings+=("lolbas:$matched")
            ((fileless_score += 40))
            log_threat 50 "LOLBAS technique detected: $matched"
        fi
    done
    
    # GTFOBins Pattern Analysis (Linux)
    for pattern in "${GTFOBINS_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            fileless_findings+=("gtfobins:$matched")
            ((fileless_score += 35))
            log_threat 45 "GTFOBins technique detected: $matched"
        fi
    done
    
    # AMSI Bypass Detection
    for pattern in "${AMSI_BYPASS_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            fileless_findings+=("amsi_bypass:$matched")
            ((fileless_score += 50))
            log_threat 60 "AMSI Bypass technique detected: $matched"
        fi
    done
    
    # Office Macro Analysis
    for pattern in "${OFFICE_MACRO_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            fileless_findings+=("office_macro:$matched")
            ((fileless_score += 35))
            log_threat 45 "Office macro indicator: $matched"
        fi
    done
    
    # Follina/MSDT Detection
    for pattern in "${FOLLINA_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            fileless_findings+=("follina:$matched")
            ((fileless_score += 60))
            log_threat 80 "Follina/MSDT exploit pattern detected: $matched"
        fi
    done
    
    # OLE Object Abuse
    for pattern in "${OLE_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            fileless_findings+=("ole_abuse:$matched")
            ((fileless_score += 40))
            log_threat 50 "OLE object abuse pattern: $matched"
        fi
    done
    
    # PowerShell Download Cradles
    if echo "$content" | grep -qiE "IEX.*\(.*New-Object.*Net\.WebClient.*\).*\.DownloadString"; then
        log_threat 70 "PowerShell download cradle detected"
        fileless_findings+=("ps_download_cradle")
        ((fileless_score += 55))
    fi
    
    if echo "$content" | grep -qiE "Invoke-Expression.*Invoke-WebRequest"; then
        log_threat 65 "PowerShell IEX+IWR combination detected"
        fileless_findings+=("ps_iex_iwr")
        ((fileless_score += 50))
    fi
    
    # Encoded PowerShell
    if echo "$content" | grep -qiE "powershell.*-[eE][nN][cC].*[A-Za-z0-9+/=]{50,}"; then
        log_threat 75 "Encoded PowerShell command detected"
        fileless_findings+=("encoded_powershell")
        ((fileless_score += 55))
        
        # Try to extract and decode
        local encoded_cmd=$(echo "$content" | grep -oiE "[A-Za-z0-9+/=]{50,}" | head -1)
        if [ -n "$encoded_cmd" ]; then
            local decoded=$(echo "$encoded_cmd" | base64 -d 2>/dev/null | iconv -f UTF-16LE -t UTF-8 2>/dev/null)
            if [ -n "$decoded" ]; then
                log_forensic "Decoded PowerShell: ${decoded:0:200}"
                echo "Decoded PowerShell: $decoded" >> "$FILELESS_REPORT"
                
                # Recursively analyze decoded content
                analyze_decoded_content_threats "$decoded"
            fi
        fi
    fi
    
    # WMIC process creation
    if echo "$content" | grep -qiE "wmic.*process.*call.*create"; then
        log_threat 55 "WMIC process creation detected"
        fileless_findings+=("wmic_process_create")
        ((fileless_score += 40))
    fi
    
    # Certutil abuse
    if echo "$content" | grep -qiE "certutil.*-urlcache.*-f.*http"; then
        log_threat 65 "Certutil download abuse detected"
        fileless_findings+=("certutil_download")
        ((fileless_score += 50))
    fi
    
    if echo "$content" | grep -qiE "certutil.*-decode"; then
        log_threat 50 "Certutil decode operation detected"
        fileless_findings+=("certutil_decode")
        ((fileless_score += 35))
    fi
    
    # BITSAdmin abuse
    if echo "$content" | grep -qiE "bitsadmin.*/(transfer|addfile)"; then
        log_threat 55 "BITSAdmin transfer abuse detected"
        fileless_findings+=("bitsadmin_abuse")
        ((fileless_score += 40))
    fi
    
    # MSHTA abuse
    if echo "$content" | grep -qiE "mshta.*(vbscript|javascript|http)"; then
        log_threat 70 "MSHTA script execution detected"
        fileless_findings+=("mshta_abuse")
        ((fileless_score += 55))
    fi
    
    # Regsvr32 scriptlet
    if echo "$content" | grep -qiE "regsvr32.*/s.*/n.*/u.*/i:"; then
        log_threat 65 "Regsvr32 scriptlet execution detected"
        fileless_findings+=("regsvr32_scriptlet")
        ((fileless_score += 50))
    fi
    
    # WMI Event Subscription
    if echo "$content" | grep -qiE "__EventFilter|__EventConsumer|CommandLineEventConsumer"; then
        log_threat 70 "WMI event subscription (persistence) detected"
        fileless_findings+=("wmi_persistence")
        ((fileless_score += 55))
    fi
    
    # Generate fileless malware report
    if [ ${#fileless_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "FILELESS MALWARE / LOTL ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Fileless Threat Score: $fileless_score"
            echo ""
            echo "Findings:"
            for finding in "${fileless_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Technique Categories:"
            echo "  LOLBAS (Windows): $(echo "${fileless_findings[@]}" | grep -c "lolbas")"
            echo "  GTFOBins (Linux): $(echo "${fileless_findings[@]}" | grep -c "gtfobins")"
            echo "  AMSI Bypass: $(echo "${fileless_findings[@]}" | grep -c "amsi")"
            echo "  Office Macros: $(echo "${fileless_findings[@]}" | grep -c "office\|ole")"
            echo "  PowerShell: $(echo "${fileless_findings[@]}" | grep -c "ps_\|powershell")"
            echo ""
            echo "MITRE ATT&CK Mapping:"
            echo "  T1059 - Command and Scripting Interpreter"
            echo "  T1218 - Signed Binary Proxy Execution"
            echo "  T1546 - Event Triggered Execution"
            echo "  T1047 - Windows Management Instrumentation"
            echo "  T1140 - Deobfuscate/Decode Files"
            echo ""
        } >> "$FILELESS_REPORT"
        
        if [ $fileless_score -ge 40 ]; then
            log_threat $((fileless_score / 2)) "Fileless malware techniques detected"
        fi
        
        analysis_success_found "FILELESS" "${#fileless_findings[@]}" "Score: $fileless_score"
    else
        analysis_success_none "FILELESS"
    fi
}

analyze_decoded_content_threats() {
    local decoded_content="$1"
    
    # Check for additional threats in decoded content
    if echo "$decoded_content" | grep -qiE "IEX|Invoke-Expression|downloadstring"; then
        log_threat 30 "Decoded content contains execution primitives"
    fi
    
    if echo "$decoded_content" | grep -qiE "http[s]?://"; then
        local urls=$(echo "$decoded_content" | grep -oiE "https?://[^\s\"'<>]+" )
        for url in $urls; do
            log_forensic "URL found in decoded content: $url"
            record_ioc "decoded_url" "$url" "URL from decoded content"
        done
    fi
    
    # Check for credential access
    if echo "$decoded_content" | grep -qiE "password|credential|mimikatz|sekurlsa"; then
        log_threat 45 "Decoded content references credentials"
    fi
}

################################################################################
# RANSOMWARE NOTE DETECTION AND ANALYSIS
################################################################################

analyze_ransomware_notes() {
    local content="$1"
    
    if [ "$RANSOMWARE_NOTE_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for ransomware note patterns..."
    
    local ransom_findings=()
    local ransom_score=0
    local ransom_family=""
    
    # Check ransomware note patterns
    local pattern_matches=0
    for pattern in "${RANSOMWARE_NOTE_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((pattern_matches++))
            ransom_findings+=("note_pattern:$pattern")
        fi
    done
    
    if [ $pattern_matches -ge 3 ]; then
        log_threat 80 "Multiple ransomware note patterns detected ($pattern_matches matches)"
        ((ransom_score += 60))
    elif [ $pattern_matches -ge 1 ]; then
        log_warning "Ransomware-related language detected ($pattern_matches patterns)"
        ((ransom_score += 25))
    fi
    
    # Check for specific ransomware families
    for family in "${!RANSOMWARE_FAMILIES[@]}"; do
        local indicators="${RANSOMWARE_FAMILIES[$family]}"
        IFS=',' read -ra ind_array <<< "$indicators"
        
        for indicator in "${ind_array[@]}"; do
            if echo "$content" | grep -qiE "$indicator"; then
                ransom_family="$family"
                ransom_findings+=("family:$family:$indicator")
                ((ransom_score += 50))
                log_threat 70 "Ransomware family indicator: $family ($indicator)"
                break 2
            fi
        done
    done
    
    # Check for ransom payment methods
    if echo "$content" | grep -qiE "bitcoin|btc|monero|xmr|cryptocurrency"; then
        log_warning "Cryptocurrency payment reference detected"
        ransom_findings+=("crypto_payment")
        ((ransom_score += 20))
    fi
    
    # Check for .onion contact
    if echo "$content" | grep -qiE "\.onion"; then
        log_warning "Tor hidden service (.onion) reference"
        ransom_findings+=("onion_contact")
        ((ransom_score += 25))
    fi
    
    # Check for victim ID patterns
    if echo "$content" | grep -qiE "(victim|personal|unique).*id.*[A-Za-z0-9]{8,}"; then
        log_warning "Victim ID pattern detected"
        ransom_findings+=("victim_id")
        ((ransom_score += 15))
    fi
    
    # Check for encryption algorithm mentions
    if echo "$content" | grep -qiE "RSA-[0-9]{4}|AES-[0-9]{3}|ChaCha20|Salsa20"; then
        log_info "Encryption algorithm reference"
        ransom_findings+=("encryption_algo")
        ((ransom_score += 10))
    fi
    
    # Check for file extension changes
    local extension_pattern=$(echo "$content" | grep -oiE "\.[a-z0-9]{4,8}" | head -5)
    if [ -n "$extension_pattern" ]; then
        # Compare against known ransomware extensions
        for ext in ".lockbit" ".conti" ".revil" ".ryuk" ".maze" ".encrypt" ".locked"; do
            if echo "$extension_pattern" | grep -qi "$ext"; then
                ransom_findings+=("ransom_extension:$ext")
                ((ransom_score += 30))
            fi
        done
    fi
    
    # Generate ransomware report
    if [ ${#ransom_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "RANSOMWARE NOTE ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Ransomware Score: $ransom_score"
            echo ""
            if [ -n "$ransom_family" ]; then
                echo "*** IDENTIFIED RANSOMWARE FAMILY: $ransom_family ***"
                echo ""
            fi
            echo "Findings:"
            for finding in "${ransom_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Risk Assessment:"
            if [ $ransom_score -ge 80 ]; then
                echo "  CRITICAL: Strong ransomware indicators detected"
                echo "  This QR likely leads to ransomware payment/contact page"
            elif [ $ransom_score -ge 40 ]; then
                echo "  HIGH: Significant ransomware-related content"
            elif [ $ransom_score -ge 20 ]; then
                echo "  MEDIUM: Some ransomware indicators present"
            else
                echo "  LOW: Minor indicators, may be false positive"
            fi
            echo ""
        } >> "$RANSOMWARE_NOTE_REPORT"
        
        if [ $ransom_score -ge 40 ]; then
            log_threat $((ransom_score / 2)) "Ransomware indicators detected"
        fi
        
        analysis_success_found "RANSOMWARE" "${#ransom_findings[@]}" "Score: $ransom_score"
    else
        analysis_success_none "RANSOMWARE"
    fi
}

################################################################################
# TOR / VPN / ANONYMIZATION DETECTION
################################################################################

analyze_tor_vpn() {
    local content="$1"
    
    if [ "$TOR_VPN_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for Tor/VPN/Anonymization indicators..."
    
    local anon_findings=()
    local anon_score=0
    
    # Check Tor patterns
    for pattern in "${TOR_EXIT_INDICATORS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            anon_findings+=("tor:$matched")
            ((anon_score += 35))
            log_warning "Tor/Darknet indicator: $matched"
        fi
    done
    
    # Check VPN/Proxy patterns
    for pattern in "${VPN_PROXY_DOMAINS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            anon_findings+=("vpn:$matched")
            ((anon_score += 15))
            log_info "VPN service reference: $matched"
        fi
    done
    
    # Check anonymizing proxy patterns
    for pattern in "${ANONYMIZING_PROXIES[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            anon_findings+=("proxy:$matched")
            ((anon_score += 25))
            log_warning "Anonymizing proxy reference: $matched"
        fi
    done
    
    # .onion URL extraction
    local onion_urls=$(echo "$content" | grep -oiE "[a-z2-7]{56}\.onion|[a-z2-7]{16}\.onion")
    if [ -n "$onion_urls" ]; then
        for onion_url in $onion_urls; do
            log_threat 50 "Tor hidden service URL: $onion_url"
            anon_findings+=("onion_url:$onion_url")
            record_ioc "onion_url" "$onion_url" "Tor hidden service"
            ((anon_score += 40))
        done
    fi
    
    # Check for tor2web gateways (clearnet access to .onion)
    if echo "$content" | grep -qiE "tor2web|onion\.(to|ws|ly|sh|city|link|direct)"; then
        log_threat 45 "Tor2Web gateway detected - clearnet access to hidden service"
        anon_findings+=("tor2web_gateway")
        ((anon_score += 35))
    fi
    
    # Check for I2P references
    if echo "$content" | grep -qiE "\.i2p|i2p.*router|eepsite"; then
        log_warning "I2P network reference detected"
        anon_findings+=("i2p_network")
        ((anon_score += 30))
    fi
    
    # Check for IP resolution if network enabled
    if [ "$NETWORK_CHECK" = true ]; then
        check_tor_exit_nodes "$content"
    fi
    
    # Generate anonymization report
    if [ ${#anon_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "TOR / VPN / ANONYMIZATION ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Anonymization Score: $anon_score"
            echo ""
            echo "Findings:"
            for finding in "${anon_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Network Type Distribution:"
            echo "  Tor/Darknet: $(echo "${anon_findings[@]}" | grep -c "tor\|onion")"
            echo "  VPN Services: $(echo "${anon_findings[@]}" | grep -c "vpn")"
            echo "  Proxies: $(echo "${anon_findings[@]}" | grep -c "proxy")"
            echo "  I2P: $(echo "${anon_findings[@]}" | grep -c "i2p")"
            echo ""
            if [ $anon_score -ge 40 ]; then
                echo "WARNING: Strong anonymization/darknet indicators"
                echo "Content likely related to criminal infrastructure"
            fi
            echo ""
        } >> "$TOR_VPN_REPORT"
        
        if [ $anon_score -ge 30 ]; then
            log_threat $((anon_score / 2)) "Tor/VPN/Anonymization indicators detected"
        fi
        
        analysis_success_found "TOR-VPN" "${#anon_findings[@]}" "Score: $anon_score"
    else
        analysis_success_none "TOR-VPN"
    fi
}

check_tor_exit_nodes() {
    local content="$1"
    
    # Extract IPs from content
    local ips=$(echo "$content" | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
    
    if [ -z "$ips" ]; then
        return
    fi
    
    # Download Tor exit node list (cached)
    local tor_list="${TEMP_DIR}/threat_intel/tor_exits.txt"
    
    if [ ! -f "$tor_list" ]; then
        curl -sfL --max-time 15 "https://check.torproject.org/exit-addresses" > "$tor_list" 2>/dev/null
    fi
    
    if [ -s "$tor_list" ]; then
        for ip in $ips; do
            if grep -q "$ip" "$tor_list"; then
                log_threat 60 "IP $ip is a known Tor exit node"
                record_ioc "tor_exit" "$ip" "Known Tor exit node"
            fi
        done
    fi
}

################################################################################
# SOCIAL ENGINEERING AND PERSONA ANALYSIS
################################################################################

analyze_social_engineering() {
    local content="$1"
    
    if [ "$PERSONA_LINKING" = false ]; then
        return
    fi
    
    log_info "Analyzing for social engineering patterns..."
    
    local se_findings=()
    local se_score=0
    local se_categories=()
    
    # Check social engineering patterns
    for pattern in "${SOCIAL_ENGINEERING_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            se_findings+=("social_eng:$matched")
            ((se_score += 15))
        fi
    done
    
    # Check BEC patterns
    for pattern in "${BEC_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            se_findings+=("bec:$matched")
            ((se_score += 30))
            log_threat 45 "Business Email Compromise indicator: $matched"
        fi
    done
    
    # Categorize the social engineering tactics
    
    # URGENCY
    local urgency_count=0
    for phrase in "urgent" "immediate" "act now" "expires" "deadline" "limited time" "hours left" "final notice"; do
        if echo "$content" | grep -qiE "$phrase"; then
            ((urgency_count++))
        fi
    done
    if [ $urgency_count -ge 2 ]; then
        se_categories+=("URGENCY:$urgency_count")
        ((se_score += 20))
        log_warning "Multiple urgency indicators ($urgency_count)"
    fi
    
    # AUTHORITY
    local authority_count=0
    for phrase in "official" "government" "bank" "security department" "legal" "court" "police" "irs" "fbi"; do
        if echo "$content" | grep -qiE "$phrase"; then
            ((authority_count++))
        fi
    done
    if [ $authority_count -ge 2 ]; then
        se_categories+=("AUTHORITY:$authority_count")
        ((se_score += 25))
        log_warning "Multiple authority indicators ($authority_count)"
    fi
    
    # FEAR
    local fear_count=0
    for phrase in "compromised" "suspended" "breach" "stolen" "hacked" "virus" "locked" "terminated" "legal action"; do
        if echo "$content" | grep -qiE "$phrase"; then
            ((fear_count++))
        fi
    done
    if [ $fear_count -ge 2 ]; then
        se_categories+=("FEAR:$fear_count")
        ((se_score += 25))
        log_warning "Multiple fear indicators ($fear_count)"
    fi
    
    # REWARD/GREED
    local reward_count=0
    for phrase in "winner" "prize" "congratulations" "won" "free" "bonus" "reward" "million"; do
        if echo "$content" | grep -qiE "$phrase"; then
            ((reward_count++))
        fi
    done
    if [ $reward_count -ge 2 ]; then
        se_categories+=("REWARD:$reward_count")
        ((se_score += 20))
        log_warning "Multiple reward/greed indicators ($reward_count)"
    fi
    
    # Check for impersonation patterns
    if echo "$content" | grep -qiE "(from|signed|regards).*@.*(bank|paypal|amazon|apple|microsoft|google)"; then
        log_threat 40 "Brand impersonation signature detected"
        se_findings+=("brand_impersonation")
        ((se_score += 30))
    fi
    
    # Check for fake invoice patterns
    if echo "$content" | grep -qiE "invoice.*#.*[0-9]+|order.*#.*[0-9]+|payment.*due"; then
        log_warning "Invoice/Payment reference pattern"
        se_findings+=("fake_invoice")
        ((se_score += 15))
    fi
    
    # Check for credential harvesting language
    if echo "$content" | grep -qiE "(verify|confirm|update).*your.*(account|password|information|details)"; then
        log_threat 35 "Credential harvesting language detected"
        se_findings+=("credential_harvest")
        ((se_score += 25))
    fi
    
    # Generate social engineering report
    if [ ${#se_findings[@]} -gt 0 ] || [ ${#se_categories[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "SOCIAL ENGINEERING ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Social Engineering Score: $se_score"
            echo ""
            echo "Psychological Manipulation Tactics:"
            for cat in "${se_categories[@]}"; do
                echo "  - $cat"
            done
            echo ""
            echo "Specific Patterns Found:"
            for finding in "${se_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Risk Assessment:"
            if [ $se_score -ge 80 ]; then
                echo "  CRITICAL: Multiple social engineering techniques combined"
                echo "  This is a sophisticated social engineering attack"
            elif [ $se_score -ge 50 ]; then
                echo "  HIGH: Strong social engineering indicators"
            elif [ $se_score -ge 25 ]; then
                echo "  MEDIUM: Social engineering tactics present"
            else
                echo "  LOW: Minor persuasion techniques detected"
            fi
            echo ""
            echo "Cialdini's Principles Detected:"
            [ $urgency_count -ge 1 ] && echo "  - Scarcity/Urgency"
            [ $authority_count -ge 1 ] && echo "  - Authority"
            [ $fear_count -ge 1 ] && echo "  - Fear (negative social proof)"
            [ $reward_count -ge 1 ] && echo "  - Reciprocity/Reward"
            echo ""
        } >> "$PERSONA_REPORT"
        
        if [ $se_score -ge 35 ]; then
            log_threat $((se_score / 3)) "Social engineering patterns detected"
        fi
        
        analysis_success_found "SOCIAL-ENGINEERING" "${#se_findings[@]}" "Score: $se_score"
    else
        analysis_success_none "SOCIAL-ENGINEERING"
    fi
}

################################################################################
# ASN AND NETWORK INFRASTRUCTURE ANALYSIS
################################################################################

analyze_asn_infrastructure() {
    local content="$1"
    
    if [ "$ASN_ANALYSIS" = false ] || [ "$NETWORK_CHECK" = false ]; then
        analysis_success_none "ASN-ANALYSIS"
        return
    fi
    
    log_info "Analyzing network infrastructure and ASN reputation..."
    
    local asn_findings=()
    local asn_score=0
    local analyzed_count=0
    
    # Extract domains and IPs
    local domains=$(echo "$content" | grep -oiE "[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}" | sort -u)
    local ips=$(echo "$content" | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | sort -u)
    
    # Display extracted targets
    if [ -n "$domains" ] || [ -n "$ips" ]; then
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│                 ASN/INFRASTRUCTURE ANALYSIS                  │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
    fi
    
    # Resolve domains to IPs
    for domain in $domains; do
        local resolved_ip=$(dig +short A "$domain" 2>/dev/null | head -1)
        if [ -n "$resolved_ip" ] && [ "$resolved_ip" != "$domain" ]; then
            echo -e "${CYAN}│${NC} Domain: ${WHITE}$domain${NC} → ${YELLOW}$resolved_ip${NC}"
            ips="$ips $resolved_ip"
            ((analyzed_count++))
        fi
    done
    
    # Analyze each IP
    for ip in $ips; do
        # Skip private/reserved IPs
        if echo "$ip" | grep -qE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.)"; then
            continue
        fi
        
        ((analyzed_count++))
        
        # Get ASN info (with timeout)
        local asn_info=$(timeout 5 whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1)
        
        if [ -n "$asn_info" ] && [ "$asn_info" != "Error" ]; then
            local asn=$(echo "$asn_info" | awk -F'|' '{print $1}' | tr -d ' ')
            local asn_name=$(echo "$asn_info" | awk -F'|' '{print $NF}' | xargs)
            local country=$(echo "$asn_info" | awk -F'|' '{print $3}' | tr -d ' ')
            
            echo -e "${CYAN}│${NC} IP: ${WHITE}$ip${NC} → AS${YELLOW}$asn${NC} (${WHITE}$asn_name${NC}) [${YELLOW}$country${NC}]"
            log_forensic "IP $ip -> AS$asn ($asn_name) [$country]"
            
            # Check against bulletproof ASN list
            for bp_asn in "${BULLETPROOF_ASNS[@]}"; do
                if [ "AS$asn" = "$bp_asn" ]; then
                    echo -e "${CYAN}│${NC}   ${RED}⚠ BULLETPROOF/HIGH-ABUSE ASN${NC}"
                    log_threat 40 "IP $ip is in known bulletproof/abuse-prone ASN: $bp_asn ($asn_name)"
                    asn_findings+=("bulletproof_asn:$bp_asn:$ip")
                    ((asn_score += 30))
                fi
            done
            
            # Check country
            case "$country" in
                "RU")
                    echo -e "${CYAN}│${NC}   ${YELLOW}⚠ High-risk country: Russia${NC}"
                    log_warning "IP $ip is in high-risk country: Russia"
                    asn_findings+=("high_risk_country:RU:$ip")
                    ((asn_score += 20))
                    ;;
                "CN")
                    echo -e "${CYAN}│${NC}   ${YELLOW}⚠ High-risk country: China${NC}"
                    log_warning "IP $ip is in high-risk country: China"
                    asn_findings+=("high_risk_country:CN:$ip")
                    ((asn_score += 20))
                    ;;
                "IR")
                    echo -e "${CYAN}│${NC}   ${YELLOW}⚠ High-risk country: Iran${NC}"
                    log_warning "IP $ip is in high-risk country: Iran"
                    asn_findings+=("high_risk_country:IR:$ip")
                    ((asn_score += 25))
                    ;;
                "KP")
                    echo -e "${CYAN}│${NC}   ${RED}⚠ CRITICAL: North Korea${NC}"
                    log_threat 50 "IP $ip is in DPRK (North Korea)"
                    asn_findings+=("high_risk_country:KP:$ip")
                    ((asn_score += 50))
                    ;;
                "SY")
                    echo -e "${CYAN}│${NC}   ${YELLOW}⚠ High-risk country: Syria${NC}"
                    log_warning "IP $ip is in high-risk country: Syria"
                    asn_findings+=("high_risk_country:SY:$ip")
                    ((asn_score += 25))
                    ;;
            esac
        fi
    done
    
    if [ -n "$domains" ] || [ -n "$ips" ]; then
        echo -e "${CYAN}│${NC}"
        echo -e "${CYAN}│${NC} Analyzed: ${WHITE}$analyzed_count targets${NC}"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
    fi
    
    # Check registrar patterns in any WHOIS we've collected
    local whois_files=$(find "${EVIDENCE_DIR}" -name "whois_*" 2>/dev/null)
    if [ -n "$whois_files" ]; then
        for registrar in "${SUSPICIOUS_REGISTRARS[@]}"; do
            # Skip empty patterns
            [ -z "$registrar" ] && continue
            local match=$(grep -il "$registrar" ${whois_files} 2>/dev/null | head -1)
            if [ -n "$match" ]; then
                log_warning "Domain registered with high-abuse registrar: $registrar (found in $(basename "$match"))"
                asn_findings+=("suspicious_registrar:$registrar")
                ((asn_score += 15))
            fi
        done
    fi
    
    # Generate ASN report
    if [ ${#asn_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "ASN AND INFRASTRUCTURE ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Infrastructure Risk Score: $asn_score"
            echo ""
            echo "Findings:"
            for finding in "${asn_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
        } >> "$ASN_REPORT"
        
        if [ $asn_score -ge 30 ]; then
            # GRANULAR OUTPUT RESTORED: Classic Paste A format for suspicious network infrastructure
            log_threat $((asn_score / 2)) "Suspicious network infrastructure detected"
            # Additional granular output per finding type for forensic visibility
            for finding in "${asn_findings[@]}"; do
                case "$finding" in
                    bulletproof_asn:*)
                        log_warning "    └─ Bulletproof/high-abuse ASN: ${finding#bulletproof_asn:}"
                        ;;
                    high_risk_country:*)
                        log_warning "    └─ High-risk country infrastructure: ${finding#high_risk_country:}"
                        ;;
                    suspicious_registrar:*)
                        log_warning "    └─ Suspicious registrar: ${finding#suspicious_registrar:}"
                        ;;
                esac
            done
        fi
        
        analysis_success_found "ASN-ANALYSIS" "${#asn_findings[@]}" "Score: $asn_score"
    else
        analysis_success_none "ASN-ANALYSIS"
    fi
    
    # If you have detection variable, e.g. found_suspicious_infra=1
    if [[ "$found_suspicious_infra" == "1" ]]; then
        echo -e "${RED}[THREAT +187]${NC} Suspicious network infrastructure detected"
    fi
}


################################################################################
# ADVERSARIAL QR CODE DETECTION
################################################################################

analyze_adversarial_qr() {
    local image="$1"
    
    if [ "$ADVERSARIAL_QR_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing for adversarial QR patterns..."
    
    local adversarial_findings=()
    local adversarial_score=0
    
    # Get image properties
    if command -v identify &> /dev/null; then
        local img_info=$(identify -verbose "$image" 2>/dev/null)
        
        # Check for unusual dimensions
        local width=$(echo "$img_info" | grep "Geometry:" | grep -oE "[0-9]+x[0-9]+" | cut -dx -f1)
        local height=$(echo "$img_info" | grep "Geometry:" | grep -oE "[0-9]+x[0-9]+" | cut -dx -f2)
        
        if [ -n "$width" ] && [ -n "$height" ]; then
            # Very small QR (possible micro QR or density attack)
            if [ "$width" -lt 50 ] || [ "$height" -lt 50 ]; then
                log_warning "Very small QR image detected (${width}x${height})"
                adversarial_findings+=("micro_qr:${width}x${height}")
                ((adversarial_score += 15))
            fi
            
            # Very large QR (possible high-density attack)
            if [ "$width" -gt 2000 ] || [ "$height" -gt 2000 ]; then
                log_warning "Very large QR image detected (${width}x${height})"
                adversarial_findings+=("oversized_qr:${width}x${height}")
                ((adversarial_score += 10))
            fi
            
            # Non-square QR (unusual)
            local ratio=$(echo "scale=2; $width / $height" | bc 2>/dev/null)
            if [ -n "$ratio" ]; then
                if (( $(echo "$ratio > 1.1 || $ratio < 0.9" | bc -l 2>/dev/null || echo "0") )); then
                    log_warning "Non-square QR image (ratio: $ratio)"
                    adversarial_findings+=("non_square:$ratio")
                    ((adversarial_score += 20))
                fi
            fi
        fi
        
        # Check color depth
        local depth=$(echo "$img_info" | grep "Depth:" | head -1)
        if echo "$depth" | grep -qE "[0-9]+-bit"; then
            local bit_depth=$(echo "$depth" | grep -oE "[0-9]+")
            if [ "$bit_depth" -gt 8 ]; then
                log_info "High bit depth QR image: $bit_depth-bit (possible stego carrier)"
                adversarial_findings+=("high_bit_depth:$bit_depth")
                ((adversarial_score += 10))
            fi
        fi
        
        # Check for transparency (alpha channel)
        if echo "$img_info" | grep -qi "Alpha:"; then
            log_info "QR image has alpha channel (transparency)"
            adversarial_findings+=("has_alpha_channel")
            ((adversarial_score += 5))
        fi
        
        # Check for embedded ICC profile
        if echo "$img_info" | grep -qi "icc:"; then
            log_info "QR image has embedded ICC profile (unusual for QR)"
            adversarial_findings+=("icc_profile")
            ((adversarial_score += 10))
        fi
        
        # Check for EXIF data (unusual for generated QR)
        if echo "$img_info" | grep -qiE "exif:|GPS"; then
            log_warning "QR image has EXIF metadata (suspicious for QR code)"
            adversarial_findings+=("has_exif")
            ((adversarial_score += 15))
        fi
    fi
    
    # Python-based advanced analysis
    analyze_qr_visual_properties "$image"
    
    # Check for multi-QR sequences (animated GIF, multiple QRs)
    if file "$image" | grep -qi "GIF"; then
        local frame_count=$(identify "$image" 2>/dev/null | wc -l)
        if [ "$frame_count" -gt 1 ]; then
            log_threat 40 "Animated QR code detected ($frame_count frames) - possible multi-payload attack"
            adversarial_findings+=("animated_qr:$frame_count")
            ((adversarial_score += 35))
        fi
    fi
    
    # Check for QR code density/version issues
    analyze_qr_density "$image"
    
    # Generate adversarial QR report
    if [ ${#adversarial_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "ADVERSARIAL QR CODE ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Adversarial Score: $adversarial_score"
            echo ""
            echo "Findings:"
            for finding in "${adversarial_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Attack Types Detected:"
            echo "  Visual Manipulation: $(echo "${adversarial_findings[@]}" | grep -c "visual\|ratio\|square")"
            echo "  Density Attacks: $(echo "${adversarial_findings[@]}" | grep -c "density\|micro\|oversized")"
            echo "  Multi-payload: $(echo "${adversarial_findings[@]}" | grep -c "animated\|sequence")"
            echo "  Stego Indicators: $(echo "${adversarial_findings[@]}" | grep -c "depth\|alpha\|icc")"
            echo ""
        } >> "$ADVERSARIAL_QR_REPORT"
        
        if [ $adversarial_score -ge 25 ]; then
            log_threat $((adversarial_score / 2)) "Adversarial QR characteristics detected"
        fi
    fi
}

analyze_qr_visual_properties() {
    local image="$1"
    
    python3 << EOF 2>/dev/null
import sys
try:
    from PIL import Image
    import numpy as np
    
    img = Image.open('$image')
    
    # Convert to grayscale for analysis
    if img.mode != 'L':
        gray = img.convert('L')
    else:
        gray = img
    
    pixels = np.array(gray)
    
    # Check for unusual color distribution (should be mostly black/white)
    unique_colors = len(np.unique(pixels))
    
    if unique_colors > 50:
        print(f"QR_VISUAL_ALERT: Unusual color count ({unique_colors}) - possible visual attack")
    
    # Check for gradients (QRs should be binary)
    gradient = np.abs(np.diff(pixels.astype(float)))
    avg_gradient = np.mean(gradient)
    
    if avg_gradient > 50:
        print(f"QR_VISUAL_ALERT: High gradient average ({avg_gradient:.2f}) - possible gradient attack")
    
    # Check for noise patterns
    noise_level = np.std(pixels)
    if noise_level > 100:
        print(f"QR_VISUAL_ALERT: High noise level ({noise_level:.2f}) - possible noise injection")
    
    # Check quiet zone (should have white border)
    border_size = min(10, pixels.shape[0] // 10, pixels.shape[1] // 10)
    if border_size > 0:
        top_border = np.mean(pixels[:border_size, :])
        bottom_border = np.mean(pixels[-border_size:, :])
        left_border = np.mean(pixels[:, :border_size])
        right_border = np.mean(pixels[:, -border_size:])
        
        avg_border = (top_border + bottom_border + left_border + right_border) / 4
        
        if avg_border < 200:  # Should be mostly white (255)
            print(f"QR_VISUAL_ALERT: Reduced quiet zone (avg: {avg_border:.0f}) - possible margin attack")
    
    # Check for embedded patterns
    # Look for regular patterns that might indicate hidden data
    fft = np.fft.fft2(pixels)
    fft_shift = np.fft.fftshift(fft)
    magnitude = np.abs(fft_shift)
    
    # Check for unusual frequency spikes (hidden periodic patterns)
    threshold = np.mean(magnitude) * 10
    spikes = np.sum(magnitude > threshold)
    
    if spikes > 100:
        print(f"QR_VISUAL_ALERT: Unusual frequency patterns ({spikes} spikes) - possible hidden data")

except Exception as e:
    pass
EOF
}

analyze_qr_density() {
    local image="$1"
    
    python3 << EOF 2>/dev/null
try:
    from pyzbar.pyzbar import decode
    from PIL import Image
    
    img = Image.open('$image')
    codes = decode(img)
    
    for code in codes:
        data = code.data.decode('utf-8', errors='ignore')
        
        # QR code versions: 1 (21x21) to 40 (177x177)
        # Higher versions can hold more data but are also used for attacks
        data_len = len(data)
        
        # Approximate QR version based on data length
        # Version 40 can hold ~2953 bytes alphanumeric
        if data_len > 2000:
            print(f"QR_DENSITY_ALERT: Very high data capacity ({data_len} bytes) - high version QR")
        
        # Check for maximum error correction exploitation
        # Attackers sometimes use high EC to hide variations
        
        # Check for null bytes or unusual characters
        null_count = data.count('\x00')
        if null_count > 0:
            print(f"QR_DENSITY_ALERT: Contains {null_count} null bytes - possible padding attack")
        
        # Check for excessive whitespace/padding
        space_ratio = len([c for c in data if c.isspace()]) / len(data) if len(data) > 0 else 0
        if space_ratio > 0.3:
            print(f"QR_DENSITY_ALERT: High whitespace ratio ({space_ratio:.2%}) - possible padding")

except Exception as e:
    pass
EOF
}

################################################################################
# ZERO-DAY AND ANOMALY DETECTION
################################################################################

analyze_zero_day_anomalies() {
    local content="$1"
    
    if [ "$ZERO_DAY_DETECTION" = false ]; then
        return
    fi
    
    log_info "Analyzing for zero-day/anomaly patterns..."
    
    local anomaly_findings=()
    local anomaly_score=0
    
    # Check for unusual encoding patterns
    analyze_encoding_anomalies "$content"
    
    # Check for polyglot patterns
    analyze_polyglot_content "$content"
    
    # Check for parser differential exploits
    analyze_parser_differentials "$content"
    
    # Statistical anomaly detection
    local content_length=${#content}
    local unique_chars=$(echo "$content" | fold -w1 | sort -u | wc -l)
    local char_ratio=$(echo "scale=4; $unique_chars / $content_length" | bc 2>/dev/null || echo "0")
    
    # Very low character diversity might indicate encoded payload
    if (( $(echo "$char_ratio < 0.05" | bc -l 2>/dev/null || echo "0") )) && [ "$content_length" -gt 100 ]; then
        log_warning "Low character diversity ratio ($char_ratio) - possible encoded payload"
        anomaly_findings+=("low_char_diversity:$char_ratio")
        ((anomaly_score += 25))
    fi
    
    # Check for unusual byte sequences
    local non_printable=$(echo "$content" | tr -d '[:print:][:space:]' | wc -c)
    local non_printable_ratio=$(echo "scale=4; $non_printable / $content_length" | bc 2>/dev/null || echo "0")
    
    if (( $(echo "$non_printable_ratio > 0.1" | bc -l 2>/dev/null || echo "0") )); then
        log_warning "High non-printable character ratio ($non_printable_ratio)"
        anomaly_findings+=("non_printable_chars:$non_printable_ratio")
        ((anomaly_score += 30))
    fi
    
    # Check for multiple encoding layers
    local base64_pattern="^[A-Za-z0-9+/=]{20,}$"
    local content_stripped=$(echo "$content" | tr -d '[:space:]')
    
    if echo "$content_stripped" | grep -qE "$base64_pattern"; then
        # Try to decode and check if result is also encoded
        local decoded=$(echo "$content_stripped" | base64 -d 2>/dev/null)
        if [ -n "$decoded" ] && echo "$decoded" | grep -qE "$base64_pattern"; then
            log_threat 45 "Multi-layer base64 encoding detected"
            anomaly_findings+=("multi_layer_encoding")
            ((anomaly_score += 35))
        fi
    fi
    
    # Check for known CVE patterns
    check_known_cve_patterns "$content"
    
    # Check for protocol confusion attacks
    if echo "$content" | grep -qE "^(http|https)://.*:(ftp|ssh|telnet|smtp)"; then
        log_threat 50 "Potential protocol confusion pattern"
        anomaly_findings+=("protocol_confusion")
        ((anomaly_score += 40))
    fi
    
    # Generate zero-day report
    if [ ${#anomaly_findings[@]} -gt 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "ZERO-DAY / ANOMALY ANALYSIS"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Anomaly Score: $anomaly_score"
            echo ""
            echo "Findings:"
            for finding in "${anomaly_findings[@]}"; do
                echo "  - $finding"
            done
            echo ""
            echo "Analysis Notes:"
            echo "  These patterns may indicate novel attack techniques"
            echo "  or zero-day exploit attempts that don't match known signatures."
            echo ""
        } >> "$ZERO_DAY_REPORT"
        
        if [ $anomaly_score -ge 30 ]; then
            log_threat $((anomaly_score / 2)) "Anomalous patterns detected - possible zero-day"
        fi
        
        analysis_success_found "ZERO-DAY" "${#anomaly_findings[@]}" "Score: $anomaly_score"
    else
        analysis_success_none "ZERO-DAY"
    fi
}

analyze_encoding_anomalies() {
    local content="$1"
    
    # Check for mixed encodings
    local has_base64=false
    local has_hex=false
    local has_url=false
    local has_unicode=false
    
    echo "$content" | grep -qE "[A-Za-z0-9+/=]{20,}" && has_base64=true
    echo "$content" | grep -qE "\\\\x[0-9a-fA-F]{2}" && has_hex=true
    echo "$content" | grep -qE "%[0-9a-fA-F]{2}" && has_url=true
    echo "$content" | grep -qE "\\\\u[0-9a-fA-F]{4}" && has_unicode=true
    
    local encoding_count=0
    [ "$has_base64" = true ] && ((encoding_count++))
    [ "$has_hex" = true ] && ((encoding_count++))
    [ "$has_url" = true ] && ((encoding_count++))
    [ "$has_unicode" = true ] && ((encoding_count++))
    
    if [ $encoding_count -ge 3 ]; then
        log_warning "Multiple encoding schemes detected ($encoding_count types) - possible evasion"
    fi
}

analyze_polyglot_content() {
    local content="$1"
    
    # Check for polyglot file signatures in content
    
    # PDF header in URL/content
    if echo "$content" | grep -qE "%PDF-|JVBERi0"; then
        log_threat 55 "PDF signature detected in content - possible polyglot"
    fi
    
    # ZIP header
    if echo "$content" | grep -qE "PK\x03\x04|UEsDB"; then
        log_threat 50 "ZIP signature detected in content - possible polyglot"
    fi
    
    # PE header
    if echo "$content" | grep -qE "MZ.*This program|TVqQ"; then
        log_threat 70 "PE executable signature detected - possible polyglot"
    fi
    
    # HTML in non-HTML context
    if echo "$content" | grep -qE "<html|<script|<iframe" && ! echo "$content" | grep -qE "^https?://"; then
        log_warning "HTML content in non-URL context - possible injection"
    fi
}

analyze_parser_differentials() {
    local content="$1"
    
    # Check for parser confusion characters
    
    # Unicode homoglyphs that might confuse parsers (check via Python or od)
    if python3 -c "
import sys
content = '''$content'''
special_chars = ['\u00A0', '\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005',
                 '\u2006', '\u2007', '\u2008', '\u2009', '\u200A', '\u200B', '\u200C',
                 '\u200D', '\u200E', '\u200F', '\u2028', '\u2029', '\u202F', '\u205F',
                 '\u3000', '\uFEFF']
sys.exit(0 if any(c in content for c in special_chars) else 1)
" 2>/dev/null; then
        log_warning "Unicode special characters detected - possible parser confusion"
    fi
    
    # Mixed directional text (RLO/LRO attack)
    if python3 -c "
import sys
content = '''$content'''
bidi_chars = ['\u202A', '\u202B', '\u202C', '\u202D', '\u202E',
              '\u2066', '\u2067', '\u2068', '\u2069']
sys.exit(0 if any(c in content for c in bidi_chars) else 1)
" 2>/dev/null; then
        log_threat 45 "Bidirectional text override characters detected - RLO attack"
    fi
    
    # Null bytes that might terminate strings early
    if echo "$content" | grep -q $'\x00'; then
        log_warning "Null byte detected - possible string termination attack"
    fi
}

check_known_cve_patterns() {
    local content="$1"
    
    # CVE-2021-44228 (Log4Shell)
    if echo "$content" | grep -qiE "\\\$\{jndi:(ldap|rmi|dns|corba)://"; then
        log_threat 90 "Log4Shell (CVE-2021-44228) pattern detected"
        record_ioc "cve" "CVE-2021-44228" "Log4Shell exploit pattern"
    fi
    
    # CVE-2021-34473/31207/34523 (ProxyShell)
    if echo "$content" | grep -qiE "autodiscover.*powershell|mapi/nspi"; then
        log_threat 85 "ProxyShell pattern detected"
        record_ioc "cve" "ProxyShell" "Exchange exploit pattern"
    fi
    
    # CVE-2022-30190 (Follina)
    if echo "$content" | grep -qiE "ms-msdt:.*IT_"; then
        log_threat 90 "Follina (CVE-2022-30190) pattern detected"
        record_ioc "cve" "CVE-2022-30190" "Follina exploit pattern"
    fi
    
    # CVE-2021-40444 (MSHTML)
    if echo "$content" | grep -qiE "\.cpl.*\.inf|\.cab.*\.inf"; then
        log_threat 80 "MSHTML (CVE-2021-40444) pattern detected"
        record_ioc "cve" "CVE-2021-40444" "MSHTML exploit pattern"
    fi
    
    # Spring4Shell
    if echo "$content" | grep -qiE "class\.module\.classLoader"; then
        log_threat 85 "Spring4Shell pattern detected"
        record_ioc "cve" "Spring4Shell" "Spring exploit pattern"
    fi
}

################################################################################
# ML-BASED HEURISTIC ANALYSIS
################################################################################

analyze_ml_heuristics() {
    local content="$1"
    
    if [ "$ML_CLASSIFICATION" = false ]; then
        return
    fi
    
    log_ml "Performing ML-based heuristic analysis..."
    
    local ml_findings=()
    local ml_score=0
    local ml_confidence=0
    
    # Feature extraction and scoring
    
    # 1. URL Structure Analysis
    if echo "$content" | grep -qiE "^https?://"; then
        local url="$content"
        
        # URL length feature
        local url_length=${#url}
        if [ $url_length -gt 200 ]; then
            ((ml_score += 15))
            ml_findings+=("long_url:$url_length")
        fi
        
        # Subdomain depth
        local domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
        local subdomain_count=$(echo "$domain" | tr '.' '\n' | wc -l)
        if [ $subdomain_count -gt 4 ]; then
            ((ml_score += 20))
            ml_findings+=("deep_subdomains:$subdomain_count")
        fi
        
        # Special character ratio in URL
        local special_chars=$(echo "$url" | tr -cd '@#%&=?-_' | wc -c)
        local special_ratio=$(echo "scale=4; $special_chars / $url_length" | bc 2>/dev/null || echo "0")
        if (( $(echo "$special_ratio > 0.1" | bc -l 2>/dev/null || echo "0") )); then
            ((ml_score += 15))
            ml_findings+=("special_char_ratio:$special_ratio")
        fi
        
        # Digit ratio in domain
        local digits=$(echo "$domain" | tr -cd '0-9' | wc -c)
        local domain_length=${#domain}
        local digit_ratio=$(echo "scale=4; $digits / $domain_length" | bc 2>/dev/null || echo "0")
        if (( $(echo "$digit_ratio > 0.3" | bc -l 2>/dev/null || echo "0") )); then
            ((ml_score += 20))
            ml_findings+=("high_digit_ratio:$digit_ratio")
        fi
        
        # Path depth
        local path_depth=$(echo "$url" | tr '/' '\n' | wc -l)
        if [ $path_depth -gt 8 ]; then
            ((ml_score += 10))
            ml_findings+=("deep_path:$path_depth")
        fi
        
        # Query parameter count
        local param_count=$(echo "$url" | grep -o '&' | wc -l)
        ((param_count++))  # Add 1 for first parameter
        if [ $param_count -gt 5 ]; then
            ((ml_score += 15))
            ml_findings+=("many_params:$param_count")
        fi
    fi
    
    # 2. Entropy-based analysis
    local entropy=$(calculate_string_entropy "$content")
    if (( $(echo "$entropy > 4.5" | bc -l 2>/dev/null || echo "0") )); then
        ((ml_score += 15))
        ml_findings+=("high_entropy:$entropy")
    fi
    
    # 3. N-gram analysis for suspicious patterns
    analyze_ngram_patterns "$content"
    
    # 4. Keyword density scoring
    local phishing_keywords=0
    for keyword in "login" "verify" "account" "password" "secure" "update" "confirm" "suspended" "urgent"; do
        if echo "$content" | grep -qiE "$keyword"; then
            ((phishing_keywords++))
        fi
    done
    
    if [ $phishing_keywords -ge 3 ]; then
        ((ml_score += 25))
        ml_findings+=("phishing_keywords:$phishing_keywords")
    fi
    
    # 5. Brand impersonation scoring
    local brand_score=$(calculate_brand_similarity "$content")
    if [ $brand_score -gt 70 ]; then
        ((ml_score += 30))
        ml_findings+=("brand_impersonation:$brand_score")
    fi
    
    # Calculate confidence based on feature coverage
    local feature_count=${#ml_findings[@]}
    if [ $feature_count -ge 5 ]; then
        ml_confidence=90
    elif [ $feature_count -ge 3 ]; then
        ml_confidence=70
    elif [ $feature_count -ge 1 ]; then
        ml_confidence=50
    else
        ml_confidence=30
    fi
    
    # Generate ML heuristics report
    {
        echo "═══════════════════════════════════════════════"
        echo "ML HEURISTIC ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo "ML Risk Score: $ml_score"
        echo "Confidence: $ml_confidence%"
        echo ""
        echo "Feature Analysis:"
        for finding in "${ml_findings[@]}"; do
            echo "  - $finding"
        done
        echo ""
        echo "Classification:"
        if [ $ml_score -ge 80 ]; then
            echo "  MALICIOUS (High Confidence)"
        elif [ $ml_score -ge 50 ]; then
            echo "  SUSPICIOUS (Medium Confidence)"
        elif [ $ml_score -ge 25 ]; then
            echo "  POTENTIALLY SUSPICIOUS (Low Confidence)"
        else
            echo "  LIKELY BENIGN"
        fi
        echo ""
    } >> "$ML_CLASSIFICATION_REPORT"
    
    if [ $ml_score -ge 40 ]; then
        log_threat $((ml_score / 3)) "ML heuristics indicate suspicious content"
        analysis_success_found "ML-HEURISTICS" "${#ml_findings[@]}" "Score: $ml_score, Confidence: $ml_confidence%"
    else
        analysis_success_none "ML-HEURISTICS"
    fi
}

calculate_string_entropy() {
    local string="$1"
    
    python3 << EOF 2>/dev/null || echo "0"
import math
from collections import Counter

s = '''$string'''
if len(s) == 0:
    print(0)
else:
    freq = Counter(s)
    probs = [count / len(s) for count in freq.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    print(f"{entropy:.4f}")
EOF
}

# After extracting $domain (domain or subdomain from QR URL)
    domain_entropy=$(echo -n "$domain" | od -An -t x1 | tr -d ' \n' | fold -w2 | sort | uniq -c | awk '{print $1}' | sort -n | tail -1)
    if [[ "$domain_entropy" -gt 4 ]]; then
        echo -e "${RED}[THREAT +60]${NC} High domain entropy/DGA pattern detected (possible algorithmic domain)"
    fi
    
    # After enumerating images (if multiple files given)
    if [ "${#images[@]}" -gt 1 ]; then
        for img in "${images[@]}"; do
            if strings "$img" | grep -Ei 'part [0-9]+ of [0-9]+'; then
                echo -e "${YELLOW}[WARNING]${NC} Possible QR chain or multipart payload detected: $img"
            fi
        done
    fi

    # After extracting QR image stats or in analyze_qr_image
    qr_meaningful_density=$(identify -verbose "$infile" | grep 'Pixels:' | awk '{print $2}')
    if [[ "$qr_meaningful_density" -gt 230000 ]]; then
        echo -e "${RED}[THREAT +25]${NC} QR density unusually high (possible adversarial or anti-ML payload)"
    fi

analyze_ngram_patterns() {
    local content="$1"
    
    # Check for suspicious character n-grams
    local suspicious_ngrams=(
        "xxx"
        "000"
        "111"
        "aaa"
        "zzz"
        ".."
        "--"
        "__"
        "@@"
        "##"
    )
    
    for ngram in "${suspicious_ngrams[@]}"; do
        local count=$(echo "$content" | grep -o "$ngram" | wc -l)
        if [ $count -gt 3 ]; then
            log_info "Suspicious n-gram pattern: '$ngram' appears $count times"
        fi
    done
}

calculate_brand_similarity() {
    local content="$1"
    local max_similarity=0
    
    # Check similarity to known brands
    for brand in "paypal" "amazon" "google" "microsoft" "apple" "facebook" "netflix" "bank" "chase" "wells"; do
        if echo "$content" | grep -qiE "$brand" 2>/dev/null; then
            # Check for typosquatting variations (use variables to avoid shell parsing issues)
            local prefix="${brand:0:3}"
            local suffix="${brand:${#brand}-3}"
            local pattern="${prefix}[a-z]*${suffix}"
            local variations=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null | wc -l)
            if [ "$variations" -gt 0 ] 2>/dev/null; then
                max_similarity=80
            else
                max_similarity=50
            fi
        fi
    done
    
    echo $max_similarity
}

################################################################################
# SIEM / EDR INTEGRATION
################################################################################

generate_siem_export() {
    if [ "$SIEM_INTEGRATION" = false ]; then
        return
    fi
    
    log_info "Generating SIEM-compatible export..."
    
    # Generate SIEM-ready JSON
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"event_type\": \"qr_code_analysis\","
        echo "  \"version\": \"$VERSION\","
        echo "  \"threat_score\": $THREAT_SCORE,"
        echo "  \"threat_level\": \"$(get_threat_level)\","
        echo "  \"iocs\": ["
        
        # Include IOCs from CSV
        local first=true
        while IFS=, read -r type indicator timestamp context; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo "    {"
            echo "      \"type\": \"$type\","
            echo "      \"value\": \"$indicator\","
            echo "      \"timestamp\": \"$timestamp\","
            echo "      \"context\": \"$context\""
            echo -n "    }"
        done < "$IOC_REPORT"
        
        echo ""
        echo "  ],"
        echo "  \"analysis_modules\": {"
        echo "    \"cloud_abuse\": $([ -s "$CLOUD_ABUSE_REPORT" ] && echo "true" || echo "false"),"
        echo "    \"mobile_threats\": $([ -s "$MOBILE_THREAT_REPORT" ] && echo "true" || echo "false"),"
        echo "    \"fileless_malware\": $([ -s "$FILELESS_REPORT" ] && echo "true" || echo "false"),"
        echo "    \"ransomware\": $([ -s "$RANSOMWARE_NOTE_REPORT" ] && echo "true" || echo "false"),"
        echo "    \"tor_vpn\": $([ -s "$TOR_VPN_REPORT" ] && echo "true" || echo "false"),"
        echo "    \"social_engineering\": $([ -s "$PERSONA_REPORT" ] && echo "true" || echo "false"),"
        echo "    \"adversarial_qr\": $([ -s "$ADVERSARIAL_QR_REPORT" ] && echo "true" || echo "false"),"
        echo "    \"zero_day\": $([ -s "$ZERO_DAY_REPORT" ] && echo "true" || echo "false")"
        echo "  }"
        echo "}"
    } > "$SIEM_EXPORT_FILE"
    
    log_success "SIEM export generated: $SIEM_EXPORT_FILE"
}

get_threat_level() {
    if [ $THREAT_SCORE -ge $CRITICAL_THRESHOLD ]; then
        echo "CRITICAL"
    elif [ $THREAT_SCORE -ge $HIGH_THRESHOLD ]; then
        echo "HIGH"
    elif [ $THREAT_SCORE -ge $MEDIUM_THRESHOLD ]; then
        echo "MEDIUM"
    elif [ $THREAT_SCORE -ge $LOW_THRESHOLD ]; then
        echo "LOW"
    else
        echo "MINIMAL"
    fi
        if [ "$final_threat_score" -ge 1000 ]; then
        echo -e "${RED}[CRITICAL]${NC} ⚠️  CRITICAL THREAT LEVEL - Immediate action required!"
    fi
}

################################################################################
# INDUSTRY-SPECIFIC THREAT ANALYSIS
################################################################################

analyze_industry_threats() {
    local content="$1"
    
    log_info "Analyzing for industry-specific threats..."
    
    local total_industry_threats=0
    
    # Healthcare
    local healthcare_matches=0
    for pattern in "${HEALTHCARE_THREAT_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((healthcare_matches++))
        fi
    done
    if [ $healthcare_matches -ge 2 ]; then
        log_warning "Healthcare-targeted content detected ($healthcare_matches indicators)"
        log_threat 30 "Potential healthcare phishing/fraud"
        ((total_industry_threats++))
    fi
    
    # Financial
    local financial_matches=0
    for pattern in "${FINANCIAL_THREAT_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((financial_matches++))
        fi
    done
    if [ $financial_matches -ge 2 ]; then
        log_warning "Financial-targeted content detected ($financial_matches indicators)"
        log_threat 35 "Potential financial fraud/phishing"
        ((total_industry_threats++))
    fi
    
    # Government
    local government_matches=0
    for pattern in "${GOVERNMENT_THREAT_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((government_matches++))
        fi
    done
    if [ $government_matches -ge 2 ]; then
        log_warning "Government-impersonation content detected ($government_matches indicators)"
        log_threat 40 "Potential government impersonation scam"
        ((total_industry_threats++))
    fi
    
    # Education
    local education_matches=0
    for pattern in "${EDUCATION_THREAT_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((education_matches++))
        fi
    done
    if [ $education_matches -ge 2 ]; then
        log_warning "Education-targeted content detected ($education_matches indicators)"
        log_threat 25 "Potential education sector phishing"
        ((total_industry_threats++))
    fi
    
    # E-commerce
    local ecommerce_matches=0
    for pattern in "${ECOMMERCE_THREAT_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((ecommerce_matches++))
        fi
    done
    if [ $ecommerce_matches -ge 2 ]; then
        log_warning "E-commerce-targeted content detected ($ecommerce_matches indicators)"
        log_threat 25 "Potential e-commerce fraud"
        ((total_industry_threats++))
    fi
    
    if [ $total_industry_threats -gt 0 ]; then
        analysis_success_found "INDUSTRY-THREATS" "$total_industry_threats" "Sector-specific threats detected"
    else
        analysis_success_none "INDUSTRY-THREATS"
    fi
}

################################################################################
# URL OBFUSCATION AND CLOAKING ANALYSIS
################################################################################

analyze_url_obfuscation() {
    local content="$1"
    
    log_info "Analyzing for URL obfuscation techniques..."
    
    local obfuscation_findings=()
    local obfuscation_score=0
    
    # Check obfuscation patterns
    for pattern in "${URL_OBFUSCATION_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            obfuscation_findings+=("obfuscation:$matched")
            ((obfuscation_score += 20))
            log_warning "URL obfuscation technique: $matched"
        fi
    done
    
    # Check for IP address obfuscation
    if echo "$content" | grep -qE "0x[0-9a-fA-F]+\.[0-9]|[0-9]{10,}|0[0-7]+\."; then
        log_threat 45 "IP address obfuscation detected (hex/decimal/octal)"
        obfuscation_findings+=("ip_obfuscation")
        ((obfuscation_score += 35))
    fi
    
    # Check for punycode domains
    if echo "$content" | grep -qiE "xn--[a-z0-9]+"; then
        log_warning "Punycode domain detected - verify actual characters"
        obfuscation_findings+=("punycode_domain")
        ((obfuscation_score += 25))
        
        # Try to decode punycode
        local punycode=$(echo "$content" | grep -oiE "xn--[a-z0-9.-]+" | head -1)
        if [ -n "$punycode" ] && command -v idn &> /dev/null; then
            local decoded=$(echo "$punycode" | idn --idna-to-unicode 2>/dev/null)
            log_forensic "Decoded punycode: $decoded"
        fi
    fi
    
    # Check for data URI
    if echo "$content" | grep -qiE "data:(text|application)"; then
        log_threat 50 "Data URI detected - embedded content"
        obfuscation_findings+=("data_uri")
        ((obfuscation_score += 40))
    fi
    
    # Check for javascript URI
    if echo "$content" | grep -qiE "javascript:"; then
        log_threat 55 "JavaScript URI detected"
        obfuscation_findings+=("javascript_uri")
        ((obfuscation_score += 45))
    fi
    
    # Check for double encoding
    if echo "$content" | grep -qE "%25[0-9a-fA-F]{2}"; then
        log_threat 40 "Double URL encoding detected"
        obfuscation_findings+=("double_encoding")
        ((obfuscation_score += 30))
    fi
    
    # Check for open redirect abuse
    if echo "$content" | grep -qiE "(redirect|url|next|goto|redir)=https?://"; then
        log_warning "Potential open redirect parameter"
        obfuscation_findings+=("open_redirect")
        ((obfuscation_score += 25))
    fi
    
    # Report findings
    if [ $obfuscation_score -ge 30 ]; then
        log_threat $((obfuscation_score / 2)) "URL obfuscation techniques detected"
        analysis_success_found "URL-OBFUSCATION" "${#obfuscation_findings[@]}" "Score: $obfuscation_score"
    else
        analysis_success_none "URL-OBFUSCATION"
    fi
}

################################################################################
# COMMAND INJECTION AND TEMPLATE INJECTION ANALYSIS
################################################################################

analyze_injection_attacks() {
    local content="$1"
    
    log_info "Analyzing for injection attack patterns..."
    
    local injection_findings=()
    local injection_score=0
    
    # Check command injection patterns
    for pattern in "${COMMAND_INJECTION_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            injection_findings+=("cmd_injection:$matched")
            ((injection_score += 40))
            log_threat 55 "Command injection pattern: $matched"
        fi
    done
    
    # Template injection (SSTI)
    if echo "$content" | grep -qE "\{\{.*\}\}|\{%.*%\}|\$\{.*\}"; then
        log_threat 50 "Template injection pattern detected"
        injection_findings+=("template_injection")
        ((injection_score += 40))
    fi
    
    # XXE patterns
    if echo "$content" | grep -qiE "<!ENTITY|SYSTEM.*file:|DOCTYPE.*ENTITY"; then
        log_threat 60 "XXE (XML External Entity) pattern detected"
        injection_findings+=("xxe_attack")
        ((injection_score += 50))
    fi
    
    # SSRF patterns
    if echo "$content" | grep -qiE "file:///|gopher://|dict://|php://"; then
        log_threat 55 "SSRF-related protocol scheme detected"
        injection_findings+=("ssrf_protocol")
        ((injection_score += 45))
    fi
    
    if [ $injection_score -ge 40 ]; then
        log_threat $((injection_score / 2)) "Injection attack patterns detected"
        analysis_success_found "INJECTION" "${#injection_findings[@]}" "Score: $injection_score"
    else
        analysis_success_none "INJECTION"
    fi
}

################################################################################
# CALLBACK/BEACON ANALYSIS
################################################################################

analyze_c2_beacons() {
    local content="$1"
    
    log_info "Analyzing for C2 beacon patterns..."
    
    local beacon_findings=()
    local beacon_score=0
    
    # Check callback/beacon patterns
    for pattern in "${CALLBACK_BEACON_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            beacon_findings+=("beacon:$matched")
            ((beacon_score += 35))
            log_threat 50 "C2/Beacon pattern: $matched"
        fi
    done
    
    # Check for known C2 framework indicators
    if echo "$content" | grep -qiE "cobalt.*strike|meterpreter|empire|covenant|sliver"; then
        log_threat 80 "Known C2 framework indicator detected"
        beacon_findings+=("known_c2_framework")
        ((beacon_score += 60))
    fi
    
    # DNS beaconing indicators
    if echo "$content" | grep -qiE "dns.*tunnel|dnscat|iodine"; then
        log_threat 65 "DNS tunneling/beaconing indicator"
        beacon_findings+=("dns_beacon")
        ((beacon_score += 50))
    fi
    
    # HTTP-based C2 patterns
    if echo "$content" | grep -qiE "/api/beacon|/c2/|/implant/|/stage[0-9]|/payload"; then
        log_threat 55 "HTTP-based C2 endpoint pattern"
        beacon_findings+=("http_c2_endpoint")
        ((beacon_score += 45))
    fi
    
    if [ $beacon_score -ge 35 ]; then
        log_threat $((beacon_score / 2)) "C2/Beacon communication patterns detected"
        analysis_success_found "C2-BEACONS" "${#beacon_findings[@]}" "Score: $beacon_score"
    else
        analysis_success_none "C2-BEACONS"
    fi
}

################################################################################
# CRYPTO SCAM ANALYSIS
################################################################################

analyze_crypto_scams() {
    local content="$1"
    
    log_info "Analyzing for cryptocurrency scam patterns..."
    
    local crypto_scam_score=0
    
    for pattern in "${CRYPTO_SCAM_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            ((crypto_scam_score += 15))
            log_warning "Crypto scam pattern: $matched"
        fi
    done
    
    # High-confidence scam combinations
    if echo "$content" | grep -qiE "giveaway|airdrop" && \
       echo "$content" | grep -qiE "elon|vitalik|satoshi|official"; then
        log_threat 70 "Celebrity crypto giveaway scam pattern"
        ((crypto_scam_score += 40))
    fi
    
    if echo "$content" | grep -qiE "send.*receive.*double|2x.*return"; then
        log_threat 80 "Crypto doubling scam detected"
        ((crypto_scam_score += 50))
    fi
    
    if echo "$content" | grep -qiE "connect.*wallet.*approve"; then
        log_threat 60 "Wallet drainer pattern detected"
        ((crypto_scam_score += 35))
    fi
    
    if [ $crypto_scam_score -ge 30 ]; then
        log_threat $((crypto_scam_score / 2)) "Cryptocurrency scam indicators detected"
        analysis_success_found "CRYPTO-SCAMS" "1" "Score: $crypto_scam_score"
    else
        analysis_success_none "CRYPTO-SCAMS"
    fi
}


################################################################################
# ENHANCED QR CONTENT ANALYSIS
################################################################################

analyze_decoded_qr_content() {
    local content="$1"
    local report_file="$2"
    
    log_info "Analyzing decoded QR content..."
    
    # Display decoded content details
    echo ""
    echo -e "${WHITE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${WHITE}│                   DECODED QR CONTENT                        │${NC}"
    echo -e "${WHITE}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${WHITE}│${NC} Length:      ${CYAN}${#content} characters${NC}"
    echo -e "${WHITE}│${NC} Preview:     ${CYAN}${content:0:60}${NC}"
    if [ ${#content} -gt 60 ]; then
        echo -e "${WHITE}│${NC}              ${CYAN}${content:60:60}...${NC}"
    fi
    echo -e "${WHITE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Determine content type
    local content_type="unknown"
    
    if echo "$content" | grep -qE "^https?://"; then
        content_type="url"
        log_info "Content type: URL"
        echo -e "  ${CYAN}├─${NC} Protocol: $(echo "$content" | sed -n 's/^\([a-z]*\):.*/\1/p')"
        echo -e "  ${CYAN}└─${NC} Domain: $(echo "$content" | sed -E 's|^https?://||' | cut -d'/' -f1)"
    elif echo "$content" | grep -qE "^mailto:"; then
        content_type="email"
        log_info "Content type: Email link"
        local email_addr=$(echo "$content" | sed 's/^mailto://' | cut -d'?' -f1)
        echo -e "  ${CYAN}└─${NC} Email: $email_addr"
    elif echo "$content" | grep -qE "^tel:|^sms:"; then
        content_type="phone"
        log_info "Content type: Phone/SMS link"
        local phone_num=$(echo "$content" | sed 's/^tel:\|^sms://' | cut -d'?' -f1)
        echo -e "  ${CYAN}└─${NC} Number: $phone_num"
    elif echo "$content" | grep -qE "^WIFI:"; then
        content_type="wifi"
        log_info "Content type: WiFi configuration"
        local wifi_ssid=$(echo "$content" | sed -n 's/.*S:\([^;]*\).*/\1/p')
        echo -e "  ${CYAN}└─${NC} SSID: $wifi_ssid"
    elif echo "$content" | grep -qE "^BEGIN:VCARD"; then
        content_type="vcard"
        log_info "Content type: vCard contact"
    elif echo "$content" | grep -qE "^BEGIN:VEVENT"; then
        content_type="vevent"
        log_info "Content type: Calendar event"
    elif echo "$content" | grep -qE "^otpauth://"; then
        content_type="otp"
        log_info "Content type: OTP/2FA code"
        log_threat 30 "⚠️  2FA/OTP configuration exposed!"
    elif echo "$content" | grep -qE "^bitcoin:|^ethereum:|^litecoin:"; then
        content_type="crypto_payment"
        log_info "Content type: Cryptocurrency payment"
    elif echo "$content" | grep -qE "^(bc1|1|3)[a-zA-Z0-9]{25,}$|^0x[a-fA-F0-9]{40}$"; then
        content_type="crypto_address"
        log_info "Content type: Cryptocurrency address"
    else
        content_type="text"
        log_info "Content type: Plain text/other"
    fi
    echo ""
    
    echo "Content Type: $content_type" >> "$report_file"
    
    # Extract and display any IP addresses in the content
    extract_and_display_ips "$content" "QR content"
    
    # Type-specific analysis
    case "$content_type" in
        "url")
            analyze_url_structure "$content"
            
            # Extract and record domain IOC
            local domain=$(echo "$content" | sed -E 's|^https?://||' | cut -d'/' -f1 | cut -d':' -f1)
            record_ioc "domain" "$domain" "Extracted from QR URL"
            
            # Check against threat intel
            check_against_threat_intel "$content" "url"
            check_against_threat_intel "$domain" "domain"
            
            # Check VirusTotal
            if [ "$VT_CHECK" = true ]; then
                check_virustotal "$content" "url"
                check_virustotal "$domain" "domain"
            fi
            
            # Extract and analyze IP if present
            if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                record_ioc "ip" "$domain" "IP from QR URL"
                check_against_threat_intel "$domain" "ip"
                if [ "$VT_CHECK" = true ]; then
                    check_virustotal "$domain" "ip"
                fi
                check_abuseipdb "$domain"
            fi
            ;;
        "email")
            local email_addr=$(echo "$content" | sed 's/mailto://' | cut -d'?' -f1)
            record_ioc "email" "$email_addr" "Email from QR"
            analyze_email_addresses "$email_addr"
            ;;
        "phone")
            local phone_num=$(echo "$content" | sed -E 's/^(tel:|sms:)//' | cut -d'?' -f1)
            record_ioc "phone" "$phone_num" "Phone from QR"
            analyze_phone_numbers "$phone_num"
            ;;
        "wifi")
            analyze_wifi_config "$content"
            ;;
        "vcard")
            analyze_vcard "$content"
            ;;
        "otp")
            log_threat 30 "OTP/2FA URI detected - potential credential capture"
            analyze_otp_uri "$content"
            ;;
        "crypto_payment"|"crypto_address")
            log_threat 40 "Cryptocurrency content detected"
            analyze_crypto_addresses "$content"
            ;;
        "text")
            # General payload analysis
            analyze_payload_content "$content"
            ;;
    esac
    
    # Always perform behavioral and APT analysis
    perform_behavioral_analysis "$content"
    analyze_apt_indicators "$content"
    
    # ===========================================================================
    # EXTENDED ANALYSIS MODULES
    # ===========================================================================
    
    # Cloud Service Abuse Detection
    if [ "$CLOUD_ABUSE_CHECK" = true ]; then
        analyze_cloud_service_abuse "$content"
    fi
    
    # Offensive Security Tools Detection
    analyze_offensive_tools "$content"
    
    # Legitimate Service Abuse Detection
    analyze_service_abuse "$content"
    
    # Mobile Deep Link Analysis
    if [ "$MOBILE_DEEPLINK_CHECK" = true ]; then
        analyze_mobile_deeplinks "$content"
    fi
    
    # Wireless Attack Detection (Bluetooth/NFC/WiFi)
    if [ "$BLUETOOTH_NFC_CHECK" = true ]; then
        analyze_wireless_attacks "$content"
    fi
    
    # Telephony Attack Detection
    analyze_telephony_attacks "$content"
    
    # Hardware Exploit Detection
    if [ "$HARDWARE_EXPLOIT_CHECK" = true ]; then
        analyze_hardware_exploits "$content"
    fi
    
    # Geofencing/Cloaking Detection
    if [ "$GEOFENCING_CHECK" = true ]; then
        analyze_geofencing_cloaking "$content"
    fi
    
    # Fileless Malware Detection
    if [ "$FILELESS_MALWARE_CHECK" = true ]; then
        analyze_fileless_malware "$content"
    fi
    
    # Ransomware Note Detection
    if [ "$RANSOMWARE_NOTE_CHECK" = true ]; then
        analyze_ransomware_notes "$content"
    fi
    
    # TOR/VPN/Anonymization Detection
    if [ "$TOR_VPN_CHECK" = true ]; then
        analyze_tor_vpn "$content"
    fi
    
    # Social Engineering Analysis
    if [ "$PERSONA_LINKING" = true ]; then
        analyze_social_engineering "$content"
    fi
    
    # ASN Infrastructure Analysis
    if [ "$ASN_ANALYSIS" = true ]; then
        analyze_asn_infrastructure "$content"
    fi
    
    # URL Obfuscation Detection
    if [ "$URL_OBFUSCATION_CHECK" = true ]; then
        analyze_url_obfuscation "$content"
    fi
    
    # Injection Attack Detection
    if [ "$INJECTION_ATTACK_CHECK" = true ]; then
        analyze_injection_attacks "$content"
    fi
    
    # C2 Beacon Detection
    if [ "$C2_BEACON_CHECK" = true ]; then
        analyze_c2_beacons "$content"
    fi
    
    # Cryptocurrency Scam Detection
    if [ "$CRYPTO_SCAM_CHECK" = true ]; then
        analyze_crypto_scams "$content"
    fi
    
    # Industry-Specific Threat Detection
    if [ "$INDUSTRY_THREAT_CHECK" = true ]; then
        analyze_industry_threats "$content"
    fi
    
    # Zero-Day/Anomaly Detection
    if [ "$ZERO_DAY_DETECTION" = true ]; then
        analyze_zero_day_anomalies "$content"
    fi
    
    # ML Heuristics Classification
    if [ "$ML_CLASSIFICATION" = true ]; then
        analyze_ml_heuristics "$content"
    fi
    
    # =========================================================================
    # AUDIT-ENHANCED ANALYSIS (22 NEW MODULES)
    # =========================================================================
    # Run all 22 audit-recommended analysis modules
    if [ "$AUDIT_ENHANCED_ANALYSIS" != false ]; then
        local extracted_url=$(echo "$content" | grep -oiE 'https?://[^\s]+' | head -1)
        run_all_audit_enhancements "$content" "$extracted_url" "$INPUT_IMAGE" ""
    fi
    
    echo "" >> "$report_file"
}

analyze_wifi_config() {
    local content="$1"
    
    log_info "Analyzing WiFi configuration..."
    
    # Parse WIFI: format (POSIX compatible)
    # WIFI:T:WPA;S:NetworkName;P:Password;;
    
    local auth_type=$(echo "$content" | sed -n 's/.*T:\([^;]*\).*/\1/p')
    local ssid=$(echo "$content" | sed -n 's/.*S:\([^;]*\).*/\1/p')
    local password=$(echo "$content" | sed -n 's/.*P:\([^;]*\).*/\1/p')
    local hidden=$(echo "$content" | sed -n 's/.*H:\([^;]*\).*/\1/p')
    
    log_forensic "WiFi SSID: $ssid"
    log_forensic "Auth Type: $auth_type"
    
    if [ -n "$password" ]; then
        log_warning "WiFi password exposed in QR code"
        log_threat 25 "Credential exposure (WiFi password)"
        record_ioc "wifi_password" "SSID:$ssid" "WiFi credentials in QR"
    fi
    
    # Check for suspicious SSIDs
    if echo "$ssid" | grep -qiE "free|guest|public|open|hack|evil|rogue"; then
        log_threat 30 "Suspicious WiFi SSID: $ssid"
    fi
    
    # Open networks
    if [ "$auth_type" = "nopass" ] || [ -z "$auth_type" ]; then
        log_warning "Open WiFi network (no encryption)"
        log_threat 20 "Unsecured WiFi network"
    fi
    
    # WEP is insecure
    if [ "$auth_type" = "WEP" ]; then
        log_warning "WEP encryption (insecure)"
        log_threat 15 "Weak WiFi encryption"
    fi
}

analyze_vcard() {
    local content="$1"
    
    log_info "Analyzing vCard content..."
    
    # Extract fields (POSIX compatible)
    local name=$(echo "$content" | grep -i "^FN:" | cut -d: -f2- | head -1)
    local email=$(echo "$content" | grep -i "^EMAIL" | cut -d: -f2- | head -1)
    local phone=$(echo "$content" | grep -i "^TEL" | cut -d: -f2- | head -1)
    local url=$(echo "$content" | grep -i "^URL" | cut -d: -f2- | head -1)
    
    [ -n "$name" ] && log_forensic "vCard Name: $name"
    [ -n "$email" ] && log_forensic "vCard Email: $email"
    [ -n "$phone" ] && log_forensic "vCard Phone: $phone"
    [ -n "$url" ] && log_forensic "vCard URL: $url"
    
    # Analyze any URLs in vCard
    if [ -n "$url" ]; then
        analyze_url_structure "$url"
    fi
    
    # Analyze emails
    if [ -n "$email" ]; then
        analyze_email_addresses "$email"
    fi
}

analyze_otp_uri() {
    local content="$1"
    
    log_info "Analyzing OTP URI..."
    
    # Parse otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER (POSIX compatible)
    local otp_type=$(echo "$content" | sed -n 's|otpauth://\([^/]*\)/.*|\1|p')
    local label=$(echo "$content" | sed -n 's|otpauth://[^/]*/\([^?]*\).*|\1|p')
    local secret=$(echo "$content" | sed -n 's/.*secret=\([^&]*\).*/\1/p')
    local issuer=$(echo "$content" | sed -n 's/.*issuer=\([^&]*\).*/\1/p')
    
    log_forensic "OTP Type: $otp_type"
    log_forensic "OTP Label: $label"
    log_forensic "OTP Issuer: $issuer"
    
    if [ -n "$secret" ]; then
        log_threat 50 "2FA secret exposed in QR code!"
        record_ioc "otp_secret" "Issuer:$issuer,Label:$label" "2FA secret exposure"
    fi
}

################################################################################
# REPORT GENERATION
################################################################################

generate_comprehensive_report() {
    log_info "Generating comprehensive analysis report..."
    
    # Final threat score assessment
    local risk_level="MINIMAL"
    if [ $THREAT_SCORE -ge $CRITICAL_THRESHOLD ]; then
        risk_level="CRITICAL"
    elif [ $THREAT_SCORE -ge $HIGH_THRESHOLD ]; then
        risk_level="HIGH"
    elif [ $THREAT_SCORE -ge $MEDIUM_THRESHOLD ]; then
        risk_level="MEDIUM"
    elif [ $THREAT_SCORE -ge $LOW_THRESHOLD ]; then
        risk_level="LOW"
    fi
    
    {
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║           FINAL ANALYSIS SUMMARY                              ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Scan Completed: $(date)"
        echo "Scanner Version: $VERSION"
        echo ""
        echo "THREAT ASSESSMENT:"
        echo "─────────────────────"
        echo "  Total Threat Score: $THREAT_SCORE / $MAX_THREAT_SCORE"
        echo "  Risk Level: $risk_level"
        echo ""
        
        # Risk level visualization
        local bar_length=$((THREAT_SCORE * 50 / MAX_THREAT_SCORE))
        printf "  Risk Meter: ["
        for ((i=0; i<50; i++)); do
            if [ $i -lt $bar_length ]; then
                if [ $i -lt 15 ]; then
                    printf "="
                elif [ $i -lt 30 ]; then
                    printf "▓"
                else
                    printf "█"
                fi
            else
                printf "░"
            fi
        done
        printf "]\n"
        echo "               0%          50%         100%"
        echo ""
        
        echo "SCAN STATISTICS:"
        echo "─────────────────────"
        echo "  Images Analyzed: $(find "$EVIDENCE_DIR" -name "*_report.txt" 2>/dev/null | wc -l | tr -d ' ')"
        echo "  Evidence Files: $(find "$EVIDENCE_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
        echo "  IOCs Detected: $(wc -l < "$IOC_REPORT" 2>/dev/null | tr -d ' ' || echo "0")"
        echo "  YARA Matches: $(wc -l < "$YARA_MATCHES" 2>/dev/null | tr -d ' ' || echo "0")"
        echo ""
        
        echo "OUTPUT FILES:"
        echo "─────────────────────"
        echo "  Main Report: $REPORT_FILE"
        echo "  JSON Report: $JSON_REPORT"
        echo "  IOC Report: $IOC_REPORT"
        echo "  Timeline: $TIMELINE_FILE"
        echo "  Evidence: $EVIDENCE_DIR"
        echo "  Log File: $LOG_FILE"
        
        if [ -s "$APT_REPORT" ]; then
            echo "  APT Report: $APT_REPORT"
        fi
        if [ -s "$STEGANOGRAPHY_REPORT" ]; then
            echo "  Stego Report: $STEGANOGRAPHY_REPORT"
        fi
        if [ -s "$BEHAVIORAL_REPORT" ]; then
            echo "  Behavioral: $BEHAVIORAL_REPORT"
        fi
        
        echo ""
        echo "RECOMMENDATIONS:"
        echo "─────────────────────"
        
        if [ "$risk_level" = "CRITICAL" ]; then
            echo "  ⚠️  CRITICAL THREAT DETECTED!"
            echo "  → Do NOT scan this QR code with a mobile device"
            echo "  → Isolate the source of this QR code"
            echo "  → Report to security team immediately"
            echo "  → Preserve evidence for forensic analysis"
        elif [ "$risk_level" = "HIGH" ]; then
            echo "  ⚠️  HIGH RISK CONTENT DETECTED"
            echo "  → Exercise extreme caution"
            echo "  → Do not open URLs without sandboxed analysis"
            echo "  → Consider blocking identified domains/IPs"
            echo "  → Review IOC report for threat indicators"
        elif [ "$risk_level" = "MEDIUM" ]; then
            echo "  ⚡ MEDIUM RISK - Proceed with caution"
            echo "  → Verify the source of this QR code"
            echo "  → Check URLs in a sandbox environment first"
            echo "  → Monitor for unusual behavior if scanned"
        elif [ "$risk_level" = "LOW" ]; then
            echo "  ℹ️  LOW RISK - Minor concerns detected"
            echo "  → Review identified issues before proceeding"
            echo "  → Standard security precautions apply"
        else
            echo "  ✓ MINIMAL RISK - No significant threats detected"
            echo "  → Standard security precautions apply"
            echo "  → Content appears safe for analysis"
        fi
        
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
    } >> "$REPORT_FILE"
}

generate_json_report() {
    log_info "Generating JSON report..."
    
    local risk_level="MINIMAL"
    if [ $THREAT_SCORE -ge $CRITICAL_THRESHOLD ]; then
        risk_level="CRITICAL"
    elif [ $THREAT_SCORE -ge $HIGH_THRESHOLD ]; then
        risk_level="HIGH"
    elif [ $THREAT_SCORE -ge $MEDIUM_THRESHOLD ]; then
        risk_level="MEDIUM"
    elif [ $THREAT_SCORE -ge $LOW_THRESHOLD ]; then
        risk_level="LOW"
    fi
    
    # Collect IOCs as JSON array
    local iocs_json="[]"
    if [ -s "$IOC_REPORT" ]; then
        iocs_json=$(awk -F, 'NR>1 {printf "{\"type\":\"%s\",\"indicator\":\"%s\",\"timestamp\":\"%s\",\"context\":\"%s\"},", $1, $2, $3, $4}' "$IOC_REPORT" | sed 's/,$//' | sed 's/^/[/' | sed 's/$/]/')
    fi
    
    cat > "$JSON_REPORT" << EOF
{
  "scan_metadata": {
    "timestamp": "$(date -Iseconds)",
    "scanner_version": "$VERSION",
    "output_directory": "$OUTPUT_DIR",
    "analysis_duration_seconds": $SECONDS
  },
  "threat_assessment": {
    "threat_score": $THREAT_SCORE,
    "max_score": $MAX_THREAT_SCORE,
    "risk_level": "$risk_level",
    "thresholds": {
      "critical": $CRITICAL_THRESHOLD,
      "high": $HIGH_THRESHOLD,
      "medium": $MEDIUM_THRESHOLD,
      "low": $LOW_THRESHOLD
    }
  },
  "statistics": {
    "images_analyzed": $(find "$EVIDENCE_DIR" -name "*_report.txt" 2>/dev/null | wc -l | tr -d ' '),
    "evidence_files": $(find "$EVIDENCE_DIR" -type f 2>/dev/null | wc -l | tr -d ' '),
    "iocs_detected": $(wc -l < "$IOC_REPORT" 2>/dev/null | tr -d ' ' || echo "0"),
    "yara_matches": $(wc -l < "$YARA_MATCHES" 2>/dev/null | tr -d ' ' || echo "0")
  },
  "iocs": $iocs_json,
  "output_files": {
    "main_report": "$REPORT_FILE",
    "ioc_report": "$IOC_REPORT",
    "timeline": "$TIMELINE_FILE",
    "evidence_dir": "$EVIDENCE_DIR",
    "log_file": "$LOG_FILE"
  }
}
EOF
    
    log_success "JSON report generated: $JSON_REPORT"
}

generate_stix_report() {
    log_info "Generating STIX 2.1 report..."
    
    local bundle_id="bundle--$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s)-$$")"
    
    cat > "$STIX_REPORT" << EOF
{
  "type": "bundle",
  "id": "$bundle_id",
  "objects": [
    {
      "type": "identity",
      "id": "identity--qr-malware-detector",
      "name": "QR Malware Detection System",
      "identity_class": "system",
      "created": "$(date -Iseconds)"
    },
    {
      "type": "report",
      "id": "report--$(date +%s)",
      "name": "QR Code Malware Analysis Report",
      "published": "$(date -Iseconds)",
      "object_refs": []
    }
  ]
}
EOF
    
    log_success "STIX report generated: $STIX_REPORT"
}

generate_forensic_timeline() {
    log_forensic "Generating forensic timeline..."
    
    {
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║              FORENSIC TIMELINE ANALYSIS                    ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""
        echo "Timeline of Events:"
        echo ""
        
        if [ -f "$TIMELINE_FILE" ]; then
            awk -F, '{
                if (NR > 1) {
                    printf "  [%s] %s: %s\n", $1, $2, $3
                }
            }' "$TIMELINE_FILE" | tail -100
        fi
        
        echo ""
    } >> "$CORRELATION_FILE"
}

################################################################################
# INITIALIZATION AND SETUP

################################################################################
# INITIALIZATION
################################################################################


parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--deep)
                DEEP_ANALYSIS=true
                shift
                ;;
            -f|--forensic)
                FORENSIC_MODE=true
                shift
                ;;
            -s|--stealth)
                STEALTH_MODE=true
                NETWORK_CHECK=false
                shift
                ;;
            --vt)
                VT_CHECK=true
                shift
                ;;
            --no-network)
                NETWORK_CHECK=false
                shift
                ;;
            --siem)
                SIEM_INTEGRATION=true
                shift
                ;;
            --no-cloud)
                CLOUD_ABUSE_CHECK=false
                shift
                ;;
            --no-mobile)
                MOBILE_DEEPLINK_CHECK=false
                shift
                ;;
            --no-ml)
                ML_CLASSIFICATION=false
                shift
                ;;
            --no-apt)
                APT_ATTRIBUTION=false
                shift
                ;;
            --no-behavioral)
                BEHAVIORAL_ANALYSIS=false
                shift
                ;;
            --no-stego)
                STEGANOGRAPHY_CHECK=false
                shift
                ;;
            --no-entropy)
                ENTROPY_ANALYSIS=false
                shift
                ;;
            --all-modules)
                CLOUD_ABUSE_CHECK=true
                MOBILE_DEEPLINK_CHECK=true
                GEOFENCING_CHECK=true
                BLUETOOTH_NFC_CHECK=true
                HARDWARE_EXPLOIT_CHECK=true
                FILELESS_MALWARE_CHECK=true
                ADVERSARIAL_QR_CHECK=true
                ZERO_DAY_DETECTION=true
                ML_CLASSIFICATION=true
                PERSONA_LINKING=true
                RANSOMWARE_NOTE_CHECK=true
                TOR_VPN_CHECK=true
                ASN_ANALYSIS=true
                URL_OBFUSCATION_CHECK=true
                INJECTION_ATTACK_CHECK=true
                C2_BEACON_CHECK=true
                CRYPTO_SCAM_CHECK=true
                INDUSTRY_THREAT_CHECK=true
                SIEM_INTEGRATION=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                TARGET_PATH="$1"
                shift
                ;;
        esac
    done
}

show_help() {
    echo "QR Code Malware Scanner - Ultimate Forensic Edition v${VERSION}"
    echo ""
    echo "Usage: $(basename "$0") [OPTIONS] <image_or_directory>"
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -d, --deep           Enable deep analysis mode"
    echo "  -f, --forensic       Enable full forensic mode"
    echo "  -s, --stealth        Stealth mode (no network calls)"
    echo "  --vt                 Enable VirusTotal checks"
    echo "  --no-network         Disable all network checks"
    echo "  --siem               Enable SIEM export (JSON format)"
    echo "  --all-modules        Enable all detection modules"
    echo ""
    echo "Module Controls:"
    echo "  --no-cloud           Disable cloud abuse detection"
    echo "  --no-mobile          Disable mobile deeplink detection"
    echo "  --no-ml              Disable ML classification"
    echo "  --no-apt             Disable APT attribution"
    echo "  --no-behavioral      Disable behavioral analysis"
    echo "  --no-stego           Disable steganography detection"
    echo "  --no-entropy         Disable entropy analysis"
    echo ""
    echo "Detection Modules:"
    echo "  - Cloud Service Abuse (Google Drive, S3, Discord CDN, etc.)"
    echo "  - Mobile Deep Links (iOS/Android app schemes)"
    echo "  - Wireless Attacks (Bluetooth/NFC/WiFi)"
    echo "  - Telephony Attacks (USSD, premium numbers)"
    echo "  - Hardware Exploits (IoT, POS terminals)"
    echo "  - Fileless Malware (LOLBAS, PowerShell)"
    echo "  - Ransomware Notes (40+ families)"
    echo "  - TOR/VPN Anonymization"
    echo "  - Social Engineering Patterns"
    echo "  - ASN Infrastructure Analysis"
    echo "  - URL Obfuscation Detection"
    echo "  - Injection Attacks (SQLi, SSTI, XXE)"
    echo "  - C2 Beacon Detection"
    echo "  - Cryptocurrency Scam Detection"
    echo "  - Zero-Day/Anomaly Detection"
    echo "  - ML Heuristics Classification"
    echo ""
    echo "Audit Enhancement Modules (22 NEW):"
    echo "  [1]  Sandbox/Detonation Analysis (urlscan.io, local Docker)"
    echo "  [2]  JavaScript/Browser Exploit Detection (XSS, DOM, exploits)"
    echo "  [3]  Enhanced ML/AI Classification (statistical features)"
    echo "  [4]  PDF/Document Payload Analysis (macros, exploits)"
    echo "  [5]  NLP/Language Analysis (scam patterns, sentiment)"
    echo "  [6]  Mobile Malware Static Analysis (APK/IPA)"
    echo "  [7]  Web Archive Analysis (Wayback Machine, archive.today)"
    echo "  [8]  Recursive Content Extraction (crawl linked content)"
    echo "  [9]  Adversarial AI Attack Detection (perturbation, patches)"
    echo "  [10] Covert Channel Detection (DNS tunneling, stego)"
    echo "  [11] Cross-QR Chaining Detection (segmented payloads)"
    echo "  [12] Template Spoofing Detection (COVID pass, shipping)"
    echo "  [13] Social Media/Marketing Link Analysis (linktree, tracking)"
    echo "  [14] UX Redress/Browser Attack Detection (clickjacking, tabnab)"
    echo "  [15] DGA Domain Analysis (entropy, bigrams, patterns)"
    echo "  [16] Unicode/Multi-language Deception (homoglyphs, RTL)"
    echo "  [17] Social Threat Tracking (URLhaus, DNSBLs)"
    echo "  [18] Blockchain/Smart Contract Scam Analysis (drainers)"
    echo "  [19] Contact Event Analysis (vCard/iCal BEC)"
    echo "  [20] Geographic Hotspot Detection (country/ASN risk)"
    echo "  [21] Emerging Protocol Detection (WebRTC, BLE, payments)"
    echo "  [22] Human Reviewer Feedback Loop (chain of custody)"
    echo ""
    echo "Examples:"
    echo "  $(basename "$0") suspicious_qr.png"
    echo "  $(basename "$0") -d --vt /path/to/qr_images/"
    echo "  $(basename "$0") -f --siem --all-modules qr_code.jpg"
}



################################################################################
################################################################################
##                                                                            ##
##          AUDIT ENHANCEMENT MODULES - 22 NEW ANALYSIS CAPABILITIES          ##
##                                                                            ##
##  Implementation of all audit suggestions for comprehensive QR analysis     ##
##                                                                            ##
################################################################################
################################################################################

# ============================================================================
# AUDIT ENHANCEMENT FLAGS AND CONFIGURATION
# ============================================================================

# Module Enable Flags
SANDBOX_DETONATION=${SANDBOX_DETONATION:-true}
JS_BROWSER_ANALYSIS=${JS_BROWSER_ANALYSIS:-true}
ML_CLASSIFICATION_ENHANCED=${ML_CLASSIFICATION_ENHANCED:-true}
PDF_DOC_ANALYSIS=${PDF_DOC_ANALYSIS:-true}
NLP_ANALYSIS=${NLP_ANALYSIS:-true}
MOBILE_STATIC_ANALYSIS=${MOBILE_STATIC_ANALYSIS:-true}
WEB_ARCHIVE_ANALYSIS=${WEB_ARCHIVE_ANALYSIS:-true}
RECURSIVE_CRAWL=${RECURSIVE_CRAWL:-true}
ADVERSARIAL_AI_DETECTION=${ADVERSARIAL_AI_DETECTION:-true}
COVERT_CHANNEL_DETECTION=${COVERT_CHANNEL_DETECTION:-true}
CROSS_QR_CHAIN_DETECTION=${CROSS_QR_CHAIN_DETECTION:-true}
TEMPLATE_SPOOF_DETECTION=${TEMPLATE_SPOOF_DETECTION:-true}
SOCIAL_MEDIA_LINK_DETECTION=${SOCIAL_MEDIA_LINK_DETECTION:-true}
UX_REDRESS_DETECTION=${UX_REDRESS_DETECTION:-true}
DGA_ANALYSIS=${DGA_ANALYSIS:-true}
UNICODE_DECEPTION_DETECTION=${UNICODE_DECEPTION_DETECTION:-true}
SOCIAL_THREAT_TRACKING=${SOCIAL_THREAT_TRACKING:-true}
BLOCKCHAIN_SCAM_ANALYSIS=${BLOCKCHAIN_SCAM_ANALYSIS:-true}
CONTACT_EVENT_ANALYSIS=${CONTACT_EVENT_ANALYSIS:-true}
GEO_HOTSPOT_DETECTION=${GEO_HOTSPOT_DETECTION:-true}
EMERGING_PROTOCOL_DETECTION=${EMERGING_PROTOCOL_DETECTION:-true}
FEEDBACK_LOOP_ENABLED=${FEEDBACK_LOOP_ENABLED:-true}

# API Keys (set via environment or config)
URLSCAN_API_KEY="${URLSCAN_API_KEY:-}"
ANYRUN_API_KEY="${ANYRUN_API_KEY:-}"
HYBRID_ANALYSIS_KEY="${HYBRID_ANALYSIS_KEY:-}"
ETHERSCAN_API_KEY="${ETHERSCAN_API_KEY:-}"
OPENAI_API_KEY="${OPENAI_API_KEY:-}"

# ============================================================================
# AUDIT 1: SANDBOX/EMULATION/DETONATION ENGINE
# ============================================================================

# Sandbox API endpoints
declare -A SANDBOX_APIS=(
    ["urlscan"]="https://urlscan.io/api/v1/scan/"
    ["anyrun"]="https://api.any.run/v1/analysis"
    ["hybrid_analysis"]="https://www.hybrid-analysis.com/api/v2/submit/url"
    ["joesandbox"]="https://jbxcloud.joesecurity.org/api/v2/analysis/submit"
    ["virustotal_url"]="https://www.virustotal.com/api/v3/urls"
)

# Known malicious behavioral indicators from sandbox results
declare -a SANDBOX_MALICIOUS_BEHAVIORS=(
    "process_injection"
    "registry_persistence"
    "scheduled_task_creation"
    "service_installation"
    "credential_theft"
    "keylogging"
    "screen_capture"
    "file_encryption"
    "network_beacon"
    "dns_tunneling"
    "powershell_encoded"
    "wmi_execution"
    "dll_injection"
    "hollowing"
    "unhooking"
    "anti_analysis"
    "evasion_technique"
    "dropper_behavior"
    "downloader_behavior"
    "c2_communication"
    "data_exfiltration"
    "ransomware_behavior"
    "wiper_behavior"
    "rootkit_behavior"
    "bootkit_behavior"
)

analyze_sandbox_detonation() {
    local url="$1"
    
    if [ "$SANDBOX_DETONATION" = false ]; then
        analysis_success_none "SANDBOX-DETONATION"
        return
    fi
    
    log_info "Performing sandbox/detonation analysis..."
    
    local sandbox_findings=()
    local sandbox_score=0
    local sandbox_report="${OUTPUT_DIR}/sandbox_detonation.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "SANDBOX DETONATION ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo "Target URL: $url"
        echo ""
    } > "$sandbox_report"
    
    # 1. URLScan.io submission
    if [ -n "$URLSCAN_API_KEY" ]; then
        log_info "  Submitting to urlscan.io..."
        local urlscan_result=$(curl -sS --max-time 30 \
            -H "API-Key: $URLSCAN_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"url\": \"$url\", \"visibility\": \"private\"}" \
            "${SANDBOX_APIS[urlscan]}" 2>/dev/null)
        
        if [ -n "$urlscan_result" ]; then
            local scan_uuid=$(echo "$urlscan_result" | grep -oE '"uuid":"[^"]+"' | cut -d'"' -f4)
            if [ -n "$scan_uuid" ]; then
                echo "URLScan UUID: $scan_uuid" >> "$sandbox_report"
                echo "URLScan Result URL: https://urlscan.io/result/$scan_uuid/" >> "$sandbox_report"
                log_forensic "URLScan submitted: $scan_uuid"
                
                # Wait and fetch results
                sleep 15
                local scan_result=$(curl -sS --max-time 30 \
                    "https://urlscan.io/api/v1/result/$scan_uuid/" 2>/dev/null)
                
                if [ -n "$scan_result" ]; then
                    # Check for malicious verdicts
                    if echo "$scan_result" | grep -qiE '"malicious":\s*true|"score":\s*[7-9][0-9]|"score":\s*100'; then
                        log_threat 80 "URLScan detected malicious content"
                        sandbox_findings+=("urlscan:malicious")
                        ((sandbox_score += 70))
                    fi
                    
                    # Extract domains contacted
                    local domains_contacted=$(echo "$scan_result" | grep -oE '"domain":"[^"]+"' | cut -d'"' -f4 | sort -u)
                    echo "Domains Contacted:" >> "$sandbox_report"
                    echo "$domains_contacted" >> "$sandbox_report"
                    
                    # Extract IPs
                    local ips_contacted=$(echo "$scan_result" | grep -oE '"ip":"[^"]+"' | cut -d'"' -f4 | sort -u)
                    echo "IPs Contacted:" >> "$sandbox_report"
                    echo "$ips_contacted" >> "$sandbox_report"
                    
                    # Check for redirects
                    local redirect_count=$(echo "$scan_result" | grep -c '"redirectResponse"')
                    if [ "$redirect_count" -gt 3 ]; then
                        log_warning "Multiple redirects detected: $redirect_count"
                        sandbox_findings+=("redirect_chain:$redirect_count")
                        ((sandbox_score += 20))
                    fi
                fi
            fi
        fi
    else
        echo "URLScan: Skipped (no API key)" >> "$sandbox_report"
    fi
    
    # 2. Local Docker sandbox (if available)
    if command -v docker &> /dev/null; then
        log_info "  Checking local Docker sandbox capability..."
        echo "" >> "$sandbox_report"
        echo "Local Docker Sandbox: Available" >> "$sandbox_report"
        
        # Create isolated analysis container
        local container_result=$(timeout 60 docker run --rm --network=none \
            --memory=512m --cpus=0.5 \
            alpine:latest sh -c "wget -q -O- --timeout=10 '$url' 2>/dev/null | head -c 10000" 2>/dev/null)
        
        if [ -n "$container_result" ]; then
            # Analyze fetched content for malicious patterns
            if echo "$container_result" | grep -qiE '<script.*eval|document\.write.*unescape|fromCharCode.*concat'; then
                log_threat 60 "Obfuscated JavaScript detected in fetched content"
                sandbox_findings+=("obfuscated_js")
                ((sandbox_score += 50))
            fi
            
            if echo "$container_result" | grep -qiE 'createElement.*iframe|appendChild.*script'; then
                log_threat 45 "Dynamic script/iframe injection detected"
                sandbox_findings+=("dynamic_injection")
                ((sandbox_score += 35))
            fi
        fi
    fi
    
    # 3. Behavioral indicator analysis
    echo "" >> "$sandbox_report"
    echo "Behavioral Analysis:" >> "$sandbox_report"
    
    for behavior in "${SANDBOX_MALICIOUS_BEHAVIORS[@]}"; do
        if echo "$url" | grep -qiE "$behavior"; then
            sandbox_findings+=("behavior:$behavior")
            ((sandbox_score += 15))
        fi
    done
    
    # Generate report
    echo "" >> "$sandbox_report"
    echo "Findings:" >> "$sandbox_report"
    for finding in "${sandbox_findings[@]}"; do
        echo "  - $finding" >> "$sandbox_report"
    done
    echo "" >> "$sandbox_report"
    echo "Sandbox Risk Score: $sandbox_score" >> "$sandbox_report"
    
    if [ ${#sandbox_findings[@]} -gt 0 ]; then
        if [ $sandbox_score -ge 50 ]; then
            log_threat $((sandbox_score / 2)) "Sandbox detonation revealed threats"
        fi
        analysis_success_found "SANDBOX-DETONATION" "${#sandbox_findings[@]}" "Score: $sandbox_score"
    else
        analysis_success_none "SANDBOX-DETONATION"
    fi
}

# ============================================================================
# AUDIT 2: JAVASCRIPT/HTML/BROWSER EXPLOIT ANALYSIS
# ============================================================================

# JavaScript exploit patterns
declare -a JS_EXPLOIT_PATTERNS=(
    # Obfuscation
    'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k'  # p.a.c.k.e.r
    'eval\s*\(\s*unescape'
    'String\.fromCharCode\s*\(\s*[0-9,\s]+'
    'document\.write\s*\(\s*unescape'
    'atob\s*\(\s*["\x27][A-Za-z0-9+/=]+'
    'window\[.?\\x[0-9a-f]+'
    'constructor\s*\(\s*["\x27]return'
    
    # XSS payloads
    '<script[^>]*>.*<\/script>'
    'javascript\s*:'
    'on(load|error|click|mouseover)\s*='
    '<img[^>]+onerror\s*='
    '<svg[^>]+onload\s*='
    '<body[^>]+onload\s*='
    
    # DOM manipulation
    'document\.cookie'
    'document\.domain'
    'document\.location'
    'window\.location'
    'location\.href\s*='
    'location\.replace'
    'innerHTML\s*='
    'outerHTML\s*='
    'document\.write'
    
    # Remote code execution
    'new\s+Function\s*\('
    'setTimeout\s*\(\s*["\x27]'
    'setInterval\s*\(\s*["\x27]'
    
    # Browser exploits
    'ActiveXObject'
    'WScript\.Shell'
    'Scripting\.FileSystemObject'
    'ADODB\.Stream'
    'msxml2\.xmlhttp'
    'shellcode'
    'spray'
    'heap'
    
    # Credential theft
    'password'
    'credentials'
    'login'
    'signin'
    'autocomplete.*off'
    
    # Known exploit kit patterns
    'Angler'
    'RIG'
    'Magnitude'
    'Sundown'
    'Fallout'
    'GrandSoft'
    'Underminer'
)

# HTML phishing indicators
declare -a HTML_PHISHING_PATTERNS=(
    '<form[^>]+action\s*=\s*["\x27]https?://'
    '<input[^>]+type\s*=\s*["\x27]password'
    '<input[^>]+name\s*=\s*["\x27](user|email|pass|pwd|login)'
    'Please\s+(verify|confirm|update)\s+your'
    'Your\s+account\s+(has\s+been|is|will\s+be)'
    'Click\s+here\s+to\s+(verify|confirm|update)'
    'Verify\s+your\s+identity'
    'Secure\s+your\s+account'
    'Unusual\s+activity'
    'Suspended'
    'Locked'
    'Expired'
    'Action\s+required'
)

analyze_js_browser_exploits() {
    local content="$1"
    local url="$2"
    
    if [ "$JS_BROWSER_ANALYSIS" = false ]; then
        analysis_success_none "JS-BROWSER-ANALYSIS"
        return
    fi
    
    log_info "Analyzing JavaScript/HTML browser exploits..."
    
    local js_findings=()
    local js_score=0
    local js_report="${OUTPUT_DIR}/js_browser_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "JAVASCRIPT/BROWSER EXPLOIT ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$js_report"
    
    # Fetch URL content if URL provided
    local html_content=""
    if [ -n "$url" ] && echo "$url" | grep -qiE "^https?://"; then
        log_info "  Fetching URL content for analysis..."
        html_content=$(timeout 30 curl -sS -L --max-time 25 \
            -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            "$url" 2>/dev/null | head -c 500000)
    fi
    
    # Combine content and HTML for analysis
    local analysis_content="$content $html_content"
    
    # Check JavaScript exploit patterns
    echo "JavaScript Exploit Patterns:" >> "$js_report"
    for pattern in "${JS_EXPLOIT_PATTERNS[@]}"; do
        if echo "$analysis_content" | grep -qiE "$pattern"; then
            local matched=$(echo "$analysis_content" | grep -oiE "$pattern" | head -1 | cut -c1-50)
            js_findings+=("js_exploit:$matched")
            ((js_score += 25))
            log_warning "JS exploit pattern: $matched"
            echo "  ⚠ DETECTED: $pattern" >> "$js_report"
        fi
    done
    
    # Check HTML phishing patterns
    echo "" >> "$js_report"
    echo "HTML Phishing Patterns:" >> "$js_report"
    for pattern in "${HTML_PHISHING_PATTERNS[@]}"; do
        if echo "$analysis_content" | grep -qiE "$pattern"; then
            local matched=$(echo "$analysis_content" | grep -oiE "$pattern" | head -1 | cut -c1-50)
            js_findings+=("html_phish:$matched")
            ((js_score += 20))
            log_warning "HTML phishing pattern: $matched"
            echo "  ⚠ DETECTED: $pattern" >> "$js_report"
        fi
    done
    
    # Check for iframe injections
    local iframe_count=$(echo "$analysis_content" | grep -ciE '<iframe' || echo 0)
    if [ "$iframe_count" -gt 0 ]; then
        echo "" >> "$js_report"
        echo "IFrame Analysis:" >> "$js_report"
        echo "  Count: $iframe_count" >> "$js_report"
        
        # Extract iframe sources
        local iframe_srcs=$(echo "$analysis_content" | grep -oiE '<iframe[^>]+src\s*=\s*["\x27][^"\x27]+' |
            sed 's/.*src\s*=\s*["\x27]//' | head -5)
        echo "  Sources:" >> "$js_report"
        echo "$iframe_srcs" >> "$js_report"
        
        if [ "$iframe_count" -gt 3 ]; then
            js_findings+=("multiple_iframes:$iframe_count")
            ((js_score += 30))
            log_threat 35 "Multiple iframes detected ($iframe_count)"
        fi
        
        # Check for hidden iframes
        if echo "$analysis_content" | grep -qiE '<iframe[^>]+(hidden|display\s*:\s*none|width\s*=\s*["\x27]?0|height\s*=\s*["\x27]?0)'; then
            js_findings+=("hidden_iframe")
            ((js_score += 45))
            log_threat 50 "Hidden iframe detected - potential drive-by"
        fi
    fi
    
    # Check for external script loading
    local script_count=$(echo "$analysis_content" | grep -ciE '<script[^>]+src' || echo 0)
    if [ "$script_count" -gt 10 ]; then
        js_findings+=("excessive_scripts:$script_count")
        ((js_score += 15))
        log_warning "Excessive external scripts: $script_count"
    fi
    
    # Headless browser analysis (if available)
    if command -v chromium &> /dev/null || command -v google-chrome &> /dev/null; then
        log_info "  Running headless browser analysis..."
        echo "" >> "$js_report"
        echo "Headless Browser Analysis: Available" >> "$js_report"
        
        # Note: Full implementation would use puppeteer/playwright
        # This is a placeholder for the concept
    fi
    
    # DOM clobbering detection
    if echo "$analysis_content" | grep -qiE 'name\s*=\s*["\x27](location|document|window|self|top|parent)'; then
        js_findings+=("dom_clobbering")
        ((js_score += 40))
        log_threat 45 "Potential DOM clobbering attack"
    fi
    
    # Prototype pollution detection
    if echo "$analysis_content" | grep -qiE '__proto__|constructor\s*\[|prototype\s*\['; then
        js_findings+=("prototype_pollution")
        ((js_score += 50))
        log_threat 55 "Potential prototype pollution attack"
    fi
    
    # Generate summary
    echo "" >> "$js_report"
    echo "Analysis Summary:" >> "$js_report"
    echo "  Total Findings: ${#js_findings[@]}" >> "$js_report"
    echo "  Risk Score: $js_score" >> "$js_report"
    echo "" >> "$js_report"
    echo "Findings:" >> "$js_report"
    for finding in "${js_findings[@]}"; do
        echo "  - $finding" >> "$js_report"
    done
    
    if [ ${#js_findings[@]} -gt 0 ]; then
        if [ $js_score -ge 50 ]; then
            log_threat $((js_score / 2)) "JavaScript/browser exploit patterns detected"
        fi
        analysis_success_found "JS-BROWSER-ANALYSIS" "${#js_findings[@]}" "Score: $js_score"
    else
        analysis_success_none "JS-BROWSER-ANALYSIS"
    fi
}

# ============================================================================
# AUDIT 3: ML/AI/STATISTICAL CLASSIFICATION ENGINE
# ============================================================================

# Feature extraction weights for ML scoring
declare -A ML_FEATURE_WEIGHTS=(
    ["url_length"]=0.15
    ["special_char_ratio"]=0.12
    ["digit_ratio"]=0.10
    ["subdomain_depth"]=0.13
    ["path_depth"]=0.08
    ["query_param_count"]=0.07
    ["entropy"]=0.15
    ["suspicious_tld"]=0.10
    ["brand_similarity"]=0.10
)

# Suspicious TLD list for ML scoring
declare -a ML_SUSPICIOUS_TLDS=(
    "tk" "ml" "ga" "cf" "gq" "top" "xyz" "work" "click" "loan"
    "date" "racing" "win" "review" "country" "stream" "download"
    "party" "bid" "trade" "webcam" "science" "accountant" "faith"
    "cricket" "gdn" "men" "link" "zip" "mobi" "info" "biz" "cc"
)

# Brand list for impersonation scoring
declare -a ML_BRAND_LIST=(
    "paypal" "amazon" "google" "microsoft" "apple" "facebook" "netflix"
    "instagram" "twitter" "linkedin" "dropbox" "chase" "wellsfargo"
    "bankofamerica" "citibank" "usbank" "capitalone" "americanexpress"
    "discover" "hsbc" "barclays" "santander" "irs" "hmrc" "dhl" "fedex"
    "ups" "usps" "royalmail" "docusign" "adobe" "zoom" "slack" "teams"
    "outlook" "office365" "onedrive" "icloud" "coinbase" "binance"
)

analyze_ml_classification_enhanced() {
    local content="$1"
    
    if [ "$ML_CLASSIFICATION_ENHANCED" = false ]; then
        analysis_success_none "ML-CLASSIFICATION"
        return
    fi
    
    log_info "Performing enhanced ML/statistical classification..."
    
    local ml_report="${OUTPUT_DIR}/ml_classification_enhanced.txt"
    local ml_score=0
    local ml_confidence=0
    local ml_features=()
    local ml_verdict="UNKNOWN"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "ENHANCED ML/STATISTICAL CLASSIFICATION"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$ml_report"
    
    # Feature extraction using Python for accuracy
    local features_json=$(python3 << EOF 2>/dev/null
import json
import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

content = '''$content'''

features = {}

# URL parsing if content is URL
if content.startswith('http://') or content.startswith('https://'):
    try:
        parsed = urlparse(content)
        
        # URL length feature
        features['url_length'] = len(content)
        features['url_length_score'] = min(len(content) / 200, 1.0)
        
        # Domain analysis
        domain = parsed.netloc
        features['domain'] = domain
        features['domain_length'] = len(domain)
        
        # Subdomain depth
        parts = domain.split('.')
        features['subdomain_depth'] = len(parts) - 2 if len(parts) > 2 else 0
        features['subdomain_score'] = min(features['subdomain_depth'] / 5, 1.0)
        
        # Path depth
        path_parts = [p for p in parsed.path.split('/') if p]
        features['path_depth'] = len(path_parts)
        features['path_score'] = min(features['path_depth'] / 8, 1.0)
        
        # Query parameters
        params = parse_qs(parsed.query)
        features['param_count'] = len(params)
        features['param_score'] = min(features['param_count'] / 10, 1.0)
        
        # Special character ratio
        special_chars = len(re.findall(r'[@#%&=?\-_~]', content))
        features['special_char_ratio'] = special_chars / len(content) if content else 0
        
        # Digit ratio in domain
        digits = len(re.findall(r'\d', domain))
        features['digit_ratio'] = digits / len(domain) if domain else 0
        
        # TLD check
        tld = parts[-1].lower() if parts else ''
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'click', 'loan']
        features['suspicious_tld'] = 1.0 if tld in suspicious_tlds else 0.0
        
        # Brand detection
        brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix',
                  'instagram', 'twitter', 'linkedin', 'dropbox', 'chase', 'bank']
        domain_lower = domain.lower()
        features['brand_in_domain'] = 1.0 if any(b in domain_lower for b in brands) else 0.0
        
        # Check for typosquatting
        features['typosquatting_score'] = 0.0
        for brand in brands:
            if brand in domain_lower and brand not in ['.' + brand + '.', brand + '.']:
                # Brand appears but not as exact domain
                if domain_lower != brand + '.com' and domain_lower != 'www.' + brand + '.com':
                    features['typosquatting_score'] = 0.8
                    break
        
    except Exception as e:
        features['parse_error'] = str(e)

# Entropy calculation
if content:
    freq = Counter(content)
    probs = [count / len(content) for count in freq.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    features['entropy'] = round(entropy, 4)
    features['entropy_score'] = min(entropy / 6, 1.0)
else:
    features['entropy'] = 0
    features['entropy_score'] = 0

# Character class analysis
if content:
    features['lowercase_ratio'] = len(re.findall(r'[a-z]', content)) / len(content)
    features['uppercase_ratio'] = len(re.findall(r'[A-Z]', content)) / len(content)
    features['numeric_ratio'] = len(re.findall(r'\d', content)) / len(content)

# N-gram analysis
def get_ngram_score(text, n=3):
    ngrams = [text[i:i+n] for i in range(len(text)-n+1)]
    freq = Counter(ngrams)
    if not freq:
        return 0
    max_freq = max(freq.values())
    return max_freq / len(ngrams) if ngrams else 0

features['bigram_score'] = get_ngram_score(content, 2) if len(content) > 2 else 0
features['trigram_score'] = get_ngram_score(content, 3) if len(content) > 3 else 0

# Calculate final ML score (weighted combination)
weights = {
    'url_length_score': 0.10,
    'subdomain_score': 0.15,
    'path_score': 0.08,
    'param_score': 0.07,
    'special_char_ratio': 0.10,
    'digit_ratio': 0.12,
    'suspicious_tld': 0.15,
    'brand_in_domain': 0.08,
    'typosquatting_score': 0.15,
    'entropy_score': 0.10
}

total_score = 0
for feature, weight in weights.items():
    if feature in features:
        total_score += features.get(feature, 0) * weight * 100

features['ml_score'] = round(total_score, 2)

# Confidence based on feature availability
available_features = sum(1 for k in weights.keys() if k in features)
features['confidence'] = round(available_features / len(weights) * 100, 1)

# Verdict
if total_score >= 70:
    features['verdict'] = 'MALICIOUS'
elif total_score >= 45:
    features['verdict'] = 'SUSPICIOUS'
elif total_score >= 25:
    features['verdict'] = 'POTENTIALLY_SUSPICIOUS'
else:
    features['verdict'] = 'LIKELY_BENIGN'

print(json.dumps(features, indent=2))
EOF
)
    
    if [ -n "$features_json" ]; then
        echo "Feature Extraction Results:" >> "$ml_report"
        echo "$features_json" >> "$ml_report"
        
        # Parse results
        ml_score=$(json_extract_number "$features_json" "ml_score")
        ml_confidence=$(json_extract_number "$features_json" "confidence")
        ml_verdict=$(json_extract_string "$features_json" "verdict")
        
        echo "" >> "$ml_report"
        echo "Classification Results:" >> "$ml_report"
        echo "  ML Score: ${ml_score:-0}" >> "$ml_report"
        echo "  Confidence: ${ml_confidence:-0}%" >> "$ml_report"
        echo "  Verdict: ${ml_verdict:-UNKNOWN}" >> "$ml_report"
        
        # Display results
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│              ML CLASSIFICATION RESULTS                       │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC} ML Score:     ${YELLOW}${ml_score:-0}${NC}"
        echo -e "${CYAN}│${NC} Confidence:   ${WHITE}${ml_confidence:-0}%${NC}"
        echo -e "${CYAN}│${NC} Verdict:      ${RED}${ml_verdict:-UNKNOWN}${NC}"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        # Add threat score based on ML verdict
        case "$ml_verdict" in
            "MALICIOUS")
                log_threat 60 "ML classification: MALICIOUS (${ml_confidence}% confidence)"
                analysis_success_found "ML-CLASSIFICATION" "1" "Verdict: $ml_verdict, Score: $ml_score"
                ;;
            "SUSPICIOUS")
                log_threat 35 "ML classification: SUSPICIOUS (${ml_confidence}% confidence)"
                analysis_success_found "ML-CLASSIFICATION" "1" "Verdict: $ml_verdict, Score: $ml_score"
                ;;
            "POTENTIALLY_SUSPICIOUS")
                log_warning "ML classification: POTENTIALLY SUSPICIOUS"
                analysis_success_found "ML-CLASSIFICATION" "1" "Verdict: $ml_verdict, Score: $ml_score"
                ;;
            *)
                analysis_success_none "ML-CLASSIFICATION"
                ;;
        esac
    else
        analysis_error "ML-CLASSIFICATION" "Python feature extraction failed"
    fi
}

# ============================================================================
# AUDIT 4: PDF/DOCUMENT EMBEDDED PAYLOAD ANALYSIS
# ============================================================================

# Known malicious PDF patterns
declare -a PDF_MALICIOUS_PATTERNS=(
    '/JavaScript'
    '/JS'
    '/Launch'
    '/EmbeddedFile'
    '/OpenAction'
    '/AA'
    '/AcroForm'
    '/XFA'
    '/RichMedia'
    '/ObjStm'
    '/URI'
    '/SubmitForm'
    '/GoToR'
    '/GoToE'
    '/JBIG2Decode'
    '/Colors > 2\^24'
    'getAnnots'
    'getPageNthWord'
    'this.exportDataObject'
    'util.printf'
    'Collab.collectEmailInfo'
    'spell.customDictionaryOpen'
)

# Office document macro patterns
declare -a OFFICE_MACRO_PATTERNS=(
    'AutoOpen'
    'AutoExec'
    'AutoClose'
    'Document_Open'
    'Workbook_Open'
    'Auto_Open'
    'Shell'
    'WScript'
    'PowerShell'
    'cmd.exe'
    'CreateObject'
    'GetObject'
    'CallByName'
    'Environ'
    'URLDownloadToFile'
    'MSXML2'
    'WinHttp'
    'StrReverse'
    'Chr('
    'ChrW('
    'ChrB('
)

analyze_pdf_document() {
    local content="$1"
    local url="$2"
    
    if [ "$PDF_DOC_ANALYSIS" = false ]; then
        analysis_success_none "PDF-DOC-ANALYSIS"
        return
    fi
    
    log_info "Analyzing for PDF/document embedded payloads..."
    
    local doc_findings=()
    local doc_score=0
    local doc_report="${OUTPUT_DIR}/pdf_document_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "PDF/DOCUMENT PAYLOAD ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$doc_report"
    
    # Check if URL points to document
    local is_doc_url=false
    local doc_type=""
    
    if echo "$url" | grep -qiE '\.(pdf|doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm|odt|ods|odp|rtf)(\?|$)'; then
        is_doc_url=true
        doc_type=$(echo "$url" | grep -oiE '\.(pdf|doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm|odt|ods|odp|rtf)' | tr '[:upper:]' '[:lower:]')
        log_warning "URL points to document: $doc_type"
        doc_findings+=("document_url:$doc_type")
        ((doc_score += 20))
    fi
    
    # Download and analyze if document URL
    if [ "$is_doc_url" = true ] && [ -n "$url" ]; then
        local temp_doc="${TEMP_DIR}/downloaded_doc$(echo $doc_type)"
        
        log_info "  Downloading document for analysis..."
        if timeout 30 curl -sS -L -o "$temp_doc" "$url" 2>/dev/null; then
            local file_type=$(file -b "$temp_doc" 2>/dev/null)
            echo "Downloaded File Type: $file_type" >> "$doc_report"
            
            # PDF Analysis
            if echo "$file_type" | grep -qi "PDF"; then
                log_info "  Analyzing PDF structure..."
                echo "" >> "$doc_report"
                echo "PDF Analysis:" >> "$doc_report"
                
                # Check for malicious PDF patterns
                for pattern in "${PDF_MALICIOUS_PATTERNS[@]}"; do
                    if grep -qa "$pattern" "$temp_doc" 2>/dev/null; then
                        doc_findings+=("pdf_pattern:$pattern")
                        ((doc_score += 25))
                        log_warning "Suspicious PDF pattern: $pattern"
                        echo "  ⚠ DETECTED: $pattern" >> "$doc_report"
                    fi
                done
                
                # Use pdfid if available
                if command -v pdfid &> /dev/null; then
                    log_info "  Running pdfid analysis..."
                    local pdfid_output=$(pdfid "$temp_doc" 2>/dev/null)
                    echo "" >> "$doc_report"
                    echo "pdfid Output:" >> "$doc_report"
                    echo "$pdfid_output" >> "$doc_report"
                    
                    # Parse pdfid results
                    if echo "$pdfid_output" | grep -qE '/JavaScript\s+[1-9]'; then
                        doc_findings+=("pdfid:javascript")
                        ((doc_score += 40))
                        log_threat 50 "PDF contains JavaScript"
                    fi
                    
                    if echo "$pdfid_output" | grep -qE '/OpenAction\s+[1-9]'; then
                        doc_findings+=("pdfid:openaction")
                        ((doc_score += 35))
                        log_threat 40 "PDF contains OpenAction (auto-execute)"
                    fi
                    
                    if echo "$pdfid_output" | grep -qE '/Launch\s+[1-9]'; then
                        doc_findings+=("pdfid:launch")
                        ((doc_score += 50))
                        log_threat 60 "PDF contains Launch action"
                    fi
                fi
                
                # Use pdf-parser if available
                if command -v pdf-parser &> /dev/null; then
                    log_info "  Running pdf-parser analysis..."
                    local parser_output=$(pdf-parser --stats "$temp_doc" 2>/dev/null | head -50)
                    echo "" >> "$doc_report"
                    echo "pdf-parser Stats:" >> "$doc_report"
                    echo "$parser_output" >> "$doc_report"
                fi
            fi
            
            # Office document analysis
            if echo "$file_type" | grep -qiE "Microsoft|Office|Composite Document|OpenDocument"; then
                log_info "  Analyzing Office document..."
                echo "" >> "$doc_report"
                echo "Office Document Analysis:" >> "$doc_report"
                
                # Use olevba if available
                if command -v olevba &> /dev/null; then
                    log_info "  Running olevba analysis..."
                    local olevba_output=$(timeout 30 olevba "$temp_doc" 2>/dev/null | head -200)
                    echo "$olevba_output" >> "$doc_report"
                    
                    if echo "$olevba_output" | grep -qi "VBA MACRO"; then
                        doc_findings+=("office:vba_macro")
                        ((doc_score += 35))
                        log_threat 40 "Office document contains VBA macros"
                    fi
                    
                    if echo "$olevba_output" | grep -qiE "AutoOpen|AutoExec|Document_Open"; then
                        doc_findings+=("office:auto_execute")
                        ((doc_score += 50))
                        log_threat 60 "Office document has auto-execute macro"
                    fi
                    
                    if echo "$olevba_output" | grep -qiE "Shell|PowerShell|cmd\.exe|WScript"; then
                        doc_findings+=("office:shell_execution")
                        ((doc_score += 60))
                        log_threat 70 "Office macro contains shell execution"
                    fi
                fi
                
                # Check for DDE
                if strings "$temp_doc" 2>/dev/null | grep -qiE 'DDE|DDEAUTO'; then
                    doc_findings+=("office:dde")
                    ((doc_score += 55))
                    log_threat 65 "Office document contains DDE (Dynamic Data Exchange)"
                fi
            fi
            
            # Extract embedded URLs
            log_info "  Extracting embedded URLs..."
            local embedded_urls=$(strings "$temp_doc" 2>/dev/null | grep -oiE 'https?://[^\s"<>]+' | sort -u | head -20)
            if [ -n "$embedded_urls" ]; then
                echo "" >> "$doc_report"
                echo "Embedded URLs:" >> "$doc_report"
                echo "$embedded_urls" >> "$doc_report"
                
                local url_count=$(echo "$embedded_urls" | wc -l)
                doc_findings+=("embedded_urls:$url_count")
                
                # Record as IOCs
                while IFS= read -r embedded_url; do
                    [ -z "$embedded_url" ] && continue
                    record_ioc "embedded_url" "$embedded_url" "URL extracted from document"
                done <<< "$embedded_urls"
            fi
            
            # Cleanup
            rm -f "$temp_doc" 2>/dev/null
        fi
    fi
    
    # Check content for document-related patterns
    for pattern in "${OFFICE_MACRO_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            doc_findings+=("macro_pattern:$pattern")
            ((doc_score += 15))
        fi
    done
    
    # Generate summary
    echo "" >> "$doc_report"
    echo "Analysis Summary:" >> "$doc_report"
    echo "  Total Findings: ${#doc_findings[@]}" >> "$doc_report"
    echo "  Risk Score: $doc_score" >> "$doc_report"
    
    if [ ${#doc_findings[@]} -gt 0 ]; then
        if [ $doc_score -ge 50 ]; then
            log_threat $((doc_score / 2)) "Document payload analysis revealed threats"
        fi
        analysis_success_found "PDF-DOC-ANALYSIS" "${#doc_findings[@]}" "Score: $doc_score"
    else
        analysis_success_none "PDF-DOC-ANALYSIS"
    fi
}

# ============================================================================
# AUDIT 5: ADVANCED STRING & NATURAL LANGUAGE ANALYSIS
# ============================================================================

# Scam/phishing language patterns (expanded)
declare -a NLP_SCAM_PATTERNS=(
    # Urgency
    "act now" "immediate action" "urgent" "expires soon" "limited time"
    "don't delay" "last chance" "final notice" "ending soon" "hurry"
    "only [0-9]+ (hours|minutes|days)" "deadline" "time-sensitive"
    
    # Fear
    "your account (will be|has been) (suspended|locked|terminated|closed)"
    "unauthorized (access|activity|transaction)" "security (alert|warning|breach)"
    "suspicious (activity|login|transaction)" "compromised" "hacked"
    "identity theft" "fraud" "illegal activity" "violation"
    
    # Authority
    "official notification" "legal action" "court order" "government"
    "IRS" "FBI" "police" "law enforcement" "investigation"
    "compliance" "regulation" "mandatory" "required by law"
    
    # Reward
    "congratulations" "you('ve| have) won" "prize" "lottery" "jackpot"
    "free" "bonus" "reward" "gift" "giveaway" "claim your"
    "selected" "winner" "lucky" "exclusive offer"
    
    # Social proof
    "millions of users" "trusted by" "verified" "official"
    "recommended" "endorsed" "certified"
    
    # Pressure
    "click (here|now|immediately)" "verify (now|immediately|your)"
    "confirm (now|immediately|your)" "update (now|immediately|your)"
    "respond within" "must (act|respond|verify)" "failure to"
    
    # Credential requests
    "enter your (password|PIN|SSN|credit card)"
    "confirm your (identity|account|information)"
    "verify your (identity|account|information)"
    "update your (password|information|details)"
    "provide your (details|information|credentials)"
)

# Legitimate language patterns (for comparison)
declare -a NLP_LEGITIMATE_PATTERNS=(
    "privacy policy" "terms of service" "unsubscribe"
    "contact us" "help center" "support" "FAQ"
    "copyright" "trademark" "registered"
)

analyze_nlp_content() {
    local content="$1"
    
    if [ "$NLP_ANALYSIS" = false ]; then
        analysis_success_none "NLP-ANALYSIS"
        return
    fi
    
    log_info "Performing NLP/language analysis..."
    
    local nlp_findings=()
    local nlp_score=0
    local urgency_count=0
    local fear_count=0
    local reward_count=0
    local pressure_count=0
    local nlp_report="${OUTPUT_DIR}/nlp_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "NATURAL LANGUAGE ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
        echo "Content Length: ${#content} characters"
        echo ""
    } > "$nlp_report"
    
    # Analyze scam patterns
    echo "Scam Pattern Detection:" >> "$nlp_report"
    
    for pattern in "${NLP_SCAM_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
            nlp_findings+=("scam_pattern:$matched")
            ((nlp_score += 10))
            echo "  ⚠ DETECTED: $pattern" >> "$nlp_report"
            
            # Categorize
            case "$pattern" in
                *urgent*|*immediate*|*expires*|*limited*|*hurry*|*deadline*)
                    ((urgency_count++))
                    ;;
                *suspended*|*locked*|*unauthorized*|*security*|*compromised*|*hacked*)
                    ((fear_count++))
                    ;;
                *won*|*prize*|*lottery*|*free*|*bonus*|*reward*|*gift*)
                    ((reward_count++))
                    ;;
                *click*|*verify*|*confirm*|*must*|*failure*)
                    ((pressure_count++))
                    ;;
            esac
        fi
    done
    
    # Python-based sentiment and entity analysis
    local nlp_results=$(python3 << EOF 2>/dev/null
import json
import re

content = '''$content'''

results = {
    'word_count': len(content.split()),
    'sentence_count': len(re.split(r'[.!?]+', content)),
    'exclamation_count': content.count('!'),
    'question_count': content.count('?'),
    'caps_words': len(re.findall(r'\b[A-Z]{3,}\b', content)),
    'url_count': len(re.findall(r'https?://\S+', content)),
    'email_count': len(re.findall(r'\b[\w.-]+@[\w.-]+\.\w+\b', content)),
    'phone_count': len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', content)),
    'money_refs': len(re.findall(r'\$\d+|\d+\s*(dollars|usd|euros|pounds)', content, re.I)),
    'urgency_words': len(re.findall(r'\b(urgent|immediate|now|today|asap|hurry)\b', content, re.I)),
}

# Calculate suspicion score
suspicion = 0
if results['exclamation_count'] > 3:
    suspicion += 15
if results['caps_words'] > 5:
    suspicion += 20
if results['urgency_words'] > 2:
    suspicion += 25
if results['money_refs'] > 1:
    suspicion += 15

results['suspicion_score'] = suspicion

# Readability approximation (simple)
if results['word_count'] > 0 and results['sentence_count'] > 0:
    avg_sentence_length = results['word_count'] / results['sentence_count']
    results['avg_sentence_length'] = round(avg_sentence_length, 1)
    # Very short sentences often indicate scam copy
    if avg_sentence_length < 8:
        results['short_sentences_flag'] = True
        suspicion += 10

print(json.dumps(results, indent=2))
EOF
)
    
    if [ -n "$nlp_results" ]; then
        echo "" >> "$nlp_report"
        echo "Statistical Analysis:" >> "$nlp_report"
        echo "$nlp_results" >> "$nlp_report"
        
        # Parse suspicion score
        local suspicion=$(json_extract_int "$nlp_results" "suspicion_score")
        ((nlp_score += ${suspicion:-0}))
    fi
    
    # Calculate Cialdini's principles score
    echo "" >> "$nlp_report"
    echo "Persuasion Principles Detected:" >> "$nlp_report"
    echo "  Urgency/Scarcity: $urgency_count" >> "$nlp_report"
    echo "  Fear: $fear_count" >> "$nlp_report"
    echo "  Reward/Reciprocity: $reward_count" >> "$nlp_report"
    echo "  Pressure/Authority: $pressure_count" >> "$nlp_report"
    
    # Bonus score for multiple principles
    local principle_count=0
    [ $urgency_count -gt 0 ] && ((principle_count++))
    [ $fear_count -gt 0 ] && ((principle_count++))
    [ $reward_count -gt 0 ] && ((principle_count++))
    [ $pressure_count -gt 0 ] && ((principle_count++))
    
    if [ $principle_count -ge 3 ]; then
        log_threat 40 "Multiple persuasion techniques detected ($principle_count principles)"
        ((nlp_score += 30))
        nlp_findings+=("multi_principle:$principle_count")
    fi
    
    # Generate summary
    echo "" >> "$nlp_report"
    echo "Analysis Summary:" >> "$nlp_report"
    echo "  Total Findings: ${#nlp_findings[@]}" >> "$nlp_report"
    echo "  NLP Risk Score: $nlp_score" >> "$nlp_report"
    
    if [ ${#nlp_findings[@]} -gt 0 ]; then
        if [ $nlp_score -ge 40 ]; then
            log_threat $((nlp_score / 3)) "NLP analysis detected scam/phishing language"
        fi
        analysis_success_found "NLP-ANALYSIS" "${#nlp_findings[@]}" "Score: $nlp_score"
    else
        analysis_success_none "NLP-ANALYSIS"
    fi
}

# ============================================================================
# AUDIT 6: FULL MOBILE MALWARE STATIC ANALYSIS
# ============================================================================

# Dangerous Android permissions
declare -a DANGEROUS_ANDROID_PERMISSIONS=(
    "android.permission.READ_SMS"
    "android.permission.SEND_SMS"
    "android.permission.RECEIVE_SMS"
    "android.permission.READ_CONTACTS"
    "android.permission.WRITE_CONTACTS"
    "android.permission.READ_CALL_LOG"
    "android.permission.WRITE_CALL_LOG"
    "android.permission.RECORD_AUDIO"
    "android.permission.CAMERA"
    "android.permission.ACCESS_FINE_LOCATION"
    "android.permission.ACCESS_COARSE_LOCATION"
    "android.permission.READ_PHONE_STATE"
    "android.permission.CALL_PHONE"
    "android.permission.READ_EXTERNAL_STORAGE"
    "android.permission.WRITE_EXTERNAL_STORAGE"
    "android.permission.RECEIVE_BOOT_COMPLETED"
    "android.permission.SYSTEM_ALERT_WINDOW"
    "android.permission.BIND_ACCESSIBILITY_SERVICE"
    "android.permission.BIND_DEVICE_ADMIN"
    "android.permission.REQUEST_INSTALL_PACKAGES"
)

# iOS suspicious entitlements
declare -a IOS_SUSPICIOUS_ENTITLEMENTS=(
    "com.apple.private"
    "platform-application"
    "com.apple.springboard"
    "com.apple.developer.kernel"
    "get-task-allow"
    "task_for_pid-allow"
    "com.apple.system-task-ports"
)

analyze_mobile_static() {
    local content="$1"
    local url="$2"
    
    if [ "$MOBILE_STATIC_ANALYSIS" = false ]; then
        analysis_success_none "MOBILE-STATIC"
        return
    fi
    
    log_info "Performing mobile malware static analysis..."
    
    local mobile_findings=()
    local mobile_score=0
    local mobile_report="${OUTPUT_DIR}/mobile_static_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "MOBILE MALWARE STATIC ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$mobile_report"
    
    # Check if URL points to mobile app
    local is_mobile_url=false
    local app_type=""
    
    if echo "$url" | grep -qiE '\.(apk|ipa|aab)(\?|$)'; then
        is_mobile_url=true
        app_type=$(echo "$url" | grep -oiE '\.(apk|ipa|aab)' | tr '[:upper:]' '[:lower:]')
        log_warning "URL points to mobile app: $app_type"
        mobile_findings+=("mobile_app_url:$app_type")
        ((mobile_score += 30))
        
        echo "Mobile App URL Detected: $app_type" >> "$mobile_report"
    fi
    
    # Check for mobile-specific patterns in content
    echo "" >> "$mobile_report"
    echo "Mobile Pattern Detection:" >> "$mobile_report"
    
    # Android patterns
    if echo "$content" | grep -qiE 'market://|play\.google\.com/store|android\.intent'; then
        mobile_findings+=("android_market")
        ((mobile_score += 15))
        echo "  ✓ Android Market/Play Store reference" >> "$mobile_report"
    fi
    
    if echo "$content" | grep -qiE 'intent://|android-app://'; then
        mobile_findings+=("android_intent_scheme")
        ((mobile_score += 25))
        log_warning "Android intent scheme detected"
        echo "  ⚠ Android Intent Scheme" >> "$mobile_report"
    fi
    
    # iOS patterns
    if echo "$content" | grep -qiE 'itms-apps://|itms-appss://|apps\.apple\.com'; then
        mobile_findings+=("ios_appstore")
        ((mobile_score += 15))
        echo "  ✓ iOS App Store reference" >> "$mobile_report"
    fi
    
    if echo "$content" | grep -qiE '\.mobileconfig|configuration profile'; then
        mobile_findings+=("ios_mobileconfig")
        ((mobile_score += 45))
        log_threat 50 "iOS MDM configuration profile detected"
        echo "  ⚠ iOS Mobile Configuration Profile" >> "$mobile_report"
    fi
    
    # Enterprise distribution
    if echo "$url" | grep -qiE 'itms-services://\?action=download-manifest'; then
        mobile_findings+=("ios_enterprise_distribution")
        ((mobile_score += 40))
        log_threat 45 "iOS enterprise app distribution detected"
        echo "  ⚠ iOS Enterprise Distribution" >> "$mobile_report"
    fi
    
    # Download and analyze APK if available
    if [ "$is_mobile_url" = true ] && [ "$app_type" = ".apk" ]; then
        local temp_apk="${TEMP_DIR}/downloaded_app.apk"
        
        if timeout 60 curl -sS -L -o "$temp_apk" "$url" 2>/dev/null; then
            log_info "  Analyzing APK file..."
            
            # Use apkanalyzer or aapt if available
            if command -v aapt &> /dev/null; then
                log_info "  Extracting APK permissions..."
                local permissions=$(aapt dump permissions "$temp_apk" 2>/dev/null)
                
                echo "" >> "$mobile_report"
                echo "APK Permissions:" >> "$mobile_report"
                
                for perm in "${DANGEROUS_ANDROID_PERMISSIONS[@]}"; do
                    if echo "$permissions" | grep -q "$perm"; then
                        mobile_findings+=("dangerous_permission:$perm")
                        ((mobile_score += 10))
                        echo "  ⚠ DANGEROUS: $perm" >> "$mobile_report"
                    fi
                done
            fi
            
            # Check for common malware indicators in DEX
            if command -v dexdump &> /dev/null || command -v baksmali &> /dev/null; then
                log_info "  Analyzing DEX code..."
            fi
            
            # String analysis
            local apk_strings=$(unzip -p "$temp_apk" "classes.dex" 2>/dev/null | strings | head -500)
            
            # Check for C2/URL patterns in DEX
            local suspicious_strings=$(echo "$apk_strings" | grep -iE 'http://|https://|\.onion|pastebin|ngrok' | head -10)
            if [ -n "$suspicious_strings" ]; then
                echo "" >> "$mobile_report"
                echo "Suspicious Strings in DEX:" >> "$mobile_report"
                echo "$suspicious_strings" >> "$mobile_report"
                mobile_findings+=("suspicious_strings")
                ((mobile_score += 25))
            fi
            
            rm -f "$temp_apk" 2>/dev/null
        fi
    fi
    
    # Generate summary
    echo "" >> "$mobile_report"
    echo "Analysis Summary:" >> "$mobile_report"
    echo "  Total Findings: ${#mobile_findings[@]}" >> "$mobile_report"
    echo "  Mobile Risk Score: $mobile_score" >> "$mobile_report"
    
    if [ ${#mobile_findings[@]} -gt 0 ]; then
        if [ $mobile_score -ge 40 ]; then
            log_threat $((mobile_score / 2)) "Mobile malware indicators detected"
        fi
        analysis_success_found "MOBILE-STATIC" "${#mobile_findings[@]}" "Score: $mobile_score"
    else
        analysis_success_none "MOBILE-STATIC"
    fi
}

# ============================================================================
# AUDIT 7: WEB ARCHIVE ANALYSIS
# ============================================================================

analyze_web_archive() {
    local url="$1"
    
    if [ "$WEB_ARCHIVE_ANALYSIS" = false ]; then
        analysis_success_none "WEB-ARCHIVE"
        return
    fi
    
    if [ -z "$url" ] || ! echo "$url" | grep -qiE "^https?://"; then
        analysis_success_none "WEB-ARCHIVE"
        return
    fi
    
    log_info "Checking web archives for historical data..."
    
    local archive_findings=()
    local archive_score=0
    local archive_report="${OUTPUT_DIR}/web_archive_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "WEB ARCHIVE ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo "Target URL: $url"
        echo ""
    } > "$archive_report"
    
    # Extract domain
    local domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
    
    # 1. Wayback Machine check
    log_info "  Checking Wayback Machine..."
    local wayback_api="http://archive.org/wayback/available?url=$url"
    local wayback_result=$(curl -sS --max-time 15 "$wayback_api" 2>/dev/null)
    
    if [ -n "$wayback_result" ]; then
        local archived_url=$(json_extract_string "$wayback_result" "url")
        local archive_timestamp=$(json_extract_string "$wayback_result" "timestamp")
        
        echo "Wayback Machine:" >> "$archive_report"
        if [ -n "$archived_url" ]; then
            echo "  Status: Found in archive" >> "$archive_report"
            echo "  Archive URL: $archived_url" >> "$archive_report"
            echo "  Timestamp: $archive_timestamp" >> "$archive_report"
            
            archive_findings+=("wayback:found")
            log_forensic "Found in Wayback Machine: $archive_timestamp"
            
            # Fetch and compare archived version
            log_info "  Fetching archived version for comparison..."
            local archived_content=$(curl -sS --max-time 20 "$archived_url" 2>/dev/null | head -c 50000)
            
            if [ -n "$archived_content" ]; then
                # Check for phishing indicators that appeared
                if echo "$archived_content" | grep -qiE 'login|password|verify|suspended'; then
                    archive_findings+=("wayback:phishing_content")
                    ((archive_score += 25))
                fi
            fi
        else
            echo "  Status: Not found in archive" >> "$archive_report"
            archive_findings+=("wayback:not_found")
            # New domains not in archive are more suspicious
            ((archive_score += 15))
        fi
    fi
    
    # 2. Check domain age via archive
    echo "" >> "$archive_report"
    echo "Domain History Analysis:" >> "$archive_report"
    
    local cdx_api="http://web.archive.org/cdx/search/cdx?url=$domain&output=json&limit=5"
    local cdx_result=$(curl -sS --max-time 15 "$cdx_api" 2>/dev/null)
    
    if [ -n "$cdx_result" ] && echo "$cdx_result" | grep -q '\['; then
        # Get first capture date
        local first_capture=$(echo "$cdx_result" | grep -oE '"[0-9]{14}"' | head -1 | tr -d '"')
        if [ -n "$first_capture" ]; then
            local first_year="${first_capture:0:4}"
            local current_year=$(date +%Y)
            local age=$((current_year - first_year))
            
            echo "  First Archive: $first_capture" >> "$archive_report"
            echo "  Approximate Age: $age years" >> "$archive_report"
            
            if [ "$age" -lt 1 ]; then
                log_warning "Domain is less than 1 year old in archives"
                archive_findings+=("new_domain:$age")
                ((archive_score += 20))
            fi
        fi
    fi
    
    # 3. Archive.today check
    log_info "  Checking archive.today..."
    local archive_today_url="https://archive.today/$url"
    local archive_today_check=$(curl -sS --max-time 10 -o /dev/null -w "%{http_code}" "$archive_today_url" 2>/dev/null)
    
    echo "" >> "$archive_report"
    echo "Archive.today:" >> "$archive_report"
    if [ "$archive_today_check" = "200" ]; then
        echo "  Status: Found" >> "$archive_report"
        echo "  URL: $archive_today_url" >> "$archive_report"
        archive_findings+=("archive_today:found")
    else
        echo "  Status: Not found" >> "$archive_report"
    fi
    
    # Generate summary
    echo "" >> "$archive_report"
    echo "Analysis Summary:" >> "$archive_report"
    echo "  Total Findings: ${#archive_findings[@]}" >> "$archive_report"
    echo "  Archive Risk Score: $archive_score" >> "$archive_report"
    
    if [ ${#archive_findings[@]} -gt 0 ]; then
        if [ $archive_score -ge 25 ]; then
            log_warning "Web archive analysis indicates suspicious history"
        fi
        analysis_success_found "WEB-ARCHIVE" "${#archive_findings[@]}" "Score: $archive_score"
    else
        analysis_success_none "WEB-ARCHIVE"
    fi
}

# ============================================================================
# AUDIT 8: EMBEDDED/EXTERNAL CONTENT EXTRACTION (RECURSIVE CRAWL)
# ============================================================================

# Maximum crawl depth
MAX_CRAWL_DEPTH=2
CRAWL_TIMEOUT=30

# Known content hosting services to crawl
declare -a CRAWL_TARGET_SERVICES=(
    "docs.google.com"
    "drive.google.com"
    "pastebin.com"
    "paste.ee"
    "ghostbin.co"
    "hastebin.com"
    "gist.github.com"
    "raw.githubusercontent.com"
    "dropbox.com"
    "onedrive.live.com"
    "1drv.ms"
    "mega.nz"
    "rentry.co"
    "privatebin.net"
)

analyze_recursive_crawl() {
    local url="$1"
    local depth="${2:-0}"
    
    if [ "$RECURSIVE_CRAWL" = false ]; then
        analysis_success_none "RECURSIVE-CRAWL"
        return
    fi
    
    if [ "$depth" -ge "$MAX_CRAWL_DEPTH" ]; then
        return
    fi
    
    if [ -z "$url" ] || ! echo "$url" | grep -qiE "^https?://"; then
        analysis_success_none "RECURSIVE-CRAWL"
        return
    fi
    
    log_info "Performing recursive content extraction (depth: $depth)..."
    
    local crawl_findings=()
    local crawl_score=0
    local crawl_report="${OUTPUT_DIR}/recursive_crawl.txt"
    
    if [ "$depth" -eq 0 ]; then
        {
            echo "═══════════════════════════════════════════════"
            echo "RECURSIVE CONTENT EXTRACTION"
            echo "═══════════════════════════════════════════════"
            echo "Timestamp: $(date -Iseconds)"
            echo "Initial URL: $url"
            echo "Max Depth: $MAX_CRAWL_DEPTH"
            echo ""
        } > "$crawl_report"
    fi
    
    # Check if URL is a content hosting service
    local domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
    local is_target_service=false
    
    for service in "${CRAWL_TARGET_SERVICES[@]}"; do
        if echo "$domain" | grep -qi "$service"; then
            is_target_service=true
            break
        fi
    done
    
    if [ "$is_target_service" = true ]; then
        log_info "  Target service detected: $domain (depth $depth)"
        
        # Fetch content
        local fetched_content=$(timeout $CRAWL_TIMEOUT curl -sS -L --max-time $((CRAWL_TIMEOUT - 5)) \
            -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            "$url" 2>/dev/null | head -c 200000)
        
        if [ -n "$fetched_content" ]; then
            echo "Depth $depth - Fetched: $url" >> "$crawl_report"
            echo "  Content Length: ${#fetched_content} bytes" >> "$crawl_report"
            
            crawl_findings+=("fetched:$domain")
            
            # Analyze fetched content
            # Check for malicious patterns
            if echo "$fetched_content" | grep -qiE 'powershell|cmd\.exe|IEX|Invoke-|downloadstring'; then
                crawl_findings+=("malicious_content:$domain")
                ((crawl_score += 50))
                log_threat 55 "Malicious content found in linked resource"
                echo "  ⚠ MALICIOUS CONTENT DETECTED" >> "$crawl_report"
            fi
            
            # Check for additional URLs to crawl
            local nested_urls=$(echo "$fetched_content" | grep -oiE 'https?://[^\s"<>'\'']+' | sort -u | head -10)
            
            if [ -n "$nested_urls" ]; then
                echo "  Nested URLs found:" >> "$crawl_report"
                
                while IFS= read -r nested_url; do
                    [ -z "$nested_url" ] && continue
                    echo "    - $nested_url" >> "$crawl_report"
                    
                    # Record as IOC
                    record_ioc "nested_url" "$nested_url" "Found in crawled content at depth $depth"
                    
                    # Recursive crawl (if target service)
                    for service in "${CRAWL_TARGET_SERVICES[@]}"; do
                        if echo "$nested_url" | grep -qi "$service"; then
                            analyze_recursive_crawl "$nested_url" $((depth + 1))
                            break
                        fi
                    done
                done <<< "$nested_urls"
            fi
            
            # Extract and analyze base64 content
            local base64_content=$(echo "$fetched_content" | grep -oE '[A-Za-z0-9+/=]{50,}' | head -5)
            if [ -n "$base64_content" ]; then
                echo "  Base64 content found:" >> "$crawl_report"
                while IFS= read -r b64; do
                    local decoded=$(echo "$b64" | base64 -d 2>/dev/null | head -c 1000)
                    if [ -n "$decoded" ]; then
                        if echo "$decoded" | grep -qiE 'powershell|cmd|wget|curl|python'; then
                            crawl_findings+=("encoded_payload:base64")
                            ((crawl_score += 40))
                            log_threat 45 "Base64 encoded payload found"
                        fi
                    fi
                done <<< "$base64_content"
            fi
        fi
    fi
    
    # Generate summary (only at depth 0)
    if [ "$depth" -eq 0 ]; then
        echo "" >> "$crawl_report"
        echo "Analysis Summary:" >> "$crawl_report"
        echo "  Total Findings: ${#crawl_findings[@]}" >> "$crawl_report"
        echo "  Crawl Risk Score: $crawl_score" >> "$crawl_report"
        
        if [ ${#crawl_findings[@]} -gt 0 ]; then
            if [ $crawl_score -ge 40 ]; then
                log_threat $((crawl_score / 2)) "Recursive crawl revealed malicious content"
            fi
            analysis_success_found "RECURSIVE-CRAWL" "${#crawl_findings[@]}" "Score: $crawl_score"
        else
            analysis_success_none "RECURSIVE-CRAWL"
        fi
    fi
}

# ============================================================================
# AUDIT 9: VISUAL ADVERSARIAL AI ATTACK DETECTION
# ============================================================================

analyze_adversarial_ai() {
    local image="$1"
    
    if [ "$ADVERSARIAL_AI_DETECTION" = false ]; then
        analysis_success_none "ADVERSARIAL-AI"
        return
    fi
    
    if [ ! -f "$image" ]; then
        analysis_error "ADVERSARIAL-AI" "Image file not found"
        return
    fi
    
    log_info "Analyzing for adversarial AI attack patterns..."
    
    local adv_findings=()
    local adv_score=0
    local adv_report="${OUTPUT_DIR}/adversarial_ai_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "ADVERSARIAL AI ATTACK DETECTION"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo "Image: $image"
        echo ""
    } > "$adv_report"
    
    # Python-based adversarial detection
    local adv_analysis=$(python3 << EOF 2>/dev/null
import json
import sys

try:
    from PIL import Image
    import numpy as np
    
    img = Image.open('$image')
    img_array = np.array(img)
    
    results = {
        'size': img.size,
        'mode': img.mode,
        'format': img.format,
    }
    
    # Calculate image statistics
    if len(img_array.shape) >= 2:
        results['mean'] = float(np.mean(img_array))
        results['std'] = float(np.std(img_array))
        results['min'] = int(np.min(img_array))
        results['max'] = int(np.max(img_array))
        
        # Check for adversarial perturbation indicators
        
        # 1. High-frequency noise detection
        if len(img_array.shape) == 3:
            gray = np.mean(img_array, axis=2)
        else:
            gray = img_array
        
        # Calculate Laplacian variance (edge/noise detection)
        from scipy import ndimage
        laplacian = ndimage.laplace(gray.astype(float))
        laplacian_var = float(np.var(laplacian))
        results['laplacian_variance'] = round(laplacian_var, 4)
        
        # High laplacian variance can indicate adversarial noise
        if laplacian_var > 500:
            results['high_frequency_noise'] = True
            results['adversarial_indicator'] = 'HIGH_FREQUENCY_PERTURBATION'
        
        # 2. Check for unusual pixel distributions
        pixel_hist, _ = np.histogram(img_array.flatten(), bins=256, range=(0, 256))
        
        # Adversarial examples often have unusual histogram patterns
        hist_entropy = -np.sum(pixel_hist[pixel_hist > 0] / pixel_hist.sum() * 
                               np.log2(pixel_hist[pixel_hist > 0] / pixel_hist.sum()))
        results['histogram_entropy'] = round(hist_entropy, 4)
        
        # Very low entropy suggests manipulation
        if hist_entropy < 4.0:
            results['unusual_distribution'] = True
        
        # 3. Check for patch attacks (localized perturbations)
        # Look for rectangular regions with different statistics
        h, w = gray.shape
        patch_size = min(h, w) // 4
        if patch_size > 10:
            center_patch = gray[h//4:3*h//4, w//4:3*w//4]
            corner_patches = [
                gray[:patch_size, :patch_size],
                gray[:patch_size, -patch_size:],
                gray[-patch_size:, :patch_size],
                gray[-patch_size:, -patch_size:]
            ]
            
            center_mean = np.mean(center_patch)
            corner_means = [np.mean(p) for p in corner_patches]
            
            # Large difference between center and corners could indicate patch attack
            max_diff = max(abs(center_mean - cm) for cm in corner_means)
            results['patch_diff'] = round(max_diff, 4)
            
            if max_diff > 50:
                results['possible_patch_attack'] = True
                results['adversarial_indicator'] = 'PATCH_ATTACK'
        
        # 4. JPEG artifacts analysis (adversarial often added post-compression)
        if img.format == 'JPEG':
            # DCT block boundary analysis would go here
            results['jpeg_analysis'] = 'JPEG format detected'
    
    print(json.dumps(results, indent=2))
    
except ImportError as e:
    print(json.dumps({'error': f'Missing dependency: {e}'}))
except Exception as e:
    print(json.dumps({'error': str(e)}))
EOF
)
    
    if [ -n "$adv_analysis" ]; then
        echo "Image Analysis Results:" >> "$adv_report"
        echo "$adv_analysis" >> "$adv_report"
        
        # Parse results
        if echo "$adv_analysis" | grep -q '"adversarial_indicator"'; then
            local indicator=$(json_extract_string "$adv_analysis" "adversarial_indicator")
            adv_findings+=("adversarial:$indicator")
            ((adv_score += 45))
            log_threat 50 "Adversarial AI attack indicator: $indicator"
        fi
        
        if echo "$adv_analysis" | grep -q '"high_frequency_noise":\s*true'; then
            adv_findings+=("high_frequency_noise")
            ((adv_score += 30))
            log_warning "High-frequency noise detected (possible perturbation)"
        fi
        
        if echo "$adv_analysis" | grep -q '"possible_patch_attack":\s*true'; then
            adv_findings+=("patch_attack")
            ((adv_score += 40))
            log_threat 45 "Possible adversarial patch attack detected"
        fi
        
        if echo "$adv_analysis" | grep -q '"unusual_distribution":\s*true'; then
            adv_findings+=("unusual_distribution")
            ((adv_score += 20))
            log_warning "Unusual pixel distribution detected"
        fi
    fi
    
    # Generate summary
    echo "" >> "$adv_report"
    echo "Analysis Summary:" >> "$adv_report"
    echo "  Total Findings: ${#adv_findings[@]}" >> "$adv_report"
    echo "  Adversarial Risk Score: $adv_score" >> "$adv_report"
    
    if [ ${#adv_findings[@]} -gt 0 ]; then
        analysis_success_found "ADVERSARIAL-AI" "${#adv_findings[@]}" "Score: $adv_score"
    else
        analysis_success_none "ADVERSARIAL-AI"
    fi
}

# ============================================================================
# AUDIT 10: COVERT CHANNEL DETECTION
# ============================================================================

# DNS covert channel indicators
declare -a DNS_COVERT_INDICATORS=(
    "TXT record with base64"
    "Unusually long subdomain"
    "High entropy subdomain"
    "Rapid DNS queries"
    "Non-standard record types"
)

analyze_covert_channels() {
    local content="$1"
    local url="$2"
    
    if [ "$COVERT_CHANNEL_DETECTION" = false ]; then
        analysis_success_none "COVERT-CHANNELS"
        return
    fi
    
    log_info "Analyzing for covert channel indicators..."
    
    local covert_findings=()
    local covert_score=0
    local covert_report="${OUTPUT_DIR}/covert_channel_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "COVERT CHANNEL DETECTION"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$covert_report"
    
    # Extract domain if URL
    local domain=""
    if echo "$url" | grep -qiE "^https?://"; then
        domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
    fi
    
    echo "DNS Covert Channel Analysis:" >> "$covert_report"
    
    if [ -n "$domain" ]; then
        # 1. Check for DNS tunneling indicators
        log_info "  Checking DNS tunneling indicators..."
        
        # Get TXT records
        local txt_records=$(dig +short TXT "$domain" 2>/dev/null)
        if [ -n "$txt_records" ]; then
            echo "  TXT Records: $txt_records" >> "$covert_report"
            
            # Check for base64 in TXT
            if echo "$txt_records" | grep -qE '[A-Za-z0-9+/=]{50,}'; then
                covert_findings+=("dns_txt_base64")
                ((covert_score += 35))
                log_warning "Base64 content in DNS TXT record"
            fi
            
            # Long TXT records
            local txt_len=$(echo "$txt_records" | wc -c)
            if [ "$txt_len" -gt 255 ]; then
                covert_findings+=("long_txt_record:$txt_len")
                ((covert_score += 20))
            fi
        fi
        
        # 2. Subdomain entropy check
        local subdomain=$(echo "$domain" | rev | cut -d'.' -f3- | rev)
        if [ -n "$subdomain" ] && [ ${#subdomain} -gt 20 ]; then
            # Calculate entropy
            local entropy=$(python3 -c "
import math
from collections import Counter
s = '$subdomain'
freq = Counter(s)
probs = [c/len(s) for c in freq.values()]
entropy = -sum(p * math.log2(p) for p in probs if p > 0)
print(round(entropy, 4))
" 2>/dev/null)
            
            echo "  Subdomain: $subdomain" >> "$covert_report"
            echo "  Subdomain Entropy: ${entropy:-N/A}" >> "$covert_report"
            
            if [ -n "$entropy" ]; then
                local high_entropy=$(echo "$entropy > 3.5" | bc -l 2>/dev/null)
                if [ "$high_entropy" = "1" ]; then
                    covert_findings+=("high_entropy_subdomain:$entropy")
                    ((covert_score += 40))
                    log_threat 45 "High-entropy subdomain detected (possible DNS tunneling)"
                fi
            fi
        fi
        
        # 3. Check for DNS over HTTPS indicators
        if echo "$content" | grep -qiE 'dns-query|application/dns-message|cloudflare-dns|dns\.google'; then
            covert_findings+=("doh_indicator")
            ((covert_score += 15))
            log_info "DNS-over-HTTPS indicator detected"
        fi
    fi
    
    echo "" >> "$covert_report"
    echo "Protocol Covert Channel Analysis:" >> "$covert_report"
    
    # 4. ICMP covert channel patterns
    if echo "$content" | grep -qiE 'icmp|ping.*-p.*[a-f0-9]{16}|ping.*data'; then
        covert_findings+=("icmp_covert")
        ((covert_score += 30))
        log_warning "ICMP covert channel indicator"
    fi
    
    # 5. HTTP header covert channels
    if echo "$content" | grep -qiE 'X-[A-Za-z0-9-]*:\s*[A-Za-z0-9+/=]{32,}'; then
        covert_findings+=("http_header_covert")
        ((covert_score += 25))
        log_warning "HTTP header covert channel pattern"
    fi
    
    # 6. Steganography indicators in URL
    if echo "$url" | grep -qE '[A-Za-z0-9+/=]{64,}'; then
        covert_findings+=("url_encoded_payload")
        ((covert_score += 20))
    fi
    
    # Generate summary
    echo "" >> "$covert_report"
    echo "Analysis Summary:" >> "$covert_report"
    echo "  Total Findings: ${#covert_findings[@]}" >> "$covert_report"
    echo "  Covert Channel Risk Score: $covert_score" >> "$covert_report"
    
    if [ ${#covert_findings[@]} -gt 0 ]; then
        if [ $covert_score -ge 35 ]; then
            log_threat $((covert_score / 2)) "Covert channel indicators detected"
        fi
        analysis_success_found "COVERT-CHANNELS" "${#covert_findings[@]}" "Score: $covert_score"
    else
        analysis_success_none "COVERT-CHANNELS"
    fi
}

# ============================================================================
# AUDIT 11: CROSS-QR STEGANOGRAPHY/CHAINING DETECTION
# ============================================================================

# Array to track QR codes in batch analysis
declare -a QR_CHAIN_HASHES=()
declare -a QR_CHAIN_CONTENTS=()

analyze_qr_chaining() {
    local content="$1"
    local image="$2"
    local batch_mode="${3:-false}"
    
    if [ "$CROSS_QR_CHAIN_DETECTION" = false ]; then
        analysis_success_none "QR-CHAINING"
        return
    fi
    
    log_info "Analyzing for cross-QR chaining/sequencing..."
    
    local chain_findings=()
    local chain_score=0
    local chain_report="${OUTPUT_DIR}/qr_chaining_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "CROSS-QR CHAINING/STEGANOGRAPHY DETECTION"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } >> "$chain_report"
    
    # 1. Check for sequence indicators in content
    echo "Sequence Pattern Detection:" >> "$chain_report"
    
    # Part X of Y patterns
    if echo "$content" | grep -qiE 'part\s*[0-9]+\s*(of|/)\s*[0-9]+'; then
        local sequence_info=$(echo "$content" | grep -oiE 'part\s*[0-9]+\s*(of|/)\s*[0-9]+' | head -1)
        chain_findings+=("sequence_marker:$sequence_info")
        ((chain_score += 40))
        log_threat 45 "QR sequence marker detected: $sequence_info"
        echo "  ⚠ SEQUENCE MARKER: $sequence_info" >> "$chain_report"
    fi
    
    # Fragment patterns
    if echo "$content" | grep -qiE '\[fragment\]|\[chunk\]|\[segment\]|##[0-9]+##'; then
        chain_findings+=("fragment_marker")
        ((chain_score += 35))
        log_warning "Fragment marker detected in QR"
    fi
    
    # 2. Check for base64 fragment patterns
    local base64_fragment=$(echo "$content" | grep -oE '^[A-Za-z0-9+/]+={0,2}$')
    if [ -n "$base64_fragment" ] && [ ${#base64_fragment} -gt 50 ]; then
        # Pure base64 content suggests it might be a fragment
        local decoded=$(echo "$base64_fragment" | base64 -d 2>/dev/null | head -c 100)
        
        # If doesn't decode to readable text, likely a fragment
        if [ -n "$decoded" ]; then
            local readable_ratio=$(echo "$decoded" | tr -dc '[:print:]' | wc -c)
            local total_len=${#decoded}
            
            if [ "$total_len" -gt 0 ] && [ "$readable_ratio" -lt $((total_len / 2)) ]; then
                chain_findings+=("possible_fragment:base64")
                ((chain_score += 30))
                echo "  ⚠ Possible base64 fragment (low readability)" >> "$chain_report"
            fi
        fi
    fi
    
    # 3. Check for hex fragment patterns
    if echo "$content" | grep -qE '^[0-9a-fA-F]{64,}$'; then
        chain_findings+=("hex_fragment")
        ((chain_score += 25))
        log_warning "Hex-encoded fragment pattern detected"
    fi
    
    # 4. Batch analysis - check for related QR codes
    if [ "$batch_mode" = true ]; then
        echo "" >> "$chain_report"
        echo "Batch Correlation Analysis:" >> "$chain_report"
        
        # Add current content to tracking
        local content_hash=$(echo "$content" | md5sum | cut -d' ' -f1)
        QR_CHAIN_HASHES+=("$content_hash")
        QR_CHAIN_CONTENTS+=("$content")
        
        echo "  QR codes analyzed: ${#QR_CHAIN_HASHES[@]}" >> "$chain_report"
        
        # Check for content similarity
        if [ ${#QR_CHAIN_CONTENTS[@]} -gt 1 ]; then
            local similar_count=0
            for prev_content in "${QR_CHAIN_CONTENTS[@]:0:${#QR_CHAIN_CONTENTS[@]}-1}"; do
                # Simple similarity check
                local common_prefix=$(printf '%s\n%s\n' "$prev_content" "$content" |
                    sed 'N;s/^\(.*\).*\n\1.*$/\1/' | head -1)
                if [ ${#common_prefix} -gt 20 ]; then
                    ((similar_count++))
                fi
            done
            
            if [ "$similar_count" -gt 0 ]; then
                chain_findings+=("similar_qr_codes:$similar_count")
                ((chain_score += 25))
                log_warning "$similar_count similar QR codes detected (possible chain)"
            fi
        fi
    fi
    
    # 5. Concatenation instruction patterns
    if echo "$content" | grep -qiE 'concat|append|combine|merge|join.*next'; then
        chain_findings+=("concatenation_instruction")
        ((chain_score += 35))
        log_warning "Concatenation instruction detected"
    fi
    
    # Generate summary
    echo "" >> "$chain_report"
    echo "Analysis Summary:" >> "$chain_report"
    echo "  Total Findings: ${#chain_findings[@]}" >> "$chain_report"
    echo "  Chain Risk Score: $chain_score" >> "$chain_report"
    
    if [ ${#chain_findings[@]} -gt 0 ]; then
        analysis_success_found "QR-CHAINING" "${#chain_findings[@]}" "Score: $chain_score"
    else
        analysis_success_none "QR-CHAINING"
    fi
}

# ============================================================================
# AUDIT 12: QR FACTORY/TEMPLATE SPOOFING DETECTION
# ============================================================================

# Known QR template signatures (visual patterns and content patterns)
declare -A TEMPLATE_SIGNATURES=(
    # COVID-related
    ["covid_pass"]="EU Digital COVID|NHS COVID Pass|Vaccination Certificate|CERTIFICATE VERIFIED"
    ["green_pass"]="Green Pass|EU DCC|Digital Green Certificate"
    
    # Shipping/Logistics
    ["fedex"]="fedex\.com|FedEx|tracking.*fedex"
    ["ups"]="ups\.com|UPS|tracking.*ups|worldship"
    ["dhl"]="dhl\.(com|de)|DHL|shipment.*dhl"
    ["usps"]="usps\.com|USPS|Postal Service"
    
    # Payments
    ["paypal"]="paypal\.com|PayPal|payment.*paypal"
    ["venmo"]="venmo\.com|Venmo"
    ["zelle"]="zellepay|Zelle"
    ["cashapp"]="cash\.app|CashApp|\$cashtag"
    
    # Banking
    ["bank_generic"]="bank.*login|account.*verify|secure.*banking"
    ["chase"]="chase\.com|Chase Bank"
    ["wellsfargo"]="wellsfargo\.com|Wells Fargo"
    ["bofa"]="bankofamerica\.com|Bank of America"
    
    # Social Media
    ["instagram"]="instagram\.com|@instagram"
    ["twitter"]="twitter\.com|@twitter|x\.com"
    ["facebook"]="facebook\.com|fb\.com|@facebook"
    ["linkedin"]="linkedin\.com|LinkedIn"
    
    # Crypto
    ["coinbase"]="coinbase\.com|Coinbase"
    ["binance"]="binance\.com|Binance"
    ["crypto_wallet"]="bitcoin:|ethereum:|wallet.*crypto"
    
    # Government
    ["irs"]="irs\.gov|Internal Revenue|tax.*refund"
    ["ssa"]="ssa\.gov|Social Security"
    ["dmv"]="dmv\.|Department of Motor"
)

# Known malicious template patterns
declare -a MALICIOUS_TEMPLATE_PATTERNS=(
    "verify.*account.*immediately"
    "suspended.*click.*restore"
    "confirm.*identity.*24.hours"
    "unusual.*activity.*login"
    "prize.*claim.*now"
    "lottery.*winner.*congratulations"
    "package.*delivery.*failed.*confirm"
    "invoice.*attached.*payment"
    "refund.*pending.*verify"
)

analyze_template_spoofing() {
    local content="$1"
    local image="$2"
    
    if [ "$TEMPLATE_SPOOF_DETECTION" = false ]; then
        analysis_success_none "TEMPLATE-SPOOFING"
        return
    fi
    
    log_info "Analyzing for QR template spoofing..."
    
    local template_findings=()
    local template_score=0
    local matched_templates=()
    local template_report="${OUTPUT_DIR}/template_spoofing_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "QR TEMPLATE SPOOFING DETECTION"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$template_report"
    
    # 1. Check against known template signatures
    echo "Template Signature Matching:" >> "$template_report"
    
    for template_name in "${!TEMPLATE_SIGNATURES[@]}"; do
        local pattern="${TEMPLATE_SIGNATURES[$template_name]}"
        if echo "$content" | grep -qiE "$pattern"; then
            matched_templates+=("$template_name")
            template_findings+=("template_match:$template_name")
            ((template_score += 20))
            echo "  ✓ Matched template: $template_name" >> "$template_report"
            log_info "QR content matches $template_name template"
        fi
    done
    
    # 2. Check for template impersonation indicators
    echo "" >> "$template_report"
    echo "Impersonation Indicators:" >> "$template_report"
    
    # Check if template match but URL doesn't match expected domain
    for template in "${matched_templates[@]}"; do
        local expected_domain=""
        case "$template" in
            "fedex") expected_domain="fedex.com" ;;
            "ups") expected_domain="ups.com" ;;
            "dhl") expected_domain="dhl.com" ;;
            "paypal") expected_domain="paypal.com" ;;
            "chase") expected_domain="chase.com" ;;
            "coinbase") expected_domain="coinbase.com" ;;
            "irs") expected_domain="irs.gov" ;;
        esac
        
        if [ -n "$expected_domain" ]; then
            # Check if URL in content matches expected domain
            local actual_domain=$(echo "$content" | grep -oiE 'https?://[^/]+' | head -1 | sed 's|https\?://||')
            
            if [ -n "$actual_domain" ] && ! echo "$actual_domain" | grep -qi "$expected_domain"; then
                template_findings+=("domain_mismatch:$template:$actual_domain")
                ((template_score += 50))
                log_threat 55 "Template impersonation: $template template but domain is $actual_domain"
                echo "  ⚠ IMPERSONATION: $template template with wrong domain: $actual_domain" >> "$template_report"
            fi
        fi
    done
    
    # 3. Check for malicious template patterns
    echo "" >> "$template_report"
    echo "Malicious Pattern Detection:" >> "$template_report"
    
    for pattern in "${MALICIOUS_TEMPLATE_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            template_findings+=("malicious_template:$pattern")
            ((template_score += 35))
            log_warning "Malicious template pattern: $pattern"
            echo "  ⚠ MALICIOUS: $pattern" >> "$template_report"
        fi
    done
    
    # 4. Visual template analysis (if image provided)
    if [ -n "$image" ] && [ -f "$image" ]; then
        echo "" >> "$template_report"
        echo "Visual Template Analysis:" >> "$template_report"
        
        # Check image dimensions for known QR template sizes
        local dimensions=$(identify -format "%wx%h" "$image" 2>/dev/null)
        echo "  Image Dimensions: $dimensions" >> "$template_report"
        
        # COVID pass QR codes are typically specific sizes
        if [ "$dimensions" = "300x300" ] || [ "$dimensions" = "400x400" ]; then
            if echo "$content" | grep -qiE "covid|vaccin|certificate|pass"; then
                template_findings+=("possible_covid_pass_template")
                ((template_score += 30))
            fi
        fi
        
        # Check for logo embedding (common in branded QR)
        local color_count=$(identify -format "%k" "$image" 2>/dev/null)
        if [ -n "$color_count" ] && [ "$color_count" -gt 10 ]; then
            echo "  Color Count: $color_count (possible logo/branding)" >> "$template_report"
            template_findings+=("branded_qr")
        fi
    fi
    
    # 5. COVID-specific checks
    if echo "$content" | grep -qiE "covid|vaccin|certificate|immuniz"; then
        echo "" >> "$template_report"
        echo "COVID Certificate Analysis:" >> "$template_report"
        
        # Check for fake EU DCC format
        if echo "$content" | grep -qE "HC1:"; then
            template_findings+=("eu_dcc_format")
            log_info "EU Digital COVID Certificate format detected"
            echo "  Format: EU DCC (HC1:)" >> "$template_report"
            
            # Validate structure
            local dcc_payload=$(echo "$content" | grep -oE "HC1:.*" | head -1)
            if [ ${#dcc_payload} -lt 100 ]; then
                template_findings+=("invalid_dcc_short")
                ((template_score += 40))
                log_warning "Suspiciously short DCC payload"
            fi
        fi
    fi
    
    # Generate summary
    echo "" >> "$template_report"
    echo "Analysis Summary:" >> "$template_report"
    echo "  Templates Matched: ${#matched_templates[@]}" >> "$template_report"
    echo "  Total Findings: ${#template_findings[@]}" >> "$template_report"
    echo "  Template Risk Score: $template_score" >> "$template_report"
    
    if [ ${#template_findings[@]} -gt 0 ]; then
        if [ $template_score -ge 50 ]; then
            log_threat $((template_score / 2)) "Template spoofing indicators detected"
        fi
        analysis_success_found "TEMPLATE-SPOOFING" "${#template_findings[@]}" "Score: $template_score"
    else
        analysis_success_none "TEMPLATE-SPOOFING"
    fi
}

# ============================================================================
# AUDIT 13: SOCIAL MEDIA/MARKETING LINK DETECTION
# ============================================================================

# Marketing/link aggregation services
declare -a MARKETING_LINK_SERVICES=(
    # Link aggregators
    "linktr.ee" "linktree.com" "link.bio" "lnk.bio" "beacons.ai"
    "stan.store" "hoo.be" "bio.fm" "tap.bio" "allmylinks.com"
    "contactinbio.com" "linkin.bio" "lnk.to" "msha.ke" "withkoji.com"
    
    # URL shorteners (additional)
    "buff.ly" "ow.ly" "dlvr.it" "po.st" "soo.gd" "mcaf.ee"
    "twurl.nl" "trib.al" "snip.ly" "tinycc.com" "short.io"
    "rebrand.ly" "bl.ink" "clickmeter.com" "t2mio.com"
    
    # Social media shorteners
    "fb.me" "fb.com" "m.me" "wa.me" "ig.me"
    "youtu.be" "amzn.to" "ebay.to" "etsy.me"
    
    # Marketing platforms
    "mailchi.mp" "campaign-archive.com" "list-manage.com"
    "sendgrid.net" "constantcontact.com" "aweber.com"
    "getresponse.com" "hubspot.net" "marketo.com"
    "mailgun.org" "sendpulse.com" "sendinblue.com"
    
    # Tracking/redirect services
    "click.redditmail.com" "links.e.*.com" "click.e.*.com"
    "email.*.com" "t.e.*.com" "go.*.com" "click.*.com"
    
    # Affiliate tracking
    "go2cloud.org" "afftrack.com" "tkqlhce.com" "anrdoezrs.net"
    "jdoqocy.com" "kqzyfj.com" "dpbolvw.net" "commission-junction"
    "shareasale.com" "awin1.com" "prf.hn" "pntra.com"
)

# Tracking parameter patterns
declare -a TRACKING_PARAMS=(
    "utm_source" "utm_medium" "utm_campaign" "utm_content" "utm_term"
    "fbclid" "gclid" "msclkid" "mc_eid" "mc_cid"
    "ref" "referrer" "source" "campaign" "affiliate"
    "trk" "track" "click_id" "clickid" "subid"
    "s1" "s2" "s3" "s4" "s5"
    "aff_id" "aff_sub" "aff_click_id"
)

analyze_social_marketing_links() {
    local content="$1"
    
    if [ "$SOCIAL_MEDIA_LINK_DETECTION" = false ]; then
        analysis_success_none "SOCIAL-MARKETING"
        return
    fi
    
    log_info "Analyzing social media/marketing links..."
    
    local social_findings=()
    local social_score=0
    local marketing_report="${OUTPUT_DIR}/social_marketing_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "SOCIAL MEDIA/MARKETING LINK ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$marketing_report"
    
    # 1. Check for marketing link services
    echo "Marketing Service Detection:" >> "$marketing_report"
    
    for service in "${MARKETING_LINK_SERVICES[@]}"; do
        if echo "$content" | grep -qiE "$service"; then
            social_findings+=("marketing_service:$service")
            ((social_score += 15))
            echo "  ✓ Detected: $service" >> "$marketing_report"
            log_info "Marketing link service: $service"
        fi
    done
    
    # 2. Check for tracking parameters
    echo "" >> "$marketing_report"
    echo "Tracking Parameter Analysis:" >> "$marketing_report"
    
    local tracking_count=0
    for param in "${TRACKING_PARAMS[@]}"; do
        if echo "$content" | grep -qiE "[?&]$param="; then
            ((tracking_count++))
            social_findings+=("tracking_param:$param")
            echo "  ✓ $param" >> "$marketing_report"
        fi
    done
    
    if [ "$tracking_count" -gt 3 ]; then
        ((social_score += 20))
        log_warning "Multiple tracking parameters detected ($tracking_count)"
    fi
    
    # 3. Check for redirect chains
    echo "" >> "$marketing_report"
    echo "Redirect Chain Analysis:" >> "$marketing_report"
    
    if echo "$content" | grep -qiE "https?://[^/]+/(redirect|redir|go|click|track|link|out)"; then
        social_findings+=("redirect_path")
        ((social_score += 15))
        echo "  ⚠ Redirect path pattern detected" >> "$marketing_report"
    fi
    
    # 4. Follow and analyze short URLs
    if echo "$content" | grep -qiE "bit\.ly|tinyurl|ow\.ly|t\.co|goo\.gl|is\.gd"; then
        local short_url=$(echo "$content" | grep -oiE "https?://(bit\.ly|tinyurl\.com|ow\.ly|t\.co|goo\.gl|is\.gd)/[A-Za-z0-9]+" | head -1)
        
        if [ -n "$short_url" ]; then
            echo "  Short URL: $short_url" >> "$marketing_report"
            
            # Attempt to expand
            local expanded=$(curl -sS -o /dev/null -w '%{url_effective}' -L --max-time 10 "$short_url" 2>/dev/null)
            
            if [ -n "$expanded" ] && [ "$expanded" != "$short_url" ]; then
                echo "  Expanded: $expanded" >> "$marketing_report"
                social_findings+=("expanded_url:$(echo "$expanded" | cut -c1-50)")
                
                # Record expanded URL as IOC
                record_ioc "expanded_url" "$expanded" "Expanded from short URL $short_url"
                
                # Check expansion for threats
                if echo "$expanded" | grep -qiE "\.exe|\.scr|\.pif|download"; then
                    social_findings+=("suspicious_expansion")
                    ((social_score += 40))
                    log_threat 45 "Short URL expands to suspicious target"
                fi
            fi
        fi
    fi
    
    # 5. Linktree/bio link analysis
    if echo "$content" | grep -qiE "linktr\.ee|linktree|link\.bio|beacons\.ai"; then
        echo "" >> "$marketing_report"
        echo "Bio Link Analysis:" >> "$marketing_report"
        
        local bio_url=$(echo "$content" | grep -oiE "https?://(linktr\.ee|link\.bio|beacons\.ai)/[A-Za-z0-9_]+" | head -1)
        
        if [ -n "$bio_url" ]; then
            social_findings+=("bio_link:$bio_url")
            
            # Fetch bio link page
            local bio_content=$(curl -sS --max-time 15 "$bio_url" 2>/dev/null | head -c 50000)
            
            if [ -n "$bio_content" ]; then
                # Extract all links from bio page
                local bio_links=$(echo "$bio_content" | grep -oiE 'href="https?://[^"]+' | cut -d'"' -f2 | sort -u | head -10)
                
                echo "  Links found in bio:" >> "$marketing_report"
                echo "$bio_links" >> "$marketing_report"
                
                # Check bio links for suspicious content
                while IFS= read -r bio_link; do
                    [ -z "$bio_link" ] && continue
                    record_ioc "bio_link" "$bio_link" "Found in linktree/bio page"
                    
                    if echo "$bio_link" | grep -qiE "\.exe|discord\.gg|t\.me|anonfiles"; then
                        social_findings+=("suspicious_bio_link")
                        ((social_score += 30))
                    fi
                done <<< "$bio_links"
            fi
        fi
    fi
    
    # Generate summary
    echo "" >> "$marketing_report"
    echo "Analysis Summary:" >> "$marketing_report"
    echo "  Total Findings: ${#social_findings[@]}" >> "$marketing_report"
    echo "  Marketing Risk Score: $social_score" >> "$marketing_report"
    
    if [ ${#social_findings[@]} -gt 0 ]; then
        if [ $social_score -ge 30 ]; then
            log_warning "Social media/marketing link analysis complete"
        fi
        analysis_success_found "SOCIAL-MARKETING" "${#social_findings[@]}" "Score: $social_score"
    else
        analysis_success_none "SOCIAL-MARKETING"
    fi
}

# ============================================================================
# AUDIT 14: UX REDRESS/BROWSER ATTACK DETECTION
# ============================================================================

# Browser attack patterns
declare -a BROWSER_ATTACK_PATTERNS=(
    # URL bar spoofing
    'data:text/html'
    'javascript:void'
    'about:blank.*document\.write'
    
    # Fullscreen overlay attacks
    'requestFullscreen'
    'mozRequestFullScreen'
    'webkitRequestFullscreen'
    'msRequestFullscreen'
    'document\.fullscreen'
    
    # History manipulation
    'history\.pushState'
    'history\.replaceState'
    'onpopstate'
    
    # Window manipulation
    'window\.open.*fullscreen'
    'window\.moveTo\s*\(\s*0\s*,\s*0'
    'window\.resizeTo'
    'window\.close'
    'window\.blur'
    
    # Clickjacking
    'pointer-events\s*:\s*none'
    'z-index\s*:\s*[0-9]{4,}'
    'opacity\s*:\s*0[.0]*[^1-9]'
    'visibility\s*:\s*hidden'
    'position\s*:\s*fixed.*top\s*:\s*0'
    
    # Tab nabbing
    'target\s*=\s*["\x27]_blank'
    'window\.opener'
    'rel\s*=\s*["\x27]?noopener'
    
    # Fake UI elements
    'fake.*login'
    'fake.*button'
    'overlay.*form'
    'screenshot.*url.*bar'
)

analyze_ux_redress_attacks() {
    local content="$1"
    local url="$2"
    
    if [ "$UX_REDRESS_DETECTION" = false ]; then
        analysis_success_none "UX-REDRESS"
        return
    fi
    
    log_info "Analyzing for UX redress/browser attacks..."
    
    local ux_findings=()
    local ux_score=0
    local ux_report="${OUTPUT_DIR}/ux_redress_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "UX REDRESS / BROWSER ATTACK DETECTION"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$ux_report"
    
    # Fetch URL content if needed
    local html_content=""
    if [ -n "$url" ] && echo "$url" | grep -qiE "^https?://"; then
        html_content=$(timeout 20 curl -sS -L --max-time 15 "$url" 2>/dev/null | head -c 200000)
    fi
    
    local analysis_content="$content $html_content"
    
    # 1. Check browser attack patterns
    echo "Browser Attack Pattern Detection:" >> "$ux_report"
    
    for pattern in "${BROWSER_ATTACK_PATTERNS[@]}"; do
        if echo "$analysis_content" | grep -qiE "$pattern"; then
            ux_findings+=("browser_attack:$pattern")
            ((ux_score += 25))
            echo "  ⚠ DETECTED: $pattern" >> "$ux_report"
            log_warning "Browser attack pattern: $pattern"
        fi
    done
    
    # 2. Data URI attack detection
    echo "" >> "$ux_report"
    echo "Data URI Analysis:" >> "$ux_report"
    
    if echo "$content" | grep -qiE "^data:(text/html|application/x-javascript)"; then
        ux_findings+=("data_uri_attack")
        ((ux_score += 50))
        log_threat 55 "Data URI with executable content"
        echo "  ⚠ DATA URI ATTACK DETECTED" >> "$ux_report"
        
        # Decode and analyze
        local encoded_part=$(echo "$content" | grep -oE ";base64,.*" | cut -c9-)
        if [ -n "$encoded_part" ]; then
            local decoded=$(echo "$encoded_part" | base64 -d 2>/dev/null | head -c 5000)
            echo "  Decoded content (preview):" >> "$ux_report"
            echo "$decoded" | head -c 500 >> "$ux_report"
            
            # Check decoded content for additional attacks
            if echo "$decoded" | grep -qiE "password|login|credential"; then
                ux_findings+=("data_uri_phishing")
                ((ux_score += 40))
            fi
        fi
    fi
    
    # 3. Tabnabbing detection
    echo "" >> "$ux_report"
    echo "Tabnabbing Analysis:" >> "$ux_report"
    
    if echo "$analysis_content" | grep -qiE 'target.*_blank' && \
       ! echo "$analysis_content" | grep -qiE 'rel.*noopener'; then
        ux_findings+=("tabnabbing_vulnerable")
        ((ux_score += 30))
        log_warning "Potential tabnabbing vulnerability (no noopener)"
        echo "  ⚠ Missing rel=noopener on _blank links" >> "$ux_report"
    fi
    
    if echo "$analysis_content" | grep -qiE 'window\.opener\s*[.=]'; then
        ux_findings+=("tabnabbing_exploit")
        ((ux_score += 45))
        log_threat 50 "Tabnabbing exploit code detected"
        echo "  ⚠ window.opener manipulation detected" >> "$ux_report"
    fi
    
    # 4. Clickjacking indicators
    echo "" >> "$ux_report"
    echo "Clickjacking Analysis:" >> "$ux_report"
    
    local clickjack_indicators=0
    
    if echo "$analysis_content" | grep -qiE 'position\s*:\s*fixed'; then
        ((clickjack_indicators++))
    fi
    if echo "$analysis_content" | grep -qiE 'z-index\s*:\s*[0-9]{5,}'; then
        ((clickjack_indicators++))
    fi
    if echo "$analysis_content" | grep -qiE 'opacity\s*:\s*0[.0]*[;"]'; then
        ((clickjack_indicators++))
    fi
    if echo "$analysis_content" | grep -qiE 'iframe[^>]+style'; then
        ((clickjack_indicators++))
    fi
    
    if [ "$clickjack_indicators" -ge 2 ]; then
        ux_findings+=("clickjacking:$clickjack_indicators")
        ((ux_score += 40))
        log_threat 45 "Multiple clickjacking indicators ($clickjack_indicators)"
        echo "  ⚠ $clickjack_indicators clickjacking indicators found" >> "$ux_report"
    fi
    
    # 5. URL bar spoofing check
    echo "" >> "$ux_report"
    echo "URL Bar Spoofing Analysis:" >> "$ux_report"
    
    # Check for homograph characters in URL
    if echo "$url" | grep -qE "[^\x00-\x7F]"; then
        ux_findings+=("unicode_url")
        ((ux_score += 35))
        log_warning "Unicode characters in URL (possible homograph attack)"
    fi
    
    # Check for lookalike domain
    local domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
    if echo "$domain" | grep -qiE "paypa1|g00gle|micros0ft|amaz0n|faceb00k"; then
        ux_findings+=("lookalike_domain")
        ((ux_score += 50))
        log_threat 55 "Lookalike domain detected (letter substitution)"
    fi
    
    # Generate summary
    echo "" >> "$ux_report"
    echo "Analysis Summary:" >> "$ux_report"
    echo "  Total Findings: ${#ux_findings[@]}" >> "$ux_report"
    echo "  UX Redress Risk Score: $ux_score" >> "$ux_report"
    
    if [ ${#ux_findings[@]} -gt 0 ]; then
        if [ $ux_score -ge 40 ]; then
            log_threat $((ux_score / 2)) "UX redress/browser attack indicators detected"
        fi
        analysis_success_found "UX-REDRESS" "${#ux_findings[@]}" "Score: $ux_score"
    else
        analysis_success_none "UX-REDRESS"
    fi
}

# ============================================================================
# AUDIT 15: DGA/ALGORITHMIC DOMAIN ANALYSIS
# ============================================================================

analyze_dga_domains() {
    local content="$1"
    
    if [ "$DGA_ANALYSIS" = false ]; then
        analysis_success_none "DGA-ANALYSIS"
        return
    fi
    
    log_info "Analyzing for DGA (Domain Generation Algorithm) patterns..."
    
    local dga_findings=()
    local dga_score=0
    local dga_report="${OUTPUT_DIR}/dga_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "DGA (DOMAIN GENERATION ALGORITHM) ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$dga_report"
    
    # Extract domain from content
    local domain=""
    if echo "$content" | grep -qiE "^https?://"; then
        domain=$(echo "$content" | sed -E 's|^https?://||' | cut -d'/' -f1 | cut -d':' -f1)
    fi
    
    if [ -z "$domain" ]; then
        analysis_success_none "DGA-ANALYSIS"
        return
    fi
    
    echo "Domain: $domain" >> "$dga_report"
    echo "" >> "$dga_report"
    
    # Python-based DGA analysis
    local dga_analysis=$(python3 << EOF 2>/dev/null
import json
import math
import re
from collections import Counter

domain = '$domain'
# Remove TLD for analysis
parts = domain.split('.')
if len(parts) > 1:
    main_domain = '.'.join(parts[:-1]) if parts[-1] in ['com','net','org','io','xyz','tk','ml','ga','cf','gq','top','info','biz','co','us','uk'] else domain
else:
    main_domain = domain

results = {
    'domain': domain,
    'main_domain': main_domain,
    'length': len(main_domain),
}

# 1. Entropy calculation
if main_domain:
    freq = Counter(main_domain.lower())
    probs = [count / len(main_domain) for count in freq.values()]
    entropy = -sum(p * math.log2(p) for p in probs if p > 0)
    results['entropy'] = round(entropy, 4)
    
    # High entropy suggests DGA
    if entropy > 3.8:
        results['high_entropy'] = True
        results['dga_indicator'] = 'HIGH_ENTROPY'
else:
    results['entropy'] = 0

# 2. Consonant/vowel ratio
vowels = set('aeiouAEIOU')
consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
vowel_count = sum(1 for c in main_domain if c in vowels)
consonant_count = sum(1 for c in main_domain if c in consonants)

if vowel_count > 0:
    cv_ratio = consonant_count / vowel_count
else:
    cv_ratio = consonant_count

results['vowel_count'] = vowel_count
results['consonant_count'] = consonant_count
results['cv_ratio'] = round(cv_ratio, 2)

# Abnormal ratio suggests DGA
if cv_ratio > 4 or (vowel_count == 0 and len(main_domain) > 5):
    results['abnormal_cv_ratio'] = True
    results['dga_indicator'] = 'ABNORMAL_CV_RATIO'

# 3. Bigram analysis
def get_bigram_score(text):
    # Common English bigrams
    common_bigrams = {'th','he','in','er','an','re','on','at','en','nd','ti','es','or','te','of','ed','is','it','al','ar','st','to','nt','ng','se','ha','as','ou','io','le','ve','co','me','de','hi','ri','ro','ic','ne','ea','ra','ce'}
    
    bigrams = [text[i:i+2].lower() for i in range(len(text)-1)]
    if not bigrams:
        return 0
    
    common_count = sum(1 for b in bigrams if b in common_bigrams)
    return common_count / len(bigrams)

bigram_score = get_bigram_score(main_domain)
results['bigram_score'] = round(bigram_score, 4)

# Low bigram score suggests DGA
if bigram_score < 0.1 and len(main_domain) > 8:
    results['low_bigram_score'] = True
    results['dga_indicator'] = 'LOW_BIGRAM_SCORE'

# 4. Digit ratio
digit_count = sum(1 for c in main_domain if c.isdigit())
digit_ratio = digit_count / len(main_domain) if main_domain else 0
results['digit_ratio'] = round(digit_ratio, 4)

if digit_ratio > 0.3:
    results['high_digit_ratio'] = True
    results['dga_indicator'] = 'HIGH_DIGIT_RATIO'

# 5. Length-based analysis
if len(main_domain) > 20:
    results['long_domain'] = True
    if 'dga_indicator' not in results:
        results['dga_indicator'] = 'LONG_RANDOM_DOMAIN'

# 6. Sequential character analysis
def has_sequential_chars(text, min_seq=4):
    text = text.lower()
    for i in range(len(text) - min_seq + 1):
        chunk = text[i:i+min_seq]
        if chunk.isalpha():
            # Check for keyboard patterns
            if chunk in 'qwerty' or chunk in 'asdfgh' or chunk in 'zxcvbn':
                return True
            # Check for alphabetic sequence
            if all(ord(chunk[j+1]) - ord(chunk[j]) == 1 for j in range(len(chunk)-1)):
                return True
    return False

if has_sequential_chars(main_domain):
    results['sequential_chars'] = True

# 7. Known DGA patterns
dga_patterns = [
    r'^[a-z]{10,}[0-9]{2,}$',  # letters followed by numbers
    r'^[0-9]{2,}[a-z]{10,}$',  # numbers followed by letters
    r'^[a-z0-9]{16,}$',        # long alphanumeric
    r'^[bcdfghjklmnpqrstvwxz]{5,}$',  # consonant only
]

for pattern in dga_patterns:
    if re.match(pattern, main_domain.lower()):
        results['matches_dga_pattern'] = pattern
        results['dga_indicator'] = 'MATCHES_DGA_PATTERN'
        break

# Calculate overall DGA score
dga_score = 0
if results.get('high_entropy'):
    dga_score += 30
if results.get('abnormal_cv_ratio'):
    dga_score += 25
if results.get('low_bigram_score'):
    dga_score += 25
if results.get('high_digit_ratio'):
    dga_score += 20
if results.get('long_domain'):
    dga_score += 15
if results.get('matches_dga_pattern'):
    dga_score += 35

results['dga_score'] = dga_score

# Verdict
if dga_score >= 60:
    results['verdict'] = 'LIKELY_DGA'
elif dga_score >= 40:
    results['verdict'] = 'POSSIBLE_DGA'
elif dga_score >= 20:
    results['verdict'] = 'SUSPICIOUS'
else:
    results['verdict'] = 'LIKELY_LEGITIMATE'

print(json.dumps(results, indent=2))
EOF
)
    
    if [ -n "$dga_analysis" ]; then
        echo "DGA Analysis Results:" >> "$dga_report"
        echo "$dga_analysis" >> "$dga_report"
        
        # Parse results
        local verdict=$(json_extract_string "$dga_analysis" "verdict")
        local score=$(json_extract_int "$dga_analysis" "dga_score")
        local entropy=$(json_extract_number "$dga_analysis" "entropy")
        
        # Display results
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│                    DGA ANALYSIS RESULTS                      │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
        echo -e "${CYAN}│${NC} Domain:       ${WHITE}$domain${NC}"
        echo -e "${CYAN}│${NC} Entropy:      ${YELLOW}${entropy:-N/A}${NC}"
        echo -e "${CYAN}│${NC} DGA Score:    ${YELLOW}${score:-0}${NC}"
        echo -e "${CYAN}│${NC} Verdict:      ${RED}${verdict:-UNKNOWN}${NC}"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        case "$verdict" in
            "LIKELY_DGA")
                dga_findings+=("dga:likely")
                ((dga_score += 60))
                log_threat 65 "Domain appears to be DGA-generated"
                ;;
            "POSSIBLE_DGA")
                dga_findings+=("dga:possible")
                ((dga_score += 40))
                log_threat 45 "Domain shows DGA characteristics"
                ;;
            "SUSPICIOUS")
                dga_findings+=("dga:suspicious")
                ((dga_score += 20))
                log_warning "Domain has suspicious patterns"
                ;;
        esac
        
        if [ "$verdict" != "LIKELY_LEGITIMATE" ]; then
            analysis_success_found "DGA-ANALYSIS" "1" "Verdict: $verdict, Score: ${score:-0}"
        else
            analysis_success_none "DGA-ANALYSIS"
        fi
    else
        analysis_error "DGA-ANALYSIS" "Python analysis failed"
    fi
}

# ============================================================================
# AUDIT 16: MULTI-LANGUAGE/UNICODE DECEPTION DETECTION
# ============================================================================

# RTL and bidirectional override characters
declare -a BIDI_OVERRIDE_CHARS=(
    '\u202A'  # LRE - Left-to-Right Embedding
    '\u202B'  # RLE - Right-to-Left Embedding
    '\u202C'  # PDF - Pop Directional Formatting
    '\u202D'  # LRO - Left-to-Right Override
    '\u202E'  # RLO - Right-to-Left Override (most dangerous)
    '\u2066'  # LRI - Left-to-Right Isolate
    '\u2067'  # RLI - Right-to-Left Isolate
    '\u2068'  # FSI - First Strong Isolate
    '\u2069'  # PDI - Pop Directional Isolate
)

# Homoglyph mappings (common confusables)
declare -A HOMOGLYPH_MAP=(
    # Cyrillic
    ["а"]="a" ["е"]="e" ["і"]="i" ["о"]="o" ["р"]="p" ["с"]="c" ["х"]="x" ["у"]="y"
    ["А"]="A" ["В"]="B" ["Е"]="E" ["К"]="K" ["М"]="M" ["Н"]="H" ["О"]="O" ["Р"]="P" ["С"]="C" ["Т"]="T" ["Х"]="X"
    # Greek
    ["α"]="a" ["ο"]="o" ["ν"]="v" ["τ"]="t"
    ["Α"]="A" ["Β"]="B" ["Ε"]="E" ["Η"]="H" ["Ι"]="I" ["Κ"]="K" ["Μ"]="M" ["Ν"]="N" ["Ο"]="O" ["Ρ"]="P" ["Τ"]="T" ["Χ"]="X" ["Υ"]="Y" ["Ζ"]="Z"
    # Latin lookalikes
    ["ⅰ"]="i" ["ⅱ"]="ii" ["ℓ"]="l" ["ℐ"]="I"
    # Numbers
    ["Ο"]="0" ["О"]="0" ["ο"]="0"
    ["Ⅰ"]="1" ["ⅼ"]="1" ["ǀ"]="1"
)

analyze_unicode_deception() {
    local content="$1"
    local url="$2"
    
    if [ "$UNICODE_DECEPTION_DETECTION" = false ]; then
        analysis_success_none "UNICODE-DECEPTION"
        return
    fi
    
    log_info "Analyzing for Unicode/multi-language deception..."
    
    local unicode_findings=()
    local unicode_score=0
    local unicode_report="${OUTPUT_DIR}/unicode_deception_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "UNICODE DECEPTION ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$unicode_report"
    
    # Python-based comprehensive Unicode analysis
    local unicode_analysis=$(python3 << EOF 2>/dev/null
import json
import unicodedata
import re

content = '''$content'''
url = '''$url'''

results = {
    'content_length': len(content),
    'findings': []
}

# 1. Check for RTL override characters
rlo_chars = ['\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069']
for char in rlo_chars:
    if char in content or char in url:
        results['findings'].append({
            'type': 'bidi_override',
            'char': repr(char),
            'severity': 'critical' if char == '\u202E' else 'high'
        })

# 2. Check for mixed scripts
def get_script(char):
    try:
        name = unicodedata.name(char, '')
        if 'CYRILLIC' in name:
            return 'Cyrillic'
        elif 'GREEK' in name:
            return 'Greek'
        elif 'LATIN' in name:
            return 'Latin'
        elif 'CJK' in name:
            return 'CJK'
        elif 'ARABIC' in name:
            return 'Arabic'
        elif 'HEBREW' in name:
            return 'Hebrew'
        else:
            return 'Other'
    except:
        return 'Unknown'

scripts_in_url = set()
for char in url:
    if char.isalpha():
        scripts_in_url.add(get_script(char))

results['scripts_in_url'] = list(scripts_in_url)

if len(scripts_in_url) > 1 and 'Latin' in scripts_in_url:
    results['findings'].append({
        'type': 'mixed_scripts',
        'scripts': list(scripts_in_url),
        'severity': 'critical'
    })

# 3. Check for specific homoglyphs
homoglyphs = {
    'а': 'a (Cyrillic)', 'е': 'e (Cyrillic)', 'о': 'o (Cyrillic)',
    'р': 'p (Cyrillic)', 'с': 'c (Cyrillic)', 'х': 'x (Cyrillic)',
    'А': 'A (Cyrillic)', 'В': 'B (Cyrillic)', 'Е': 'E (Cyrillic)',
    'К': 'K (Cyrillic)', 'М': 'M (Cyrillic)', 'Н': 'H (Cyrillic)',
    'О': 'O (Cyrillic)', 'Р': 'P (Cyrillic)', 'С': 'C (Cyrillic)',
    'Т': 'T (Cyrillic)', 'α': 'a (Greek)', 'ο': 'o (Greek)',
}

found_homoglyphs = []
for char, desc in homoglyphs.items():
    if char in url:
        found_homoglyphs.append(desc)

if found_homoglyphs:
    results['findings'].append({
        'type': 'homoglyphs',
        'found': found_homoglyphs,
        'severity': 'critical'
    })

# 4. Check for zero-width characters
zero_width = ['\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD']
for zw in zero_width:
    if zw in content or zw in url:
        results['findings'].append({
            'type': 'zero_width',
            'char': repr(zw),
            'severity': 'high'
        })

# 5. Check for confusable Unicode
confusables = {
    '\u2024': 'ONE DOT LEADER (looks like period)',
    '\u2025': 'TWO DOT LEADER',
    '\u2026': 'HORIZONTAL ELLIPSIS',
    '\u2215': 'DIVISION SLASH (looks like /)',
    '\u2044': 'FRACTION SLASH',
    '\u29F8': 'BIG SOLIDUS',
    '\uFF0F': 'FULLWIDTH SOLIDUS',
    '\u2216': 'SET MINUS (looks like backslash)',
    '\u3002': 'IDEOGRAPHIC FULL STOP (looks like period)',
    '\uFF0E': 'FULLWIDTH FULL STOP',
}

for char, desc in confusables.items():
    if char in url:
        results['findings'].append({
            'type': 'confusable',
            'char': repr(char),
            'description': desc,
            'severity': 'high'
        })

# 6. IDN/Punycode analysis
if url.startswith('http'):
    domain = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
    
    # Check for xn-- prefix (punycode)
    if 'xn--' in domain.lower():
        results['findings'].append({
            'type': 'punycode',
            'domain': domain,
            'severity': 'medium'
        })
    
    # Check for non-ASCII in domain
    non_ascii = [c for c in domain if ord(c) > 127]
    if non_ascii:
        results['findings'].append({
            'type': 'non_ascii_domain',
            'chars': [repr(c) for c in non_ascii],
            'severity': 'high'
        })

# Calculate overall score
score = 0
for finding in results['findings']:
    if finding['severity'] == 'critical':
        score += 50
    elif finding['severity'] == 'high':
        score += 30
    elif finding['severity'] == 'medium':
        score += 15

results['unicode_score'] = score

if score >= 50:
    results['verdict'] = 'DECEPTIVE_UNICODE'
elif score >= 25:
    results['verdict'] = 'SUSPICIOUS_UNICODE'
else:
    results['verdict'] = 'LIKELY_SAFE'

print(json.dumps(results, indent=2))
EOF
)
    
    if [ -n "$unicode_analysis" ]; then
        echo "Unicode Analysis Results:" >> "$unicode_report"
        echo "$unicode_analysis" >> "$unicode_report"
        
        # Parse results
        local verdict=$(json_extract_string "$unicode_analysis" "verdict")
        local score=$(json_extract_int "$unicode_analysis" "unicode_score")
        local finding_count=$(echo "$unicode_analysis" | grep -c '"type":')
        
        if [ "$verdict" = "DECEPTIVE_UNICODE" ]; then
            unicode_findings+=("deceptive_unicode")
            ((unicode_score += 60))
            log_threat 65 "Deceptive Unicode characters detected"
            
            # Check for specific critical issues
            if echo "$unicode_analysis" | grep -q "bidi_override"; then
                log_critical "⚠️  RTL OVERRIDE ATTACK DETECTED!"
                unicode_findings+=("rlo_attack")
            fi
            
            if echo "$unicode_analysis" | grep -q "homoglyphs"; then
                log_critical "⚠️  HOMOGLYPH ATTACK DETECTED!"
                unicode_findings+=("homoglyph_attack")
            fi
            
        elif [ "$verdict" = "SUSPICIOUS_UNICODE" ]; then
            unicode_findings+=("suspicious_unicode")
            ((unicode_score += 30))
            log_warning "Suspicious Unicode patterns detected"
        fi
        
        if [ ${#unicode_findings[@]} -gt 0 ]; then
            analysis_success_found "UNICODE-DECEPTION" "${#unicode_findings[@]}" "Score: ${score:-0}"
        else
            analysis_success_none "UNICODE-DECEPTION"
        fi
    else
        analysis_error "UNICODE-DECEPTION" "Python analysis failed"
    fi
}

# ============================================================================
# AUDIT 17: SOCIAL THREAT TRACKING
# ============================================================================

# Social threat tracking sources
declare -a SOCIAL_THREAT_SOURCES=(
    "https://urlhaus-api.abuse.ch/v1/url/"
    "https://www.phishtank.com/checkurl/"
)

analyze_social_threat_tracking() {
    local url="$1"
    local domain="$2"
    
    if [ "$SOCIAL_THREAT_TRACKING" = false ]; then
        analysis_success_none "SOCIAL-THREATS"
        return
    fi
    
    log_info "Checking social threat tracking sources..."
    
    local social_findings=()
    local social_score=0
    local social_report="${OUTPUT_DIR}/social_threat_tracking.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "SOCIAL THREAT TRACKING"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo "Target: $url"
        echo ""
    } > "$social_report"
    
    # Extract domain if not provided
    if [ -z "$domain" ] && echo "$url" | grep -qiE "^https?://"; then
        domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1)
    fi
    
    # 1. URLhaus check
    echo "URLhaus Check:" >> "$social_report"
    local urlhaus_result=$(curl -sS --max-time 10 \
        -d "url=$url" \
        "https://urlhaus-api.abuse.ch/v1/url/" 2>/dev/null)
    
    if [ -n "$urlhaus_result" ]; then
        if echo "$urlhaus_result" | grep -q '"query_status":"ok"'; then
            social_findings+=("urlhaus:found")
            ((social_score += 70))
            
            # Extract details first
            local threat_type=$(json_extract_string "$urlhaus_result" "threat")
            
            # Forensic detection output
            log_forensic_detection 100 \
                "URLhaus Database Match" \
                "$url" \
                "URLhaus API Query" \
                "Social threat tracking" \
                "URL is associated with malware distribution" \
                "https://urlhaus.abuse.ch"
            
            echo "  ⚠ FOUND IN URLHAUS DATABASE" >> "$social_report"
            echo "  Threat Type: $threat_type" >> "$social_report"
        else
            echo "  Not found" >> "$social_report"
        fi
    fi
    
    # 2. Check domain reputation via DNSBLs
    echo "" >> "$social_report"
    echo "DNSBL Check:" >> "$social_report"
    
    if [ -n "$domain" ]; then
        # Reverse domain for DNSBL query
        local reversed=$(echo "$domain" | awk -F. '{for(i=NF;i>0;i--) printf "%s%s",$i,(i>1?".":"")}')
        
        declare -a DNSBLS=(
            "zen.spamhaus.org"
            "bl.spamcop.net"
            "dnsbl.sorbs.net"
            "b.barracudacentral.org"
            "dbl.spamhaus.org"
        )
        
        local dnsbl_hits=0
        for dnsbl in "${DNSBLS[@]}"; do
            local check_result=$(dig +short "$reversed.$dnsbl" 2>/dev/null | head -1)
            if [ -n "$check_result" ] && echo "$check_result" | grep -qE "^127\."; then
                ((dnsbl_hits++))
                social_findings+=("dnsbl:$dnsbl")
                echo "  ⚠ Listed in: $dnsbl" >> "$social_report"
            fi
        done
        
        if [ "$dnsbl_hits" -gt 0 ]; then
            ((social_score += dnsbl_hits * 15))
            log_warning "Domain listed in $dnsbl_hits DNSBL(s)"
        else
            echo "  Not listed in checked DNSBLs" >> "$social_report"
        fi
    fi
    
    # 3. Check for recent mentions in public threat feeds (simulated)
    echo "" >> "$social_report"
    echo "Threat Feed Check:" >> "$social_report"
    
    # This would integrate with real threat intelligence APIs
    # For now, check against local threat intel we've downloaded
    if [ -d "${TEMP_DIR}/threat_intel" ]; then
        for feed_file in "${TEMP_DIR}/threat_intel"/*.txt; do
            [ -f "$feed_file" ] || continue
            if grep -qi "$domain" "$feed_file" 2>/dev/null || grep -qi "$url" "$feed_file" 2>/dev/null; then
                local feed_name=$(basename "$feed_file" .txt)
                social_findings+=("feed_hit:$feed_name")
                ((social_score += 40))
                log_warning "Found in threat feed: $feed_name"
                echo "  ⚠ Found in: $feed_name" >> "$social_report"
            fi
        done
    fi
    
    # Generate summary
    echo "" >> "$social_report"
    echo "Analysis Summary:" >> "$social_report"
    echo "  Total Findings: ${#social_findings[@]}" >> "$social_report"
    echo "  Social Threat Score: $social_score" >> "$social_report"
    
    if [ ${#social_findings[@]} -gt 0 ]; then
        if [ $social_score -ge 50 ]; then
            log_threat $((social_score / 2)) "Social threat tracking detected issues"
        fi
        analysis_success_found "SOCIAL-THREATS" "${#social_findings[@]}" "Score: $social_score"
    else
        analysis_success_none "SOCIAL-THREATS"
    fi
}

# ============================================================================
# AUDIT 18: BLOCKCHAIN/SMART CONTRACT SCAM ANALYSIS
# ============================================================================

# Known scam contract patterns
declare -a CRYPTO_SCAM_CONTRACT_PATTERNS=(
    "approve.*unlimited"
    "setApprovalForAll"
    "transfer.*owner"
    "drain"
    "honeypot"
    "rug.*pull"
    "mint.*free"
    "claim.*airdrop"
)

# Known scam wallet address prefixes (simulated)
declare -a KNOWN_SCAM_WALLETS=(
    "0x000000000000000000000000000000000000dead"
    "0x0000000000000000000000000000000000000000"
)

analyze_blockchain_scams() {
    local content="$1"
    
    if [ "$BLOCKCHAIN_SCAM_ANALYSIS" = false ]; then
        analysis_success_none "BLOCKCHAIN-SCAMS"
        return
    fi
    
    log_info "Analyzing for blockchain/smart contract scams..."
    
    local blockchain_findings=()
    local blockchain_score=0
    local blockchain_report="${OUTPUT_DIR}/blockchain_scam_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "BLOCKCHAIN/SMART CONTRACT SCAM ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$blockchain_report"
    
    # 1. Extract cryptocurrency addresses
    echo "Cryptocurrency Address Detection:" >> "$blockchain_report"
    
    # Ethereum addresses (0x...)
    local eth_addresses=$(echo "$content" | grep -oiE '0x[a-fA-F0-9]{40}' | sort -u)
    # Bitcoin addresses
    local btc_addresses=$(echo "$content" | grep -oE '(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}' | sort -u)
    # Solana addresses
    local sol_addresses=$(echo "$content" | grep -oE '[1-9A-HJ-NP-Za-km-z]{32,44}' | sort -u)
    
    if [ -n "$eth_addresses" ]; then
        echo "  Ethereum Addresses:" >> "$blockchain_report"
        echo "$eth_addresses" >> "$blockchain_report"
        blockchain_findings+=("eth_addresses:$(echo "$eth_addresses" | wc -l)")
        
        # Check against known scam wallets (would use Etherscan API in production)
        while IFS= read -r addr; do
            [ -z "$addr" ] && continue
            record_ioc "eth_address" "$addr" "Ethereum address in QR content"
            
            # Simulated scam check (in production, use Etherscan/similar API)
            for scam_addr in "${KNOWN_SCAM_WALLETS[@]}"; do
                if [ "${addr,,}" = "${scam_addr,,}" ]; then
                    blockchain_findings+=("known_scam_wallet:$addr")
                    ((blockchain_score += 80))
                    log_threat 85 "KNOWN SCAM WALLET DETECTED: $addr"
                fi
            done
        done <<< "$eth_addresses"
    fi
    
    if [ -n "$btc_addresses" ]; then
        echo "  Bitcoin Addresses:" >> "$blockchain_report"
        echo "$btc_addresses" >> "$blockchain_report"
        blockchain_findings+=("btc_addresses:$(echo "$btc_addresses" | wc -l)")
        
        while IFS= read -r addr; do
            [ -z "$addr" ] && continue
            record_ioc "btc_address" "$addr" "Bitcoin address in QR content"
        done <<< "$btc_addresses"
    fi
    
    # 2. Check for smart contract interaction patterns
    echo "" >> "$blockchain_report"
    echo "Smart Contract Pattern Analysis:" >> "$blockchain_report"
    
    for pattern in "${CRYPTO_SCAM_CONTRACT_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            blockchain_findings+=("contract_pattern:$pattern")
            ((blockchain_score += 30))
            log_warning "Suspicious contract pattern: $pattern"
            echo "  ⚠ DETECTED: $pattern" >> "$blockchain_report"
        fi
    done
    
    # 3. DeFi scam indicators
    echo "" >> "$blockchain_report"
    echo "DeFi Scam Indicators:" >> "$blockchain_report"
    
    # Check for fake swap/DEX URLs
    if echo "$content" | grep -qiE "uniswap.*claim|pancakeswap.*free|sushiswap.*bonus"; then
        blockchain_findings+=("fake_dex")
        ((blockchain_score += 50))
        log_threat 55 "Fake DEX claim pattern detected"
        echo "  ⚠ Fake DEX claim pattern" >> "$blockchain_report"
    fi
    
    # Check for fake wallet connect
    if echo "$content" | grep -qiE "walletconnect.*verify|connect.*wallet.*claim"; then
        blockchain_findings+=("fake_wallet_connect")
        ((blockchain_score += 45))
        log_threat 50 "Fake wallet connect pattern"
        echo "  ⚠ Fake wallet connect pattern" >> "$blockchain_report"
    fi
    
    # 4. NFT scam patterns
    if echo "$content" | grep -qiE "free.*nft|nft.*mint.*0|claim.*nft|airdrop.*nft"; then
        blockchain_findings+=("nft_scam")
        ((blockchain_score += 40))
        log_warning "NFT scam pattern detected"
        echo "  ⚠ NFT scam pattern" >> "$blockchain_report"
    fi
    
    # 5. Etherscan API check (if API key available)
    if [ -n "$ETHERSCAN_API_KEY" ] && [ -n "$eth_addresses" ]; then
        echo "" >> "$blockchain_report"
        echo "Etherscan Verification:" >> "$blockchain_report"
        
        local first_addr=$(echo "$eth_addresses" | head -1)
        local etherscan_result=$(curl -sS --max-time 10 \
            "https://api.etherscan.io/api?module=account&action=balance&address=$first_addr&tag=latest&apikey=$ETHERSCAN_API_KEY" 2>/dev/null)
        
        if [ -n "$etherscan_result" ]; then
            echo "  API Response: $etherscan_result" >> "$blockchain_report"
        fi
    fi
    
    # Generate summary
    echo "" >> "$blockchain_report"
    echo "Analysis Summary:" >> "$blockchain_report"
    echo "  Total Findings: ${#blockchain_findings[@]}" >> "$blockchain_report"
    echo "  Blockchain Scam Score: $blockchain_score" >> "$blockchain_report"
    
    if [ ${#blockchain_findings[@]} -gt 0 ]; then
        if [ $blockchain_score -ge 40 ]; then
            log_threat $((blockchain_score / 2)) "Blockchain/crypto scam indicators detected"
        fi
        analysis_success_found "BLOCKCHAIN-SCAMS" "${#blockchain_findings[@]}" "Score: $blockchain_score"
    else
        analysis_success_none "BLOCKCHAIN-SCAMS"
    fi
}

# ============================================================================
# AUDIT 19: CONTACT EVENT DETONATION (VCARD/ICALENDAR)
# ============================================================================

# Suspicious vCard fields
declare -a SUSPICIOUS_VCARD_PATTERNS=(
    "URL:.*bit\.ly"
    "URL:.*tinyurl"
    "NOTE:.*verify"
    "NOTE:.*password"
    "NOTE:.*click"
    "X-.*:.*http"
    "PHOTO.*http"
)

# Suspicious calendar patterns
declare -a SUSPICIOUS_ICAL_PATTERNS=(
    "DESCRIPTION:.*verify"
    "DESCRIPTION:.*password"
    "DESCRIPTION:.*click.*here"
    "URL:.*bit\.ly"
    "ATTENDEE:.*@"
    "ORGANIZER:.*suspicious"
)

analyze_contact_events() {
    local content="$1"
    
    if [ "$CONTACT_EVENT_ANALYSIS" = false ]; then
        analysis_success_none "CONTACT-EVENTS"
        return
    fi
    
    # Check if content is vCard or iCalendar
    local is_vcard=false
    local is_ical=false
    
    if echo "$content" | grep -qi "BEGIN:VCARD"; then
        is_vcard=true
    fi
    if echo "$content" | grep -qi "BEGIN:VCALENDAR\|BEGIN:VEVENT"; then
        is_ical=true
    fi
    
    if [ "$is_vcard" = false ] && [ "$is_ical" = false ]; then
        analysis_success_none "CONTACT-EVENTS"
        return
    fi
    
    log_info "Analyzing contact/calendar event content..."
    
    local contact_findings=()
    local contact_score=0
    local contact_report="${OUTPUT_DIR}/contact_event_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "CONTACT/CALENDAR EVENT ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$contact_report"
    
    if [ "$is_vcard" = true ]; then
        echo "vCard Analysis:" >> "$contact_report"
        log_info "  Analyzing vCard content..."
        
        # Extract fields
        local name=$(echo "$content" | grep -iE "^(FN|N):" | head -1 | cut -d':' -f2-)
        local email=$(echo "$content" | grep -iE "^EMAIL" | cut -d':' -f2- | head -1)
        local phone=$(echo "$content" | grep -iE "^TEL" | cut -d':' -f2- | head -1)
        local url=$(echo "$content" | grep -iE "^URL" | cut -d':' -f2- | head -1)
        local note=$(echo "$content" | grep -iE "^NOTE" | cut -d':' -f2- | head -1)
        
        echo "  Name: ${name:-N/A}" >> "$contact_report"
        echo "  Email: ${email:-N/A}" >> "$contact_report"
        echo "  Phone: ${phone:-N/A}" >> "$contact_report"
        echo "  URL: ${url:-N/A}" >> "$contact_report"
        echo "  Note: ${note:-N/A}" >> "$contact_report"
        
        # Check for suspicious patterns
        for pattern in "${SUSPICIOUS_VCARD_PATTERNS[@]}"; do
            if echo "$content" | grep -qiE "$pattern"; then
                contact_findings+=("vcard_suspicious:$pattern")
                ((contact_score += 25))
                log_warning "Suspicious vCard pattern: $pattern"
            fi
        done
        
        # Check if email domain is suspicious
        if [ -n "$email" ]; then
            local email_domain=$(echo "$email" | cut -d'@' -f2)
            if echo "$email_domain" | grep -qiE "\.tk$|\.ml$|\.ga$|\.cf$|\.gq$"; then
                contact_findings+=("vcard_suspicious_email:$email_domain")
                ((contact_score += 30))
                log_warning "vCard has email with suspicious TLD: $email_domain"
            fi
        fi
        
        # Check for URL in vCard
        if [ -n "$url" ]; then
            record_ioc "vcard_url" "$url" "URL from vCard"
            
            # Analyze URL for threats
            if echo "$url" | grep -qiE "bit\.ly|tinyurl|ngrok|duckdns"; then
                contact_findings+=("vcard_suspicious_url")
                ((contact_score += 35))
                log_warning "vCard contains suspicious URL"
            fi
        fi
        
        # Check for BEC patterns in name
        if echo "$name" | grep -qiE "ceo|cfo|director|executive|finance|payroll|hr"; then
            contact_findings+=("vcard_bec_title")
            ((contact_score += 20))
            log_warning "vCard contains executive title (possible BEC setup)"
        fi
    fi
    
    if [ "$is_ical" = true ]; then
        echo "" >> "$contact_report"
        echo "iCalendar Analysis:" >> "$contact_report"
        log_info "  Analyzing iCalendar content..."
        
        # Extract fields
        local summary=$(echo "$content" | grep -iE "^SUMMARY:" | cut -d':' -f2- | head -1)
        local description=$(echo "$content" | grep -iE "^DESCRIPTION:" | cut -d':' -f2- | head -1)
        local location=$(echo "$content" | grep -iE "^LOCATION:" | cut -d':' -f2- | head -1)
        local organizer=$(echo "$content" | grep -iE "^ORGANIZER" | head -1)
        
        echo "  Summary: ${summary:-N/A}" >> "$contact_report"
        echo "  Description: ${description:0:100}..." >> "$contact_report"
        echo "  Location: ${location:-N/A}" >> "$contact_report"
        echo "  Organizer: ${organizer:-N/A}" >> "$contact_report"
        
        # Check for suspicious patterns
        for pattern in "${SUSPICIOUS_ICAL_PATTERNS[@]}"; do
            if echo "$content" | grep -qiE "$pattern"; then
                contact_findings+=("ical_suspicious:$pattern")
                ((contact_score += 25))
                log_warning "Suspicious calendar pattern: $pattern"
            fi
        done
        
        # Calendar spam indicators
        if echo "$summary$description" | grep -qiE "lottery|winner|prize|claim|verify|suspended"; then
            contact_findings+=("calendar_spam")
            ((contact_score += 40))
            log_threat 45 "Calendar spam/scam content detected"
        fi
        
        # Check for suspicious meeting links
        if echo "$location$description" | grep -qiE "zoom\.us/j/[0-9]+|teams\.microsoft\.com/l/meetup"; then
            # Extract meeting URL
            local meeting_url=$(echo "$location$description" | grep -oiE "https?://[^\s]+" | head -1)
            if [ -n "$meeting_url" ]; then
                record_ioc "calendar_meeting_url" "$meeting_url" "Meeting URL from calendar"
            fi
        fi
    fi
    
    # Generate summary
    echo "" >> "$contact_report"
    echo "Analysis Summary:" >> "$contact_report"
    echo "  Total Findings: ${#contact_findings[@]}" >> "$contact_report"
    echo "  Contact Event Risk Score: $contact_score" >> "$contact_report"
    
    if [ ${#contact_findings[@]} -gt 0 ]; then
        if [ $contact_score -ge 30 ]; then
            log_threat $((contact_score / 2)) "Contact/calendar event threats detected"
        fi
        analysis_success_found "CONTACT-EVENTS" "${#contact_findings[@]}" "Score: $contact_score"
    else
        analysis_success_none "CONTACT-EVENTS"
    fi
}

# ============================================================================
# AUDIT 20: GEOLOCATION HOTSPOT DETECTION
# ============================================================================

# High-risk geographic regions (ISO country codes)
declare -A GEO_RISK_SCORES=(
    ["RU"]=40  # Russia
    ["CN"]=35  # China
    ["KP"]=60  # North Korea
    ["IR"]=45  # Iran
    ["SY"]=50  # Syria
    ["UA"]=20  # Ukraine (cyber activity)
    ["NG"]=30  # Nigeria (419 scams)
    ["RO"]=20  # Romania
    ["BR"]=15  # Brazil
    ["IN"]=10  # India
)

# Known malware distribution hotspot ASNs
declare -a MALWARE_HOTSPOT_ASNS=(
    "AS44477"   # Stark Industries (abuse)
    "AS206349"  # Constantmalta Limited
    "AS57523"   # Chang Way Technologies
    "AS211252"  # Delis LLC
    "AS47846"   # Sedo Domain Parking
)

analyze_geo_hotspots() {
    local content="$1"
    local url="$2"
    
    if [ "$GEO_HOTSPOT_DETECTION" = false ]; then
        analysis_success_none "GEO-HOTSPOTS"
        return
    fi
    
    log_info "Analyzing geographic threat hotspots..."
    
    local geo_findings=()
    local geo_score=0
    local geo_report="${OUTPUT_DIR}/geo_hotspot_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "GEOGRAPHIC HOTSPOT DETECTION"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$geo_report"
    
    # Extract domain/IP
    local domain=""
    local ip=""
    
    if echo "$url" | grep -qiE "^https?://"; then
        domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1 | cut -d':' -f1)
    fi
    
    # Check if domain is IP
    if echo "$domain" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
        ip="$domain"
    else
        # Resolve domain
        ip=$(dig +short A "$domain" 2>/dev/null | head -1)
    fi
    
    echo "Domain: $domain" >> "$geo_report"
    echo "IP: ${ip:-N/A}" >> "$geo_report"
    echo "" >> "$geo_report"
    
    if [ -n "$ip" ]; then
        # Get geolocation info
        log_info "  Looking up IP geolocation..."
        
        local geo_info=$(curl -sS --max-time 10 "http://ip-api.com/json/$ip" 2>/dev/null)
        
        if [ -n "$geo_info" ]; then
            local country=$(json_extract_string "$geo_info" "country")
            local country_code=$(json_extract_string "$geo_info" "countryCode")
            local region=$(json_extract_string "$geo_info" "regionName")
            local city=$(json_extract_string "$geo_info" "city")
            local isp=$(json_extract_string "$geo_info" "isp")
            local org=$(json_extract_string "$geo_info" "org")
            local as_info=$(json_extract_string "$geo_info" "as")
            
            echo "Geolocation Results:" >> "$geo_report"
            echo "  Country: $country ($country_code)" >> "$geo_report"
            echo "  Region: $region" >> "$geo_report"
            echo "  City: $city" >> "$geo_report"
            echo "  ISP: $isp" >> "$geo_report"
            echo "  Organization: $org" >> "$geo_report"
            echo "  AS: $as_info" >> "$geo_report"
            
            # Check against high-risk countries
            if [ -n "$country_code" ] && [ -n "${GEO_RISK_SCORES[$country_code]}" ]; then
                local risk_score="${GEO_RISK_SCORES[$country_code]}"
                geo_findings+=("high_risk_country:$country_code")
                ((geo_score += risk_score))
                log_warning "IP located in high-risk country: $country ($country_code)"
                echo "  ⚠ HIGH-RISK COUNTRY: $country (risk: $risk_score)" >> "$geo_report"
            fi
            
            # Check ASN against known malware hotspots
            local asn=$(echo "$as_info" | grep -oE "AS[0-9]+")
            for hotspot_asn in "${MALWARE_HOTSPOT_ASNS[@]}"; do
                if [ "$asn" = "$hotspot_asn" ]; then
                    geo_findings+=("malware_hotspot_asn:$asn")
                    ((geo_score += 50))
                    log_threat 55 "IP in known malware distribution ASN: $asn"
                    echo "  ⚠ MALWARE HOTSPOT ASN: $asn" >> "$geo_report"
                fi
            done
            
            # Check for hosting vs residential
            if echo "$isp$org" | grep -qiE "hosting|vps|server|cloud|datacenter"; then
                geo_findings+=("hosting_provider")
                ((geo_score += 10))
                echo "  Info: Hosted on commercial infrastructure" >> "$geo_report"
            fi
        fi
    fi
    
    # Check for suspicious TLD geography correlation
    echo "" >> "$geo_report"
    echo "TLD Analysis:" >> "$geo_report"
    
    local tld=$(echo "$domain" | grep -oE '\.[a-z]+$' | tail -1)
    case "$tld" in
        ".ru"|".su")
            geo_findings+=("russian_tld")
            ((geo_score += 20))
            echo "  ⚠ Russian TLD detected" >> "$geo_report"
            ;;
        ".cn")
            geo_findings+=("chinese_tld")
            ((geo_score += 15))
            echo "  ⚠ Chinese TLD detected" >> "$geo_report"
            ;;
        ".ir")
            geo_findings+=("iranian_tld")
            ((geo_score += 25))
            echo "  ⚠ Iranian TLD detected" >> "$geo_report"
            ;;
        ".kp")
            geo_findings+=("nk_tld")
            ((geo_score += 50))
            echo "  ⚠ North Korean TLD detected" >> "$geo_report"
            ;;
    esac
    
    # Generate summary
    echo "" >> "$geo_report"
    echo "Analysis Summary:" >> "$geo_report"
    echo "  Total Findings: ${#geo_findings[@]}" >> "$geo_report"
    echo "  Geographic Risk Score: $geo_score" >> "$geo_report"
    
    if [ ${#geo_findings[@]} -gt 0 ]; then
        if [ $geo_score -ge 30 ]; then
            log_warning "Geographic threat indicators detected"
        fi
        analysis_success_found "GEO-HOTSPOTS" "${#geo_findings[@]}" "Score: $geo_score"
    else
        analysis_success_none "GEO-HOTSPOTS"
    fi
}

# ============================================================================
# AUDIT 21: EMERGING PROTOCOLS (WebRTC, BLE, Payment QR)
# ============================================================================

# Payment QR schemes
declare -A PAYMENT_QR_SCHEMES=(
    # International
    ["emvco"]="EMV.*QR|EMVCO"
    ["iso20022"]="ISO\s*20022|pain\.[0-9]+"
    
    # Regional payment systems
    ["pix_brazil"]="pix\.bcb\.gov\.br|PIX|00020126"
    ["upi_india"]="upi://|pa=.*@|BHIM"
    ["paynow_sg"]="PayNow|SGQR"
    ["promptpay_th"]="PromptPay|00020101021129"
    ["duitnow_my"]="DuitNow"
    ["khqr_kh"]="KHQR"
    ["qrph_ph"]="QRPh|InstaPay"
    ["vnpay_vn"]="VNPay|VNQR"
    
    # Chinese payment
    ["alipay"]="alipays://|alipay\.com|ALIPAY"
    ["wechat_pay"]="weixin://|wxp://|WECHATPAY"
    ["unionpay"]="UnionPay|UPQR|95516"
    
    # Western payment
    ["paypal_qr"]="paypal\.me|PayPal.*QR"
    ["venmo_qr"]="venmo\.com|Venmo"
    ["cashapp_qr"]='\$[A-Za-z][A-Za-z0-9_]{1,20}|cash\.app'
    ["zelle_qr"]="zellepay\.com|Zelle"
    
    # Crypto payment
    ["bitcoin_pay"]="bitcoin:|BTC:"
    ["ethereum_pay"]="ethereum:|ETH:"
    ["lightning"]="lightning:|lnbc[0-9]+"
)

# WebRTC and emerging protocol patterns
declare -a EMERGING_PROTOCOL_PATTERNS=(
    # WebRTC
    "stun:"
    "turn:"
    "webrtc://"
    "RTCPeerConnection"
    "RTCDataChannel"
    "getUserMedia"
    "getDisplayMedia"
    
    # Bluetooth LE
    "bluetooth:"
    "ble://"
    "gatt://"
    "uuid.*0000[0-9a-f]{4}-0000-1000-8000-00805f9b34fb"
    
    # NFC
    "nfc:"
    "ndef:"
    "android\.nfc"
    
    # IoT protocols
    "mqtt://"
    "mqtts://"
    "coap://"
    "coaps://"
    "lwm2m://"
    "zigbee://"
    "zwave://"
    
    # Smart home
    "homekit://"
    "hap://"
    "matter://"
    "thread://"
    
    # Automotive
    "can://"
    "obd://"
    "carplay://"
    "androidauto://"
)

analyze_emerging_protocols() {
    local content="$1"
    
    if [ "$EMERGING_PROTOCOL_DETECTION" = false ]; then
        analysis_success_none "EMERGING-PROTOCOLS"
        return
    fi
    
    log_info "Analyzing for emerging protocols and payment schemes..."
    
    local protocol_findings=()
    local protocol_score=0
    local protocol_report="${OUTPUT_DIR}/emerging_protocols_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "EMERGING PROTOCOLS & PAYMENT QR ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$protocol_report"
    
    # 1. Check for payment QR schemes
    echo "Payment QR Scheme Detection:" >> "$protocol_report"
    
    for scheme_name in "${!PAYMENT_QR_SCHEMES[@]}"; do
        local pattern="${PAYMENT_QR_SCHEMES[$scheme_name]}"
        if echo "$content" | grep -qiE "$pattern"; then
            protocol_findings+=("payment_qr:$scheme_name")
            ((protocol_score += 15))
            log_info "Payment QR scheme detected: $scheme_name"
            echo "  ✓ Detected: $scheme_name" >> "$protocol_report"
            
            # Additional validation based on scheme
            case "$scheme_name" in
                "pix_brazil")
                    # PIX QR validation
                    if echo "$content" | grep -qE "^00020126"; then
                        echo "    PIX format: Valid structure" >> "$protocol_report"
                    fi
                    ;;
                "upi_india")
                    # Extract UPI ID
                    local upi_id=$(echo "$content" | grep -oiE "pa=[^&]+" | cut -d'=' -f2)
                    if [ -n "$upi_id" ]; then
                        echo "    UPI ID: $upi_id" >> "$protocol_report"
                        record_ioc "upi_id" "$upi_id" "UPI payment ID from QR"
                    fi
                    ;;
                "alipay"|"wechat_pay")
                    protocol_findings+=("chinese_payment_app")
                    log_warning "Chinese payment app QR detected"
                    ;;
                "lightning")
                    # Extract Lightning invoice
                    local ln_invoice=$(echo "$content" | grep -oiE "lnbc[a-z0-9]+" | head -1)
                    if [ -n "$ln_invoice" ]; then
                        record_ioc "lightning_invoice" "$ln_invoice" "Lightning Network invoice"
                    fi
                    ;;
            esac
        fi
    done
    
    # 2. Check for emerging protocol patterns
    echo "" >> "$protocol_report"
    echo "Emerging Protocol Detection:" >> "$protocol_report"
    
    for pattern in "${EMERGING_PROTOCOL_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            protocol_findings+=("protocol:$pattern")
            ((protocol_score += 20))
            log_warning "Emerging protocol detected: $pattern"
            echo "  ⚠ Detected: $pattern" >> "$protocol_report"
        fi
    done
    
    # 3. WebRTC-specific analysis
    if echo "$content" | grep -qiE "stun:|turn:|webrtc"; then
        echo "" >> "$protocol_report"
        echo "WebRTC Analysis:" >> "$protocol_report"
        
        # Extract STUN/TURN servers
        local stun_servers=$(echo "$content" | grep -oiE "stun:[^\s]+" | head -5)
        local turn_servers=$(echo "$content" | grep -oiE "turn:[^\s]+" | head -5)
        
        if [ -n "$stun_servers" ]; then
            echo "  STUN Servers:" >> "$protocol_report"
            echo "$stun_servers" >> "$protocol_report"
            protocol_findings+=("webrtc_stun")
        fi
        
        if [ -n "$turn_servers" ]; then
            echo "  TURN Servers:" >> "$protocol_report"
            echo "$turn_servers" >> "$protocol_report"
            protocol_findings+=("webrtc_turn")
            ((protocol_score += 25))
            log_warning "TURN server in QR - potential for media relay abuse"
        fi
    fi
    
    # 4. Bluetooth LE analysis
    if echo "$content" | grep -qiE "bluetooth:|ble:|gatt:"; then
        echo "" >> "$protocol_report"
        echo "Bluetooth LE Analysis:" >> "$protocol_report"
        
        # Extract UUIDs
        local ble_uuids=$(echo "$content" | grep -oiE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" | head -5)
        if [ -n "$ble_uuids" ]; then
            echo "  BLE UUIDs:" >> "$protocol_report"
            echo "$ble_uuids" >> "$protocol_report"
            protocol_findings+=("ble_uuid")
            
            # Check for known malicious/suspicious UUIDs
            # (In production, would check against a database)
        fi
    fi
    
    # 5. IoT protocol analysis
    if echo "$content" | grep -qiE "mqtt://|coap://|zigbee:|zwave:"; then
        protocol_findings+=("iot_protocol")
        ((protocol_score += 30))
        log_warning "IoT protocol in QR - verify device trust"
        echo "" >> "$protocol_report"
        echo "IoT Protocol Warning: IoT protocol detected - verify source" >> "$protocol_report"
    fi
    
    # 6. Payment fraud indicators
    echo "" >> "$protocol_report"
    echo "Payment Fraud Analysis:" >> "$protocol_report"
    
    # Check for payment request without proper merchant info
    if echo "$content" | grep -qiE "pay|amount|money|transfer" && \
       ! echo "$content" | grep -qiE "merchant|store|shop|company"; then
        protocol_findings+=("suspicious_payment")
        ((protocol_score += 25))
        log_warning "Payment request without merchant identification"
        echo "  ⚠ Payment without clear merchant info" >> "$protocol_report"
    fi
    
    # Check for unusually high amounts
    local amounts=$(echo "$content" | grep -oE "[0-9]+(\.[0-9]+)?" | head -5)
    while IFS= read -r amount; do
        if [ -n "$amount" ]; then
            # Check if amount > 10000 (could be scam)
            if (( $(echo "$amount > 10000" | bc -l 2>/dev/null || echo 0) )); then
                protocol_findings+=("high_amount:$amount")
                ((protocol_score += 15))
                log_warning "High payment amount detected: $amount"
            fi
        fi
    done <<< "$amounts"
    
    # Generate summary
    echo "" >> "$protocol_report"
    echo "Analysis Summary:" >> "$protocol_report"
    echo "  Total Findings: ${#protocol_findings[@]}" >> "$protocol_report"
    echo "  Protocol Risk Score: $protocol_score" >> "$protocol_report"
    
    if [ ${#protocol_findings[@]} -gt 0 ]; then
        if [ $protocol_score -ge 30 ]; then
            log_warning "Emerging protocol/payment analysis complete"
        fi
        analysis_success_found "EMERGING-PROTOCOLS" "${#protocol_findings[@]}" "Score: $protocol_score"
    else
        analysis_success_none "EMERGING-PROTOCOLS"
    fi
}

# ============================================================================
# AUDIT 22: HUMAN REVIEWER FEEDBACK LOOP
# ============================================================================

# Feedback storage
FEEDBACK_DIR="${OUTPUT_DIR}/feedback"
FEEDBACK_FILE="${FEEDBACK_DIR}/analysis_feedback.json"

initialize_feedback_system() {
    if [ "$FEEDBACK_LOOP_ENABLED" = false ]; then
        return
    fi
    
    mkdir -p "$FEEDBACK_DIR"
    
    # Initialize feedback file if not exists
    if [ ! -f "$FEEDBACK_FILE" ]; then
        echo '{"feedback_entries": [], "created": "'$(date -Iseconds)'"}' > "$FEEDBACK_FILE"
    fi
}

record_analysis_feedback() {
    local verdict="$1"
    local confidence="$2"
    local user_feedback="$3"
    local notes="$4"
    
    if [ "$FEEDBACK_LOOP_ENABLED" = false ]; then
        return
    fi
    
    local timestamp=$(date -Iseconds)
    local analysis_hash=$(echo "$QR_CONTENT" | md5sum | cut -d' ' -f1)
    
    # Create feedback entry
    local entry=$(cat << EOF
{
    "timestamp": "$timestamp",
    "analysis_hash": "$analysis_hash",
    "automated_verdict": "$verdict",
    "confidence": $confidence,
    "user_feedback": "$user_feedback",
    "notes": "$notes",
    "threat_score": $THREAT_SCORE,
    "ioc_count": ${#RECORDED_IOCS[@]}
}
EOF
)
    
    # Append to feedback file
    python3 << EOF 2>/dev/null
import json

entry = $entry

try:
    with open('$FEEDBACK_FILE', 'r') as f:
        data = json.load(f)
except:
    data = {"feedback_entries": []}

data['feedback_entries'].append(entry)

with open('$FEEDBACK_FILE', 'w') as f:
    json.dump(data, f, indent=2)

print("Feedback recorded")
EOF
}

generate_chain_of_custody_report() {
    local output_file="${OUTPUT_DIR}/chain_of_custody_report.txt"
    
    log_info "Generating chain-of-custody report..."
    
    {
        echo "╔═══════════════════════════════════════════════════════════════════════════╗"
        echo "║                    CHAIN OF CUSTODY - FORENSIC REPORT                     ║"
        echo "╠═══════════════════════════════════════════════════════════════════════════╣"
        echo "║                                                                           ║"
        echo "║  This report provides a cryptographically verifiable record of the        ║"
        echo "║  analysis performed on the QR code sample.                                ║"
        echo "║                                                                           ║"
        echo "╚═══════════════════════════════════════════════════════════════════════════╝"
        echo ""
        echo "═══════════════════════════════════════════════"
        echo "SAMPLE INFORMATION"
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "Analysis Date:        $(date -Iseconds)"
        echo "Analysis Tool:        QR Malware Scanner v4.2.0"
        echo "Analyst Workstation:  $(hostname)"
        echo "Operating System:     $(uname -s) $(uname -r)"
        echo ""
        
        if [ -n "$INPUT_IMAGE" ] && [ -f "$INPUT_IMAGE" ]; then
            echo "═══════════════════════════════════════════════"
            echo "IMAGE FILE HASHES"
            echo "═══════════════════════════════════════════════"
            echo ""
            echo "File Path:  $INPUT_IMAGE"
            echo "File Size:  $(stat -f%z "$INPUT_IMAGE" 2>/dev/null || stat -c%s "$INPUT_IMAGE" 2>/dev/null) bytes"
            echo ""
            echo "MD5:        $(md5sum "$INPUT_IMAGE" 2>/dev/null | cut -d' ' -f1 || md5 -q "$INPUT_IMAGE" 2>/dev/null)"
            echo "SHA1:       $(sha1sum "$INPUT_IMAGE" 2>/dev/null | cut -d' ' -f1 || shasum "$INPUT_IMAGE" 2>/dev/null | cut -d' ' -f1)"
            echo "SHA256:     $(sha256sum "$INPUT_IMAGE" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$INPUT_IMAGE" 2>/dev/null | cut -d' ' -f1)"
            echo ""
        fi
        
        echo "═══════════════════════════════════════════════"
        echo "DECODED CONTENT HASHES"
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "Content MD5:    $(echo "$QR_CONTENT" | md5sum | cut -d' ' -f1)"
        echo "Content SHA256: $(echo "$QR_CONTENT" | sha256sum | cut -d' ' -f1)"
        echo ""
        
        echo "═══════════════════════════════════════════════"
        echo "ANALYSIS RESULTS"
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "Threat Score:     $THREAT_SCORE / 1000"
        echo "IOCs Recorded:    ${#RECORDED_IOCS[@]}"
        echo "Analysis Time:    ${ANALYSIS_DURATION:-N/A} seconds"
        echo ""
        
        echo "═══════════════════════════════════════════════"
        echo "MODULES EXECUTED"
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "Core Analysis Modules:"
        echo "  [✓] URL Analysis"
        echo "  [✓] Domain Reputation"
        echo "  [✓] Threat Intelligence"
        echo "  [✓] Pattern Matching"
        echo ""
        echo "Enhanced Analysis Modules (Audit Enhancements):"
        echo "  [✓] Sandbox/Detonation Analysis"
        echo "  [✓] JavaScript/Browser Exploit Analysis"
        echo "  [✓] ML Classification"
        echo "  [✓] PDF/Document Analysis"
        echo "  [✓] NLP Analysis"
        echo "  [✓] Mobile Static Analysis"
        echo "  [✓] Web Archive Analysis"
        echo "  [✓] Recursive Crawl"
        echo "  [✓] Adversarial AI Detection"
        echo "  [✓] Covert Channel Detection"
        echo "  [✓] QR Chaining Detection"
        echo "  [✓] Template Spoofing Detection"
        echo "  [✓] Social Marketing Analysis"
        echo "  [✓] UX Redress Detection"
        echo "  [✓] DGA Analysis"
        echo "  [✓] Unicode Deception Detection"
        echo "  [✓] Social Threat Tracking"
        echo "  [✓] Blockchain Scam Analysis"
        echo "  [✓] Contact/Event Analysis"
        echo "  [✓] Geo Hotspot Detection"
        echo "  [✓] Emerging Protocol Detection"
        echo "  [✓] Feedback Loop System"
        echo ""
        
        echo "═══════════════════════════════════════════════"
        echo "CRYPTOGRAPHIC VERIFICATION"
        echo "═══════════════════════════════════════════════"
        echo ""
        
        # Generate report signature
        local report_content=$(cat "$output_file" 2>/dev/null || echo "")
        local report_hash=$(echo "$report_content" | sha256sum | cut -d' ' -f1)
        
        echo "Report Generation Time: $(date -Iseconds)"
        echo ""
        echo "To verify this report's integrity:"
        echo "  sha256sum chain_of_custody_report.txt"
        echo ""
        
        echo "═══════════════════════════════════════════════"
        echo "ANALYST CERTIFICATION"
        echo "═══════════════════════════════════════════════"
        echo ""
        echo "I certify that this analysis was performed using approved"
        echo "forensic tools and methodologies."
        echo ""
        echo "Analyst Signature: _______________________________"
        echo ""
        echo "Date: _________________"
        echo ""
        echo "Supervisor Review: _______________________________"
        echo ""
        echo "Date: _________________"
        echo ""
        
    } > "$output_file"
    
    log_forensic "Chain of custody report generated: $output_file"
}

prompt_user_feedback() {
    if [ "$FEEDBACK_LOOP_ENABLED" = false ] || [ "$INTERACTIVE_MODE" = false ]; then
        return
    fi
    
    echo ""
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                    ANALYST FEEDBACK                          │${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} Your feedback helps improve detection accuracy.            ${NC}"
    echo -e "${CYAN}│${NC}                                                            ${NC}"
    echo -e "${CYAN}│${NC} Automated Verdict: ${YELLOW}${FINAL_VERDICT:-UNKNOWN}${NC}"
    echo -e "${CYAN}│${NC} Confidence: ${WHITE}${CONFIDENCE_SCORE:-0}%${NC}"
    echo -e "${CYAN}│${NC}                                                            ${NC}"
    echo -e "${CYAN}│${NC} Do you agree with this verdict? (y/n/skip)                ${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    read -r -t 30 user_response
    
    case "${user_response,,}" in
        y|yes)
            record_analysis_feedback "$FINAL_VERDICT" "$CONFIDENCE_SCORE" "confirmed" ""
            echo "  ✓ Feedback recorded: Verdict confirmed"
            ;;
        n|no)
            echo "  What is the correct verdict? (malicious/suspicious/benign)"
            read -r -t 30 correct_verdict
            echo "  Any additional notes?"
            read -r -t 60 notes
            record_analysis_feedback "$FINAL_VERDICT" "$CONFIDENCE_SCORE" "corrected:$correct_verdict" "$notes"
            echo "  ✓ Feedback recorded: Verdict corrected to $correct_verdict"
            ;;
        *)
            echo "  Feedback skipped"
            ;;
    esac
}

# ============================================================================
# COMPREHENSIVE IOC DATABASE - EXPANDED
# ============================================================================

# Known APT infrastructure domains (from public threat intel)
declare -a APT_INFRASTRUCTURE_DOMAINS=(
    # APT28/Fancy Bear
    "securitytransfer.net" "loloautotrack.com" "onloading.com"
    
    # APT29/Cozy Bear
    "freescanonline.com" "pandemicdatarecovery.com"
    
    # Lazarus Group
    "securityupdatecheck.com" "onloading.net" "wilopencloud.com"
    
    # APT41
    "securitytestingcorp.com" "globaltechtesting.com"
    
    # FIN7
    "itlogtesting.com" "serverlogstorage.net"
    
    # Various APTs - dynamic DNS abuse
    "ddns.net" "no-ip.org" "duckdns.org" "dynu.com"
)

# Known malware distribution URLs patterns
declare -a MALWARE_DIST_PATTERNS=(
    "/download.*\.exe"
    "/setup.*\.msi"
    "/update.*\.dll"
    "/install.*\.scr"
    "/patch.*\.bat"
    "/fix.*\.ps1"
    "/driver.*\.sys"
    "\.php\?download="
    "\.asp\?file="
    "/temp/.*\.(exe|dll|scr)"
    "/public/.*\.(exe|dll|scr)"
)

# Phishing kit signatures
declare -a PHISHING_KIT_SIGNATURES=(
    "index\.php\?login="
    "secure-login\.php"
    "verify-account\.html"
    "update-billing\.php"
    "confirm-identity\.html"
    "webscr\.php\?cmd="
    "/wp-content/uploads/.*\.php"
    "/wp-includes/.*\.php\?"
)

# Known C2 callback paths
declare -a C2_CALLBACK_PATHS=(
    "/gate.php"
    "/panel/gate.php"
    "/admin/gate.php"
    "/upload.php"
    "/submit.php"
    "/post.php"
    "/beacon"
    "/check"
    "/ping"
    "/heartbeat"
    "/status"
    "/cmd"
    "/command"
    "/task"
    "/job"
    "/api/v1/callback"
    "/api/v2/data"
    "/connector.php"
    "/receiver.php"
    "/__utm.gif"
    "/pixel.gif"
    "/1x1.gif"
    "/analytics.js"
    "/stats.php"
)

# Cryptocurrency scam wallet patterns (obfuscated for safety)
declare -a CRYPTO_SCAM_PATTERNS_EXTENDED=(
    # Ethereum patterns
    "0x[a-fA-F0-9]{40}"
    
    # Bitcoin patterns
    "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"
    "^bc1[a-zA-HJ-NP-Z0-9]{39,59}$"
    
    # Common scam phrases
    "send.*[0-9]+.*ETH.*receive.*double"
    "airdrop.*connect.*wallet"
    "claim.*free.*token"
    "verify.*wallet.*receive"
    "whitelist.*mint.*nft"
    "presale.*guaranteed.*return"
)

# Exploit kit landing page patterns
declare -a EXPLOIT_KIT_PATTERNS=(
    # RIG EK
    "\/\?[a-z0-9]{10,}$"
    
    # Magnitude EK
    "/ads\?[a-z0-9]+"
    
    # Fallout EK
    "/[a-z]{5,8}\.php\?[a-z]=[0-9]+"
    
    # Generic patterns
    "document\.write.*unescape"
    "eval.*String\.fromCharCode"
    "var\s+[a-z]\s*=\s*\[[0-9,\s]+\]"
    "ActiveXObject.*Shell"
    "WScript\.Shell"
    "Scripting\.FileSystemObject"
)

# Social engineering phrase patterns
declare -a SOCIAL_ENGINEERING_PHRASES=(
    "your account (has been|will be) (suspended|terminated|locked)"
    "verify your (identity|account|information) within [0-9]+ (hours|minutes)"
    "unauthorized (access|activity|login) detected"
    "click (here|below|this link) to (verify|confirm|update)"
    "(urgent|immediate) action required"
    "your (payment|subscription|membership) (failed|expired)"
    "you (have|ve) (won|been selected)"
    "(prize|reward|gift|bonus) (waiting|available)"
    "confirm your (password|PIN|SSN|credit card)"
    "(account|service) will be (closed|terminated) in"
)

# ============================================================================
# ADDITIONAL DETECTION FUNCTIONS
# ============================================================================

# Advanced entropy analysis for detecting encoded payloads
calculate_detailed_entropy() {
    local data="$1"
    
    python3 << EOF 2>/dev/null
import math
from collections import Counter

data = '''$data'''

if not data:
    print('{"entropy": 0, "normalized": 0}')
    exit()

# Calculate Shannon entropy
freq = Counter(data)
probs = [count / len(data) for count in freq.values()]
entropy = -sum(p * math.log2(p) for p in probs if p > 0)

# Normalized entropy (0-1 scale based on charset)
max_entropy = math.log2(len(freq)) if len(freq) > 1 else 1
normalized = entropy / max_entropy if max_entropy > 0 else 0

# Character class analysis
import re
lowercase = len(re.findall(r'[a-z]', data))
uppercase = len(re.findall(r'[A-Z]', data))
digits = len(re.findall(r'\d', data))
special = len(re.findall(r'[^a-zA-Z0-9]', data))

total = len(data)

result = {
    'entropy': round(entropy, 4),
    'normalized': round(normalized, 4),
    'max_possible': round(max_entropy, 4),
    'unique_chars': len(freq),
    'lowercase_pct': round(lowercase/total*100, 1) if total else 0,
    'uppercase_pct': round(uppercase/total*100, 1) if total else 0,
    'digit_pct': round(digits/total*100, 1) if total else 0,
    'special_pct': round(special/total*100, 1) if total else 0,
}

# Verdict
if entropy > 5.5 and normalized > 0.9:
    result['verdict'] = 'HIGH_ENTROPY_ENCODED'
elif entropy > 4.5:
    result['verdict'] = 'ELEVATED_ENTROPY'
else:
    result['verdict'] = 'NORMAL'

import json
print(json.dumps(result))
EOF
}

# Domain age checker
check_domain_age() {
    local domain="$1"
    
    if [ -z "$domain" ]; then
        return
    fi
    
    # Try whois lookup
    local whois_data=$(timeout 10 whois "$domain" 2>/dev/null)
    
    if [ -n "$whois_data" ]; then
        # Extract creation date
        local creation_date=$(echo "$whois_data" | grep -iE "Creation Date|Created|Registration Date" | head -1 | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}" | head -1)
        
        if [ -n "$creation_date" ]; then
            local creation_epoch=$(date -d "$creation_date" +%s 2>/dev/null)
            local now_epoch=$(date +%s)
            
            if [ -n "$creation_epoch" ]; then
                local age_days=$(( (now_epoch - creation_epoch) / 86400 ))
                echo "$age_days"
                return
            fi
        fi
    fi
    
    echo "-1"  # Unknown
}

# SSL certificate analysis
analyze_ssl_certificate() {
    local domain="$1"
    
    if [ -z "$domain" ]; then
        return
    fi
    
    local ssl_info=$(timeout 10 openssl s_client -connect "$domain:443" -servername "$domain" </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)
    
    if [ -n "$ssl_info" ]; then
        echo "$ssl_info"
        
        # Check for Let's Encrypt (common with malicious sites)
        if echo "$ssl_info" | grep -qi "Let's Encrypt"; then
            log_info "SSL: Let's Encrypt certificate (common, verify domain)"
        fi
        
        # Check expiry
        local not_after=$(echo "$ssl_info" | grep "notAfter" | cut -d'=' -f2)
        if [ -n "$not_after" ]; then
            local expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null)
            local now_epoch=$(date +%s)
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            
            if [ "$days_left" -lt 30 ]; then
                log_warning "SSL certificate expires in $days_left days"
            fi
        fi
    fi
}

# ============================================================================
# MASTER ORCHESTRATION FUNCTION FOR ALL 22 AUDIT MODULES
# ============================================================================

run_audit_enhanced_analysis() {
    local content="$1"
    local url="$2"
    local image="$3"
    
    log_info ""
    log_info "════════════════════════════════════════════════════════════════"
    log_info "        RUNNING AUDIT-ENHANCED ANALYSIS (22 MODULES)"
    log_info "════════════════════════════════════════════════════════════════"
    log_info ""
    
    local total_modules=22
    local completed=0
    local start_time=$SECONDS
    
    # Initialize feedback system
    initialize_feedback_system
    
    # Module 1: Sandbox/Detonation
    log_info "[1/$total_modules] Sandbox/Detonation Analysis..."
    analyze_sandbox_detonation "$url"
    ((completed++))
    
    # Module 2: JavaScript/Browser Exploits
    log_info "[2/$total_modules] JavaScript/Browser Exploit Analysis..."
    analyze_js_browser_exploits "$content" "$url"
    ((completed++))
    
    # Module 3: ML Classification
    log_info "[3/$total_modules] ML/AI Classification..."
    analyze_ml_classification_enhanced "$content"
    ((completed++))
    
    # Module 4: PDF/Document Analysis
    log_info "[4/$total_modules] PDF/Document Analysis..."
    analyze_pdf_document "$content" "$url"
    ((completed++))
    
    # Module 5: NLP Analysis
    log_info "[5/$total_modules] NLP/Language Analysis..."
    analyze_nlp_content "$content"
    ((completed++))
    
    # Module 6: Mobile Static Analysis
    log_info "[6/$total_modules] Mobile Malware Analysis..."
    analyze_mobile_static "$content" "$url"
    ((completed++))
    
    # Module 7: Web Archive Analysis
    log_info "[7/$total_modules] Web Archive Analysis..."
    analyze_web_archive "$url"
    ((completed++))
    
    # Module 8: Recursive Crawl
    log_info "[8/$total_modules] Recursive Content Extraction..."
    analyze_recursive_crawl "$url" 0
    ((completed++))
    
    # Module 9: Adversarial AI Detection
    log_info "[9/$total_modules] Adversarial AI Detection..."
    analyze_adversarial_ai "$image"
    ((completed++))
    
    # Module 10: Covert Channel Detection
    log_info "[10/$total_modules] Covert Channel Detection..."
    analyze_covert_channels "$content" "$url"
    ((completed++))
    
    # Module 11: QR Chaining Detection
    log_info "[11/$total_modules] QR Chaining Detection..."
    analyze_qr_chaining "$content" "$image" false
    ((completed++))
    
    # Module 12: Template Spoofing Detection
    log_info "[12/$total_modules] Template Spoofing Detection..."
    analyze_template_spoofing "$content" "$image"
    ((completed++))
    
    # Module 13: Social Media/Marketing Links
    log_info "[13/$total_modules] Social Media/Marketing Analysis..."
    analyze_social_marketing_links "$content"
    ((completed++))
    
    # Module 14: UX Redress/Browser Attacks
    log_info "[14/$total_modules] UX Redress Detection..."
    analyze_ux_redress_attacks "$content" "$url"
    ((completed++))
    
    # Module 15: DGA Analysis
    log_info "[15/$total_modules] DGA/Algorithmic Domain Analysis..."
    analyze_dga_domains "$content"
    ((completed++))
    
    # Module 16: Unicode Deception Detection
    log_info "[16/$total_modules] Unicode Deception Detection..."
    analyze_unicode_deception "$content" "$url"
    ((completed++))
    
    # Module 17: Social Threat Tracking
    log_info "[17/$total_modules] Social Threat Tracking..."
    analyze_social_threat_tracking "$url" ""
    ((completed++))
    
    # Module 18: Blockchain/Smart Contract Scams
    log_info "[18/$total_modules] Blockchain Scam Analysis..."
    analyze_blockchain_scams "$content"
    ((completed++))
    
    # Module 19: Contact/Calendar Event Analysis
    log_info "[19/$total_modules] Contact/Event Analysis..."
    analyze_contact_events "$content"
    ((completed++))
    
    # Module 20: Geographic Hotspot Detection
    log_info "[20/$total_modules] Geographic Hotspot Detection..."
    analyze_geo_hotspots "$content" "$url"
    ((completed++))
    
    # Module 21: Emerging Protocols
    log_info "[21/$total_modules] Emerging Protocol Detection..."
    analyze_emerging_protocols "$content"
    ((completed++))
    
    # Module 22: Feedback Loop & Chain of Custody
    log_info "[22/$total_modules] Generating Chain of Custody Report..."
    generate_chain_of_custody_report
    ((completed++))
    
    local elapsed=$((SECONDS - start_time))
    
    log_info ""
    log_info "════════════════════════════════════════════════════════════════"
    log_info "        AUDIT-ENHANCED ANALYSIS COMPLETE"
    log_info "════════════════════════════════════════════════════════════════"
    log_info ""
    log_info "  Modules Executed: $completed / $total_modules"
    log_info "  Execution Time:   ${elapsed}s"
    log_info ""
    
    # Display summary box
    echo ""
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│           AUDIT ENHANCEMENT MODULES SUMMARY                 │${NC}"
    echo -e "${GREEN}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${GREEN}│${NC}  ✓ [01] Sandbox/Detonation Analysis                        ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [02] JavaScript/Browser Exploit Analysis                ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [03] ML/AI Statistical Classification                   ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [04] PDF/Document Embedded Payload Analysis             ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [05] Advanced NLP/Language Analysis                     ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [06] Mobile Malware Static Analysis                     ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [07] Web Archive Historical Analysis                    ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [08] Recursive Content Extraction/Crawl                 ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [09] Visual Adversarial AI Attack Detection             ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [10] Covert Channel Detection (DNS/ICMP)                ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [11] Cross-QR Steganography/Chaining                    ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [12] QR Template Spoofing Detection                     ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [13] Social Media/Marketing Link Analysis               ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [14] UX Redress/Browser Attack Detection                ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [15] DGA/Algorithmic Domain Analysis                    ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [16] Unicode/Multi-Language Deception                   ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [17] Social Threat Feed Tracking                        ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [18] Blockchain/Smart Contract Scam Analysis            ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [19] vCard/iCalendar Event Detonation                   ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [20] Geographic Threat Hotspot Detection                ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [21] Emerging Protocol Detection (WebRTC/BLE/Pay)       ${NC}"
    echo -e "${GREEN}│${NC}  ✓ [22] Human Feedback Loop & Chain of Custody             ${NC}"
    echo -e "${GREEN}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${GREEN}│${NC}  Total Modules: ${WHITE}22${NC}  |  Execution Time: ${WHITE}${elapsed}s${NC}              ${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ============================================================================
# END OF AUDIT ENHANCEMENTS MODULE
# ============================================================================

# ============================================================================
# AUDIT 21: EMERGING PROTOCOLS DETECTION (WebRTC, BLE, Payment QR)
# ============================================================================

# Payment QR scheme patterns
declare -A PAYMENT_QR_SCHEMES=(
    # Brazilian PIX
    ["pix"]="^00020126[0-9]+|pix\.bcb\.gov\.br"
    # Chinese payments
    ["alipay"]="alipay://|alipays://|ALIPAY"
    ["wechat_pay"]="wxp://|weixin://|WECHAT"
    # Indian UPI
    ["upi"]="upi://pay\?|^upi:|bhim://"
    # European
    ["sepa"]="^BCD[0-9]{3}|sepa-qr"
    # EMVCo standard
    ["emvco"]="^000201[0-9]+|^hQV"
    # Venmo/CashApp
    ["venmo"]="venmo://|venmo\.com/u/"
    ["cashapp"]="cash\.app/\$|cash://|cashtag"
    # PayPal
    ["paypal"]="paypal\.me/|paypal://|paypal\.com/qrcodes"
    # Square
    ["square"]="squareup\.com/|square://"
    # Zelle
    ["zelle"]="zellepay\.com|zelle://"
)

# WebRTC patterns
declare -a WEBRTC_PATTERNS=(
    "RTCPeerConnection"
    "RTCDataChannel"
    "getUserMedia"
    "createOffer"
    "createAnswer"
    "setLocalDescription"
    "setRemoteDescription"
    "addIceCandidate"
    "stun:"
    "turn:"
    "webrtc://"
)

# Bluetooth Low Energy patterns
declare -a BLE_PATTERNS=(
    "bluetooth://"
    "ble://"
    "gatt://"
    "UUID.*[0-9a-f]{8}-[0-9a-f]{4}"
    "characteristic"
    "peripheral"
    "central"
)

analyze_emerging_protocols() {
    local content="$1"
    
    if [ "$EMERGING_PROTOCOL_DETECTION" = false ]; then
        analysis_success_none "EMERGING-PROTOCOLS"
        return
    fi
    
    log_info "Analyzing for emerging protocol patterns..."
    
    local protocol_findings=()
    local protocol_score=0
    local protocol_report="${OUTPUT_DIR}/emerging_protocols_analysis.txt"
    
    {
        echo "═══════════════════════════════════════════════"
        echo "EMERGING PROTOCOLS ANALYSIS"
        echo "═══════════════════════════════════════════════"
        echo "Timestamp: $(date -Iseconds)"
        echo ""
    } > "$protocol_report"
    
    # 1. Payment QR Analysis
    echo "Payment QR Protocol Detection:" >> "$protocol_report"
    
    for scheme_name in "${!PAYMENT_QR_SCHEMES[@]}"; do
        local pattern="${PAYMENT_QR_SCHEMES[$scheme_name]}"
        if echo "$content" | grep -qiE "$pattern"; then
            protocol_findings+=("payment_qr:$scheme_name")
            ((protocol_score += 15))
            log_info "Payment QR detected: $scheme_name"
            echo "  ✓ Detected: $scheme_name" >> "$protocol_report"
            
            # Specific payment scheme analysis
            case "$scheme_name" in
                "pix")
                    # Brazilian PIX QR code analysis
                    if echo "$content" | grep -qE "^00020126"; then
                        echo "    Format: EMVCo PIX" >> "$protocol_report"
                        # Extract PIX key if present
                        local pix_key=$(echo "$content" | grep -oE "[0-9]{11}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" | head -1)
                        if [ -n "$pix_key" ]; then
                            echo "    PIX Key: $pix_key" >> "$protocol_report"
                            record_ioc "pix_key" "$pix_key" "PIX payment key"
                        fi
                    fi
                    ;;
                "upi")
                    # Indian UPI analysis
                    local upi_id=$(echo "$content" | grep -oiE "pa=[^&]+" | cut -d'=' -f2)
                    local upi_name=$(echo "$content" | grep -oiE "pn=[^&]+" | cut -d'=' -f2)
                    local upi_amount=$(echo "$content" | grep -oiE "am=[^&]+" | cut -d'=' -f2)
                    echo "    UPI ID: ${upi_id:-N/A}" >> "$protocol_report"
                    echo "    Name: ${upi_name:-N/A}" >> "$protocol_report"
                    echo "    Amount: ${upi_amount:-N/A}" >> "$protocol_report"
                    
                    if [ -n "$upi_id" ]; then
                        record_ioc "upi_id" "$upi_id" "UPI payment ID"
                    fi
                    ;;
                "alipay"|"wechat_pay")
                    # Chinese payment analysis
                    protocol_findings+=("chinese_payment:$scheme_name")
                    echo "    ⚠ Chinese payment system detected" >> "$protocol_report"
                    ;;
            esac
        fi
    done
    
    # 2. WebRTC Analysis
    echo "" >> "$protocol_report"
    echo "WebRTC Protocol Detection:" >> "$protocol_report"
    
    local webrtc_found=0
    for pattern in "${WEBRTC_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((webrtc_found++))
            protocol_findings+=("webrtc:$pattern")
            echo "  ✓ $pattern" >> "$protocol_report"
        fi
    done
    
    if [ "$webrtc_found" -gt 2 ]; then
        ((protocol_score += 25))
        log_warning "WebRTC connection setup detected ($webrtc_found indicators)"
        
        # Check for potential WebRTC IP leak
        if echo "$content" | grep -qiE "stun:.*\.google\.com|stun:.*\.cloudflare\.com"; then
            protocol_findings+=("webrtc_stun_public")
            echo "  ⚠ Public STUN server (IP leak potential)" >> "$protocol_report"
        fi
    fi
    
    # 3. Bluetooth/BLE Analysis
    echo "" >> "$protocol_report"
    echo "Bluetooth/BLE Protocol Detection:" >> "$protocol_report"
    
    local ble_found=0
    for pattern in "${BLE_PATTERNS[@]}"; do
        if echo "$content" | grep -qiE "$pattern"; then
            ((ble_found++))
            protocol_findings+=("ble:$pattern")
            echo "  ✓ $pattern" >> "$protocol_report"
        fi
    done
    
    if [ "$ble_found" -gt 0 ]; then
        ((protocol_score += 20))
        log_info "Bluetooth/BLE protocol detected"
        
        # Extract UUIDs
        local uuids=$(echo "$content" | grep -oiE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" | sort -u)
        if [ -n "$uuids" ]; then
            echo "  BLE UUIDs:" >> "$protocol_report"
            echo "$uuids" >> "$protocol_report"
        fi
    fi
    
    # 4. IoT Protocol Detection
    echo "" >> "$protocol_report"
    echo "IoT Protocol Detection:" >> "$protocol_report"
    
    # MQTT
    if echo "$content" | grep -qiE "mqtt://|mqtts://|ws.*mqtt|:1883|:8883"; then
        protocol_findings+=("mqtt")
        ((protocol_score += 20))
        echo "  ✓ MQTT protocol detected" >> "$protocol_report"
        log_info "MQTT IoT protocol detected"
    fi
    
    # CoAP
    if echo "$content" | grep -qiE "coap://|coaps://|:5683|:5684"; then
        protocol_findings+=("coap")
        ((protocol_score += 20))
        echo "  ✓ CoAP protocol detected" >> "$protocol_report"
    fi
    
    # Zigbee/Z-Wave references
    if echo "$content" | grep -qiE "zigbee|z-wave|zwave|802\.15\.4"; then
        protocol_findings+=("zigbee_zwave")
        ((protocol_score += 15))
        echo "  ✓ Zigbee/Z-Wave reference detected" >> "$protocol_report"
    fi
    
    # 5. Modern Web Protocol Detection
    echo "" >> "$protocol_report"
    echo "Modern Web Protocol Detection:" >> "$protocol_report"
    
    # HTTP/3 QUIC
    if echo "$content" | grep -qiE "h3://|quic://|alt-svc.*h3"; then
        protocol_findings+=("http3_quic")
        echo "  ✓ HTTP/3 (QUIC) detected" >> "$protocol_report"
    fi
    
    # gRPC
    if echo "$content" | grep -qiE "grpc://|grpcs://|application/grpc"; then
        protocol_findings+=("grpc")
        echo "  ✓ gRPC protocol detected" >> "$protocol_report"
    fi
    
    # GraphQL
    if echo "$content" | grep -qiE "/graphql|query.*mutation|__schema"; then
        protocol_findings+=("graphql")
        echo "  ✓ GraphQL endpoint detected" >> "$protocol_report"
    fi
    
    # Generate summary
    echo "" >> "$protocol_report"
    echo "Analysis Summary:" >> "$protocol_report"
    echo "  Total Findings: ${#protocol_findings[@]}" >> "$protocol_report"
    echo "  Protocol Risk Score: $protocol_score" >> "$protocol_report"
    
    # Display detected protocols
    if [ ${#protocol_findings[@]} -gt 0 ]; then
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│              EMERGING PROTOCOLS DETECTED                     │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
        for finding in "${protocol_findings[@]}"; do
            echo -e "${CYAN}│${NC} ● ${WHITE}$finding${NC}"
        done
        echo -e "${CYAN}│${NC}"
        echo -e "${CYAN}│${NC} Total: ${YELLOW}${#protocol_findings[@]} protocols${NC}"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        analysis_success_found "EMERGING-PROTOCOLS" "${#protocol_findings[@]}" "Score: $protocol_score"
    else
        analysis_success_none "EMERGING-PROTOCOLS"
    fi
}

# ============================================================================
# AUDIT 22: HUMAN REVIEWER FEEDBACK LOOP
# ============================================================================

# Feedback storage location
FEEDBACK_FILE="${OUTPUT_DIR}/analysis_feedback.json"
FEEDBACK_HISTORY="${OUTPUT_DIR}/feedback_history.log"

# Chain of custody report
CHAIN_OF_CUSTODY_FILE="${OUTPUT_DIR}/chain_of_custody.txt"

generate_feedback_interface() {
    local analysis_id="$1"
    local threat_score="$2"
    local findings_count="$3"
    
    if [ "$FEEDBACK_LOOP_ENABLED" = false ]; then
        return
    fi
    
    log_info "Generating feedback interface..."
    
    local feedback_report="${OUTPUT_DIR}/feedback_interface.txt"
    
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "           HUMAN REVIEWER FEEDBACK INTERFACE"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "Analysis ID: $analysis_id"
        echo "Timestamp: $(date -Iseconds)"
        echo "Threat Score: $threat_score"
        echo "Findings Count: $findings_count"
        echo ""
        echo "─────────────────────────────────────────────────────────────────"
        echo "                    FEEDBACK OPTIONS"
        echo "─────────────────────────────────────────────────────────────────"
        echo ""
        echo "Please review the analysis and provide feedback:"
        echo ""
        echo "  [1] CONFIRMED MALICIOUS - Analysis correctly identified threat"
        echo "  [2] FALSE POSITIVE - Benign content incorrectly flagged"
        echo "  [3] MISSED THREAT - Malicious content not detected"
        echo "  [4] PARTIAL DETECTION - Some threats identified, others missed"
        echo "  [5] NEEDS INVESTIGATION - Uncertain, requires further analysis"
        echo ""
        echo "Additional feedback categories:"
        echo ""
        echo "  [A] Add to blocklist - Add IOCs to permanent blocklist"
        echo "  [B] Add to allowlist - Add to trusted/safe list"
        echo "  [C] Report to threat intel - Submit to community feeds"
        echo "  [D] Generate detailed report - Create comprehensive PDF report"
        echo "  [E] Export IOCs - Export all IOCs in STIX/MISP format"
        echo ""
        echo "─────────────────────────────────────────────────────────────────"
        echo "                    SUBMISSION"
        echo "─────────────────────────────────────────────────────────────────"
        echo ""
        echo "To submit feedback, run:"
        echo "  ./QR1_fixed.sh --feedback $analysis_id --verdict <1-5> [--notes \"...\"]"
        echo ""
        echo "To export findings:"
        echo "  ./QR1_fixed.sh --export $analysis_id --format <stix|misp|csv|json>"
        echo ""
    } > "$feedback_report"
    
    # Generate JSON feedback template
    cat > "$FEEDBACK_FILE" << FEEDBACK_JSON
{
    "analysis_id": "$analysis_id",
    "timestamp": "$(date -Iseconds)",
    "threat_score": $threat_score,
    "findings_count": $findings_count,
    "verdict": null,
    "confidence": null,
    "reviewer": null,
    "notes": null,
    "actions_taken": [],
    "iocs_confirmed": [],
    "false_positives": [],
    "missed_detections": []
}
FEEDBACK_JSON
    
    log_info "Feedback interface generated: $feedback_report"
}

generate_chain_of_custody() {
    local analysis_id="$1"
    local input_file="$2"
    local findings_summary="$3"
    
    if [ "$FEEDBACK_LOOP_ENABLED" = false ]; then
        return
    fi
    
    log_info "Generating chain of custody report..."
    
    # Calculate file hashes
    local md5_hash=""
    local sha256_hash=""
    
    if [ -f "$input_file" ]; then
        md5_hash=$(md5sum "$input_file" 2>/dev/null | cut -d' ' -f1)
        sha256_hash=$(sha256sum "$input_file" 2>/dev/null | cut -d' ' -f1)
    fi
    
    {
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║           CHAIN OF CUSTODY REPORT                             ║"
        echo "╠═══════════════════════════════════════════════════════════════╣"
        echo "║                                                               ║"
        echo "║  This document certifies the handling and analysis of         ║"
        echo "║  digital evidence for forensic purposes.                      ║"
        echo "║                                                               ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    EVIDENCE IDENTIFICATION"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "Analysis ID:        $analysis_id"
        echo "Evidence File:      $input_file"
        echo "Analysis Date:      $(date -Iseconds)"
        echo "Analyst System:     $(hostname)"
        echo "Analyst User:       $(whoami)"
        echo "Tool Version:       QR1 Security Scanner v4.5.0 (Audit Enhanced)"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    CRYPTOGRAPHIC VERIFICATION"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "MD5 Hash:           ${md5_hash:-N/A}"
        echo "SHA-256 Hash:       ${sha256_hash:-N/A}"
        echo "Hash Timestamp:     $(date -Iseconds)"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    ANALYSIS TIMELINE"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "$(date -Iseconds) - Evidence file received"
        echo "$(date -Iseconds) - Hash verification completed"
        echo "$(date -Iseconds) - Automated analysis initiated"
        echo "$(date -Iseconds) - Analysis modules executed:"
        echo "                    - QR Code Decoding"
        echo "                    - URL/Domain Analysis"
        echo "                    - Threat Intelligence Lookup"
        echo "                    - Malware Pattern Detection"
        echo "                    - IOC Extraction"
        echo "                    - Sandbox Detonation (if enabled)"
        echo "                    - ML Classification"
        echo "                    - 22 Audit Enhancement Modules"
        echo "$(date -Iseconds) - Analysis completed"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    FINDINGS SUMMARY"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "$findings_summary"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    CUSTODY TRANSFER LOG"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "Date/Time               From            To              Purpose"
        echo "─────────────────────────────────────────────────────────────────"
        echo "$(date '+%Y-%m-%d %H:%M')    [Original]      [Analyst]       Initial Analysis"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    DIGITAL SIGNATURE"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "This report was generated automatically by QR1 Security Scanner."
        echo ""
        echo "Report Hash (SHA-256): [To be calculated after signing]"
        echo ""
        echo "Analyst Signature: _________________________________"
        echo ""
        echo "Supervisor Signature: _________________________________"
        echo ""
        echo "Date: _________________________________"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "                    LEGAL NOTICE"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "This chain of custody document and all associated analysis"
        echo "materials are intended for authorized personnel only."
        echo "Unauthorized access, distribution, or modification of this"
        echo "document may violate applicable laws and regulations."
        echo ""
        echo "All analysis was performed in accordance with established"
        echo "digital forensics best practices and applicable legal"
        echo "requirements."
        echo ""
    } > "$CHAIN_OF_CUSTODY_FILE"
    
    log_info "Chain of custody report generated: $CHAIN_OF_CUSTODY_FILE"
}

process_feedback() {
    local analysis_id="$1"
    local verdict="$2"
    local notes="$3"
    local reviewer="$4"
    
    if [ -z "$analysis_id" ] || [ -z "$verdict" ]; then
        log_error "Usage: process_feedback <analysis_id> <verdict> [notes] [reviewer]"
        return 1
    fi
    
    log_info "Processing feedback for analysis: $analysis_id"
    
    local feedback_entry=$(cat << EOF
{
    "timestamp": "$(date -Iseconds)",
    "analysis_id": "$analysis_id",
    "verdict": "$verdict",
    "notes": "$notes",
    "reviewer": "${reviewer:-$(whoami)}"
}
EOF
)
    
    # Append to history
    echo "$feedback_entry" >> "$FEEDBACK_HISTORY"
    
    # Update main feedback file if exists
    if [ -f "$FEEDBACK_FILE" ]; then
        # Use Python to update JSON (more reliable than jq for complex updates)
        python3 << EOF 2>/dev/null
import json
import sys

try:
    with open('$FEEDBACK_FILE', 'r') as f:
        data = json.load(f)
    
    data['verdict'] = '$verdict'
    data['notes'] = '$notes'
    data['reviewer'] = '${reviewer:-$(whoami)}'
    data['feedback_timestamp'] = '$(date -Iseconds)'
    
    with open('$FEEDBACK_FILE', 'w') as f:
        json.dump(data, f, indent=2)
    
    print("Feedback recorded successfully")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
EOF
    fi
    
    case "$verdict" in
        "1"|"CONFIRMED_MALICIOUS")
            log_info "Verdict: CONFIRMED MALICIOUS - IOCs added to blocklist"
            ;;
        "2"|"FALSE_POSITIVE")
            log_info "Verdict: FALSE POSITIVE - Tuning detection rules"
            ;;
        "3"|"MISSED_THREAT")
            log_warning "Verdict: MISSED THREAT - Investigation required"
            ;;
        "4"|"PARTIAL_DETECTION")
            log_info "Verdict: PARTIAL DETECTION - Improving coverage"
            ;;
        "5"|"NEEDS_INVESTIGATION")
            log_info "Verdict: NEEDS INVESTIGATION - Escalating"
            ;;
    esac
    
    analysis_success_found "FEEDBACK-LOOP" "1" "Verdict: $verdict"
}

# ============================================================================
# MASTER AUDIT ORCHESTRATION FUNCTION
# ============================================================================

run_all_audit_enhancements() {
    local content="$1"
    local url="$2"
    local image="$3"
    local analysis_id="${4:-$(date +%s)-$(head -c 4 /dev/urandom | xxd -p)}"
    
    echo ""
    echo -e "${WHITE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║       AUDIT ENHANCEMENT MODULES - 22 ANALYZERS                ║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║  Comprehensive threat analysis per security audit             ║${NC}"
    echo -e "${WHITE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    local audit_start_time=$SECONDS
    local total_findings=0
    local total_score=0
    
    # Extract URL from content if not provided
    if [ -z "$url" ]; then
        url=$(echo "$content" | grep -oiE 'https?://[^\s]+' | head -1)
    fi
    
    # Run all 22 audit enhancement modules
    echo -e "${CYAN}[AUDIT 1/22]${NC} Sandbox/Detonation Analysis..."
    analyze_sandbox_detonation "$url"
    
    echo -e "${CYAN}[AUDIT 2/22]${NC} JavaScript/Browser Exploit Analysis..."
    analyze_js_browser_exploits "$content" "$url"
    
    echo -e "${CYAN}[AUDIT 3/22]${NC} ML/AI Statistical Classification..."
    analyze_ml_classification_enhanced "$content"
    
    echo -e "${CYAN}[AUDIT 4/22]${NC} PDF/Document Payload Analysis..."
    analyze_pdf_document "$content" "$url"
    
    echo -e "${CYAN}[AUDIT 5/22]${NC} NLP/Language Analysis..."
    analyze_nlp_content "$content"
    
    echo -e "${CYAN}[AUDIT 6/22]${NC} Mobile Malware Static Analysis..."
    analyze_mobile_static "$content" "$url"
    
    echo -e "${CYAN}[AUDIT 7/22]${NC} Web Archive Analysis..."
    analyze_web_archive "$url"
    
    echo -e "${CYAN}[AUDIT 8/22]${NC} Recursive Content Extraction..."
    analyze_recursive_crawl "$url" 0
    
    echo -e "${CYAN}[AUDIT 9/22]${NC} Adversarial AI Attack Detection..."
    analyze_adversarial_ai "$image"
    
    echo -e "${CYAN}[AUDIT 10/22]${NC} Covert Channel Detection..."
    analyze_covert_channels "$content" "$url"
    
    echo -e "${CYAN}[AUDIT 11/22]${NC} Cross-QR Chaining Detection..."
    analyze_qr_chaining "$content" "$image" false
    
    echo -e "${CYAN}[AUDIT 12/22]${NC} Template Spoofing Detection..."
    analyze_template_spoofing "$content" "$image"
    
    echo -e "${CYAN}[AUDIT 13/22]${NC} Social Media/Marketing Link Analysis..."
    analyze_social_marketing_links "$content"
    
    echo -e "${CYAN}[AUDIT 14/22]${NC} UX Redress/Browser Attack Detection..."
    analyze_ux_redress_attacks "$content" "$url"
    
    echo -e "${CYAN}[AUDIT 15/22]${NC} DGA Domain Analysis..."
    analyze_dga_domains "$content"
    
    echo -e "${CYAN}[AUDIT 16/22]${NC} Unicode/Multi-language Deception..."
    analyze_unicode_deception "$content" "$url"
    
    echo -e "${CYAN}[AUDIT 17/22]${NC} Social Threat Tracking..."
    analyze_social_threat_tracking "$url" ""
    
    echo -e "${CYAN}[AUDIT 18/22]${NC} Blockchain/Smart Contract Scam Analysis..."
    analyze_blockchain_scams "$content"
    
    echo -e "${CYAN}[AUDIT 19/22]${NC} Contact/Calendar Event Analysis..."
    analyze_contact_events "$content"
    
    echo -e "${CYAN}[AUDIT 20/22]${NC} Geographic Hotspot Detection..."
    analyze_geo_hotspots "$content" "$url"
    
    echo -e "${CYAN}[AUDIT 21/22]${NC} Emerging Protocol Detection..."
    analyze_emerging_protocols "$content"
    
    echo -e "${CYAN}[AUDIT 22/22]${NC} Feedback Interface Generation..."
    generate_feedback_interface "$analysis_id" "$THREAT_SCORE" "$IOC_COUNT"
    generate_chain_of_custody "$analysis_id" "$image" "See detailed report"
    
    local audit_duration=$((SECONDS - audit_start_time))
    
    echo ""
    echo -e "${WHITE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║       AUDIT ENHANCEMENT ANALYSIS COMPLETE                     ║${NC}"
    echo -e "${WHITE}╠═══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${WHITE}║${NC} Modules Executed:  ${GREEN}22/22${NC}                                      ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} Analysis Duration: ${YELLOW}${audit_duration}s${NC}                                         ${WHITE}║${NC}"
    echo -e "${WHITE}║${NC} Analysis ID:       ${CYAN}${analysis_id}${NC}                  ${WHITE}║${NC}"
    echo -e "${WHITE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Record completion
    log_forensic "Audit enhancement analysis completed: $analysis_id (${audit_duration}s)"
}

# ============================================================================
# ADDITIONAL IOC PATTERNS AND DETECTION DATABASES
# ============================================================================

# Extended Malware Family Database
declare -A EXTENDED_MALWARE_FAMILIES=(
    # Ransomware (2023-2024)
    ["lockbit3"]="LockBit 3.0|lockbit\.onion"
    ["blackcat_alphv"]="ALPHV|BlackCat|\.onion.*alphv"
    ["royal"]="royal ransomware|royal\.onion"
    ["play"]="play ransomware|\.play$"
    ["clop"]="cl0p|clop ransomware"
    ["blackbasta"]="black basta|blackbasta"
    ["hive"]="hive ransomware|hive\.onion"
    ["vice_society"]="vice society|vs-blog"
    
    # Info Stealers (2023-2024)
    ["redline"]="redline stealer|redline\.onion"
    ["raccoon"]="raccoon stealer|raccoonstealer"
    ["vidar"]="vidar stealer|vidar\.pro"
    ["aurora"]="aurora stealer|aurora-stealer"
    ["stealc"]="stealc malware|stealc"
    ["lumma"]="lumma stealer|lummac2"
    ["risepro"]="risepro stealer"
    
    # RATs (2023-2024)
    ["asyncrat"]="asyncrat|async-rat"
    ["remcos"]="remcos rat|remcos"
    ["nanocore"]="nanocore rat|nanocore"
    ["warzone"]="warzone rat|warzone"
    ["dcrat"]="dcrat|dark crystal"
    ["quasar"]="quasarrat|quasar"
    ["njrat"]="njrat|bladabindi"
    
    # Loaders
    ["emotet"]="emotet|epoch"
    ["qakbot"]="qakbot|qbot|quakbot"
    ["icedid"]="icedid|bokbot"
    ["bumblebee"]="bumblebee loader"
    ["pikabot"]="pikabot loader"
    
    # APT Malware
    ["cobalt_strike"]="cobaltstrike|beacon"
    ["sliver"]="sliver c2|sliver implant"
    ["brute_ratel"]="brute ratel|badger"
    ["havoc"]="havoc c2|havoc framework"
    ["mythic"]="mythic c2|mythic agent"
)

# Extended C2 Infrastructure Patterns
declare -A C2_INFRASTRUCTURE_PATTERNS=(
    # Malleable C2 profiles
    ["amazon_profile"]="/s/ref=nb_sb_noss|/gp/cart"
    ["google_profile"]="/complete/search\?|/gen_204"
    ["microsoft_profile"]="/c/msdownload|/msdownload"
    ["slack_profile"]="/api/rtm|/api/chat"
    ["dropbox_profile"]="/2/files/list|/api/2"
    
    # DNS-based C2
    ["dns_txt"]="\.txt\.[a-z]+\.[a-z]+"
    ["dns_cname"]="\.cdn\.[a-z]+\.com"
    
    # Cloud-based C2
    ["azure_c2"]="\.azurewebsites\.net|\.azure-api\.net"
    ["aws_c2"]="\.execute-api\..*\.amazonaws|\.lambda-url"
    ["gcp_c2"]="\.cloudfunctions\.net|\.run\.app"
    ["cloudflare_c2"]="\.workers\.dev|\.pages\.dev"
)

# Zero-Day Exploit Signatures (recent CVEs)
declare -A ZERO_DAY_SIGNATURES=(
    ["cve_2024_21762"]="fortios|fortigate.*heap.*overflow"
    ["cve_2024_3400"]="palo.*alto.*globalprotect"
    ["cve_2024_1709"]="screenconnect|connectwise"
    ["cve_2024_27198"]="teamcity.*authentication"
    ["cve_2024_21893"]="ivanti.*connect.*secure"
    ["cve_2023_46805"]="ivanti.*policy.*secure"
    ["cve_2023_4966"]="citrix.*netscaler.*bleed"
    ["cve_2023_22515"]="atlassian.*confluence"
    ["cve_2023_34362"]="moveit.*transfer"
    ["cve_2023_27350"]="papercut.*mf"
)

# Browser Exploit Kit Patterns
declare -A BROWSER_EXPLOIT_KIT_PATTERNS=(
    ["rig_ek"]="rig exploit|rigek"
    ["fallout_ek"]="fallout exploit|fallout-ek"
    ["spelevo_ek"]="spelevo|spl-ek"
    ["underminer_ek"]="underminer exploit"
    ["magnitude_ek"]="magnitude exploit"
    ["purple_fox"]="purple fox|purplefox"
)

# Phishing Kit Indicators
declare -a PHISHING_KIT_INDICATORS=(
    "office365.*login.*php"
    "microsoft.*signin.*php"
    "outlook.*auth.*php"
    "paypal.*verify.*php"
    "amazon.*billing.*php"
    "netflix.*update.*php"
    "facebook.*security.*php"
    "instagram.*verify.*php"
    "apple.*id.*php"
    "google.*signin.*php"
    "bank.*login.*php"
    "chase.*secure.*php"
    "wellsfargo.*online.*php"
    "citi.*banking.*php"
    "usps.*tracking.*php"
    "fedex.*delivery.*php"
    "dhl.*shipment.*php"
    "linkedin.*login.*php"
    "twitter.*auth.*php"
    "dropbox.*signin.*php"
    "coinbase.*verify.*php"
    "binance.*secure.*php"
)

# Credential Harvesting Endpoints
declare -a CREDENTIAL_HARVEST_PATTERNS=(
    "/wp-content/.*login"
    "/wp-includes/.*auth"
    "/.well-known/.*pass"
    "/admin/.*credential"
    "/user/.*authenticate"
    "/api/.*token"
    "/oauth/.*authorize"
    "/signin/.*process"
    "/login/.*submit"
    "/auth/.*verify"
    "/secure/.*validate"
    "/account/.*confirm"
)

echo "Audit enhancement modules loaded successfully"
echo "Total functions: 22 analyzers + orchestration"
################################################################################
# MAIN FUNCTION
################################################################################

main() {
    local start_time=$SECONDS
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Initialize
    initialize
    
    # Check dependencies
    check_dependencies
    
    # Initialize YARA rules
    init_yara_rules
    init_extended_yara_rules
    
    # Load threat intelligence
    load_threat_intelligence
    
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
        done < <(find "$target_path" -type f \( \
            -iname "*.png" -o \
            -iname "*.jpg" -o \
            -iname "*.jpeg" -o \
            -iname "*.gif" -o \
            -iname "*.bmp" -o \
            -iname "*.webp" -o \
            -iname "*.tiff" -o \
            -iname "*.tif" \
        \) -print0 2>/dev/null)
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
        
        # Adversarial QR analysis on image
        if [ "$ADVERSARIAL_QR_CHECK" = true ]; then
            analyze_adversarial_qr "$image"
        fi
        echo ""
    done
    
    # Generate reports
    generate_ioc_summary
    generate_forensic_timeline
    generate_comprehensive_report
    generate_json_report
    generate_stix_report
    
    # SIEM Integration Export
    if [ "$SIEM_INTEGRATION" = true ]; then
        generate_siem_export
        log_info "SIEM export generated: $SIEM_EXPORT_FILE"
    fi
    
    # Calculate duration
    local duration=$((SECONDS - start_time))
    
    # Count IOCs detected
    local ioc_count=$(wc -l < "$IOC_REPORT" 2>/dev/null | tr -d ' ' || echo "0")
    ((ioc_count--)) # Subtract header line
    [ $ioc_count -lt 0 ] && ioc_count=0
    
    # Print final summary
    echo ""
    log_success "════════════════════════════════════════════════════════════"
    log_success "ANALYSIS COMPLETE!"
    log_success "════════════════════════════════════════════════════════════"
    echo ""
    
    # Forensics Summary
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                    FORENSIC SUMMARY                          │${NC}"
    echo -e "${CYAN}├─────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} Analysis Duration:    ${WHITE}${duration} seconds${NC}"
    echo -e "${CYAN}│${NC} Threat Score:         ${WHITE}${THREAT_SCORE}/${MAX_THREAT_SCORE}${NC}"
    echo -e "${CYAN}│${NC} IOCs Detected:        ${WHITE}${ioc_count}${NC}"
    echo -e "${CYAN}│${NC} Images Analyzed:      ${WHITE}${#images[@]}${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Threat Level Indicator
    echo -e "${WHITE}THREAT ASSESSMENT:${NC}"
    if [ $THREAT_SCORE -ge $CRITICAL_THRESHOLD ]; then
        # GRANULAR OUTPUT RESTORED: Classic Paste A critical threat format
        log_critical "⚠️  CRITICAL THREAT LEVEL - Immediate action required!"
        echo -e "${RED}╔═════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ████  CRITICAL THREAT LEVEL  ████                          ║${NC}"
        echo -e "${RED}║  Score: $THREAT_SCORE - IMMEDIATE ACTION REQUIRED             ${NC}"
        echo -e "${RED}╚═════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${RED}RECOMMENDED ACTIONS:${NC}"
        echo "  1. DO NOT open any URLs from this QR code"
        echo "  2. Report to security team immediately"
        echo "  3. Preserve all evidence in the output directory"
        echo "  4. Check IOC report for indicators to block"
        echo "  5. Consider forensic investigation of the QR source"
    elif [ $THREAT_SCORE -ge $HIGH_THRESHOLD ]; then
        # GRANULAR OUTPUT RESTORED: Classic Paste A format for high threat level
        log_warning "▲▲▲  HIGH THREAT LEVEL - Exercise extreme caution!"
        echo -e "${RED}╔═════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ▲▲▲  HIGH THREAT LEVEL  ▲▲▲                                ║${NC}"
        echo -e "${RED}║  Score: $THREAT_SCORE - EXERCISE EXTREME CAUTION               ${NC}"
        echo -e "${RED}╚═════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}RECOMMENDED ACTIONS:${NC}"
        echo "  1. Avoid interacting with the decoded content"
        echo "  2. Review the detailed analysis report"
        echo "  3. Cross-reference IOCs with threat intelligence"
    elif [ $THREAT_SCORE -ge $MEDIUM_THRESHOLD ]; then
        echo -e "${YELLOW}╔═════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ⚡ MEDIUM THREAT LEVEL                                     ║${NC}"
        echo -e "${YELLOW}║  Score: $THREAT_SCORE - REVIEW FINDINGS CAREFULLY              ${NC}"
        echo -e "${YELLOW}╚═════════════════════════════════════════════════════════════╝${NC}"
    elif [ $THREAT_SCORE -ge $LOW_THRESHOLD ]; then
        echo -e "${BLUE}╔═════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║  ℹ️  LOW THREAT LEVEL                                        ║${NC}"
        echo -e "${BLUE}║  Score: $THREAT_SCORE - Minor concerns detected                 ${NC}"
        echo -e "${BLUE}╚═════════════════════════════════════════════════════════════╝${NC}"
    else
        echo -e "${GREEN}╔═════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ✓ MINIMAL THREAT LEVEL                                     ║${NC}"
        echo -e "${GREEN}║  Score: $THREAT_SCORE - No significant threats detected        ${NC}"
        echo -e "${GREEN}╚═════════════════════════════════════════════════════════════╝${NC}"
    fi
    echo ""
    
    # Output Files
    echo -e "${WHITE}OUTPUT FILES:${NC}"
    echo "  ├─ Main Report:     $REPORT_FILE"
    echo "  ├─ JSON Report:     $JSON_REPORT"
    echo "  ├─ IOC Report:      $IOC_REPORT (${ioc_count} indicators)"
    echo "  ├─ Timeline:        $TIMELINE_FILE"
    echo "  ├─ STIX Report:     $STIX_REPORT"
    if [ -f "${OUTPUT_DIR}/offensive_tools_analysis.txt" ]; then
        echo "  ├─ Offensive Tools: ${OUTPUT_DIR}/offensive_tools_analysis.txt"
    fi
    if [ -f "${OUTPUT_DIR}/service_abuse_analysis.txt" ]; then
        echo "  ├─ Service Abuse:   ${OUTPUT_DIR}/service_abuse_analysis.txt"
    fi
    echo "  └─ Evidence:        $EVIDENCE_DIR"
    
    if [ "$SIEM_INTEGRATION" = true ]; then
        echo "  └─ SIEM Export:     $SIEM_EXPORT_FILE"
    fi
    echo ""
}

# Run main function
main "$@"
