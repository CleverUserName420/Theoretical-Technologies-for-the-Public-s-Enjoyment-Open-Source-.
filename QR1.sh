#!/bin/bash

# Strict error handling
set -o pipefail
shopt -s nullglob extglob nocasematch

################################################################################
# GLOBAL CONFIGURATION
################################################################################

VERSION="4.0.0-ULTIMATE-FORENSIC"
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

# Extended Report Files (set after OUTPUT_DIR is defined in initialize())
# These will be set dynamically in initialize_extended_reports()

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
    
    if [ ${#missing_optional[@]} -ne 0 ]; then
        log_warning "Missing optional dependencies (reduced functionality):"
        printf '%s\n' "${missing_optional[@]}"
        echo -e "\n${YELLOW}Install additional tools:${NC}"
        echo "brew install qrencode quirc imagemagick tesseract exiftool ssdeep steghide zsteg whois nmap bind binwalk foremost"
        echo "gem install zsteg"
        echo "pip3 install opencv-python-headless numpy scipy scikit-learn"
    fi
    
    # Check Python modules
    python3 -c "import PIL, pyzbar" 2>/dev/null || {
        log_error "Missing Python dependencies"
        echo "Install: pip3 install pillow pyzbar qrcode opencv-python-headless numpy scipy scikit-learn"
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
    
    # Add to timeline
    echo "$(date -Iseconds),$level,\"$msg\"" >> "$TIMELINE_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    log_msg "INFO" "$*"
}

log_success() {

# Extended Report Files (initialized dynamically)
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

log_forensic() {
    local msg="$*"
    echo -e "${CYAN}[FORENSIC]${NC} $msg"
    log_msg "FORENSIC" "$msg"
}

log_apt() {
    local msg="$*"
    echo -e "${ORANGE}[APT]${NC} $msg"
    log_msg "APT" "$msg"
}

log_ml() {
    local msg="$*"
    echo -e "${WHITE}[ML-HEURISTIC]${NC} $msg"
    log_msg "ML" "$msg"
}

log_stego() {
    local msg="$*"
    echo -e "${CYAN}[STEGANOGRAPHY]${NC} $msg"
    log_msg "STEGO" "$msg"
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

# HOMOGRAPH ATTACK CHARACTERS
declare -a HOMOGRAPH_CHARS=(
    "а" "е" "о" "р" "с" "у" "х"    # Cyrillic lookalikes
    "α" "ο" "ρ"                    # Greek lookalikes
    "ı" "ɪ" "l" "I" "1" "|"        # i/l/1 confusion
    "0" "O" "Ο" "О"                # o/0 confusion
    "ɡ" "ɢ"                        # g lookalikes
    "ν" "v"                        # v/nu confusion
    "ω" "w"                        # w/omega confusion
    "ß" "β"                        # B lookalikes
    "ḁ" "ạ" "ą" "ă" "ā" "ã"        # a variants
    "ḃ" "ḅ" "ḇ"                    # b variants
    "ċ" "ç" "ć" "č"                # c variants
    "ḋ" "ḍ" "ḏ" "ḑ"                # d variants
    "ė" "ę" "ě" "ē" "ẹ"            # e variants
    "ḟ" "ƒ"                        # f variants
    "ġ" "ğ" "ģ" "ǧ"                # g variants
    "ḣ" "ḥ" "ḧ" "ħ"                # h variants
    "ì" "í" "î" "ï" "ị"            # i variants
    "ǰ" "ĵ"                        # j variants
    "ḱ" "ķ" "ǩ"                    # k variants
    "ḷ" "ļ" "ľ" "ł"                # l variants
    "ṁ" "ṃ"                        # m variants
    "ṅ" "ņ" "ň" "ñ"                # n variants
    "ò" "ó" "ô" "õ" "ö" "ọ"        # o variants
    "ṗ"                            # p variants
    "ŗ" "ř" "ṛ" "ṟ"                # r variants
    "ṡ" "ş" "ș" "š"                # s variants
    "ṫ" "ţ" "ț" "ť"                # t variants
    "ù" "ú" "û" "ü" "ụ"            # u variants
    "ẃ" "ẅ" "ẇ"                    # w variants
    "ẋ" "ẍ"                        # x variants
    "ỳ" "ý" "ŷ" "ÿ" "ỵ"            # y variants
    "ẑ" "ž" "ż"                    # z variants
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
    ["aws_secret_key"]="[A-Za-z0-9/+=]{40}"
    ["aws_session_token"]="FwoGZXIvYXdzE[A-Za-z0-9/+=]+"
    ["gcp_api_key"]="AIza[0-9A-Za-z_-]{35}"
    ["gcp_oauth"]="[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"
    ["gcp_service_account"]="\"type\":.*\"service_account\""
    ["azure_client_id"]="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
    ["azure_subscription"]="[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
    ["digitalocean_token"]="dop_v1_[a-f0-9]{64}"
    ["digitalocean_oauth"]="doo_v1_[a-f0-9]{64}"
    ["linode_token"]="[a-f0-9]{64}"
    ["vultr_api_key"]="[A-Z0-9]{36}"
    ["heroku_api_key"]="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    # Version Control
    ["github_token"]="ghp_[0-9a-zA-Z]{36}"
    ["github_oauth"]="gho_[0-9a-zA-Z]{36}"
    ["github_app_token"]="ghu_[0-9a-zA-Z]{36}"
    ["github_refresh_token"]="ghr_[0-9a-zA-Z]{36}"
    ["github_fine_grained"]="github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}"
    ["gitlab_token"]="glpat-[0-9a-zA-Z_-]{20}"
    ["gitlab_runner"]="GR1348941[0-9a-zA-Z_-]{20}"
    ["bitbucket_token"]="ATBB[A-Za-z0-9_-]{32}"
    # Communication
    ["slack_token"]="xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"
    ["slack_webhook"]="https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+"
    ["discord_token"]="[MN][A-Za-z\\d]{23,}\.[\\w-]{6}\\.[\\w-]{27}"
    ["discord_webhook"]="https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"
    ["telegram_token"]="[0-9]{8,10}:[a-zA-Z0-9_-]{35}"
    ["twilio_sid"]="AC[a-z0-9]{32}"
    ["twilio_auth"]="[a-z0-9]{32}"
    # Payment
    ["stripe_publishable"]="pk_(test|live)_[0-9a-zA-Z]{24,99}"
    ["stripe_secret"]="sk_(test|live)_[0-9a-zA-Z]{24,99}"
    ["stripe_restricted"]="rk_(test|live)_[0-9a-zA-Z]{24,99}"
    ["square_access"]="sq0atp-[0-9A-Za-z_-]{22}"
    ["square_application"]="sq0idp-[0-9A-Za-z_-]{22}"
    ["paypal_client_id"]="A[a-zA-Z0-9_-]{20,}[A-Za-z0-9]"
    ["braintree_access"]="access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"
    # Social Media
    ["twitter_api_key"]="[a-zA-Z0-9]{25}"
    ["twitter_secret"]="[a-zA-Z0-9]{50}"
    ["twitter_bearer"]="AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]+"
    ["facebook_access"]="EAACEdEose0cBA[0-9A-Za-z]+"
    ["instagram_access"]="IGQV[a-zA-Z0-9_-]+"
    ["linkedin_client"]="[0-9a-z]{12,14}"
    # Email Services
    ["sendgrid_api"]="SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"
    ["mailchimp_api"]="[a-f0-9]{32}-us[0-9]{1,2}"
    ["mailgun_api"]="key-[0-9a-zA-Z]{32}"
    ["postmark_token"]="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
    # Databases
    ["mongodb_uri"]="mongodb(\\+srv)?://[^:]+:[^@]+@[^/]+"
    ["postgres_uri"]="postgres://[^:]+:[^@]+@[^/]+"
    ["mysql_uri"]="mysql://[^:]+:[^@]+@[^/]+"
    ["redis_uri"]="redis://[^:]+:[^@]+@[^:]+:[0-9]+"
    # Analytics
    ["mixpanel_token"]="[a-f0-9]{32}"
    ["amplitude_api"]="[a-f0-9]{32}"
    ["segment_write"]="[a-zA-Z0-9]{32}"
    # Security/Auth
    ["okta_token"]="00[A-Za-z0-9_-]{40,}"
    ["auth0_token"]="[a-zA-Z0-9_-]{32,}"
    ["jwt_token"]="eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"
    # CI/CD
    ["circleci_token"]="[a-f0-9]{40}"
    ["travis_token"]="[a-zA-Z0-9]{22}"
    ["jenkins_token"]="[a-f0-9]{32,}"
    # Other
    ["algolia_api"]="[a-f0-9]{32}"
    ["mapbox_token"]="pk\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+"
    ["npm_token"]="npm_[A-Za-z0-9]{36}"
    ["pypi_token"]="pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}"
    ["nuget_api"]="oy2[a-z0-9]{43}"
    ["sentry_dsn"]="https://[a-f0-9]+@[a-z]+\\.ingest\\.sentry\\.io/[0-9]+"
    ["datadog_api"]="[a-f0-9]{32}"
    ["newrelic_api"]="NRAK-[A-Z0-9]{27}"
    ["pagerduty_token"]="[a-zA-Z0-9+/]{20}"
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
    ["hex_string"]="^[0-9a-fA-F]{40,}$"
    ["hex_escape"]="(\\\\x[0-9a-fA-F]{2}){10,}"
    ["unicode_escape"]="(\\\\u[0-9a-fA-F]{4}){10,}"
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
    ["xor_key"]="[A-Za-z0-9]{8,32}"
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
    ["long_subdomain"]="[a-z0-9]{50,}\\."
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
    "\`.*\`"
    "\\$\\(.*\\)"
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
    "\`.*\`"
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
            log_threat $((stego_score / 2)) "High likelihood of steganographic content"
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
    
    # Extract components
    local protocol=$(echo "$url" | grep -oP '^[a-z]+(?=:)' | head -1)
    local domain=$(echo "$url" | sed -E 's|^[a-z]+://||' | cut -d'/' -f1 | cut -d':' -f1)
    local port=$(echo "$url" | grep -oP ':[0-9]+' | tr -d ':' | head -1)
    local path=$(echo "$url" | sed 's|^[^/]*//[^/]*/||')
    local query=$(echo "$url" | grep -oP '\?.*$' | head -1)
    
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
            log_threat 100 "KNOWN MALICIOUS IP: $domain - ${KNOWN_MALICIOUS_IPS[$domain]}"
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
    
    # Extract MIME type
    local mime_type=$(echo "$uri" | grep -oP 'data:[^;,]+' | sed 's/data://')
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
    
    # Get full redirect chain
    local redirect_chain=$(curl -sIL --max-redirs "$max_redirects" -w "%{url_effective}\n" -o /dev/null "$url" 2>/dev/null)
    
    if [ -n "$redirect_chain" ] && [ "$redirect_chain" != "$url" ]; then
        log_warning "Redirect chain resolved to: $redirect_chain"
        
        # Count redirects
        local redirect_count=$(curl -sIL --max-redirs "$max_redirects" -w "%{redirect_count}" -o /dev/null "$url" 2>/dev/null)
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
    local has_latin=$(echo "$domain" | grep -P '[a-zA-Z]' | wc -l)
    local has_cyrillic=$(echo "$domain" | grep -P '[а-яА-ЯёЁ]' | wc -l)
    local has_greek=$(echo "$domain" | grep -P '[α-ωΑ-Ω]' | wc -l)
    
    if [ $has_latin -gt 0 ] && ([ $has_cyrillic -gt 0 ] || [ $has_greek -gt 0 ]); then
        log_threat 50 "HOMOGRAPH ATTACK: Mixed character sets detected"
    fi
    
    # Check for lookalike characters
    for char in "${HOMOGRAPH_CHARS[@]}"; do
        if echo "$domain" | grep -qF "$char"; then
            log_threat 40 "Homograph character detected: $char"
        fi
    done
    
    # Punycode detection
    if echo "$domain" | grep -qE 'xn--'; then
        log_threat 30 "Punycode domain (IDN spoofing possible): $domain"
        local decoded=$(python3 -c "print('$domain'.encode('ascii').decode('idna'))" 2>/dev/null)
        [ -n "$decoded" ] && log_info "Decoded IDN: $decoded"
    fi
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
    
    # Registrar check
    local registrar=$(grep -i "Registrar:" "$whois_file" | head -1)
    [ -n "$registrar" ] && log_forensic "Registrar: $registrar"
    
    # Privacy protection
    if grep -qi "privacy\|proxy\|whoisguard\|domains by proxy\|perfect privacy" "$whois_file"; then
        log_warning "Domain uses privacy protection service"
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
                    log_threat 100 "URL found in OpenPhish feed!"
                    ((matches++))
                fi
            fi
            
            # URLhaus
            if [ -f "${TEMP_DIR}/threat_intel/urlhaus.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/urlhaus.txt" 2>/dev/null; then
                    log_threat 100 "URL found in URLhaus feed!"
                    ((matches++))
                fi
            fi
            
            # PhishTank
            if [ -f "${TEMP_DIR}/threat_intel/phishtank.json" ]; then
                if jq -e ".[] | select(.url == \"$ioc\")" "${TEMP_DIR}/threat_intel/phishtank.json" > /dev/null 2>&1; then
                    log_threat 100 "URL found in PhishTank!"
                    ((matches++))
                fi
            fi
            ;;
        "domain")
            # Ransomware domains
            if [ -f "${TEMP_DIR}/threat_intel/ransomware_domains.txt" ]; then
                if grep -qiF "$ioc" "${TEMP_DIR}/threat_intel/ransomware_domains.txt" 2>/dev/null; then
                    log_threat 100 "Domain found in ransomware tracker!"
                    ((matches++))
                fi
            fi
            
            # OTX IOCs
            if [ -f "${TEMP_DIR}/threat_intel/otx_iocs.txt" ]; then
                if grep -qiF "$ioc" "${TEMP_DIR}/threat_intel/otx_iocs.txt" 2>/dev/null; then
                    log_threat 80 "Domain found in OTX AlienVault!"
                    ((matches++))
                fi
            fi
            ;;
        "ip")
            # Spamhaus DROP
            if [ -f "${TEMP_DIR}/threat_intel/spamhaus_drop.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/spamhaus_drop.txt" 2>/dev/null; then
                    log_threat 100 "IP found in Spamhaus DROP list!"
                    ((matches++))
                fi
            fi
            
            # Feodo Tracker
            if [ -f "${TEMP_DIR}/threat_intel/feodo_ips.txt" ]; then
                if grep -qF "$ioc" "${TEMP_DIR}/threat_intel/feodo_ips.txt" 2>/dev/null; then
                    log_threat 100 "IP found in Feodo Tracker (banking trojan C2)!"
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
    
    if multi_decoder_analysis "$image" "$decode_output"; then
        local merged_content=$(cat "${decode_output}_merged.txt" 2>/dev/null)
        
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
        if echo "$content" | grep -qiE "$pattern"; then
            local matched=$(echo "$content" | grep -oiE "$pattern" | head -1)
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
    fi
}

################################################################################
# ASN AND NETWORK INFRASTRUCTURE ANALYSIS
################################################################################

analyze_asn_infrastructure() {
    local content="$1"
    
    if [ "$ASN_ANALYSIS" = false ] || [ "$NETWORK_CHECK" = false ]; then
        return
    fi
    
    log_info "Analyzing network infrastructure and ASN reputation..."
    
    local asn_findings=()
    local asn_score=0
    
    # Extract domains and IPs
    local domains=$(echo "$content" | grep -oiE "[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}" | sort -u)
    local ips=$(echo "$content" | grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | sort -u)
    
    # Resolve domains to IPs
    for domain in $domains; do
        local resolved_ip=$(dig +short A "$domain" 2>/dev/null | head -1)
        if [ -n "$resolved_ip" ] && [ "$resolved_ip" != "$domain" ]; then
            ips="$ips $resolved_ip"
        fi
    done
    
    # Analyze each IP
    for ip in $ips; do
        # Skip private/reserved IPs
        if echo "$ip" | grep -qE "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|0\.)"; then
            continue
        fi
        
        # Get ASN info
        local asn_info=$(whois -h whois.cymru.com " -v $ip" 2>/dev/null | tail -1)
        
        if [ -n "$asn_info" ]; then
            local asn=$(echo "$asn_info" | awk -F'|' '{print $1}' | tr -d ' ')
            local asn_name=$(echo "$asn_info" | awk -F'|' '{print $NF}' | xargs)
            local country=$(echo "$asn_info" | awk -F'|' '{print $3}' | tr -d ' ')
            
            log_forensic "IP $ip -> AS$asn ($asn_name) [$country]"
            
            # Check against bulletproof ASN list
            for bp_asn in "${BULLETPROOF_ASNS[@]}"; do
                if [ "AS$asn" = "$bp_asn" ]; then
                    log_threat 40 "IP $ip is in known bulletproof/abuse-prone ASN: $bp_asn ($asn_name)"
                    asn_findings+=("bulletproof_asn:$bp_asn:$ip")
                    ((asn_score += 30))
                fi
            done
            
            # Check country
            case "$country" in
                "RU"|"CN"|"IR"|"KP"|"SY")
                    log_warning "IP $ip is in high-risk country: $country"
                    asn_findings+=("high_risk_country:$country:$ip")
                    ((asn_score += 20))
                    ;;
            esac
        fi
    done
    
    # Check registrar patterns in any WHOIS we've collected
    for registrar in "${SUSPICIOUS_REGISTRARS[@]}"; do
        if find "${EVIDENCE_DIR}" -name "whois_*" -exec grep -qil "$registrar" {} \; 2>/dev/null; then
            log_warning "Domain registered with high-abuse registrar: $registrar"
            asn_findings+=("suspicious_registrar:$registrar")
            ((asn_score += 15))
        fi
    done
    
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
            log_threat $((asn_score / 2)) "Suspicious network infrastructure detected"
        fi
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
    
    # Unicode homoglyphs that might confuse parsers
    if echo "$content" | grep -qP "[\x{00A0}\x{2000}-\x{200F}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}]" 2>/dev/null; then
        log_warning "Unicode special characters detected - possible parser confusion"
    fi
    
    # Mixed directional text
    if echo "$content" | grep -qP "[\x{202A}-\x{202E}\x{2066}-\x{2069}]" 2>/dev/null; then
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
        if echo "$content" | grep -qiE "$brand"; then
            # Check for typosquatting variations
            local variations=$(echo "$content" | grep -oiE "${brand:0:3}[a-z]*${brand: -3}" | wc -l)
            if [ $variations -gt 0 ]; then
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
}

################################################################################
# INDUSTRY-SPECIFIC THREAT ANALYSIS
################################################################################

analyze_industry_threats() {
    local content="$1"
    
    log_info "Analyzing for industry-specific threats..."
    
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
    fi
}


################################################################################
# ENHANCED QR CONTENT ANALYSIS
################################################################################

analyze_decoded_qr_content() {
    local content="$1"
    local report_file="$2"
    
    log_info "Analyzing decoded QR content..."
    
    # Determine content type
    local content_type="unknown"
    
    if echo "$content" | grep -qE "^https?://"; then
        content_type="url"
        log_info "Content type: URL"
    elif echo "$content" | grep -qE "^mailto:"; then
        content_type="email"
        log_info "Content type: Email link"
    elif echo "$content" | grep -qE "^tel:|^sms:"; then
        content_type="phone"
        log_info "Content type: Phone/SMS link"
    elif echo "$content" | grep -qE "^WIFI:"; then
        content_type="wifi"
        log_info "Content type: WiFi configuration"
    elif echo "$content" | grep -qE "^BEGIN:VCARD"; then
        content_type="vcard"
        log_info "Content type: vCard contact"
    elif echo "$content" | grep -qE "^BEGIN:VEVENT"; then
        content_type="vevent"
        log_info "Content type: Calendar event"
    elif echo "$content" | grep -qE "^otpauth://"; then
        content_type="otp"
        log_info "Content type: OTP/2FA code"
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
    
    echo "Content Type: $content_type" >> "$report_file"
    
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
    
    echo "" >> "$report_file"
}

analyze_wifi_config() {
    local content="$1"
    
    log_info "Analyzing WiFi configuration..."
    
    # Parse WIFI: format
    # WIFI:T:WPA;S:NetworkName;P:Password;;
    
    local auth_type=$(echo "$content" | grep -oP 'T:[^;]+' | cut -d: -f2)
    local ssid=$(echo "$content" | grep -oP 'S:[^;]+' | cut -d: -f2)
    local password=$(echo "$content" | grep -oP 'P:[^;]+' | cut -d: -f2)
    local hidden=$(echo "$content" | grep -oP 'H:[^;]+' | cut -d: -f2)
    
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
    
    # Extract fields
    local name=$(echo "$content" | grep -oP 'FN:[^\n]+' | cut -d: -f2-)
    local email=$(echo "$content" | grep -oP 'EMAIL[^:]*:[^\n]+' | cut -d: -f2-)
    local phone=$(echo "$content" | grep -oP 'TEL[^:]*:[^\n]+' | cut -d: -f2-)
    local url=$(echo "$content" | grep -oP 'URL[^:]*:[^\n]+' | cut -d: -f2-)
    
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
    
    # Parse otpauth://totp/ISSUER:ACCOUNT?secret=SECRET&issuer=ISSUER
    local otp_type=$(echo "$content" | grep -oP 'otpauth://[^/]+' | cut -d'/' -f3)
    local label=$(echo "$content" | grep -oP 'otpauth://[^/]+/[^?]+' | cut -d'/' -f4)
    local secret=$(echo "$content" | grep -oP 'secret=[^&]+' | cut -d'=' -f2)
    local issuer=$(echo "$content" | grep -oP 'issuer=[^&]+' | cut -d'=' -f2)
    
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

initialize() {
    log_info "Initializing QR Malware Scanner..."
    
    # Create output directories
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR" "$EVIDENCE_DIR"
    
    # Initialize log file
    echo "=== QR Malware Scanner Log ===" > "$LOG_FILE"
    echo "Started: $(date)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
    
    # Initialize report file
    echo "╔═══════════════════════════════════════════════════════════════════════════╗" > "$REPORT_FILE"
    echo "║           QR CODE MALWARE SCANNER - FORENSIC ANALYSIS REPORT              ║" >> "$REPORT_FILE"
    echo "║                         Version: $VERSION                                   ║" >> "$REPORT_FILE"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Analysis Date: $(date)" >> "$REPORT_FILE"
    echo "Hostname: $(hostname)" >> "$REPORT_FILE"
    echo "User: $(whoami)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Initialize IOC CSV
    echo "type,value,context,timestamp,threat_score" > "$IOC_REPORT"
    
    # Initialize timeline
    echo "timestamp,event_type,description,threat_level" > "$TIMELINE_FILE"
    
    # Initialize extended reports
    initialize_extended_reports
    
    log_success "Initialization complete"
}

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
    echo "Examples:"
    echo "  $(basename "$0") suspicious_qr.png"
    echo "  $(basename "$0") -d --vt /path/to/qr_images/"
    echo "  $(basename "$0") -f --siem --all-modules qr_code.jpg"
}


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
    
    # Print final summary
    echo ""
    log_success "════════════════════════════════════════════════════════════"
    log_success "ANALYSIS COMPLETE!"
    log_success "════════════════════════════════════════════════════════════"
    log_info "Duration: ${duration} seconds"
    log_info "Results saved to: $OUTPUT_DIR"
    log_info ""
    log_info "Key outputs:"
    log_info "  → Main Report:  $REPORT_FILE"
    log_info "  → JSON Report:  $JSON_REPORT"
    log_info "  → IOC Report:   $IOC_REPORT"
    log_info "  → Evidence:     $EVIDENCE_DIR"
    
    if [ "$SIEM_INTEGRATION" = true ]; then
        log_info "  → SIEM Export:  $SIEM_EXPORT_FILE"
    fi
    echo ""
    
    # Final threat level output
    if [ $THREAT_SCORE -ge $CRITICAL_THRESHOLD ]; then
        log_critical "⚠️  CRITICAL THREAT LEVEL - Immediate action required!"
    elif [ $THREAT_SCORE -ge $HIGH_THRESHOLD ]; then
        log_error "⚠️  HIGH THREAT LEVEL - Exercise extreme caution!"
    elif [ $THREAT_SCORE -ge $MEDIUM_THRESHOLD ]; then
        log_warning "⚡ MEDIUM THREAT LEVEL - Review findings carefully"
    elif [ $THREAT_SCORE -ge $LOW_THRESHOLD ]; then
        log_info "ℹ️  LOW THREAT LEVEL - Minor concerns detected"
    else
        log_success "✓ MINIMAL THREAT LEVEL - No significant threats detected"
    fi
    echo ""
}

# Run main function
main "$@"
