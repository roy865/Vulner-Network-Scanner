#!/bin/bash
############################################################
# Project: VULNER - Network Scanner & Vulnerability Mapper
# Student Name: Roy Mastrov
# Student ID: s23
# Unit Name: TMagen773639
# Program Code: zx301
# Lecturer Name: Zach Azoalis
############################################################

# --- Colors for Output ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Helper Functions ---
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root! Use: sudo $0"
        exit 1
    fi
}

check_dependencies() {
    for cmd in nmap hydra searchsploit zip; do
        if ! command -v "$cmd" &> /dev/null; then
            error "$cmd is not installed. Please install it first."
            exit 1
        fi
    done
}

validate_input() {
    if [[ -z "$TARGET" ]]; then
        error "Target network/IP is required."
        exit 1
    fi
    if [[ -z "$DIR_NAME" ]]; then
        error "Directory name is required."
        exit 1
    fi
    if [[ "${MODE,,}" != "basic" && "${MODE,,}" != "full" ]]; then
        error "Mode must be 'Basic' or 'Full'."
        exit 1
    fi
}

run_brute() {
    local port=$1
    local service=$2
    
    # Extract ONLY valid IPs from Nmap gnmap file that have the specific port open
    local hosts=$(grep "^Host:" nmap_report.gnmap | grep -E "[[:space:]]${port}/open/" | awk '{print $2}' | sort -u)
    
    if [[ -z "$hosts" ]]; then
        info "Port $port ($service) is not open on any scanned target."
        return
    fi
    
    for ip in $hosts; do
        warn "Attempting brute force on $service at $ip..."
        local outfile="hydra_${service}_${ip}.txt"
        
        # Run hydra quietly
        hydra -L passwords.lst -P passwords.lst "$ip" "$service" -I -f -o "$outfile" > /dev/null 2>&1
        
        # Verify if actual credentials were found
        if grep -q "login:" "$outfile" 2>/dev/null; then
            success "Credentials FOUND for $service on $ip! Saved to $outfile"
            echo -e "${YELLOW}>> Valid Credentials for $ip ($service):${NC}"
            grep "login:" "$outfile"
        else
            info "No weak credentials found for $service on $ip."
            rm -f "$outfile" # Cleanup empty files
        fi
    done
}

# --- Main Execution ---
check_root
check_dependencies

echo -e "${YELLOW}"
echo "------------------------------------------------"
echo "   VULNER PROJECT - AUTOMATED PEN-TESTING      "
echo "------------------------------------------------"
echo -e "${NC}"

# 1. Getting the User Input
read -p "Enter Target IP or Range (e.g. 192.168.1.0/24): " TARGET
read -p "Enter Output Directory Name: " DIR_NAME
read -p "Choose Mode (Basic / Full): " MODE
read -p "Enter path to custom password list (Press Enter to skip): " CUSTOM_PASS_LIST

validate_input

# Setup Directory
mkdir -p "$DIR_NAME"
# Save absolute path of custom list before cd
if [[ -n "$CUSTOM_PASS_LIST" && -f "$CUSTOM_PASS_LIST" ]]; then
    CUSTOM_PASS_ABS=$(realpath "$CUSTOM_PASS_LIST")
fi

cd "$DIR_NAME" || exit
info "All results will be saved in: $(pwd)"

# Nmap Scan
info "Starting Network Mapping on $TARGET (Mode: $MODE)..."
if [[ "${MODE,,}" == "full" ]]; then
    # Full: TCP, NSE, Versions
    nmap -sV -sC --script vuln "$TARGET" -oA nmap_report
else
    # Basic: TCP & UDP, Versions (-sU added per guidelines. Limited top-ports to save time)
    nmap -sS -sU -sV --top-ports 100 "$TARGET" -oA nmap_report
fi
success "Nmap scan finished."

# 2. Weak Credentials
info "Preparing password list..."
# Built-in list
cat << EOF > passwords.lst
admin
123456
password
root
msfadmin
user
1234
EOF

# Custom list
if [[ -n "$CUSTOM_PASS_ABS" ]]; then
    cat "$CUSTOM_PASS_ABS" >> passwords.lst
    success "Added user-supplied passwords to the list."
fi

# Check Login Services
info "Checking for weak credentials on FTP, SSH, Telnet, RDP..."
run_brute "21" "ftp"
run_brute "22" "ssh"
run_brute "23" "telnet"
run_brute "3389" "rdp"

# 3. Mapping Vulnerabilities
if [[ "${MODE,,}" == "full" ]]; then
    info "Analyzing vulnerabilities with Searchsploit..."
    searchsploit --nmap nmap_report.xml > vulnerability_analysis.txt 2>/dev/null
    success "Vulnerability mapping complete. Saved to vulnerability_analysis.txt"
fi

# 4. Show the user the found information
echo -e "\n${YELLOW}--- SUMMARY OF FINDINGS ---${NC}"
info "Target(s) Open Ports Overview:"
# Fix: Clean output of IPs and their open ports without breaking format
grep "Ports:" nmap_report.gnmap | awk -F'\t' '{print "   [+] " $1 "\n       " $2}'
echo ""

info "Check hydra results files in the directory for any found passwords."
if [[ "${MODE,,}" == "full" ]]; then
    info "Vulnerabilities mapped via Searchsploit are in vulnerability_analysis.txt"
fi

# Search Feature
echo -e "\n${YELLOW}--- SEARCH FEATURE ---${NC}"
read -p "Enter keyword to search in results (or press enter to skip): " SEARCH_QUERY
if [[ -n "$SEARCH_QUERY" ]]; then
    grep -rni --color=always "$SEARCH_QUERY" .
fi

# ZIP IT!
echo -e "\n"
read -p "Would you like to zip all results? (y/n): " ZIP_CHOICE
if [[ "${ZIP_CHOICE,,}" == "y" ]]; then
    cd ..
    zip -r "${DIR_NAME}.zip" "$DIR_NAME" > /dev/null
    success "Created archive: ${DIR_NAME}.zip"
fi

success "VULNER Operation Order Complete."
