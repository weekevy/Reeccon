#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
BOLD_GREEN='\033[1;32m'
BOLD_YELLOW='\033[1;33m'
BOLD_WHITE='\033[1;37m'
PURPLE='\033[0;35m'
UNDERLINE='\033[4m'
RESET='\033[0m'

# Default output file
OUTPUT_FILE="./all_subs.txt"

# Show usage for active enumeration
show_active_usage() {
    echo -e "Usage: reecon sub --active -w <wordlist> -d <domain> [-o <output_file>]"
    echo ""
    echo -e "  -f <input_file>  List of domains"
    echo -e "  -d <domain>      Target domain to bruteforce"
    echo -e "  -w <wordlist>    Wordlist for bruteforce (required)"
    echo -e "  -t <threads>     Threads for massdns (default: 1000)"
    echo -e "  -r <resolvers>   Resolvers file (default: ./resolvers/resolvers.txt)"
    echo -e "  -o <file/dir>    Output file (for -d) or directory (for -f)"
    echo -e ""
    echo -e "${YELLOW}examples:${RESET}"
    echo -e "  reecon sub --active -d example.com -w subdomains.txt"
    echo -e "  reecon sub --active -d example.com -w all.txt -t 2000 -o results.txt"
    echo -e "  reecon sub --active -f domains.txt -w all.txt -o /home/user/result"
    exit 1
}
show_passive_usage() {
    echo -e "${BOLD_GREEN}Usage: $0 --passive -d <domain> [-o <output_file>]${RESET}"
    echo -e "${YELLOW}Options:${RESET}"
    echo -e "  -d <domain>    Target domain to enumerate"
    echo -e "  -o <file>      Output file (default: ./all_subs.txt)"
    echo -e ""
    echo -e "${BOLD_GREEN}Examples:${RESET}"
    echo -e "  $0 --passive -d example.com"
    echo -e "  $0 --passive -d example.com -o /home/user/subdomains.txt"
    exit 1
}

# Check required tools for active enumeration
check_active_tools() {
    local tools=("massdns" "dnsx")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing tools: ${missing[*]}${RESET}"
        echo -e "${YELLOW}[+] Please install missing tools and try again${RESET}"
        exit 1
    fi
    
    if [ ! -f "$RESOLVERS" ]; then
        echo -e "${RED}[-] Error: Resolvers file $RESOLVERS not found${RESET}"
        echo -e "${YELLOW}[+] Get it from: https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt${RESET}"
        exit 1
    fi
}

# Generate DNS queries
generate_dns_queries() {
    local domain="$1"
    local wordlist="$2"
    
    if [ ! -f "$wordlist" ]; then
        echo -e "${RED}[-] Error: Wordlist $wordlist not found${RESET}"
        exit 1
    fi
    
    while IFS= read -r sub; do
        sub=$(echo "$sub" | tr -d '[:space:]')
        if [ -n "$sub" ]; then
            echo "${sub}.${domain}"
        fi
    done < "$wordlist"
}

# Detect wildcard DNS
detect_wildcard() {
    local domain="$1"
    local resolvers="$2"
    
    echo -e "${CYAN}[*] Checking for wildcard subdomains...${RESET}"
    
    for i in {1..5}; do
        random_sub=$(head /dev/urandom | tr -dc 'a-z0-9' | fold -w 20 | head -n 1)
        test_domain="${random_sub}.${domain}"
        
        if massdns -r "$resolvers" -t A -o S -w /dev/stdout <<< "$test_domain" 2>/dev/null | grep -q "ANSWER: 1"; then
            echo -e "${YELLOW}[!] Wildcard detected for *.${domain}${RESET}"
            return 0
        fi
    done
    
    echo -e "${GREEN}[+] No wildcard detected${RESET}"
    return 1
}

# Progress bar function
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r${CYAN}[${RESET}"
    printf "%${completed}s" | tr ' ' '='
    printf "%${remaining}s" | tr ' ' '-'
    printf "${CYAN}]${RESET} ${BOLD_GREEN}%d%%${RESET} ${YELLOW}(%d/%d subdomains tested)${RESET}" "$percentage" "$current" "$total"
}

# Bruteforce single domain with progress
bruteforce_domain() {
    local domain=$1
    local wordlist=$2
    local threads=$3
    local resolvers=$4
    local output=$5
    
    local word_count=$(wc -l < "$wordlist" | tr -d ' ')
    local temp_queries=$(mktemp)
    local temp_output=$(mktemp)
    
    echo -e "${BOLD_GREEN}[+] Starting active subdomain bruteforce for: $domain${RESET}"
    echo -e "${BOLD_GREEN}[+] Wordlist: $wordlist ($word_count words)${RESET}"
    echo -e "${BOLD_GREEN}[+] Threads: $threads${RESET}"
    echo -e "${BOLD_GREEN}[+] Output file: $output${RESET}"
    echo ""
    
    # Generate all DNS queries first
    echo -e "${BLUE}[+] Generating DNS queries...${RESET}"
    generate_dns_queries "$domain" "$wordlist" > "$temp_queries"
    local total_queries=$(wc -l < "$temp_queries" | tr -d ' ')
    
    echo -e "${BLUE}[+] Running massdns bruteforce...${RESET}"
    echo ""
    
    # Run massdns with progress monitoring
    (
        massdns -r "$resolvers" -t A -o S -w "$temp_output" -s "$threads" < "$temp_queries" 2>/dev/null &
        local massdns_pid=$!
        
        # Monitor progress
        local count=0
        while kill -0 $massdns_pid 2>/dev/null; do
            if [ -f "$temp_output" ]; then
                count=$(grep -c "ANSWER: 1" "$temp_output" 2>/dev/null || echo "0")
            fi
            show_progress $count $total_queries
            sleep 0.5
        done
        
        # Final progress
        if [ -f "$temp_output" ]; then
            count=$(grep -c "ANSWER: 1" "$temp_output" 2>/dev/null || echo "0")
        fi
        show_progress $total_queries $total_queries
        echo ""
        echo ""
        
        wait $massdns_pid
    )
    
    # Process massdns results
    if [ -f "$temp_output" ] && [ -s "$temp_output" ]; then
        echo -e "${YELLOW}[+] Extracting valid subdomains...${RESET}"
        grep "ANSWER: 1" "$temp_output" 2>/dev/null | \
        awk '{print $1}' | sed 's/\.$//' | \
        sort -u > "$output.tmp"
        
        local massdns_count=$(wc -l < "$output.tmp" | tr -d ' ')
        echo -e "${GREEN}[+] massdns found: $massdns_count potential subdomains${RESET}"
        
        # Verify with dnsx
        if [ -s "$output.tmp" ]; then
            echo -e "${YELLOW}[+] Verifying results with dnsx...${RESET}"
            
            local verified=0
            local dnsx_total=$(wc -l < "$output.tmp")
            
            # Run dnsx with progress
            (
                cat "$output.tmp" | dnsx -silent -a -resp -r "$resolvers" > "$output.verified" 2>/dev/null &
                local dnsx_pid=$!
                
                while kill -0 $dnsx_pid 2>/dev/null; do
                    if [ -f "$output.verified" ]; then
                        verified=$(wc -l < "$output.verified" 2>/dev/null || echo "0")
                    fi
                    printf "\r${CYAN}[dnsx]${RESET} ${YELLOW}Verified: ${BOLD_GREEN}%d${RESET}${YELLOW}/%d${RESET}" "$verified" "$dnsx_total"
                    sleep 0.3
                done
                
                wait $dnsx_pid
            )
            
            # Final dnsx results
            if [ -f "$output.verified" ] && [ -s "$output.verified" ]; then
                awk '{print $1}' "$output.verified" | sort -u > "$output"
                verified=$(wc -l < "$output" | tr -d ' ')
                printf "\r${CYAN}[dnsx]${RESET} ${YELLOW}Verified: ${BOLD_GREEN}%d${RESET}${YELLOW}/%d${RESET}\n" "$verified" "$dnsx_total"
            else
                touch "$output"
                verified=0
            fi
            
            echo ""
            
            rm -f "$output.verified"
        else
            echo -e "${RED}[-] No subdomains to verify${RESET}"
            touch "$output"
            verified=0
        fi
        
        rm -f "$output.tmp"
    else
        echo -e "${RED}[-] No subdomains found for $domain${RESET}"
        touch "$output"
        verified=0
    fi
    
    # Clean up temp files
    rm -f "$temp_queries" "$temp_output"
    
    # Summary
    echo -e "${BOLD_GREEN}"
    echo "=== BRUTEFORCE SUMMARY ==="
    echo "Domain: $domain"
    echo "Wordlist size: $word_count"
    echo "Threads: $threads"
    echo "Queries tested: $total_queries"
    echo "-------------------"
    echo "Valid subdomains found: $verified"
    echo "Final output: $output"
    echo -e "${RESET}"
}

# Process multiple domains for active enumeration
process_file_active() {
    local input_file=$1
    local output_dir="$OUTPUT_DIR"
    
    if [ ! -f "$input_file" ]; then
        echo -e "${RED}[-] Error: File '$input_file' not found${RESET}"
        exit 1
    fi
    
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
        echo -e "${GREEN}[+] Created output directory: $output_dir${RESET}"
    fi
    
    local total_domains=$(wc -l < "$input_file")
    local current=0
    
    echo -e "${BOLD_GREEN}[+] Processing $total_domains domains from file: $input_file${RESET}"
    echo -e "${BOLD_GREEN}[+] Results will be saved in: $output_dir${RESET}"
    echo ""
    
    while IFS= read -r domain; do
        [ -z "$domain" ] && continue
        [[ "$domain" =~ ^#.*$ ]] && continue
        
        current=$((current + 1))
        echo -e "${CYAN}[+] [$current/$total_domains] Processing domain: $domain${RESET}"
        echo ""
        
        OUTPUT_FILE="${output_dir}/brute-${domain}.txt"
        
        detect_wildcard "$domain" "$RESOLVERS"
        bruteforce_domain "$domain" "$WORDLIST" "$THREADS" "$RESOLVERS" "$OUTPUT_FILE"
        
        echo ""
        echo -e "${MAGENTA}========================================${RESET}"
        echo ""
    done < "$input_file"
    
    echo -e "${BOLD_GREEN}[+] All domains processed!${RESET}"
    echo -e "${BOLD_GREEN}[+] Results saved in directory: $output_dir${RESET}"
    echo -e "${BOLD_GREEN}[+] Files format: brute-<domain>.txt${RESET}"
}

# Check required tools
check_tools() {
    local tools=("subfinder" "assetfinder" "findomain" "chaos" "dnsrecon" "jq" "curl")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}[-] Missing tools: ${missing[*]}${RESET}"
        echo -e "${YELLOW}[+] Please install missing tools and try again${RESET}"
        exit 1
    fi
}

# Single target passive enumeration
single_target() {
    local domain=$1
    local output_file="$OUTPUT_FILE"
    local temp_dir=$(mktemp -d)
    
    echo -e "${BOLD_GREEN}[+] Starting passive subdomain enumeration for: $domain${RESET}"
    echo -e "${BOLD_GREEN}[+] Output file: $output_file${RESET}"
    
    # 1. Subfinder
    echo -e "${GREEN}[+] subfinder working !${RESET}"
    subfinder -d "$domain" -silent > "$temp_dir/subfinder.txt" 2>/dev/null
    local subfinder_count=$(wc -l < "$temp_dir/subfinder.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[+] subfinder done : $subfinder_count subdomains${RESET}"

    # 2. Assetfinder
    echo -e "${YELLOW}[+] assetfinder working !${RESET}"
    assetfinder --subs-only "$domain" > "$temp_dir/assetfinder.txt" 2>/dev/null
    local assetfinder_count=$(wc -l < "$temp_dir/assetfinder.txt" 2>/dev/null || echo "0")
    echo -e "${YELLOW}[+] assetfinder done : $assetfinder_count subdomains${RESET}"
    
    # 3. crt.sh
    echo -e "${BLUE}[+] crt.sh working !${RESET}"
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value // empty' 2>/dev/null | sed 's/\*\.//g' | sort -u > "$temp_dir/crtsh.txt" 2>/dev/null
    local crtsh_count=$(wc -l < "$temp_dir/crtsh.txt" 2>/dev/null || echo "0")
    echo -e "${BLUE}[+] crt.sh done : $crtsh_count subdomains${RESET}"

    # 4. Findomain
    echo -e "${CYAN}[+] findomain working !${RESET}"
    findomain -t "$domain" --quiet -u "$temp_dir/findomain.txt" > /dev/null 2>&1
    local findomain_count=$(wc -l < "$temp_dir/findomain.txt" 2>/dev/null || echo "0")
    echo -e "${CYAN}[+] findomain done : $findomain_count subdomains${RESET}"

    # 5. DNSRecon (Passive standard enumeration)
    echo -e "${BOLD_YELLOW}[+] dnsrecon working !${RESET}"
    dnsrecon -d "$domain" -t std > "$temp_dir/dnsrecon.txt" 2>/dev/null
    local dnsrecon_count=$(grep -c "$domain" "$temp_dir/dnsrecon.txt" 2>/dev/null || echo "0")
    echo -e "${BOLD_YELLOW}[+] dnsrecon done : $dnsrecon_count records${RESET}"

    # 6. Chaos
    echo -e "${BOLD_WHITE}[+] chaos working !${RESET}"
    chaos -d "$domain" -silent > "$temp_dir/chaos.txt" 2>/dev/null
    local chaos_count=$(wc -l < "$temp_dir/chaos.txt" 2>/dev/null || echo "0")
    echo -e "${BOLD_WHITE}[+] chaos done : $chaos_count subdomains${RESET}"

    echo -e "${PURPLE}[+] Combining and deduplicating results...${RESET}"
    cat "$temp_dir"/{subfinder,assetfinder,crtsh,findomain,chaos}.txt 2>/dev/null | \
        grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" | \
        grep "$domain" | \
        sort -u > "$output_file"
    
    local total_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    
    rm -rf "$temp_dir"
    
    echo -e "${BOLD_GREEN}"
    echo "=== ENUMERATION SUMMARY ==="
    echo "Domain: $domain"
    echo "Subfinder: $subfinder_count"
    echo "Assetfinder: $assetfinder_count"
    echo "crt.sh: $crtsh_count"
    echo "Findomain: $findomain_count"
    echo "Chaos: $chaos_count"
    echo "DNSRecon: $dnsrecon_count"
    echo "-------------------"
    echo "Total unique subdomains: $total_count"
    echo "Final output: $output_file"
    echo -e "${RESET}"
}

# Process multiple domains from file
process_file() {
    local input_file=$1
    local output_dir="$OUTPUT_DIR"
    
    if [ ! -f "$input_file" ]; then
        echo -e "${RED}[-] Error: File '$input_file' not found${RESET}"
        exit 1
    fi
    
    # Create output directory if it doesn't exist
    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
        echo -e "${GREEN}[+] Created output directory: $output_dir${RESET}"
    fi
    
    local total_domains=$(wc -l < "$input_file")
    local current=0
    
    echo -e "${BOLD_GREEN}[+] Processing $total_domains domains from file: $input_file${RESET}"
    echo -e "${BOLD_GREEN}[+] Results will be saved in: $output_dir${RESET}"
    echo ""
    
    while IFS= read -r domain; do
        # Skip empty lines and comments
        [ -z "$domain" ] && continue
        [[ "$domain" =~ ^#.*$ ]] && continue
        
        current=$((current + 1))
        echo -e "${CYAN}[+] [$current/$total_domains] Processing domain: $domain${RESET}"
        echo ""
        
        # Set output file for this domain in the output directory
        OUTPUT_FILE="${output_dir}/result-${domain}.txt"
        
        # Run enumeration
        single_target "$domain"
        
        echo ""
        echo -e "${MAGENTA}========================================${RESET}"
        echo ""
    done < "$input_file"
    
    echo -e "${BOLD_GREEN}[+] All domains processed!${RESET}"
    echo -e "${BOLD_GREEN}[+] Results saved in directory: $output_dir${RESET}"
    echo -e "${BOLD_GREEN}[+] Files format: result-<domain>.txt${RESET}"
}

# Passive enumeration function
passive_enumeration() {
    local domain=""
    local input_file=""
    local custom_output=""
    
    # Shift past the --passive argument
    shift
    
    while getopts "f:d:o:h" opt; do
        case $opt in
            f)
                input_file="$OPTARG"
                ;;
            d)
                domain="$OPTARG"
                ;;
            o)
                custom_output="$OPTARG"
                ;;
            h)
                show_passive_usage
                ;;
            \?)
                echo -e "${RED}[-] Invalid option: -$OPTARG${RESET}" >&2
                show_passive_usage
                ;;
            :)
                echo -e "${RED}[-] Option -$OPTARG requires an argument.${RESET}" >&2
                show_passive_usage
                ;;
        esac
    done
    
    # Check if both -f and -d are provided
    if [ -n "$input_file" ] && [ -n "$domain" ]; then
        echo -e "${RED}[-] Error: Cannot use both -f and -d options together${RESET}"
        show_passive_usage
    fi
    
    # Check if neither -f nor -d is provided
    if [ -z "$input_file" ] && [ -z "$domain" ]; then
        echo -e "${RED}[-] Error: Either -f or -d option is required${RESET}"
        show_passive_usage
    fi
    
    check_tools
    
    # Process based on input type
    if [ -n "$input_file" ]; then
        # For file input, -o specifies output directory
        if [ -n "$custom_output" ]; then
            OUTPUT_DIR="$custom_output"
        fi
        process_file "$input_file"
    else
        # For single domain, -o specifies output file
        if [ -n "$custom_output" ]; then
            OUTPUT_FILE="$custom_output"
        fi
        single_target "$domain"
    fi
}

# Active enumeration function
active_enumeration() {
    local domain=""
    local input_file=""
    local custom_output=""
    
    shift
    
    while getopts "f:d:w:t:r:o:h" opt; do
        case $opt in
            f)
                input_file="$OPTARG"
                ;;
            d)
                domain="$OPTARG"
                ;;
            w)
                WORDLIST="$OPTARG"
                ;;
            t)
                THREADS="$OPTARG"
                ;;
            r)
                RESOLVERS="$OPTARG"
                ;;
            o)
                custom_output="$OPTARG"
                ;;
            h)
                show_active_usage
                ;;
            \?)
                echo -e "${RED}[-] Invalid option: -$OPTARG${RESET}" >&2
                echo ""
                show_active_usage
                ;;
            :)
                echo -e "${RED}[-] Option -$OPTARG requires an argument.${RESET}" >&2
                show_active_usage
                ;;
        esac
    done
    
    # Validate: Cannot use both -f and -d
    if [ -n "$input_file" ] && [ -n "$domain" ]; then
        echo -e "${RED}[-] Error: Cannot use both -f and -d options together${RESET}"
        echo ""
        show_active_usage
    fi
    
    # Validate: Must provide either -f or -d
    if [ -z "$input_file" ] && [ -z "$domain" ]; then
        echo -e "${RED}[-] Error: Either -f (file) or -d (domain) is required${RESET}"
        echo ""
        show_active_usage
    fi
    
    # Validate: Wordlist is required
    if [ -z "$WORDLIST" ]; then
        echo -e "${RED}[-] Error: Wordlist is required (-w)${RESET}"
        echo ""
        show_active_usage
    fi
    
    # Validate: Wordlist file exists
    if [ ! -f "$WORDLIST" ]; then
        echo -e "${RED}[-] Error: Wordlist file '$WORDLIST' not found${RESET}"
        exit 1
    fi
    
    # Validate: Input file exists (if -f is used)
    if [ -n "$input_file" ] && [ ! -f "$input_file" ]; then
        echo -e "${RED}[-] Error: Input file '$input_file' not found${RESET}"
        exit 1
    fi
    
    # Validate: Threads is a number
    if ! [[ "$THREADS" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[-] Error: Threads must be a positive number${RESET}"
        exit 1
    fi
    
    # Validate: Resolvers file exists
    if [ ! -f "$RESOLVERS" ]; then
        echo -e "${RED}[-] Error: Resolvers file '$RESOLVERS' not found${RESET}"
        echo -e "${YELLOW}[+] You can download it from:${RESET}"
        echo -e "${YELLOW}    https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt${RESET}"
        exit 1
    fi
    
    # Check required tools
    check_active_tools
    
    # Process based on input type
    if [ -n "$input_file" ]; then
        # Multiple domains from file
        if [ -n "$custom_output" ]; then
            OUTPUT_DIR="$custom_output"
        fi
        process_file_active "$input_file"
    else
        # Single domain
        if [ -n "$custom_output" ]; then
            OUTPUT_FILE="$custom_output"
        else
            OUTPUT_FILE="brute_results.txt"
        fi
        detect_wildcard "$domain" "$RESOLVERS"
        bruteforce_domain "$domain" "$WORDLIST" "$THREADS" "$RESOLVERS" "$OUTPUT_FILE"
    fi
}

# Argument parsing function
parse_arguments() {
    local passive=false
    local active=false
    
    if [[ $# -eq 0 ]]; then
        echo "  Usage: netdom sub [type]"
        echo -e "${YELLOW}  Modules${RESET}"
        echo ""
        echo "      --passive      passive enumeration"
        echo "      --active       active enumeration"
        echo ""
        echo ""
        exit 0
    fi
    
    # Parse command line arguments
    case $1 in
        --passive)
            passive_enumeration "$@"
            ;;
        --active)
            active_enumeration "$@"
            ;;
        *)
            echo "Error: Unknown argument '$1'"
            exit 1
            ;;
    esac
}

# Main function
main() {
    parse_arguments "$@"
    exit 0
}

# Execute main function with all script arguments
main "$@"
