#!/bin/bash

# autoAR Logo
printf "==============================\n"
printf "

 ▗▄▖ ▗▖ ▗▖▗▄▄▄▖▗▄▖  ▗▄▖ ▗▄▄▖ 
▐▌ ▐▌▐▌ ▐▌  █ ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌
▐▛▀▜▌▐▌ ▐▌  █ ▐▌ ▐▌▐▛▀▜▌▐▛▀▚▖
▐▌ ▐▌▝▚▄▞▘  █ ▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌
                              By: h0tak88r
                                    
"
printf "==============================\n"

# Constants
RESULTS_DIR="results"
WORDLIST_DIR="Wordlists"
FUZZ_WORDLIST="$WORDLIST_DIR/quick_fuzz.txt"
TARGET=""
SINGLE_SUBDOMAIN=""
LOG_FILE="autoAR.log"
DISCORD_WEBHOOK=""
VERBOSE=false
SKIP_PORT_SCAN=false
SKIP_FUZZING=false
SKIP_SQLI=false
SKIP_PARAMX=false
SKIP_DALFOX=false
PARAMX_TEMPLATES="paramx-templates"
DOMAIN_DIR=""

# Help function
show_help() {
    cat << EOF
Usage: ./autoAr.sh [-d domain.com] [-s subdomain.domain.com] [options]

Options:
    -h, --help              Show this help message
    -d, --domain           Target domain (e.g., example.com)
    -s, --subdomain        Single subdomain to scan (e.g., sub.example.com)
    -v, --verbose          Enable verbose output
    --skip-port            Skip port scanning
    --skip-fuzzing         Skip fuzzing scans
    --skip-sqli           Skip SQL injection scanning
    --skip-paramx         Skip ParamX scanning
    --skip-dalfox         Skip Dalfox XSS scanning
    --discord-webhook     Discord webhook URL for notifications

Examples:
    ./autoAr.sh -d example.com
    ./autoAr.sh -s sub.example.com --skip-port
    ./autoAr.sh -d example.com --skip-fuzzing --skip-sqli
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--domain)
            TARGET="$2"
            shift 2
            ;;
        -s|--subdomain)
            SINGLE_SUBDOMAIN="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --skip-port)
            SKIP_PORT_SCAN=true
            shift
            ;;
        --skip-fuzzing)
            SKIP_FUZZING=true
            shift
            ;;
        --skip-sqli)
            SKIP_SQLI=true
            shift
            ;;
        --skip-paramx)
            SKIP_PARAMX=true
            shift
            ;;
        --skip-dalfox)
            SKIP_DALFOX=true
            shift
            ;;
        --discord-webhook)
            DISCORD_WEBHOOK="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" ]] && [[ -z "$SINGLE_SUBDOMAIN" ]]; then
    log "Error: Must specify either -d (domain) or -s (subdomain)"
    show_help
    exit 1
fi

if [[ -n "$TARGET" ]] && [[ -n "$SINGLE_SUBDOMAIN" ]]; then
    log "Error: Cannot specify both domain and subdomain. Choose one."
    show_help
    exit 1
fi

# Function to log messages
log() {
    local message="$1"
    printf "%s\n" "$message"
    printf "%s\n" "$message" >> "$LOG_FILE"
    
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        send_to_discord "$message"
    fi
}

# Function to send messages to Discord
send_to_discord() {
    local content="$1"
    curl -H "Content-Type: application/json" \
         -X POST \
         -d "{\"content\": \"$content\"}" \
         "$DISCORD_WEBHOOK" > /dev/null 2>&1
}

# Function to send files to Discord
send_file_to_discord() {
    local file="$1"
    local description="$2"
    if [[ -f "$file" ]]; then
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            curl -F "file=@$file" \
                 -F "payload_json={\"content\": \"$description\"}" \
                 "$DISCORD_WEBHOOK" > /dev/null 2>&1
        else
            log "Discord webhook not provided, skipping file upload."
        fi
    else
        log "Error: File $file does not exist."
    fi
}

# Function to check and clone repositories if they do not exist
check_and_clone() {
    local dir="$1"
    local repo_url="$2"
    if [[ ! -d "$dir" ]]; then
        log "Error: $dir directory not found."
        log "To clone $dir, run:"
        log "git clone $repo_url"
        exit 1
    fi
}

# Function to check if required tools are installed
check_tools() {
    local tools=("subfinder" "httpx" "naabu" "nuclei" "ffuf" "kxss" "qsreplace" "paramx" "dalfox" "urlfinder" "interlace")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log "Error: The following tools are not installed:"
        for tool in "${missing_tools[@]}"; do
            log "- $tool"
        done
        log "Please install missing tools before running the script."
        exit 1
    fi
}

# Function to setup results directory
setup_results_dir() {
    # Set up domain-specific directory path first
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        DOMAIN_DIR="$RESULTS_DIR/$SINGLE_SUBDOMAIN"
    elif [[ -n "$TARGET" ]]; then
        DOMAIN_DIR="$RESULTS_DIR/$TARGET"
    else
        log "Error: No target specified"
        exit 1
    fi
    
    # Remove domain-specific directory if it exists
    if [[ -d "$DOMAIN_DIR" ]]; then
        log "[+] Removing previous results for ${SINGLE_SUBDOMAIN:-$TARGET}"
        rm -rf "$DOMAIN_DIR"
    fi
    
    # Create fresh domain directory and subdirectories
    mkdir -p "$DOMAIN_DIR"/{subs,urls,vulnerabilities/{xss,sqli,ssrf,ssti,lfi,rce,idor},fuzzing,ports}
    
    # Create initial empty files
    touch "$DOMAIN_DIR/urls/live.txt"
    touch "$DOMAIN_DIR/urls/all-urls.txt"
    touch "$DOMAIN_DIR/ports/ports.txt"
    touch "$DOMAIN_DIR/vulnerabilities/put-scan.txt"
    touch "$DOMAIN_DIR/fuzzing/ffufGet.txt"
    touch "$DOMAIN_DIR/fuzzing/ffufPost.txt"
    touch "$DOMAIN_DIR/subs/all-subs.txt"
    touch "$DOMAIN_DIR/subs/apis-subs.txt"
    touch "$DOMAIN_DIR/subs/subfinder-subs.txt"
    
    log "[+] Created fresh directory structure at $DOMAIN_DIR"
}

# Function to run fuzzing with ffuf
run_ffuf() {
    log "[+] Fuzzing with ffuf"
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        ffuf -u "https://$SINGLE_SUBDOMAIN/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique > "$DOMAIN_DIR/fuzzing/ffuf.html"
        ffuf -u "https://$SINGLE_SUBDOMAIN/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique -X POST > "$DOMAIN_DIR/fuzzing/ffuf-post.html"
        send_file_to_discord "$DOMAIN_DIRR/fuzzing/ffuf.html" "ffuf GET Fuzz Results"
        send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf-post.html" "ffuf POST Fuzz Results"
    else
        while IFS= read -r url; do
            log "[+] Fuzzing $url with ffuf"
            ffuf -u "$url/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique > "$DOMAIN_DIR/fuzzing/ffuf.html"
            ffuf -u "$url/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique -X POST > "$DOMAIN_DIR/fuzzing/ffuf-post.html"
            send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf.html" "ffuf GET Fuzz Results for $url"
            send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf-post.html" "ffuf POST Fuzz Results for $url"
        done < "$DOMAIN_DIR/subs/live-subs.txt"
    fi
}

# Function to run SQL injection scanning with sqlmap
run_sql_injection_scan() {
    log "[+] SQL Injection Scanning with sqlmap"
    interlace -tL "$DOMAIN_DIR/gf-sqli.txt" -threads 5 -c "sqlmap -u _target_ --batch --dbs --random-agent >> '$DOMAIN_DIR/sqlmap-sqli.txt'"
    send_file_to_discord "$DOMAIN_DIR/sqlmap-sqli.txt" "SQL Injection Scan Results"
}

# Function to run reflection scanning
run_reflection_scan() {
    log "[+] Reflection Scanning"
    kxss < "$DOMAIN_DIR/urls/all-urls.txt" | tee "$DOMAIN_DIR/vulnerabilities/kxss-results.txt"
    send_file_to_discord "$DOMAIN_DIR/vulnerabilities/kxss-results.txt" "Reflection Scan Results"
}

# Function to run subdomain enumeration
subEnum() {
    local domain="$1"
    log "[+] Subdomain Enumeration using SubFinder and free API Sources"
    
    # Create temporary file for collecting subdomains
    local tmp_file="$DOMAIN_DIR/subs/tmp_subs.txt"
    
    # Ensure subs directory exists
    mkdir -p "$DOMAIN_DIR/subs"
    
    # Initialize/clear files
    > "$DOMAIN_DIR/subs/apis-subs.txt"
    > "$DOMAIN_DIR/subs/subfinder-subs.txt"
    > "$DOMAIN_DIR/subs/all-subs.txt"
    > "$tmp_file"
    
    # Collect subdomains from various sources
    log "[+] Collecting subdomains from APIs..."
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://certspotter.com/api/v0/certs?domain=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://crt.sh/?q=%.$domain&output=json" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> "$tmp_file"
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    
    # Clean and sort API results
    if [[ -f "$tmp_file" ]]; then
        cat "$tmp_file" | sed -e "s/\*\.$domain//g" -e "s/^\..*//g" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$DOMAIN_DIR/subs/apis-subs.txt"
        rm "$tmp_file"
    fi
    
    # Run subfinder
    log "[+] Running subfinder..."
    if command -v subfinder &> /dev/null; then
        subfinder -d "$domain" -all -silent -o "$DOMAIN_DIR/subs/subfinder-subs.txt"
    else
        log "[-] subfinder not found, skipping subfinder enumeration"
    fi
    
    # Combine and sort all results
    cat "$DOMAIN_DIR/subs/subfinder-subs.txt" "$DOMAIN_DIR/subs/apis-subs.txt" 2>/dev/null | grep -v "*" | sort -u > "$DOMAIN_DIR/subs/all-subs.txt"
    
    # Count results
    local total_subs=$(wc -l < "$DOMAIN_DIR/subs/all-subs.txt")
    log "[+] Found $total_subs unique subdomains"
    
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        log "Subdomain Enumeration completed. Results saved in $DOMAIN_DIR/subs/all-subs.txt"
        send_file_to_discord "$DOMAIN_DIR/subs/all-subs.txt" "Subdomain Enumeration completed - Found $total_subs subdomains"
    else
        log "[-] No subdomains found for $domain"
    fi
}

# Function to fetch URLs
fetch_urls() {
    log "[+] Fetching URLs using URLFinder"
    
    # Ensure urls directory exists
    mkdir -p "$DOMAIN_DIR/urls"
    
    # Initialize/clear files
    > "$DOMAIN_DIR/urls/all-urls.txt"
    > "$DOMAIN_DIR/urls/live.txt"
    
    # Run URLFinder with all sources and proper filtering
    urlfinder -d "$TARGET" -all  -silent -o "$DOMAIN_DIR/urls/all-urls.txt"
    
    # Check if we found any URLs
    if [[ -f "$DOMAIN_DIR/urls/all-urls.txt" && -s "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        # Filter live URLs using httpx
        if command -v httpx &> /dev/null; then
            cat "$DOMAIN_DIR/urls/all-urls.txt" | httpx -silent -mc 200,201,301,302,403 -o "$DOMAIN_DIR/urls/live.txt"
        else
            cp "$DOMAIN_DIR/urls/all-urls.txt" "$DOMAIN_DIR/urls/live.txt"
            log "[-] httpx not found, skipping live URL filtering"
        fi
        
        # Count URLs
        local total_urls=$(wc -l < "$DOMAIN_DIR/urls/all-urls.txt")
        local live_urls=$(wc -l < "$DOMAIN_DIR/urls/live.txt")
        log "[+] Found $total_urls unique URLs ($live_urls live)"
        
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$DOMAIN_DIR/urls/live.txt" "Found $live_urls live URLs"
        fi
    else
        log "[-] No URLs found for $TARGET"
        echo "" > "$DOMAIN_DIR/urls/all-urls.txt"
        echo "" > "$DOMAIN_DIR/urls/live.txt"
    fi
}

# Function to filter live hosts
filter_live_hosts() {
    if [[ ! -f "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        log "[-] No subdomains file found at $DOMAIN_DIR/subs/all-subs.txt"
        return
    fi
    
    log "[+] Filtering live hosts"
    mkdir -p "$DOMAIN_DIR/subs"
    
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        cat "$DOMAIN_DIR/subs/all-subs.txt" | httpx -silent -mc 200,201,301,302,403 -o "$DOMAIN_DIR/subs/live-subs.txt"
        local total_subs=$(wc -l < "$DOMAIN_DIR/subs/all-subs.txt")
        local live_subs=$(wc -l < "$DOMAIN_DIR/subs/live-subs.txt")
        log "[+] Found $live_subs live subdomains out of $total_subs total"
    else
        log "[-] No subdomains found to filter"
        touch "$DOMAIN_DIR/subs/live-subs.txt"
    fi
}

# Function to run port scanning
run_port_scan() {
    log "[+] Port Scanning with naabu"
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        naabu -l "$DOMAIN_DIR/subs/all-subs.txt" -p - -o "$DOMAIN_DIR/ports/ports.txt"
        if [[ -s "$DOMAIN_DIR/ports/ports.txt" ]]; then
            send_file_to_discord "$DOMAIN_DIR/ports/ports.txt" "Port Scan Results"
        else
            log "[-] No open ports found"
        fi
    else
        log "[-] No subdomains found to scan ports"
    fi
}

# Function to run ParamX scans
run_paramx_scans() {
    log "[+] Running ParamX scans for different vulnerability patterns"
    
    # Create vulnerabilities directory if it doesn't exist
    mkdir -p "$DOMAIN_DIR/vulnerabilities"
    
    # Define vulnerability patterns to scan for
    local patterns=("xss" "sqli" "lfi" "rce" "idor" "ssrf" "ssti" "redirect")
    
    # Check if we have URLs to scan
    if [[ ! -f "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        log "[!] No URLs found to scan"
        return
    fi
    
    # Scan for each vulnerability pattern
    for pattern in "${patterns[@]}"; do
        # Create directory for this vulnerability type
        mkdir -p "$DOMAIN_DIR/vulnerabilities/$pattern"
        
        log "  [*] Scanning for $pattern parameters"
        cat "$DOMAIN_DIR/urls/all-urls.txt" | paramx -tp "$PARAMX_TEMPLATES" -tag "$pattern" -o "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt"
        
        # Check if we found any parameters
        if [[ -s "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt" ]]; then
            local count=$(wc -l < "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt")
            log "  [+] Found $count potential $pattern parameters"
            
            if [[ -n "$DISCORD_WEBHOOK" ]]; then
                send_file_to_discord "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt" "Found $count potential $pattern parameters"
            fi
        fi
    done
}

# Function to check and setup paramx templates
setup_paramx_templates() {
    # Check if templates directory exists
    if [[ ! -d "$PARAMX_TEMPLATES" ]]; then
        log "[+] Creating ParamX templates directory"
        mkdir -p "$PARAMX_TEMPLATES"
        
        # Clone default templates if directory is empty
        if [[ -z "$(ls -A "$PARAMX_TEMPLATES")" ]]; then
            log "[+] Cloning default ParamX templates"
            git clone https://github.com/cyinnove/paramx-templates.git tmp_templates
            cp -r tmp_templates/* "$PARAMX_TEMPLATES/"
            rm -rf tmp_templates
        fi
    fi
    
    # Verify templates exist
    if [[ -z "$(ls -A "$PARAMX_TEMPLATES")" ]]; then
        log "Error: No ParamX templates found in $PARAMX_TEMPLATES"
        log "Please add your templates to this directory or use -t to specify a different directory"
        exit 1
    fi
    
    log "[+] Using ParamX templates from: $PARAMX_TEMPLATES"
}

# Function to scan a single subdomain
scan_single_subdomain() {
    local subdomain="$1"
    
    log "[+] Running scans on subdomain: $subdomain"
    
    # Create initial URL list and discover URLs
    mkdir -p "$DOMAIN_DIR/urls"
    echo "https://$subdomain" > "$DOMAIN_DIR/urls/live.txt"
    echo "http://$subdomain" >> "$DOMAIN_DIR/urls/live.txt"
    
    # Use urlfinder to discover URLs
    log "[+] Running urlfinder on subdomain"
    urlfinder -d "$subdomain" -all -silent -o "$DOMAIN_DIR/urls/all-urls.txt"
    
    put_scan "$DOMAIN_DIR"
    scan_js_exposures "$DOMAIN_DIR"
    run_nuclei_scans "$DOMAIN_DIR"

    # Run focused scans
    if [[ "$SKIP_FUZZING" != "true" ]]; then
        run_ffuf
    fi
    
    if [[ "$SKIP_SQLI" != "true" ]]; then
        run_sql_injection_scan
    fi
    
    if [[ "$SKIP_DALFOX" != "true" ]]; then
        run_dalfox_scan
    fi
}

# Function to scan entire domain
scan_domain() {
    local domain="$1"
    log "[+] Running scans on domain: $domain"
    
    # Initial domain reconnaissance
    subEnum "$domain"
    fetch_urls
    filter_live_hosts
    
    # Create vulnerabilities directory
    mkdir -p "$DOMAIN_DIR/vulnerabilities"
    
    put_scan "$DOMAIN_DIR"
    subdomain_takeover_scan "$DOMAIN_DIR"
    scan_js_exposures "$DOMAIN_DIR"
    
    # Run port scan if not skipped
    if [[ "$SKIP_PORT_SCAN" != "true" ]]; then
        log "[+] Port scanning enabled"
        run_port_scan
    else
        log "[-] Port scanning disabled"
    fi
    
    # Run security scans
    if [[ "$SKIP_FUZZING" != "true" ]]; then
        run_ffuf
    fi
    
    if [[ "$SKIP_SQLI" != "true" ]]; then
        run_sql_injection_scan
    fi
    
    if [[ "$SKIP_DALFOX" != "true" ]]; then
        run_dalfox_scan
    else
        log "[-] Dalfox scanning disabled"
    fi
    

}

# Function to check enabled PUT Method
put_scan() {
    local domain_dir="$1"
    log "[+] Checking for PUT method"
    while IFS= read -r host; do
        local path="evil.txt"
        curl -s -X PUT -d "hello world" "${host}/${path}" > /dev/null
        if curl -s -o /dev/null -w "%{http_code}" -X GET "${host}/${path}" | grep -q "200"; then
            echo "$host" >> "$domain_dir/vulnerabilities/put-scan.txt"
        fi
    done < "$domain_dir/subs/live-subs.txt"
    send_file_to_discord "$domain_dir/vulnerabilities/put-scan.txt" "PUT Scan results"
    log "[+] PUT Method scan completed"
}

# Function to run Dalfox scans
run_dalfox_scan() {
    log "[+] Dalfox Scanning"
    dalfox file "$DOMAIN_DIR/gf-xss.txt" --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav -b "XSS Server here" -w 50 -o "$DOMAIN_DIR/dalfox-results.txt"
    send_file_to_discord "$DOMAIN_DIR/dalfox-results.txt" "Dalfox XSS Scan Results"
}

# Function to run subdomain takeover scanning
subdomain_takeover_scan() {
    local domain_dir="$1"
    log "[+] Subdomain Takeover Scanning"
    
    # Check if subs.txt exists
    if [[ ! -f "$domain_dir/subs/all-subs.txt" ]]; then
        log "[-] No subdomains file found at $domain_dir/subs/all-subs.txt"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/takeovers"
    
    # Run subov88r if available
    if command -v subov88r &> /dev/null; then
        log "[+] Running subov88r for Azure services check"
        subov88r -f "$domain_dir/subs/all-subs.txt" -o "$domain_dir/vulnerabilities/takeovers/azureSDT.txt"
    else
        log "[-] subov88r not found, skipping Azure subdomain takeover check"
    fi
    
    # Run nuclei scans
    if [[ -d "nuclei_templates" ]]; then
        log "[+] Running nuclei takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei_templates/http/takeovers/ -o "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt"
        
        if [[ -s "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" ]]; then
            send_file_to_discord "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" "Nuclei Takeover Scan Results"
        fi
    fi
    
    if [[ -d "nuclei_templates" ]]; then
        log "[+] Running custom takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei_templates/takeover/detect-all-takeover.yaml -o "$domain_dir/vulnerabilities/takeovers/custom-results.txt"
        
        if [[ -s "$domain_dir/vulnerabilities/takeovers/custom-results.txt" ]]; then
            send_file_to_discord "$domain_dir/vulnerabilities/takeovers/custom-results.txt" "Custom Takeover Scan Results"
        fi
    fi
    
    # Send Azure results if they exist and are not empty
    if [[ -s "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" ]]; then
        send_file_to_discord "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" "Azure Subdomain Takeover Results"
    fi
    
    # Create a summary of all findings
    {
        echo "=== Subdomain Takeover Scan Summary ==="
        echo "Time: $(date)"
        echo
        echo "=== Azure Services ==="
        if [[ -s "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" ]]; then
            cat "$domain_dir/vulnerabilities/takeovers/azureSDT.txt"
        else
            echo "No Azure services found"
        fi
        echo
        echo "=== Nuclei Takeover Results ==="
        if [[ -s "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" ]]; then
            cat "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt"
        else
            echo "No findings from nuclei takeover templates"
        fi
        echo
        echo "=== Custom Takeover Results ==="
        if [[ -s "$domain_dir/vulnerabilities/takeovers/custom-results.txt" ]]; then
            cat "$domain_dir/vulnerabilities/takeovers/custom-results.txt"
        else
            echo "No findings from custom takeover templates"
        fi
    } > "$domain_dir/vulnerabilities/takeovers/summary.txt"
    
    send_file_to_discord "$domain_dir/vulnerabilities/takeovers/summary.txt" "Subdomain Takeover Summary"
}

# Function to scan for JS exposures
scan_js_exposures() {
    local domain_dir="$1"
    log "[+] JS Exposures"
    
    # Check if urls.txt exists
    if [[ ! -f "$domain_dir/urls/all-urls.txt" ]]; then
        log "[-] No URLs file found at $domain_dir/urls/all-urls.txt"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/js"
    
    # Extract JS URLs and save them
    log "[+] Extracting JavaScript URLs"
    grep -i "\.js" "$domain_dir/urls/all-urls.txt" > "$domain_dir/vulnerabilities/js/js-urls.txt"
    
    # Only proceed if we found JS files
    if [[ -s "$domain_dir/vulnerabilities/js/js-urls.txt" ]]; then
        local js_count=$(wc -l < "$domain_dir/vulnerabilities/js/js-urls.txt")
        log "[+] Found $js_count JavaScript files"
        
        if [[ -d "nuclei_templates" ]]; then
            log "[+] Scanning JavaScript files with nuclei"
            nuclei -l "$domain_dir/vulnerabilities/js/js-urls.txt" -t nuclei_templates/js/ -o "$domain_dir/vulnerabilities/js/exposures.txt"
            
            # Send results only if we found exposures
            if [[ -s "$domain_dir/vulnerabilities/js/exposures.txt" ]]; then
                local vuln_count=$(wc -l < "$domain_dir/vulnerabilities/js/exposures.txt")
                log "[+] Found $vuln_count potential JavaScript vulnerabilities"
                send_file_to_discord "$domain_dir/vulnerabilities/js/exposures.txt" "JS Exposures Scan Results"
            else
                log "[+] No JavaScript vulnerabilities found"
            fi
        else
            log "[-] nuclei_templates directory not found, skipping JS exposure scan"
        fi
    else
        log "[-] No JavaScript files found in URLs"
    fi
    
    # Create a summary report
    {
        echo "=== JavaScript Analysis Summary ==="
        echo "Time: $(date)"
        echo
        if [[ -s "$domain_dir/vulnerabilities/js/js-urls.txt" ]]; then
            echo "Total JavaScript files found: $(wc -l < "$domain_dir/vulnerabilities/js/js-urls.txt")"
            echo
            echo "=== JavaScript URLs ==="
            cat "$domain_dir/vulnerabilities/js/js-urls.txt"
            echo
            echo "=== Vulnerabilities Found ==="
            if [[ -s "$domain_dir/vulnerabilities/js/exposures.txt" ]]; then
                cat "$domain_dir/vulnerabilities/js/exposures.txt"
            else
                echo "No vulnerabilities found"
            fi
        else
            echo "No JavaScript files found"
        fi
    } > "$domain_dir/vulnerabilities/js/summary.txt"
    
    send_file_to_discord "$domain_dir/vulnerabilities/js/summary.txt" "JavaScript Analysis Summary"
}

# Function to run nuclei scans
run_nuclei_scans() {
    local domain_dir="$1"
    log "[+] Nuclei Scanning with severity filtering (medium,high,critical)"
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        nuclei -u "https://$SINGLE_SUBDOMAIN" -s medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt"
        nuclei -u "https://$SINGLE_SUBDOMAIN" -s medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt"
    else
        nuclei -l "$domain_dir/subs/live-subs.txt" -s medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt"
        nuclei -l "$domain_dir/subs/live-subs.txt" -s medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt"
    fi
    send_file_to_discord "$domain_dir/vulnerabilities/nuclei_templates-results.txt" "Collected Templates Nuclei Scans Results"
    send_file_to_discord "$domain_dir/vulnerabilities/nuclei-templates-results.txt" "Public Nuclei Scans Results"
}

# Main function
main() {
    # Check required tools first
    check_tools
    
    # Validate input
    if [[ -z "$TARGET" ]] && [[ -z "$SINGLE_SUBDOMAIN" ]]; then
        log "Error: Must specify either -d (domain) or -s (subdomain)"
        show_help
        exit 1
    fi
    
    if [[ -n "$TARGET" ]] && [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        log "Error: Cannot specify both domain and subdomain. Choose one."
        show_help
        exit 1
    fi
    
    # Setup results directory and structure
    setup_results_dir
    
    # Clone required repositories if they don't exist
    if [[ ! -d "$WORDLIST_DIR" ]]; then
        log "[+] Cloning wordlists repository..."
        git clone https://github.com/h0tak88r/Wordlists.git "$WORDLIST_DIR"
    fi
    
    if [[ ! -d "nuclei_templates" ]]; then
        log "[+] Cloning nuclei templates..."
        git clone https://github.com/h0tak88r/nuclei_templates.git
    fi
    
    # Setup ParamX templates if not skipping
    if [[ "$SKIP_PARAMX" != "true" ]]; then
        setup_paramx_templates
    fi
    
    # Execute appropriate scan based on input
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        scan_single_subdomain "$SINGLE_SUBDOMAIN"
    else
        scan_domain "$TARGET"
    fi
    
    # Final reporting
    log "[+] All scans completed successfully!"
    log "[+] Results are saved in: $DOMAIN_DIR"
    
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        send_to_discord "🎉 AutoAR scan completed! Check $DOMAIN_DIR for detailed findings."
    fi
}

main
