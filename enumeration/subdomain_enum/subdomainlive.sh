#!/usr/bin/env bash
# subdomain_live.sh — Subdomain reachability & block detection
set -uo pipefail

# Early help check
for _arg in "$@"; do
    if [[ "$_arg" == "-h" || "$_arg" == "--help" ]]; then
        cat << 'EOF'
subdomain_live.sh — Subdomain reachability & block detection

Usage: ./subdomain_live.sh [input_file] [options]

Options:
  -i, --input FILE         Input file with subdomains (default: scope)
  -o, --output-dir DIR     Output directory (default: results_TIMESTAMP)
  -t, --timeout SECS       DNS/HTTP timeout in seconds (default: 5)
  -T, --threads N          Parallel workers (default: 10)
  -r, --resolver IP        Single resolver to use
  -R, --resolver-file FILE File with resolvers (one per line)
  -f, --format FORMAT      Output format: tsv, csv, json (default: tsv)
  -v, --verbose N          Verbose level 0-3 (default: 1)
  -q, --quiet              Quiet mode (no output)
  --no-progress            Disable progress bar
  --retry N                Number of retries for failed checks (default: 2)
  --rate-limit MS          Minimum ms between requests (rate limiting)

Examples:
  ./subdomain_live.sh subdomains.txt
  ./subdomain_live.sh subdomains.txt -t 3 -T 20 -v 0
  ./subdomain_live.sh -i subdomains.txt -R resolvers.txt -f json -o myresults
EOF
        exit 0
    fi
done

# Defaults
INPUT_FILE="scope"
TIMEOUT=5
THREADS=10
RESOLVERS=("8.8.8.8" "1.1.1.1" "9.9.9.9")
RESOLVER_FILE=""
OUTPUT_DIR="results_$(date +%Y%m%d_%H%M%S)"
OUTPUT_FORMAT="tsv"
VERBOSE=1
QUIET=0
RETRY=2
RATE_LIMIT=0
PROGRESS=1

# If $1 is a plain filename (not a flag), consume it as INPUT_FILE
if [[ $# -gt 0 && "$1" != -* ]]; then
    INPUT_FILE="$1"
    shift
fi

# Arg parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--input)        INPUT_FILE="$2";    shift 2 ;;
        -o|--output-dir)   OUTPUT_DIR="$2";    shift 2 ;;
        -t|--timeout)      TIMEOUT="$2";       shift 2 ;;
        -T|--threads)      THREADS="$2";       shift 2 ;;
        -r|--resolver)     RESOLVERS=("$2");   shift 2 ;;
        -R|--resolver-file) RESOLVER_FILE="$2"; shift 2 ;;
        -f|--format)       OUTPUT_FORMAT="$2"; shift 2 ;;
        -v|--verbose)      VERBOSE="$2"; [[ "$VERBOSE" =~ ^[0-9]+$ ]] || VERBOSE=1; shift 2 ;;
        -q|--quiet)        QUIET=1; VERBOSE=0; shift ;;
        --no-progress)     PROGRESS=0;         shift ;;
        --retry)           RETRY="$2";         shift 2 ;;
        --rate-limit)      RATE_LIMIT="$2";    shift 2 ;;
        *) echo "Unknown option: $1"; echo "Use -h for help"; exit 1 ;;
    esac
done

# Bash version check
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    echo "Error: Bash 4.0 or higher is required (current: $BASH_VERSION)" >&2
    echo "macOS users: brew install bash" >&2
    exit 1
fi

# Load resolvers from file
if [[ -n "$RESOLVER_FILE" && -f "$RESOLVER_FILE" ]]; then
    mapfile -t FILE_RESOLVERS < <(grep -vE '^\s*#|^\s*$' "$RESOLVER_FILE")
    if [[ ${#FILE_RESOLVERS[@]} -gt 0 ]]; then
        RESOLVERS=("${FILE_RESOLVERS[@]}")
    fi
fi

# Colour helpers
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

ok()   { [[ $QUIET -eq 0 ]] && echo -e "${GREEN}+${RESET} $*"; }
fail() { [[ $QUIET -eq 0 ]] && echo -e "${RED}x${RESET} $*"; }
warn() { [[ $QUIET -eq 0 ]] && echo -e "${YELLOW}!${RESET} $*"; }
info() { [[ $QUIET -eq 0 ]] && echo -e "${CYAN}i${RESET} $*"; }

# Dependency check
MISSING=()
for cmd in dig curl ping awk grep sed xargs flock; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing tools: ${MISSING[*]}"
    warn "Install with: sudo apt install dnsutils curl iputils-ping util-linux"
    exit 1
fi

# Sanity check input
if [[ ! -f "$INPUT_FILE" ]]; then
    fail "Input file '$INPUT_FILE' not found."
    echo "Usage: $0 [input_file] [--timeout N] [--threads N]"
    echo "Use -h for full help"
    exit 1
fi

# Validate domains
VALID_HOSTS=()
while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    host=$(echo "$line" | awk '{print $1}')
    [[ -z "$host" ]] && continue
    if [[ "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
        VALID_HOSTS+=("$host")
    else
        [[ $VERBOSE -ge 2 ]] && warn "Skipping invalid domain: $host"
    fi
done < "$INPUT_FILE"

HOSTS=("${VALID_HOSTS[@]}")
TOTAL=${#HOSTS[@]}

if [[ $TOTAL -eq 0 ]]; then
    fail "No valid hosts found in $INPUT_FILE"
    exit 1
fi

# Validate resolvers
VALID_RESOLVERS=()
for resolver in "${RESOLVERS[@]}"; do
    if dig +short +time=2 "@${resolver}" google.com A &>/dev/null; then
        VALID_RESOLVERS+=("$resolver")
    else
        [[ $VERBOSE -ge 2 ]] && warn "Resolver $resolver is not responding"
    fi
done

if [[ ${#VALID_RESOLVERS[@]} -eq 0 ]]; then
    warn "No valid resolvers, using system default"
    VALID_RESOLVERS=("")
else
    RESOLVERS=("${VALID_RESOLVERS[@]}")
fi

# Output setup
mkdir -p "$OUTPUT_DIR"
RESOLVED_FILE="$OUTPUT_DIR/resolved.txt"
UNRESOLVED_FILE="$OUTPUT_DIR/unresolved.txt"
BLOCKED_FILE="$OUTPUT_DIR/blocked.txt"
FILTERED_FILE="$OUTPUT_DIR/filtered.txt"
TIMEOUT_FILE="$OUTPUT_DIR/timed_out.txt"
SUMMARY_FILE="$OUTPUT_DIR/summary.$OUTPUT_FORMAT"
RESOLVED_IPS_FILE="$OUTPUT_DIR/resolved_ips.txt"
UNRESOLVED_IPS_FILE="$OUTPUT_DIR/unresolved_ips.txt"

> "$RESOLVED_IPS_FILE"
> "$UNRESOLVED_IPS_FILE"

case "$OUTPUT_FORMAT" in
    tsv)  printf "subdomain\tip\tdns_status\thttp_code\thttps_code\tstatus\tnotes\n" > "$SUMMARY_FILE" ;;
    csv)  printf "subdomain,ip,dns_status,http_code,https_code,status,notes\n" > "$SUMMARY_FILE" ;;
    json) printf "[\n" > "$SUMMARY_FILE" ;;
esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Sinkhole IPs / ranges
SINKHOLE_NETS=("0.0.0.0" "127.0.0.1" "::1")

# Block-page body patterns
BLOCK_PAGE_PATTERNS=(
    "This site has been blocked"
    "Access Denied"
    "This domain has been seized"
    "has been suspended"
    "Parked Domain"
    "Domain For Sale"
    "Website Blocked"
    "The requested URL was rejected"
    "ERR_BLOCKED_BY"
    "The domain.*expired"
)

# Signal handling
handle_signal() {
    warn "Interrupted! Saving partial results..."
    trap - SIGINT SIGTERM
    kill -SIGINT "$$"
}
trap handle_signal SIGINT SIGTERM

# Functions
resolve_dns() {
    local host="$1"
    local ip="" status="NXDOMAIN" ipv6="" cname=""

    local host_hash
    host_hash=$(printf '%s' "$host" | cksum | awk '{print $1}')
    local cache_file="$TMP_DIR/cache_${host_hash}"
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return
    fi

    for resolver in "${RESOLVERS[@]}"; do
        if [[ -n "$resolver" ]]; then
            ip=$(dig +short +time="$TIMEOUT" "@${resolver}" A "$host" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        else
            ip=$(dig +short +time="$TIMEOUT" A "$host" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        fi
        [[ -n "$ip" ]] && { status="RESOLVED"; break; }
    done

    if [[ -z "$ip" ]]; then
        for resolver in "${RESOLVERS[@]}"; do
            if [[ -n "$resolver" ]]; then
                ipv6=$(dig +short +time="$TIMEOUT" "@${resolver}" AAAA "$host" 2>/dev/null | grep -E '^[0-9a-fA-F:]' | head -1)
            else
                ipv6=$(dig +short +time="$TIMEOUT" AAAA "$host" 2>/dev/null | grep -E '^[0-9a-fA-F:]' | head -1)
            fi
            [[ -n "$ipv6" ]] && { status="RESOLVED_V6"; break; }
        done
    fi

    if [[ -z "$ip" && -z "$ipv6" ]]; then
        cname=$(dig +short +time="$TIMEOUT" CNAME "$host" 2>/dev/null | head -1)
        if [[ -n "$cname" ]]; then
            local cname_ip=""
            for resolver in "${RESOLVERS[@]}"; do
                if [[ -n "$resolver" ]]; then
                    cname_ip=$(dig +short +time="$TIMEOUT" "@${resolver}" A "${cname}" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
                else
                    cname_ip=$(dig +short +time="$TIMEOUT" A "${cname}" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
                fi
                [[ -n "$cname_ip" ]] && { ip="$cname_ip"; status="CNAME_RESOLVED"; break; }
            done
            if [[ -z "$cname_ip" ]]; then
                ip="$cname"
                status="CNAME_ONLY"
            fi
        fi
    fi

    local result="${ip:-$ipv6}|${status}"
    echo "$result" > "$cache_file"
    echo "$result"
}

is_sinkholed() {
    local ip="$1"
    for net in "${SINKHOLE_NETS[@]}"; do
        [[ "$ip" == "$net" ]] && return 0
    done
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    [[ "$ip" =~ ^10\.       ]] && return 0
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
    return 1
}

probe_http() {
    local host="$1" scheme="$2"
    local tmp_body
    tmp_body=$(mktemp)

    local code
    code=$(curl -sk \
        --max-time "$TIMEOUT" \
        --connect-timeout "$TIMEOUT" \
        -o "$tmp_body" \
        -w "%{http_code}" \
        -L --max-redirs 1 \
        -H "User-Agent: Mozilla/5.0 (compatible; subdomain-checker/2.0)" \
        "${scheme}://${host}" 2>/dev/null)

    local body_status="ok"
    for pat in "${BLOCK_PAGE_PATTERNS[@]}"; do
        grep -qiE "$pat" "$tmp_body" 2>/dev/null && { body_status="block_page"; break; }
    done
    rm -f "$tmp_body"

    echo "${code:-000}|$body_status"
}

check_host() {
    local host="$1"
    local result_file="$TMP_DIR/result_${host//[^a-zA-Z0-9]/_}_$$_$RANDOM"
    local attempt=0 success=0
    local dns_status="UNKNOWN" ip="-" http_code="-" https_code="-"
    local status="UNKNOWN" notes=""

    while [[ $attempt -lt $RETRY && $success -eq 0 ]]; do
        ((attempt++))

        if [[ $RATE_LIMIT -gt 0 ]]; then
            local whole=$(( RATE_LIMIT / 1000 ))
            local frac
            frac=$(printf '%03d' $(( RATE_LIMIT % 1000 )))
            sleep "${whole}.${frac}"
        fi

        local dns_result http_body https_body
        dns_result=$(resolve_dns "$host")
        ip="${dns_result%%|*}"
        dns_status="${dns_result##*|}"

        if [[ "$dns_status" == "NXDOMAIN" ]]; then
            status="UNRESOLVED"
            notes="DNS: NXDOMAIN across system + ${#RESOLVERS[@]} public resolvers"
            http_code="-"; https_code="-"
            success=1
        elif [[ "$dns_status" == "CNAME_ONLY" ]]; then
            status="CNAME_NO_A"
            notes="Resolves to CNAME only, no A record"
            http_code="-"; https_code="-"
            success=1
        else
            if is_sinkholed "$ip"; then
                status="SINKHOLED"
                notes="IP $ip is sinkhole/private — likely seized or blocked"
            fi

            local http_result https_result
            http_result=$(probe_http  "$host" "http")
            https_result=$(probe_http "$host" "https")

            http_code="${http_result%%|*}";   http_body="${http_result##*|}"
            https_code="${https_result%%|*}"; https_body="${https_result##*|}"

            if [[ "$status" != "SINKHOLED" ]]; then
                if [[ "$http_code" == "000" && "$https_code" == "000" ]]; then
                    if [[ $TIMEOUT -ge 1 ]] && ping -c 1 -W "$TIMEOUT" "$ip" &>/dev/null; then
                        status="CONN_REFUSED"
                        notes="Responds to ICMP but HTTP/S ports are closed or firewalled"
                    else
                        status="TIMEOUT/FILTERED"
                        notes="No ICMP or HTTP(S) response — firewall dropping or host is down"
                    fi
                elif [[ "$http_code"  =~ ^(403|406|429|451)$ || \
                        "$https_code" =~ ^(403|406|429|451)$ ]]; then
                    status="HTTP_BLOCKED"
                    notes="HTTP ${http_code} / HTTPS ${https_code} — access denied or legally blocked"
                elif [[ "$http_body" == "block_page" || "$https_body" == "block_page" ]]; then
                    status="BLOCK_PAGE"
                    notes="Block, parking, or seizure content detected in response body"
                elif [[ "$http_code" =~ ^[23] || "$https_code" =~ ^[23] ]]; then
                    status="UP"
                    notes="Responding normally"
                elif [[ "$http_code" =~ ^5 || "$https_code" =~ ^5 ]]; then
                    status="SERVER_ERROR"
                    notes="HTTP ${http_code} / HTTPS ${https_code} — server-side error"
                else
                    status="UNCLEAR"
                    notes="HTTP ${http_code} / HTTPS ${https_code} — unexpected response"
                fi
            fi
            success=1
        fi
    done

    if [[ $success -eq 0 ]]; then
        status="CHECK_FAILED"
        notes="Failed after $RETRY attempts"
    fi

    local output_ip="${ip:--}"

    case "$OUTPUT_FORMAT" in
        tsv)
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
                "$host" "$output_ip" "$dns_status" "${http_code:--}" "${https_code:--}" "$status" "$notes" \
                > "$result_file" ;;
        csv)
            printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
                "$host" "$output_ip" "$dns_status" "${http_code:--}" "${https_code:--}" "$status" "$notes" \
                > "$result_file" ;;
        json)
            local http_c="${http_code:--}" https_c="${https_code:--}"
            http_c="${http_c//\"/\\\"}"; https_c="${https_c//\"/\\\"}"
            notes="${notes//\"/\\\"}"
            printf '{"subdomain":"%s","ip":"%s","dns_status":"%s","http_code":"%s","https_code":"%s","status":"%s","notes":"%s"}\n' \
                "$host" "$output_ip" "$dns_status" "$http_c" "$https_c" "$status" "$notes" \
                > "$result_file" ;;
    esac

    [[ $QUIET -eq 1 ]] && return

    local colour="$RESET"
    case "$status" in
        UP)                    colour="$GREEN"  ;;
        UNRESOLVED|CNAME_NO_A) colour="$DIM"    ;;
        SINKHOLED|HTTP_BLOCKED|BLOCK_PAGE|CONN_REFUSED|TIMEOUT/FILTERED) colour="$RED" ;;
        SERVER_ERROR)          colour="$YELLOW" ;;
        *)                     colour="$YELLOW" ;;
    esac

    [[ $VERBOSE -ge 1 ]] && printf "${BOLD}%-45s${RESET}  ${colour}%-20s${RESET}  ip=%-18s  http=%-7s https=%-7s  %s\n" \
        "$host" "$status" "$output_ip" "${http_code:--}" "${https_code:--}" "$notes"
}

export -f check_host resolve_dns probe_http is_sinkholed
export TIMEOUT TMP_DIR SINKHOLE_NETS BLOCK_PAGE_PATTERNS
export RED GREEN YELLOW CYAN BOLD DIM RESET OUTPUT_FORMAT RETRY RATE_LIMIT QUIET VERBOSE

RESOLVERS_EXPORT="${RESOLVERS[*]}"
export RESOLVERS_EXPORT

# Header
if [[ $QUIET -eq 0 ]]; then
    echo ""
    echo -e "${BOLD}+==============================================================+${RESET}"
    echo -e "${BOLD}|      Subdomain Reachability & Block Detector                 |${RESET}"
    echo -e "${BOLD}+==============================================================+${RESET}"
    echo ""
    info "Input      : $INPUT_FILE"
    info "Output dir : $OUTPUT_DIR/"
    info "Timeout    : ${TIMEOUT}s"
    info "Threads    : $THREADS"
    info "Resolvers  : ${RESOLVERS[*]}"
    info "Format     : $OUTPUT_FORMAT"
    echo ""
    printf "${BOLD}%-45s  %-20s  %-18s  %-7s %-7s  %s${RESET}\n" \
        "SUBDOMAIN" "STATUS" "IP" "HTTP" "HTTPS" "NOTES"
    printf '%0.s-' {1..115}; echo ""
fi

info "Checking $TOTAL unique hosts with $THREADS parallel workers..."
[[ $QUIET -eq 0 ]] && echo ""

# Progress tracking
PROGRESS_FILE="$TMP_DIR/progress.txt"
PROGRESS_LOCK="$TMP_DIR/progress.lock"
echo "0" > "$PROGRESS_FILE"
touch "$PROGRESS_LOCK"

update_progress() {
    [[ $PROGRESS -eq 0 || $QUIET -eq 1 || $TOTAL -eq 0 ]] && return
    local current
    current=$(flock "$PROGRESS_LOCK" bash -c \
        'v=$(cat "$1"); echo $((v + 1)) > "$1"; echo $((v + 1))' \
        _ "$PROGRESS_FILE")
    local pct=$((current * 100 / TOTAL))
    printf "\rProgress: [%d/%d] %d%%" "$current" "$TOTAL" "$pct" >&2
}

export -f update_progress
export PROGRESS PROGRESS_FILE PROGRESS_LOCK TOTAL

# Run
START_TIME=$(date +%s)

printf '%s\n' "${HOSTS[@]}" | \
    xargs -P "$THREADS" -I{} bash -c '
        read -ra RESOLVERS <<< "$RESOLVERS_EXPORT"
        export RESOLVERS
        check_host "$@"
        update_progress
    ' _ {} || true

[[ $PROGRESS -eq 1 && $QUIET -eq 0 ]] && echo "" >&2

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Aggregate
[[ $QUIET -eq 0 ]] && { printf '%0.s-' {1..115}; echo ""; echo ""; }

declare -A counts
counts[UP]=0; counts[UNRESOLVED]=0; counts[BLOCKED]=0
counts[TIMEOUT]=0; counts[OTHER]=0

FIRST=1
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    case "$OUTPUT_FORMAT" in
        tsv)
            host="${line%%	*}";    rest="${line#*	}"
            ip="${rest%%	*}";     rest="${rest#*	}"
            dns_s="${rest%%	*}";  rest="${rest#*	}"
            http="${rest%%	*}";   rest="${rest#*	}"
            https="${rest%%	*}";  rest="${rest#*	}"
            status="${rest%%	*}"; notes="${rest#*	}"
            ;;
        csv)
            IFS=',' read -r host ip dns_s http https status notes <<< "$line"
            host="${host//\"/}"; ip="${ip//\"/}"; dns_s="${dns_s//\"/}"
            http="${http//\"/}"; https="${https//\"/}"
            status="${status//\"/}"; notes="${notes//\"/}"
            ;;
        json)
            host=$(echo   "$line" | grep -o '"subdomain":"[^"]*"'  | cut -d'"' -f4)
            ip=$(echo     "$line" | grep -o '"ip":"[^"]*"'          | cut -d'"' -f4)
            dns_s=$(echo  "$line" | grep -o '"dns_status":"[^"]*"'  | cut -d'"' -f4)
            http=$(echo   "$line" | grep -o '"http_code":"[^"]*"'   | cut -d'"' -f4)
            https=$(echo  "$line" | grep -o '"https_code":"[^"]*"'  | cut -d'"' -f4)
            status=$(echo "$line" | grep -o '"status":"[^"]*"'      | cut -d'"' -f4)
            notes=$(echo  "$line" | grep -o '"notes":"[^"]*"'       | cut -d'"' -f4)
            ;;
    esac

    case "$OUTPUT_FORMAT" in
        tsv|csv)
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
                "$host" "$ip" "$dns_s" "$http" "$https" "$status" "$notes" >> "$SUMMARY_FILE" ;;
        json)
            [[ $FIRST -eq 1 ]] && FIRST=0 || printf ",\n" >> "$SUMMARY_FILE"
            printf "%s" "$line" >> "$SUMMARY_FILE" ;;
    esac

    case "$status" in
        UP)
            echo "$host  ($ip)" >> "$RESOLVED_FILE"
            echo "$ip"          >> "$RESOLVED_IPS_FILE"
            ((counts[UP]++)) ;;
        UNRESOLVED|CNAME_NO_A)
            echo "$host" >> "$UNRESOLVED_FILE"
            echo "$host" >> "$UNRESOLVED_IPS_FILE"
            ((counts[UNRESOLVED]++)) ;;
        SINKHOLED|HTTP_BLOCKED|BLOCK_PAGE|CONN_REFUSED)
            echo "$host  ($ip)  [$status]  $notes" >> "$BLOCKED_FILE"
            [[ -n "$ip" && "$ip" != "-" ]] \
                && echo "$ip"   >> "$RESOLVED_IPS_FILE" \
                || echo "$host" >> "$UNRESOLVED_IPS_FILE"
            ((counts[BLOCKED]++)) ;;
        TIMEOUT*|SERVER_ERROR)
            echo "$host  ($ip)  [$status]  $notes" >> "$TIMEOUT_FILE"
            [[ -n "$ip" && "$ip" != "-" ]] \
                && echo "$ip"   >> "$RESOLVED_IPS_FILE" \
                || echo "$host" >> "$UNRESOLVED_IPS_FILE"
            ((counts[TIMEOUT]++)) ;;
        *)
            echo "$host  ($ip)  [$status]  $notes" >> "$FILTERED_FILE"
            [[ -n "$ip" && "$ip" != "-" ]] \
                && echo "$ip"   >> "$RESOLVED_IPS_FILE" \
                || echo "$host" >> "$UNRESOLVED_IPS_FILE"
            ((counts[OTHER]++)) ;;
    esac
done < <(cat "$TMP_DIR"/result_* 2>/dev/null)

[[ "$OUTPUT_FORMAT" == "json" ]] && printf "\n]\n" >> "$SUMMARY_FILE"

# Summary
if [[ $QUIET -eq 0 ]]; then
    echo -e "${BOLD}Results Summary${RESET}"
    echo "----------------------------------------"
    echo -e "  Total checked    : ${BOLD}${TOTAL}${RESET}"
    echo -e "  Duration         : ${DURATION}s"
    ok    "  Up & responding  : ${counts[UP]}"
    fail  "  Unresolved DNS   : ${counts[UNRESOLVED]}"
    warn  "  Blocked/Seized   : ${counts[BLOCKED]}"
    warn  "  Timeout/Filtered : ${counts[TIMEOUT]}"
    info  "  Other/Unclear    : ${counts[OTHER]}"
    echo ""
    pct=$(( counts[UP] * 100 / TOTAL ))
    echo -e "  Resolution rate  : ${BOLD}${pct}%${RESET}"
    echo ""
    info "Output files in ${BOLD}${OUTPUT_DIR}/${RESET}:"
    for f in "$RESOLVED_FILE" "$UNRESOLVED_FILE" "$BLOCKED_FILE" "$TIMEOUT_FILE" \
             "$FILTERED_FILE" "$SUMMARY_FILE" "$RESOLVED_IPS_FILE" "$UNRESOLVED_IPS_FILE"; do
        [[ -f "$f" && -s "$f" ]] && \
            printf "    %-40s  (%s lines)\n" "$(basename "$f")" "$(wc -l < "$f")"
    done
    echo ""
    echo -e "${BOLD}IP List Files:${RESET}"
    echo "  resolved_ips.txt   — one IP per line for every subdomain that resolved"
    echo "  unresolved_ips.txt — one subdomain per line for every host with no A record"
fi
