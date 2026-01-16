#!/bin/bash
# =============================================================================
# GoTestWAF Multi-WAF Comparison Script
# =============================================================================
# Usage: ./run-waf-tests.sh [options]
# 
# This script runs GoTestWAF against multiple WAF endpoints and generates
# comparative reports.
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
REPORTS_DIR="./reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORKERS=5
SEND_DELAY=100
TIMEOUT=30

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -c, --config FILE       Configuration file with WAF targets
    -u, --url URL           Single URL to test
    -o, --output DIR        Output directory for reports (default: ./reports)
    -w, --workers NUM       Number of concurrent workers (default: 5)
    -d, --delay MS          Delay between requests in ms (default: 100)
    -g, --graphql           Enable GraphQL testing
    -r, --grpc              Enable gRPC testing
    -a, --api FILE          OpenAPI spec file/URL
    -h, --help              Show this help message

Examples:
    # Test single WAF
    $0 -u https://app.example.com

    # Test with all protocols
    $0 -u https://app.example.com -g -r

    # Test multiple WAFs from config file
    $0 -c waf-targets.conf

Config file format (waf-targets.conf):
    # name,url,graphql_url,grpc_port
    cloudflare,https://cf.example.com,https://cf.example.com/graphql,443
    akamai,https://akamai.example.com,,
    imperva,https://imperva.example.com,https://imperva.example.com/graphql,

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -u|--url)
                SINGLE_URL="$2"
                shift 2
                ;;
            -o|--output)
                REPORTS_DIR="$2"
                shift 2
                ;;
            -w|--workers)
                WORKERS="$2"
                shift 2
                ;;
            -d|--delay)
                SEND_DELAY="$2"
                shift 2
                ;;
            -g|--graphql)
                ENABLE_GRAPHQL=true
                shift
                ;;
            -r|--grpc)
                ENABLE_GRPC=true
                shift
                ;;
            -a|--api)
                OPENAPI_FILE="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_msg $RED "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Run GoTestWAF against a single target
run_gotestwaf() {
    local name=$1
    local url=$2
    local graphql_url=$3
    local grpc_port=$4
    local report_path="${REPORTS_DIR}/${TIMESTAMP}/${name}"
    
    mkdir -p "$report_path"
    
    print_msg $BLUE "================================================"
    print_msg $BLUE "Testing: $name"
    print_msg $BLUE "URL: $url"
    print_msg $BLUE "================================================"
    
    # Build GoTestWAF command
    local cmd="docker run --rm --network host"
    cmd+=" -v $(pwd)/${report_path}:/reports"
    cmd+=" wallarm/gotestwaf"
    cmd+=" --url $url"
    cmd+=" --workers $WORKERS"
    cmd+=" --sendDelay $SEND_DELAY"
    cmd+=" --reportFormat html,json"
    cmd+=" --reportPath /reports"
    
    # Add GraphQL if specified
    if [[ -n "$graphql_url" ]]; then
        cmd+=" --graphqlURL $graphql_url"
        print_msg $YELLOW "  GraphQL: $graphql_url"
    fi
    
    # Add gRPC if specified
    if [[ -n "$grpc_port" ]]; then
        cmd+=" --grpcPort $grpc_port"
        print_msg $YELLOW "  gRPC Port: $grpc_port"
    fi
    
    # Add OpenAPI spec if specified
    if [[ -n "$OPENAPI_FILE" ]]; then
        cmd+=" --openapiFile $OPENAPI_FILE"
        print_msg $YELLOW "  OpenAPI: $OPENAPI_FILE"
    fi
    
    print_msg $GREEN "Running tests..."
    echo "Command: $cmd"
    echo ""
    
    # Run the test
    if eval $cmd; then
        print_msg $GREEN "✓ Completed: $name"
    else
        print_msg $RED "✗ Failed: $name"
    fi
    
    echo ""
}

# Process config file
process_config() {
    local config_file=$1
    
    if [[ ! -f "$config_file" ]]; then
        print_msg $RED "Config file not found: $config_file"
        exit 1
    fi
    
    while IFS=',' read -r name url graphql_url grpc_port || [[ -n "$name" ]]; do
        # Skip comments and empty lines
        [[ "$name" =~ ^#.*$ ]] && continue
        [[ -z "$name" ]] && continue
        
        # Trim whitespace
        name=$(echo "$name" | xargs)
        url=$(echo "$url" | xargs)
        graphql_url=$(echo "$graphql_url" | xargs)
        grpc_port=$(echo "$grpc_port" | xargs)
        
        run_gotestwaf "$name" "$url" "$graphql_url" "$grpc_port"
    done < "$config_file"
}

# Generate comparison summary
generate_summary() {
    local summary_file="${REPORTS_DIR}/${TIMESTAMP}/summary.md"
    
    print_msg $BLUE "Generating comparison summary..."
    
    cat > "$summary_file" << EOF
# WAF Comparison Report

**Generated:** $(date)
**Test Run ID:** $TIMESTAMP

## Test Configuration

- Workers: $WORKERS
- Send Delay: ${SEND_DELAY}ms

## Results

| WAF | Blocked | Bypassed | Unresolved | Score |
|-----|---------|----------|------------|-------|
EOF

    # Parse JSON reports and add to summary
    for report_dir in "${REPORTS_DIR}/${TIMESTAMP}"/*/; do
        if [[ -d "$report_dir" ]]; then
            local waf_name=$(basename "$report_dir")
            local json_report=$(find "$report_dir" -name "*.json" | head -1)
            
            if [[ -f "$json_report" ]]; then
                # Extract stats using jq if available, otherwise show placeholder
                if command -v jq &> /dev/null; then
                    local blocked=$(jq -r '.summary.true_positive // "N/A"' "$json_report" 2>/dev/null || echo "N/A")
                    local bypassed=$(jq -r '.summary.true_negative // "N/A"' "$json_report" 2>/dev/null || echo "N/A")
                    local unresolved=$(jq -r '.summary.unresolved // "N/A"' "$json_report" 2>/dev/null || echo "N/A")
                    local score=$(jq -r '.summary.score // "N/A"' "$json_report" 2>/dev/null || echo "N/A")
                else
                    local blocked="See Report"
                    local bypassed="See Report"
                    local unresolved="See Report"
                    local score="See Report"
                fi
                
                echo "| $waf_name | $blocked | $bypassed | $unresolved | $score |" >> "$summary_file"
            fi
        fi
    done
    
    cat >> "$summary_file" << EOF

## Report Locations

EOF

    for report_dir in "${REPORTS_DIR}/${TIMESTAMP}"/*/; do
        if [[ -d "$report_dir" ]]; then
            local waf_name=$(basename "$report_dir")
            echo "- **${waf_name}:** \`${report_dir}\`" >> "$summary_file"
        fi
    done
    
    print_msg $GREEN "Summary saved to: $summary_file"
}

# Main execution
main() {
    parse_args "$@"
    
    # Create reports directory
    mkdir -p "${REPORTS_DIR}/${TIMESTAMP}"
    
    print_msg $GREEN "=========================================="
    print_msg $GREEN "GoTestWAF Multi-WAF Comparison"
    print_msg $GREEN "=========================================="
    print_msg $YELLOW "Reports will be saved to: ${REPORTS_DIR}/${TIMESTAMP}"
    echo ""
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        print_msg $RED "Docker is required but not installed."
        exit 1
    fi
    
    # Run tests
    if [[ -n "$CONFIG_FILE" ]]; then
        process_config "$CONFIG_FILE"
    elif [[ -n "$SINGLE_URL" ]]; then
        local graphql_url=""
        local grpc_port=""
        
        [[ "$ENABLE_GRAPHQL" == true ]] && graphql_url="${SINGLE_URL}/graphql"
        [[ "$ENABLE_GRPC" == true ]] && grpc_port="50051"
        
        run_gotestwaf "single-target" "$SINGLE_URL" "$graphql_url" "$grpc_port"
    else
        print_msg $RED "No target specified. Use -u URL or -c CONFIG_FILE"
        show_usage
        exit 1
    fi
    
    # Generate summary
    generate_summary
    
    print_msg $GREEN "=========================================="
    print_msg $GREEN "Testing complete!"
    print_msg $GREEN "Reports: ${REPORTS_DIR}/${TIMESTAMP}"
    print_msg $GREEN "=========================================="
}

main "$@"
