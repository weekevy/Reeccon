#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
RESET='\033[0m'

function banner() {
    echo ""
    echo "  netdom v0.1"
    echo "  weekeyv/github"
}


function show_help() {
    banner
    echo "  Usage: netdom [MODULE]"
    echo ""
    echo -e "${YELLOW}  Modules${RESET}"
    echo ""

    echo "  passive       passive recon using variouse tools"
    echo "  active        active subdomains enumuration (brute force)"
    echo "  level         extract subdomain by level"

    echo ""
    echo ""
    exit 0
    echo "" 
}
echo ""

function show_module_error() {
    banner
    echo ""
    echo -e "${YELLOW}  Modules${RESET}"

    echo "  passive       passive recon using variouse tools"
    echo "  active        active subdomains enumuration (brute force)"
    echo "  level         extract subdomain by level"

    echo ""
    echo -e "  ${BOLD}no module selected ${RESET}"
    echo "  -h, --help     show help message"
    echo ""
    exit 1
}

if [[ $# -eq 0 ]]; then
    show_module_error
elif [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
fi

MODULE="$1"
shift

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_PATH="$SCRIPT_DIR/modules/${MODULE}.sh"

function main() {
    if [[ -f "$MODULE_PATH" ]]; then
        # Pass ALL remaining arguments after shift
        bash "$MODULE_PATH" "$@"
    else
        banner
        echo ""
        echo "Error: Module '$MODULE' does not exist."
        echo ""
        echo "Available modules:"
        echo "  passive"
        echo "  active"
        echo "  level"
        exit 1
    fi
}

main "$@"
