#!/usr/bin/env bash

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

IPSET_NAME="SCANNERS-BLOCK-V4"
IPSET_CONF="/etc/ipset.conf"

log_info()  { echo -e "${GREEN}[INFO]${NC} $1" >&2; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

usage() {
    echo "Usage: $0 <add|remove> <ipv4-address>" >&2
    echo "" >&2
    echo "  add     Block an IPv4 address" >&2
    echo "  remove  Unblock an IPv4 address" >&2
    exit 1
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root (use sudo)"
        exit 1
    fi
}

validate_ipv4() {
    local ip="$1"
    if ! echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        log_error "Invalid IPv4 address: $ip"
        exit 1
    fi
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [ "$octet" -gt 255 ]; then
            log_error "Invalid IPv4 address: $ip (octet $octet out of range)"
            exit 1
        fi
    done
}

if [ "$#" -ne 2 ]; then
    usage
fi

COMMAND="$1"
IP="$2"

check_root

case "$COMMAND" in
    add|remove) ;;
    *) log_error "Unknown command: $COMMAND"; usage ;;
esac

validate_ipv4 "$IP"

if ! ipset list "$IPSET_NAME" &>/dev/null; then
    log_error "ipset '$IPSET_NAME' does not exist — run 'antiscan-simple full' first"
    exit 1
fi

case "$COMMAND" in
    add)
        if ipset test "$IPSET_NAME" "$IP" &>/dev/null; then
            log_warn "$IP is already in $IPSET_NAME"
        else
            ipset add "$IPSET_NAME" "$IP"
            log_info "Added $IP to $IPSET_NAME"
        fi
        ;;
    remove)
        if ! ipset test "$IPSET_NAME" "$IP" &>/dev/null; then
            log_warn "$IP is not in $IPSET_NAME"
        else
            ipset del "$IPSET_NAME" "$IP"
            log_info "Removed $IP from $IPSET_NAME"
        fi
        ;;
esac

ipset save > "$IPSET_CONF"
log_info "Saved ipset configuration to $IPSET_CONF"
