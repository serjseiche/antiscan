#!/usr/bin/env bash

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

REPO="serjseiche/antiscan"
BINARY_NAME="antiscan-simple"
INSTALL_DIR="/usr/local/bin"
LATEST_RELEASE_URL="https://github.com/${REPO}/releases/latest/download"
DEV_MODE=false

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Must be run as root (use sudo)"
        exit 1
    fi
}

detect_system() {
    local os=""
    local arch=""

    case "$(uname -s)" in
        Linux*)
            os="linux"
            ;;
        *)
            log_error "Unsupported OS: $(uname -s). Only Linux is supported."
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        i386|i686)
            arch="386"
            ;;
        armv7l|armv6l)
            arch="arm"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

get_latest_release_tag() {
    local api_url="https://api.github.com/repos/${REPO}/releases"

    if [ "$DEV_MODE" = true ]; then
        log_info "DEV mode: fetching latest release (including pre-releases)..."
        api_url="${api_url}?per_page=1"
    else
        api_url="${api_url}/latest"
    fi

    local raw=""
    if command -v curl &> /dev/null; then
        raw=$(curl -fsSL "${api_url}")
    elif command -v wget &> /dev/null; then
        raw=$(wget -qO- "${api_url}")
    else
        log_error "Neither curl nor wget found. Install one of them and retry."
        exit 1
    fi

    local tag=""
    # Prefer jq for robust JSON parsing; fall back to grep/sed.
    if command -v jq &> /dev/null; then
        # DEV_MODE returns an array; latest returns an object.
        if [ "$DEV_MODE" = true ]; then
            tag=$(echo "$raw" | jq -r '.[0].tag_name // empty' 2>/dev/null)
        else
            tag=$(echo "$raw" | jq -r '.tag_name // empty' 2>/dev/null)
        fi
    else
        tag=$(echo "$raw" | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/"tag_name": *"\(.*\)"/\1/')
    fi

    if [ -z "$tag" ]; then
        log_error "Could not determine release version"
        exit 1
    fi

    echo "$tag"
}

download_binary() {
    local platform=$1
    local temp_file=$2
    local download_url=""

    if [ "$DEV_MODE" = true ]; then
        local tag
        tag=$(get_latest_release_tag)
        log_info "Found version: ${tag}"
        download_url="https://github.com/${REPO}/releases/download/${tag}/${BINARY_NAME}-${platform}"
    else
        download_url="${LATEST_RELEASE_URL}/${BINARY_NAME}-${platform}"
    fi

    log_info "Downloading ${BINARY_NAME} for ${platform}..."
    log_info "URL: ${download_url}"

    if command -v curl &> /dev/null; then
        if ! curl -fsSL "${download_url}" -o "${temp_file}"; then
            log_error "Download failed"
            exit 1
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q "${download_url}" -O "${temp_file}"; then
            log_error "Download failed"
            exit 1
        fi
    else
        log_error "Neither curl nor wget found. Install one of them and retry."
        exit 1
    fi
}

install_binary() {
    local temp_file=$1
    local install_path="${INSTALL_DIR}/${BINARY_NAME}"

    log_info "Installing to ${install_path}..."

    mkdir -p "${INSTALL_DIR}"
    cp "${temp_file}" "${install_path}"
    chmod +x "${install_path}"

    log_info "Installation complete"
}

verify_installation() {
    local install_path="${INSTALL_DIR}/${BINARY_NAME}"
    if [ -x "${install_path}" ]; then
        local version
        version=$("${install_path}" --version 2>&1 | head -n1)
        log_info "${BINARY_NAME} installed successfully"
        log_info "Version: ${version}"
        log_info "Path:    ${install_path}"
        return 0
    else
        log_error "Installation verification failed"
        return 1
    fi
}

show_usage() {
    log_info ""
    log_info "IMPORTANT: specify one or more blocklist URLs with the -u flag"
    echo "" >&2
    log_info "Public lists are available at:"
    echo "  https://github.com/shadow-netlab/traffic-guard-lists/tree/main" >&2
    log_info "Full usage:"
    echo "" >&2
    echo "  ${BINARY_NAME} --help" >&2
    echo "" >&2
}

show_help() {
    echo "Usage: $0 [OPTIONS]" >&2
    echo "" >&2
    echo "Options:" >&2
    echo "  --dev       Install the latest release (including pre-releases)" >&2
    echo "  --help      Show this help" >&2
    echo "" >&2
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dev)
                DEV_MODE=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage." >&2
                exit 1
                ;;
        esac
    done
}

main() {
    parse_args "$@"

    log_info "=== Installing antiscan-simple ==="
    if [ "$DEV_MODE" = true ]; then
        log_warn "DEV mode: installing latest version (including pre-releases)"
    fi
    echo "" >&2

    check_root

    local platform
    platform=$(detect_system)
    log_info "Detected platform: ${platform}"

    # Create a unique temp file and guarantee cleanup on any exit.
    local temp_file
    temp_file=$(mktemp /tmp/antiscan-simple.XXXXXX)
    trap 'rm -f "$temp_file"' EXIT

    download_binary "${platform}" "${temp_file}"
    install_binary "${temp_file}"

    if verify_installation; then
        echo "" >&2
        show_usage
        exit 0
    else
        exit 1
    fi
}

main "$@"
