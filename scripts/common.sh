#!/bin/bash
# Common utilities for PPEM scripts
# Source this file in other scripts with: source "$(dirname "$0")/common.sh"

# Color definitions
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export NC='\033[0m'

# Version requirements (centralized)
export GO_MIN_VERSION="1.21"
export NODE_MIN_VERSION="16"
export RUST_MIN_VERSION="1.70"
export SNARKJS_VERSION="0.7.3"
export CIRCOM_VERSION="2.1.6"

# Common paths
export SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export CIRCOM_DIR="$PROJECT_ROOT/circom"
export RISC0_DIR="$PROJECT_ROOT/risc0"

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Find executable path (with fallback)
find_executable() {
    local tool="$1"
    if command_exists "$tool"; then
        command -v "$tool"
    else
        echo "$tool"
    fi
}

# Version comparison helper
version_ge() {
    [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# Get tool version
get_tool_version() {
    local tool="$1"
    case "$tool" in
        "go")
            if command_exists go; then
                go version | awk '{print $3}' | sed 's/go//'
            fi
            ;;
        "cargo"|"rust")
            if command_exists cargo; then
                rustc --version | awk '{print $2}'
            fi
            ;;
        "node")
            if command_exists node; then
                node --version | sed 's/v//'
            fi
            ;;
        "circom")
            if command_exists circom; then
                circom --version 2>&1 | head -n1
            fi
            ;;
        "snarkjs")
            if command_exists snarkjs; then
                # snarkjs --version outputs help text, just return "installed"
                echo "installed"
            fi
            ;;
    esac
}

# Check tool with version requirement
check_tool_version() {
    local tool="$1"
    local min_version="$2"
    local current_version
    
    if ! command_exists "$tool"; then
        return 1
    fi
    
    current_version=$(get_tool_version "$tool")
    if [ -n "$min_version" ] && [ -n "$current_version" ]; then
        version_ge "$current_version" "$min_version"
    else
        true  # Tool exists but version check not applicable
    fi
}

# Print status message with icon
print_status() {
    local status="$1"
    local message="$2"
    case "$status" in
        "success"|"ok")
            echo -e "${GREEN}✓${NC} $message"
            ;;
        "warning"|"warn")
            echo -e "${YELLOW}⚠${NC} $message"
            ;;
        "error"|"fail")
            echo -e "${RED}✗${NC} $message"
            ;;
        "info")
            echo -e "${BLUE}ℹ${NC} $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Check if binary exists and is executable
check_binary() {
    local binary_path="$1"
    local binary_name="${2:-$(basename "$binary_path")}"
    
    if [ -f "$binary_path" ]; then
        local size=$(du -h "$binary_path" 2>/dev/null | cut -f1 || echo "unknown")
        print_status "success" "$binary_name binary exists ($size)"
        
        if [ ! -x "$binary_path" ]; then
            print_status "warning" "$binary_name is not executable, fixing..."
            chmod +x "$binary_path"
        fi
        return 0
    else
        print_status "error" "$binary_name binary not found at $binary_path"
        return 1
    fi
}

# Get file size in human readable format
get_file_size() {
    local file_path="$1"
    if [ -f "$file_path" ]; then
        du -h "$file_path" 2>/dev/null | cut -f1
    else
        echo "0B"
    fi
}

# Verify core PPEM tools are installed
verify_core_tools() {
    local errors=0
    local tools=("git" "make" "cmake" "node" "npm" "cargo" "circom" "snarkjs")
    
    print_status "info" "Verifying core tools..."
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            local version=$(get_tool_version "$tool")
            print_status "success" "$tool: ${version:-installed}"
        else
            print_status "error" "$tool not found"
            errors=$((errors + 1))
        fi
    done
    
    return $errors
}

# Verify PPEM project binaries
verify_project_binaries() {
    local errors=0
    
    print_status "info" "Verifying project binaries..."
    
    # Check stark_verify
    if ! check_binary "$CIRCOM_DIR/stark_verify"; then
        errors=$((errors + 1))
    fi
    
    # Check prover
    if ! check_binary "$CIRCOM_DIR/prover"; then
        errors=$((errors + 1))
    fi
    
    # Check proving key
    if [ -f "$CIRCOM_DIR/stark_verify_final.zkey" ]; then
        local size=$(get_file_size "$CIRCOM_DIR/stark_verify_final.zkey")
        print_status "success" "Proving key exists ($size)"
    else
        print_status "warning" "Proving key not found (optional but recommended)"
    fi
    
    # Check RISC Zero
    if [ -f "$RISC0_DIR/target/release/host" ]; then
        print_status "success" "RISC Zero host binary exists"
    else
        print_status "warning" "RISC Zero not built yet"
    fi
    
    # Check main binary
    if [ -f "$PROJECT_ROOT/ppem" ]; then
        print_status "success" "Main PPEM binary exists"
    else
        print_status "warning" "Main PPEM binary not built"
    fi
    
    return $errors
}

# Download file with progress (wget/curl fallback)
download_file() {
    local url="$1"
    local output_path="$2"
    local temp_path="${output_path}.tmp"
    
    if command_exists wget; then
        wget -O "$temp_path" --show-progress "$url"
    elif command_exists curl; then
        curl -L -o "$temp_path" --progress-bar "$url"
    else
        print_status "error" "Neither wget nor curl found"
        return 1
    fi
    
    mv "$temp_path" "$output_path"
}

# Verify file checksum
verify_checksum() {
    local file_path="$1"
    local expected_sha256="$2"
    
    if [ -z "$expected_sha256" ] || [ "$expected_sha256" = "YOUR_SHA256_HASH_HERE" ]; then
        print_status "warning" "No checksum provided, skipping verification"
        return 0
    fi
    
    if command_exists sha256sum; then
        local actual_sha=$(sha256sum "$file_path" | cut -d' ' -f1)
        if [ "$actual_sha" = "$expected_sha256" ]; then
            print_status "success" "Checksum verified"
            return 0
        else
            print_status "error" "Checksum mismatch"
            echo "Expected: $expected_sha256"
            echo "Got:      $actual_sha"
            return 1
        fi
    else
        print_status "warning" "sha256sum not available, skipping checksum verification"
        return 0
    fi
}

# Ask yes/no question with default
ask_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local REPLY
    
    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi
    
    read -p "$prompt" -r REPLY
    REPLY=${REPLY:-$default}
    [[ "$REPLY" =~ ^[Yy]$ ]]
}

# Print section header
print_section() {
    local title="$1"
    echo ""
    echo -e "${BLUE}${title}${NC}"
    echo "$(printf '%.0s─' $(seq 1 ${#title}))"
}

# Print completion message
print_completion() {
    local title="$1"
    local border_length=${#title}
    local border=$(printf '%.0s═' $(seq 1 $((border_length + 8))))
    
    echo ""
    echo -e "${GREEN}╔${border}╗${NC}"
    echo -e "${GREEN}║    ${title}    ║${NC}"
    echo -e "${GREEN}╚${border}╝${NC}"
}