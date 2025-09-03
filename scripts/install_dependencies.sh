#!/bin/bash
# Complete system dependencies installation script
set -e

# Source common utilities
source "$(dirname "$0")/common.sh"

# Parse arguments
AUTO_YES=false

for arg in "$@"; do
    case $arg in
        --auto-yes) AUTO_YES=true ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --auto-yes        Skip confirmation prompt"
            echo "  --help            Show this help"
            exit 0
            ;;
    esac
done

print_completion "PPEM System Dependencies Installer"

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    echo "Detected OS: $OS"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
    esac
    echo "Detected architecture: $ARCH"
}

# Version comparison function now provided by common.sh

# Install system packages
install_system_packages() {
    print_status "info" "Installing system packages..."
    
    case $OS in
        debian)
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                pkg-config \
                libssl-dev \
                libgmp-dev \
                nlohmann-json3-dev \
                nasm \
                git \
                git-lfs \
                curl \
                wget \
                jq
            ;;
        macos)
            # Check if Homebrew is installed
            if ! command -v brew &> /dev/null; then
                echo "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install \
                cmake \
                pkg-config \
                openssl \
                gmp \
                nlohmann-json \
                nasm \
                git \
                git-lfs \
                curl \
                wget \
                jq
            ;;
        arch)
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm \
                base-devel \
                cmake \
                openssl \
                gmp \
                nlohmann-json \
                nasm \
                git \
                git-lfs \
                curl \
                wget \
                jq
            ;;
        *)
            print_status "error" "Unsupported OS. Please install dependencies manually."
            exit 1
            ;;
    esac
    
    print_status "success" "System packages installed"
}

# Install Go
install_go() {
    print_status "info" "Checking Go installation..."
    
    if check_tool_version "go" "$GO_MIN_VERSION"; then
        local version=$(get_tool_version "go")
        print_status "success" "Go $version already installed"
        return
    fi
    
    if command_exists go; then
        local version=$(get_tool_version "go")
        print_status "warning" "Go version $version is too old (need >= $GO_MIN_VERSION)"
    fi
    
    print_status "info" "Installing Go..."
    GO_VERSION="1.23.3"
    GO_FILE="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    
    wget "https://go.dev/dl/${GO_FILE}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${GO_FILE}"
    rm "${GO_FILE}"
    
    # Add to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    
    print_status "success" "Go ${GO_VERSION} installed"
}

# Install Rust
install_rust() {
    print_status "info" "Checking Rust installation..."
    
    if check_tool_version "cargo" "$RUST_MIN_VERSION"; then
        local version=$(get_tool_version "cargo")
        print_status "success" "Rust $version already installed"
        return
    fi
    
    print_status "info" "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
    print_status "success" "Rust installed"
}

# Install Node.js
install_nodejs() {
    print_status "info" "Checking Node.js installation..."
    
    if command_exists node; then
        NODE_VERSION=$(get_tool_version "node" | cut -d. -f1)
        if [ "$NODE_VERSION" -ge "$NODE_MIN_VERSION" ]; then
            print_status "success" "Node.js $(node --version) already installed"
            return
        fi
    fi
    
    print_status "info" "Installing Node.js..."
    if [ "$OS" = "debian" ]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [ "$OS" = "macos" ]; then
        brew install node
    else
        # Use NodeSource universal installer
        curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
        source ~/.bashrc
        nvm install 20
        nvm use 20
    fi
    
    print_status "success" "Node.js installed"
}

# Install Circom
install_circom() {
    print_status "info" "Checking Circom installation..."
    
    if command_exists circom; then
        print_status "success" "Circom already installed"
        return
    fi
    
    print_status "info" "Installing Circom..."
    CIRCOM_FILE="circom-${OS}-${ARCH}"
    curl -L "https://github.com/iden3/circom/releases/download/v${CIRCOM_VERSION}/${CIRCOM_FILE}" -o circom
    chmod +x circom
    sudo mv circom /usr/local/bin/
    
    print_status "success" "Circom ${CIRCOM_VERSION} installed"
}

# Install SnarkJS
install_snarkjs() {
    print_status "info" "Checking SnarkJS installation..."
    
    if command_exists snarkjs; then
        print_status "success" "SnarkJS already installed"
        return
    fi
    
    print_status "info" "Installing SnarkJS..."
    npm install -g snarkjs@${SNARKJS_VERSION}
    
    print_status "success" "SnarkJS ${SNARKJS_VERSION} installed"
}


# Verify installation (now uses shared function)
verify_installation() {
    verify_core_tools
}

# Main installation flow
main() {
    detect_os
    detect_arch
    
    print_status "info" "This will install:"
    echo "• System packages (build tools, libraries)"
    echo "• Go ${GO_MIN_VERSION}+"
    echo "• Rust/Cargo ${RUST_MIN_VERSION}+"
    echo "• Node.js ${NODE_MIN_VERSION}+"
    echo "• Circom ${CIRCOM_VERSION}"
    echo "• SnarkJS ${SNARKJS_VERSION}"
    echo ""
    
    if [ "$AUTO_YES" = false ]; then
        if ! ask_yes_no "Continue with installation?"; then
            echo "Installation cancelled"
            exit 0
        fi
    else
        print_status "info" "Auto-proceeding with installation..."
    fi
    
    install_system_packages
    install_go
    install_rust
    install_nodejs
    install_circom
    install_snarkjs
    
    echo ""
    verify_installation
    
    print_completion "Installation Complete!"
    echo ""
    echo "Next steps:"
    echo "1. Reload your shell: source ~/.bashrc"
    echo "2. Run setup: ./scripts/setup.sh"
}

# Run main
main "$@"