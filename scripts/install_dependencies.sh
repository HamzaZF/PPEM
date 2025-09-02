#!/bin/bash
# Complete system dependencies installation script
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Version requirements
GO_MIN_VERSION="1.21"
NODE_MIN_VERSION="16"
RUST_MIN_VERSION="1.70"
SNARKJS_VERSION="0.7.3"
CIRCOM_VERSION="2.1.6"

echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}   PPEM System Dependencies Installer      ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo ""

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

# Version comparison
version_ge() {
    [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# Install system packages
install_system_packages() {
    echo -e "\n${YELLOW}Installing system packages...${NC}"
    
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
            echo -e "${RED}Unsupported OS. Please install dependencies manually.${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${GREEN}✓ System packages installed${NC}"
}

# Install Go
install_go() {
    echo -e "\n${YELLOW}Checking Go installation...${NC}"
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        if version_ge "$GO_VERSION" "$GO_MIN_VERSION"; then
            echo -e "${GREEN}✓ Go $GO_VERSION already installed${NC}"
            return
        else
            echo "Go version $GO_VERSION is too old (need >= $GO_MIN_VERSION)"
        fi
    fi
    
    echo "Installing Go..."
    GO_VERSION="1.23.3"
    GO_FILE="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    
    wget "https://go.dev/dl/${GO_FILE}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "${GO_FILE}"
    rm "${GO_FILE}"
    
    # Add to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    
    echo -e "${GREEN}✓ Go ${GO_VERSION} installed${NC}"
}

# Install Rust
install_rust() {
    echo -e "\n${YELLOW}Checking Rust installation...${NC}"
    
    if command -v cargo &> /dev/null; then
        RUST_VERSION=$(rustc --version | awk '{print $2}')
        if version_ge "$RUST_VERSION" "$RUST_MIN_VERSION"; then
            echo -e "${GREEN}✓ Rust $RUST_VERSION already installed${NC}"
            return
        fi
    fi
    
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
    echo -e "${GREEN}✓ Rust installed${NC}"
}

# Install Node.js
install_nodejs() {
    echo -e "\n${YELLOW}Checking Node.js installation...${NC}"
    
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version | sed 's/v//' | cut -d. -f1)
        if [ "$NODE_VERSION" -ge "$NODE_MIN_VERSION" ]; then
            echo -e "${GREEN}✓ Node.js $(node --version) already installed${NC}"
            return
        fi
    fi
    
    echo "Installing Node.js..."
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
    
    echo -e "${GREEN}✓ Node.js installed${NC}"
}

# Install Circom
install_circom() {
    echo -e "\n${YELLOW}Checking Circom installation...${NC}"
    
    if command -v circom &> /dev/null; then
        echo -e "${GREEN}✓ Circom already installed${NC}"
        return
    fi
    
    echo "Installing Circom..."
    CIRCOM_FILE="circom-${OS}-${ARCH}"
    curl -L "https://github.com/iden3/circom/releases/download/v${CIRCOM_VERSION}/${CIRCOM_FILE}" -o circom
    chmod +x circom
    sudo mv circom /usr/local/bin/
    
    echo -e "${GREEN}✓ Circom ${CIRCOM_VERSION} installed${NC}"
}

# Install SnarkJS
install_snarkjs() {
    echo -e "\n${YELLOW}Checking SnarkJS installation...${NC}"
    
    if command -v snarkjs &> /dev/null; then
        echo -e "${GREEN}✓ SnarkJS already installed${NC}"
        return
    fi
    
    echo "Installing SnarkJS..."
    npm install -g snarkjs@${SNARKJS_VERSION}
    
    echo -e "${GREEN}✓ SnarkJS ${SNARKJS_VERSION} installed${NC}"
}

# Setup Git LFS
setup_git_lfs() {
    echo -e "\n${YELLOW}Setting up Git LFS...${NC}"
    
    git lfs install
    
    echo -e "${GREEN}✓ Git LFS configured${NC}"
}

# Verify installation
verify_installation() {
    echo -e "\n${BLUE}Verifying installation...${NC}"
    echo "------------------------"
    
    ERRORS=0
    
    # Check each tool
    check_tool() {
        if command -v "$1" &> /dev/null; then
            echo -e "${GREEN}✓${NC} $1: $($1 --version 2>&1 | head -n1)"
        else
            echo -e "${RED}✗${NC} $1 not found"
            ERRORS=$((ERRORS + 1))
        fi
    }
    
    check_tool "go"
    check_tool "cargo"
    check_tool "node"
    check_tool "npm"
    check_tool "circom"
    check_tool "snarkjs"
    check_tool "git"
    check_tool "make"
    check_tool "cmake"
    
    echo "------------------------"
    
    if [ $ERRORS -eq 0 ]; then
        echo -e "${GREEN}All dependencies installed successfully!${NC}"
        return 0
    else
        echo -e "${RED}$ERRORS dependencies missing or failed to install${NC}"
        return 1
    fi
}

# Main installation flow
main() {
    detect_os
    detect_arch
    
    echo -e "\n${BLUE}This will install:${NC}"
    echo "• System packages (build tools, libraries)"
    echo "• Go ${GO_MIN_VERSION}+"
    echo "• Rust/Cargo ${RUST_MIN_VERSION}+"
    echo "• Node.js ${NODE_MIN_VERSION}+"
    echo "• Circom ${CIRCOM_VERSION}"
    echo "• SnarkJS ${SNARKJS_VERSION}"
    echo ""
    
    read -p "Continue with installation? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled"
        exit 0
    fi
    
    install_system_packages
    install_go
    install_rust
    install_nodejs
    install_circom
    install_snarkjs
    setup_git_lfs
    
    echo ""
    verify_installation
    
    echo -e "\n${GREEN}═══════════════════════════════════════════${NC}"
    echo -e "${GREEN}   Installation Complete!                   ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Reload your shell: source ~/.bashrc"
    echo "2. Run setup: ./scripts/setup.sh"
    echo "3. Build the project: go build -o ppem ./cmd/ppem"
}

# Run main
main "$@"