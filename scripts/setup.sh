#!/bin/bash
# Main setup script for PPEM-Final
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     PPEM-Final Setup Script            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Parse arguments
INTERACTIVE=false
SKIP_DEPS=false
SKIP_PROVING_KEY=false

for arg in "$@"; do
    case $arg in
        --interactive) INTERACTIVE=true ;;
        --skip-deps) SKIP_DEPS=true ;;
        --skip-proving-key) SKIP_PROVING_KEY=true ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --interactive      Run in interactive mode"
            echo "  --skip-deps       Skip dependency installation"
            echo "  --skip-proving-key Skip proving key generation"
            echo "  --help            Show this help"
            exit 0
            ;;
    esac
done

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to ask yes/no
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

# Step 1: Check dependencies
echo -e "${YELLOW}Step 1: Checking dependencies...${NC}"
missing_deps=()

if ! command_exists git; then missing_deps+=("git"); fi
if ! command_exists make; then missing_deps+=("make/build-essential"); fi
if ! command_exists cmake; then missing_deps+=("cmake"); fi
if ! command_exists node; then missing_deps+=("nodejs"); fi
if ! command_exists npm; then missing_deps+=("npm"); fi
if ! command_exists cargo; then missing_deps+=("rust/cargo"); fi

if [ ${#missing_deps[@]} -ne 0 ]; then
    echo -e "${RED}Missing dependencies: ${missing_deps[*]}${NC}"
    if [ "$SKIP_DEPS" = false ]; then
        if [ "$INTERACTIVE" = true ]; then
            if ask_yes_no "Install missing dependencies?" "y"; then
                ./scripts/install_dependencies.sh
            fi
        else
            echo "Run './scripts/install_dependencies.sh' to install them"
            exit 1
        fi
    fi
else
    echo -e "${GREEN}✓ All system dependencies found${NC}"
fi

# Step 2: Install Circom
echo -e "\n${YELLOW}Step 2: Installing Circom...${NC}"
if command_exists circom; then
    echo -e "${GREEN}✓ Circom already installed${NC}"
else
    if [ "$INTERACTIVE" = true ]; then
        if ask_yes_no "Install Circom?" "y"; then
            ./scripts/install_circom.sh
        fi
    else
        ./scripts/install_circom.sh
    fi
fi

# Step 3: Install SnarkJS
echo -e "\n${YELLOW}Step 3: Installing SnarkJS...${NC}"
if command_exists snarkjs; then
    echo -e "${GREEN}✓ SnarkJS already installed${NC}"
else
    echo "Installing SnarkJS globally..."
    npm install -g snarkjs
fi

# Step 4: Build stark_verify
echo -e "\n${YELLOW}Step 4: Building stark_verify binary...${NC}"
if [ -f "circom/stark_verify" ]; then
    if [ "$INTERACTIVE" = true ]; then
        if ask_yes_no "stark_verify exists. Rebuild?" "n"; then
            ./scripts/build_stark_verify.sh
        fi
    else
        echo -e "${GREEN}✓ stark_verify already exists${NC}"
    fi
else
    ./scripts/build_stark_verify.sh
fi

# Step 5: Build RapidSNARK prover
echo -e "\n${YELLOW}Step 5: Building RapidSNARK prover...${NC}"
if [ -f "circom/prover" ]; then
    if [ "$INTERACTIVE" = true ]; then
        if ask_yes_no "prover exists. Rebuild?" "n"; then
            ./scripts/build_rapidsnark.sh
        fi
    else
        echo -e "${GREEN}✓ prover already exists${NC}"
    fi
else
    ./scripts/build_rapidsnark.sh
fi

# Step 6: Handle proving key
echo -e "\n${YELLOW}Step 6: Setting up proving key...${NC}"
if [ -f "circom/stark_verify_final.zkey" ]; then
    echo -e "${GREEN}✓ Proving key already exists${NC}"
elif [ "$SKIP_PROVING_KEY" = false ]; then
    echo "The proving key (3.6GB) is required for the system to work."
    echo "Options:"
    echo "  1) Download pre-generated key (faster, ~3.6GB download)"
    echo "  2) Generate from scratch (slower, requires 32GB+ RAM)"
    echo "  3) Skip for now (system won't be fully functional)"
    
    if [ "$INTERACTIVE" = true ]; then
        read -p "Choose option [1/2/3]: " -r choice
        case $choice in
            1) ./scripts/download_proving_key.sh ;;
            2) ./scripts/generate_proving_key.sh ;;
            3) echo -e "${YELLOW}⚠ Skipping proving key. Run setup again to generate it.${NC}" ;;
            *) echo -e "${YELLOW}⚠ Invalid choice. Skipping.${NC}" ;;
        esac
    else
        echo -e "${YELLOW}Downloading pre-generated proving key...${NC}"
        ./scripts/download_proving_key.sh
    fi
fi

# Step 7: Build RISC Zero
echo -e "\n${YELLOW}Step 7: Building RISC Zero components...${NC}"
cd risc0
cargo build --release
cd ..
echo -e "${GREEN}✓ RISC Zero built successfully${NC}"

# Step 8: Verification
echo -e "\n${YELLOW}Step 8: Verifying setup...${NC}"
./scripts/verify_setup.sh

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     Setup Complete! 🎉                 ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo "You can now run the PPEM system:"
echo "  ./ppem"
echo ""
echo "For testing:"
echo "  ./scripts/test_risc0_integration.sh"