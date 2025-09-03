#!/bin/bash
# Main setup script for PPEM-Final
set -e

# Source common utilities
source "$(dirname "$0")/common.sh"

print_completion "PPEM-Final Setup Script"

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

# Command exists function now provided by common.sh

# Ask yes/no function now provided by common.sh

# Step 1: Ensure all dependencies are installed
print_section "Step 1: Ensuring dependencies are installed"
if [ "$SKIP_DEPS" = false ]; then
    # Quick check for missing core dependencies
    missing_deps=()
    for tool in git make cmake node npm cargo circom snarkjs; do
        if ! command_exists "$tool"; then
            missing_deps+=("$tool")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_status "warning" "Missing dependencies detected: ${missing_deps[*]}"
        print_status "info" "Running dependency installer..."
        "$SCRIPT_DIR/install_dependencies.sh" --auto-yes
    else
        print_status "success" "All dependencies already installed"
    fi
else
    print_status "warning" "Skipping dependency check (--skip-deps)"
fi

# Step 2: Initialize Git LFS for project
print_section "Step 2: Setting up Git LFS for project"
if git lfs install --local >/dev/null 2>&1; then
    print_status "success" "Git LFS configured for project"
else
    print_status "error" "Git LFS setup failed - may not be installed"
fi

# Step 3: Build stark_verify
print_section "Step 3: Building stark_verify binary"
if [ -f "$CIRCOM_DIR/stark_verify" ]; then
    if [ "$INTERACTIVE" = true ]; then
        if ask_yes_no "stark_verify exists. Rebuild?" "n"; then
            "$SCRIPT_DIR/build_stark_verify.sh"
        fi
    else
        print_status "success" "stark_verify already exists"
    fi
else
    "$SCRIPT_DIR/build_stark_verify.sh"
fi

# Step 4: Build RapidSNARK prover
print_section "Step 4: Building RapidSNARK prover"
if [ -f "$CIRCOM_DIR/prover" ]; then
    if [ "$INTERACTIVE" = true ]; then
        if ask_yes_no "prover exists. Rebuild?" "n"; then
            "$SCRIPT_DIR/build_rapidsnark.sh"
        fi
    else
        print_status "success" "prover already exists"
    fi
else
    "$SCRIPT_DIR/build_rapidsnark.sh"
fi

# Step 5: Handle proving key
print_section "Step 5: Setting up proving key"
if [ -f "$CIRCOM_DIR/stark_verify_final.zkey" ]; then
    print_status "success" "Proving key already exists"
elif [ "$SKIP_PROVING_KEY" = false ]; then
    echo "The proving key (3.6GB) is required for the system to work."
    echo "Options:"
    echo "  1) Download pre-generated key (faster, ~3.6GB download)"
    echo "  2) Generate from scratch (slower, requires 32GB+ RAM)"
    echo "  3) Skip for now (system won't be fully functional)"
    
    if [ "$INTERACTIVE" = true ]; then
        read -p "Choose option [1/2/3]: " -r choice
        case $choice in
            1) "$SCRIPT_DIR/download_proving_key.sh" ;;
            2) "$SCRIPT_DIR/generate_proving_key.sh" ;;
            3) print_status "warning" "Skipping proving key. Run setup again to generate it." ;;
            *) print_status "warning" "Invalid choice. Skipping." ;;
        esac
    else
        print_status "info" "Downloading pre-generated proving key..."
        "$SCRIPT_DIR/download_proving_key.sh"
    fi
fi

# Step 6: Build RISC Zero
print_section "Step 6: Building RISC Zero components"
cd "$RISC0_DIR"
cargo build --release
cd "$PROJECT_ROOT"
print_status "success" "RISC Zero built successfully"

# Step 7: Verification
print_section "Step 7: Verifying setup"
"$SCRIPT_DIR/verify_setup.sh"

print_completion "Setup Complete! 🎉"
echo ""
echo "You can now run the PPEM system:"
echo "  ./ppem"
echo ""
echo "For testing:"
echo "  ./scripts/test_risc0_integration.sh"