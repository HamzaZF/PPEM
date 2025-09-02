#!/bin/bash
# Generate ppem.config.json with detected tool paths

set -e

CONFIG_FILE="ppem.config.json"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Generating tool configuration..."

# Function to find executable
find_executable() {
    local tool="$1"
    if command -v "$tool" >/dev/null 2>&1; then
        command -v "$tool"
    else
        echo "$tool"
    fi
}

# Detect paths
CARGO=$(find_executable "cargo")
CIRCOM=$(find_executable "circom")
NODE=$(find_executable "node")
SNARKJS=$(find_executable "snarkjs")
PYTHON=$(find_executable "python3" || find_executable "python")

# Get absolute paths for local binaries
PWD=$(pwd)
STARK_VERIFY="$PWD/circom/stark_verify"
PROVER="$PWD/circom/prover"
RISC0_DIR="$PWD/risc0"
CIRCOM_DIR="$PWD/circom"

# Check if local binaries exist
if [ ! -f "$STARK_VERIFY" ]; then
    echo -e "${YELLOW}Warning: stark_verify not found at $STARK_VERIFY${NC}"
    STARK_VERIFY="./circom/stark_verify"
fi

if [ ! -f "$PROVER" ]; then
    echo -e "${YELLOW}Warning: prover not found at $PROVER${NC}"
    PROVER="./circom/prover"
fi

# Generate JSON config
cat > "$CONFIG_FILE" <<EOF
{
  "cargo_path": "$CARGO",
  "circom_path": "$CIRCOM",
  "stark_verify_path": "$STARK_VERIFY",
  "prover_path": "$PROVER",
  "node_path": "$NODE",
  "snarkjs_path": "$SNARKJS",
  "python_path": "$PYTHON",
  "risc0_dir": "$RISC0_DIR",
  "circom_dir": "$CIRCOM_DIR"
}
EOF

echo -e "${GREEN}✓${NC} Configuration saved to $CONFIG_FILE"
echo ""
echo "Detected tools:"
echo "  Cargo:        $CARGO"
echo "  Circom:       $CIRCOM"
echo "  StarkVerify:  $STARK_VERIFY"
echo "  Prover:       $PROVER"
echo "  Node:         $NODE"
echo "  SnarkJS:      $SNARKJS"
echo "  Python:       $PYTHON"
echo ""
echo "You can edit $CONFIG_FILE to customize paths if needed."