#!/bin/bash
# Generate ppem.config.json with detected tool paths

set -e

# Source common utilities
source "$(dirname "$0")/common.sh"

CONFIG_FILE="ppem.config.json"

print_status "info" "Generating tool configuration..."

# Detect paths using shared function
CARGO=$(find_executable "cargo")
CIRCOM=$(find_executable "circom")
NODE=$(find_executable "node")
SNARKJS=$(find_executable "snarkjs")
PYTHON=$(find_executable "python3" || find_executable "python")

# Use centralized paths
STARK_VERIFY="$CIRCOM_DIR/stark_verify"
PROVER="$CIRCOM_DIR/prover"

# Check if local binaries exist
if [ ! -f "$STARK_VERIFY" ]; then
    print_status "warning" "stark_verify not found at $STARK_VERIFY"
    STARK_VERIFY="./circom/stark_verify"
fi

if [ ! -f "$PROVER" ]; then
    print_status "warning" "prover not found at $PROVER"
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

print_status "success" "Configuration saved to $CONFIG_FILE"
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