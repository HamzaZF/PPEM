#!/bin/bash
# Build stark_verify binary from Circom circuit
set -e

echo "Building stark_verify binary..."

# Check for ARM architecture
if [[ $(uname -m) == "arm64" ]] || [[ $(uname -m) == "aarch64" ]]; then
    echo "Detected ARM architecture, using --no_asm flag"
    EXTRA_FLAGS="--no_asm"
else
    EXTRA_FLAGS=""
fi

# Compile Circom to C++
echo "Compiling stark_verify.circom to C++..."
circom risc0/stark_verify.circom --r1cs --sym --c $EXTRA_FLAGS --output circom/

# Build the witness generator
echo "Building C++ witness generator..."
cd circom/stark_verify_cpp
make -j$(nproc 2>/dev/null || echo 4)

# Move binary to correct location
mv stark_verify ../stark_verify
cd ../..

echo "✓ stark_verify built successfully ($(du -h circom/stark_verify | cut -f1))"