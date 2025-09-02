#!/bin/bash
# Verify that all components are properly installed
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Verifying PPEM setup..."
echo "----------------------"

ERRORS=0

# Check Circom
if command -v circom >/dev/null 2>&1; then
    VERSION=$(circom --version 2>&1 | head -n1)
    echo -e "${GREEN}✓${NC} Circom installed: $VERSION"
else
    echo -e "${RED}✗${NC} Circom not installed"
    ERRORS=$((ERRORS + 1))
fi

# Check SnarkJS
if command -v snarkjs >/dev/null 2>&1; then
    VERSION=$(snarkjs --version 2>&1 || echo "version unknown")
    echo -e "${GREEN}✓${NC} SnarkJS installed: $VERSION"
else
    echo -e "${RED}✗${NC} SnarkJS not installed"
    ERRORS=$((ERRORS + 1))
fi

# Check stark_verify binary
if [ -f "circom/stark_verify" ]; then
    SIZE=$(du -h circom/stark_verify | cut -f1)
    echo -e "${GREEN}✓${NC} stark_verify binary exists ($SIZE)"
    if [ -x "circom/stark_verify" ]; then
        echo -e "${GREEN}✓${NC} stark_verify is executable"
    else
        echo -e "${YELLOW}⚠${NC} stark_verify is not executable, fixing..."
        chmod +x circom/stark_verify
    fi
else
    echo -e "${RED}✗${NC} stark_verify binary not found"
    ERRORS=$((ERRORS + 1))
fi

# Check prover binary
if [ -f "circom/prover" ]; then
    SIZE=$(du -h circom/prover | cut -f1)
    echo -e "${GREEN}✓${NC} prover binary exists ($SIZE)"
    if [ -x "circom/prover" ]; then
        echo -e "${GREEN}✓${NC} prover is executable"
    else
        echo -e "${YELLOW}⚠${NC} prover is not executable, fixing..."
        chmod +x circom/prover
    fi
else
    echo -e "${RED}✗${NC} prover binary not found"
    ERRORS=$((ERRORS + 1))
fi

# Check proving key
if [ -f "circom/stark_verify_final.zkey" ]; then
    SIZE=$(du -h circom/stark_verify_final.zkey | cut -f1)
    echo -e "${GREEN}✓${NC} Proving key exists ($SIZE)"
else
    echo -e "${YELLOW}⚠${NC} Proving key not found (optional but recommended)"
fi

# Check RISC Zero build
if [ -f "risc0/target/release/host" ]; then
    echo -e "${GREEN}✓${NC} RISC Zero host binary exists"
else
    echo -e "${YELLOW}⚠${NC} RISC Zero not built yet"
fi

# Check main binary
if [ -f "ppem" ]; then
    echo -e "${GREEN}✓${NC} Main PPEM binary exists"
else
    echo -e "${YELLOW}⚠${NC} Main PPEM binary not built. Run: go build -o ppem ./cmd/ppem"
fi

echo "----------------------"

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}All checks passed!${NC}"
    exit 0
else
    echo -e "${RED}$ERRORS errors found. Please run ./scripts/setup.sh to fix them.${NC}"
    exit 1
fi