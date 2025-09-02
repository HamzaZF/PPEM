#!/bin/bash
# Download pre-generated proving key for PPEM
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PROVING_KEY_URL="${PPEM_PROVING_KEY_URL:-https://your-storage.com/ppem/stark_verify_final.zkey}"
PROVING_KEY_SHA256="${PPEM_PROVING_KEY_SHA256:-YOUR_SHA256_HASH_HERE}"
PROVING_KEY_SIZE="3.6G"
TARGET_PATH="circom/stark_verify_final.zkey"

echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo -e "${BLUE}   PPEM Proving Key Downloader             ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════${NC}"
echo ""

# Check if already exists
if [ -f "$TARGET_PATH" ]; then
    echo -e "${YELLOW}Proving key already exists at $TARGET_PATH${NC}"
    echo "Verifying integrity..."
    
    if command -v sha256sum &> /dev/null; then
        CURRENT_SHA=$(sha256sum "$TARGET_PATH" | cut -d' ' -f1)
        if [ "$CURRENT_SHA" = "$PROVING_KEY_SHA256" ]; then
            echo -e "${GREEN}✓ Proving key is valid${NC}"
            exit 0
        else
            echo -e "${RED}✗ Proving key checksum mismatch${NC}"
            echo "Expected: $PROVING_KEY_SHA256"
            echo "Got:      $CURRENT_SHA"
            read -p "Re-download? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
fi

echo -e "${YELLOW}This will download a ${PROVING_KEY_SIZE} file${NC}"
echo "URL: $PROVING_KEY_URL"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Download cancelled"
    exit 0
fi

# Create directory if needed
mkdir -p circom

# Download with progress
echo -e "\n${YELLOW}Downloading proving key...${NC}"
if command -v wget &> /dev/null; then
    wget -O "$TARGET_PATH.tmp" --show-progress "$PROVING_KEY_URL"
elif command -v curl &> /dev/null; then
    curl -L -o "$TARGET_PATH.tmp" --progress-bar "$PROVING_KEY_URL"
else
    echo -e "${RED}Error: Neither wget nor curl found${NC}"
    exit 1
fi

# Verify checksum
if [ -n "$PROVING_KEY_SHA256" ] && [ "$PROVING_KEY_SHA256" != "YOUR_SHA256_HASH_HERE" ]; then
    echo -e "\n${YELLOW}Verifying checksum...${NC}"
    DOWNLOADED_SHA=$(sha256sum "$TARGET_PATH.tmp" | cut -d' ' -f1)
    if [ "$DOWNLOADED_SHA" != "$PROVING_KEY_SHA256" ]; then
        echo -e "${RED}✗ Checksum verification failed${NC}"
        echo "Expected: $PROVING_KEY_SHA256"
        echo "Got:      $DOWNLOADED_SHA"
        rm -f "$TARGET_PATH.tmp"
        exit 1
    fi
    echo -e "${GREEN}✓ Checksum verified${NC}"
fi

# Move to final location
mv "$TARGET_PATH.tmp" "$TARGET_PATH"

echo -e "\n${GREEN}✓ Proving key downloaded successfully!${NC}"
echo "Location: $TARGET_PATH"
echo "Size: $(du -h $TARGET_PATH | cut -f1)"

# Note for the user
echo ""
echo -e "${YELLOW}Note:${NC} For production use, consider:"
echo "  1. Participating in a new trusted setup ceremony"
echo "  2. Verifying the proving key's provenance"
echo "  3. Using Git LFS to track this file"