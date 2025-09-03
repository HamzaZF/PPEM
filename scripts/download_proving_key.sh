#!/bin/bash
# Download pre-generated proving key for PPEM
set -e

# Source common utilities
source "$(dirname "$0")/common.sh"

# Configuration
PROVING_KEY_URL="${PPEM_PROVING_KEY_URL:-https://your-storage.com/ppem/stark_verify_final.zkey}"
PROVING_KEY_SHA256="${PPEM_PROVING_KEY_SHA256:-YOUR_SHA256_HASH_HERE}"
PROVING_KEY_SIZE="3.6G"
TARGET_PATH="$CIRCOM_DIR/stark_verify_final.zkey"

print_completion "PPEM Proving Key Downloader"

# Check if already exists
if [ -f "$TARGET_PATH" ]; then
    print_status "warning" "Proving key already exists at $TARGET_PATH"
    print_status "info" "Verifying integrity..."
    
    if verify_checksum "$TARGET_PATH" "$PROVING_KEY_SHA256"; then
        exit 0
    else
        if ! ask_yes_no "Re-download?"; then
            exit 1
        fi
    fi
fi

print_status "warning" "This will download a ${PROVING_KEY_SIZE} file"
echo "URL: $PROVING_KEY_URL"
echo ""
if ! ask_yes_no "Continue?"; then
    echo "Download cancelled"
    exit 0
fi

# Create directory if needed
mkdir -p "$CIRCOM_DIR"

# Download with progress
print_status "info" "Downloading proving key..."
if ! download_file "$PROVING_KEY_URL" "$TARGET_PATH"; then
    exit 1
fi

# Verify checksum
if ! verify_checksum "$TARGET_PATH" "$PROVING_KEY_SHA256"; then
    rm -f "$TARGET_PATH"
    exit 1
fi

print_status "success" "Proving key downloaded successfully!"
echo "Location: $TARGET_PATH"
echo "Size: $(get_file_size "$TARGET_PATH")"

# Note for the user
echo ""
print_status "info" "For production use, consider:"
echo "  1. Participating in a new trusted setup ceremony"
echo "  2. Verifying the proving key's provenance"
echo "  3. Using Git LFS to track this file"