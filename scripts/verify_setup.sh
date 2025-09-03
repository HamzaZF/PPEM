#!/bin/bash
# Verify that all components are properly installed
set -e

# Source common utilities
source "$(dirname "$0")/common.sh"

print_section "Verifying PPEM setup"

# Verify core tools
verify_core_tools
core_errors=$?

# Verify project binaries  
verify_project_binaries
project_errors=$?

echo "$(printf '%.0s─' $(seq 1 40))"

total_errors=$((core_errors + project_errors))

if [ $total_errors -eq 0 ]; then
    print_status "success" "All checks passed!"
    exit 0
else
    print_status "error" "$total_errors errors found. Please run ./scripts/setup.sh to fix them."
    exit 1
fi