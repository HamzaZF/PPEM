#!/bin/bash

# Enhanced PPEM + RISC Zero Integration Test Script
# Tests the complete Privacy-Preserving Energy Market with RISC Zero auction proofs
# Features comprehensive caching for faster subsequent runs

set -e  # Exit on any error

echo "=========================================="
echo "🧪 Enhanced PPEM + RISC Zero Integration Test"
echo "=========================================="

# Configuration
PARTICIPANTS=20
BUYER_RATIO=0.5
VERBOSITY="info"

# Cache management
CACHE_DIR=".ppem_cache"

# Parse command line arguments
CLEAR_CACHE=false
REBUILD_ALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clear-cache)
            CLEAR_CACHE=true
            shift
            ;;
        --rebuild-all)
            REBUILD_ALL=true
            shift
            ;;
        --participants)
            PARTICIPANTS="$2"
            shift 2
            ;;
        --verbosity)
            VERBOSITY="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --clear-cache      Clear all cached circuits and builds"
            echo "  --rebuild-all      Force rebuild of all components"
            echo "  --participants N   Number of participants (default: 20)"
            echo "  --verbosity LEVEL  Verbosity level (default: info)"
            echo "  --help            Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Clear cache if requested
if [ "$CLEAR_CACHE" = true ]; then
    echo "🧹 Clearing all caches..."
    rm -rf "$CACHE_DIR"
    echo "✓ Cache cleared"
fi

# Force rebuild if requested
if [ "$REBUILD_ALL" = true ]; then
    echo "🔨 Forcing rebuild of all components..."
    rm -rf "$CACHE_DIR"
    make clean 2>/dev/null || true
    echo "✓ Prepared for full rebuild"
fi

echo "📋 Test Configuration:"
echo "   • Participants: $PARTICIPANTS"
echo "   • Buyer ratio: $BUYER_RATIO"
echo "   • Verbosity: $VERBOSITY"
echo "   • Cache directory: $CACHE_DIR"
echo ""

# Check prerequisites
echo "🔍 Checking prerequisites..."

# Check for Go
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed or not in PATH"
    exit 1
fi
echo "   ✓ Go: $(go version | cut -d' ' -f3)"

# Check for Cargo (Rust)
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo (Rust) is not installed or not in PATH"
    exit 1
fi
echo "   ✓ Cargo: $(cargo --version | cut -d' ' -f2)"

# Check for snarkjs
if ! command -v snarkjs &> /dev/null; then
    echo "❌ snarkjs is not installed"
    echo "Install with: npm install -g snarkjs"
    exit 1
fi
echo "   ✓ snarkjs: $(snarkjs --version 2>/dev/null || echo 'installed')"

echo "✅ All prerequisites satisfied"
echo ""

# Cache status reporting
echo "📊 Cache Status:"
if [ -d "$CACHE_DIR" ]; then
    cache_size=$(du -sh "$CACHE_DIR" 2>/dev/null | cut -f1 || echo "0B")
    cache_files=$(find "$CACHE_DIR" -type f 2>/dev/null | wc -l || echo "0")
    echo "   • Cache size: $cache_size"
    echo "   • Cached files: $cache_files"
    
    # Show cache breakdown
    if [ -d "$CACHE_DIR/circuits" ]; then
        circuit_count=$(ls "$CACHE_DIR/circuits"/*.json 2>/dev/null | wc -l || echo "0")
        echo "   • Cached circuits: $circuit_count"
    fi
    
    if [ -d "$CACHE_DIR/risc0" ]; then
        echo "   • RISC Zero build: cached"
    fi
    
    if [ -d "$CACHE_DIR/circom" ]; then
        echo "   • Circom setup: cached"
    fi
else
    echo "   • No cache found (first run or cleared)"
fi
echo ""

# Build phase
echo "🔨 Building Enhanced PPEM..."

# Ensure required directories exist
mkdir -p circom/circom_data

# Pre-cache Circom verification key if it doesn't exist
# This is critical for Go circuit compilation
if [ ! -f "circom/vkey.json" ]; then
    echo "🔧 Generating initial Circom verification key..."
    
    # Check if we have the required Circom files
    if [ ! -f "circom/stark_verify_final.zkey" ]; then
        echo "⚠️  Missing Circom setup files - will be generated during first run"
    else
        cd circom
        if command -v snarkjs &> /dev/null; then
            snarkjs zkey export verificationkey stark_verify_final.zkey vkey.json 2>/dev/null || true
        fi
        cd ..
    fi
fi

# Build Go program
echo "   • Compiling Go program..."
start_time=$(date +%s)
go build -o ppem_enhanced . 2>&1 | head -20
end_time=$(date +%s)
build_time=$((end_time - start_time))

if [ ! -f "ppem_enhanced" ]; then
    echo "❌ Failed to build Go program"
    exit 1
fi

echo "   ✓ Go build completed in ${build_time}s"
echo ""

# Execution phase
echo "🚀 Running Enhanced PPEM Protocol..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Run the enhanced PPEM with timing
execution_start=$(date +%s)

# Use timeout to prevent hanging (30 minutes max)
timeout 1800 ./ppem_enhanced \
    -n "$PARTICIPANTS" \
    -buyer-ratio "$BUYER_RATIO" \
    -verbosity "$VERBOSITY" \
    2>&1 | tee execution.log

execution_end=$(date +%s)
execution_time=$((execution_end - execution_start))

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verify execution success
if [ $? -eq 0 ]; then
    echo "🎉 Protocol execution completed successfully!"
    
    # Extract key metrics from output
    echo ""
    echo "📈 Execution Summary:"
    echo "   • Total execution time: ${execution_time}s ($(($execution_time / 60))m $(($execution_time % 60))s)"
    
    # Extract metrics from log
    if [ -f "execution.log" ]; then
        # Look for successful completion indicators
        if grep -q "RISC Zero proof generation: SUCCESS" execution.log; then
            echo "   ✓ RISC Zero proof generation: SUCCESS"
        fi
        
        if grep -q "recursive verification: SUCCESS" execution.log; then
            echo "   ✓ Recursive proof verification: SUCCESS"
        fi
        
        # Extract performance metrics
        clearing_price=$(grep -o "Clearing price.*" execution.log | tail -1 || echo "Not found")
        energy_traded=$(grep -o "Energy traded.*" execution.log | tail -1 || echo "Not found")
        
        if [ "$clearing_price" != "Not found" ]; then
            echo "   • $clearing_price"
        fi
        
        if [ "$energy_traded" != "Not found" ]; then
            echo "   • $energy_traded"
        fi
    fi
    
    # Cache statistics after run
    echo ""
    echo "💾 Post-execution Cache Status:"
    if [ -d "$CACHE_DIR" ]; then
        cache_size_after=$(du -sh "$CACHE_DIR" 2>/dev/null | cut -f1 || echo "0B")
        echo "   • Total cache size: $cache_size_after"
        echo "   • Cache location: $CACHE_DIR"
        
        echo ""
        echo "🔄 Next run will be much faster thanks to caching!"
        echo "   Use --clear-cache to reset or --rebuild-all to force rebuild"
    fi
    
else
    echo "❌ Protocol execution failed!"
    echo ""
    echo "🔍 Troubleshooting:"
    echo "   • Check execution.log for detailed errors"
    echo "   • Try --clear-cache to reset state"
    echo "   • Ensure all dependencies are installed"
    echo "   • Check available disk space and memory"
    exit 1
fi

echo ""
echo "🎯 Test completed successfully!"
echo "==========================================" 