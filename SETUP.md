# 🚨 IMPORTANT: Setup Required Before First Use

This project requires building cryptographic binaries from source. The repository includes precompiled binaries for x86_64 Linux, but **you should rebuild them for your architecture and security**.

## Quick Start (Automated)

```bash
# Run the automated setup script
./scripts/setup.sh

# Or if you prefer step-by-step:
./scripts/setup.sh --interactive
```

## What Gets Built

1. **`circom/stark_verify`** (142MB) - STARK proof verifier compiled from Circom
2. **`circom/prover`** (500KB) - RapidSNARK Groth16 prover
3. **`circom/stark_verify_final.zkey`** (3.6GB) - Proving key (downloaded/generated)

## Prerequisites

### System Requirements
- **OS**: Linux or macOS (Windows via WSL2)
- **RAM**: Minimum 16GB (32GB recommended for proving key generation)
- **Disk**: ~10GB free space
- **Architecture**: x86_64 or ARM64

### Required Software
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libgmp-dev \
    nlohmann-json3-dev \
    nasm \
    git \
    curl \
    nodejs \
    npm

# macOS
brew install cmake gmp nlohmann-json nasm node

# Install Rust (for RISC Zero)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

## Manual Build Instructions

### Step 1: Install Circom
```bash
# Download Circom (adjust version/architecture as needed)
curl -L https://github.com/iden3/circom/releases/download/v2.1.6/circom-linux-amd64 -o circom
chmod +x circom
sudo mv circom /usr/local/bin/
```

### Step 2: Install SnarkJS
```bash
npm install -g snarkjs
```

### Step 3: Build stark_verify Binary
```bash
# Compile Circom to C++
circom risc0/stark_verify.circom --c --output circom/

# Build the witness generator
cd circom/stark_verify_cpp
make
mv stark_verify ../stark_verify
cd ../..
```

### Step 4: Build RapidSNARK Prover
```bash
# Clone and build RapidSNARK
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark
npm install
git submodule init && git submodule update
./build_gmp.sh
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../package
make -j$(nproc)
make install
cp ../package/bin/prover ../../circom/prover
cd ../..
rm -rf rapidsnark  # Clean up
```

### Step 5: Generate/Download Proving Key
```bash
# Option A: Download pre-generated key (faster, ~3.6GB)
./scripts/download_proving_key.sh

# Option B: Generate from scratch (slower, more secure)
./scripts/generate_proving_key.sh
```

## Verification

After setup, verify everything works:
```bash
./scripts/verify_setup.sh
```

Expected output:
```
✓ circom installed
✓ snarkjs installed  
✓ stark_verify binary exists (142MB)
✓ prover binary exists (500KB)
✓ proving key exists (3.6GB)
✓ RISC Zero builds successfully
✓ Test proof generation works
```

## Troubleshooting

### ARM/M1 Mac Issues
Add `--no_asm` flag when compiling Circom:
```bash
circom risc0/stark_verify.circom --c --no_asm --output circom/
```

### Out of Memory During Compilation
The stark_verify circuit is large (56MB). If compilation fails:
1. Close other applications
2. Increase swap space
3. Use a machine with more RAM (32GB+ recommended)

### Missing Dependencies
Run the dependency check:
```bash
./scripts/check_dependencies.sh
```

## Docker Alternative

If you prefer containerized deployment:
```bash
docker build -t ppem-final .
docker run -it ppem-final
```

## Security Notes

⚠️ **The precompiled binaries in this repo are for convenience only**. For production use:
1. Always rebuild from source
2. Verify the Circom circuits
3. Consider participating in a new trusted setup ceremony
4. Audit the proving key generation

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/PPEM-Final/issues)
- **Documentation**: See [docs/](./docs/) directory
- **Circuit Details**: [risc0/README.md](./risc0/README.md)

---
*Last updated: September 2025*