# PPEM Deployment Guide

## Overview

PPEM is a privacy-preserving energy market system that requires significant computational resources and specific cryptographic dependencies for production deployment.

## System Requirements

### Hardware Requirements
- **CPU**: 8+ cores (x86_64 or ARM64)
- **Memory**: 32GB RAM minimum (64GB recommended)
- **Storage**: 100GB available disk space
- **Network**: Enhanced networking for cloud deployments

### Software Dependencies
- **Operating System**: Ubuntu 22.04 LTS or CentOS 8+
- **Go**: Version 1.21 or higher
- **Rust**: Version 1.70 or higher
- **Node.js**: Version 16 or higher
- **System packages**: build-essential, cmake, libgmp-dev, nlohmann-json3-dev, nasm

## Installation

### Automated Installation
```bash
# Clone repository
git lfs install
git clone <repository-url>
cd PPEM

# Install system dependencies
./scripts/install_dependencies.sh

# Complete setup process
./scripts/setup.sh
```

### Manual Installation

#### 1. System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake libgmp-dev nlohmann-json3-dev nasm git git-lfs

# RHEL/CentOS
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake gmp-devel json-devel nasm git git-lfs
```

#### 2. Programming Languages
```bash
# Install Go 1.21+
wget https://go.dev/dl/go1.23.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

#### 3. ZK Tools
```bash
# Install Circom
curl -L https://github.com/iden3/circom/releases/download/v2.1.6/circom-linux-amd64 -o circom
chmod +x circom
sudo mv circom /usr/local/bin/

# Install SnarkJS
npm install -g snarkjs@0.7.3
```

#### 4. Build Cryptographic Components
```bash
# Build STARK verifier (30+ minutes)
./scripts/build_stark_verify.sh

# Build RapidSNARK prover
./scripts/build_rapidsnark.sh

# Download proving key (3.4GB)
./scripts/download_proving_key.sh
```

#### 5. Build Application
```bash
# Build RISC Zero components
cd risc0
cargo build --release
cd ..

# Build main application
go build -o ppem ./cmd/ppem

# Verify installation
./scripts/verify_setup.sh
```

## Configuration

### Tool Configuration
Create `ppem.config.json`:
```json
{
  "cargo_path": "cargo",
  "stark_verify_path": "./circom/stark_verify",
  "prover_path": "./circom/prover",
  "snarkjs_path": "snarkjs",
  "risc0_dir": "./risc0",
  "circom_dir": "./circom"
}
```

### Environment Variables
```bash
# Override tool paths if needed
export PPEM_STARK_VERIFY_PATH=/opt/ppem/bin/stark_verify
export PPEM_PROVER_PATH=/opt/ppem/bin/prover
export PPEM_SNARKJS_PATH=/usr/local/bin/snarkjs

# Performance tuning
export RAYON_NUM_THREADS=16
export GOMAXPROCS=16
```

## Production Deployment

### Binary Distribution
```bash
# Build optimized binary
CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o ppem ./cmd/ppem

# Create distribution package
tar -czf ppem-deployment.tar.gz \
  ppem \
  ppem.config.json \
  circom/ \
  risc0/target/release/ \
  scenarios/
```

### Systemd Service
```ini
# /etc/systemd/system/ppem.service
[Unit]
Description=PPEM Privacy-Preserving Energy Market
After=network.target

[Service]
Type=oneshot
User=ppem
Group=ppem
WorkingDirectory=/opt/ppem
ExecStart=/opt/ppem/ppem -scenario /opt/ppem/scenarios/auction_scenario_N10.json
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadOnlyPaths=/opt/ppem
ReadWritePaths=/var/log/ppem

# Resource limits
LimitNOFILE=65536
MemoryLimit=32G
CPUQuota=800%

[Install]
WantedBy=multi-user.target
```

Enable service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ppem
```

### Container Deployment
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential cmake libgmp-dev \
    && rm -rf /var/lib/apt/lists/*

COPY ppem /usr/local/bin/
COPY ppem.config.json /etc/ppem/
COPY circom/ /opt/ppem/circom/
COPY scenarios/ /opt/ppem/scenarios/

WORKDIR /opt/ppem
USER nobody

CMD ["ppem", "-scenario", "scenarios/auction_scenario_N10.json"]
```

## Monitoring and Troubleshooting

### Verification Commands
```bash
# Check system dependencies
./scripts/verify_setup.sh

# Test with small scenario
./ppem -scenario scenarios/auction_scenario_N10.json -verbosity debug

# Check binary sizes and permissions
ls -lh circom/stark_verify circom/prover circom/stark_verify_final.zkey
```

### Common Issues

**Binary not found**
```bash
# Check PATH configuration
which stark_verify prover snarkjs

# Regenerate configuration
./scripts/generate_config.sh
```

**Out of memory errors**
```bash
# Add swap space
sudo fallocate -l 32G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

**Permission denied**
```bash
# Fix binary permissions
chmod +x circom/stark_verify circom/prover
```

### Performance Tuning
```bash
# CPU frequency scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Memory settings
echo 1 | sudo tee /proc/sys/vm/overcommit_memory
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
```

## Security Considerations

### File Permissions
```bash
# Secure configuration files
chmod 600 ppem.config.json

# Protect proving keys
chmod 400 circom/stark_verify_final.zkey

# Set proper ownership
chown -R ppem:ppem /opt/ppem
```

### Network Security
- Restrict network access to essential ports only
- Use TLS for any network communications
- Implement proper authentication for multi-user environments

### Key Management
- Generate proving keys from trusted sources
- Verify checksums of downloaded binaries
- Use separate signing keys for different environments

## File Inventory

### Critical Files (Required)
- `ppem` - Main application binary
- `circom/stark_verify` (142MB) - STARK proof verifier
- `circom/prover` (500KB) - RapidSNARK Groth16 prover
- `circom/stark_verify_final.zkey` (3.4GB) - Proving key
- `risc0/target/release/host` - RISC Zero host binary
- `ppem.config.json` - Tool configuration

### Scenario Files (Required)
- `scenarios/auction_scenario_N10.json` - 10-participant test scenario
- `scenarios/auction_scenario_N15.json` - 15-participant test scenario

### Generated Files (Runtime)
- `circom/input.json` - RISC Zero output for Circom
- `circom/witness.wtns` - Circom witness file
- `circom/proof.json`, `circom/public.json` - Generated proofs
- `ledger_final.json` - Final protocol state
- `graphs/*.png` - Auction visualization outputs
- `exchange_data/*.json` - Detailed auction results

## Support and Maintenance

### Logs and Debugging
```bash
# Enable debug mode
./ppem -scenario scenarios/auction_scenario_N10.json -verbosity debug

# System logs (if using systemd)
journalctl -u ppem -f

# Resource monitoring
htop
iotop
```

### Updates and Maintenance
- Monitor for new releases of core dependencies (Go, Rust, Circom)
- Regenerate proving keys when upgrading cryptographic components
- Test scenario files after any configuration changes
- Backup critical files before system updates

For additional support, consult the project repository issues tracker.