# PPEM - Privacy-Preserving Energy Market

A cryptographic protocol implementing sealed-bid double auctions with zero-knowledge proofs for energy trading applications.

## Overview

PPEM implements a five-phase protocol enabling participants to submit encrypted energy buy/sell orders, execute privacy-preserving auctions, and maintain transaction privacy through multiple zero-knowledge proof systems. The system combines Groth16 SNARKs, RISC Zero STARKs, and Circom circuits to provide comprehensive privacy and verification guarantees.

## Architecture

### Core Components

- **Go Implementation (11K+ lines)** - Main protocol orchestration and transaction processing
- **RISC Zero zkVM** - Auction computation verification using STARKs
- **Circom Circuits** - STARK proof verification and conversion to Groth16
- **gnark Framework** - Zero-knowledge proof generation using BW6-761 curve
- **RapidSNARK** - Optimized Groth16 proof generation

### Protocol Phases

**Phase 1: Setup**
- Cryptographic circuit compilation with caching support
- Participant key generation (DH + ECDH keypairs)
- Ledger initialization with base note commitments

**Phase 2: Registration**
- Encrypted order submission using ElGamal encryption
- Zero-knowledge proofs of order validity (9,679 constraints)
- Transaction commitment to public ledger

**Phase 3: Exchange**
- Order decryption by auctioneer
- Double auction execution with uniform marginal clearing
- RISC Zero STARK proof generation (auction correctness)
- Circom circuit verification (25,749 inputs)
- Groth16 proof generation for succinct verification

**Phase 4: Finalization**
- Transaction commitment and ledger closure
- Auction result export (graphs, JSON data)
- Protocol state persistence

**Phase 5: Withdrawal**
- Emergency fund recovery mechanism
- Zero-knowledge proofs of note ownership (6,364 constraints)

## System Requirements

### Hardware Requirements
- **CPU**: 8+ cores (x86_64 architecture)
- **Memory**: 32GB RAM minimum (64GB recommended for large participant sets)
- **Storage**: 100GB available disk space
- **Network**: Enhanced networking capabilities for distributed deployments

### Software Dependencies
- **Operating System**: Ubuntu 22.04 LTS, CentOS 8+, or macOS 12+
- **Go**: Version 1.21 or higher
- **Rust**: Version 1.70 or higher (with Cargo)
- **Node.js**: Version 16 or higher
- **System Libraries**: build-essential, cmake, libgmp-dev, nlohmann-json3-dev, nasm
- **Git**: With Git LFS support for large files

## Installation

```bash
# Clone repository with LFS support
git lfs install
git clone <repository-url>
cd PPEM

# Install all system dependencies (Go, Rust, Node.js, Circom, SnarkJS, system packages)
./scripts/install_dependencies.sh

# Complete setup process (builds binaries, downloads proving keys)
./scripts/setup.sh

# Verify installation
./scripts/verify_setup.sh
```

### Installation Components

The automated installation process handles:
- **System packages**: build-essential, cmake, cryptographic libraries
- **Programming languages**: Go 1.21+, Rust 1.70+, Node.js 16+
- **ZK tools**: Circom 2.1.6, SnarkJS 0.7.3
- **Binary compilation**: STARK verifier (142MB), RapidSNARK prover (500KB)
- **Cryptographic assets**: Proving key download (3.6GB)
- **RISC Zero build**: Host program compilation

## Configuration

Tool configuration is automatically generated during setup. The `ppem.config.json` file contains:
```json
{
  "cargo_path": "/path/to/cargo",
  "circom_path": "/path/to/circom",
  "stark_verify_path": "./circom/stark_verify",
  "prover_path": "./circom/prover",
  "node_path": "/path/to/node",
  "snarkjs_path": "/path/to/snarkjs",
  "python_path": "/path/to/python3",
  "risc0_dir": "./risc0",
  "circom_dir": "./circom"
}
```

To regenerate the configuration:
```bash
./scripts/generate_config.sh
```

## Usage

### Basic Operation

**Standard Auction Execution:**
```bash
./ppem -scenario scenarios/auction_scenario_N10.json
```

**With Emergency Withdrawals:**
```bash
./ppem -scenario scenarios/auction_scenario_N10.json -withdraw-all
```

**Selective Participant Withdrawal:**
```bash
./ppem -scenario scenarios/auction_scenario_N10.json -withdraw-list "0,2,5"
```

**Debug Mode:**
```bash
./ppem -scenario scenarios/auction_scenario_N10.json -verbosity debug
```

### Scenario Generation

**Generate Custom Scenarios:**
```bash
# Generate scenario with N participants (50% buyers, 50% sellers)
python3 generate_auction_scenario.py 10

# Save to specific location
python3 generate_auction_scenario.py 8 --output scenarios/custom_scenario_N8.json

# Generate with custom name and seed for reproducibility
python3 generate_auction_scenario.py 15 --name "Test_Scenario_15" --seed 12345
```

### Command Line Options

- `-scenario FILE` - Auction scenario JSON file (required)
- `-verbosity LEVEL` - Output verbosity (quiet, info, debug, trace)
- `-withdraw-all` - Enable withdrawal for all participants
- `-withdraw-list IDS` - Comma-separated participant IDs for withdrawal

## Binary Dependencies

### Core Binaries
- **ppem** - Main application binary
- **circom/stark_verify** (142MB) - STARK proof verifier compiled from Circom
- **circom/prover** (500KB) - RapidSNARK Groth16 prover
- **circom/stark_verify_final.zkey** (3.6GB) - Trusted setup proving key
- **risc0/target/release/host** - RISC Zero host execution binary

### Runtime Generated Files
- **circom/input.json** - RISC Zero proof data for Circom circuit
- **circom/witness.wtns** - Circuit witness file
- **circom/proof.json, public.json** - Generated Groth16 proofs
- **ledger_final.json** - Complete protocol execution state
- **graphs/*.png** - Supply/demand curve visualizations
- **exchange_data/*.json** - Detailed auction execution results


## Production Deployment

### Optimized Binary Build
```bash
CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o ppem ./cmd/ppem
```

### Distribution Package
```bash
tar -czf ppem-deployment.tar.gz \
  ppem ppem.config.json circom/ risc0/target/release/ scenarios/
```

### Systemd Service Configuration

Create `/etc/systemd/system/ppem.service`:
```ini
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
ReadWritePaths=/var/log/ppem

# Resource limits
MemoryLimit=32G
CPUQuota=800%

[Install]
WantedBy=multi-user.target
```

Enable service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ppem
sudo systemctl start ppem
```

## Troubleshooting

### Common Issues

**Binary not found errors:**
```bash
# Verify tool availability
which go cargo node circom snarkjs

# Regenerate configuration
./scripts/generate_config.sh

# Check binary permissions
chmod +x circom/stark_verify circom/prover
```

**Out of memory errors:**
```bash
# Add swap space
sudo fallocate -l 32G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Verify memory usage
free -h
```

**Circuit compilation failures:**
```bash
# Clear compilation cache
rm -rf .ppem_cache/

# Rebuild with verbose output
./scripts/build_stark_verify.sh

# Check Circom installation
circom --version
```

**RISC Zero execution failures:**
```bash
# Check Rust installation
cargo --version

# Rebuild RISC Zero components
cd risc0
cargo clean
cargo build --release
cd ..

# Test with smaller scenario
./ppem -scenario scenarios/auction_scenario_N5.json -verbosity debug
```

### Performance Optimization

**CPU frequency scaling:**
```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

**Memory settings:**
```bash
echo 1 | sudo tee /proc/sys/vm/overcommit_memory
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
```

**Disk I/O optimization:**
```bash
# Use SSD storage for .ppem_cache/ directory
# Enable filesystem caching for large files
```

### Verification Commands

```bash
# Complete system verification
./scripts/verify_setup.sh

# Test with minimal scenario
./ppem -scenario scenarios/auction_scenario_N5.json

# Check file integrity
ls -lh circom/stark_verify circom/prover circom/stark_verify_final.zkey

# Monitor resource usage during execution
htop & ./ppem -scenario scenarios/auction_scenario_N10.json -verbosity info
```

## Security Considerations

### File Permissions
```bash
# Secure configuration files
chmod 600 ppem.config.json

# Protect cryptographic keys
chmod 400 circom/stark_verify_final.zkey

# Set proper binary permissions
chmod +x circom/stark_verify circom/prover
```

### Key Management
- Generate proving keys from trusted ceremony participants
- Verify SHA-256 checksums of downloaded proving keys
- Use separate keys for development and production environments
- Store private keys in hardware security modules for production

### Network Security
- Restrict network access to essential services only
- Implement TLS for any network communications
- Use proper authentication mechanisms for multi-participant scenarios

## Development and Research Context

PPEM serves as a research implementation demonstrating practical integration of multiple zero-knowledge proof systems for privacy-preserving auction mechanisms. The system showcases advanced cryptographic techniques including:

- **Multi-layer Proof Composition** - RISC Zero STARKs verified through Circom circuits converted to Groth16 SNARKs
- **Privacy-Preserving Computation** - Encrypted bid processing with zero-knowledge correctness proofs
- **Scalable Circuit Architecture** - Dynamic circuit generation supporting variable participant counts
- **Practical ZK Integration** - Real-world coordination of multiple proof systems and cryptographic tools

## License

This project is licensed under the MIT License. See LICENSE.md for details.

## Support

For technical issues, configuration assistance, or research collaboration inquiries, please consult the project repository issue tracker.