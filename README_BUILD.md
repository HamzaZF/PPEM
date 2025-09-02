# PPEM-Final: Privacy-Preserving Energy Market

## ⚠️ Important: First-Time Setup Required

**This project requires building cryptographic binaries from source.** The included precompiled binaries are for x86_64 Linux only.

### Quick Setup
```bash
# Automated setup (recommended)
./scripts/setup.sh

# Or follow the detailed guide
cat SETUP.md
```

## Project Overview

PPEM-Final implements a privacy-preserving double auction system for energy markets using zero-knowledge proofs. It combines:

- **RISC Zero**: STARK-based zkVM for auction computation
- **Circom/SnarkJS**: STARK-to-SNARK conversion bridge  
- **Gnark**: Recursive proof verification in Go
- **RapidSNARK**: High-performance Groth16 prover

## Architecture

```
Auction Data → RISC Zero (STARK) → Circom Bridge → Groth16 (SNARK) → Gnark Verification
```

## Binary Files Explanation

| File | Size | Purpose | Source |
|------|------|---------|--------|
| `circom/stark_verify` | 142MB | STARK verifier compiled from Circom | Built from `risc0/stark_verify.circom` |
| `circom/prover` | 500KB | RapidSNARK Groth16 prover | From [iden3/rapidsnark](https://github.com/iden3/rapidsnark) |
| `circom/stark_verify_final.zkey` | 3.6GB | Proving key | Generated via trusted setup |

## Building from Source

### Prerequisites
- Go 1.21+
- Rust/Cargo (stable)
- Node.js 16+ & npm
- CMake, GCC/Clang
- 16GB+ RAM (32GB for proving key generation)

### Full Build Process
```bash
# 1. Install dependencies
./scripts/install_dependencies.sh

# 2. Build all components
./scripts/setup.sh

# 3. Verify installation
./scripts/verify_setup.sh
```

## Running the System

```bash
# Build main binary
go build -o ppem ./cmd/ppem

# Run with sample data
./ppem

# Test RISC Zero integration
./scripts/test_risc0_integration.sh
```

## Docker Deployment

```bash
# Build Docker image
docker build -t ppem-final .

# Run container
docker run -it ppem-final
```

## Security Considerations

1. **Always rebuild binaries from source for production**
2. **The proving key requires a trusted setup ceremony**
3. **Verify all dependencies and audit the circuits**

## Troubleshooting

### Common Issues

**"stark_verify: command not found"**
- Run: `./scripts/build_stark_verify.sh`

**"Out of memory" during compilation**
- The circuit is large (56MB). Use a machine with 32GB+ RAM
- Or use precompiled binaries for testing only

**ARM/M1 Mac compatibility**
- Add `--no_asm` flag when building Circom circuits
- See `SETUP.md` for details

## Repository Structure

```
.
├── risc0/                 # RISC Zero STARK prover
│   ├── stark_verify.circom   # STARK verifier circuit (56MB)
│   └── risc0.circom          # Helper templates
├── circom/                # Circom working directory  
│   ├── stark_verify*         # Generated binaries
│   └── *.zkey                # Proving/verification keys
├── internal/              # Go implementation
│   ├── risc0/               # RISC Zero integration
│   └── transactions/        # Auction logic
└── scripts/               # Build and setup scripts
    ├── setup.sh             # Main setup script
    └── verify_setup.sh      # Verification script
```

## Contributing

1. Fork the repository
2. Build from source (don't commit binaries)
3. Test with `./scripts/test_risc0_integration.sh`
4. Submit PR with clear description

## License

[Your License Here]

## Support

- **Setup Issues**: See [SETUP.md](./SETUP.md)
- **Bug Reports**: [GitHub Issues](https://github.com/HamzaZf/PPEM-Final/issues)
- **Documentation**: [docs/](./docs/)