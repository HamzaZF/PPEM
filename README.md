# PPEM - Privacy-Preserving Energy Market

A cryptographic protocol for running privacy-preserving double auctions using zero-knowledge proofs.

## What It Does

PPEM implements a 5-phase protocol where participants can:
- Submit encrypted energy buy/sell orders
- Execute sealed-bid double auctions
- Maintain transaction privacy via zero-knowledge proofs
- Verify auction integrity using RISC Zero STARKs

**Core Technologies:**
- **Go** - Protocol implementation (11K+ lines)
- **Groth16 SNARKs** - Transaction privacy (BW6-761 curve)
- **RISC Zero** - Auction computation verification
- **gnark** - Zero-knowledge proof framework

## Quick Start

### Prerequisites
- Linux/macOS with 16GB+ RAM
- 10GB disk space
- Docker (recommended) OR system dependencies

### Option 1: Docker (Recommended)
```bash
git clone <repo>
cd PPEM
docker-compose up -d
```

### Option 2: Local Build
```bash
# Install dependencies
./scripts/install_dependencies.sh

# Setup project (builds binaries, downloads proving keys)
./scripts/setup.sh

# Build and run protocol
go build -o ppem ./cmd/ppem
./ppem -scenario scenarios/auction_scenario_N10.json
```

## Protocol Phases

1. **Setup** - Circuit compilation, key generation
2. **Registration** - Encrypted order submission 
3. **Exchange** - Auction execution + RISC Zero proof
4. **Finalization** - Ledger commitment
5. **Withdrawal** - Emergency fund recovery

## Configuration

Configure tool paths in `ppem.config.json`:
```json
{
  "stark_verify_path": "./circom/stark_verify",
  "prover_path": "./circom/prover", 
  "snarkjs_path": "snarkjs",
  "circom_dir": "./circom"
}
```

Override via environment:
```bash
export PPEM_STARK_VERIFY_PATH=/usr/local/bin/stark_verify
export PPEM_PROVER_PATH=/usr/local/bin/prover
```

## Usage Examples

```bash
# Run with existing scenario
./ppem -scenario scenarios/auction_scenario_N10.json

# Enable withdrawal simulation
./ppem -scenario scenarios/auction_scenario_N10.json -withdraw-all

# Verbose output
./ppem -scenario scenarios/auction_scenario_N10.json -verbosity debug
```

## Development

### Architecture
- `cmd/ppem/` - Main application
- `internal/transactions/` - Protocol phases (register, exchange, withdraw)  
- `internal/zerocash/` - Cryptographic primitives
- `risc0/` - RISC Zero integration
- `circom/` - Circuit binaries and proving keys

### Testing
```bash
go test ./...
./scripts/test_risc0_integration.sh
```

### Generate Auction Scenarios

Create custom auction scenarios using the Python generator:

```bash
# Generate scenario for 10 participants (50% buyers)
python3 generate_auction_scenario.py 10

# Generate scenario with custom buyer ratio
python3 generate_auction_scenario.py 15 --buyer-ratio 0.6

# Save to custom location
python3 generate_auction_scenario.py 8 > scenarios/my_scenario_N8.json

# Run with generated scenario
./ppem -scenario scenarios/auction_scenario_N15.json
```

**Available scenarios:**
- `scenarios/auction_scenario_N10.json` - 10 participants, 5 buyers/5 sellers
- `scenarios/auction_scenario_N15.json` - 15 participants, realistic market conditions

## Binary Dependencies

The protocol requires several compiled binaries:

| Binary | Size | Purpose |
|--------|------|---------|
| `circom/stark_verify` | 142MB | STARK verifier (from Circom) |
| `circom/prover` | 500KB | RapidSNARK Groth16 prover |
| `circom/stark_verify_final.zkey` | 3.6GB | Proving key |

**Note:** These are automatically built/downloaded by `./scripts/setup.sh`

## Circuit Constraints

- **Transaction Circuit:** 10,658 constraints
- **Registration Circuit:** 9,679 constraints  
- **Exchange Circuit:** Variable (depends on participant count)
- **Withdrawal Circuit:** 6,364 constraints

## Security Model

- **Privacy:** Individual orders and balances are encrypted
- **Integrity:** RISC Zero STARKs verify auction computation
- **Trust:** Auctioneer is trusted for auction logic (limitation)
- **Recovery:** Emergency withdrawal for participant protection

## Troubleshooting

**"stark_verify: command not found"**
```bash
./scripts/build_stark_verify.sh
chmod +x circom/stark_verify
```

**"Out of memory during compilation"**
- Close other applications
- Use machine with 32GB+ RAM
- Add swap space

**"Missing proving key"**
```bash
./scripts/download_proving_key.sh
# OR generate from scratch (requires 32GB+ RAM):
./scripts/generate_proving_key.sh
```

## Research Context

This is a research implementation of privacy-preserving auction protocols. Key papers:
- Zerocash: Decentralized Anonymous Payments
- RISC Zero: A Zero-Knowledge Virtual Machine
- gnark: A Fast zk-SNARK Library

## License

[Add license information]