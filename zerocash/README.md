# Zerocash Confidential Transaction Protocol (Go Implementation)

This package implements a research-grade, production-quality confidential transaction protocol inspired by [Zerocash](https://zerocash-project.org/media/pdf/zerocash-extended-20140518.pdf), using modern Go (1.22+), the standard library, and [gnark-crypto](https://github.com/Consensys/gnark-crypto) for zero-knowledge proofs and cryptography.

## Protocol Overview

- **Confidentiality:** Transaction values and recipients are hidden using commitments and zero-knowledge proofs (Groth16, BW6-761).
- **Unlinkability:** Notes are randomized and unlinkable; serial numbers prevent double-spending.
- **P2P Scenario:** Participants exchange public keys, perform a DH key exchange, and transfer confidential notes over a REST API.
- **Ledger:** All transactions are recorded in an append-only, persistent ledger (JSON file).

## Security Model

- **Cryptography:**
  - MiMC hash for commitments and PRFs
  - BLS12-377 for Diffie-Hellman key exchange
  - Groth16 (BW6-761) for zero-knowledge proofs
  - All randomness from `crypto/rand`
- **Double-Spend Prevention:** Serial numbers are unique per note and checked on the ledger.
- **Key Management:** Proving and verifying keys are generated once and loaded by all participants.

## File/Module Structure

- `types.go` — Core types (`Gamma`, `Params`)
- `note.go` — Note type and creation logic
- `crypto.go` — Cryptographic primitives, DH, MiMC, note encryption
- `tx.go` — Transaction creation, ZKP proof/verify, note encryption for circuit
- `ledger.go` — Persistent, append-only ledger (JSON)
- `api.go` — REST API, participant orchestration, endpoints
- `doc.go` — Package-level documentation
- `zerocash_test.go` — Comprehensive tests for all protocol logic

## API Usage & Example Scenario

### Running the Demo

1. **Start Bob (receiver):**
   ```sh
   go run main.go -name Bob -port 8081
   ```
2. **Start Alice (sender):**
   ```sh
   go run main.go -name Alice -port 8080 -peer localhost:8081 -coins 100 -energy 50
   ```
3. **Observe:**
   - Alice fetches Bob's public key, creates a confidential note, and sends it to Bob.
   - Bob recognizes and decrypts his note, appends the transaction to his ledger, and logs the received value.

### REST Endpoints

- `GET /pubkey` — Returns the participant's public key (hex-encoded BLS12-377 G1Affine)
- `POST /tx` — Submits a confidential transaction (ZKP-verified, note encrypted)

### Example: Sending a Transaction

See `main.go` for a minimal orchestrator. All cryptographic and protocol logic is encapsulated in the `zerocash` package.

## Security Notes & Best Practices

- **All randomness is cryptographically secure.**
- **All ZKP keys must be generated and distributed securely.**
- **Ledger is append-only but not thread-safe by itself; use a mutex for concurrent access.**
- **All REST endpoints validate input and handle errors securely.**
- **This implementation is for research and educational purposes.**

## References

- Zerocash: Decentralized Anonymous Payments from Bitcoin ([Ben-Sasson et al., 2014](https://zerocash-project.org/media/pdf/zerocash-extended-20140518.pdf))
- [gnark-crypto](https://github.com/Consensys/gnark-crypto) (BLS12-377, MiMC, Groth16)
- Go standard library (`net/http`, `crypto/rand`, etc.)

## Running Tests

Run all protocol tests:
```sh
go test ./zerocash -v
```

## Production Caveats

- This code is designed for clarity, modularity, and security, but is not audited for production use.
- Use with caution in real-world deployments; review all cryptographic and protocol assumptions.
- For production, consider:
  - Secure key distribution and management
  - Persistent, tamper-evident ledger storage
  - Rate limiting, authentication, and logging middleware for REST endpoints
  - Regular security audits and code reviews

## Features
- Confidential note creation and transfer
- Serial number and commitment generation
- MiMC-based cryptography
- Groth16 zkSNARK circuit (via gnark)
- Clean, idiomatic Go API

## Usage

```
go get ./zerocash

import "yourmodule/zerocash"

// Create and verify a transaction
oldNote := ... // *zerocash.Note
oldSk := ...   // []byte
newOwnerPk := ... // []byte
value := ...   // *big.Int
energy := ...  // *big.Int
params := &zerocash.Params{}

// Create a transaction
zTx, err := zerocash.CreateTx(oldNote, oldSk, newOwnerPk, value, energy, params)
if err != nil {
    // handle error
}

// Verify a transaction
err = zerocash.VerifyTx(zTx, params)
if err != nil {
    // handle error
}
```

## License
See project root. 