// Package zerocash implements a confidential transaction protocol inspired by Zerocash.
//
// Overview:
//   - Provides confidential, unlinkable transactions using zero-knowledge proofs (Groth16)
//   - All cryptographic and protocol logic is encapsulated in this package
//   - Supports note creation, confidential transfer, persistent ledger, and REST API for P2P scenarios
//
// Security Model:
//   - Uses MiMC hash for commitments and PRFs
//   - Uses BLS12-377 for Diffie-Hellman key exchange
//   - Zero-knowledge proofs are generated and verified using gnark (Groth16, BW6-761)
//   - All randomness is generated using crypto/rand
//   - Serial numbers prevent double-spending; commitments ensure confidentiality
//
// Usage:
//   - Import the package and use NewNote, CreateTx, VerifyTx, NewLedger, etc.
//   - Use NewParticipant and RunServer for REST-based P2P scenarios
//   - See README.md for protocol details and example usage
//
// References:
//   - Zerocash: Decentralized Anonymous Payments from Bitcoin (Ben-Sasson et al., 2014)
//   - https://zerocash-project.org/media/pdf/zerocash-extended-20140518.pdf
//
// WARNING: This package is for research and educational purposes. Use with caution in production environments.
package zerocash
