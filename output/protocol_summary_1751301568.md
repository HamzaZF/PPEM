# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 00:39:28
**Total Participants:** 10
**Total Execution Time:** 1m5.3913498s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 59.0640928s | ✅ Complete |
| Registration | 5.9332398s | ✅ Complete |
| Auction | 379.6828ms | ✅ Complete |
| Receiving | 2.7829ms | ✅ Complete |
| **TOTAL** | **1m5.3913498s** | ✅ **Complete** |

## Ledger Summary

- **Total Transactions:** 20
- **Commitments:** 20
- **Serial Numbers:** 20

## Privacy Guarantees

✅ **Bidders' Anonymity:** Identity protected through zero-knowledge proofs
✅ **Bidders' Confidentiality:** Bids encrypted and never revealed
✅ **Winners' Anonymity:** Winners unlinkable to original identities
✅ **Winners' Confidentiality:** Amounts hidden via commitments
✅ **Non-Repudiation:** Cryptographic proofs prevent denial
✅ **Integrity:** Zero-knowledge proofs ensure correctness

## Technical Details

- **Cryptographic Library:** Gnark (Go)
- **Elliptic Curve:** BLS12-377 / BW6-761
- **Proof System:** Groth16
- **Hash Function:** MiMC
- **Auction Type:** Sealed-Bid Exchange Mechanism (SBExM)
