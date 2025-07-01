# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 09:56:19
**Total Participants:** 10
**Total Execution Time:** 4m33.3442176s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 4m15.7126264s | ✅ Complete |
| Registration | 10.6650049s | ✅ Complete |
| Auction | 6.9239094s | ✅ Complete |
| Receiving | 8.6584ms | ✅ Complete |
| **TOTAL** | **4m33.3442176s** | ✅ **Complete** |

## Ledger Summary

- **Total Transactions:** 11
- **Commitments:** 11
- **Serial Numbers:** 11

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
