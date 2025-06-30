# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 00:59:44
**Total Participants:** 10
**Total Execution Time:** 2m0.2486175s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 1m49.6570626s | ✅ Complete |
| Registration | 6.0017056s | ✅ Complete |
| Auction | 4.5653546s | ✅ Complete |
| Receiving | 12.4482ms | ✅ Complete |
| **TOTAL** | **2m0.2486175s** | ✅ **Complete** |

## Ledger Summary

- **Total Transactions:** 51
- **Commitments:** 51
- **Serial Numbers:** 51

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
