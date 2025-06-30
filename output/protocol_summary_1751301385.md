# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 00:36:25
**Total Participants:** 10
**Total Execution Time:** 1m15.4486273s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 1m8.0241171s | ✅ Complete |
| Registration | 6.9679089s | ✅ Complete |
| Auction | 431.0458ms | ✅ Complete |
| Receiving | 4.1088ms | ✅ Complete |
| **TOTAL** | **1m15.4486273s** | ✅ **Complete** |

## Ledger Summary

- **Total Transactions:** 10
- **Commitments:** 10
- **Serial Numbers:** 10

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
