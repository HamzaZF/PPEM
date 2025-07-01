# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 09:54:12
**Total Participants:** 10
**Total Execution Time:** 5m15.1479298s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 4m44.7070761s | ✅ Complete |
| Registration | 18.2765888s | ✅ Complete |
| Auction | 12.0222464s | ✅ Complete |
| Receiving | 11.0265ms | ✅ Complete |
| **TOTAL** | **5m15.1479298s** | ✅ **Complete** |

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
