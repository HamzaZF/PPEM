# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 10:14:15
**Total Participants:** 10
**Total Execution Time:** 1m30.585744s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 1m23.3171997s | ✅ Complete |
| Registration | 4.1742005s | ✅ Complete |
| Auction | 3.0804842s | ✅ Complete |
| Receiving | 2.3197ms | ✅ Complete |
| **TOTAL** | **1m30.585744s** | ✅ **Complete** |

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
