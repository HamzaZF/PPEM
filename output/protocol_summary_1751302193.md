# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 00:49:53
**Total Participants:** 10
**Total Execution Time:** 2m0.7423902s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 1m49.2247684s | ✅ Complete |
| Registration | 6.7393235s | ✅ Complete |
| Auction | 4.7631707s | ✅ Complete |
| Receiving | 2.5319ms | ✅ Complete |
| **TOTAL** | **2m0.7423902s** | ✅ **Complete** |

## Ledger Summary

- **Total Transactions:** 30
- **Commitments:** 30
- **Serial Numbers:** 30

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
