# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 09:35:52
**Total Participants:** 10
**Total Execution Time:** 4m31.7245236s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 4m2.0412768s | ✅ Complete |
| Registration | 18.6994938s | ✅ Complete |
| Auction | 10.9430194s | ✅ Complete |
| Receiving | 12.4012ms | ✅ Complete |
| **TOTAL** | **4m31.7245236s** | ✅ **Complete** |

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
