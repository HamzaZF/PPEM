# Privacy-Preserving Auction Protocol - Execution Report

**Execution Date:** 2025-07-01 00:54:15
**Total Participants:** 10
**Total Execution Time:** 2m1.3920038s

## Performance Metrics

| Phase | Duration | Status |
|-------|----------|--------|
| Setup | 1m50.7265956s | ✅ Complete |
| Registration | 6.0067368s | ✅ Complete |
| Auction | 4.638192s | ✅ Complete |
| Receiving | 3.255ms | ✅ Complete |
| **TOTAL** | **2m1.3920038s** | ✅ **Complete** |

## Ledger Summary

- **Total Transactions:** 40
- **Commitments:** 40
- **Serial Numbers:** 40

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
