# Withdraw Feature

## Overview
The withdraw feature allows participants to reclaim their engaged funds if the auctioneer fails to perform the exchange. It follows the protocol described in the paper and uses a zero-knowledge proof to ensure only the rightful participant can withdraw.

## How to Trigger Withdrawal
- Use the CLI command or REST endpoint `/withdraw`.
- The system will gather the required data from your wallet and submit a withdrawal transaction and proof to the ledger.

## Security Guarantees
- Only the participant with the correct secret key can withdraw to their requested output key.
- The proof ensures the withdrawal is valid and the funds are not double-spent.
- The ledger verifies the proof before appending the transaction. 