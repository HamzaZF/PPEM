# Withdraw Circuit and Logic

## Circuit: `CircuitWithdraw`
- **Public Inputs:**
  - `SnIn`: Serial number of input note
  - `CmOut`: Commitment of output note
  - `PkT`: Auctioneer's public key
  - `CipherAux`: Registration ciphertext
- **Private Inputs:**
  - `SkIn`: Participant's secret key
  - `B`: Registration randomness
  - `NIn`: Input note (coins, energy, pk, rho, r, cm)
  - `NOut`: Output note (coins, energy, pk, rho, r, cm)

## Constraints
1. `SnIn = PRF(SkIn, NIn.RhoIn)`
2. `CmOut = Com(NOut.Coins, NOut.Energy, NOut.PkOut, NOut.RhoOut, NOut.ROut)`
3. `CipherAux = EncWithdrawMimc(NOut.PkOut, SkIn, B, PkT)`

## Integration
- Used in the withdraw protocol if the auctioneer fails to perform the exchange.
- Proof is generated using Groth16 and verified by the ledger before appending the transaction. 