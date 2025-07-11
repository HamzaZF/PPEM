package withdraw

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

type CircuitWithdraw struct {
	// Public (Instance: x = (sn^in, cm^out, pk_T, C_i))
	SnIn      frontend.Variable    `gnark:",public"`
	CmOut     frontend.Variable    `gnark:",public"`
	PkT       sw_bls12377.G1Affine `gnark:",public"`
	CipherAux [5]frontend.Variable `gnark:",public"` // C_i = (pk^out, sk^in, bid, coins, energy) - same as registration

	// Private (Witness: w = (n_i^in, n_i^out, sk_i^in, b_i))
	SkIn frontend.Variable // sk_i^in
	Bid  frontend.Variable // b_i (bid value)

	// Shared secret (computed during registration, not recomputed here)
	SharedSecret sw_bls12377.G1Affine // sharedKey from registration DH computation

	// Input note n_i^in = (Γ^in, pk^in, ρ^in, r^in, cm^in)
	NIn struct {
		Coins  frontend.Variable // Γ^in.coins
		Energy frontend.Variable // Γ^in.energy
		PkIn   frontend.Variable // pk^in
		RhoIn  frontend.Variable // ρ^in
		RIn    frontend.Variable // r^in
		CmIn   frontend.Variable // cm^in
	}

	// Output note n_i^out = (Γ^out, pk^out, ρ^out, r^out, cm^out)
	NOut struct {
		Coins  frontend.Variable // Γ^out.coins
		Energy frontend.Variable // Γ^out.energy
		PkOut  frontend.Variable // pk^out
		RhoOut frontend.Variable // ρ^out
		ROut   frontend.Variable // r^out
		CmOut  frontend.Variable // cm^out
	}
}

func (c *CircuitWithdraw) Define(api frontend.API) error {
	// Algorithm 4 Statement Verification:

	// (1) Serial number: sn^in = PRF_{sk^in}(n^in.seed())
	snComputed := PRF(api, c.SkIn, c.NIn.RhoIn)
	api.AssertIsEqual(c.SnIn, snComputed)

	// (2) Output commitment: cm^out = Com(Γ^out || pk^out || ρ^out, r^out)
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(c.NOut.Coins)  // Γ^out.coins
	hasher.Write(c.NOut.Energy) // Γ^out.energy
	hasher.Write(c.NOut.PkOut)  // pk^out
	hasher.Write(c.NOut.RhoOut) // ρ^out
	hasher.Write(c.NOut.ROut)   // r^out
	cmComputed := hasher.Sum()
	api.AssertIsEqual(c.CmOut, cmComputed)

	// (3) Ciphertext: C_i = DH-OTP(sharedSecret, (pk^out, sk^in, bid, coins, energy)) - same as registration!
	encVal := EncWithdrawMimc(api, c.Bid, c.SkIn, c.NOut.PkOut, c.NOut.Coins, c.NOut.Energy, c.SharedSecret)
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(c.CipherAux[i], encVal[i])
	}

	return nil
}

// PRF for serial number (MiMC-based)
func PRF(api frontend.API, sk, rho frontend.Variable) frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	h.Write(sk)
	h.Write(rho)
	return h.Sum()
}

// EncWithdrawMimc for ciphertext (MiMC-based DH-OTP encryption)
// Encrypts (b_i, sk_i^in, pk_i^out) using DH shared secret (NO r_enc needed)
func EncWithdrawMimc(api frontend.API, bid, skIn, pkOut, coins, energy frontend.Variable, sharedSecret sw_bls12377.G1Affine) [5]frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	// Generate encryption masks using MiMC hash chain with DH shared secret (SAME as registration)
	h.Write(sharedSecret.X)
	h.Write(sharedSecret.Y)
	mask1 := h.Sum()

	h.Reset() // Reset hash before next computation
	h.Write(mask1)
	mask2 := h.Sum()

	h.Reset() // Reset hash before next computation
	h.Write(mask2)
	mask3 := h.Sum()

	h.Reset() // Reset hash before next computation
	h.Write(mask3)
	mask4 := h.Sum()

	h.Reset() // Reset hash before next computation
	h.Write(mask4)
	mask5 := h.Sum()

	// Perform DH-OTP encryption: ciphertext = plaintext + mask
	// SAME encryption as registration: [pkOut, skIn, bid, coins, energy] -> [mask1, mask2, mask3, mask4, mask5]
	pkOut_enc := api.Add(pkOut, mask1)   // pkOut encrypted with mask1 (index 0)
	skIn_enc := api.Add(skIn, mask2)     // skIn encrypted with mask2 (index 1)
	bid_enc := api.Add(bid, mask3)       // bid encrypted with mask3 (index 2)
	coins_enc := api.Add(coins, mask4)   // coins encrypted with mask4 (index 3)
	energy_enc := api.Add(energy, mask5) // energy encrypted with mask5 (index 4)

	return [5]frontend.Variable{pkOut_enc, skIn_enc, bid_enc, coins_enc, energy_enc}
}
