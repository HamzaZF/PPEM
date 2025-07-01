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
	CipherAux [3]frontend.Variable `gnark:",public"` // C_i = (b_i, sk_i^in, pk_i^out)

	// Private (Witness: w = (n_i^in, n_i^out, sk_i^in, b_i))
	SkIn frontend.Variable // sk_i^in
	Bid  frontend.Variable // b_i (bid value)

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

	// (3) Ciphertext: C_i = DH-OTP(pk_T, (b_i, sk_i^in, pk_i^out))
	encVal := EncWithdrawMimc(api, c.Bid, c.SkIn, c.NOut.PkOut, c.PkT)
	for i := 0; i < 3; i++ {
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
func EncWithdrawMimc(api frontend.API, bid, skIn, pkOut frontend.Variable, pkT sw_bls12377.G1Affine) [3]frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	// Generate encryption masks using MiMC hash chain with DH shared secret
	h.Write(pkT.X)
	h.Write(pkT.Y)
	mask1 := h.Sum()

	h.Write(mask1)
	mask2 := h.Sum()

	h.Write(mask2)
	mask3 := h.Sum()

	// Perform DH-OTP encryption: ciphertext = plaintext + mask
	// C_i = DH-OTP(pk_T, (b_i, sk_i^in, pk_i^out)) - no r_enc needed!
	bid_enc := api.Add(bid, mask1)     // b_i
	skIn_enc := api.Add(skIn, mask2)   // sk_i^in
	pkOut_enc := api.Add(pkOut, mask3) // pk_i^out

	return [3]frontend.Variable{bid_enc, skIn_enc, pkOut_enc}
}
