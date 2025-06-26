package withdraw

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

type CircuitWithdraw struct {
	// Public
	SnIn      frontend.Variable    `gnark:",public"`
	CmOut     frontend.Variable    `gnark:",public"`
	PkT       sw_bls12377.G1Affine `gnark:",public"`
	CipherAux [3]frontend.Variable `gnark:",public"`

	// Private
	SkIn frontend.Variable
	REnc frontend.Variable

	NIn struct {
		Coins  frontend.Variable
		Energy frontend.Variable
		PkIn   frontend.Variable
		RhoIn  frontend.Variable
		RIn    frontend.Variable
		CmIn   frontend.Variable
	}

	NOut struct {
		Coins  frontend.Variable
		Energy frontend.Variable
		PkOut  frontend.Variable
		RhoOut frontend.Variable
		ROut   frontend.Variable
		CmOut  frontend.Variable
	}
}

func (c *CircuitWithdraw) Define(api frontend.API) error {
	// (1) Serial number
	snComputed := PRF(api, c.SkIn, c.NIn.RhoIn)
	api.AssertIsEqual(c.SnIn, snComputed)

	// (2) Commitment: must include PkOut
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(c.NOut.Coins)
	hasher.Write(c.NOut.Energy)
	hasher.Write(c.NOut.PkOut)
	hasher.Write(c.NOut.RhoOut)
	hasher.Write(c.NOut.ROut)
	cmComputed := hasher.Sum()
	api.AssertIsEqual(c.CmOut, cmComputed)

	// (3) Ciphertext: use DH shared secret as key (as in your codebase)
	encVal := EncWithdrawMimc(api, c.NOut.PkOut, c.SkIn, c.REnc, c.PkT)
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

// EncWithdrawMimc for ciphertext (MiMC-based, DH shared secret)
func EncWithdrawMimc(api frontend.API, pkOut, skIn, rEnc frontend.Variable, pkT sw_bls12377.G1Affine) [3]frontend.Variable {
	h, _ := mimc.NewMiMC(api)
	// Use pkT.X, pkT.Y, pkOut, skIn, rEnc as key material
	h.Write(pkT.X)
	h.Write(pkT.Y)
	h.Write(pkOut)
	h.Write(skIn)
	h.Write(rEnc)
	mask1 := h.Sum()
	h.Write(mask1)
	mask2 := h.Sum()
	h.Write(mask2)
	mask3 := h.Sum()
	return [3]frontend.Variable{mask1, mask2, mask3}
}
