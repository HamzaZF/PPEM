package register

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// CircuitTxRegister defines the ZK circuit for the registration phase of the protocol.
// This circuit is for the registration proof (π_reg) in Algorithm 2 (Register),
// and is separate from the Zerocash transaction proof (π) in Algorithm 1 (Transaction).
// It proves knowledge of a valid note, bid, and encryption, using MiMC and BLS12-377.
type CircuitTxRegister struct {
	// ====== PUBLIC VARIABLES ======
	CmIn          frontend.Variable    `gnark:",public"` // Commitment of input note
	CAux          [5]frontend.Variable `gnark:",public"` // Encrypted (pk, sk, bid, coins, energy)
	GammaInEnergy frontend.Variable    `gnark:",public"` // Input note energy
	GammaInCoins  frontend.Variable    `gnark:",public"` // Input note coins
	Bid           frontend.Variable    `gnark:",public"` // Bid value
	G             sw_bls12377.G1Affine `gnark:",public"`
	G_b           sw_bls12377.G1Affine `gnark:",public"`
	G_r           sw_bls12377.G1Affine `gnark:",public"`

	// ====== PRIVATE VARIABLES ======
	InCoin   frontend.Variable
	InEnergy frontend.Variable
	RhoIn    frontend.Variable
	RandIn   frontend.Variable
	SkIn     frontend.Variable
	PkIn     frontend.Variable
	PkOut    frontend.Variable
	EncKey   sw_bls12377.G1Affine
	R        frontend.Variable
}

// Define implements the circuit constraints for registration.
func (c *CircuitTxRegister) Define(api frontend.API) error {
	// 1) Recompute cmIn following paper: cm = Com(Γ || pk || ρ, r)
	hasher, _ := mimc.NewMiMC(api)
	hasher.Reset()
	hasher.Write(c.InCoin)   // Γ.coins
	hasher.Write(c.InEnergy) // Γ.energy
	hasher.Write(c.PkIn)     // pk (public key)
	hasher.Write(c.RhoIn)    // ρ (rho)
	hasher.Write(c.RandIn)   // r (randomness)
	cm := hasher.Sum()
	api.AssertIsEqual(c.CmIn, cm)

	// 2) Check pk_in = MiMC(sk_in)
	hasher.Reset()
	hasher.Write(c.SkIn)
	pk := hasher.Sum()
	api.AssertIsEqual(c.PkIn, pk)

	// 3) Recompute cAux[j] = EncZKReg(pk, sk, bid, coins, energy, encKey)
	encVal := EncZKReg(api, c.PkOut, c.SkIn, c.Bid, c.GammaInCoins, c.GammaInEnergy, c.EncKey)
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(c.CAux[i], encVal[i])
	}

	// 4) Encryption checks
	// (G^r)^b == EncKey
	G_r_b := new(sw_bls12377.G1Affine)
	G_r_b.ScalarMul(api, c.G_b, c.R)
	api.AssertIsEqual(c.EncKey.X, G_r_b.X)
	api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)

	// (G^r) == G_r
	G_r := new(sw_bls12377.G1Affine)
	G_r.ScalarMul(api, c.G, c.R)
	api.AssertIsEqual(c.G_r.X, G_r.X)
	api.AssertIsEqual(c.G_r.Y, G_r.Y)

	return nil
}

// EncZKReg implements MiMC-based encryption for registration.
// It mimics the style of zerocash's note encryption, but for (pk, sk, bid, coins, energy).
func EncZKReg(api frontend.API, pkOut, skIn, bid, coins, energy frontend.Variable, encKey sw_bls12377.G1Affine) [5]frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
	// Use encKey.X and encKey.Y as the base for the mask chain
	hasher.Reset()
	hasher.Write(encKey.X)
	hasher.Write(encKey.Y)
	mask0 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask0)
	mask1 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask1)
	mask2 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask2)
	mask3 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask3)
	mask4 := hasher.Sum()

	// Encrypt each field by adding the mask
	enc0 := api.Add(pkOut, mask0)
	enc1 := api.Add(skIn, mask1)
	enc2 := api.Add(bid, mask2)
	enc3 := api.Add(coins, mask3)
	enc4 := api.Add(energy, mask4)

	return [5]frontend.Variable{enc0, enc1, enc2, enc3, enc4}
}
