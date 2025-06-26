package zerocash

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

type CircuitTx struct {
	// Public inputs
	OldCoin   frontend.Variable    `gnark:",public"`
	OldEnergy frontend.Variable    `gnark:",public"`
	CmOld     frontend.Variable    `gnark:",public"`
	SnOld     frontend.Variable    `gnark:",public"`
	PkOld     frontend.Variable    `gnark:",public"`
	NewCoin   frontend.Variable    `gnark:",public"`
	NewEnergy frontend.Variable    `gnark:",public"`
	CmNew     frontend.Variable    `gnark:",public"`
	CNew      [6]frontend.Variable `gnark:",public"`
	G         sw_bls12377.G1Affine `gnark:",public"`
	G_b       sw_bls12377.G1Affine `gnark:",public"`
	G_r       sw_bls12377.G1Affine `gnark:",public"`

	// Private inputs
	SkOld   frontend.Variable
	RhoOld  frontend.Variable
	RandOld frontend.Variable
	PkNew   frontend.Variable
	RhoNew  frontend.Variable
	RandNew frontend.Variable
	R       frontend.Variable
	EncKey  sw_bls12377.G1Affine
}

func (c *CircuitTx) Define(api frontend.API) error {
	// Step 1: Serial number (snOld = PRF(skOld, rhoOld))
	snComputed := PRF(api, c.SkOld, c.RhoOld)
	api.AssertIsEqual(c.SnOld, snComputed)

	// Step 2: rhoNew = H(snOld)
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(snComputed)
	rhoNewComputed := hasher.Sum()
	api.AssertIsEqual(c.RhoNew, rhoNewComputed)

	// Step 4: Commitment (cmNew = Com(coins, energy, rhoNew, randNew))
	hasher.Reset()
	hasher.Write(c.NewCoin)
	hasher.Write(c.NewEnergy)
	hasher.Write(c.RhoNew)
	hasher.Write(c.RandNew)
	cmNewComputed := hasher.Sum()
	api.AssertIsEqual(c.CmNew, cmNewComputed)

	// Step 6: Encryption (cNew = Enc(pkNew, coins, energy, rhoNew, randNew, cmNew, encKey))
	encVal := EncZK(api, c.PkNew, c.NewCoin, c.NewEnergy, c.RhoNew, c.RandNew, c.CmNew, c.EncKey)
	for i := 0; i < 6; i++ {
		api.AssertIsEqual(c.CNew[i], encVal[i])
	}

	// Step 7: Value conservation
	api.AssertIsEqual(c.OldCoin, c.NewCoin)
	api.AssertIsEqual(c.OldEnergy, c.NewEnergy)

	// Key derivations for encryption
	G_r_b := new(sw_bls12377.G1Affine)
	G_r_b.ScalarMul(api, c.G_b, c.R)
	api.AssertIsEqual(c.EncKey.X, G_r_b.X)
	api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)
	G_r := new(sw_bls12377.G1Affine)
	G_r.ScalarMul(api, c.G, c.R)
	api.AssertIsEqual(c.G_r.X, G_r.X)
	api.AssertIsEqual(c.G_r.Y, G_r.Y)

	// Public key derivation (pkOld = H(skOld))
	hasher.Reset()
	hasher.Write(c.SkOld)
	pkOldComputed := hasher.Sum()
	api.AssertIsEqual(c.PkOld, pkOldComputed)

	return nil
}

// PRF implements a pseudo-random function using MiMC hash in the circuit
func PRF(api frontend.API, sk, rho frontend.Variable) frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(sk)
	hasher.Write(rho)
	return hasher.Sum()
}

// EncZK encrypts note data using MiMC-based encryption in the circuit
func EncZK(api frontend.API, pk, coins, energy, rho, rand, cm frontend.Variable, enc_key sw_bls12377.G1Affine) []frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	// Generate encryption masks using MiMC hash chain
	h.Write(enc_key.X)
	h.Write(enc_key.Y)
	h_enc_key := h.Sum()

	h.Write(h_enc_key)
	h_h_enc_key := h.Sum()

	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum()

	// Encrypt each field by adding the corresponding mask
	pk_enc := api.Add(pk, h_enc_key)
	coins_enc := api.Add(coins, h_h_enc_key)
	energy_enc := api.Add(energy, h_h_h_enc_key)
	rho_enc := api.Add(rho, h_h_h_h_enc_key)
	rand_enc := api.Add(rand, h_h_h_h_h_enc_key)
	cm_enc := api.Add(cm, h_h_h_h_h_h_enc_key)

	return []frontend.Variable{pk_enc, coins_enc, energy_enc, rho_enc, rand_enc, cm_enc}
}
