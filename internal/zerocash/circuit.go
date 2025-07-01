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

	// Step 2: rhoNew = H(j||snOld) as per paper formula (j=0 for single note)
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(0)          // Add index j=0 for single note output
	hasher.Write(snComputed) // Add serial number
	rhoNewComputed := hasher.Sum()
	api.AssertIsEqual(c.RhoNew, rhoNewComputed)

	// Step 4: Commitment (cmNew = Com(Γ || pk || ρ, r)) as per paper formula
	hasher.Reset()
	hasher.Write(c.NewCoin)   // Γ.coins
	hasher.Write(c.NewEnergy) // Γ.energy
	hasher.Write(c.PkNew)     // pk (public key)
	hasher.Write(c.RhoNew)    // ρ (rho)
	hasher.Write(c.RandNew)   // r (randomness)
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

// CircuitTx10 implements a batched Zerocash transaction circuit for N=10 notes.
// This is identical to CircuitTx but vectorized for 10 notes, used in the auction phase.
type CircuitTx10 struct {
	// Public inputs (arrays of length 10)
	OldCoin   [10]frontend.Variable    `gnark:",public"`
	OldEnergy [10]frontend.Variable    `gnark:",public"`
	CmOld     [10]frontend.Variable    `gnark:",public"`
	SnOld     [10]frontend.Variable    `gnark:",public"`
	PkOld     [10]frontend.Variable    `gnark:",public"`
	NewCoin   [10]frontend.Variable    `gnark:",public"`
	NewEnergy [10]frontend.Variable    `gnark:",public"`
	CmNew     [10]frontend.Variable    `gnark:",public"`
	CNew      [10][6]frontend.Variable `gnark:",public"`
	G         sw_bls12377.G1Affine     `gnark:",public"`
	G_b       sw_bls12377.G1Affine     `gnark:",public"`
	G_r       [10]sw_bls12377.G1Affine `gnark:",public"`

	// Private inputs (arrays of length 10)
	SkOld   [10]frontend.Variable
	RhoOld  [10]frontend.Variable
	RandOld [10]frontend.Variable
	PkNew   [10]frontend.Variable
	RhoNew  [10]frontend.Variable
	RandNew [10]frontend.Variable
	R       [10]frontend.Variable
	EncKey  [10]sw_bls12377.G1Affine
}

func (c *CircuitTx10) Define(api frontend.API) error {
	// First, compute all serial numbers
	var allSerialNumbers [10]frontend.Variable
	for i := 0; i < 10; i++ {
		// Step 1: Serial number (snOld = PRF(skOld, rhoOld)) for note i
		snComputed := PRF(api, c.SkOld[i], c.RhoOld[i])
		api.AssertIsEqual(c.SnOld[i], snComputed)
		allSerialNumbers[i] = snComputed
	}

	// Apply all CircuitTx constraints element-wise for each of the 10 notes
	for i := 0; i < 10; i++ {
		// Step 2: rhoNew = H(j||sn₁ᵒˡᵈ||...||sn₁₀ᵒˡᵈ) as per paper formula
		hasher, _ := mimc.NewMiMC(api)
		hasher.Write(i) // Add index j
		// Add all old serial numbers sn₁ᵒˡᵈ||...||sn₁₀ᵒˡᵈ
		for j := 0; j < 10; j++ {
			hasher.Write(allSerialNumbers[j])
		}
		rhoNewComputed := hasher.Sum()
		api.AssertIsEqual(c.RhoNew[i], rhoNewComputed)

		// Step 4: Commitment (cmNew = Com(Γ || pk || ρ, r)) as per paper formula for note i
		hasher.Reset()
		hasher.Write(c.NewCoin[i])   // Γ.coins
		hasher.Write(c.NewEnergy[i]) // Γ.energy
		hasher.Write(c.PkNew[i])     // pk (public key)
		hasher.Write(c.RhoNew[i])    // ρ (rho)
		hasher.Write(c.RandNew[i])   // r (randomness)
		cmNewComputed := hasher.Sum()
		api.AssertIsEqual(c.CmNew[i], cmNewComputed)

		// Step 6: Encryption (cNew = Enc(pkNew, coins, energy, rhoNew, randNew, cmNew, encKey)) for note i
		encVal := EncZK(api, c.PkNew[i], c.NewCoin[i], c.NewEnergy[i], c.RhoNew[i], c.RandNew[i], c.CmNew[i], c.EncKey[i])
		for j := 0; j < 6; j++ {
			api.AssertIsEqual(c.CNew[i][j], encVal[j])
		}

		// Step 7: Value conservation for note i
		api.AssertIsEqual(c.OldCoin[i], c.NewCoin[i])
		api.AssertIsEqual(c.OldEnergy[i], c.NewEnergy[i])

		// Key derivations for encryption for note i
		G_r_b := new(sw_bls12377.G1Affine)
		G_r_b.ScalarMul(api, c.G_b, c.R[i])
		api.AssertIsEqual(c.EncKey[i].X, G_r_b.X)
		api.AssertIsEqual(c.EncKey[i].Y, G_r_b.Y)
		G_r := new(sw_bls12377.G1Affine)
		G_r.ScalarMul(api, c.G, c.R[i])
		api.AssertIsEqual(c.G_r[i].X, G_r.X)
		api.AssertIsEqual(c.G_r[i].Y, G_r.Y)

		// Public key derivation (pkOld = H(skOld)) for note i
		hasher.Reset()
		hasher.Write(c.SkOld[i])
		pkOldComputed := hasher.Sum()
		api.AssertIsEqual(c.PkOld[i], pkOldComputed)
	}

	return nil
}
