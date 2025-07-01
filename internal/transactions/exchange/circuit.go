// circuit.go - Circuit for the auction phase (exchange) of the protocol.
//
// Defines CircuitTxF10 for N=10 participants, enforcing cryptographic consistency
// (decryption, PRF, commitments, EC operations) but not the auction logic itself.
//
// WARNING: This circuit does NOT enforce the auction computation. Only cryptographic consistency is proven.

package exchange

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// DecZKReg decrypts a registration ciphertext in the circuit using MiMC-based mask chain.
func DecZKReg(api frontend.API, c []frontend.Variable, encKey sw_bls12377.G1Affine) [5]frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
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

	dec0 := api.Sub(c[0], mask0)
	dec1 := api.Sub(c[1], mask1)
	dec2 := api.Sub(c[2], mask2)
	dec3 := api.Sub(c[3], mask3)
	dec4 := api.Sub(c[4], mask4)

	return [5]frontend.Variable{dec0, dec1, dec2, dec3, dec4}
}

// PRF implements a pseudo-random function using MiMC hash in the circuit.
func PRF(api frontend.API, sk, rho frontend.Variable) frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(sk)
	hasher.Write(rho)
	return hasher.Sum()
}

// CircuitTxF10 represents a circuit for 10 coins/participants in the auction phase.
type CircuitTxF10 struct {
	// ----- Input/Output Arrays for 10 coins -----
	InCoin   [10]frontend.Variable `gnark:",public"`
	InEnergy [10]frontend.Variable `gnark:",public"`
	InCm     [10]frontend.Variable `gnark:",public"`
	InSn     [10]frontend.Variable `gnark:",public"`
	InPk     [10]frontend.Variable `gnark:",public"`
	InSk     [10]frontend.Variable `gnark:",public"`
	InRho    [10]frontend.Variable `gnark:",public"`
	InRand   [10]frontend.Variable `gnark:",public"`

	OutCoin   [10]frontend.Variable `gnark:",public"`
	OutEnergy [10]frontend.Variable `gnark:",public"`
	OutCm     [10]frontend.Variable `gnark:",public"`
	OutSn     [10]frontend.Variable `gnark:",public"`
	OutPk     [10]frontend.Variable `gnark:",public"`
	OutRho    [10]frontend.Variable `gnark:",public"`
	OutRand   [10]frontend.Variable `gnark:",public"`

	C      [10][5]frontend.Variable
	DecVal [10][5]frontend.Variable

	// ----- DH Parameters for each coin -----
	SkT    [10]sw_bls12377.G1Affine
	R      [10]frontend.Variable
	G      [10]sw_bls12377.G1Affine `gnark:",public"`
	G_b    [10]sw_bls12377.G1Affine `gnark:",public"`
	G_r    [10]sw_bls12377.G1Affine `gnark:",public"`
	EncKey [10]sw_bls12377.G1Affine
}

// Define implements the constraints for CircuitTxF10 using arrays and for loops.
func (c *CircuitTxF10) Define(api frontend.API) error {
	// Process all 10 coins using a for loop
	for coin := 0; coin < 10; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.SkT[coin])
		for i := 0; i < 5; i++ {
			api.AssertIsEqual(c.DecVal[coin][i], decVal[i])
		}

		// --- Verify serial number computation ---
		snComputed := PRF(api, c.InSk[coin], c.InRho[coin])
		api.AssertIsEqual(c.InSn[coin], snComputed)

		// --- Preserve coin and energy values ---
		api.AssertIsEqual(c.InCoin[coin], c.OutCoin[coin])
		api.AssertIsEqual(c.InEnergy[coin], c.OutEnergy[coin])

		// --- Compute output commitment: cm = Com(Γ || pk || ρ, r) where Γ = (coins, energy) ---
		hasher, _ := mimc.NewMiMC(api)
		hasher.Write(c.OutCoin[coin])   // Γ.coins
		hasher.Write(c.OutEnergy[coin]) // Γ.energy
		hasher.Write(c.OutPk[coin])     // pk (public key)
		hasher.Write(c.OutRho[coin])    // ρ (rho)
		hasher.Write(c.OutRand[coin])   // r (randomness)
		cm := hasher.Sum()
		api.AssertIsEqual(c.OutCm[coin], cm)

		// --- Verify DH encryption constraints ---
		// EncKey = G_b^R
		G_r_b := new(sw_bls12377.G1Affine)
		G_r_b.ScalarMul(api, c.G_b[coin], c.R[coin])
		api.AssertIsEqual(c.EncKey[coin].X, G_r_b.X)
		api.AssertIsEqual(c.EncKey[coin].Y, G_r_b.Y)

		// G_r = G^R
		G_r := new(sw_bls12377.G1Affine)
		G_r.ScalarMul(api, c.G[coin], c.R[coin])
		api.AssertIsEqual(c.G_r[coin].X, G_r.X)
		api.AssertIsEqual(c.G_r[coin].Y, G_r.Y)

		// --- Verify public key derivation: InPk = MiMC(InSk) ---
		hasher.Reset()
		hasher.Write(c.InSk[coin])
		pk := hasher.Sum()
		api.AssertIsEqual(c.InPk[coin], pk)
	}

	return nil
}
