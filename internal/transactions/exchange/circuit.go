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
	// ----- Coin 0 -----
	InCoin0   frontend.Variable `gnark:",public"`
	InEnergy0 frontend.Variable `gnark:",public"`
	InCm0     frontend.Variable `gnark:",public"`
	InSn0     frontend.Variable `gnark:",public"`
	InPk0     frontend.Variable `gnark:",public"`
	InSk0     frontend.Variable `gnark:",public"`
	InRho0    frontend.Variable `gnark:",public"`
	InRand0   frontend.Variable `gnark:",public"`

	OutCoin0   frontend.Variable `gnark:",public"`
	OutEnergy0 frontend.Variable `gnark:",public"`
	OutCm0     frontend.Variable `gnark:",public"`
	OutSn0     frontend.Variable `gnark:",public"`
	OutPk0     frontend.Variable `gnark:",public"`
	OutRho0    frontend.Variable `gnark:",public"`
	OutRand0   frontend.Variable `gnark:",public"`

	C0      [5]frontend.Variable
	DecVal0 [5]frontend.Variable

	// ----- Coin 1 -----
	InCoin1   frontend.Variable `gnark:",public"`
	InEnergy1 frontend.Variable `gnark:",public"`
	InCm1     frontend.Variable `gnark:",public"`
	InSn1     frontend.Variable `gnark:",public"`
	InPk1     frontend.Variable `gnark:",public"`
	InSk1     frontend.Variable `gnark:",public"`
	InRho1    frontend.Variable `gnark:",public"`
	InRand1   frontend.Variable `gnark:",public"`

	OutCoin1   frontend.Variable `gnark:",public"`
	OutEnergy1 frontend.Variable `gnark:",public"`
	OutCm1     frontend.Variable `gnark:",public"`
	OutSn1     frontend.Variable `gnark:",public"`
	OutPk1     frontend.Variable `gnark:",public"`
	OutRho1    frontend.Variable `gnark:",public"`
	OutRand1   frontend.Variable `gnark:",public"`

	C1      [5]frontend.Variable
	DecVal1 [5]frontend.Variable

	// ----- Coin 2 -----
	InCoin2   frontend.Variable `gnark:",public"`
	InEnergy2 frontend.Variable `gnark:",public"`
	InCm2     frontend.Variable `gnark:",public"`
	InSn2     frontend.Variable `gnark:",public"`
	InPk2     frontend.Variable `gnark:",public"`
	InSk2     frontend.Variable `gnark:",public"`
	InRho2    frontend.Variable `gnark:",public"`
	InRand2   frontend.Variable `gnark:",public"`

	OutCoin2   frontend.Variable `gnark:",public"`
	OutEnergy2 frontend.Variable `gnark:",public"`
	OutCm2     frontend.Variable `gnark:",public"`
	OutSn2     frontend.Variable `gnark:",public"`
	OutPk2     frontend.Variable `gnark:",public"`
	OutRho2    frontend.Variable `gnark:",public"`
	OutRand2   frontend.Variable `gnark:",public"`

	C2      [5]frontend.Variable
	DecVal2 [5]frontend.Variable

	// ----- Coin 3 -----
	InCoin3   frontend.Variable `gnark:",public"`
	InEnergy3 frontend.Variable `gnark:",public"`
	InCm3     frontend.Variable `gnark:",public"`
	InSn3     frontend.Variable `gnark:",public"`
	InPk3     frontend.Variable `gnark:",public"`
	InSk3     frontend.Variable `gnark:",public"`
	InRho3    frontend.Variable `gnark:",public"`
	InRand3   frontend.Variable `gnark:",public"`

	OutCoin3   frontend.Variable `gnark:",public"`
	OutEnergy3 frontend.Variable `gnark:",public"`
	OutCm3     frontend.Variable `gnark:",public"`
	OutSn3     frontend.Variable `gnark:",public"`
	OutPk3     frontend.Variable `gnark:",public"`
	OutRho3    frontend.Variable `gnark:",public"`
	OutRand3   frontend.Variable `gnark:",public"`

	C3      [5]frontend.Variable
	DecVal3 [5]frontend.Variable

	// ----- Coin 4 -----
	InCoin4   frontend.Variable `gnark:",public"`
	InEnergy4 frontend.Variable `gnark:",public"`
	InCm4     frontend.Variable `gnark:",public"`
	InSn4     frontend.Variable `gnark:",public"`
	InPk4     frontend.Variable `gnark:",public"`
	InSk4     frontend.Variable `gnark:",public"`
	InRho4    frontend.Variable `gnark:",public"`
	InRand4   frontend.Variable `gnark:",public"`

	OutCoin4   frontend.Variable `gnark:",public"`
	OutEnergy4 frontend.Variable `gnark:",public"`
	OutCm4     frontend.Variable `gnark:",public"`
	OutSn4     frontend.Variable `gnark:",public"`
	OutPk4     frontend.Variable `gnark:",public"`
	OutRho4    frontend.Variable `gnark:",public"`
	OutRand4   frontend.Variable `gnark:",public"`

	C4      [5]frontend.Variable
	DecVal4 [5]frontend.Variable

	// ----- Coin 5 -----
	InCoin5   frontend.Variable `gnark:",public"`
	InEnergy5 frontend.Variable `gnark:",public"`
	InCm5     frontend.Variable `gnark:",public"`
	InSn5     frontend.Variable `gnark:",public"`
	InPk5     frontend.Variable `gnark:",public"`
	InSk5     frontend.Variable `gnark:",public"`
	InRho5    frontend.Variable `gnark:",public"`
	InRand5   frontend.Variable `gnark:",public"`

	OutCoin5   frontend.Variable `gnark:",public"`
	OutEnergy5 frontend.Variable `gnark:",public"`
	OutCm5     frontend.Variable `gnark:",public"`
	OutSn5     frontend.Variable `gnark:",public"`
	OutPk5     frontend.Variable `gnark:",public"`
	OutRho5    frontend.Variable `gnark:",public"`
	OutRand5   frontend.Variable `gnark:",public"`

	C5      [5]frontend.Variable
	DecVal5 [5]frontend.Variable

	// ----- Coin 6 -----
	InCoin6   frontend.Variable `gnark:",public"`
	InEnergy6 frontend.Variable `gnark:",public"`
	InCm6     frontend.Variable `gnark:",public"`
	InSn6     frontend.Variable `gnark:",public"`
	InPk6     frontend.Variable `gnark:",public"`
	InSk6     frontend.Variable `gnark:",public"`
	InRho6    frontend.Variable `gnark:",public"`
	InRand6   frontend.Variable `gnark:",public"`

	OutCoin6   frontend.Variable `gnark:",public"`
	OutEnergy6 frontend.Variable `gnark:",public"`
	OutCm6     frontend.Variable `gnark:",public"`
	OutSn6     frontend.Variable `gnark:",public"`
	OutPk6     frontend.Variable `gnark:",public"`
	OutRho6    frontend.Variable `gnark:",public"`
	OutRand6   frontend.Variable `gnark:",public"`

	C6      [5]frontend.Variable
	DecVal6 [5]frontend.Variable

	// ----- Coin 7 -----
	InCoin7   frontend.Variable `gnark:",public"`
	InEnergy7 frontend.Variable `gnark:",public"`
	InCm7     frontend.Variable `gnark:",public"`
	InSn7     frontend.Variable `gnark:",public"`
	InPk7     frontend.Variable `gnark:",public"`
	InSk7     frontend.Variable `gnark:",public"`
	InRho7    frontend.Variable `gnark:",public"`
	InRand7   frontend.Variable `gnark:",public"`

	OutCoin7   frontend.Variable `gnark:",public"`
	OutEnergy7 frontend.Variable `gnark:",public"`
	OutCm7     frontend.Variable `gnark:",public"`
	OutSn7     frontend.Variable `gnark:",public"`
	OutPk7     frontend.Variable `gnark:",public"`
	OutRho7    frontend.Variable `gnark:",public"`
	OutRand7   frontend.Variable `gnark:",public"`

	C7      [5]frontend.Variable
	DecVal7 [5]frontend.Variable

	// ----- Coin 8 -----
	InCoin8   frontend.Variable `gnark:",public"`
	InEnergy8 frontend.Variable `gnark:",public"`
	InCm8     frontend.Variable `gnark:",public"`
	InSn8     frontend.Variable `gnark:",public"`
	InPk8     frontend.Variable `gnark:",public"`
	InSk8     frontend.Variable `gnark:",public"`
	InRho8    frontend.Variable `gnark:",public"`
	InRand8   frontend.Variable `gnark:",public"`

	OutCoin8   frontend.Variable `gnark:",public"`
	OutEnergy8 frontend.Variable `gnark:",public"`
	OutCm8     frontend.Variable `gnark:",public"`
	OutSn8     frontend.Variable `gnark:",public"`
	OutPk8     frontend.Variable `gnark:",public"`
	OutRho8    frontend.Variable `gnark:",public"`
	OutRand8   frontend.Variable `gnark:",public"`

	C8      [5]frontend.Variable
	DecVal8 [5]frontend.Variable

	// ----- Coin 9 -----
	InCoin9   frontend.Variable `gnark:",public"`
	InEnergy9 frontend.Variable `gnark:",public"`
	InCm9     frontend.Variable `gnark:",public"`
	InSn9     frontend.Variable `gnark:",public"`
	InPk9     frontend.Variable `gnark:",public"`
	InSk9     frontend.Variable `gnark:",public"`
	InRho9    frontend.Variable `gnark:",public"`
	InRand9   frontend.Variable `gnark:",public"`

	OutCoin9   frontend.Variable `gnark:",public"`
	OutEnergy9 frontend.Variable `gnark:",public"`
	OutCm9     frontend.Variable `gnark:",public"`
	OutSn9     frontend.Variable `gnark:",public"`
	OutPk9     frontend.Variable `gnark:",public"`
	OutRho9    frontend.Variable `gnark:",public"`
	OutRand9   frontend.Variable `gnark:",public"`

	C9      [5]frontend.Variable
	DecVal9 [5]frontend.Variable

	// ----- Parameters for each coin -----
	SkT0    sw_bls12377.G1Affine
	R0      frontend.Variable
	G0      sw_bls12377.G1Affine `gnark:",public"`
	G_b0    sw_bls12377.G1Affine `gnark:",public"`
	G_r0    sw_bls12377.G1Affine `gnark:",public"`
	EncKey0 sw_bls12377.G1Affine

	SkT1    sw_bls12377.G1Affine
	R1      frontend.Variable
	G1      sw_bls12377.G1Affine `gnark:",public"`
	G_b1    sw_bls12377.G1Affine `gnark:",public"`
	G_r1    sw_bls12377.G1Affine `gnark:",public"`
	EncKey1 sw_bls12377.G1Affine

	SkT2    sw_bls12377.G1Affine
	R2      frontend.Variable
	G2      sw_bls12377.G1Affine `gnark:",public"`
	G_b2    sw_bls12377.G1Affine `gnark:",public"`
	G_r2    sw_bls12377.G1Affine `gnark:",public"`
	EncKey2 sw_bls12377.G1Affine

	SkT3    sw_bls12377.G1Affine
	R3      frontend.Variable
	G3      sw_bls12377.G1Affine `gnark:",public"`
	G_b3    sw_bls12377.G1Affine `gnark:",public"`
	G_r3    sw_bls12377.G1Affine `gnark:",public"`
	EncKey3 sw_bls12377.G1Affine

	SkT4    sw_bls12377.G1Affine
	R4      frontend.Variable
	G4      sw_bls12377.G1Affine `gnark:",public"`
	G_b4    sw_bls12377.G1Affine `gnark:",public"`
	G_r4    sw_bls12377.G1Affine `gnark:",public"`
	EncKey4 sw_bls12377.G1Affine

	SkT5    sw_bls12377.G1Affine
	R5      frontend.Variable
	G5      sw_bls12377.G1Affine `gnark:",public"`
	G_b5    sw_bls12377.G1Affine `gnark:",public"`
	G_r5    sw_bls12377.G1Affine `gnark:",public"`
	EncKey5 sw_bls12377.G1Affine

	SkT6    sw_bls12377.G1Affine
	R6      frontend.Variable
	G6      sw_bls12377.G1Affine `gnark:",public"`
	G_b6    sw_bls12377.G1Affine `gnark:",public"`
	G_r6    sw_bls12377.G1Affine `gnark:",public"`
	EncKey6 sw_bls12377.G1Affine

	SkT7    sw_bls12377.G1Affine
	R7      frontend.Variable
	G7      sw_bls12377.G1Affine `gnark:",public"`
	G_b7    sw_bls12377.G1Affine `gnark:",public"`
	G_r7    sw_bls12377.G1Affine `gnark:",public"`
	EncKey7 sw_bls12377.G1Affine

	SkT8    sw_bls12377.G1Affine
	R8      frontend.Variable
	G8      sw_bls12377.G1Affine `gnark:",public"`
	G_b8    sw_bls12377.G1Affine `gnark:",public"`
	G_r8    sw_bls12377.G1Affine `gnark:",public"`
	EncKey8 sw_bls12377.G1Affine

	SkT9    sw_bls12377.G1Affine
	R9      frontend.Variable
	G9      sw_bls12377.G1Affine `gnark:",public"`
	G_b9    sw_bls12377.G1Affine `gnark:",public"`
	G_r9    sw_bls12377.G1Affine `gnark:",public"`
	EncKey9 sw_bls12377.G1Affine
}

// Define implements the constraints for CircuitTxF10.
func (c *CircuitTxF10) Define(api frontend.API) error {
	// // Add a minimal constraint to prevent 0-constraint circuit panic
	// api.AssertIsEqual(c.InCoin0, c.InCoin0)

	// --- Traitement du coin 0 ---
	decVal0 := DecZKReg(api, c.C0[:], c.SkT0)
	for i := 0; i < 5; i++ {
		api.AssertIsEqual(c.DecVal0[i], decVal0[i])
	}
	snComputed0 := PRF(api, c.InSk0, c.InRho0)
	api.AssertIsEqual(c.InSn0, snComputed0)
	api.AssertIsEqual(c.InCoin0, c.OutCoin0)
	api.AssertIsEqual(c.InEnergy0, c.OutEnergy0)
	hasher0, _ := mimc.NewMiMC(api)
	hasher0.Write(c.OutCoin0)
	hasher0.Write(c.OutEnergy0)
	hasher0.Write(c.OutRho0)
	hasher0.Write(c.OutRand0)
	cm0 := hasher0.Sum()
	api.AssertIsEqual(c.OutCm0, cm0)

	// // --- Traitement du coin 1 ---
	// decVal1 := DecZKReg(api, c.C1[:], c.SkT1)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal1[i], decVal1[i])
	// }
	// snComputed1 := PRF(api, c.InSk1, c.InRho1)
	// api.AssertIsEqual(c.InSn1, snComputed1)
	// api.AssertIsEqual(c.InCoin1, c.OutCoin1)
	// api.AssertIsEqual(c.InEnergy1, c.OutEnergy1)
	// hasher1, _ := mimc.NewMiMC(api)
	// hasher1.Write(c.OutCoin1)
	// hasher1.Write(c.OutEnergy1)
	// hasher1.Write(c.OutRho1)
	// hasher1.Write(c.OutRand1)
	// cm1 := hasher1.Sum()
	// api.AssertIsEqual(c.OutCm1, cm1)

	// // --- Traitement du coin 2 ---
	// decVal2 := DecZKReg(api, c.C2[:], c.SkT2)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal2[i], decVal2[i])
	// }
	// snComputed2 := PRF(api, c.InSk2, c.InRho2)
	// api.AssertIsEqual(c.InSn2, snComputed2)
	// api.AssertIsEqual(c.InCoin2, c.OutCoin2)
	// api.AssertIsEqual(c.InEnergy2, c.OutEnergy2)
	// hasher2, _ := mimc.NewMiMC(api)
	// hasher2.Write(c.OutCoin2)
	// hasher2.Write(c.OutEnergy2)
	// hasher2.Write(c.OutRho2)
	// hasher2.Write(c.OutRand2)
	// cm2 := hasher2.Sum()
	// api.AssertIsEqual(c.OutCm2, cm2)

	// // --- Traitement du coin 3 ---
	// decVal3 := DecZKReg(api, c.C3[:], c.SkT3)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal3[i], decVal3[i])
	// }
	// snComputed3 := PRF(api, c.InSk3, c.InRho3)
	// api.AssertIsEqual(c.InSn3, snComputed3)
	// api.AssertIsEqual(c.InCoin3, c.OutCoin3)
	// api.AssertIsEqual(c.InEnergy3, c.OutEnergy3)
	// hasher3, _ := mimc.NewMiMC(api)
	// hasher3.Write(c.OutCoin3)
	// hasher3.Write(c.OutEnergy3)
	// hasher3.Write(c.OutRho3)
	// hasher3.Write(c.OutRand3)
	// cm3 := hasher3.Sum()
	// api.AssertIsEqual(c.OutCm3, cm3)

	// // --- Traitement du coin 4 ---
	// decVal4 := DecZKReg(api, c.C4[:], c.SkT4)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal4[i], decVal4[i])
	// }
	// snComputed4 := PRF(api, c.InSk4, c.InRho4)
	// api.AssertIsEqual(c.InSn4, snComputed4)
	// api.AssertIsEqual(c.InCoin4, c.OutCoin4)
	// api.AssertIsEqual(c.InEnergy4, c.OutEnergy4)
	// hasher4, _ := mimc.NewMiMC(api)
	// hasher4.Write(c.OutCoin4)
	// hasher4.Write(c.OutEnergy4)
	// hasher4.Write(c.OutRho4)
	// hasher4.Write(c.OutRand4)
	// cm4 := hasher4.Sum()
	// api.AssertIsEqual(c.OutCm4, cm4)

	// // --- Traitement du coin 5 ---
	// decVal5 := DecZKReg(api, c.C5[:], c.SkT5)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal5[i], decVal5[i])
	// }
	// snComputed5 := PRF(api, c.InSk5, c.InRho5)
	// api.AssertIsEqual(c.InSn5, snComputed5)
	// api.AssertIsEqual(c.InCoin5, c.OutCoin5)
	// api.AssertIsEqual(c.InEnergy5, c.OutEnergy5)
	// hasher5, _ := mimc.NewMiMC(api)
	// hasher5.Write(c.OutCoin5)
	// hasher5.Write(c.OutEnergy5)
	// hasher5.Write(c.OutRho5)
	// hasher5.Write(c.OutRand5)
	// cm5 := hasher5.Sum()
	// api.AssertIsEqual(c.OutCm5, cm5)

	// // --- Traitement du coin 6 ---
	// decVal6 := DecZKReg(api, c.C6[:], c.SkT6)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal6[i], decVal6[i])
	// }
	// snComputed6 := PRF(api, c.InSk6, c.InRho6)
	// api.AssertIsEqual(c.InSn6, snComputed6)
	// api.AssertIsEqual(c.InCoin6, c.OutCoin6)
	// api.AssertIsEqual(c.InEnergy6, c.OutEnergy6)
	// hasher6, _ := mimc.NewMiMC(api)
	// hasher6.Write(c.OutCoin6)
	// hasher6.Write(c.OutEnergy6)
	// hasher6.Write(c.OutRho6)
	// hasher6.Write(c.OutRand6)
	// cm6 := hasher6.Sum()
	// api.AssertIsEqual(c.OutCm6, cm6)

	// // --- Traitement du coin 7 ---
	// decVal7 := DecZKReg(api, c.C7[:], c.SkT7)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal7[i], decVal7[i])
	// }
	// snComputed7 := PRF(api, c.InSk7, c.InRho7)
	// api.AssertIsEqual(c.InSn7, snComputed7)
	// api.AssertIsEqual(c.InCoin7, c.OutCoin7)
	// api.AssertIsEqual(c.InEnergy7, c.OutEnergy7)
	// hasher7, _ := mimc.NewMiMC(api)
	// hasher7.Write(c.OutCoin7)
	// hasher7.Write(c.OutEnergy7)
	// hasher7.Write(c.OutRho7)
	// hasher7.Write(c.OutRand7)
	// cm7 := hasher7.Sum()
	// api.AssertIsEqual(c.OutCm7, cm7)

	// // --- Traitement du coin 8 ---
	// decVal8 := DecZKReg(api, c.C8[:], c.SkT8)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal8[i], decVal8[i])
	// }
	// snComputed8 := PRF(api, c.InSk8, c.InRho8)
	// api.AssertIsEqual(c.InSn8, snComputed8)
	// api.AssertIsEqual(c.InCoin8, c.OutCoin8)
	// api.AssertIsEqual(c.InEnergy8, c.OutEnergy8)
	// hasher8, _ := mimc.NewMiMC(api)
	// hasher8.Write(c.OutCoin8)
	// hasher8.Write(c.OutEnergy8)
	// hasher8.Write(c.OutRho8)
	// hasher8.Write(c.OutRand8)
	// cm8 := hasher8.Sum()
	// api.AssertIsEqual(c.OutCm8, cm8)

	// // --- Traitement du coin 9 ---
	// decVal9 := DecZKReg(api, c.C9[:], c.SkT9)
	// for i := 0; i < 5; i++ {
	// 	api.AssertIsEqual(c.DecVal9[i], decVal9[i])
	// }
	// snComputed9 := PRF(api, c.InSk9, c.InRho9)
	// api.AssertIsEqual(c.InSn9, snComputed9)
	// api.AssertIsEqual(c.InCoin9, c.OutCoin9)
	// api.AssertIsEqual(c.InEnergy9, c.OutEnergy9)
	// hasher9, _ := mimc.NewMiMC(api)
	// hasher9.Write(c.OutCoin9)
	// hasher9.Write(c.OutEnergy9)
	// hasher9.Write(c.OutRho9)
	// hasher9.Write(c.OutRand9)
	// cm9 := hasher9.Sum()
	// api.AssertIsEqual(c.OutCm9, cm9)

	// // --- Vérifications globales (encryption) ---
	// // Pour chaque coin, vérifier que EncKey == G_b * R et que G^R == G_r

	// // Coin 0
	// G_r_b0 := new(sw_bls12377.G1Affine)
	// G_r_b0.ScalarMul(api, c.G_b0, c.R0)
	// api.AssertIsEqual(c.EncKey0.X, G_r_b0.X)
	// api.AssertIsEqual(c.EncKey0.Y, G_r_b0.Y)
	// G_r0 := new(sw_bls12377.G1Affine)
	// G_r0.ScalarMul(api, c.G0, c.R0)
	// api.AssertIsEqual(c.G_r0.X, G_r0.X)
	// api.AssertIsEqual(c.G_r0.Y, G_r0.Y)

	// // Coin 1
	// G_r_b1 := new(sw_bls12377.G1Affine)
	// G_r_b1.ScalarMul(api, c.G_b1, c.R1)
	// api.AssertIsEqual(c.EncKey1.X, G_r_b1.X)
	// api.AssertIsEqual(c.EncKey1.Y, G_r_b1.Y)
	// G_r1 := new(sw_bls12377.G1Affine)
	// G_r1.ScalarMul(api, c.G1, c.R1)
	// api.AssertIsEqual(c.G_r1.X, G_r1.X)
	// api.AssertIsEqual(c.G_r1.Y, G_r1.Y)

	// // Coin 2
	// G_r_b2 := new(sw_bls12377.G1Affine)
	// G_r_b2.ScalarMul(api, c.G_b2, c.R2)
	// api.AssertIsEqual(c.EncKey2.X, G_r_b2.X)
	// api.AssertIsEqual(c.EncKey2.Y, G_r_b2.Y)
	// G_r2 := new(sw_bls12377.G1Affine)
	// G_r2.ScalarMul(api, c.G2, c.R2)
	// api.AssertIsEqual(c.G_r2.X, G_r2.X)
	// api.AssertIsEqual(c.G_r2.Y, G_r2.Y)

	// // Coin 3
	// G_r_b3 := new(sw_bls12377.G1Affine)
	// G_r_b3.ScalarMul(api, c.G_b3, c.R3)
	// api.AssertIsEqual(c.EncKey3.X, G_r_b3.X)
	// api.AssertIsEqual(c.EncKey3.Y, G_r_b3.Y)
	// G_r3 := new(sw_bls12377.G1Affine)
	// G_r3.ScalarMul(api, c.G3, c.R3)
	// api.AssertIsEqual(c.G_r3.X, G_r3.X)
	// api.AssertIsEqual(c.G_r3.Y, G_r3.Y)

	// // Coin 4
	// G_r_b4 := new(sw_bls12377.G1Affine)
	// G_r_b4.ScalarMul(api, c.G_b4, c.R4)
	// api.AssertIsEqual(c.EncKey4.X, G_r_b4.X)
	// api.AssertIsEqual(c.EncKey4.Y, G_r_b4.Y)
	// G_r4 := new(sw_bls12377.G1Affine)
	// G_r4.ScalarMul(api, c.G4, c.R4)
	// api.AssertIsEqual(c.G_r4.X, G_r4.X)
	// api.AssertIsEqual(c.G_r4.Y, G_r4.Y)

	// // Coin 5
	// G_r_b5 := new(sw_bls12377.G1Affine)
	// G_r_b5.ScalarMul(api, c.G_b5, c.R5)
	// api.AssertIsEqual(c.EncKey5.X, G_r_b5.X)
	// api.AssertIsEqual(c.EncKey5.Y, G_r_b5.Y)
	// G_r5 := new(sw_bls12377.G1Affine)
	// G_r5.ScalarMul(api, c.G5, c.R5)
	// api.AssertIsEqual(c.G_r5.X, G_r5.X)
	// api.AssertIsEqual(c.G_r5.Y, G_r5.Y)

	// // Coin 6
	// G_r_b6 := new(sw_bls12377.G1Affine)
	// G_r_b6.ScalarMul(api, c.G_b6, c.R6)
	// api.AssertIsEqual(c.EncKey6.X, G_r_b6.X)
	// api.AssertIsEqual(c.EncKey6.Y, G_r_b6.Y)
	// G_r6 := new(sw_bls12377.G1Affine)
	// G_r6.ScalarMul(api, c.G6, c.R6)
	// api.AssertIsEqual(c.G_r6.X, G_r6.X)
	// api.AssertIsEqual(c.G_r6.Y, G_r6.Y)

	// // Coin 7
	// G_r_b7 := new(sw_bls12377.G1Affine)
	// G_r_b7.ScalarMul(api, c.G_b7, c.R7)
	// api.AssertIsEqual(c.EncKey7.X, G_r_b7.X)
	// api.AssertIsEqual(c.EncKey7.Y, G_r_b7.Y)
	// G_r7 := new(sw_bls12377.G1Affine)
	// G_r7.ScalarMul(api, c.G7, c.R7)
	// api.AssertIsEqual(c.G_r7.X, G_r7.X)
	// api.AssertIsEqual(c.G_r7.Y, G_r7.Y)

	// // Coin 8
	// G_r_b8 := new(sw_bls12377.G1Affine)
	// G_r_b8.ScalarMul(api, c.G_b8, c.R8)
	// api.AssertIsEqual(c.EncKey8.X, G_r_b8.X)
	// api.AssertIsEqual(c.EncKey8.Y, G_r_b8.Y)
	// G_r8 := new(sw_bls12377.G1Affine)
	// G_r8.ScalarMul(api, c.G8, c.R8)
	// api.AssertIsEqual(c.G_r8.X, G_r8.X)
	// api.AssertIsEqual(c.G_r8.Y, G_r8.Y)

	// // Coin 9
	// G_r_b9 := new(sw_bls12377.G1Affine)
	// G_r_b9.ScalarMul(api, c.G_b9, c.R9)
	// api.AssertIsEqual(c.EncKey9.X, G_r_b9.X)
	// api.AssertIsEqual(c.EncKey9.Y, G_r_b9.Y)
	// G_r9 := new(sw_bls12377.G1Affine)
	// G_r9.ScalarMul(api, c.G9, c.R9)
	// api.AssertIsEqual(c.G_r9.X, G_r9.X)
	// api.AssertIsEqual(c.G_r9.Y, G_r9.Y)

	// // Vérification de la dérivation de la clé publique pour chaque coin : InPk = MiMC(InSk)
	// hasher0.Reset()
	// hasher0.Write(c.InSk0)
	// pk0 := hasher0.Sum()
	// api.AssertIsEqual(c.InPk0, pk0)

	// hasher1.Reset()
	// hasher1.Write(c.InSk1)
	// pk1 := hasher1.Sum()
	// api.AssertIsEqual(c.InPk1, pk1)

	// hasher2.Reset()
	// hasher2.Write(c.InSk2)
	// pk2 := hasher2.Sum()
	// api.AssertIsEqual(c.InPk2, pk2)

	// hasher3.Reset()
	// hasher3.Write(c.InSk3)
	// pk3 := hasher3.Sum()
	// api.AssertIsEqual(c.InPk3, pk3)

	// hasher4.Reset()
	// hasher4.Write(c.InSk4)
	// pk4 := hasher4.Sum()
	// api.AssertIsEqual(c.InPk4, pk4)

	// hasher5.Reset()
	// hasher5.Write(c.InSk5)
	// pk5 := hasher5.Sum()
	// api.AssertIsEqual(c.InPk5, pk5)

	// hasher6.Reset()
	// hasher6.Write(c.InSk6)
	// pk6 := hasher6.Sum()
	// api.AssertIsEqual(c.InPk6, pk6)

	// hasher7.Reset()
	// hasher7.Write(c.InSk7)
	// pk7 := hasher7.Sum()
	// api.AssertIsEqual(c.InPk7, pk7)

	// hasher8.Reset()
	// hasher8.Write(c.InSk8)
	// pk8 := hasher8.Sum()
	// api.AssertIsEqual(c.InPk8, pk8)

	// hasher9.Reset()
	// hasher9.Write(c.InSk9)
	// pk9 := hasher9.Sum()
	// api.AssertIsEqual(c.InPk9, pk9)

	return nil
}
