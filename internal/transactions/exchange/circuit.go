// circuit.go - Circuit for the auction phase (exchange) of the protocol.
//
// Defines dynamic circuits for any N participants, enforcing cryptographic consistency
// (decryption, PRF, commitments, EC operations) and basic auction constraints.
//
// AUCTION CONSTRAINTS:
// - First N/2 participants are buyers (sorted descending by bid)
// - Last N/2 participants are sellers (sorted ascending by ask)
// - DecVal[i][2] contains the bid/ask price for participant i
//
// WARNING: This circuit enforces sorting constraints but does NOT implement the full auction matching logic.

package exchange

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// TRADING_VOLUME is the hardcoded trading volume for the simplified auction
const TRADING_VOLUME = 10

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

// CircuitTxFN represents a dynamic circuit for N coins/participants in the auction phase.
// This circuit can be generated for any number of participants.
//
// Auction Structure:
// - First N/2 participants (indices 0 to N/2-1) are BUYERS
// - Last N/2 participants (indices N/2 to N-1) are SELLERS
// - DecVal[i][2] represents the bid (for buyers) or ask (for sellers) price
// - Buyers must be sorted in DESCENDING order (highest bid first)
// - Sellers must be sorted in ASCENDING order (lowest ask first)
type CircuitTxFN struct {
	// Number of participants this circuit supports (must be even)
	N int

	// ----- Input/Output Arrays for N coins -----
	InCoin   []frontend.Variable `gnark:",public"`
	InEnergy []frontend.Variable `gnark:",public"`
	InCm     []frontend.Variable `gnark:",public"`
	InSn     []frontend.Variable `gnark:",public"`
	InPk     []frontend.Variable `gnark:",public"`
	InSk     []frontend.Variable `gnark:",public"`
	InRho    []frontend.Variable `gnark:",public"`
	InRand   []frontend.Variable `gnark:",public"`

	OutCoin   []frontend.Variable `gnark:",public"`
	OutEnergy []frontend.Variable `gnark:",public"`
	OutCm     []frontend.Variable `gnark:",public"`
	OutSn     []frontend.Variable `gnark:",public"`
	OutPk     []frontend.Variable `gnark:",public"`
	OutRho    []frontend.Variable `gnark:",public"`
	OutRand   []frontend.Variable `gnark:",public"`

	C      [][]frontend.Variable
	DecVal [][]frontend.Variable // DecVal[i][2] contains the bid/ask price for participant i

	// ----- DH Parameters for each coin -----
	R      []frontend.Variable
	G      []sw_bls12377.G1Affine `gnark:",public"`
	G_b    []sw_bls12377.G1Affine `gnark:",public"`
	G_r    []sw_bls12377.G1Affine `gnark:",public"`
	EncKey []sw_bls12377.G1Affine // DH shared secret: used for both decryption and DH verification
}

// NewCircuitTxFN creates a new dynamic circuit for N participants
// N must be even: first N/2 participants are buyers, last N/2 are sellers
func NewCircuitTxFN(n int) *CircuitTxFN {
	if n <= 0 {
		panic("CircuitTxFN: N must be positive")
	}
	if n%2 != 0 {
		panic("CircuitTxFN: N must be even (N/2 buyers, N/2 sellers)")
	}

	circuit := &CircuitTxFN{
		N: n,
		// Initialize arrays with proper sizes
		InCoin:   make([]frontend.Variable, n),
		InEnergy: make([]frontend.Variable, n),
		InCm:     make([]frontend.Variable, n),
		InSn:     make([]frontend.Variable, n),
		InPk:     make([]frontend.Variable, n),
		InSk:     make([]frontend.Variable, n),
		InRho:    make([]frontend.Variable, n),
		InRand:   make([]frontend.Variable, n),

		OutCoin:   make([]frontend.Variable, n),
		OutEnergy: make([]frontend.Variable, n),
		OutCm:     make([]frontend.Variable, n),
		OutSn:     make([]frontend.Variable, n),
		OutPk:     make([]frontend.Variable, n),
		OutRho:    make([]frontend.Variable, n),
		OutRand:   make([]frontend.Variable, n),

		C:      make([][]frontend.Variable, n),
		DecVal: make([][]frontend.Variable, n),

		R:      make([]frontend.Variable, n),
		G:      make([]sw_bls12377.G1Affine, n),
		G_b:    make([]sw_bls12377.G1Affine, n),
		G_r:    make([]sw_bls12377.G1Affine, n),
		EncKey: make([]sw_bls12377.G1Affine, n),
	}

	// Initialize 2D arrays
	for i := 0; i < n; i++ {
		circuit.C[i] = make([]frontend.Variable, 5)
		circuit.DecVal[i] = make([]frontend.Variable, 5)
	}

	return circuit
}

// Define implements the constraints for CircuitTxFN using dynamic arrays and for loops.
func (c *CircuitTxFN) Define(api frontend.API) error {
	// Process all N coins using a for loop
	for coin := 0; coin < c.N; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
		for i := 0; i < 5; i++ {
			api.AssertIsEqual(c.DecVal[coin][i], decVal[i])
		}

		// --- Verify serial number computation ---
		snComputed := PRF(api, c.InSk[coin], c.InRho[coin])
		api.AssertIsEqual(c.InSn[coin], snComputed)

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
		// EncKey = G_b^R (same variable used for both decryption and DH verification)
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

	// --- Verify auction sorting constraints ---
	// First half (0 to N/2-1) are buyers: DecVal[i][2] should be in descending order (highest bid first)
	// Second half (N/2 to N-1) are sellers: DecVal[i][2] should be in ascending order (lowest ask first)
	halfN := c.N / 2

	// Verify buyers are sorted in descending order (highest bid first)
	for i := 0; i < halfN-1; i++ {
		// For buyers: DecVal[i][2] >= DecVal[i+1][2]
		// Use api.AssertIsLessOrEqual to verify DecVal[i+1][2] <= DecVal[i][2]
		api.AssertIsLessOrEqual(c.DecVal[i+1][2], c.DecVal[i][2])
	}

	// Verify sellers are sorted in ascending order (lowest ask first)
	for i := halfN; i < c.N-1; i++ {
		// For sellers: DecVal[i][2] <= DecVal[i+1][2]
		api.AssertIsLessOrEqual(c.DecVal[i][2], c.DecVal[i+1][2])
	}

	// --- Implement auction trading logic ---
	// Define clearing price as the bid of buyer number N/4
	clearingPrice := c.DecVal[halfN/2][2]

	// Process trading for all participants
	for i := 0; i < c.N; i++ {
		if i < halfN {
			// This is a buyer (index 0 to N/2-1)
			// Buyer qualifies if their bid >= clearing price

			// Calculate what the output should be
			tradingCost := api.Mul(clearingPrice, TRADING_VOLUME)
			coinAfterTrade := api.Sub(c.InCoin[i], tradingCost)
			energyAfterTrade := api.Add(c.InEnergy[i], TRADING_VOLUME)

			// // Simplified qualification: bid >= clearing price
			// // If (bid - clearing) >= 0, then qualified = 1, else qualified = 0
			// bidDiff := api.Sub(c.DecVal[i][2], clearingPrice)
			// //qualified := api.IsZero(api.IsZero(bidDiff)) // This gives 1 if bidDiff >= 0

			// qualified := api.IsZero(api.Sub(0, api.IsZero(bidDiff)))

			// Buyer qualifies if bid >= clearing price
			// api.Cmp(bid, clearingPrice) returns 1 if bid > clearing, 0 if equal, -1 if bid < clearing
			// We want 1 if qualified (bid >= clearing), 0 otherwise
			cmpResult := api.Cmp(c.DecVal[i][2], clearingPrice)

			qualified := api.Select(api.IsZero(cmpResult), 1, api.IsZero(api.Sub(1, cmpResult)))

			// Compute expected outputs based on qualification
			expectedCoin := api.Add(c.InCoin[i], api.Mul(qualified, api.Sub(coinAfterTrade, c.InCoin[i])))
			expectedEnergy := api.Add(c.InEnergy[i], api.Mul(qualified, api.Sub(energyAfterTrade, c.InEnergy[i])))

			// Assert that the claimed outputs match our computation
			api.AssertIsEqual(c.OutCoin[i], expectedCoin)
			api.AssertIsEqual(c.OutEnergy[i], expectedEnergy)
		} else {
			// This is a seller (index N/2 to N-1)
			// Seller qualifies if their ask <= clearing price

			// Calculate what the output should be
			tradingRevenue := api.Mul(clearingPrice, TRADING_VOLUME)
			coinAfterTrade := api.Add(c.InCoin[i], tradingRevenue)
			energyAfterTrade := api.Sub(c.InEnergy[i], TRADING_VOLUME)

			// Seller qualifies if ask <= clearing price
			// api.Cmp(clearingPrice, ask) returns 1 if clearing > ask, 0 if equal, -1 if clearing < ask
			// We want 1 if qualified (ask <= clearing), 0 otherwise
			cmpResult := api.Cmp(clearingPrice, c.DecVal[i][2])
			qualified := api.Select(api.IsZero(cmpResult), 1, api.IsZero(api.Sub(1, cmpResult)))
			//qualified := api.IsZero(api.Sub(1, cmpResult)) // 1 if cmpResult >= 0, 0 otherwise

			// Compute expected outputs based on qualification
			expectedCoin := api.Add(c.InCoin[i], api.Mul(qualified, api.Sub(coinAfterTrade, c.InCoin[i])))
			expectedEnergy := api.Add(c.InEnergy[i], api.Mul(qualified, api.Sub(energyAfterTrade, c.InEnergy[i])))

			// Assert that the claimed outputs match our computation
			api.AssertIsEqual(c.OutCoin[i], expectedCoin)
			api.AssertIsEqual(c.OutEnergy[i], expectedEnergy)
		}
	}

	return nil
}

// // Define implements the constraints for CircuitTxFN using dynamic arrays and for loops.
// func (c *CircuitTxFN) Define(api frontend.API) error {
// 	// Process all N coins using a for loop
// 	for coin := 0; coin < c.N; coin++ {
// 		// --- Decrypt and verify the registration data ---
// 		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
// 		for i := 0; i < 5; i++ {
// 			api.AssertIsEqual(c.DecVal[coin][i], decVal[i])
// 		}

// 		// --- Verify serial number computation ---
// 		snComputed := PRF(api, c.InSk[coin], c.InRho[coin])
// 		api.AssertIsEqual(c.InSn[coin], snComputed)

// 		// --- Compute output commitment: cm = Com(Γ || pk || ρ, r) where Γ = (coins, energy) ---
// 		hasher, _ := mimc.NewMiMC(api)
// 		hasher.Write(c.OutCoin[coin])   // Γ.coins
// 		hasher.Write(c.OutEnergy[coin]) // Γ.energy
// 		hasher.Write(c.OutPk[coin])     // pk (public key)
// 		hasher.Write(c.OutRho[coin])    // ρ (rho)
// 		hasher.Write(c.OutRand[coin])   // r (randomness)
// 		cm := hasher.Sum()
// 		api.AssertIsEqual(c.OutCm[coin], cm)

// 		// --- Verify DH encryption constraints ---
// 		// EncKey = G_b^R (same variable used for both decryption and DH verification)
// 		G_r_b := new(sw_bls12377.G1Affine)
// 		G_r_b.ScalarMul(api, c.G_b[coin], c.R[coin])
// 		api.AssertIsEqual(c.EncKey[coin].X, G_r_b.X)
// 		api.AssertIsEqual(c.EncKey[coin].Y, G_r_b.Y)

// 		// G_r = G^R
// 		G_r := new(sw_bls12377.G1Affine)
// 		G_r.ScalarMul(api, c.G[coin], c.R[coin])
// 		api.AssertIsEqual(c.G_r[coin].X, G_r.X)
// 		api.AssertIsEqual(c.G_r[coin].Y, G_r.Y)

// 		// --- Verify public key derivation: InPk = MiMC(InSk) ---
// 		hasher.Reset()
// 		hasher.Write(c.InSk[coin])
// 		pk := hasher.Sum()
// 		api.AssertIsEqual(c.InPk[coin], pk)
// 	}

// 	// --- Verify auction sorting constraints ---
// 	// First half (0 to N/2-1) are buyers: DecVal[i][2] should be in descending order (highest bid first)
// 	// Second half (N/2 to N-1) are sellers: DecVal[i][2] should be in ascending order (lowest ask first)
// 	halfN := c.N / 2

// 	// Verify buyers are sorted in descending order (highest bid first)
// 	for i := 0; i < halfN-1; i++ {
// 		// For buyers: DecVal[i][2] >= DecVal[i+1][2]
// 		// Use api.AssertIsLessOrEqual to verify DecVal[i+1][2] <= DecVal[i][2]
// 		api.AssertIsLessOrEqual(c.DecVal[i+1][2], c.DecVal[i][2])
// 	}

// 	// Verify sellers are sorted in ascending order (lowest ask first)
// 	for i := halfN; i < c.N-1; i++ {
// 		// For sellers: DecVal[i][2] <= DecVal[i+1][2]
// 		api.AssertIsLessOrEqual(c.DecVal[i][2], c.DecVal[i+1][2])
// 	}

// 	// --- Implement auction trading logic ---
// 	// Define clearing price as the ask of seller number N/2 (first seller)
// 	clearingPrice := c.DecVal[halfN][2]

// 	// Process trading for all participants
// 	for i := 0; i < c.N; i++ {
// 		if i < halfN {
// 			// This is a buyer (index 0 to N/2-1)
// 			// Buyer qualifies if their bid >= clearing price

// 			// Buyer qualifies if their bid >= clearing price
// 			// Calculate trading results
// 			tradingCost := api.Mul(clearingPrice, TRADING_VOLUME)
// 			coinAfterTrade := api.Sub(c.InCoin[i], tradingCost)
// 			energyAfterTrade := api.Add(c.InEnergy[i], TRADING_VOLUME)

// 			// Buyer qualifies if bid >= clearing price
// 			// Use conditional logic: if qualified, apply trading; else keep original

// 			// Calculate qualification: 1 if bid >= clearing, 0 otherwise
// 			qualified := api.IsZero(api.IsZero(api.Sub(c.DecVal[i][2], clearingPrice)))

// 			// Apply trading only if qualified using multiplication
// 			tradingDelta := api.Mul(qualified, api.Sub(coinAfterTrade, c.InCoin[i]))
// 			energyDelta := api.Mul(qualified, api.Sub(energyAfterTrade, c.InEnergy[i]))

// 			c.OutCoin[i] = api.Add(c.InCoin[i], tradingDelta)
// 			c.OutEnergy[i] = api.Add(c.InEnergy[i], energyDelta)
// 		} else {
// 			// This is a seller (index N/2 to N-1)
// 			// Seller qualifies if their ask <= clearing price

// 			// Seller qualifies if their ask <= clearing price
// 			// Calculate trading results
// 			tradingRevenue := api.Mul(clearingPrice, TRADING_VOLUME)
// 			coinAfterTrade := api.Add(c.InCoin[i], tradingRevenue)
// 			energyAfterTrade := api.Sub(c.InEnergy[i], TRADING_VOLUME)

// 			// Seller qualifies if ask <= clearing price
// 			// Use conditional logic: if qualified, apply trading; else keep original

// 			// Calculate qualification: 1 if ask <= clearing, 0 otherwise
// 			qualified := api.IsZero(api.IsZero(api.Sub(clearingPrice, c.DecVal[i][2])))

// 			// Apply trading only if qualified using multiplication
// 			tradingDelta := api.Mul(qualified, api.Sub(coinAfterTrade, c.InCoin[i]))
// 			energyDelta := api.Mul(qualified, api.Sub(energyAfterTrade, c.InEnergy[i]))

// 			c.OutCoin[i] = api.Add(c.InCoin[i], tradingDelta)
// 			c.OutEnergy[i] = api.Add(c.InEnergy[i], energyDelta)
// 		}
// 	}

// 	return nil
// }

// CircuitTxF10 represents a circuit for 10 coins/participants in the auction phase.
// DEPRECATED: Use CircuitTxFN instead for better scalability.
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
	R      [10]frontend.Variable
	G      [10]sw_bls12377.G1Affine `gnark:",public"`
	G_b    [10]sw_bls12377.G1Affine `gnark:",public"`
	G_r    [10]sw_bls12377.G1Affine `gnark:",public"`
	EncKey [10]sw_bls12377.G1Affine // DH shared secret: used for both decryption and DH verification
}

// CircuitTxF20 represents a circuit for 20 coins/participants in the auction phase.
// DEPRECATED: Use CircuitTxFN instead for better scalability.
type CircuitTxF20 struct {
	// ----- Input/Output Arrays for 20 coins -----
	InCoin   [20]frontend.Variable `gnark:",public"`
	InEnergy [20]frontend.Variable `gnark:",public"`
	InCm     [20]frontend.Variable `gnark:",public"`
	InSn     [20]frontend.Variable `gnark:",public"`
	InPk     [20]frontend.Variable `gnark:",public"`
	InSk     [20]frontend.Variable `gnark:",public"`
	InRho    [20]frontend.Variable `gnark:",public"`
	InRand   [20]frontend.Variable `gnark:",public"`

	OutCoin   [20]frontend.Variable `gnark:",public"`
	OutEnergy [20]frontend.Variable `gnark:",public"`
	OutCm     [20]frontend.Variable `gnark:",public"`
	OutSn     [20]frontend.Variable `gnark:",public"`
	OutPk     [20]frontend.Variable `gnark:",public"`
	OutRho    [20]frontend.Variable `gnark:",public"`
	OutRand   [20]frontend.Variable `gnark:",public"`

	C      [20][5]frontend.Variable
	DecVal [20][5]frontend.Variable

	// ----- DH Parameters for each coin -----
	R      [20]frontend.Variable
	G      [20]sw_bls12377.G1Affine `gnark:",public"`
	G_b    [20]sw_bls12377.G1Affine `gnark:",public"`
	G_r    [20]sw_bls12377.G1Affine `gnark:",public"`
	EncKey [20]sw_bls12377.G1Affine // DH shared secret: used for both decryption and DH verification
}

// Define implements the constraints for CircuitTxF10 using arrays and for loops.
func (c *CircuitTxF10) Define(api frontend.API) error {
	// Process all 10 coins using a for loop
	for coin := 0; coin < 10; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
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
		// EncKey = G_b^R (same variable used for both decryption and DH verification)
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

// Define implements the constraints for CircuitTxF20 using arrays and for loops.
func (c *CircuitTxF20) Define(api frontend.API) error {
	// Process all 20 coins using a for loop
	for coin := 0; coin < 20; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
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
		// EncKey = G_b^R (same variable used for both decryption and DH verification)
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
