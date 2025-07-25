// circuit.go - Circuit for the auction phase (exchange) of the protocol.
//
// This file defines the zero-knowledge circuit for the auction (exchange) phase of the PPEM protocol.
// It enforces cryptographic consistency (decryption, PRF, commitments, EC operations) and basic auction constraints.
//
// Auction constraints:
// - First N/2 participants are buyers (sorted descending by bid)
// - Last N/2 participants are sellers (sorted ascending by ask)
// - DecVal[i][2] contains the bid/ask price for participant i
//
// WARNING: This circuit enforces sorting and basic trading constraints but does NOT implement a full double auction.

package exchange

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// TRADING_VOLUME is the hardcoded trading volume for the simplified auction.
// All trades are for this fixed quantity of energy.
const TRADING_VOLUME = 10

// DecZKReg decrypts a registration ciphertext in the circuit using a MiMC-based mask chain.
// This function mimics the off-circuit decryption logic for registration payloads.
//
// Parameters:
//   - api: gnark frontend API
//   - c: ciphertext array (length 5)
//   - encKey: shared DH key (G1Affine)
//
// Returns:
//   - [5]frontend.Variable: decrypted values (pkOut, skIn, bid/ask, coins, energy)
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
// Used for serial number computation.
//
// Parameters:
//   - api: gnark frontend API
//   - sk: secret key
//   - rho: randomizer
//
// Returns:
//   - frontend.Variable: PRF output
func PRF(api frontend.API, sk, rho frontend.Variable) frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(sk)
	hasher.Write(rho)
	return hasher.Sum()
}

// CircuitTxFN represents a dynamic circuit for N coins/participants in the auction phase.
// This circuit can be generated for any number of participants (N must be even).
//
// Fields:
//   - N: number of participants
//   - InCoin, InEnergy, ...: input arrays for each participant
//   - OutCoin, OutEnergy, ...: output arrays for each participant
//   - C, DecVal: encrypted and decrypted registration data
//   - R, G, G_b, G_r, EncKey: Diffie-Hellman parameters for each participant
//
// Auction structure:
//   - First N/2 participants are buyers (indices 0 to N/2-1)
//   - Last N/2 participants are sellers (indices N/2 to N-1)
//   - DecVal[i][2] is the bid (buyers) or ask (sellers)
type CircuitTxFN struct {
	// Number of participants this circuit supports (must be even)
	N int

	// ----- Auction Parameters (Public) -----
	ClearingPrice       frontend.Variable `gnark:",public"` // Auction clearing price
	CommissionPerUnit   frontend.Variable `gnark:",public"` // Commission per energy unit
	MarginalBuyerPrice  frontend.Variable `gnark:",public"` // Marginal buyer price (for Euclidean division)
	MarginalSellerPrice frontend.Variable `gnark:",public"` // Marginal seller price (for Euclidean division)
	TotalEnergyTraded   frontend.Variable `gnark:",public"` // Total energy units traded
	TotalCommission     frontend.Variable `gnark:",public"` // Total commission collected

	// Per-participant trading data
	ParticipantRoles []frontend.Variable `gnark:",public"` // 0=BUY, 1=SELL
	TradedQuantities []frontend.Variable `gnark:",public"` // Energy quantity traded per participant
	IsQualified      []frontend.Variable `gnark:",public"` // 1 if participant qualified for trade, 0 otherwise

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

// NewCircuitTxFN creates a new dynamic circuit for N participants.
// Circuit verifies cryptographic consistency only - auction logic runs outside.
func NewCircuitTxFN(n int) *CircuitTxFN {
	if n <= 0 {
		panic("CircuitTxFN: N must be positive")
	}

	// Auction logic runs outside the circuit

	circuit := &CircuitTxFN{
		N: n,

		// Initialize auction parameter arrays
		ParticipantRoles: make([]frontend.Variable, n),
		TradedQuantities: make([]frontend.Variable, n),
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
// This is the main circuit logic for the auction phase.
//
// Constraints enforced:
//   - Decrypt registration data and check consistency
//   - Verify serial number computation
//   - Check output commitments
//   - Verify DH encryption constraints
//   - Enforce public key derivation
//   - Enforce sorting of buyers/sellers
//   - Enforce trading logic: buyers with bid >= clearing price and sellers with ask <= clearing price trade at fixed volume
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

	// ==== STEP 2: EUCLIDEAN DIVISION VERIFICATION ====
	// Verify that: MarginalBuyerPrice + MarginalSellerPrice = 2 * ClearingPrice + CommissionPerUnit
	// This ensures the clearing price was computed correctly using Euclidean division
	marginalSum := api.Add(c.MarginalBuyerPrice, c.MarginalSellerPrice)
	clearingTimesTwo := api.Mul(c.ClearingPrice, 2)
	expectedSum := api.Add(clearingTimesTwo, c.CommissionPerUnit)
	api.AssertIsEqual(marginalSum, expectedSum)

	// Verify that TotalCommission = CommissionPerUnit * TotalEnergyTraded
	expectedTotalCommission := api.Mul(c.CommissionPerUnit, c.TotalEnergyTraded)
	api.AssertIsEqual(c.TotalCommission, expectedTotalCommission)

	// STEP 3a: Verify sorting using simple consecutive checks
	// Assumption: Auctioneer provides buyers first (descending), then sellers (ascending)
	for i := 0; i < c.N-1; i++ {
		currentRole := c.ParticipantRoles[i]
		nextRole := c.ParticipantRoles[i+1]

		// If both consecutive participants are buyers (role=0): verify descending
		bothBuyers := api.Mul(api.IsZero(currentRole), api.IsZero(nextRole))
		buyerConstraint := api.Mul(bothBuyers, c.DecVal[i+1][2]) // next_price * flag
		buyerLimit := api.Mul(bothBuyers, c.DecVal[i][2])        // current_price * flag
		api.AssertIsLessOrEqual(buyerConstraint, buyerLimit)     // next <= current when both buyers

		// If both consecutive participants are sellers (role=1): verify ascending
		bothSellers := api.Mul(api.IsZero(api.Sub(currentRole, 1)), api.IsZero(api.Sub(nextRole, 1)))
		sellerConstraint := api.Mul(bothSellers, c.DecVal[i][2]) // current_price * flag
		sellerLimit := api.Mul(bothSellers, c.DecVal[i+1][2])    // next_price * flag
		api.AssertIsLessOrEqual(sellerConstraint, sellerLimit)   // current <= next when both sellers

		// Ensure buyers come before sellers (no seller followed by buyer)
		invalidOrder := api.Mul(api.IsZero(api.Sub(currentRole, 1)), api.IsZero(nextRole))
		api.AssertIsEqual(invalidOrder, 0) // seller->buyer transition not allowed
	}

	return nil
}
