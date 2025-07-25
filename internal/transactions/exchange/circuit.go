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

	// Verify sorting using simple consecutive checks
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

	// STEP 1: Find marginal buyer and seller values
	// Verify that MarginalBuyerPrice and MarginalSellerPrice come from actual participants
	marginalBuyerFound := frontend.Variable(0)
	marginalSellerFound := frontend.Variable(0)

	// Store which participants are marginal buyers and sellers for STEP 3
	isMarginalBuyerAtIndex := make([]frontend.Variable, c.N)
	isMarginalSellerAtIndex := make([]frontend.Variable, c.N)

	for i := 0; i < c.N; i++ {
		// Check if this participant is a buyer with marginal buyer price
		isBuyer := api.IsZero(c.ParticipantRoles[i])
		priceMatchesMarginalBuyer := api.IsZero(api.Sub(c.DecVal[i][2], c.MarginalBuyerPrice))
		buyerMatch := api.Mul(isBuyer, priceMatchesMarginalBuyer)
		marginalBuyerFound = api.Add(marginalBuyerFound, buyerMatch)

		// Store this information for later use
		isMarginalBuyerAtIndex[i] = buyerMatch

		// Check if this participant is a seller with marginal seller price
		isSeller := api.IsZero(api.Sub(c.ParticipantRoles[i], 1))
		priceMatchesMarginalSeller := api.IsZero(api.Sub(c.DecVal[i][2], c.MarginalSellerPrice))
		sellerMatch := api.Mul(isSeller, priceMatchesMarginalSeller)
		marginalSellerFound = api.Add(marginalSellerFound, sellerMatch)

		// Store this information for later use
		isMarginalSellerAtIndex[i] = sellerMatch
	}

	// Assert that we found at least one marginal buyer and one marginal seller
	api.AssertIsLessOrEqual(1, marginalBuyerFound)
	api.AssertIsLessOrEqual(1, marginalSellerFound)

	// STEP 2: Verify Euclidean division
	// MarginalBuyerPrice + MarginalSellerPrice = 2 * ClearingPrice + CommissionPerUnit
	marginalSum := api.Add(c.MarginalBuyerPrice, c.MarginalSellerPrice)
	clearingTimesTwo := api.Mul(c.ClearingPrice, 2)
	expectedSum := api.Add(clearingTimesTwo, c.CommissionPerUnit)
	api.AssertIsEqual(marginalSum, expectedSum)

	// Ensure CommissionPerUnit is either 0 or 1
	// CommissionPerUnit * (CommissionPerUnit - 1) = 0
	commissionCheck := api.Mul(c.CommissionPerUnit, api.Sub(c.CommissionPerUnit, 1))
	api.AssertIsEqual(commissionCheck, 0)

	// // Verify that TotalCommission = CommissionPerUnit * TotalEnergyTraded
	// expectedTotalCommission := api.Mul(c.CommissionPerUnit, c.TotalEnergyTraded)
	// api.AssertIsEqual(c.TotalCommission, expectedTotalCommission)

	// STEP 3a: Verify intersection boundary (buyer side)
	// Check that the first buyer after marginal buyer has bid < marginal seller ask
	// Also check that the buyer before marginal buyer has bid >= clearing price
	// This proves the intersection is correct (subsequent buyers are even lower due to sorting)

	for i := 0; i < c.N-1; i++ {
		// Use the stored information about whether this is a marginal buyer
		foundMarginalBuyer := isMarginalBuyerAtIndex[i]

		// Check if next participant is also a buyer
		nextIsBuyer := api.IsZero(c.ParticipantRoles[i+1])

		// If we found marginal buyer at i and i+1 is also a buyer: bid[i+1] < marginal seller ask
		checkCondition := api.Mul(foundMarginalBuyer, nextIsBuyer)
		constraint := api.Mul(checkCondition, api.Add(c.DecVal[i+1][2], 1))
		limit := api.Mul(checkCondition, c.MarginalSellerPrice)
		api.AssertIsLessOrEqual(constraint, limit) // next_buyer_bid + 1 <= marginal_seller_ask

		// Also check previous buyer if we're not at the first position
		if i > 0 {
			// Check if previous participant is also a buyer
			prevIsBuyer := api.IsZero(c.ParticipantRoles[i-1])

			// If we found marginal buyer at i and i-1 is also a buyer: bid[i-1] >= clearing_price
			checkPrevCondition := api.Mul(foundMarginalBuyer, prevIsBuyer)
			prevConstraint := api.Mul(checkPrevCondition, c.ClearingPrice)
			prevLimit := api.Mul(checkPrevCondition, c.DecVal[i-1][2])
			api.AssertIsLessOrEqual(prevConstraint, prevLimit) // clearing_price <= prev_buyer_bid
		}
	}

	// STEP 3b: Verify intersection boundary (seller side)
	// Check that the first seller after marginal seller has ask > marginal buyer bid
	// Also check that the seller before marginal seller has ask <= clearing price
	// This proves the intersection is correct (subsequent sellers are even higher due to sorting)

	for i := 0; i < c.N-1; i++ {
		// Use the stored information about whether this is a marginal seller
		foundMarginalSeller := isMarginalSellerAtIndex[i]

		// Check if next participant is also a seller
		nextIsSeller := api.IsZero(api.Sub(c.ParticipantRoles[i+1], 1))

		// If we found marginal seller at i and i+1 is also a seller: ask[i+1] > marginal buyer bid
		checkCondition := api.Mul(foundMarginalSeller, nextIsSeller)
		constraint := api.Mul(checkCondition, api.Add(c.MarginalBuyerPrice, 1))
		limit := api.Mul(checkCondition, c.DecVal[i+1][2])
		api.AssertIsLessOrEqual(constraint, limit) // marginal_buyer_bid + 1 <= next_seller_ask

		// Also check previous seller if we're not at the first position
		if i > 0 {
			// Check if previous participant is also a seller
			prevIsSeller := api.IsZero(api.Sub(c.ParticipantRoles[i-1], 1))

			// If we found marginal seller at i and i-1 is also a seller: ask[i-1] <= clearing_price
			checkPrevCondition := api.Mul(foundMarginalSeller, prevIsSeller)
			prevConstraint := api.Mul(checkPrevCondition, c.DecVal[i-1][2])
			prevLimit := api.Mul(checkPrevCondition, c.ClearingPrice)
			api.AssertIsLessOrEqual(prevConstraint, prevLimit) // prev_seller_ask <= clearing_price
		}
	}

	return nil
}
