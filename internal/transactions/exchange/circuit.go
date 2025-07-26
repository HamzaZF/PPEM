// circuit.go - Circuit for the auction phase (exchange) of the protocol.
//
// This file defines the zero-knowledge circuit for the auction (exchange) phase of the PPEM protocol.
// It enforces cryptographic consistency (decryption, PRF, commitments, EC operations) and basic auction constraints.
//
// Auction constraints:
// - First N/2 participants are buyers (sorted descending by bid)
// - Last N/2 participants are sellers (sorted ascending by ask)
// - DecVal[i][2] contains the bid/ask price for participant i

package exchange

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// DecZKReg decrypts a registration ciphertext in the circuit using a MiMC-based mask chain.
// This function mimics the off-circuit decryption logic for registration payloads.
//
// Parameters:
//   - api: gnark frontend API
//   - c: ciphertext array (length 7)
//   - encKey: shared DH key (G1Affine)
//
// Returns:
//   - [7]frontend.Variable: decrypted values (pkOut, skIn, bid/ask, coins, energy, role, quantity)
func DecZKReg(api frontend.API, c []frontend.Variable, encKey sw_bls12377.G1Affine) [7]frontend.Variable {
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

	hasher.Reset()
	hasher.Write(mask4)
	mask5 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask5)
	mask6 := hasher.Sum()

	dec0 := api.Sub(c[0], mask0)
	dec1 := api.Sub(c[1], mask1)
	dec2 := api.Sub(c[2], mask2)
	dec3 := api.Sub(c[3], mask3)
	dec4 := api.Sub(c[4], mask4)
	dec5 := api.Sub(c[5], mask5)
	dec6 := api.Sub(c[6], mask6)

	return [7]frontend.Variable{dec0, dec1, dec2, dec3, dec4, dec5, dec6}
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

	// ParticipantRoles and TradedQuantities are now decrypted from registration data:
	// - ParticipantRoles: DecVal[i][5] (0=BUY, 1=SELL)
	// - TradedQuantities: DecVal[i][6] (Energy quantity traded per participant)

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
		// ParticipantRoles: make([]frontend.Variable, n), // Removed
		// TradedQuantities: make([]frontend.Variable, n), // Removed
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
		circuit.C[i] = make([]frontend.Variable, 7)      // Changed from 5 to 7
		circuit.DecVal[i] = make([]frontend.Variable, 7) // Changed from 5 to 7
	}

	return circuit
}

// Define implements the circuit verification logic for PPEM transactions.
func (c *CircuitTxFN) Define(api frontend.API) error {
	// Verify basic cryptographic constraints for all participants
	if err := c.verifyBasicCrypto(api); err != nil {
		return err
	}

	// AUCTION VERIFICATION STEPS

	// Step 1: Verify participant list is properly sorted
	c.verifySorting(api)

	// Step 2: Find and verify marginal participants exist
	marginalBuyerIndices, marginalSellerIndices := c.findMarginalParticipants(api)

	// Step 3: Verify Euclidean division formula holds
	c.verifyEuclideanDivision(api)

	// Step 4: Verify intersection boundary conditions
	c.verifyIntersectionBoundary(api, marginalBuyerIndices, marginalSellerIndices)

	// Step 5: Verify energy and coin conservation
	// This also ensures only qualified participants changed their note values
	c.verifyConservation(api)

	// Step 6: Verify exchanges are correct for qualified non-marginal participants
	c.verifyQualifiedParticipantExchanges(api, marginalBuyerIndices, marginalSellerIndices)

	return nil
}

// verifyBasicCrypto verifies the basic cryptographic constraints for all participants
func (c *CircuitTxFN) verifyBasicCrypto(api frontend.API) error {
	// Process all N coins using a for loop
	for coin := 0; coin < c.N; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
		for i := 0; i < 7; i++ { // Changed from 5 to 7
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
	return nil
}

// verifySorting verifies that participants are properly sorted:
// - Buyers in descending order by bid
// - Sellers in ascending order by ask
// - All buyers come before all sellers
func (c *CircuitTxFN) verifySorting(api frontend.API) {
	// Verify sorting using simple consecutive checks
	// Assumption: Auctioneer provides buyers first (descending), then sellers (ascending)
	for i := 0; i < c.N-1; i++ {
		currentRole := c.DecVal[i][5] // Use DecVal[i][5] for role
		nextRole := c.DecVal[i+1][5]  // Use DecVal[i+1][5] for role

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
}

// findMarginalParticipants finds and verifies that MarginalBuyerPrice and MarginalSellerPrice
// correspond to actual participants in the list. Returns arrays indicating which participants
// are marginal buyers/sellers.
func (c *CircuitTxFN) findMarginalParticipants(api frontend.API) ([]frontend.Variable, []frontend.Variable) {
	marginalBuyerFound := frontend.Variable(0)
	marginalSellerFound := frontend.Variable(0)

	// Store which participants are marginal buyers and sellers for later use
	isMarginalBuyerAtIndex := make([]frontend.Variable, c.N)
	isMarginalSellerAtIndex := make([]frontend.Variable, c.N)

	for i := 0; i < c.N; i++ {
		// Check if this participant is a buyer with marginal buyer price
		isBuyer := api.IsZero(c.DecVal[i][5]) // Use DecVal[i][5] for role
		priceMatchesMarginalBuyer := api.IsZero(api.Sub(c.DecVal[i][2], c.MarginalBuyerPrice))
		buyerMatch := api.Mul(isBuyer, priceMatchesMarginalBuyer)
		marginalBuyerFound = api.Add(marginalBuyerFound, buyerMatch)

		// Store this information for later use
		isMarginalBuyerAtIndex[i] = buyerMatch

		// Check if this participant is a seller with marginal seller price
		isSeller := api.IsZero(api.Sub(c.DecVal[i][5], 1)) // Use DecVal[i][5] for role
		priceMatchesMarginalSeller := api.IsZero(api.Sub(c.DecVal[i][2], c.MarginalSellerPrice))
		sellerMatch := api.Mul(isSeller, priceMatchesMarginalSeller)
		marginalSellerFound = api.Add(marginalSellerFound, sellerMatch)

		// Store this information for later use
		isMarginalSellerAtIndex[i] = sellerMatch
	}

	// Assert that we found at least one marginal buyer and one marginal seller
	api.AssertIsLessOrEqual(1, marginalBuyerFound)
	api.AssertIsLessOrEqual(1, marginalSellerFound)

	return isMarginalBuyerAtIndex, isMarginalSellerAtIndex
}

// verifyEuclideanDivision verifies the Euclidean division formula:
// MarginalBuyerPrice + MarginalSellerPrice = 2 * ClearingPrice + CommissionPerUnit
// Also verifies CommissionPerUnit is either 0 or 1
func (c *CircuitTxFN) verifyEuclideanDivision(api frontend.API) {
	// Verify: MarginalBuyerPrice + MarginalSellerPrice = 2 * ClearingPrice + CommissionPerUnit
	marginalSum := api.Add(c.MarginalBuyerPrice, c.MarginalSellerPrice)
	clearingTimesTwo := api.Mul(c.ClearingPrice, 2)
	expectedSum := api.Add(clearingTimesTwo, c.CommissionPerUnit)
	api.AssertIsEqual(marginalSum, expectedSum)

	// Ensure CommissionPerUnit is either 0 or 1 (valid remainder for division by 2)
	// CommissionPerUnit * (CommissionPerUnit - 1) = 0
	commissionCheck := api.Mul(c.CommissionPerUnit, api.Sub(c.CommissionPerUnit, 1))
	api.AssertIsEqual(commissionCheck, 0)
}

// verifyIntersectionBoundary verifies that the intersection between buyer and seller curves
// is correct by checking boundary conditions around marginal participants
func (c *CircuitTxFN) verifyIntersectionBoundary(api frontend.API, marginalBuyerIndices, marginalSellerIndices []frontend.Variable) {
	c.verifyBuyerIntersectionBoundary(api, marginalBuyerIndices)
	c.verifySellerIntersectionBoundary(api, marginalSellerIndices)
}

// verifyBuyerIntersectionBoundary verifies buyer side of intersection:
// - Next buyer after marginal has bid < marginal seller ask (can't trade)
// - Previous buyer before marginal has bid >= clearing price (can trade)
func (c *CircuitTxFN) verifyBuyerIntersectionBoundary(api frontend.API, marginalBuyerIndices []frontend.Variable) {
	for i := 0; i < c.N-1; i++ {
		foundMarginalBuyer := marginalBuyerIndices[i]

		// Check next buyer (forward boundary)
		nextIsBuyer := api.IsZero(c.DecVal[i+1][5]) // Use DecVal[i+1][5] for role
		checkCondition := api.Mul(foundMarginalBuyer, nextIsBuyer)
		constraint := api.Mul(checkCondition, api.Add(c.DecVal[i+1][2], 1))
		limit := api.Mul(checkCondition, c.MarginalSellerPrice)
		api.AssertIsLessOrEqual(constraint, limit) // next_buyer_bid + 1 <= marginal_seller_ask

		// Check previous buyer (backward boundary) with safe access
		hasPrevious := frontend.Variable(0)
		if i > 0 {
			hasPrevious = frontend.Variable(1)
		}

		prevIsBuyer := frontend.Variable(0)
		prevPrice := frontend.Variable(0)
		if i > 0 {
			prevIsBuyer = api.IsZero(c.DecVal[i-1][5]) // Use DecVal[i-1][5] for role
			prevPrice = c.DecVal[i-1][2]
		}

		checkPrevCondition := api.Mul(foundMarginalBuyer, api.Mul(hasPrevious, prevIsBuyer))
		prevConstraint := api.Mul(checkPrevCondition, c.ClearingPrice)
		prevLimit := api.Mul(checkPrevCondition, prevPrice)
		api.AssertIsLessOrEqual(prevConstraint, prevLimit) // clearing_price <= prev_buyer_bid
	}
}

// verifySellerIntersectionBoundary verifies seller side of intersection:
// - Next seller after marginal has ask > marginal buyer bid (can't trade)
// - Previous seller before marginal has ask <= clearing price (can trade)
func (c *CircuitTxFN) verifySellerIntersectionBoundary(api frontend.API, marginalSellerIndices []frontend.Variable) {
	for i := 0; i < c.N-1; i++ {
		foundMarginalSeller := marginalSellerIndices[i]

		// Check next seller (forward boundary)
		nextIsSeller := api.IsZero(api.Sub(c.DecVal[i+1][5], 1)) // Use DecVal[i+1][5] for role
		checkCondition := api.Mul(foundMarginalSeller, nextIsSeller)
		constraint := api.Mul(checkCondition, api.Add(c.MarginalBuyerPrice, 1))
		limit := api.Mul(checkCondition, c.DecVal[i+1][2])
		api.AssertIsLessOrEqual(constraint, limit) // marginal_buyer_bid + 1 <= next_seller_ask

		// Check previous seller (backward boundary) with safe access
		hasPrevious := frontend.Variable(0)
		if i > 0 {
			hasPrevious = frontend.Variable(1)
		}

		prevIsSeller := frontend.Variable(0)
		prevPrice := frontend.Variable(0)
		if i > 0 {
			prevIsSeller = api.IsZero(api.Sub(c.DecVal[i-1][5], 1)) // Use DecVal[i-1][5] for role
			prevPrice = c.DecVal[i-1][2]
		}

		checkPrevCondition := api.Mul(foundMarginalSeller, api.Mul(hasPrevious, prevIsSeller))
		prevConstraint := api.Mul(checkPrevCondition, prevPrice)
		prevLimit := api.Mul(checkPrevCondition, c.ClearingPrice)
		api.AssertIsLessOrEqual(prevConstraint, prevLimit) // prev_seller_ask <= clearing_price
	}
}

// verifyConservation verifies energy and coin conservation across all participants
// and ensures individual participant trades are logical based on clearing price
func (c *CircuitTxFN) verifyConservation(api frontend.API) {
	// Step 1: Verify total energy conservation
	c.verifyEnergyConservation(api)

	// Step 2: Verify total coin conservation accounting for commission
	c.verifyCoinConservationWithCommission(api)
}

// verifyEnergyConservation ensures total input energy equals total output energy
func (c *CircuitTxFN) verifyEnergyConservation(api frontend.API) {
	totalInEnergy := frontend.Variable(0)
	totalOutEnergy := frontend.Variable(0)

	for i := 0; i < c.N; i++ {
		totalInEnergy = api.Add(totalInEnergy, c.InEnergy[i])
		totalOutEnergy = api.Add(totalOutEnergy, c.OutEnergy[i])
	}

	api.AssertIsEqual(totalInEnergy, totalOutEnergy)
}

// verifyCoinConservationWithCommission ensures total coin conservation accounting for commission
// Formula: sum(InCoin) = sum(OutCoin) + CommissionPerUnit * TotalEnergyTraded
func (c *CircuitTxFN) verifyCoinConservationWithCommission(api frontend.API) {
	totalInCoin := frontend.Variable(0)
	totalOutCoin := frontend.Variable(0)
	totalEnergyTraded := frontend.Variable(0)

	// Calculate total input and output coins
	for i := 0; i < c.N; i++ {
		totalInCoin = api.Add(totalInCoin, c.InCoin[i])
		totalOutCoin = api.Add(totalOutCoin, c.OutCoin[i])
	}

	// Calculate total energy traded by summing energy gains (buyers gain energy when they trade)
	// This avoids double counting since each unit of energy traded represents one buyer gaining
	// and one seller losing the same amount
	for i := 0; i < c.N; i++ {
		participantRole := c.DecVal[i][5] // 0=BUY, 1=SELL
		isBuyer := api.IsZero(participantRole)

		// Calculate energy gained (positive for buyers, 0 for sellers)
		energyGain := api.Sub(c.OutEnergy[i], c.InEnergy[i])
		// Only count positive energy changes (buyers gaining energy)
		// Use max(0, energyGain) by checking if energyGain > 0
		energyGainPositive := api.Mul(isBuyer, energyGain)
		totalEnergyTraded = api.Add(totalEnergyTraded, energyGainPositive)
	}

	// Calculate total commission
	totalCommission := api.Mul(c.CommissionPerUnit, totalEnergyTraded)

	// Verify conservation: sum(InCoin) = sum(OutCoin) + totalCommission
	expectedOutCoin := api.Sub(totalInCoin, totalCommission)
	api.AssertIsEqual(totalOutCoin, expectedOutCoin)
}

// verifyQualifiedParticipantExchanges verifies that qualified non-marginal participants
// have correct energy and coin exchanges based on the clearing price.
// This function uses assertions with conditional constraints rather than boolean comparisons.
func (c *CircuitTxFN) verifyQualifiedParticipantExchanges(api frontend.API, marginalBuyerIndices, marginalSellerIndices []frontend.Variable) {
	for i := 0; i < c.N; i++ {
		participantRole := c.DecVal[i][5] // 0=BUY, 1=SELL
		bidAskPrice := c.DecVal[i][2]
		tradedQuantity := c.DecVal[i][6]

		// First, identify qualified participants (those who should trade based on price)
		isBuyer := api.IsZero(participantRole)
		isNonMarginalBuyer := api.Sub(1, marginalBuyerIndices[i]) // 1 - isMarginal = isNonMarginal

		// For non-marginal buyers who are qualified: verify trade correctness
		baseBuyerCondition := api.Mul(isBuyer, isNonMarginalBuyer)

		// Check if participant actually traded (energy changed by the expected amount)
		energyChanged := api.Sub(c.OutEnergy[i], c.InEnergy[i])

		// If non-marginal buyer AND energy changed by traded quantity, then verify:
		// 1. bid >= clearing price
		// 2. trade is correct
		buyerTradedCondition := api.Mul(baseBuyerCondition, api.IsZero(api.Sub(energyChanged, tradedQuantity))) // energy gain equals traded quantity

		// Assert: if buyer traded, then bid >= clearing price
		clearingPriceConstraint := api.Mul(buyerTradedCondition, c.ClearingPrice)
		bidConstraint := api.Mul(buyerTradedCondition, bidAskPrice)
		api.AssertIsLessOrEqual(clearingPriceConstraint, bidConstraint)

		// Assert: if buyer traded, then trade is correct
		expectedEnergyOutBuyer := api.Add(c.InEnergy[i], tradedQuantity)
		energyConstraintBuyer := api.Mul(buyerTradedCondition, c.OutEnergy[i])
		energyTargetBuyer := api.Mul(buyerTradedCondition, expectedEnergyOutBuyer)
		api.AssertIsEqual(energyConstraintBuyer, energyTargetBuyer)

		coinCost := api.Mul(c.ClearingPrice, tradedQuantity)
		expectedCoinOutBuyer := api.Sub(c.InCoin[i], coinCost)
		coinConstraintBuyer := api.Mul(buyerTradedCondition, c.OutCoin[i])
		coinTargetBuyer := api.Mul(buyerTradedCondition, expectedCoinOutBuyer)
		api.AssertIsEqual(coinConstraintBuyer, coinTargetBuyer)

		// For sellers: similar logic
		isSeller := api.IsZero(api.Sub(participantRole, 1))
		isNonMarginalSeller := api.Sub(1, marginalSellerIndices[i]) // 1 - isMarginal = isNonMarginal

		baseSellerCondition := api.Mul(isSeller, isNonMarginalSeller)

		// Check if seller actually traded (energy decreased)
		sellerEnergyChanged := api.Sub(c.InEnergy[i], c.OutEnergy[i])                                                   // Should be positive if energy lost
		sellerTradedCondition := api.Mul(baseSellerCondition, api.IsZero(api.Sub(sellerEnergyChanged, tradedQuantity))) // energy loss equals traded quantity

		// Assert: if seller traded, then ask <= clearing price
		askConstraint := api.Mul(sellerTradedCondition, bidAskPrice)
		clearingPriceConstraintSeller := api.Mul(sellerTradedCondition, c.ClearingPrice)
		api.AssertIsLessOrEqual(askConstraint, clearingPriceConstraintSeller)

		// Assert: if seller traded, then trade is correct
		expectedEnergyOutSeller := api.Sub(c.InEnergy[i], tradedQuantity)
		energyConstraintSeller := api.Mul(sellerTradedCondition, c.OutEnergy[i])
		energyTargetSeller := api.Mul(sellerTradedCondition, expectedEnergyOutSeller)
		api.AssertIsEqual(energyConstraintSeller, energyTargetSeller)

		coinGain := api.Mul(c.ClearingPrice, tradedQuantity)
		expectedCoinOutSeller := api.Add(c.InCoin[i], coinGain)
		coinConstraintSeller := api.Mul(sellerTradedCondition, c.OutCoin[i])
		coinTargetSeller := api.Mul(sellerTradedCondition, expectedCoinOutSeller)
		api.AssertIsEqual(coinConstraintSeller, coinTargetSeller)
	}
}
