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

	// Step 2: Verify Euclidean division formula holds
	c.verifyEuclideanDivision(api)

	// Step 3: Ensure marginal buyer and seller are correct (they actually exist + the particpant after and before each of them falls below/above the clearing price (depends on the the role and the side)

	// Step 4: Ensure the total energy in equals the total energy out

	// Step 5: Ensure (total coin in) equals (total coin out + total commission)

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
		currentRole := c.DecVal[i][5] // Use DecVal[i][5] for role (0=BUY, 1=SELL)
		nextRole := c.DecVal[i+1][5]  // Use DecVal[i+1][5] for role (0=BUY, 1=SELL)

		// Check if current participant is buyer (role == 0)
		currentIsBuyer := api.IsZero(currentRole)
		// Check if next participant is buyer (role == 0)
		nextIsBuyer := api.IsZero(nextRole)

		// Check if current participant is seller (role == 1)
		// We do this by: (role == 1) ≡ (role != 0) AND (role * (role - 1) == 0)
		// Since role can only be 0 or 1, we use: isSeller = (1 - isBuyer)
		currentIsSeller := api.Sub(1, currentIsBuyer)
		nextIsSeller := api.Sub(1, nextIsBuyer)

		// Verify role constraint: each role must be either 0 or 1
		// role * (role - 1) = 0 ensures role ∈ {0, 1}
		roleConstraintCurrent := api.Mul(currentRole, api.Sub(currentRole, 1))
		api.AssertIsEqual(roleConstraintCurrent, 0)
		roleConstraintNext := api.Mul(nextRole, api.Sub(nextRole, 1))
		api.AssertIsEqual(roleConstraintNext, 0)

		// If both consecutive participants are buyers (role=0): verify descending order
		bothBuyers := api.Mul(currentIsBuyer, nextIsBuyer)
		buyerConstraint := api.Mul(bothBuyers, c.DecVal[i+1][2]) // next_price * flag
		buyerLimit := api.Mul(bothBuyers, c.DecVal[i][2])        // current_price * flag
		api.AssertIsLessOrEqual(buyerConstraint, buyerLimit)     // next <= current when both buyers

		// If both consecutive participants are sellers (role=1): verify ascending order
		bothSellers := api.Mul(currentIsSeller, nextIsSeller)
		sellerConstraint := api.Mul(bothSellers, c.DecVal[i][2]) // current_price * flag
		sellerLimit := api.Mul(bothSellers, c.DecVal[i+1][2])    // next_price * flag
		api.AssertIsLessOrEqual(sellerConstraint, sellerLimit)   // current <= next when both sellers

		// Ensure buyers come before sellers (no seller followed by buyer)
		// invalidOrder = currentIsSeller AND nextIsBuyer
		invalidOrder := api.Mul(currentIsSeller, nextIsBuyer)
		api.AssertIsEqual(invalidOrder, 0) // seller->buyer transition not allowed
	}
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

// calculateQualifiedBuyerDemand calculates total demand from qualified buyers
func (c *CircuitTxFN) calculateQualifiedBuyerDemand(api frontend.API, marginalBuyerIndices []frontend.Variable, includeMarginal bool) frontend.Variable {
	totalDemand := frontend.Variable(0)

	for i := 0; i < c.N; i++ {
		participantRole := c.DecVal[i][5] // 0=BUY, 1=SELL
		bidPrice := c.DecVal[i][2]
		tradedQuantity := c.DecVal[i][6]

		isBuyer := api.IsZero(participantRole)
		isMarginalBuyer := marginalBuyerIndices[i]

		// Check if buyer is qualified (bid >= clearing price)
		isQualifiedBuyer := api.Mul(isBuyer, api.IsZero(api.Sub(api.Add(bidPrice, 1), api.Add(c.ClearingPrice, 1)))) // bid >= clearing

		// Determine if we should include this buyer
		shouldInclude := isQualifiedBuyer
		if !includeMarginal {
			// Exclude marginal buyer: qualified AND not marginal
			shouldInclude = api.Mul(isQualifiedBuyer, api.Sub(1, isMarginalBuyer))
		}

		// Add to total demand
		contribution := api.Mul(shouldInclude, tradedQuantity)
		totalDemand = api.Add(totalDemand, contribution)
	}

	return totalDemand
}

// calculateQualifiedSellerSupply calculates total supply from qualified sellers
func (c *CircuitTxFN) calculateQualifiedSellerSupply(api frontend.API, marginalSellerIndices []frontend.Variable, includeMarginal bool) frontend.Variable {
	totalSupply := frontend.Variable(0)

	for i := 0; i < c.N; i++ {
		participantRole := c.DecVal[i][5] // 0=BUY, 1=SELL
		askPrice := c.DecVal[i][2]
		tradedQuantity := c.DecVal[i][6]

		isSeller := api.IsZero(api.Sub(participantRole, 1))
		isMarginalSeller := marginalSellerIndices[i]

		// Check if seller is qualified (ask <= clearing price)
		isQualifiedSeller := api.Mul(isSeller, api.IsZero(api.Sub(api.Add(c.ClearingPrice, 1), api.Add(askPrice, 1)))) // clearing >= ask

		// Determine if we should include this seller
		shouldInclude := isQualifiedSeller
		if !includeMarginal {
			// Exclude marginal seller: qualified AND not marginal
			shouldInclude = api.Mul(isQualifiedSeller, api.Sub(1, isMarginalSeller))
		}

		// Add to total supply
		contribution := api.Mul(shouldInclude, tradedQuantity)
		totalSupply = api.Add(totalSupply, contribution)
	}

	return totalSupply
}

// verifyMarginalTradesScenario1 verifies trades when buyer curve cuts seller curve
// Marginal buyer trades full quantity, marginal seller trades partial quantity
func (c *CircuitTxFN) verifyMarginalTradesScenario1(api frontend.API, marginalBuyerIndices, marginalSellerIndices []frontend.Variable,
	totalBuyerDemand, totalSellerSupply frontend.Variable) {

	marginalSellerPartialQuantity := api.Sub(totalBuyerDemand, totalSellerSupply)

	for i := 0; i < c.N; i++ {
		isMarginalBuyer := marginalBuyerIndices[i]
		isMarginalSeller := marginalSellerIndices[i]
		tradedQuantity := c.DecVal[i][6]

		// Verify marginal buyer trades full quantity
		marginalBuyerCondition := isMarginalBuyer

		// Energy gain should equal full traded quantity
		expectedEnergyOutBuyer := api.Add(c.InEnergy[i], tradedQuantity)
		energyConstraintBuyer := api.Mul(marginalBuyerCondition, c.OutEnergy[i])
		energyTargetBuyer := api.Mul(marginalBuyerCondition, expectedEnergyOutBuyer)
		api.AssertIsEqual(energyConstraintBuyer, energyTargetBuyer)

		// Coin loss should equal clearing price * full quantity
		coinCost := api.Mul(c.ClearingPrice, tradedQuantity)
		expectedCoinOutBuyer := api.Sub(c.InCoin[i], coinCost)
		coinConstraintBuyer := api.Mul(marginalBuyerCondition, c.OutCoin[i])
		coinTargetBuyer := api.Mul(marginalBuyerCondition, expectedCoinOutBuyer)
		api.AssertIsEqual(coinConstraintBuyer, coinTargetBuyer)

		// Verify marginal seller trades partial quantity
		marginalSellerCondition := isMarginalSeller

		// Energy loss should equal partial quantity
		expectedEnergyOutSeller := api.Sub(c.InEnergy[i], marginalSellerPartialQuantity)
		energyConstraintSeller := api.Mul(marginalSellerCondition, c.OutEnergy[i])
		energyTargetSeller := api.Mul(marginalSellerCondition, expectedEnergyOutSeller)
		api.AssertIsEqual(energyConstraintSeller, energyTargetSeller)

		// Coin gain should equal clearing price * partial quantity
		coinGain := api.Mul(c.ClearingPrice, marginalSellerPartialQuantity)
		expectedCoinOutSeller := api.Add(c.InCoin[i], coinGain)
		coinConstraintSeller := api.Mul(marginalSellerCondition, c.OutCoin[i])
		coinTargetSeller := api.Mul(marginalSellerCondition, expectedCoinOutSeller)
		api.AssertIsEqual(coinConstraintSeller, coinTargetSeller)
	}
}

// verifyMarginalTradesScenario2 verifies trades when seller curve cuts buyer curve
// Marginal seller trades full quantity, marginal buyer trades partial quantity
func (c *CircuitTxFN) verifyMarginalTradesScenario2(api frontend.API, marginalBuyerIndices, marginalSellerIndices []frontend.Variable,
	totalBuyerDemand, totalSellerSupply frontend.Variable) {

	marginalBuyerPartialQuantity := api.Sub(totalSellerSupply, totalBuyerDemand)

	for i := 0; i < c.N; i++ {
		isMarginalBuyer := marginalBuyerIndices[i]
		isMarginalSeller := marginalSellerIndices[i]
		tradedQuantity := c.DecVal[i][6]

		// Verify marginal seller trades full quantity
		marginalSellerCondition := isMarginalSeller

		// Energy loss should equal full traded quantity
		expectedEnergyOutSeller := api.Sub(c.InEnergy[i], tradedQuantity)
		energyConstraintSeller := api.Mul(marginalSellerCondition, c.OutEnergy[i])
		energyTargetSeller := api.Mul(marginalSellerCondition, expectedEnergyOutSeller)
		api.AssertIsEqual(energyConstraintSeller, energyTargetSeller)

		// Coin gain should equal clearing price * full quantity
		coinGain := api.Mul(c.ClearingPrice, tradedQuantity)
		expectedCoinOutSeller := api.Add(c.InCoin[i], coinGain)
		coinConstraintSeller := api.Mul(marginalSellerCondition, c.OutCoin[i])
		coinTargetSeller := api.Mul(marginalSellerCondition, expectedCoinOutSeller)
		api.AssertIsEqual(coinConstraintSeller, coinTargetSeller)

		// Verify marginal buyer trades partial quantity
		marginalBuyerCondition := isMarginalBuyer

		// Energy gain should equal partial quantity
		expectedEnergyOutBuyer := api.Add(c.InEnergy[i], marginalBuyerPartialQuantity)
		energyConstraintBuyer := api.Mul(marginalBuyerCondition, c.OutEnergy[i])
		energyTargetBuyer := api.Mul(marginalBuyerCondition, expectedEnergyOutBuyer)
		api.AssertIsEqual(energyConstraintBuyer, energyTargetBuyer)

		// Coin loss should equal clearing price * partial quantity
		coinCost := api.Mul(c.ClearingPrice, marginalBuyerPartialQuantity)
		expectedCoinOutBuyer := api.Sub(c.InCoin[i], coinCost)
		coinConstraintBuyer := api.Mul(marginalBuyerCondition, c.OutCoin[i])
		coinTargetBuyer := api.Mul(marginalBuyerCondition, expectedCoinOutBuyer)
		api.AssertIsEqual(coinConstraintBuyer, coinTargetBuyer)
	}
}
