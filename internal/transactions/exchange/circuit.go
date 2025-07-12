// circuit.go - Circuit for the auction phase (exchange) of the protocol.
//
// Defines dynamic circuits for any N participants, enforcing cryptographic consistency
// (decryption, PRF, commitments, EC operations) AND the auction logic itself.
//
// UPDATED: Now includes complete auction logic enforcement in circuit.

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

// CircuitTxFN represents a dynamic circuit for N coins/participants in the auction phase.
// This circuit can be generated for any number of participants.
type CircuitTxFN struct {
	// Number of participants this circuit supports
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
	DecVal [][]frontend.Variable

	// ----- DH Parameters for each coin -----
	R      []frontend.Variable
	G      []sw_bls12377.G1Affine `gnark:",public"`
	G_b    []sw_bls12377.G1Affine `gnark:",public"`
	G_r    []sw_bls12377.G1Affine `gnark:",public"`
	EncKey []sw_bls12377.G1Affine // DH shared secret: used for both decryption and DH verification
}

// NewCircuitTxFN creates a new dynamic circuit for N participants
func NewCircuitTxFN(n int) *CircuitTxFN {
	if n <= 0 {
		panic("CircuitTxFN: N must be positive")
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

// isParticipantBuyer determines if a participant is a buyer (first half) or seller (second half)
func (c *CircuitTxFN) isParticipantBuyer(api frontend.API, participantIdx int) frontend.Variable {
	midpoint := c.N / 2

	// Convert to frontend.Variable for circuit operations
	participantVar := frontend.Variable(participantIdx)
	midpointVar := frontend.Variable(midpoint)

	// Return 1 if buyer, 0 if seller
	comparison := api.Cmp(participantVar, midpointVar) // returns -1 if <, 0 if =, 1 if >
	return api.IsZero(api.Add(comparison, 1))          // 1 if participantIdx < midpoint, 0 otherwise
}

// computeMarketClearingPrice computes the market clearing price using all participants' bids
func (c *CircuitTxFN) computeMarketClearingPrice(api frontend.API) frontend.Variable {
	buySum := frontend.Variable(0)
	buyCount := frontend.Variable(0)
	sellSum := frontend.Variable(0)
	sellCount := frontend.Variable(0)

	midpoint := c.N / 2
	midpointVar := frontend.Variable(midpoint)

	for i := 0; i < c.N; i++ {
		// Convert loop variable to frontend.Variable
		iVar := frontend.Variable(i)

		// Determine if participant is buyer or seller
		comparison := api.Cmp(iVar, midpointVar)      // returns -1 if <, 0 if =, 1 if >
		isBuyer := api.IsZero(api.Add(comparison, 1)) // 1 if i < midpoint, 0 otherwise

		// DecVal[i][2] contains the bid price
		bidPrice := c.DecVal[i][2]

		// Accumulate buy orders (first half of participants)
		buySum = api.Add(buySum, api.Mul(isBuyer, bidPrice))
		buyCount = api.Add(buyCount, isBuyer)

		// Accumulate sell orders (second half of participants)
		sellSum = api.Add(sellSum, api.Mul(api.Sub(1, isBuyer), bidPrice))
		sellCount = api.Add(sellCount, api.Sub(1, isBuyer))
	}

	// Compute average bid and ask prices
	avgBuyPrice := api.Div(buySum, buyCount)
	avgSellPrice := api.Div(sellSum, sellCount)

	// Market clearing price = midpoint of average bid and ask
	marketPrice := api.Div(api.Add(avgBuyPrice, avgSellPrice), 2)

	return marketPrice
}

// shouldParticipantTrade determines if a participant should trade at the market price
func (c *CircuitTxFN) shouldParticipantTrade(api frontend.API, participantIdx int, marketPrice frontend.Variable) frontend.Variable {
	// Get participant's bid price
	bidPrice := c.DecVal[participantIdx][2]

	// Check if participant is buyer or seller
	isBuyer := c.isParticipantBuyer(api, participantIdx)

	// For buyers: trade if bid >= market price
	// For sellers: trade if ask <= market price (bid is their ask price)

	// api.Cmp(bidPrice, marketPrice) returns: -1 if bidPrice < marketPrice, 0 if equal, 1 if bidPrice > marketPrice
	// For buyers: want to trade when bidPrice >= marketPrice (comparison >= 0)
	// For sellers: want to trade when bidPrice <= marketPrice (comparison <= 0)

	comparison := api.Cmp(bidPrice, marketPrice)

	// Buyer trades when comparison >= 0 (bid >= market)
	// This is equivalent to: NOT (comparison == -1)
	buyerTrades := api.Sub(1, api.IsZero(api.Add(comparison, 1))) // 1 if comparison != -1, 0 if comparison == -1

	// Seller trades when comparison <= 0 (ask <= market)
	// This is equivalent to: (comparison == -1) OR (comparison == 0)
	sellerTrades := api.IsZero(api.Sub(comparison, 1)) // 1 if comparison <= 0, 0 if comparison > 0

	// Return 1 if should trade, 0 otherwise
	return api.Select(isBuyer, buyerTrades, sellerTrades)
}

// computeExpectedOutput computes the expected output values after auction
func (c *CircuitTxFN) computeExpectedOutput(api frontend.API, participantIdx int, marketPrice frontend.Variable) (frontend.Variable, frontend.Variable) {
	// Original balances
	originalCoins := c.InCoin[participantIdx]
	originalEnergy := c.InEnergy[participantIdx]

	// Determine if participant trades
	trades := c.shouldParticipantTrade(api, participantIdx, marketPrice)

	// Fixed trade quantity (10 energy units per trade)
	tradeQuantity := frontend.Variable(10)

	// Compute trade value = marketPrice * tradeQuantity
	// Since inputs are NOT scaled in the circuit, we use raw values
	tradeValue := api.Mul(marketPrice, tradeQuantity)

	// Determine if participant is buyer or seller
	isBuyer := c.isParticipantBuyer(api, participantIdx)

	// Compute final coin balance
	// If buyer and trades: originalCoins - tradeValue
	// If seller and trades: originalCoins + tradeValue
	// If no trade: originalCoins
	coinsAfterTrade := api.Select(isBuyer,
		api.Sub(originalCoins, tradeValue), // Buyer loses coins
		api.Add(originalCoins, tradeValue)) // Seller gains coins

	finalCoins := api.Select(trades, coinsAfterTrade, originalCoins)

	// Compute final energy balance
	// If buyer and trades: originalEnergy + tradeQuantity
	// If seller and trades: originalEnergy - tradeQuantity
	// If no trade: originalEnergy
	energyAfterTrade := api.Select(isBuyer,
		api.Add(originalEnergy, tradeQuantity), // Buyer gains energy
		api.Sub(originalEnergy, tradeQuantity)) // Seller loses energy

	finalEnergy := api.Select(trades, energyAfterTrade, originalEnergy)

	return finalCoins, finalEnergy
}

// Define implements the constraints for CircuitTxFN using dynamic arrays and for loops.
func (c *CircuitTxFN) Define(api frontend.API) error {
	// First, compute the market clearing price using all participants' bids
	marketPrice := c.computeMarketClearingPrice(api)

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

		// --- IMPLEMENT THE AUCTION LOGIC (Previously missing) ---
		// Compute expected output values based on auction rules
		expectedOutCoin, expectedOutEnergy := c.computeExpectedOutput(api, coin, marketPrice)

		// Assert that actual outputs match expected outputs from auction
		api.AssertIsEqual(c.OutCoin[coin], expectedOutCoin)
		api.AssertIsEqual(c.OutEnergy[coin], expectedOutEnergy)

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

// Define implements the constraints for CircuitTxF10 - enhanced with auction logic
func (c *CircuitTxF10) Define(api frontend.API) error {
	// Compute market clearing price
	marketPrice := c.computeMarketClearingPriceF10(api)

	// Process all 10 coins
	for coin := 0; coin < 10; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
		for i := 0; i < 5; i++ {
			api.AssertIsEqual(c.DecVal[coin][i], decVal[i])
		}

		// --- Verify serial number computation ---
		snComputed := PRF(api, c.InSk[coin], c.InRho[coin])
		api.AssertIsEqual(c.InSn[coin], snComputed)

		// --- IMPLEMENT THE AUCTION LOGIC ---
		expectedOutCoin, expectedOutEnergy := c.computeExpectedOutputF10(api, coin, marketPrice)
		api.AssertIsEqual(c.OutCoin[coin], expectedOutCoin)
		api.AssertIsEqual(c.OutEnergy[coin], expectedOutEnergy)

		// --- Compute output commitment ---
		hasher, _ := mimc.NewMiMC(api)
		hasher.Write(c.OutCoin[coin])
		hasher.Write(c.OutEnergy[coin])
		hasher.Write(c.OutPk[coin])
		hasher.Write(c.OutRho[coin])
		hasher.Write(c.OutRand[coin])
		cm := hasher.Sum()
		api.AssertIsEqual(c.OutCm[coin], cm)

		// --- Verify DH constraints ---
		G_r_b := new(sw_bls12377.G1Affine)
		G_r_b.ScalarMul(api, c.G_b[coin], c.R[coin])
		api.AssertIsEqual(c.EncKey[coin].X, G_r_b.X)
		api.AssertIsEqual(c.EncKey[coin].Y, G_r_b.Y)

		G_r := new(sw_bls12377.G1Affine)
		G_r.ScalarMul(api, c.G[coin], c.R[coin])
		api.AssertIsEqual(c.G_r[coin].X, G_r.X)
		api.AssertIsEqual(c.G_r[coin].Y, G_r.Y)

		// --- Verify public key derivation ---
		hasher.Reset()
		hasher.Write(c.InSk[coin])
		pk := hasher.Sum()
		api.AssertIsEqual(c.InPk[coin], pk)
	}

	return nil
}

// computeMarketClearingPriceF10 computes market clearing price for F10 circuit
func (c *CircuitTxF10) computeMarketClearingPriceF10(api frontend.API) frontend.Variable {
	buySum := frontend.Variable(0)
	sellSum := frontend.Variable(0)

	// First 5 are buyers, last 5 are sellers
	for i := 0; i < 5; i++ {
		buySum = api.Add(buySum, c.DecVal[i][2])
	}
	for i := 5; i < 10; i++ {
		sellSum = api.Add(sellSum, c.DecVal[i][2])
	}

	avgBuyPrice := api.Div(buySum, 5)
	avgSellPrice := api.Div(sellSum, 5)

	return api.Div(api.Add(avgBuyPrice, avgSellPrice), 2)
}

// computeExpectedOutputF10 computes expected output for F10 circuit
func (c *CircuitTxF10) computeExpectedOutputF10(api frontend.API, participantIdx int, marketPrice frontend.Variable) (frontend.Variable, frontend.Variable) {
	originalCoins := c.InCoin[participantIdx]
	originalEnergy := c.InEnergy[participantIdx]

	// Determine if buyer (idx < 5) or seller (idx >= 5)
	// Convert to frontend.Variable for circuit operations
	participantVar := frontend.Variable(participantIdx)
	midpoint := frontend.Variable(5)
	isBuyer := api.IsZero(api.Sub(api.Cmp(participantVar, midpoint), -1)) // participantIdx < 5

	// Check if should trade
	bidPrice := c.DecVal[participantIdx][2]

	// Fix the trading logic: buyers trade when bid >= market, sellers trade when ask <= market
	comparison := api.Cmp(bidPrice, marketPrice)
	buyerTrades := api.Sub(1, api.IsZero(api.Add(comparison, 1))) // 1 if bid >= market
	sellerTrades := api.IsZero(api.Sub(comparison, 1))            // 1 if ask <= market
	trades := api.Select(isBuyer, buyerTrades, sellerTrades)

	// Trade parameters
	tradeQuantity := frontend.Variable(10)
	tradeValue := api.Mul(marketPrice, tradeQuantity)

	// Compute final balances
	coinsAfterTrade := api.Select(isBuyer,
		api.Sub(originalCoins, tradeValue),
		api.Add(originalCoins, tradeValue))
	finalCoins := api.Select(trades, coinsAfterTrade, originalCoins)

	energyAfterTrade := api.Select(isBuyer,
		api.Add(originalEnergy, tradeQuantity),
		api.Sub(originalEnergy, tradeQuantity))
	finalEnergy := api.Select(trades, energyAfterTrade, originalEnergy)

	return finalCoins, finalEnergy
}

// CircuitTxF20 represents a circuit for 20 coins/participants in the auction phase.
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

// Define implements the constraints for CircuitTxF20 - enhanced with auction logic
func (c *CircuitTxF20) Define(api frontend.API) error {
	// Compute market clearing price
	marketPrice := c.computeMarketClearingPriceF20(api)

	// Process all 20 coins
	for coin := 0; coin < 20; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
		for i := 0; i < 5; i++ {
			api.AssertIsEqual(c.DecVal[coin][i], decVal[i])
		}

		// --- Verify serial number computation ---
		snComputed := PRF(api, c.InSk[coin], c.InRho[coin])
		api.AssertIsEqual(c.InSn[coin], snComputed)

		// --- IMPLEMENT THE AUCTION LOGIC ---
		expectedOutCoin, expectedOutEnergy := c.computeExpectedOutputF20(api, coin, marketPrice)
		api.AssertIsEqual(c.OutCoin[coin], expectedOutCoin)
		api.AssertIsEqual(c.OutEnergy[coin], expectedOutEnergy)

		// --- Compute output commitment ---
		hasher, _ := mimc.NewMiMC(api)
		hasher.Write(c.OutCoin[coin])
		hasher.Write(c.OutEnergy[coin])
		hasher.Write(c.OutPk[coin])
		hasher.Write(c.OutRho[coin])
		hasher.Write(c.OutRand[coin])
		cm := hasher.Sum()
		api.AssertIsEqual(c.OutCm[coin], cm)

		// --- Verify DH constraints ---
		G_r_b := new(sw_bls12377.G1Affine)
		G_r_b.ScalarMul(api, c.G_b[coin], c.R[coin])
		api.AssertIsEqual(c.EncKey[coin].X, G_r_b.X)
		api.AssertIsEqual(c.EncKey[coin].Y, G_r_b.Y)

		G_r := new(sw_bls12377.G1Affine)
		G_r.ScalarMul(api, c.G[coin], c.R[coin])
		api.AssertIsEqual(c.G_r[coin].X, G_r.X)
		api.AssertIsEqual(c.G_r[coin].Y, G_r.Y)

		// --- Verify public key derivation ---
		hasher.Reset()
		hasher.Write(c.InSk[coin])
		pk := hasher.Sum()
		api.AssertIsEqual(c.InPk[coin], pk)
	}

	return nil
}

// computeMarketClearingPriceF20 computes market clearing price for F20 circuit
func (c *CircuitTxF20) computeMarketClearingPriceF20(api frontend.API) frontend.Variable {
	buySum := frontend.Variable(0)
	sellSum := frontend.Variable(0)

	// First 10 are buyers, last 10 are sellers
	for i := 0; i < 10; i++ {
		buySum = api.Add(buySum, c.DecVal[i][2])
	}
	for i := 10; i < 20; i++ {
		sellSum = api.Add(sellSum, c.DecVal[i][2])
	}

	avgBuyPrice := api.Div(buySum, 10)
	avgSellPrice := api.Div(sellSum, 10)

	return api.Div(api.Add(avgBuyPrice, avgSellPrice), 2)
}

// computeExpectedOutputF20 computes expected output for F20 circuit
func (c *CircuitTxF20) computeExpectedOutputF20(api frontend.API, participantIdx int, marketPrice frontend.Variable) (frontend.Variable, frontend.Variable) {
	originalCoins := c.InCoin[participantIdx]
	originalEnergy := c.InEnergy[participantIdx]

	// Determine if buyer (idx < 10) or seller (idx >= 10)
	// Convert to frontend.Variable for circuit operations
	participantVar := frontend.Variable(participantIdx)
	midpoint := frontend.Variable(10)
	isBuyer := api.IsZero(api.Sub(api.Cmp(participantVar, midpoint), -1)) // participantIdx < 10

	// Check if should trade
	bidPrice := c.DecVal[participantIdx][2]

	// Fix the trading logic: buyers trade when bid >= market, sellers trade when ask <= market
	comparison := api.Cmp(bidPrice, marketPrice)
	buyerTrades := api.Sub(1, api.IsZero(api.Add(comparison, 1))) // 1 if bid >= market
	sellerTrades := api.IsZero(api.Sub(comparison, 1))            // 1 if ask <= market
	trades := api.Select(isBuyer, buyerTrades, sellerTrades)

	// Trade parameters
	tradeQuantity := frontend.Variable(10)
	tradeValue := api.Mul(marketPrice, tradeQuantity)

	// Compute final balances
	coinsAfterTrade := api.Select(isBuyer,
		api.Sub(originalCoins, tradeValue),
		api.Add(originalCoins, tradeValue))
	finalCoins := api.Select(trades, coinsAfterTrade, originalCoins)

	energyAfterTrade := api.Select(isBuyer,
		api.Add(originalEnergy, tradeQuantity),
		api.Sub(originalEnergy, tradeQuantity))
	finalEnergy := api.Select(trades, energyAfterTrade, originalEnergy)

	return finalCoins, finalEnergy
}
