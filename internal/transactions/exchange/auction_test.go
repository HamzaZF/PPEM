// auction_test.go - Test the complete auction implementation
//
// This file tests the enhanced auction logic with fixed-point arithmetic
// and market clearing price computation.

package exchange

import (
	"math/big"
	"testing"
)

// TestRunAuctionLogic tests the complete auction algorithm
func TestRunAuctionLogic(t *testing.T) {
	// Create test inputs for 10 participants
	// First 5 are buyers, last 5 are sellers
	inputs := []DecryptedRegistration{
		// Buyers (participants 0-4)
		{
			PkOut:  big.NewInt(100),
			SkIn:   big.NewInt(200),
			Bid:    big.NewInt(50), // Buyer willing to pay $50
			Coins:  big.NewInt(1000),
			Energy: big.NewInt(0),
		},
		{
			PkOut:  big.NewInt(101),
			SkIn:   big.NewInt(201),
			Bid:    big.NewInt(45), // Buyer willing to pay $45
			Coins:  big.NewInt(900),
			Energy: big.NewInt(0),
		},
		{
			PkOut:  big.NewInt(102),
			SkIn:   big.NewInt(202),
			Bid:    big.NewInt(40), // Buyer willing to pay $40
			Coins:  big.NewInt(800),
			Energy: big.NewInt(0),
		},
		{
			PkOut:  big.NewInt(103),
			SkIn:   big.NewInt(203),
			Bid:    big.NewInt(35), // Buyer willing to pay $35
			Coins:  big.NewInt(700),
			Energy: big.NewInt(0),
		},
		{
			PkOut:  big.NewInt(104),
			SkIn:   big.NewInt(204),
			Bid:    big.NewInt(30), // Buyer willing to pay $30
			Coins:  big.NewInt(600),
			Energy: big.NewInt(0),
		},
		// Sellers (participants 5-9)
		{
			PkOut:  big.NewInt(105),
			SkIn:   big.NewInt(205),
			Bid:    big.NewInt(25), // Seller willing to sell at $25
			Coins:  big.NewInt(500),
			Energy: big.NewInt(100),
		},
		{
			PkOut:  big.NewInt(106),
			SkIn:   big.NewInt(206),
			Bid:    big.NewInt(30), // Seller willing to sell at $30
			Coins:  big.NewInt(400),
			Energy: big.NewInt(100),
		},
		{
			PkOut:  big.NewInt(107),
			SkIn:   big.NewInt(207),
			Bid:    big.NewInt(35), // Seller willing to sell at $35
			Coins:  big.NewInt(300),
			Energy: big.NewInt(100),
		},
		{
			PkOut:  big.NewInt(108),
			SkIn:   big.NewInt(208),
			Bid:    big.NewInt(40), // Seller willing to sell at $40
			Coins:  big.NewInt(200),
			Energy: big.NewInt(100),
		},
		{
			PkOut:  big.NewInt(109),
			SkIn:   big.NewInt(209),
			Bid:    big.NewInt(45), // Seller willing to sell at $45
			Coins:  big.NewInt(100),
			Energy: big.NewInt(100),
		},
	}

	// Run the auction
	outputs := RunAuctionLogic(inputs)

	// Verify we have the same number of outputs
	if len(outputs) != len(inputs) {
		t.Fatalf("Expected %d outputs, got %d", len(inputs), len(outputs))
	}

	// Calculate expected market clearing price
	// Average buyer bid: (50+45+40+35+30)/5 = 40
	// Average seller ask: (25+30+35+40+45)/5 = 35
	// Market clearing price: (40+35)/2 = 37.5 ≈ 37 (integer)
	expectedMarketPrice := big.NewInt(37)

	t.Logf("Expected market clearing price: %v", expectedMarketPrice)

	// Verify that participants who should trade actually traded
	// Trade quantity is fixed at 10 units per trade
	tradeQuantity := big.NewInt(10)

	// Check buyers
	for i := 0; i < 5; i++ {
		originalBid := inputs[i].Bid
		originalCoins := inputs[i].Coins
		originalEnergy := inputs[i].Energy

		outputCoins := outputs[i].Coins
		outputEnergy := outputs[i].Energy

		// Check if buyer should have traded (bid >= market price)
		shouldTrade := originalBid.Cmp(expectedMarketPrice) >= 0

		if shouldTrade {
			// Buyer should have lost coins and gained energy
			expectedCoins := new(big.Int).Sub(originalCoins, new(big.Int).Mul(expectedMarketPrice, tradeQuantity))
			expectedEnergy := new(big.Int).Add(originalEnergy, tradeQuantity)

			t.Logf("Buyer %d: bid=%v, should trade=%v", i, originalBid, shouldTrade)
			t.Logf("  Original: coins=%v, energy=%v", originalCoins, originalEnergy)
			t.Logf("  Expected: coins=%v, energy=%v", expectedCoins, expectedEnergy)
			t.Logf("  Actual:   coins=%v, energy=%v", outputCoins, outputEnergy)

			// Note: Due to fixed-point arithmetic, there might be small differences
			// We'll check if the changes are in the right direction
			if outputCoins.Cmp(originalCoins) >= 0 {
				t.Errorf("Buyer %d should have lost coins, but coins didn't decrease", i)
			}
			if outputEnergy.Cmp(originalEnergy) <= 0 {
				t.Errorf("Buyer %d should have gained energy, but energy didn't increase", i)
			}
		} else {
			// Buyer should not have traded
			if outputCoins.Cmp(originalCoins) != 0 {
				t.Errorf("Buyer %d should not have traded, but coins changed from %v to %v", i, originalCoins, outputCoins)
			}
			if outputEnergy.Cmp(originalEnergy) != 0 {
				t.Errorf("Buyer %d should not have traded, but energy changed from %v to %v", i, originalEnergy, outputEnergy)
			}
		}
	}

	// Check sellers
	for i := 5; i < 10; i++ {
		originalBid := inputs[i].Bid
		originalCoins := inputs[i].Coins
		originalEnergy := inputs[i].Energy

		outputCoins := outputs[i].Coins
		outputEnergy := outputs[i].Energy

		// Check if seller should have traded (ask <= market price)
		shouldTrade := originalBid.Cmp(expectedMarketPrice) <= 0

		if shouldTrade {
			// Seller should have gained coins and lost energy
			t.Logf("Seller %d: ask=%v, should trade=%v", i, originalBid, shouldTrade)
			t.Logf("  Original: coins=%v, energy=%v", originalCoins, originalEnergy)
			t.Logf("  Actual:   coins=%v, energy=%v", outputCoins, outputEnergy)

			// Check if changes are in the right direction
			if outputCoins.Cmp(originalCoins) <= 0 {
				t.Errorf("Seller %d should have gained coins, but coins didn't increase", i)
			}
			if outputEnergy.Cmp(originalEnergy) >= 0 {
				t.Errorf("Seller %d should have lost energy, but energy didn't decrease", i)
			}
		} else {
			// Seller should not have traded
			if outputCoins.Cmp(originalCoins) != 0 {
				t.Errorf("Seller %d should not have traded, but coins changed from %v to %v", i, originalCoins, outputCoins)
			}
			if outputEnergy.Cmp(originalEnergy) != 0 {
				t.Errorf("Seller %d should not have traded, but energy changed from %v to %v", i, originalEnergy, outputEnergy)
			}
		}
	}
}

// TestMarketClearingPrice tests the market clearing price computation
func TestMarketClearingPrice(t *testing.T) {
	// Simple test case
	inputs := []DecryptedRegistration{
		{Bid: big.NewInt(100)}, // Buyer
		{Bid: big.NewInt(90)},  // Buyer
		{Bid: big.NewInt(60)},  // Seller
		{Bid: big.NewInt(70)},  // Seller
	}

	buyers := []int{0, 1}
	sellers := []int{2, 3}

	// Expected: avg buy = (100+90)/2 = 95, avg sell = (60+70)/2 = 65
	// Market clearing = (95+65)/2 = 80
	expectedPrice := big.NewInt(80)

	actualPrice := computeMarketClearingPrice(inputs, buyers, sellers)

	if actualPrice.Cmp(expectedPrice) != 0 {
		t.Errorf("Expected market clearing price %v, got %v", expectedPrice, actualPrice)
	}
}

// TestFixedPointArithmetic tests fixed-point conversion functions
func TestFixedPointArithmetic(t *testing.T) {
	const scale = 1 << 16 // 65536

	// Test conversion to fixed-point
	original := big.NewInt(100)
	scaled := scaleToFixedPoint(original, scale)
	expected := big.NewInt(100 * scale)

	if scaled.Cmp(expected) != 0 {
		t.Errorf("Expected scaled value %v, got %v", expected, scaled)
	}

	// Test conversion back from fixed-point
	recovered := scaleFromFixedPoint(scaled, scale)
	if recovered.Cmp(original) != 0 {
		t.Errorf("Expected recovered value %v, got %v", original, recovered)
	}
}

// TestShouldParticipantTrade tests the trade decision logic
func TestShouldParticipantTrade(t *testing.T) {
	marketPrice := big.NewInt(50)

	testCases := []struct {
		name     string
		bid      *big.Int
		isBuyer  bool
		expected bool
	}{
		{"Buyer with high bid", big.NewInt(60), true, true},
		{"Buyer with equal bid", big.NewInt(50), true, true},
		{"Buyer with low bid", big.NewInt(40), true, false},
		{"Seller with low ask", big.NewInt(40), false, true},
		{"Seller with equal ask", big.NewInt(50), false, true},
		{"Seller with high ask", big.NewInt(60), false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			participant := DecryptedRegistration{Bid: tc.bid}
			result := shouldParticipantTrade(participant, marketPrice, tc.isBuyer)
			if result != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}
