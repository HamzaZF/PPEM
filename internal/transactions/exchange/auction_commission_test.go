package exchange

import (
	"math/big"
	"testing"

	"implementation/internal/zerocash"
)

// Test scenarios for RunAuctionLogicWithCommission
func TestRunAuctionLogicWithCommission(t *testing.T) {
	tests := []struct {
		name                      string
		inputs                    []DecryptedRegistration
		roles                     map[int]zerocash.OrderType
		expectedTradingOccurs     bool
		expectedClearingPrice     *big.Int
		expectedCommissionPerUnit *big.Int
		expectedTotalCommission   *big.Int
		expectedEnergyTraded      int64
		expectedQualifiedBuyers   int
		expectedQualifiedSellers  int
		description               string
	}{
		{
			name: "Perfect Intersection - Even Sum",
			inputs: []DecryptedRegistration{
				{Price: big.NewInt(50), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Buyer
				{Price: big.NewInt(30), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Seller
			},
			roles: map[int]zerocash.OrderType{
				0: zerocash.BUY,
				1: zerocash.SELL,
			},
			expectedTradingOccurs:     true,
			expectedClearingPrice:     big.NewInt(40), // (50 + 30) / 2 = 40
			expectedCommissionPerUnit: big.NewInt(0),  // (50 + 30) % 2 = 0
			expectedTotalCommission:   big.NewInt(0),  // 0 * 10 = 0
			expectedEnergyTraded:      10,
			expectedQualifiedBuyers:   1,
			expectedQualifiedSellers:  1,
			description:               "Sum is even (80), so no commission per unit",
		},
		{
			name: "Perfect Intersection - Odd Sum",
			inputs: []DecryptedRegistration{
				{Price: big.NewInt(51), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Buyer
				{Price: big.NewInt(30), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Seller
			},
			roles: map[int]zerocash.OrderType{
				0: zerocash.BUY,
				1: zerocash.SELL,
			},
			expectedTradingOccurs:     true,
			expectedClearingPrice:     big.NewInt(40), // (51 + 30) / 2 = 40 (truncated)
			expectedCommissionPerUnit: big.NewInt(1),  // (51 + 30) % 2 = 1
			expectedTotalCommission:   big.NewInt(10), // 1 * 10 = 10
			expectedEnergyTraded:      10,
			expectedQualifiedBuyers:   1,
			expectedQualifiedSellers:  1,
			description:               "Sum is odd (81), so 1 coin commission per unit traded",
		},
		{
			name: "No Intersection - Buyer Bid Too Low",
			inputs: []DecryptedRegistration{
				{Price: big.NewInt(20), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Buyer
				{Price: big.NewInt(50), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Seller
			},
			roles: map[int]zerocash.OrderType{
				0: zerocash.BUY,
				1: zerocash.SELL,
			},
			expectedTradingOccurs:     false,
			expectedClearingPrice:     big.NewInt(0),
			expectedCommissionPerUnit: big.NewInt(0),
			expectedTotalCommission:   big.NewInt(0),
			expectedEnergyTraded:      0,
			expectedQualifiedBuyers:   0,
			expectedQualifiedSellers:  0,
			description:               "Buyer bids 20, seller asks 50 - no intersection",
		},
		{
			name: "Multiple Participants - Mixed Commission",
			inputs: []DecryptedRegistration{
				{Price: big.NewInt(60), Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Buyer 0
				{Price: big.NewInt(55), Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Buyer 1
				{Price: big.NewInt(45), Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Buyer 2
				{Price: big.NewInt(25), Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Seller 0
				{Price: big.NewInt(35), Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Seller 1
				{Price: big.NewInt(40), Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Seller 2
			},
			roles: map[int]zerocash.OrderType{
				0: zerocash.BUY, 1: zerocash.BUY, 2: zerocash.BUY,
				3: zerocash.SELL, 4: zerocash.SELL, 5: zerocash.SELL,
			},
			expectedTradingOccurs:     true,
			expectedClearingPrice:     big.NewInt(42), // Depends on intersection logic
			expectedCommissionPerUnit: big.NewInt(1),  // Depends on sum being odd/even
			expectedTotalCommission:   big.NewInt(15), // commission * energy traded
			expectedEnergyTraded:      15,
			expectedQualifiedBuyers:   3, // All buyers qualify (45+ >= clearing)
			expectedQualifiedSellers:  3, // All sellers qualify (<= clearing)
			description:               "Complex market with 6 participants",
		},
		{
			name: "Large Commission Example",
			inputs: []DecryptedRegistration{
				{Price: big.NewInt(99), Quantity: big.NewInt(20), Coins: big.NewInt(2000), Energy: big.NewInt(200)}, // Buyer
				{Price: big.NewInt(50), Quantity: big.NewInt(20), Coins: big.NewInt(1000), Energy: big.NewInt(200)}, // Seller
			},
			roles: map[int]zerocash.OrderType{
				0: zerocash.BUY,
				1: zerocash.SELL,
			},
			expectedTradingOccurs:     true,
			expectedClearingPrice:     big.NewInt(74), // (99 + 50) / 2 = 74 (truncated)
			expectedCommissionPerUnit: big.NewInt(1),  // (99 + 50) % 2 = 1
			expectedTotalCommission:   big.NewInt(20), // 1 * 20 = 20
			expectedEnergyTraded:      20,
			expectedQualifiedBuyers:   1,
			expectedQualifiedSellers:  1,
			description:               "Large trade with significant price difference",
		},
		{
			name: "Edge Case - Zero Commission",
			inputs: []DecryptedRegistration{
				{Price: big.NewInt(40), Quantity: big.NewInt(15), Coins: big.NewInt(1000), Energy: big.NewInt(150)}, // Buyer
				{Price: big.NewInt(40), Quantity: big.NewInt(15), Coins: big.NewInt(1000), Energy: big.NewInt(150)}, // Seller
			},
			roles: map[int]zerocash.OrderType{
				0: zerocash.BUY,
				1: zerocash.SELL,
			},
			expectedTradingOccurs:     true,
			expectedClearingPrice:     big.NewInt(40), // (40 + 40) / 2 = 40
			expectedCommissionPerUnit: big.NewInt(0),  // (40 + 40) % 2 = 0
			expectedTotalCommission:   big.NewInt(0),  // 0 * 15 = 0
			expectedEnergyTraded:      15,
			expectedQualifiedBuyers:   1,
			expectedQualifiedSellers:  1,
			description:               "Same bid and ask prices result in zero commission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RunAuctionLogicWithCommission(tt.inputs, tt.roles)

			// Check if trading occurred
			if (result.TotalEnergyTraded > 0) != tt.expectedTradingOccurs {
				t.Errorf("Trading occurrence mismatch: expected %v, got %v",
					tt.expectedTradingOccurs, result.TotalEnergyTraded > 0)
			}

			if !tt.expectedTradingOccurs {
				// For no-trading scenarios, just verify nothing happened
				if result.ClearingPrice.Cmp(big.NewInt(0)) != 0 {
					t.Errorf("Expected zero clearing price when no trading, got %v", result.ClearingPrice)
				}
				if result.AuctioneerCommission.Cmp(big.NewInt(0)) != 0 {
					t.Errorf("Expected zero commission when no trading, got %v", result.AuctioneerCommission)
				}
				return
			}

			// Verify clearing price
			if result.ClearingPrice.Cmp(tt.expectedClearingPrice) != 0 {
				t.Errorf("Clearing price mismatch: expected %v, got %v",
					tt.expectedClearingPrice, result.ClearingPrice)
			}

			// Verify total commission
			if result.AuctioneerCommission.Cmp(tt.expectedTotalCommission) != 0 {
				t.Errorf("Total commission mismatch: expected %v, got %v",
					tt.expectedTotalCommission, result.AuctioneerCommission)
			}

			// Verify energy traded
			if result.TotalEnergyTraded != tt.expectedEnergyTraded {
				t.Errorf("Energy traded mismatch: expected %d, got %d",
					tt.expectedEnergyTraded, result.TotalEnergyTraded)
			}

			// Verify qualified participants
			if result.QualifiedBuyers != tt.expectedQualifiedBuyers {
				t.Errorf("Qualified buyers mismatch: expected %d, got %d",
					tt.expectedQualifiedBuyers, result.QualifiedBuyers)
			}

			if result.QualifiedSellers != tt.expectedQualifiedSellers {
				t.Errorf("Qualified sellers mismatch: expected %d, got %d",
					tt.expectedQualifiedSellers, result.QualifiedSellers)
			}

			// Test Euclidean division property
			if tt.expectedTradingOccurs {
				// Get the intersection prices by re-running the internal logic
				// For now, we test that the commission per unit matches expected
				commissionPerUnit := new(big.Int).Div(result.AuctioneerCommission, big.NewInt(result.TotalEnergyTraded))
				if commissionPerUnit.Cmp(tt.expectedCommissionPerUnit) != 0 {
					t.Errorf("Commission per unit mismatch: expected %v, got %v",
						tt.expectedCommissionPerUnit, commissionPerUnit)
				}
			}

			t.Logf("✅ %s: %s", tt.name, tt.description)
		})
	}
}

// Test conservation laws
func TestAuctionConservation(t *testing.T) {
	inputs := []DecryptedRegistration{
		{Price: big.NewInt(61), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)}, // Buyer - odd price
		{Price: big.NewInt(51), Quantity: big.NewInt(10), Coins: big.NewInt(500), Energy: big.NewInt(150)},  // Buyer - odd price
		{Price: big.NewInt(30), Quantity: big.NewInt(10), Coins: big.NewInt(800), Energy: big.NewInt(120)},  // Seller - even price
		{Price: big.NewInt(40), Quantity: big.NewInt(10), Coins: big.NewInt(600), Energy: big.NewInt(130)},  // Seller - even price
	}

	roles := map[int]zerocash.OrderType{
		0: zerocash.BUY, 1: zerocash.BUY,
		2: zerocash.SELL, 3: zerocash.SELL,
	}

	// Calculate initial totals
	initialCoins := big.NewInt(0)
	initialEnergy := big.NewInt(0)
	for _, input := range inputs {
		initialCoins.Add(initialCoins, input.Coins)
		initialEnergy.Add(initialEnergy, input.Energy)
	}

	result := RunAuctionLogicWithCommission(inputs, roles)

	// Calculate final totals
	finalCoins := big.NewInt(0)
	finalEnergy := big.NewInt(0)
	for _, output := range result.Outputs {
		finalCoins.Add(finalCoins, output.Coins)
		finalEnergy.Add(finalEnergy, output.Energy)
	}

	// Add auctioneer commission to final coins (since auctioneer gets it)
	finalCoinsWithCommission := new(big.Int).Add(finalCoins, result.AuctioneerCommission)

	// Test conservation laws
	if initialCoins.Cmp(finalCoinsWithCommission) != 0 {
		t.Errorf("Coin conservation violation: initial=%v, final+commission=%v, commission=%v",
			initialCoins, finalCoinsWithCommission, result.AuctioneerCommission)
	}

	if initialEnergy.Cmp(finalEnergy) != 0 {
		t.Errorf("Energy conservation violation: initial=%v, final=%v",
			initialEnergy, finalEnergy)
	}

	t.Logf("✅ Conservation test passed: coins %v, energy %v, commission %v",
		initialCoins, initialEnergy, result.AuctioneerCommission)
}

// Test conservation laws with guaranteed commission
func TestAuctionConservationWithCommission(t *testing.T) {
	inputs := []DecryptedRegistration{
		{Price: big.NewInt(99), Quantity: big.NewInt(15), Coins: big.NewInt(2000), Energy: big.NewInt(200)}, // Buyer - high odd price
		{Price: big.NewInt(20), Quantity: big.NewInt(15), Coins: big.NewInt(500), Energy: big.NewInt(150)},  // Seller - low even price
	}

	roles := map[int]zerocash.OrderType{
		0: zerocash.BUY,
		1: zerocash.SELL,
	}

	// Calculate initial totals
	initialCoins := big.NewInt(0)
	initialEnergy := big.NewInt(0)
	for _, input := range inputs {
		initialCoins.Add(initialCoins, input.Coins)
		initialEnergy.Add(initialEnergy, input.Energy)
	}

	result := RunAuctionLogicWithCommission(inputs, roles)

	// Verify commission was generated
	if result.AuctioneerCommission.Cmp(big.NewInt(0)) == 0 {
		t.Fatal("Expected non-zero commission for this test scenario")
	}

	// Calculate expected commission: (99 + 20) % 2 = 1 coin per unit * 15 units = 15 coins
	expectedCommissionPerUnit := int64((99 + 20) % 2) // Should be 1
	expectedTotalCommission := expectedCommissionPerUnit * result.TotalEnergyTraded

	if result.AuctioneerCommission.Int64() != expectedTotalCommission {
		t.Errorf("Commission calculation error: expected %d, got %v",
			expectedTotalCommission, result.AuctioneerCommission)
	}

	// Calculate final totals
	finalCoins := big.NewInt(0)
	finalEnergy := big.NewInt(0)
	for _, output := range result.Outputs {
		finalCoins.Add(finalCoins, output.Coins)
		finalEnergy.Add(finalEnergy, output.Energy)
	}

	// Add auctioneer commission to final coins (since auctioneer gets it)
	finalCoinsWithCommission := new(big.Int).Add(finalCoins, result.AuctioneerCommission)

	// Test conservation laws
	if initialCoins.Cmp(finalCoinsWithCommission) != 0 {
		t.Errorf("Coin conservation violation: initial=%v, final+commission=%v, commission=%v",
			initialCoins, finalCoinsWithCommission, result.AuctioneerCommission)
	}

	if initialEnergy.Cmp(finalEnergy) != 0 {
		t.Errorf("Energy conservation violation: initial=%v, final=%v",
			initialEnergy, finalEnergy)
	}

	t.Logf("✅ Conservation with commission test passed:")
	t.Logf("   Initial coins: %v, Final coins: %v, Commission: %v",
		initialCoins, finalCoins, result.AuctioneerCommission)
	t.Logf("   Conservation check: %v = %v + %v",
		initialCoins, finalCoins, result.AuctioneerCommission)
	t.Logf("   Commission per unit: %d, Total units: %d",
		expectedCommissionPerUnit, result.TotalEnergyTraded)
}

// Test Euclidean division properties
func TestEuclideanDivisionProperty(t *testing.T) {
	testCases := []struct {
		buyerPrice  int64
		sellerPrice int64
		description string
	}{
		{50, 30, "Even sum (80)"},
		{51, 30, "Odd sum (81)"},
		{99, 1, "Large odd sum (100)"},
		{100, 0, "Even sum with zero"},
		{73, 46, "Medium odd sum (119)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			inputs := []DecryptedRegistration{
				{Price: big.NewInt(tc.buyerPrice), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
				{Price: big.NewInt(tc.sellerPrice), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
			}

			roles := map[int]zerocash.OrderType{
				0: zerocash.BUY,
				1: zerocash.SELL,
			}

			result := RunAuctionLogicWithCommission(inputs, roles)

			if result.TotalEnergyTraded > 0 {
				// Test Euclidean division: (buyerPrice + sellerPrice) = 2 * clearingPrice + remainder
				sum := tc.buyerPrice + tc.sellerPrice
				expectedClearingPrice := sum / 2
				expectedRemainder := sum % 2
				expectedTotalCommission := expectedRemainder * result.TotalEnergyTraded

				if result.ClearingPrice.Int64() != expectedClearingPrice {
					t.Errorf("Clearing price mismatch: expected %d, got %v",
						expectedClearingPrice, result.ClearingPrice)
				}

				if result.AuctioneerCommission.Int64() != expectedTotalCommission {
					t.Errorf("Commission mismatch: expected %d, got %v",
						expectedTotalCommission, result.AuctioneerCommission)
				}

				// Verify the Euclidean division equation
				calculatedSum := 2*result.ClearingPrice.Int64() + (result.AuctioneerCommission.Int64() / result.TotalEnergyTraded)
				if calculatedSum != sum {
					t.Errorf("Euclidean division violation: %d + %d = 2*%d + %d, but calculated sum = %d",
						tc.buyerPrice, tc.sellerPrice, result.ClearingPrice,
						result.AuctioneerCommission.Int64()/result.TotalEnergyTraded, calculatedSum)
				}

				t.Logf("✅ Euclidean division verified: %d + %d = 2*%d + %d",
					tc.buyerPrice, tc.sellerPrice, result.ClearingPrice,
					result.AuctioneerCommission.Int64()/result.TotalEnergyTraded)
			}
		})
	}
}

// Test edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("Empty inputs", func(t *testing.T) {
		result := RunAuctionLogicWithCommission([]DecryptedRegistration{}, map[int]zerocash.OrderType{})

		if result.TotalEnergyTraded != 0 {
			t.Errorf("Expected no trading with empty inputs")
		}
		if result.AuctioneerCommission.Cmp(big.NewInt(0)) != 0 {
			t.Errorf("Expected zero commission with empty inputs")
		}
	})

	t.Run("Only buyers", func(t *testing.T) {
		inputs := []DecryptedRegistration{
			{Price: big.NewInt(50), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
			{Price: big.NewInt(40), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
		}
		roles := map[int]zerocash.OrderType{
			0: zerocash.BUY,
			1: zerocash.BUY,
		}

		result := RunAuctionLogicWithCommission(inputs, roles)

		if result.TotalEnergyTraded != 0 {
			t.Errorf("Expected no trading with only buyers")
		}
	})

	t.Run("Only sellers", func(t *testing.T) {
		inputs := []DecryptedRegistration{
			{Price: big.NewInt(30), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
			{Price: big.NewInt(40), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
		}
		roles := map[int]zerocash.OrderType{
			0: zerocash.SELL,
			1: zerocash.SELL,
		}

		result := RunAuctionLogicWithCommission(inputs, roles)

		if result.TotalEnergyTraded != 0 {
			t.Errorf("Expected no trading with only sellers")
		}
	})

	t.Run("Nil prices", func(t *testing.T) {
		inputs := []DecryptedRegistration{
			{Price: nil, Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
			{Price: big.NewInt(40), Quantity: big.NewInt(10), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
		}
		roles := map[int]zerocash.OrderType{
			0: zerocash.BUY,
			1: zerocash.SELL,
		}

		result := RunAuctionLogicWithCommission(inputs, roles)

		// Should handle nil prices gracefully
		if result == nil {
			t.Errorf("Function should not panic with nil prices")
		}
	})
}
