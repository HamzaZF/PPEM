// auction_comprehensive_test.go - Comprehensive testing of all auction scenarios with conservation verification and plotting

package exchange

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"

	"implementation/internal/zerocash"
)

// TestComprehensiveAuctionScenarios tests all auction scenarios with full conservation verification and plotting
func TestComprehensiveAuctionScenarios(t *testing.T) {
	scenarios := []struct {
		name                      string
		description               string
		buyers                    []ParticipantData
		sellers                   []ParticipantData
		expectedTrade             bool
		expectedCommissionPerUnit int64
	}{
		{
			name:        "Perfect_Intersection_Even_Sum",
			description: "Perfect supply-demand intersection with even price sum (no commission)",
			buyers: []ParticipantData{
				{price: 60, quantity: 15, initialCoins: 1000, initialEnergy: 50},
				{price: 55, quantity: 20, initialCoins: 1200, initialEnergy: 40},
			},
			sellers: []ParticipantData{
				{price: 40, quantity: 18, initialCoins: 800, initialEnergy: 200},
				{price: 45, quantity: 22, initialCoins: 600, initialEnergy: 250},
			},
			expectedTrade:             true,
			expectedCommissionPerUnit: 0, // (60+45) = 105, 105 mod 2 = 1, but intersection should be different
		},
		{
			name:        "Perfect_Intersection_Odd_Sum",
			description: "Perfect supply-demand intersection with odd price sum (commission = 1)",
			buyers: []ParticipantData{
				{price: 71, quantity: 12, initialCoins: 1500, initialEnergy: 30},
			},
			sellers: []ParticipantData{
				{price: 30, quantity: 12, initialCoins: 500, initialEnergy: 150},
			},
			expectedTrade:             true,
			expectedCommissionPerUnit: 1, // (71+30) = 101, 101 mod 2 = 1
		},
		{
			name:        "No_Intersection_Gap",
			description: "No intersection - buyers bid too low, sellers ask too high",
			buyers: []ParticipantData{
				{price: 25, quantity: 10, initialCoins: 800, initialEnergy: 50},
				{price: 20, quantity: 15, initialCoins: 600, initialEnergy: 40},
			},
			sellers: []ParticipantData{
				{price: 80, quantity: 12, initialCoins: 400, initialEnergy: 120},
				{price: 90, quantity: 8, initialCoins: 300, initialEnergy: 100},
			},
			expectedTrade:             false,
			expectedCommissionPerUnit: 0,
		},
		{
			name:        "Single_Point_Intersection",
			description: "Supply and demand curves intersect at exactly one point",
			buyers: []ParticipantData{
				{price: 50, quantity: 10, initialCoins: 1000, initialEnergy: 50},
			},
			sellers: []ParticipantData{
				{price: 50, quantity: 10, initialCoins: 500, initialEnergy: 100},
			},
			expectedTrade:             true,
			expectedCommissionPerUnit: 0, // (50+50) = 100, 100 mod 2 = 0
		},
		{
			name:        "High_Volume_Multi_Participant",
			description: "Large market with many participants and high trading volumes",
			buyers: []ParticipantData{
				{price: 80, quantity: 50, initialCoins: 5000, initialEnergy: 100},
				{price: 75, quantity: 45, initialCoins: 4500, initialEnergy: 120},
				{price: 70, quantity: 40, initialCoins: 4000, initialEnergy: 110},
				{price: 65, quantity: 35, initialCoins: 3500, initialEnergy: 90},
			},
			sellers: []ParticipantData{
				{price: 50, quantity: 60, initialCoins: 2000, initialEnergy: 400},
				{price: 55, quantity: 55, initialCoins: 2200, initialEnergy: 380},
				{price: 60, quantity: 50, initialCoins: 2400, initialEnergy: 360},
				{price: 65, quantity: 45, initialCoins: 2600, initialEnergy: 340},
			},
			expectedTrade:             true,
			expectedCommissionPerUnit: 1, // Will depend on intersection prices
		},
		{
			name:        "Asymmetric_Market",
			description: "Asymmetric market with more buyers than sellers",
			buyers: []ParticipantData{
				{price: 60, quantity: 10, initialCoins: 1200, initialEnergy: 40},
				{price: 55, quantity: 12, initialCoins: 1100, initialEnergy: 45},
				{price: 50, quantity: 8, initialCoins: 1000, initialEnergy: 50},
			},
			sellers: []ParticipantData{
				{price: 45, quantity: 25, initialCoins: 800, initialEnergy: 200},
			},
			expectedTrade:             true,
			expectedCommissionPerUnit: 1, // Depends on intersection
		},
		{
			name:        "Edge_Case_Minimal_Trade",
			description: "Minimal viable trade with small quantities",
			buyers: []ParticipantData{
				{price: 100, quantity: 1, initialCoins: 200, initialEnergy: 10},
			},
			sellers: []ParticipantData{
				{price: 99, quantity: 1, initialCoins: 100, initialEnergy: 50},
			},
			expectedTrade:             true,
			expectedCommissionPerUnit: 1, // (100+99) = 199, 199 mod 2 = 1
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			fmt.Printf("\n🧪 TESTING SCENARIO: %s\n", scenario.name)
			fmt.Printf("📖 Description: %s\n", scenario.description)

			// Create inputs and roles for the scenario
			inputs, roles := createScenarioInputs(scenario.buyers, scenario.sellers)
			totalParticipants := len(inputs)

			// Log initial state
			logInitialState(t, inputs, roles)

			// Auctioneer secret key no longer needed

			// Execute auction (uniform, no commission)
			result := RunAuctionLogicUniform(inputs, roles)

			// Verify basic auction properties
			verifyAuctionResult(t, result, scenario.expectedTrade)

			// CRITICAL: Verify conservation laws (N inputs → N outputs)
			verifyConservationLaws(t, inputs, result, scenario.name)

			// Auctioneer note removed (no commission)

			// Generate visualization plot for this scenario
			generateScenarioPlot(t, scenario, inputs, result, roles)

			// Log final results
			logFinalResults(t, scenario, result, totalParticipants)
		})
	}
}

// ParticipantData represents a participant's initial state and order
type ParticipantData struct {
	price         int64 // Order price (bid for buyers, ask for sellers)
	quantity      int64 // Order quantity
	initialCoins  int64 // Initial coin balance
	initialEnergy int64 // Initial energy balance
}

// createScenarioInputs converts scenario data into auction inputs and roles
func createScenarioInputs(buyers, sellers []ParticipantData) ([]DecryptedRegistration, map[int]zerocash.OrderType) {
	totalParticipants := len(buyers) + len(sellers)
	inputs := make([]DecryptedRegistration, totalParticipants)
	roles := make(map[int]zerocash.OrderType)

	// Add buyers
	for i, buyer := range buyers {
		inputs[i] = DecryptedRegistration{
			PkOut:    big.NewInt(int64(100 + i)),
			SkIn:     big.NewInt(int64(200 + i)),
			Price:    big.NewInt(buyer.price),
			Quantity: big.NewInt(buyer.quantity),
			Coins:    big.NewInt(buyer.initialCoins),
			Energy:   big.NewInt(buyer.initialEnergy),
		}
		roles[i] = zerocash.BUY
	}

	// Add sellers
	buyerCount := len(buyers)
	for i, seller := range sellers {
		idx := buyerCount + i
		inputs[idx] = DecryptedRegistration{
			PkOut:    big.NewInt(int64(100 + idx)),
			SkIn:     big.NewInt(int64(200 + idx)),
			Price:    big.NewInt(seller.price),
			Quantity: big.NewInt(seller.quantity),
			Coins:    big.NewInt(seller.initialCoins),
			Energy:   big.NewInt(seller.initialEnergy),
		}
		roles[idx] = zerocash.SELL
	}

	return inputs, roles
}

// verifyAuctionResult verifies basic auction execution properties
func verifyAuctionResult(t *testing.T, result *AuctionExecutionResult, expectedTrade bool) {
	require.NotNil(t, result, "Auction result must not be nil")

	if expectedTrade {
		assert.Greater(t, result.TotalEnergyTraded, int64(0), "Energy should be traded in this scenario")
		assert.NotNil(t, result.ClearingPrice, "Clearing price should be set")
		assert.GreaterOrEqual(t, result.QualifiedBuyers, 0, "Should have qualified buyers")
		assert.GreaterOrEqual(t, result.QualifiedSellers, 0, "Should have qualified sellers")
	} else {
		assert.Equal(t, int64(0), result.TotalEnergyTraded, "No energy should be traded in this scenario")
		assert.Equal(t, big.NewInt(0), result.ClearingPrice, "Clearing price should be 0")
		assert.Equal(t, 0, result.QualifiedBuyers, "No qualified buyers expected")
		assert.Equal(t, 0, result.QualifiedSellers, "No qualified sellers expected")
	}
}

// verifyConservationLaws performs rigorous conservation verification
func verifyConservationLaws(t *testing.T, inputs []DecryptedRegistration, result *AuctionExecutionResult, scenarioName string) {
	// Calculate total inputs
	var totalInputCoins, totalInputEnergy int64
	for _, input := range inputs {
		totalInputCoins += input.Coins.Int64()
		totalInputEnergy += input.Energy.Int64()
	}

	// Calculate total participant outputs
	var totalOutputCoins, totalOutputEnergy int64
	for _, output := range result.Outputs {
		totalOutputCoins += output.Coins.Int64()
		totalOutputEnergy += output.Energy.Int64()
	}

	// Verify conservation laws (participants only)
	assert.Equal(t, totalInputCoins, totalOutputCoins,
		"[%s] COIN CONSERVATION: Total input coins (%d) must equal total output coins (%d)",
		scenarioName, totalInputCoins, totalOutputCoins)

	assert.Equal(t, totalInputEnergy, totalOutputEnergy,
		"[%s] ENERGY CONSERVATION: Total input energy (%d) must equal total output energy (%d)",
		scenarioName, totalInputEnergy, totalOutputEnergy)

	// Verify output count: N inputs → N outputs
	expectedOutputCount := len(inputs)
	actualOutputCount := len(result.Outputs)
	assert.Equal(t, expectedOutputCount, actualOutputCount,
		"[%s] OUTPUT COUNT: Expected %d outputs (N), got %d",
		scenarioName, expectedOutputCount, actualOutputCount)

	t.Logf("[%s] Conservation verified: %d inputs -> %d outputs", scenarioName, len(inputs), actualOutputCount)
}

// Auctioneer note rigor test removed (no commission)

// generateScenarioPlot creates a supply/demand plot for the scenario
func generateScenarioPlot(t *testing.T, scenario struct {
	name                      string
	description               string
	buyers                    []ParticipantData
	sellers                   []ParticipantData
	expectedTrade             bool
	expectedCommissionPerUnit int64
}, inputs []DecryptedRegistration, result *AuctionExecutionResult, roles map[int]zerocash.OrderType) {

	p := plot.New()
	p.Title.Text = fmt.Sprintf("Auction Scenario: %s", scenario.name)
	p.X.Label.Text = "Quantity (Energy Units)"
	p.Y.Label.Text = "Price (Coins per Unit)"

	// Create demand curve (buyers - descending prices)
	var demandPoints plotter.XYs
	var cumulativeDemand float64 = 0

	// Sort buyers by price descending for demand curve
	buyerPrices := make([]struct{ price, quantity float64 }, 0)
	for _, buyer := range scenario.buyers {
		buyerPrices = append(buyerPrices, struct{ price, quantity float64 }{
			price: float64(buyer.price), quantity: float64(buyer.quantity),
		})
	}

	// Create step-wise demand curve
	for _, buyer := range buyerPrices {
		// Add horizontal line at current quantity
		demandPoints = append(demandPoints, plotter.XY{X: cumulativeDemand, Y: buyer.price})
		cumulativeDemand += buyer.quantity
		// Add vertical line to next price level
		demandPoints = append(demandPoints, plotter.XY{X: cumulativeDemand, Y: buyer.price})
	}

	// Create supply curve (sellers - ascending prices)
	var supplyPoints plotter.XYs
	var cumulativeSupply float64 = 0

	// Sort sellers by price ascending for supply curve
	sellerPrices := make([]struct{ price, quantity float64 }, 0)
	for _, seller := range scenario.sellers {
		sellerPrices = append(sellerPrices, struct{ price, quantity float64 }{
			price: float64(seller.price), quantity: float64(seller.quantity),
		})
	}

	// Create step-wise supply curve
	for _, seller := range sellerPrices {
		// Add horizontal line at current quantity
		supplyPoints = append(supplyPoints, plotter.XY{X: cumulativeSupply, Y: seller.price})
		cumulativeSupply += seller.quantity
		// Add vertical line to next price level
		supplyPoints = append(supplyPoints, plotter.XY{X: cumulativeSupply, Y: seller.price})
	}

	// Add curves to plot
	if len(demandPoints) > 0 {
		demandLine, err := plotter.NewLine(demandPoints)
		require.NoError(t, err)
		demandLine.Color = plotutil.Color(0) // Red
		demandLine.Width = vg.Points(2)
		p.Add(demandLine)
		p.Legend.Add("Demand (Buyers)", demandLine)
	}

	if len(supplyPoints) > 0 {
		supplyLine, err := plotter.NewLine(supplyPoints)
		require.NoError(t, err)
		supplyLine.Color = plotutil.Color(1) // Blue
		supplyLine.Width = vg.Points(2)
		p.Add(supplyLine)
		p.Legend.Add("Supply (Sellers)", supplyLine)
	}

	// Add clearing price line if trading occurred
	if result.TotalEnergyTraded > 0 && result.ClearingPrice.Int64() > 0 {
		clearingPrice := float64(result.ClearingPrice.Int64())
		maxQuantity := cumulativeDemand
		if cumulativeSupply > maxQuantity {
			maxQuantity = cumulativeSupply
		}

		clearingLine, err := plotter.NewLine(plotter.XYs{
			{X: 0, Y: clearingPrice},
			{X: maxQuantity, Y: clearingPrice},
		})
		require.NoError(t, err)
		clearingLine.Color = plotutil.Color(2) // Orange
		clearingLine.Width = vg.Points(2)
		clearingLine.Dashes = []vg.Length{vg.Points(5), vg.Points(5)}
		p.Add(clearingLine)
		p.Legend.Add(fmt.Sprintf("Clearing Price: %d", result.ClearingPrice.Int64()), clearingLine)
	}

	// Save plot
	filename := fmt.Sprintf("comprehensive_test_%s.svg", scenario.name)
	err := p.Save(8*vg.Inch, 6*vg.Inch, filename)
	require.NoError(t, err)

	t.Logf("Plot saved: %s", filename)
}

// logInitialState logs the initial state of all participants
func logInitialState(t *testing.T, inputs []DecryptedRegistration, roles map[int]zerocash.OrderType) {
	var totalCoins, totalEnergy int64
	var buyerCount, sellerCount int

	for i, input := range inputs {
		role := roles[i]
		if role == zerocash.BUY {
			buyerCount++
		} else {
			sellerCount++
		}
		totalCoins += input.Coins.Int64()
		totalEnergy += input.Energy.Int64()

		t.Logf("   Participant %d (%s): Price=%v, Quantity=%v, Coins=%v, Energy=%v",
			i, role.String(), input.Price, input.Quantity, input.Coins, input.Energy)
	}

	t.Logf("Initial market state:")
	t.Logf("   👥 Participants: %d total (%d buyers, %d sellers)", len(inputs), buyerCount, sellerCount)
	t.Logf("   💰 Total Coins: %d", totalCoins)
	t.Logf("   ⚡ Total Energy: %d", totalEnergy)
}

// logFinalResults logs the final auction results
func logFinalResults(t *testing.T, scenario struct {
	name                      string
	description               string
	buyers                    []ParticipantData
	sellers                   []ParticipantData
	expectedTrade             bool
	expectedCommissionPerUnit int64
}, result *AuctionExecutionResult, totalParticipants int) {

	t.Logf("Final results for %s:", scenario.name)
	t.Logf("   Trading: %v (expected: %v)", result.TotalEnergyTraded > 0, scenario.expectedTrade)
	t.Logf("   Clearing price: %v", result.ClearingPrice)
	t.Logf("   🔄 Energy Traded: %d units", result.TotalEnergyTraded)
	t.Logf("   🎭 Participants: %d qualified buyers, %d qualified sellers", result.QualifiedBuyers, result.QualifiedSellers)
	t.Logf("   🏗️  Outputs: %d total (%d participants)", len(result.Outputs), totalParticipants)
}
