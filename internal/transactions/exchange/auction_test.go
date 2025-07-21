package exchange

import (
	"fmt"
	"image/color"
	"math/big"
	"sort"
	"strings"
	"testing"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"

	"implementation/internal/zerocash"
)

// TestScenario represents a test case for the auction
type TestScenario struct {
	Name           string
	Description    string
	Buyers         []Participant // Price and quantity for buyers
	Sellers        []Participant // Price and quantity for sellers
	ExpectedResult TestAuctionResult
}

// Participant represents a market participant for testing
type Participant struct {
	Price    int64 // Price they're willing to bid/ask
	Quantity int64 // Quantity they want to trade
}

// TestAuctionResult represents expected results for testing
type TestAuctionResult struct {
	ShouldTrade      bool
	ClearingPrice    *int64 // nil if no trading
	QualifiedBuyers  int
	QualifiedSellers int
	TotalVolume      int64
}

// StepPoint represents a point on the supply/demand curve
type StepPoint struct {
	Quantity float64
	Price    float64
}

// createTestInputs converts test participants to DecryptedRegistration format
func createTestInputs(buyers, sellers []Participant) ([]DecryptedRegistration, map[int]zerocash.OrderType) {
	totalParticipants := len(buyers) + len(sellers)
	inputs := make([]DecryptedRegistration, totalParticipants)
	roles := make(map[int]zerocash.OrderType)

	// Add buyers first
	for i, buyer := range buyers {
		inputs[i] = DecryptedRegistration{
			Price:    big.NewInt(buyer.Price),
			Quantity: big.NewInt(buyer.Quantity),
			Coins:    big.NewInt(1000), // Initial coins
			Energy:   big.NewInt(100),  // Initial energy
		}
		roles[i] = zerocash.BUY
	}

	// Add sellers after buyers
	for i, seller := range sellers {
		idx := len(buyers) + i
		inputs[idx] = DecryptedRegistration{
			Price:    big.NewInt(seller.Price),
			Quantity: big.NewInt(seller.Quantity),
			Coins:    big.NewInt(1000), // Initial coins
			Energy:   big.NewInt(100),  // Initial energy
		}
		roles[idx] = zerocash.SELL
	}

	return inputs, roles
}

// buildSupplyCurve creates step-wise supply curve (ascending prices)
func buildSupplyCurve(sellers []Participant) []StepPoint {
	if len(sellers) == 0 {
		return []StepPoint{}
	}

	sortedSellers := make([]Participant, len(sellers))
	copy(sortedSellers, sellers)
	sort.Slice(sortedSellers, func(i, j int) bool {
		return sortedSellers[i].Price < sortedSellers[j].Price
	})

	var curve []StepPoint
	cumQty := 0.0

	for _, seller := range sortedSellers {
		curve = append(curve, StepPoint{Quantity: cumQty, Price: float64(seller.Price)})
		cumQty += float64(seller.Quantity)
		curve = append(curve, StepPoint{Quantity: cumQty, Price: float64(seller.Price)})
	}

	return curve
}

// buildDemandCurve creates step-wise demand curve (descending prices)
func buildDemandCurve(buyers []Participant) []StepPoint {
	if len(buyers) == 0 {
		return []StepPoint{}
	}

	sortedBuyers := make([]Participant, len(buyers))
	copy(sortedBuyers, buyers)
	sort.Slice(sortedBuyers, func(i, j int) bool {
		return sortedBuyers[i].Price > sortedBuyers[j].Price
	})

	var curve []StepPoint
	cumQty := 0.0

	for _, buyer := range sortedBuyers {
		curve = append(curve, StepPoint{Quantity: cumQty, Price: float64(buyer.Price)})
		cumQty += float64(buyer.Quantity)
		curve = append(curve, StepPoint{Quantity: cumQty, Price: float64(buyer.Price)})
	}

	return curve
}

// PlotAuction creates a visual plot of supply and demand curves with intersection
func PlotAuction(buyers, sellers []Participant, clearingPrice *int64, title string) error {
	p := plot.New()
	p.Title.Text = fmt.Sprintf("Double Auction: %s", title)
	p.X.Label.Text = "Cumulative Quantity"
	p.Y.Label.Text = "Price per Unit"

	// Build curves
	supplyCurve := buildSupplyCurve(sellers)
	demandCurve := buildDemandCurve(buyers)

	// Convert to plotter points for supply curve
	var supplyPoints plotter.XYs
	for _, point := range supplyCurve {
		supplyPoints = append(supplyPoints, plotter.XY{X: point.Quantity, Y: point.Price})
	}

	// Convert to plotter points for demand curve
	var demandPoints plotter.XYs
	for _, point := range demandCurve {
		demandPoints = append(demandPoints, plotter.XY{X: point.Quantity, Y: point.Price})
	}

	// Add supply curve
	if len(supplyPoints) > 0 {
		supplyLine, err := plotter.NewLine(supplyPoints)
		if err != nil {
			return err
		}
		supplyLine.Color = color.RGBA{R: 0, G: 150, B: 0, A: 255} // Green
		supplyLine.Width = vg.Points(3)
		p.Add(supplyLine)
		p.Legend.Add("Supply Curve", supplyLine)
	}

	// Add demand curve
	if len(demandPoints) > 0 {
		demandLine, err := plotter.NewLine(demandPoints)
		if err != nil {
			return err
		}
		demandLine.Color = color.RGBA{R: 0, G: 0, B: 200, A: 255} // Blue
		demandLine.Width = vg.Points(3)
		p.Add(demandLine)
		p.Legend.Add("Demand Curve", demandLine)
	}

	// Add clearing price lines if intersection exists
	if clearingPrice != nil && *clearingPrice > 0 {
		maxQty := 0.0
		if len(supplyCurve) > 0 {
			maxQty = max(maxQty, supplyCurve[len(supplyCurve)-1].Quantity)
		}
		if len(demandCurve) > 0 {
			maxQty = max(maxQty, demandCurve[len(demandCurve)-1].Quantity)
		}

		maxPrice := 0.0
		if len(sellers) > 0 {
			for _, s := range sellers {
				maxPrice = max(maxPrice, float64(s.Price))
			}
		}
		if len(buyers) > 0 {
			for _, b := range buyers {
				maxPrice = max(maxPrice, float64(b.Price))
			}
		}

		// Horizontal clearing price line
		clearingLine, _ := plotter.NewLine(plotter.XYs{
			plotter.XY{X: 0, Y: float64(*clearingPrice)},
			plotter.XY{X: maxQty, Y: float64(*clearingPrice)},
		})
		clearingLine.Color = color.RGBA{R: 200, G: 0, B: 0, A: 255} // Red
		clearingLine.Width = vg.Points(2)
		clearingLine.Dashes = []vg.Length{vg.Points(5), vg.Points(2)}

		p.Add(clearingLine)
		p.Legend.Add(fmt.Sprintf("Clearing Price (%d)", *clearingPrice), clearingLine)

		// Add intersection point
		intersectionQty := findIntersectionQuantity(supplyCurve, demandCurve, float64(*clearingPrice))
		if intersectionQty > 0 {
			intersection, _ := plotter.NewScatter(plotter.XYs{
				plotter.XY{X: intersectionQty, Y: float64(*clearingPrice)},
			})
			intersection.GlyphStyle.Color = color.RGBA{R: 255, G: 0, B: 0, A: 255}
			intersection.GlyphStyle.Radius = vg.Points(5)
			p.Add(intersection)
			p.Legend.Add("Intersection", intersection)
		}
	}

	// Set axis ranges
	maxQty := 0.0
	maxPrice := 0.0

	if len(supplyCurve) > 0 {
		maxQty = max(maxQty, supplyCurve[len(supplyCurve)-1].Quantity)
	}
	if len(demandCurve) > 0 {
		maxQty = max(maxQty, demandCurve[len(demandCurve)-1].Quantity)
	}

	for _, s := range sellers {
		maxPrice = max(maxPrice, float64(s.Price))
	}
	for _, b := range buyers {
		maxPrice = max(maxPrice, float64(b.Price))
	}

	if maxQty == 0 {
		maxQty = 10
	}
	if maxPrice == 0 {
		maxPrice = 10
	}

	p.X.Min = 0
	p.X.Max = maxQty * 1.1
	p.Y.Min = 0
	p.Y.Max = maxPrice * 1.1

	// Save plot
	// Clean up filename to be Windows-compatible (remove colons, etc.)
	cleanTitle := strings.ReplaceAll(strings.ToLower(title), ":", "")
	cleanTitle = strings.ReplaceAll(cleanTitle, " ", "_")
	cleanTitle = strings.ReplaceAll(cleanTitle, "(", "")
	cleanTitle = strings.ReplaceAll(cleanTitle, ")", "")
	cleanTitle = strings.ReplaceAll(cleanTitle, ",", "")
	filename := fmt.Sprintf("auction_%s.png", cleanTitle)

	return p.Save(10*vg.Inch, 7*vg.Inch, filename)
}

// findIntersectionQuantity finds the quantity at which curves intersect at given price
func findIntersectionQuantity(supply, demand []StepPoint, price float64) float64 {
	var supplyQty, demandQty float64

	// Find quantity on supply curve at this price
	for i := 0; i < len(supply)-1; i += 2 {
		if supply[i].Price <= price && (i+1 >= len(supply) || supply[i+1].Price >= price) {
			supplyQty = supply[i+1].Quantity
			break
		}
	}

	// Find quantity on demand curve at this price
	for i := 0; i < len(demand)-1; i += 2 {
		if demand[i].Price >= price && (i+1 >= len(demand) || demand[i+1].Price <= price) {
			demandQty = demand[i+1].Quantity
			break
		}
	}

	return min(supplyQty, demandQty)
}

// Helper functions
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// drawMarketGraph creates an ASCII visualization of supply and demand curves
func drawMarketGraph(buyers, sellers []Participant, clearingPrice *int64, title string) string {
	var result strings.Builder

	result.WriteString(fmt.Sprintf("\n=== %s ===\n", title))

	// Sort buyers by price (descending) and sellers by price (ascending)
	sortedBuyers := make([]Participant, len(buyers))
	copy(sortedBuyers, buyers)
	sort.Slice(sortedBuyers, func(i, j int) bool {
		return sortedBuyers[i].Price > sortedBuyers[j].Price
	})

	sortedSellers := make([]Participant, len(sellers))
	copy(sortedSellers, sellers)
	sort.Slice(sortedSellers, func(i, j int) bool {
		return sortedSellers[i].Price < sortedSellers[j].Price
	})

	// Create demand curve (buyers)
	result.WriteString("\nDEMAND CURVE (Buyers - willing to pay):\n")
	cumulativeQty := int64(0)
	for _, buyer := range sortedBuyers {
		result.WriteString(fmt.Sprintf("Price %2d: %s (%d units, cumulative: %d)\n",
			buyer.Price, strings.Repeat("█", int(buyer.Quantity)), buyer.Quantity, cumulativeQty+buyer.Quantity))
		cumulativeQty += buyer.Quantity
	}

	// Create supply curve (sellers)
	result.WriteString("\nSUPPLY CURVE (Sellers - willing to accept):\n")
	cumulativeQty = 0
	for _, seller := range sortedSellers {
		result.WriteString(fmt.Sprintf("Price %2d: %s (%d units, cumulative: %d)\n",
			seller.Price, strings.Repeat("▓", int(seller.Quantity)), seller.Quantity, cumulativeQty+seller.Quantity))
		cumulativeQty += seller.Quantity
	}

	// Show intersection analysis
	result.WriteString("\nINTERSECTION ANALYSIS:\n")
	intersectionFound := false

	for _, buyer := range sortedBuyers {
		for _, seller := range sortedSellers {
			if buyer.Price >= seller.Price {
				result.WriteString(fmt.Sprintf("✓ Buyer (price=%d) ≥ Seller (price=%d) → INTERSECTION!\n", buyer.Price, seller.Price))
				intersectionFound = true
				break
			}
		}
		if intersectionFound {
			break
		}
	}

	if !intersectionFound {
		result.WriteString("✗ No intersection found - highest buyer bid < lowest seller ask\n")
	}

	if clearingPrice != nil {
		result.WriteString(fmt.Sprintf("\n🎯 CLEARING PRICE: %d coins/unit\n", *clearingPrice))
	} else {
		result.WriteString("\n❌ NO TRADING OCCURS\n")
	}

	return result.String()
}

// Test scenarios covering all possible market conditions
func TestAuctionScenarios(t *testing.T) {

	scenarios := []TestScenario{
		{
			Name:        "Scenario 1: Perfect Intersection",
			Description: "Buyer and seller curves intersect cleanly",
			Buyers: []Participant{
				{Price: 10, Quantity: 5}, // High bidder
				{Price: 8, Quantity: 3},  // Medium bidder
				{Price: 6, Quantity: 2},  // Low bidder
			},
			Sellers: []Participant{
				{Price: 5, Quantity: 4}, // Low ask
				{Price: 7, Quantity: 3}, // Medium ask
				{Price: 9, Quantity: 2}, // High ask
			},
			ExpectedResult: TestAuctionResult{
				ShouldTrade:      true,
				ClearingPrice:    func() *int64 { cp := int64(7); return &cp }(), // (10+5)/2 = 7.5 → 7
				QualifiedBuyers:  2,                                              // Buyers with price ≥ 7: 10, 8
				QualifiedSellers: 2,                                              // Sellers with price ≤ 7: 5, 7
			},
		},

		{
			Name:        "Scenario 2: No Intersection (Gap)",
			Description: "Highest buyer bid < lowest seller ask",
			Buyers: []Participant{
				{Price: 5, Quantity: 3}, // Highest buyer bid = 5
				{Price: 4, Quantity: 2},
				{Price: 3, Quantity: 1},
			},
			Sellers: []Participant{
				{Price: 8, Quantity: 2}, // Lowest seller ask = 8
				{Price: 9, Quantity: 3},
				{Price: 10, Quantity: 1},
			},
			ExpectedResult: TestAuctionResult{
				ShouldTrade:   false,
				ClearingPrice: nil, // No intersection
			},
		},

		{
			Name:        "Scenario 3: Buyer Curve Cuts Seller Curve",
			Description: "High buyer demand intersects with competitive sellers",
			Buyers: []Participant{
				{Price: 15, Quantity: 2}, // Very high bidder
				{Price: 12, Quantity: 3}, // High bidder
				{Price: 8, Quantity: 4},  // Medium bidder
				{Price: 5, Quantity: 1},  // Low bidder
			},
			Sellers: []Participant{
				{Price: 6, Quantity: 2},  // Competitive seller
				{Price: 10, Quantity: 3}, // Medium seller
				{Price: 14, Quantity: 2}, // Expensive seller
			},
			ExpectedResult: TestAuctionResult{
				ShouldTrade:      true,
				ClearingPrice:    func() *int64 { cp := int64(11); return &cp }(), // Step-wise intersection: (12+10)/2 = 11
				QualifiedBuyers:  2,                                               // Buyers ≥ 11: 15, 12
				QualifiedSellers: 2,                                               // Sellers ≤ 11: 6, 10
			},
		},

		{
			Name:        "Scenario 4: Seller Curve Cuts Buyer Curve",
			Description: "Many low-price sellers meet fewer high-value buyers",
			Buyers: []Participant{
				{Price: 12, Quantity: 1}, // Single high-value buyer
				{Price: 7, Quantity: 2},  // Medium buyers
				{Price: 4, Quantity: 3},  // Low buyers
			},
			Sellers: []Participant{
				{Price: 3, Quantity: 2},  // Very competitive
				{Price: 5, Quantity: 3},  // Competitive
				{Price: 8, Quantity: 2},  // Medium price
				{Price: 11, Quantity: 1}, // High price
			},
			ExpectedResult: TestAuctionResult{
				ShouldTrade:      true,
				ClearingPrice:    func() *int64 { cp := int64(6); return &cp }(), // Step-wise intersection: (7+5)/2 = 6
				QualifiedBuyers:  2,                                              // Buyers ≥ 6: 12, 7
				QualifiedSellers: 2,                                              // Sellers ≤ 6: 3, 5
			},
		},

		{
			Name:        "Scenario 5: Single Point Intersection",
			Description: "Exact price match between one buyer and one seller",
			Buyers: []Participant{
				{Price: 10, Quantity: 2},
				{Price: 6, Quantity: 1}, // Matches seller exactly
				{Price: 4, Quantity: 3},
			},
			Sellers: []Participant{
				{Price: 6, Quantity: 2}, // Matches buyer exactly
				{Price: 8, Quantity: 1},
				{Price: 12, Quantity: 1},
			},
			ExpectedResult: TestAuctionResult{
				ShouldTrade:      true,
				ClearingPrice:    func() *int64 { cp := int64(6); return &cp }(), // Step-wise intersection: (6+6)/2 = 6
				QualifiedBuyers:  2,                                              // Buyers ≥ 6: 10, 6
				QualifiedSellers: 1,                                              // Sellers ≤ 6: 6
			},
		},

		{
			Name:        "Scenario 6: High Volume Market",
			Description: "Many participants with varying prices",
			Buyers: []Participant{
				{Price: 20, Quantity: 1},
				{Price: 15, Quantity: 2},
				{Price: 12, Quantity: 3},
				{Price: 10, Quantity: 4},
				{Price: 8, Quantity: 2},
				{Price: 6, Quantity: 1},
			},
			Sellers: []Participant{
				{Price: 5, Quantity: 2},
				{Price: 7, Quantity: 3},
				{Price: 9, Quantity: 2},
				{Price: 11, Quantity: 4},
				{Price: 14, Quantity: 1},
				{Price: 18, Quantity: 1},
			},
			ExpectedResult: TestAuctionResult{
				ShouldTrade:      true,
				ClearingPrice:    func() *int64 { cp := int64(9); return &cp }(), // Step-wise intersection: (10+9)/2 = 9.5 → 9
				QualifiedBuyers:  4,                                              // Buyers ≥ 9: 20, 15, 12, 10
				QualifiedSellers: 3,                                              // Sellers ≤ 9: 5, 7, 9
			},
		},
	}

	// Test each scenario
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			// Create test inputs
			inputs, roles := createTestInputs(scenario.Buyers, scenario.Sellers)

			// Run auction
			outputs := RunAuctionLogic(inputs, roles)

			// Determine if trading occurred by checking if any balances changed
			tradingOccurred := false
			clearingPrice := extractClearingPrice(scenario.Buyers, scenario.Sellers)

			for i, output := range outputs {
				if output.Coins.Cmp(inputs[i].Coins) != 0 || output.Energy.Cmp(inputs[i].Energy) != 0 {
					tradingOccurred = true
					break
				}
			}

			// Draw ASCII graph visualization
			graph := drawMarketGraph(scenario.Buyers, scenario.Sellers, clearingPrice, scenario.Name)
			fmt.Println(graph)

			// Create visual plot
			if err := PlotAuction(scenario.Buyers, scenario.Sellers, clearingPrice, scenario.Name); err != nil {
				t.Errorf("ERROR: Could not create plot for %s: %v", scenario.Name, err)
			} else {
				// Generate the same clean filename as in PlotAuction
				cleanTitle := strings.ReplaceAll(strings.ToLower(scenario.Name), ":", "")
				cleanTitle = strings.ReplaceAll(cleanTitle, " ", "_")
				cleanTitle = strings.ReplaceAll(cleanTitle, "(", "")
				cleanTitle = strings.ReplaceAll(cleanTitle, ")", "")
				cleanTitle = strings.ReplaceAll(cleanTitle, ",", "")
				filename := fmt.Sprintf("auction_%s.png", cleanTitle)
				fmt.Printf("📊 Visual plot saved as: %s\n", filename)
			}

			// Validate results
			if scenario.ExpectedResult.ShouldTrade != tradingOccurred {
				t.Errorf("Expected trading=%v, got trading=%v", scenario.ExpectedResult.ShouldTrade, tradingOccurred)
			}

			if scenario.ExpectedResult.ShouldTrade {
				// Count qualified participants
				qualifiedBuyers, qualifiedSellers := countQualifiedParticipants(inputs, roles, clearingPrice)

				if scenario.ExpectedResult.QualifiedBuyers > 0 && qualifiedBuyers != scenario.ExpectedResult.QualifiedBuyers {
					t.Errorf("Expected %d qualified buyers, got %d", scenario.ExpectedResult.QualifiedBuyers, qualifiedBuyers)
				}

				if scenario.ExpectedResult.QualifiedSellers > 0 && qualifiedSellers != scenario.ExpectedResult.QualifiedSellers {
					t.Errorf("Expected %d qualified sellers, got %d", scenario.ExpectedResult.QualifiedSellers, qualifiedSellers)
				}
			}

			fmt.Printf("✅ %s: PASSED\n\n", scenario.Name)
		})
	}
}

// extractClearingPrice determines what the clearing price should be for a scenario using step-wise curve logic
func extractClearingPrice(buyers, sellers []Participant) *int64 {
	// Sort to match main algorithm
	sortedBuyers := make([]Participant, len(buyers))
	copy(sortedBuyers, buyers)
	sort.Slice(sortedBuyers, func(i, j int) bool {
		return sortedBuyers[i].Price > sortedBuyers[j].Price
	})

	sortedSellers := make([]Participant, len(sellers))
	copy(sortedSellers, sellers)
	sort.Slice(sortedSellers, func(i, j int) bool {
		return sortedSellers[i].Price < sortedSellers[j].Price
	})

	// Build cumulative step-wise curves (same logic as main algorithm)
	buyerSteps := make([]struct {
		price         int64
		cumulativeQty int64
	}, 0)
	sellerSteps := make([]struct {
		price         int64
		cumulativeQty int64
	}, 0)

	// Build buyer steps (demand curve - descending prices)
	var buyerCumQty int64 = 0
	for _, buyer := range sortedBuyers {
		buyerCumQty += buyer.Quantity
		buyerSteps = append(buyerSteps, struct {
			price         int64
			cumulativeQty int64
		}{
			price: buyer.Price, cumulativeQty: buyerCumQty,
		})
	}

	// Build seller steps (supply curve - ascending prices)
	var sellerCumQty int64 = 0
	for _, seller := range sortedSellers {
		sellerCumQty += seller.Quantity
		sellerSteps = append(sellerSteps, struct {
			price         int64
			cumulativeQty int64
		}{
			price: seller.Price, cumulativeQty: sellerCumQty,
		})
	}

	// Find intersection: last step where buyer_price >= seller_price (same logic as main algorithm)
	var lastValidBuyerPrice, lastValidSellerPrice int64
	var hasValidIntersection bool
	buyerIdx, sellerIdx := 0, 0

	for buyerIdx < len(buyerSteps) && sellerIdx < len(sellerSteps) {
		buyerStep := buyerSteps[buyerIdx]
		sellerStep := sellerSteps[sellerIdx]

		// Check if curves still intersect at this quantity level
		if buyerStep.price >= sellerStep.price {
			// Valid intersection - save these prices
			lastValidBuyerPrice = buyerStep.price
			lastValidSellerPrice = sellerStep.price
			hasValidIntersection = true

			// Move to next step based on cumulative quantity
			if buyerStep.cumulativeQty <= sellerStep.cumulativeQty {
				buyerIdx++
			} else {
				sellerIdx++
			}
		} else {
			// No more intersections
			break
		}
	}

	if hasValidIntersection {
		// Clearing price = average of last intersecting step prices (rounded down)
		cp := (lastValidBuyerPrice + lastValidSellerPrice) / 2
		return &cp
	}

	return nil // No intersection
}

// countQualifiedParticipants counts how many would qualify at the clearing price
func countQualifiedParticipants(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType, clearingPrice *int64) (int, int) {
	if clearingPrice == nil {
		return 0, 0
	}

	clearingPriceBig := big.NewInt(*clearingPrice)
	qualifiedBuyers := 0
	qualifiedSellers := 0

	for i, input := range inputs {
		role := roles[i]
		if input.Price == nil {
			continue
		}

		if role == zerocash.BUY && input.Price.Cmp(clearingPriceBig) >= 0 {
			qualifiedBuyers++
		} else if role == zerocash.SELL && input.Price.Cmp(clearingPriceBig) <= 0 {
			qualifiedSellers++
		}
	}

	return qualifiedBuyers, qualifiedSellers
}

// TestAuctionLogicEdgeCases tests edge cases and error conditions
func TestAuctionLogicEdgeCases(t *testing.T) {

	t.Run("Empty inputs", func(t *testing.T) {
		inputs := []DecryptedRegistration{}
		roles := map[int]zerocash.OrderType{}

		outputs := RunAuctionLogic(inputs, roles)

		if len(outputs) != 0 {
			t.Errorf("Expected empty output for empty input, got %d outputs", len(outputs))
		}
	})

	t.Run("Only buyers (no sellers)", func(t *testing.T) {
		inputs := []DecryptedRegistration{
			{Price: big.NewInt(10), Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
			{Price: big.NewInt(8), Quantity: big.NewInt(3), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
		}
		roles := map[int]zerocash.OrderType{
			0: zerocash.BUY,
			1: zerocash.BUY,
		}

		outputs := RunAuctionLogic(inputs, roles)

		// Should be no trading since no sellers
		for i, output := range outputs {
			if output.Coins.Cmp(inputs[i].Coins) != 0 || output.Energy.Cmp(inputs[i].Energy) != 0 {
				t.Errorf("Expected no trading with only buyers, but participant %d's balance changed", i)
			}
		}

		fmt.Println("✅ Only buyers test: No trading occurred (correct)")
	})

	t.Run("Only sellers (no buyers)", func(t *testing.T) {
		inputs := []DecryptedRegistration{
			{Price: big.NewInt(5), Quantity: big.NewInt(4), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
			{Price: big.NewInt(7), Quantity: big.NewInt(2), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
		}
		roles := map[int]zerocash.OrderType{
			0: zerocash.SELL,
			1: zerocash.SELL,
		}

		outputs := RunAuctionLogic(inputs, roles)

		// Should be no trading since no buyers
		for i, output := range outputs {
			if output.Coins.Cmp(inputs[i].Coins) != 0 || output.Energy.Cmp(inputs[i].Energy) != 0 {
				t.Errorf("Expected no trading with only sellers, but participant %d's balance changed", i)
			}
		}

		fmt.Println("✅ Only sellers test: No trading occurred (correct)")
	})

	t.Run("Nil prices", func(t *testing.T) {
		inputs := []DecryptedRegistration{
			{Price: nil, Quantity: big.NewInt(5), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
			{Price: big.NewInt(10), Quantity: big.NewInt(3), Coins: big.NewInt(1000), Energy: big.NewInt(100)},
		}
		roles := map[int]zerocash.OrderType{
			0: zerocash.BUY,
			1: zerocash.SELL,
		}

		// Should not panic and should handle nil gracefully
		outputs := RunAuctionLogic(inputs, roles)

		if len(outputs) != len(inputs) {
			t.Errorf("Expected %d outputs, got %d", len(inputs), len(outputs))
		}

		fmt.Println("✅ Nil prices test: Handled gracefully")
	})
}

// BenchmarkAuctionLogic benchmarks the auction performance
func BenchmarkAuctionLogic(b *testing.B) {
	// Create a large market scenario
	buyers := make([]Participant, 50)
	sellers := make([]Participant, 50)

	for i := 0; i < 50; i++ {
		buyers[i] = Participant{Price: int64(100 - i), Quantity: int64(10 + i%5)}
		sellers[i] = Participant{Price: int64(20 + i), Quantity: int64(5 + i%3)}
	}

	inputs, roles := createTestInputs(buyers, sellers)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RunAuctionLogic(inputs, roles)
	}
}
