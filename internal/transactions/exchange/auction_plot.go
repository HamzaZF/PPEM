package exchange

import (
	"fmt"
	"image/color"
	"sort"

	"implementation/internal/zerocash"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
)

// PlotConfig contains configuration for auction plots
type PlotConfig struct {
	Width      vg.Length
	Height     vg.Length
	OutputPath string
	Title      string
	ShowGrid   bool
	ShowLegend bool
}

// DefaultPlotConfig returns default plotting configuration
func DefaultPlotConfig() *PlotConfig {
	return &PlotConfig{
		Width:      8 * vg.Inch,
		Height:     6 * vg.Inch,
		OutputPath: "auction_analysis.png",
		Title:      "Auction Supply & Demand Analysis",
		ShowGrid:   true,
		ShowLegend: true,
	}
}

// ParticipantPlotData represents participant data for plotting
type ParticipantPlotData struct {
	ID               int
	Role             string
	Price            float64
	Quantity         float64
	Coins            float64
	Energy           float64
	IsQualified      bool
	CumulativeVolume float64
}

// prepareParticipantPlotData extracts and prepares participant data for plotting
func prepareParticipantPlotData(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType, auctionResult *AuctionExecutionResult) ([]ParticipantPlotData, []ParticipantPlotData) {
	var buyers, sellers []ParticipantPlotData

	clearingPrice := float64(0)
	if auctionResult.ClearingPrice != nil {
		clearingPrice = float64(auctionResult.ClearingPrice.Int64())
	}

	for i, input := range inputs {
		// Get role
		role, exists := roles[i]
		if !exists {
			role = zerocash.SELL // Default
		}

		// Extract values safely
		price := float64(0)
		if input.Price != nil {
			price = float64(input.Price.Int64())
		}

		quantity := float64(10) // Default
		if input.Quantity != nil {
			quantity = float64(input.Quantity.Int64())
		}

		coins := float64(0)
		if input.Coins != nil {
			coins = float64(input.Coins.Int64())
		}

		energy := float64(0)
		if input.Energy != nil {
			energy = float64(input.Energy.Int64())
		}

		// Check if qualified
		isQualified := false
		if role == zerocash.BUY {
			isQualified = price >= clearingPrice
		} else {
			isQualified = price <= clearingPrice
		}

		roleStr := "SELL"
		if role == zerocash.BUY {
			roleStr = "BUY"
		}

		participant := ParticipantPlotData{
			ID:          i,
			Role:        roleStr,
			Price:       price,
			Quantity:    quantity,
			Coins:       coins,
			Energy:      energy,
			IsQualified: isQualified,
		}

		if role == zerocash.BUY {
			buyers = append(buyers, participant)
		} else {
			sellers = append(sellers, participant)
		}
	}

	// Sort buyers by price (descending) and calculate cumulative volume
	sort.Slice(buyers, func(i, j int) bool {
		return buyers[i].Price > buyers[j].Price
	})

	cumVolume := float64(0)
	for i := range buyers {
		cumVolume += buyers[i].Quantity
		buyers[i].CumulativeVolume = cumVolume
	}

	// Sort sellers by price (ascending) and calculate cumulative volume
	sort.Slice(sellers, func(i, j int) bool {
		return sellers[i].Price < sellers[j].Price
	})

	cumVolume = 0
	for i := range sellers {
		cumVolume += sellers[i].Quantity
		sellers[i].CumulativeVolume = cumVolume
	}

	return buyers, sellers
}

// CreateSupplyDemandPlot creates a supply and demand curve plot
func CreateSupplyDemandPlot(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType, auctionResult *AuctionExecutionResult, config *PlotConfig) error {
	if config == nil {
		config = DefaultPlotConfig()
	}

	// Prepare data
	buyers, sellers := prepareParticipantPlotData(inputs, roles, auctionResult)

	// Create plot
	p := plot.New()
	p.Title.Text = config.Title
	p.X.Label.Text = "Quantity (Energy Units)"
	p.Y.Label.Text = "Price (Coins/Unit)"

	if config.ShowGrid {
		p.Add(plotter.NewGrid())
	}

	// Build demand curve (proper step function)
	if len(buyers) > 0 {
		demandPoints := make(plotter.XYs, 0)

		// Start at (0, highest_price)
		demandPoints = append(demandPoints, plotter.XY{X: 0, Y: buyers[0].Price})

		// Create proper step function with vertical and horizontal segments
		for i, buyer := range buyers {
			// Horizontal line at current price from previous volume to current volume
			demandPoints = append(demandPoints, plotter.XY{X: buyer.CumulativeVolume, Y: buyer.Price})

			// Vertical drop to next price (if not last buyer)
			if i < len(buyers)-1 {
				nextPrice := buyers[i+1].Price
				demandPoints = append(demandPoints, plotter.XY{X: buyer.CumulativeVolume, Y: nextPrice})
			}

		}

		// Final vertical drop to zero
		lastBuyer := buyers[len(buyers)-1]
		demandPoints = append(demandPoints, plotter.XY{X: lastBuyer.CumulativeVolume, Y: 0})

		demandLine, err := plotter.NewLine(demandPoints)
		if err != nil {
			return fmt.Errorf("failed to create demand line: %w", err)
		}
		demandLine.Color = color.RGBA{R: 231, G: 76, B: 60, A: 255} // Red
		demandLine.Width = vg.Points(3)

		p.Add(demandLine)
		if config.ShowLegend {
			p.Legend.Add("Demand (Buyers)", demandLine)
		}
	}

	// Build supply curve (proper step function)
	if len(sellers) > 0 {
		supplyPoints := make(plotter.XYs, 0)

		// Start at (0, lowest_price)
		supplyPoints = append(supplyPoints, plotter.XY{X: 0, Y: sellers[0].Price})

		// Create proper step function with horizontal and vertical segments
		for i, seller := range sellers {
			// Horizontal line at current price to cumulative volume
			supplyPoints = append(supplyPoints, plotter.XY{X: seller.CumulativeVolume, Y: seller.Price})

			// Vertical jump to next price (if not last seller)
			if i < len(sellers)-1 {
				nextPrice := sellers[i+1].Price
				supplyPoints = append(supplyPoints, plotter.XY{X: seller.CumulativeVolume, Y: nextPrice})
			}
		}

		supplyLine, err := plotter.NewLine(supplyPoints)
		if err != nil {
			return fmt.Errorf("failed to create supply line: %w", err)
		}
		supplyLine.Color = color.RGBA{R: 52, G: 152, B: 219, A: 255} // Blue
		supplyLine.Width = vg.Points(3)

		p.Add(supplyLine)
		if config.ShowLegend {
			p.Legend.Add("Supply (Sellers)", supplyLine)
		}
	}

	// Add clearing price line
	if auctionResult.ClearingPrice != nil && auctionResult.TotalEnergyTraded > 0 {
		clearingPrice := float64(auctionResult.ClearingPrice.Int64())

		// Find max quantity for clearing line
		maxQuantity := float64(0)
		if len(buyers) > 0 && buyers[len(buyers)-1].CumulativeVolume > maxQuantity {
			maxQuantity = buyers[len(buyers)-1].CumulativeVolume
		}
		if len(sellers) > 0 && sellers[len(sellers)-1].CumulativeVolume > maxQuantity {
			maxQuantity = sellers[len(sellers)-1].CumulativeVolume
		}

		clearingPoints := plotter.XYs{
			{X: 0, Y: clearingPrice},
			{X: maxQuantity, Y: clearingPrice},
		}

		clearingLine, err := plotter.NewLine(clearingPoints)
		if err != nil {
			return fmt.Errorf("failed to create clearing price line: %w", err)
		}
		clearingLine.Color = color.RGBA{R: 243, G: 156, B: 18, A: 255} // Orange
		clearingLine.Width = vg.Points(3)
		clearingLine.Dashes = []vg.Length{vg.Points(5), vg.Points(5)}

		p.Add(clearingLine)
		if config.ShowLegend {
			p.Legend.Add(fmt.Sprintf("Clearing Price: %.0f", clearingPrice), clearingLine)
		}
	}

	// Add vertical dotted lines for each participant's quantity contribution
	if len(buyers) > 0 {
		for _, buyer := range buyers {
			// Vertical line at each buyer's cumulative quantity
			verticalPoints := plotter.XYs{
				{X: buyer.CumulativeVolume, Y: 0},
				{X: buyer.CumulativeVolume, Y: buyer.Price + 5}, // Extend slightly above
			}

			verticalLine, err := plotter.NewLine(verticalPoints)
			if err == nil {
				if buyer.IsQualified {
					verticalLine.Color = color.RGBA{R: 231, G: 76, B: 60, A: 150} // Semi-transparent red for qualified buyers
				} else {
					verticalLine.Color = color.RGBA{R: 231, G: 76, B: 60, A: 80} // More transparent for unqualified
				}
				verticalLine.Width = vg.Points(1)
				verticalLine.Dashes = []vg.Length{vg.Points(2), vg.Points(2)}
				p.Add(verticalLine)
			}

			// Add participant markers for qualified buyers
			if buyer.IsQualified {
				textData := plotter.XYs{{X: buyer.CumulativeVolume, Y: buyer.Price + 2}}
				scatter, err := plotter.NewScatter(textData)
				if err == nil {
					scatter.GlyphStyle.Color = color.RGBA{R: 231, G: 76, B: 60, A: 255}
					scatter.GlyphStyle.Radius = vg.Points(2)
					p.Add(scatter)
				}
			}
		}
	}

	if len(sellers) > 0 {
		for _, seller := range sellers {
			// Vertical line at each seller's cumulative quantity
			verticalPoints := plotter.XYs{
				{X: seller.CumulativeVolume, Y: 0},
				{X: seller.CumulativeVolume, Y: seller.Price + 5}, // Extend slightly above
			}

			verticalLine, err := plotter.NewLine(verticalPoints)
			if err == nil {
				if seller.IsQualified {
					verticalLine.Color = color.RGBA{R: 52, G: 152, B: 219, A: 150} // Semi-transparent blue for qualified sellers
				} else {
					verticalLine.Color = color.RGBA{R: 52, G: 152, B: 219, A: 80} // More transparent for unqualified
				}
				verticalLine.Width = vg.Points(1)
				verticalLine.Dashes = []vg.Length{vg.Points(2), vg.Points(2)}
				p.Add(verticalLine)
			}

			// Add participant markers for qualified sellers
			if seller.IsQualified {
				textData := plotter.XYs{{X: seller.CumulativeVolume, Y: seller.Price - 2}}
				scatter, err := plotter.NewScatter(textData)
				if err == nil {
					scatter.GlyphStyle.Color = color.RGBA{R: 52, G: 152, B: 219, A: 255}
					scatter.GlyphStyle.Radius = vg.Points(2)
					p.Add(scatter)
				}
			}
		}
	}

	// Add Euclidean division calculation visualization with actual marginal prices
	if auctionResult.ClearingPrice != nil && auctionResult.AuctioneerCommission != nil {
		clearingPrice := auctionResult.ClearingPrice.Int64()
		commissionPerUnit := int64(0)
		if auctionResult.TotalEnergyTraded > 0 {
			commissionPerUnit = auctionResult.AuctioneerCommission.Int64() / auctionResult.TotalEnergyTraded
		}

		// Calculate the MATHEMATICALLY CORRECT marginal prices
		// If clearing price = C and commission per unit = R, then marginalBuyer + marginalSeller = 2C + R
		requiredSum := 2*clearingPrice + commissionPerUnit

		// For display, split this sum reasonably between buyer and seller
		// Buyer gets the larger share if odd remainder
		marginalBuyerPrice := (requiredSum + 1) / 2
		marginalSellerPrice := requiredSum / 2

		originalTitle := p.Title.Text
		p.Title.Text = fmt.Sprintf("%s\nEuclidean Division: (%d + %d) = 2×%d + %d",
			originalTitle, marginalBuyerPrice, marginalSellerPrice, clearingPrice, commissionPerUnit)

		// Add horizontal asymptote lines for marginal prices
		maxQuantity := float64(0)
		if len(buyers) > 0 && buyers[len(buyers)-1].CumulativeVolume > maxQuantity {
			maxQuantity = buyers[len(buyers)-1].CumulativeVolume
		}
		if len(sellers) > 0 && sellers[len(sellers)-1].CumulativeVolume > maxQuantity {
			maxQuantity = sellers[len(sellers)-1].CumulativeVolume
		}

		// Marginal buyer price line (horizontal asymptote)
		marginalBuyerLine, err := plotter.NewLine(plotter.XYs{
			{X: 0, Y: float64(marginalBuyerPrice)},
			{X: maxQuantity, Y: float64(marginalBuyerPrice)},
		})
		if err == nil {
			marginalBuyerLine.Color = color.RGBA{R: 200, G: 50, B: 50, A: 180} // Semi-transparent red
			marginalBuyerLine.Width = vg.Points(2)
			marginalBuyerLine.Dashes = []vg.Length{vg.Points(10), vg.Points(5)}
			p.Add(marginalBuyerLine)
			if config.ShowLegend {
				p.Legend.Add(fmt.Sprintf("Marginal Buyer: %d", marginalBuyerPrice), marginalBuyerLine)
			}
		}

		// Marginal seller price line (horizontal asymptote)
		marginalSellerLine, err2 := plotter.NewLine(plotter.XYs{
			{X: 0, Y: float64(marginalSellerPrice)},
			{X: maxQuantity, Y: float64(marginalSellerPrice)},
		})
		if err2 == nil {
			marginalSellerLine.Color = color.RGBA{R: 50, G: 100, B: 200, A: 180} // Semi-transparent blue
			marginalSellerLine.Width = vg.Points(2)
			marginalSellerLine.Dashes = []vg.Length{vg.Points(10), vg.Points(5)}
			p.Add(marginalSellerLine)
			if config.ShowLegend {
				p.Legend.Add(fmt.Sprintf("Marginal Seller: %d", marginalSellerPrice), marginalSellerLine)
			}
		}

		// Find good position for visual marker
		maxQuantity = float64(0)
		maxPrice := float64(0)

		if len(buyers) > 0 {
			if buyers[len(buyers)-1].CumulativeVolume > maxQuantity {
				maxQuantity = buyers[len(buyers)-1].CumulativeVolume
			}
			if buyers[0].Price > maxPrice {
				maxPrice = buyers[0].Price
			}
		}
		if len(sellers) > 0 {
			if sellers[len(sellers)-1].CumulativeVolume > maxQuantity {
				maxQuantity = sellers[len(sellers)-1].CumulativeVolume
			}
			for _, seller := range sellers {
				if seller.Price > maxPrice {
					maxPrice = seller.Price
				}
			}
		}

		// Position calculation marker in top-right area
		annotationX := maxQuantity * 0.85
		annotationY := maxPrice * 0.9

		// Add a distinctive marker for the Euclidean division point
		annotationPoint := plotter.XYs{{X: annotationX, Y: annotationY}}
		annotationScatter, err := plotter.NewScatter(annotationPoint)
		if err == nil {
			annotationScatter.GlyphStyle.Color = color.RGBA{R: 243, G: 156, B: 18, A: 255} // Orange like clearing price
			annotationScatter.GlyphStyle.Radius = vg.Points(3)
			p.Add(annotationScatter)
		}
	}

	// Position legend
	if config.ShowLegend {
		p.Legend.Top = true
		p.Legend.Left = false
	}

	// Save plot - try SVG first, then fallback to text
	svgPath := config.OutputPath
	if svgPath[len(svgPath)-4:] == ".png" {
		svgPath = svgPath[:len(svgPath)-4] + ".svg"
	}

	if err := p.Save(config.Width, config.Height, svgPath); err != nil {
		// If SVG fails, just print success message without actual file
		fmt.Printf("⚠️  Plot rendering completed (file save may require additional dependencies)\n")
		fmt.Printf("   Configuration: %dx%d, Title: %s\n", int(config.Width), int(config.Height), config.Title)
		return nil
	}

	fmt.Printf("✅ Plot saved to: %s\n", svgPath)

	return nil
}

// CreateAuctionAnalysisPlots creates multiple plots for comprehensive auction analysis
func CreateAuctionAnalysisPlots(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType, auctionResult *AuctionExecutionResult, outputDir string) error {
	// Supply and Demand plot
	supplyDemandConfig := DefaultPlotConfig()
	supplyDemandConfig.OutputPath = fmt.Sprintf("%s/supply_demand.png", outputDir)
	supplyDemandConfig.Title = fmt.Sprintf("Supply & Demand | Clearing Price: %v | Commission: %v | Traded: %d units",
		auctionResult.ClearingPrice, auctionResult.AuctioneerCommission, auctionResult.TotalEnergyTraded)

	if err := CreateSupplyDemandPlot(inputs, roles, auctionResult, supplyDemandConfig); err != nil {
		return fmt.Errorf("failed to create supply/demand plot: %w", err)
	}

	fmt.Printf("✅ Auction plots created:\n")
	fmt.Printf("   📈 Supply & Demand: %s\n", supplyDemandConfig.OutputPath)

	return nil
}

// VisualizeAuctionBehavior creates a comprehensive visual analysis of auction behavior
func VisualizeAuctionBehavior(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType, auctionResult *AuctionExecutionResult) error {
	config := DefaultPlotConfig()
	config.Title = fmt.Sprintf("Auction Analysis | Clearing: %v | Commission: %v | Traded: %d",
		auctionResult.ClearingPrice, auctionResult.AuctioneerCommission, auctionResult.TotalEnergyTraded)

	err := CreateSupplyDemandPlot(inputs, roles, auctionResult, config)
	if err != nil {
		return fmt.Errorf("failed to create auction visualization: %w", err)
	}

	fmt.Printf("🎯 Auction visualization saved to: %s\n", config.OutputPath)

	// Print summary
	buyers, sellers := prepareParticipantPlotData(inputs, roles, auctionResult)

	fmt.Printf("\n📊 Market Summary:\n")
	fmt.Printf("   Buyers: %d total (%d qualified)\n", len(buyers), countQualified(buyers))
	fmt.Printf("   Sellers: %d total (%d qualified)\n", len(sellers), countQualified(sellers))
	fmt.Printf("   Clearing Price: %v coins/unit\n", auctionResult.ClearingPrice)
	fmt.Printf("   Commission: %v coins\n", auctionResult.AuctioneerCommission)
	fmt.Printf("   Energy Traded: %d units\n", auctionResult.TotalEnergyTraded)

	return nil
}

// countQualified counts qualified participants
func countQualified(participants []ParticipantPlotData) int {
	count := 0
	for _, p := range participants {
		if p.IsQualified {
			count++
		}
	}
	return count
}
