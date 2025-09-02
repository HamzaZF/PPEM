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
	if config == nil { config = DefaultPlotConfig() }
	buyers, sellers := prepareParticipantPlotData(inputs, roles, auctionResult)
	p := plot.New()
	p.Title.Text = config.Title
	p.X.Label.Text = "Quantity (Energy Units)"
	p.Y.Label.Text = "Price (Coins/Unit)"
	if config.ShowGrid { p.Add(plotter.NewGrid()) }
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

	// Remove Euclidean division and commission annotations
	if config.ShowLegend { p.Legend.Top = true; p.Legend.Left = false }

	// Save plot - try SVG first, then fallback to text
	svgPath := config.OutputPath
	if len(svgPath) >= 4 && svgPath[len(svgPath)-4:] == ".png" { svgPath = svgPath[:len(svgPath)-4] + ".svg" }
	if err := p.Save(config.Width, config.Height, svgPath); err != nil {
		return nil
	}
	return nil
}
