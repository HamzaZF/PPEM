package exchange

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"implementation/internal/zerocash"
)

// ParticipantState represents the state of a participant before or after trading
type ParticipantState struct {
	ID          int      `json:"id"`
	Role        string   `json:"role"`
	Price       *big.Int `json:"price"`
	Quantity    *big.Int `json:"quantity"`
	Coins       *big.Int `json:"coins"`
	Energy      *big.Int `json:"energy"`
	IsQualified bool     `json:"is_qualified"`
	TradeAmount int64    `json:"trade_amount"`
}

// TradeExecution represents details of a single trade
type TradeExecution struct {
	BuyerID   int      `json:"buyer_id"`
	SellerID  int      `json:"seller_id"`
	Quantity  int64    `json:"quantity"`
	Price     *big.Int `json:"price"`
	TotalCost *big.Int `json:"total_cost"`
}

// EuclideanDivisionData represents the mathematical verification
type EuclideanDivisionData struct {
	MarginalBuyerPrice  *big.Int `json:"marginal_buyer_price"`
	MarginalSellerPrice *big.Int `json:"marginal_seller_price"`
	ClearingPrice       *big.Int `json:"clearing_price"`
	IsValid             bool     `json:"is_valid"`
}

// ConservationData represents conservation law verification
type ConservationData struct {
	TotalInputCoins   *big.Int `json:"total_input_coins"`
	TotalInputEnergy  *big.Int `json:"total_input_energy"`
	TotalOutputCoins  *big.Int `json:"total_output_coins"`
	TotalOutputEnergy *big.Int `json:"total_output_energy"`
	CoinsConserved    bool     `json:"coins_conserved"`
	EnergyConserved   bool     `json:"energy_conserved"`
	ParticipantCount  int      `json:"participant_count"`
	TotalOutputCount  int      `json:"total_output_count"`
}

// AuctionExportData represents the complete auction results for JSON export
type AuctionExportData struct {
	Metadata struct {
		Timestamp         time.Time `json:"timestamp"`
		TotalParticipants int       `json:"total_participants"`
		BuyerCount        int       `json:"buyer_count"`
		SellerCount       int       `json:"seller_count"`
		TradingOccurred   bool      `json:"trading_occurred"`
		ExportVersion     string    `json:"export_version"`
	} `json:"metadata"`

	MarketData struct {
		ClearingPrice     *big.Int `json:"clearing_price"`
		TotalEnergyTraded int64    `json:"total_energy_traded"`
		TotalCoinsTraded  int64    `json:"total_coins_traded"`
		QualifiedBuyers   int      `json:"qualified_buyers"`
		QualifiedSellers  int      `json:"qualified_sellers"`
	} `json:"market_data"`

	ParticipantsBefore []ParticipantState    `json:"participants_before"`
	ParticipantsAfter  []ParticipantState    `json:"participants_after"`
	Trades             []TradeExecution      `json:"trades"`
	EuclideanDivision  EuclideanDivisionData `json:"euclidean_division"`
	Conservation       ConservationData      `json:"conservation"`
}

// ExportAuctionToJSON creates a comprehensive JSON export of auction results
func ExportAuctionToJSON(
	inputs []DecryptedRegistration,
	roles map[int]zerocash.OrderType,
	auctionResult *AuctionExecutionResult,
	outputDir string,
	filename string,
) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize export data
	exportData := AuctionExportData{}

	// Fill metadata
	exportData.Metadata.Timestamp = time.Now()
	exportData.Metadata.TotalParticipants = len(inputs)
	exportData.Metadata.TradingOccurred = auctionResult.TotalEnergyTraded > 0
	exportData.Metadata.ExportVersion = "2.0"

	// Count buyers and sellers
	for _, role := range roles {
		if role == zerocash.BUY {
			exportData.Metadata.BuyerCount++
		} else {
			exportData.Metadata.SellerCount++
		}
	}

	// Fill market data
	exportData.MarketData.ClearingPrice = auctionResult.ClearingPrice
	exportData.MarketData.TotalEnergyTraded = auctionResult.TotalEnergyTraded
	exportData.MarketData.TotalCoinsTraded = auctionResult.TotalCoinsTraded
	exportData.MarketData.QualifiedBuyers = auctionResult.QualifiedBuyers
	exportData.MarketData.QualifiedSellers = auctionResult.QualifiedSellers

	// Create participants before trading
	clearingPrice := float64(0)
	if auctionResult.ClearingPrice != nil {
		clearingPrice = float64(auctionResult.ClearingPrice.Int64())
	}

	for i, input := range inputs {
		role := roles[i]
		roleStr := "SELL"
		if role == zerocash.BUY {
			roleStr = "BUY"
		}

		price := float64(0)
		if input.Price != nil {
			price = float64(input.Price.Int64())
		}

		isQualified := false
		if role == zerocash.BUY {
			isQualified = price >= clearingPrice
		} else {
			isQualified = price <= clearingPrice
		}

		beforeState := ParticipantState{
			ID:          i,
			Role:        roleStr,
			Price:       input.Price,
			Quantity:    input.Quantity,
			Coins:       input.Coins,
			Energy:      input.Energy,
			IsQualified: isQualified,
			TradeAmount: 0,
		}
		exportData.ParticipantsBefore = append(exportData.ParticipantsBefore, beforeState)
	}

	// Create participants after trading and calculate trade amounts
	for i, output := range auctionResult.Outputs {
		role := roles[i]
		roleStr := "SELL"
		if role == zerocash.BUY {
			roleStr = "BUY"
		}

		input := inputs[i]

		// Calculate trade amount (change in energy)
		tradeAmount := int64(0)
		if input.Energy != nil && output.Energy != nil {
			energyDiff := new(big.Int).Sub(output.Energy, input.Energy)
			tradeAmount = energyDiff.Int64()
		}

		price := float64(0)
		if input.Price != nil {
			price = float64(input.Price.Int64())
		}

		isQualified := false
		if role == zerocash.BUY {
			isQualified = price >= clearingPrice
		} else {
			isQualified = price <= clearingPrice
		}

		afterState := ParticipantState{
			ID:          i,
			Role:        roleStr,
			Price:       input.Price,
			Quantity:    input.Quantity,
			Coins:       output.Coins,
			Energy:      output.Energy,
			IsQualified: isQualified,
			TradeAmount: tradeAmount,
		}
		exportData.ParticipantsAfter = append(exportData.ParticipantsAfter, afterState)
	}

	// Calculate Euclidean division data
	exportData.EuclideanDivision = EuclideanDivisionData{ MarginalBuyerPrice: auctionResult.MarginalBuyerPrice, MarginalSellerPrice: auctionResult.MarginalSellerPrice, ClearingPrice: auctionResult.ClearingPrice, IsValid: auctionResult.TotalEnergyTraded > 0 }

	// Calculate conservation data
	exportData.Conservation = calculateConservation(inputs, auctionResult)

	// Marshal to JSON with pretty printing
	jsonData, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal auction data to JSON: %w", err)
	}

	// Write to file
	filePath := filepath.Join(outputDir, filename)
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}

// calculateConservation verifies conservation laws
func calculateConservation(
	inputs []DecryptedRegistration,
	auctionResult *AuctionExecutionResult,
) ConservationData {
	data := ConservationData{}

	// Calculate input totals
	data.TotalInputCoins = big.NewInt(0)
	data.TotalInputEnergy = big.NewInt(0)
	for _, input := range inputs {
		if input.Coins != nil {
			data.TotalInputCoins.Add(data.TotalInputCoins, input.Coins)
		}
		if input.Energy != nil {
			data.TotalInputEnergy.Add(data.TotalInputEnergy, input.Energy)
		}
	}

	// Calculate output totals (participants only)
	participantOutputCoins := big.NewInt(0)
	participantOutputEnergy := big.NewInt(0)
	for _, output := range auctionResult.Outputs {
		if output.Coins != nil {
			participantOutputCoins.Add(participantOutputCoins, output.Coins)
		}
		if output.Energy != nil {
			participantOutputEnergy.Add(participantOutputEnergy, output.Energy)
		}
	}

	// Add auctioneer contribution
	data.TotalOutputCoins = new(big.Int).Set(participantOutputCoins)
	data.TotalOutputEnergy = new(big.Int).Set(participantOutputEnergy)

	// Check conservation
	data.CoinsConserved = data.TotalInputCoins.Cmp(data.TotalOutputCoins) == 0
	data.EnergyConserved = data.TotalInputEnergy.Cmp(data.TotalOutputEnergy) == 0

	// Count participants
	data.ParticipantCount = len(inputs)
	data.TotalOutputCount = len(auctionResult.Outputs)

	return data
}
