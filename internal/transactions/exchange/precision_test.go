// precision_test.go - Comprehensive precision testing for fixed-point arithmetic in auctions
//
// This file demonstrates how to assess precision loss from fixed-point arithmetic
// and provides tools to optimize scaling factors for auction calculations.

package exchange

import (
	"fmt"
	"testing"
)

// TestPrecisionLoss tests precision loss with different scaling factors
func TestPrecisionLoss(t *testing.T) {
	testCases := []PrecisionTestCase{
		// Small price values (typical energy prices)
		{
			Name:             "Small Price - 8 bits",
			Value:            0.05,
			ScaleBits:        8,
			MaxAbsoluteError: 0.004, // Realistic threshold for 8-bit
			MaxRelativeError: 0.08,  // Realistic threshold for 8-bit
		},
		{
			Name:             "Small Price - 16 bits",
			Value:            0.05,
			ScaleBits:        16,
			MaxAbsoluteError: 0.0001,
			MaxRelativeError: 0.002,
		},
		{
			Name:             "Small Price - 20 bits",
			Value:            0.05,
			ScaleBits:        20,
			MaxAbsoluteError: 0.00001,
			MaxRelativeError: 0.0002,
		},
		// Medium price values
		{
			Name:             "Medium Price - 12 bits",
			Value:            25.75,
			ScaleBits:        12,
			MaxAbsoluteError: 0.01,
			MaxRelativeError: 0.0005,
		},
		{
			Name:             "Medium Price - 16 bits",
			Value:            25.75,
			ScaleBits:        16,
			MaxAbsoluteError: 0.001,
			MaxRelativeError: 0.00005,
		},
		// Large price values
		{
			Name:             "Large Price - 16 bits",
			Value:            1000.123,
			ScaleBits:        16,
			MaxAbsoluteError: 0.1,
			MaxRelativeError: 0.0001,
		},
		// High precision requirements
		{
			Name:             "High Precision - 20 bits",
			Value:            123.456789,
			ScaleBits:        20,
			MaxAbsoluteError: 0.00001,
			MaxRelativeError: 0.00001,
		},
	}

	fmt.Println("=== PRECISION LOSS ANALYSIS ===")
	fmt.Printf("%-25s %8s %12s %12s %12s %8s %8s\n",
		"Test Case", "Original", "Recovered", "Abs Error", "Rel Error", "Scale", "Pass")
	fmt.Println("---------------------------------------------------------------------------------")

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			metrics := AnalyzePrecisionLoss(testCase.Value, testCase.ScaleBits)

			// Print results
			fmt.Printf("%-25s %8.6f %12.6f %12.8f %12.8f %8d %8t\n",
				testCase.Name,
				metrics.Original,
				metrics.Recovered,
				metrics.AbsoluteError,
				metrics.RelativeError,
				1<<testCase.ScaleBits,
				metrics.AbsoluteError <= testCase.MaxAbsoluteError,
			)

			// Test absolute error
			if metrics.AbsoluteError > testCase.MaxAbsoluteError {
				t.Errorf("Absolute error %.8f exceeds maximum %.8f",
					metrics.AbsoluteError, testCase.MaxAbsoluteError)
			}

			// Test relative error
			if metrics.RelativeError > testCase.MaxRelativeError {
				t.Errorf("Relative error %.8f exceeds maximum %.8f",
					metrics.RelativeError, testCase.MaxRelativeError)
			}
		})
	}
}

// TestOptimalScaling tests finding optimal scaling factors
func TestOptimalScaling(t *testing.T) {
	scenarios := []struct {
		name         string
		priceRange   [2]float64
		maxError     float64
		expectedBits int
	}{
		{
			name:         "Energy Trading (Low Prices)",
			priceRange:   [2]float64{0.01, 100.0},
			maxError:     0.001,
			expectedBits: 16,
		},
		{
			name:         "High-Value Trading",
			priceRange:   [2]float64{100.0, 10000.0},
			maxError:     0.01,
			expectedBits: 16,
		},
		{
			name:         "Micro-transactions",
			priceRange:   [2]float64{0.0001, 1.0},
			maxError:     0.00001,
			expectedBits: 20,
		},
	}

	fmt.Println("\n=== OPTIMAL SCALING ANALYSIS ===")
	fmt.Printf("%-30s %15s %10s %12s %10s\n",
		"Scenario", "Price Range", "Max Error", "Optimal Bits", "Scale Factor")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			optimalBits := findOptimalScaling(scenario.priceRange, scenario.maxError)
			scaleFactor := 1 << optimalBits

			fmt.Printf("%-30s [%.6f, %.2f] %10.6f %12d %10d\n",
				scenario.name,
				scenario.priceRange[0],
				scenario.priceRange[1],
				scenario.maxError,
				optimalBits,
				scaleFactor,
			)

			// Verify the optimal scaling meets requirements
			worstCase := testWorstCasePrecision(scenario.priceRange, optimalBits)
			if worstCase.AbsoluteError > scenario.maxError {
				t.Errorf("Optimal scaling %d bits still exceeds error requirement: %.8f > %.8f",
					optimalBits, worstCase.AbsoluteError, scenario.maxError)
			}
		})
	}
}

// TestAuctionPrecisionRequirements tests precision requirements for auction calculations
func TestAuctionPrecisionRequirements(t *testing.T) {
	// Test typical auction scenarios
	auctionScenarios := []struct {
		name          string
		avgBidPrice   float64
		avgAskPrice   float64
		tradeQuantity float64
		scaleBits     int
		maxPriceError float64
		maxValueError float64
	}{
		{
			name:          "Standard Energy Auction",
			avgBidPrice:   35.50,
			avgAskPrice:   38.25,
			tradeQuantity: 10.0,
			scaleBits:     16,
			maxPriceError: 0.01,
			maxValueError: 0.10,
		},
		{
			name:          "High-Frequency Trading",
			avgBidPrice:   125.789,
			avgAskPrice:   126.123,
			tradeQuantity: 100.0,
			scaleBits:     20,
			maxPriceError: 0.001,
			maxValueError: 0.10,
		},
		{
			name:          "Micro-Energy Trading",
			avgBidPrice:   0.0123,
			avgAskPrice:   0.0156,
			tradeQuantity: 1000.0,
			scaleBits:     18,
			maxPriceError: 0.0001,
			maxValueError: 0.10,
		},
	}

	fmt.Println("\n=== AUCTION PRECISION REQUIREMENTS ===")
	fmt.Printf("%-25s %12s %12s %12s %8s %12s\n",
		"Scenario", "Clearing Price", "Price Error", "Trade Value", "Scale", "Value Error")
	fmt.Println("-------------------------------------------------------------------------------------")

	for _, scenario := range auctionScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Compute market clearing price
			clearingPrice := (scenario.avgBidPrice + scenario.avgAskPrice) / 2.0

			// Analyze precision loss for clearing price
			priceMetrics := AnalyzePrecisionLoss(clearingPrice, scenario.scaleBits)

			// Compute trade value and analyze precision loss
			tradeValue := clearingPrice * scenario.tradeQuantity
			valueMetrics := AnalyzePrecisionLoss(tradeValue, scenario.scaleBits)

			fmt.Printf("%-25s %12.6f %12.8f %12.2f %8d %12.6f\n",
				scenario.name,
				clearingPrice,
				priceMetrics.AbsoluteError,
				tradeValue,
				1<<scenario.scaleBits,
				valueMetrics.AbsoluteError,
			)

			// Test price precision
			if priceMetrics.AbsoluteError > scenario.maxPriceError {
				t.Errorf("Price precision error %.8f exceeds maximum %.8f",
					priceMetrics.AbsoluteError, scenario.maxPriceError)
			}

			// Test value precision
			if valueMetrics.AbsoluteError > scenario.maxValueError {
				t.Errorf("Value precision error %.6f exceeds maximum %.6f",
					valueMetrics.AbsoluteError, scenario.maxValueError)
			}
		})
	}
}

// TestScalingRecommendations provides scaling recommendations for different use cases
func TestScalingRecommendations(t *testing.T) {
	recommendations := []struct {
		useCase         string
		priceRange      [2]float64
		precisionReq    float64
		recommendedBits int
		reasoning       string
	}{
		{
			useCase:         "Energy Trading (Standard)",
			priceRange:      [2]float64{0.01, 100.0},
			precisionReq:    0.001,
			recommendedBits: 16,
			reasoning:       "16 bits provides 4 decimal places precision, suitable for energy prices",
		},
		{
			useCase:         "High-Frequency Trading",
			priceRange:      [2]float64{50.0, 1000.0},
			precisionReq:    0.0001,
			recommendedBits: 20,
			reasoning:       "20 bits required for sub-cent precision in high-value trades",
		},
		{
			useCase:         "Micro-payments",
			priceRange:      [2]float64{0.0001, 1.0},
			precisionReq:    0.00001,
			recommendedBits: 24,
			reasoning:       "24 bits needed for micro-payment precision requirements",
		},
		{
			useCase:         "Circuit Efficiency",
			priceRange:      [2]float64{1.0, 1000.0},
			precisionReq:    0.01,
			recommendedBits: 12,
			reasoning:       "12 bits balances precision with circuit complexity",
		},
	}

	fmt.Println("\n=== SCALING RECOMMENDATIONS ===")
	fmt.Printf("%-30s %15s %12s %8s %s\n",
		"Use Case", "Price Range", "Precision", "Bits", "Reasoning")
	fmt.Println("-------------------------------------------------------------------------------------")

	for _, rec := range recommendations {
		fmt.Printf("%-30s [%.6f, %.2f] %12.6f %8d %s\n",
			rec.useCase,
			rec.priceRange[0],
			rec.priceRange[1],
			rec.precisionReq,
			rec.recommendedBits,
			rec.reasoning,
		)

		// Verify recommendation meets requirements
		worstCase := testWorstCasePrecision(rec.priceRange, rec.recommendedBits)
		if worstCase.AbsoluteError > rec.precisionReq {
			t.Errorf("Recommendation for %s doesn't meet precision requirement: %.8f > %.8f",
				rec.useCase, worstCase.AbsoluteError, rec.precisionReq)
		}
	}
}

// findOptimalScaling finds the optimal number of bits for a given price range and error requirement
func findOptimalScaling(priceRange [2]float64, maxError float64) int {
	for bits := 8; bits <= 32; bits++ {
		worstCase := testWorstCasePrecision(priceRange, bits)
		if worstCase.AbsoluteError <= maxError {
			return bits
		}
	}
	return 32 // Maximum practical scaling
}

// testWorstCasePrecision tests precision loss for the worst case in a price range
func testWorstCasePrecision(priceRange [2]float64, scaleBits int) PrecisionMetrics {
	// Test both ends of the range and some middle values
	testValues := []float64{
		priceRange[0],
		priceRange[1],
		(priceRange[0] + priceRange[1]) / 2.0,
		priceRange[0] + 0.1*(priceRange[1]-priceRange[0]),
		priceRange[0] + 0.9*(priceRange[1]-priceRange[0]),
	}

	worstCase := PrecisionMetrics{}
	for _, value := range testValues {
		metrics := AnalyzePrecisionLoss(value, scaleBits)
		if metrics.AbsoluteError > worstCase.AbsoluteError {
			worstCase = metrics
		}
	}

	return worstCase
}

// BenchmarkFixedPointOperations benchmarks fixed-point arithmetic operations
func BenchmarkFixedPointOperations(b *testing.B) {
	const scaleBits = 16
	const scale = 1 << scaleBits

	// Test values
	price1 := 35.50
	price2 := 38.25
	quantity := 10.0

	// Convert to fixed-point
	fixedPrice1 := int64(price1 * scale)
	fixedPrice2 := int64(price2 * scale)
	fixedQuantity := int64(quantity * scale)

	b.Run("Addition", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = fixedPrice1 + fixedPrice2
		}
	})

	b.Run("Multiplication", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = (fixedPrice1 * fixedQuantity) >> scaleBits
		}
	})

	b.Run("Division", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = (fixedPrice1 << scaleBits) / fixedPrice2
		}
	})

	b.Run("Float Conversion", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = float64(fixedPrice1) / float64(scale)
		}
	})
}

// Example usage and demonstration
func ExamplePrecisionAnalysis() {
	// Example: Analyzing precision for a typical energy auction
	fmt.Println("=== PRECISION ANALYSIS EXAMPLE ===")

	// Test different scaling factors
	scalingOptions := []int{8, 12, 16, 20, 24}
	testPrice := 35.75 // Typical energy price

	fmt.Printf("Price: $%.6f\n", testPrice)
	fmt.Printf("%-6s %-12s %-12s %-12s\n", "Bits", "Scale", "Abs Error", "Rel Error")
	fmt.Println("--------------------------------------------")

	for _, bits := range scalingOptions {
		metrics := AnalyzePrecisionLoss(testPrice, bits)
		fmt.Printf("%-6d %-12d %-12.8f %-12.8f\n",
			bits, 1<<bits, metrics.AbsoluteError, metrics.RelativeError)
	}

	// Recommendation
	fmt.Println("\nRecommendation: Use 16 bits for energy trading (provides 4 decimal places)")
	fmt.Println("This gives absolute error < 0.0001 for prices up to $1000")
}
