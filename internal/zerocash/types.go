// types.go - Core types for the zerocash confidential transaction protocol.
//
// Defines value representations and protocol parameters shared across the package.

package zerocash

import "math/big"

// Gamma represents the value of a note (coins and energy).
// Both fields are arbitrary-precision integers for flexibility.
type Gamma struct {
	Coins  *big.Int // Amount of coins
	Energy *big.Int // Amount of energy
}

// Params holds protocol and curve parameters.
// Extend this struct to add protocol-wide configuration or cryptographic parameters.
type Params struct {
	// Add curve, field, or protocol parameters here if needed
}

// OrderType represents the type of energy market order
type OrderType int

const (
	BUY  OrderType = 0 // "I want to buy energy"
	SELL OrderType = 1 // "I want to sell energy"
)

// String returns the string representation of the order type
func (o OrderType) String() string {
	switch o {
	case BUY:
		return "BUY"
	case SELL:
		return "SELL"
	default:
		return "UNKNOWN"
	}
}

// EnergyOrder represents a participant's energy market order
type EnergyOrder struct {
	Type     OrderType // BUY or SELL
	Quantity *big.Int  // Amount of energy to buy/sell
	Price    *big.Int  // Price per unit (max for BUY, min for SELL)
}
