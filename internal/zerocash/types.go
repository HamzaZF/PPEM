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
