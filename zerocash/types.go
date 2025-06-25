package zerocash

import "math/big"

// Gamma represents the value of a note (coins and energy)
type Gamma struct {
	Coins  *big.Int
	Energy *big.Int
}

// Params holds protocol and curve parameters (can be extended as needed)
type Params struct {
	// Add curve, field, or protocol parameters here if needed
}
