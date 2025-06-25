package zerocash

import "math/big"

// Note represents a confidential transaction note
// (commitment, owner, randomness, etc.)
type Note struct {
	Value   Gamma  // The value (coins and energy) of the note
	PkOwner []byte // Public key of the note owner
	Rho     []byte // Randomness for commitment
	Rand    []byte // Additional randomness
	Cm      []byte // Commitment to the note
}

// NewNote creates a new note with given coins, energy, and secret key
func NewNote(coins, energy *big.Int, sk []byte) *Note {
	rho := randomBytes(32)
	rand := randomBytes(32)
	pk := mimcHash(sk)
	cm := Commitment(coins, energy, new(big.Int).SetBytes(rho), new(big.Int).SetBytes(rand))
	return &Note{
		Value: Gamma{
			Coins:  coins,
			Energy: energy,
		},
		PkOwner: pk,
		Rho:     rho,
		Rand:    rand,
		Cm:      cm,
	}
}
