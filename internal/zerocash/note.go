// note.go - Note type and logic for the zerocash confidential transaction protocol.
//
// A Note represents a confidential asset (coins, energy) owned by a participant.
// Notes are committed, unlinkable, and can be transferred using zero-knowledge proofs.

package zerocash

import "math/big"

// Note represents a confidential transaction note.
// Each note is a commitment to value, owner, and randomness.
type Note struct {
	Value   Gamma  // The value (coins and energy) of the note
	PkOwner []byte // Public key of the note owner (commitment to owner's secret key)
	Rho     []byte // Randomness for commitment (unique per note)
	Rand    []byte // Additional randomness (for hiding, unlinkability)
	Cm      []byte // Commitment to the note (MiMC hash of all fields)
}

// NewNote creates a new note with the given coins, energy, and secret key.
// The note is randomized and committed using MiMC following paper spec: cm = Com(Γ || pk || ρ, r).
func NewNote(coins, energy *big.Int, sk []byte) *Note {
	rho := randomBytes(32)
	rand := randomBytes(32)
	pk := mimcHash(sk)
	// Commitment follows paper: cm = Com(Γ || pk || ρ, r)
	cm := Commitment(coins, energy, pk, new(big.Int).SetBytes(rho), new(big.Int).SetBytes(rand))
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
