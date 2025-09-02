// commitment.go - Cryptographic commitment utilities
package crypto

import (
	"math/big"

	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
)

// Commitment computes a MiMC-based commitment
func Commitment(coins, energy *big.Int, pk []byte, rho, r *big.Int) []byte {
	h := mimcNative.NewMiMC()
	h.Write(coins.Bytes())
	h.Write(energy.Bytes())
	h.Write(pk)
	h.Write(rho.Bytes())
	h.Write(r.Bytes())
	return h.Sum(nil)
}

// NewMiMC creates a new MiMC hash instance
func NewMiMC() interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
	Reset()
} {
	return mimcNative.NewMiMC()
}

// MimcHashPublic computes MiMC hash of data (public version)
func MimcHashPublic(data []byte) *big.Int {
	h := mimcNative.NewMiMC()
	h.Write(data)
	return new(big.Int).SetBytes(h.Sum(nil))
}

// PRF implements a pseudo-random function using MiMC hash (big.Int version)
func PRF(sk, rho *big.Int) *big.Int {
	h := mimcNative.NewMiMC()
	h.Write(sk.Bytes())
	h.Write(rho.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil))
}

// PRFBytes implements a pseudo-random function using MiMC hash ([]byte version)
func PRFBytes(sk, rho []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	h.Write(rho)
	return h.Sum(nil)
}

// ComputeMimcCommitment computes a MiMC-based commitment (alternative interface)
func ComputeMimcCommitment(coins, energy, pk, rho, rand *big.Int) *big.Int {
	h := mimcNative.NewMiMC()
	h.Write(coins.Bytes())
	h.Write(energy.Bytes())
	h.Write(pk.Bytes())
	h.Write(rho.Bytes())
	h.Write(rand.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil))
}
