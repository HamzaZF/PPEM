package zerocash

import (
	"crypto/rand"
	"math/big"

	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
)

// PRF implements a pseudo-random function using MiMC hash
func prf(sk, rho []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	h.Write(rho)
	return h.Sum(nil)
}

// Commitment creates a commitment to note data using MiMC hash
func Commitment(coins, energy, rho, r *big.Int) []byte {
	h := mimcNative.NewMiMC()
	h.Write(coins.Bytes())
	h.Write(energy.Bytes())
	h.Write(rho.Bytes())
	h.Write(r.Bytes())
	return h.Sum(nil)
}

// mimcHash computes MiMC hash of input bytes
func mimcHash(data []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(data)
	return h.Sum(nil)
}

// randomBytes generates random bytes of specified length
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
