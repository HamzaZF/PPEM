// crypto.go - Cryptographic primitives and utilities for the zerocash protocol.
//
// Implements MiMC-based PRFs, commitments, random number generation, and BLS12-377 DH key exchange.
// All cryptographic operations use secure randomness and are designed for unlinkability and confidentiality.

package zerocash

import (
	"bytes"
	"crypto/rand"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
)

// prf implements a pseudo-random function using MiMC hash.
// Used for serial number and other protocol PRFs.
func prf(sk, rho []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	h.Write(rho)
	return h.Sum(nil)
}

// Commitment creates a commitment to note data using MiMC hash.
// Follows paper specification: cm = Com(Γ || pk || ρ, r)
// where Γ = (coins, energy), pk is the public key, ρ is rho, and r is randomness
func Commitment(coins, energy *big.Int, pk []byte, rho, r *big.Int) []byte {
	h := mimcNative.NewMiMC()
	// Commit to Γ || pk || ρ with randomness r
	h.Write(coins.Bytes())  // Γ.coins
	h.Write(energy.Bytes()) // Γ.energy
	h.Write(pk)             // pk (public key)
	h.Write(rho.Bytes())    // ρ (rho)
	h.Write(r.Bytes())      // r (randomness)
	return h.Sum(nil)
}

// mimcHash computes MiMC hash of input bytes.
func mimcHash(data []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(data)
	return h.Sum(nil)
}

// randomBytes generates random bytes of specified length using crypto/rand.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// RandomBytes is a public wrapper for randomBytes.
// Use this for all protocol randomness.
func RandomBytes(n int) []byte {
	return randomBytes(n)
}

// DHKeyPair represents a BLS12-377 keypair for Diffie-Hellman key exchange.
// sk: scalar (private), pk: G1Affine (public)
type DHKeyPair struct {
	Sk *bls12377_fr.Element // Private scalar
	Pk *bls12377.G1Affine   // Public key (G1 point)
}

// GenerateDHKeyPair generates a random BLS12-377 keypair for DH.
func GenerateDHKeyPair() (*DHKeyPair, error) {
	var sk bls12377_fr.Element
	sk.SetRandom()
	var g1Jac, _, _, _ = bls12377.Generators()
	var pk bls12377.G1Affine
	pk.FromJacobian(&g1Jac)
	pk.ScalarMultiplication(&pk, sk.BigInt(new(big.Int)))
	return &DHKeyPair{Sk: &sk, Pk: &pk}, nil
}

// ComputeDHShared computes the shared secret (G^ab) given our sk and their pk.
func ComputeDHShared(sk *bls12377_fr.Element, pk *bls12377.G1Affine) *bls12377.G1Affine {
	var shared bls12377.G1Affine
	shared.ScalarMultiplication(pk, sk.BigInt(new(big.Int)))
	return &shared
}

// EncryptNoteWithSharedKey encrypts note fields using MiMC and the shared key.
// Returns an array of encrypted fields (pkOwner, coins, energy, rho, rand, cm).
func EncryptNoteWithSharedKey(note *Note, shared *bls12377.G1Affine) [6][]byte {
	// Use the same MiMC-based mask chain as buildEncMimc, but output as []byte
	h := mimcNative.NewMiMC()
	encKeyX := shared.X.Bytes()
	encKeyY := shared.Y.Bytes()
	h.Write(encKeyX[:])
	h.Write(encKeyY[:])
	h_enc_key := h.Sum(nil)

	h.Write(h_enc_key)
	h_h_enc_key := h.Sum(nil)

	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum(nil)

	fields := [][]byte{
		note.PkOwner,
		note.Value.Coins.Bytes(),
		note.Value.Energy.Bytes(),
		note.Rho,
		note.Rand,
		note.Cm,
	}
	masks := [][]byte{
		h_enc_key,
		h_h_enc_key,
		h_h_h_enc_key,
		h_h_h_h_enc_key,
		h_h_h_h_h_enc_key,
		h_h_h_h_h_h_enc_key,
	}
	var enc [6][]byte
	for i := 0; i < 6; i++ {
		enc[i] = xorPad(fields[i], masks[i])
	}
	return enc
}

// DecryptNoteWithSharedKey decrypts note fields using MiMC and the shared key.
// Returns the decrypted fields in the same order as EncryptNoteWithSharedKey.
func DecryptNoteWithSharedKey(enc [6][]byte, shared *bls12377.G1Affine) (fields [6][]byte, err error) {
	h := mimcNative.NewMiMC()
	encKeyX := shared.X.Bytes()
	encKeyY := shared.Y.Bytes()
	h.Write(encKeyX[:])
	h.Write(encKeyY[:])
	h_enc_key := h.Sum(nil)

	h.Write(h_enc_key)
	h_h_enc_key := h.Sum(nil)

	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum(nil)

	masks := [][]byte{
		h_enc_key,
		h_h_enc_key,
		h_h_h_enc_key,
		h_h_h_h_enc_key,
		h_h_h_h_h_enc_key,
		h_h_h_h_h_h_enc_key,
	}
	for i := 0; i < 6; i++ {
		fields[i] = xorPad(enc[i], masks[i])
	}
	return fields, nil
}

// xorPad xors two byte slices, padding the shorter one with zeros.
// Used for MiMC-based encryption of note fields.
func xorPad(a, b []byte) []byte {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	out := make([]byte, maxLen)
	for i := 0; i < maxLen; i++ {
		var ab, bb byte
		if i < len(a) {
			ab = a[i]
		}
		if i < len(b) {
			bb = b[i]
		}
		out[i] = ab ^ bb
	}
	return out
}

// RecognizeNote attempts to decrypt and parse a note, returning true if the pkOwner matches.
// Used by recipients to scan for their notes in the ledger.
func RecognizeNote(enc [6][]byte, shared *bls12377.G1Affine, myPk []byte) (bool, *Note, error) {
	fields, err := DecryptNoteWithSharedKey(enc, shared)
	if err != nil {
		return false, nil, err
	}
	if !bytes.Equal(fields[0], myPk) {
		return false, nil, nil
	}
	coins := new(big.Int).SetBytes(fields[1])
	energy := new(big.Int).SetBytes(fields[2])
	note := &Note{
		Value: Gamma{
			Coins:  coins,
			Energy: energy,
		},
		PkOwner: fields[0],
		Rho:     fields[3],
		Rand:    fields[4],
		Cm:      fields[5],
	}
	return true, note, nil
}

// NewMiMC creates a new MiMC hash instance.
// Use this for all MiMC-based operations.
func NewMiMC() interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
	Reset()
} {
	return mimcNative.NewMiMC()
}

// MimcHashPublic is a wrapper for testing
func MimcHashPublic(data []byte) *big.Int {
	hash := mimcHash(data)
	return new(big.Int).SetBytes(hash)
}

// SerialNumber computes a serial number from secret key and rho
func SerialNumber(sk, rho []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	h.Write(rho)
	return h.Sum(nil)
}

// RandomBytesPublic generates random bytes (exposed for testing)
func RandomBytesPublic(n int) []byte {
	return randomBytes(n)
}

// GnarkG1Affine is a type alias for testing
type GnarkG1Affine struct {
	X string
	Y string
}
