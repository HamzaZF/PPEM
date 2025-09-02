// dh.go - Diffie-Hellman key exchange utilities
package crypto

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// DHKeyPair represents a Diffie-Hellman key pair
type DHKeyPair struct {
	Sk *bls12377_fr.Element // Secret key
	Pk *bls12377.G1Affine   // Public key
}

// GenerateDHKeyPair generates a new Diffie-Hellman key pair
func GenerateDHKeyPair() (*DHKeyPair, error) {
	var sk bls12377_fr.Element
	sk.SetRandom()

	var pk bls12377.G1Affine
	pk.ScalarMultiplication(&bls12377.G1Affine{}, sk.BigInt(nil))

	return &DHKeyPair{Sk: &sk, Pk: &pk}, nil
}

// ComputeDHShared computes the shared secret from private key and public key
func ComputeDHShared(sk *bls12377_fr.Element, pk *bls12377.G1Affine) *bls12377.G1Affine {
	var shared bls12377.G1Affine
	shared.ScalarMultiplication(pk, sk.BigInt(nil))
	return &shared
}
