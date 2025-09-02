// random.go - Secure random number generation utilities
package crypto

import (
	"crypto/rand"
)

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// RandomBytesPublic generates cryptographically secure random bytes (public version)
func RandomBytesPublic(n int) []byte {
	return RandomBytes(n)
}

