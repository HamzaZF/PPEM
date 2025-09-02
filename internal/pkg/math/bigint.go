// bigint.go - big.Int utility functions
package math

import (
	"fmt"
	"math/big"
)

// StringToBigInt safely converts a string to *big.Int
func StringToBigInt(s string) (*big.Int, error) {
	val := new(big.Int)
	if _, ok := val.SetString(s, 10); !ok {
		return nil, fmt.Errorf("invalid big integer string: %s", s)
	}
	return val, nil
}

// BigIntToString converts *big.Int to string (base 10)
func BigIntToString(val *big.Int) string {
	if val == nil {
		return "0"
	}
	return val.String()
}

// SafeBigInt ensures a big.Int is not nil
func SafeBigInt(val *big.Int) *big.Int {
	if val == nil {
		return big.NewInt(0)
	}
	return val
}

// CopyBigInt creates a copy of a big.Int
func CopyBigInt(val *big.Int) *big.Int {
	if val == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(val)
}

