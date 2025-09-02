package circom

import (
	"fmt"
	"math/big"
	"strconv"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// stringToBigInt parses a string as a big integer.
func stringToBigInt(s string) (*big.Int, error) {
	bi := new(big.Int)
	_, ok := bi.SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid big integer: %s", s)
	}
	return bi, nil
}

// stringToG1 converts a Circom G1 point (slice of strings) to a curve.G1Affine.
// Expected format: [X, Y, Z] where Z should be "1".
func stringToG1(point []string) (*curve.G1Affine, error) {
	if len(point) != 3 {
		return nil, fmt.Errorf("G1 point must have exactly 3 coordinates, got %d", len(point))
	}

	// Parse X coordinate
	xBig, err := stringToBigInt(point[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X coordinate: %v", err)
	}

	// Parse Y coordinate
	yBig, err := stringToBigInt(point[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Y coordinate: %v", err)
	}

	// Check Z coordinate (should be "1")
	if point[2] != "1" {
		return nil, fmt.Errorf("expected Z coordinate to be '1', got '%s'", point[2])
	}

	// Create the G1 point
	var x, y fp.Element
	x.SetBigInt(xBig)
	y.SetBigInt(yBig)

	g1Point := &curve.G1Affine{
		X: x,
		Y: y,
	}

	// Verify the point is on the curve
	if !g1Point.IsOnCurve() {
		return nil, fmt.Errorf("point is not on the G1 curve")
	}

	return g1Point, nil
}

// stringToG2 converts a Circom G2 point (2D slice of strings) to a curve.G2Affine.
// Expected format: [[X.A0, X.A1], [Y.A0, Y.A1], [Z.A0, Z.A1]] where Z should be ["1", "0"].
func stringToG2(point [][]string) (*curve.G2Affine, error) {
	if len(point) != 3 {
		return nil, fmt.Errorf("G2 point must have exactly 3 coordinate pairs, got %d", len(point))
	}

	// Check that each coordinate pair has exactly 2 elements
	for i, coord := range point {
		if len(coord) != 2 {
			return nil, fmt.Errorf("coordinate pair %d must have exactly 2 elements, got %d", i, len(coord))
		}
	}

	// Parse X coordinates
	x0Big, err := stringToBigInt(point[0][0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.A0 coordinate: %v", err)
	}
	x1Big, err := stringToBigInt(point[0][1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.A1 coordinate: %v", err)
	}

	// Parse Y coordinates
	y0Big, err := stringToBigInt(point[1][0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Y.A0 coordinate: %v", err)
	}
	y1Big, err := stringToBigInt(point[1][1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Y.A1 coordinate: %v", err)
	}

	// Check Z coordinates (should be ["1", "0"])
	if point[2][0] != "1" || point[2][1] != "0" {
		return nil, fmt.Errorf("expected Z coordinate to be ['1', '0'], got ['%s', '%s']", point[2][0], point[2][1])
	}

	// Create the G2 point using the proper Fp2 structure
	var x, y curve.E2
	x.A0.SetBigInt(x0Big)
	x.A1.SetBigInt(x1Big)
	y.A0.SetBigInt(y0Big)
	y.A1.SetBigInt(y1Big)

	g2Point := &curve.G2Affine{
		X: x,
		Y: y,
	}

	// Verify the point is on the curve
	if !g2Point.IsOnCurve() {
		return nil, fmt.Errorf("point is not on the G2 curve")
	}

	return g2Point, nil
}

// parseStringToInt parses a string to int, with error handling.
func parseStringToInt(s string) (int, error) {
	return strconv.Atoi(s)
}
