package risc0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	logger "implementation/internal/logging"
	"implementation/internal/zerocash"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	recursion "github.com/consensys/gnark/std/recursion/groth16"
)

// CircomProof represents the proof structure output by SnarkJS
type CircomProof struct {
	PiA      []string   `json:"pi_a"`
	PiB      [][]string `json:"pi_b"`
	PiC      []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

// CircomVerificationKey represents the verification key structure output by SnarkJS
type CircomVerificationKey struct {
	Protocol      string       `json:"protocol"`
	Curve         string       `json:"curve"`
	NPublic       int          `json:"nPublic"`
	VkAlpha1      []string     `json:"vk_alpha_1"`
	VkBeta2       [][]string   `json:"vk_beta_2"`
	VkGamma2      [][]string   `json:"vk_gamma_2"`
	VkDelta2      [][]string   `json:"vk_delta_2"`
	IC            [][]string   `json:"IC"`
	VkAlphabeta12 [][][]string `json:"vk_alphabeta_12"`
}

// Participant represents a participant in the RISC Zero auction format
type Participant struct {
	ID        uint32 `json:"id"`
	Role      uint32 `json:"role"`       // 0 = BUY, 1 = SELL
	Price     uint64 `json:"price"`      // bid price for buyers, ask price for sellers
	Quantity  uint64 `json:"quantity"`   // energy quantity to trade
	InCoin    uint64 `json:"in_coin"`    // initial coin balance
	InEnergy  uint64 `json:"in_energy"`  // initial energy balance
	OutCoin   uint64 `json:"out_coin"`   // final coin balance (after auction)
	OutEnergy uint64 `json:"out_energy"` // final energy balance (after auction)
}

// AuctionInput represents the input format for RISC Zero
type AuctionInput struct {
	Participants              []Participant `json:"participants"`
	ExpectedClearingPrice     uint64        `json:"expected_clearing_price"`
	ExpectedTotalEnergyTraded uint64        `json:"expected_total_energy_traded"`
}

// AuctionScenario represents a complete auction scenario for RISC Zero
type AuctionScenario struct {
	ScenarioName              string        `json:"scenario_name"`
	Description               string        `json:"description"`
	ExpectedClearingPrice     uint64        `json:"expected_clearing_price"`
	ExpectedTotalEnergyTraded uint64        `json:"expected_total_energy_traded"`
	Participants              []Participant `json:"participants"`
}

// RISC0ProofData contains the generated proof and public inputs
type RISC0ProofData struct {
	Proof                recursion.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	VerifyingKey         recursion.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	PublicInputs         recursion.Witness[sw_bn254.ScalarField]
	RawProofJSON         []byte
	RawVKeyJSON          []byte
	RawPublicSignalsJSON []byte
}

// scenarioFilePath holds the global scenario file path
var scenarioFilePath string

// SetScenarioFile sets the scenario file path globally  
func SetScenarioFile(filePath string) {
	scenarioFilePath = filePath
}

// GenerateRISC0Proof generates a RISC Zero proof and converts it via Circom to gnark format
func GenerateRISC0Proof(participants []Participant, clearingPrice *big.Int, totalEnergyTraded int64) (*RISC0ProofData, error) {
	if scenarioFilePath == "" {
		return nil, fmt.Errorf("scenario file path not set - call risc0.SetScenarioFile() first")
	}
	// Get current working directory to establish absolute paths
	pwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	circomDir := filepath.Join(pwd, "circom")

	// // Initialize cache managers
	// risc0Cache := cache.NewRISC0Cache(".ppem_cache/risc0", risc0Dir)
	// circomCache := cache.NewCircomCache(".ppem_cache/circom", circomDir)

	// // Step 1: Ensure RISC Zero is built (with caching)
	// logger.Debugf("RISC0 cache: checking build cache...\n")
	// if err := risc0Cache.GetOrBuildRISC0(); err != nil {
	// 	return nil, fmt.Errorf("failed to build RISC Zero program: %w", err)
	// }

	// // Step 2: Ensure Circom setup is ready (with caching)
	// logger.Debugf("Circom cache: checking setup cache...\n")
	// if err := circomCache.EnsureCircomSetup(); err != nil {
	// 	return nil, fmt.Errorf("failed to setup Circom: %w", err)
	// }

	// Step 3: Run RISC Zero with the provided scenario file
	logger.Debugf("RISC0: running double auction with scenario: %s\n", scenarioFilePath)
	if err := runRISC0WithScenarioFile(scenarioFilePath); err != nil {
		return nil, fmt.Errorf("failed to run RISC Zero auction: %w", err)
	}

	// Step 4: Run Circom proof generation
	logger.Debugf("Circom: generating proof...\n")
	if err := runCircomProofGeneration(circomDir); err != nil {
		return nil, fmt.Errorf("failed to generate Circom proof: %w", err)
	}

	// Step 5: Parse and convert proof data
	proofPath := filepath.Join(circomDir, "circom_data", "proof.json")
	vkeyPath := filepath.Join(circomDir, "circom_data", "vkey.json")
	publicSignalsPath := filepath.Join(circomDir, "circom_data", "public_signals.json")

	circomProofData, err := ParseCircomProofData(proofPath, vkeyPath, publicSignalsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Circom proof data: %w", err)
	}

	return circomProofData, nil
}

// runRISC0WithData runs the RISC Zero program with auction scenario data using cargo run --release
func runRISC0WithData(participants []Participant, clearingPrice *big.Int, totalEnergyTraded int64, risc0Dir, circomDir string) error {
	// This function is deprecated - scenario file should be passed directly
	return fmt.Errorf("runRISC0WithData is deprecated - use runRISC0WithScenarioFile instead")
}

// runCircomProofGeneration runs the Circom proof generation workflow directly in Go
func runCircomProofGeneration(circomDir string) error {
	// Use the configuration-aware version
	return runCircomProofGenerationConfig()
}

// ParseCircomProofData parses the JSON files from circom and converts them to gnark recursion format
func ParseCircomProofData(proofPath, vkeyPath, publicSignalsPath string) (*RISC0ProofData, error) {
	// Read the JSON files
	proofData, err := os.ReadFile(proofPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof.json: %w", err)
	}

	vkeyData, err := os.ReadFile(vkeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vkey.json: %w", err)
	}

	publicSignalsData, err := os.ReadFile(publicSignalsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public_signals.json: %w", err)
	}

	// Sanitize potential trailing NULs/whitespace produced by workflow scripts
	clean := func(b []byte) []byte { return bytes.TrimRight(b, "\x00\n\r\t ") }
	proofData = clean(proofData)
	vkeyData = clean(vkeyData)
	publicSignalsData = clean(publicSignalsData)

	// Parse JSON structures
	var circomProof CircomProof
	if err := json.Unmarshal(proofData, &circomProof); err != nil {
		return nil, fmt.Errorf("failed to parse proof JSON: %w", err)
	}

	var circomVk CircomVerificationKey
	if err := json.Unmarshal(vkeyData, &circomVk); err != nil {
		return nil, fmt.Errorf("failed to parse vkey JSON: %w", err)
	}

	var publicSignals []string
	if err := json.Unmarshal(publicSignalsData, &publicSignals); err != nil {
		return nil, fmt.Errorf("failed to parse public signals JSON: %w", err)
	}

	// Convert to gnark recursion format
	recursionData, err := convertCircomToGnarkRecursion(&circomVk, &circomProof, publicSignals)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to gnark recursion format: %w", err)
	}

	return &RISC0ProofData{
		Proof:                recursionData.Proof,
		VerifyingKey:         recursionData.VerifyingKey,
		PublicInputs:         recursionData.PublicInputs,
		RawProofJSON:         proofData,
		RawVKeyJSON:          vkeyData,
		RawPublicSignalsJSON: publicSignalsData,
	}, nil
}

// convertCircomToGnarkRecursion converts circom proof data to gnark recursion format
func convertCircomToGnarkRecursion(circomVk *CircomVerificationKey, circomProof *CircomProof, publicSignals []string) (*RISC0ProofData, error) {
	// Convert public signals to emulated elements
	publicInputElements := make([]emulated.Element[sw_bn254.ScalarField], len(publicSignals))
	for i, signal := range publicSignals {
		// Convert string to big.Int then to emulated element
		bigIntValue := new(big.Int)
		bigIntValue.SetString(signal, 10)
		publicInputElements[i] = emulated.ValueOf[sw_bn254.ScalarField](bigIntValue)
	}

	// Convert the proof to gnark format first
	gnarkProof, err := ConvertProof(circomProof)
	if err != nil {
		return nil, fmt.Errorf("failed to convert proof: %w", err)
	}

	// Convert the verification key to gnark format
	gnarkVk, err := ConvertVerificationKey(circomVk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert verification key: %w", err)
	}

	// Convert to recursion format
	recursionProof, err := recursion.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](gnarkProof)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to recursion proof: %w", err)
	}

	recursionVk, err := recursion.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to recursion verification key: %w", err)
	}

	// Create the recursion data structure
	recursionData := &RISC0ProofData{
		Proof:        recursionProof,
		VerifyingKey: recursionVk,
		PublicInputs: recursion.Witness[sw_bn254.ScalarField]{
			Public: publicInputElements,
		},
	}

	return recursionData, nil
}

// ConvertToRISC0Participants converts PPEM participants to RISC Zero format
func ConvertToRISC0Participants(decryptedRegs []interface{}, roles map[int]zerocash.OrderType) []Participant {
	participants := make([]Participant, 0)

	// Type assertion to get the actual DecryptedRegistration type
	type DecryptedRegistration struct {
		PkOut    *big.Int
		SkIn     *big.Int
		Price    *big.Int
		Quantity *big.Int
		Coins    *big.Int
		Energy   *big.Int
		NoteData *zerocash.Note
	}

	for i, reg := range decryptedRegs {
		// Convert interface{} to the concrete type
		var dr DecryptedRegistration
		switch v := reg.(type) {
		case DecryptedRegistration:
			dr = v
		case map[string]interface{}:
			// Handle map type if needed
			continue
		default:
			// Skip if type doesn't match
			continue
		}

		role := uint32(0)
		if roles[i] == zerocash.SELL {
			role = 1
		}

		p := Participant{
			ID:       uint32(i),
			Role:     role,
			Price:    dr.Price.Uint64(),
			Quantity: dr.Quantity.Uint64(),
			InCoin:   dr.Coins.Uint64(),
			InEnergy: dr.Energy.Uint64(),
			// OutCoin and OutEnergy will be set by RISC Zero
			OutCoin:   dr.Coins.Uint64(),
			OutEnergy: dr.Energy.Uint64(),
		}
		participants = append(participants, p)
	}

	return participants
}

// Copy the working conversion functions from end-to-end-worklow/circom/

// ConvertProof converts a CircomProof into a Gnark-compatible Proof structure
func ConvertProof(snarkProof *CircomProof) (*groth16_bn254.Proof, error) {
	// Parse PiA (G1 point)
	arG1, err := stringToG1(snarkProof.PiA)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiA: %w", err)
	}
	// Parse PiC (G1 point)
	krsG1, err := stringToG1(snarkProof.PiC)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiC: %w", err)
	}
	// Parse PiB (G2 point)
	bsG2, err := stringToG2(snarkProof.PiB)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PiB: %w", err)
	}
	// Construct the Proof
	gnarkProof := &groth16_bn254.Proof{
		Ar:  *arG1,
		Krs: *krsG1,
		Bs:  *bsG2,
	}
	return gnarkProof, nil
}

// ConvertVerificationKey converts a CircomVerificationKey into a Gnark-compatible VerifyingKey
func ConvertVerificationKey(snarkVk *CircomVerificationKey) (*groth16_bn254.VerifyingKey, error) {
	// Parse vk_alpha_1 (G1 point)
	alphaG1, err := stringToG1(snarkVk.VkAlpha1)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkAlpha1: %w", err)
	}
	// Parse vk_beta_2 (G2 point)
	betaG2, err := stringToG2(snarkVk.VkBeta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkBeta2: %w", err)
	}
	// Parse vk_gamma_2 (G2 point)
	gammaG2, err := stringToG2(snarkVk.VkGamma2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkGamma2: %w", err)
	}
	// Parse vk_delta_2 (G2 point)
	deltaG2, err := stringToG2(snarkVk.VkDelta2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VkDelta2: %w", err)
	}

	// Parse IC (G1 points for public inputs)
	numIC := len(snarkVk.IC)
	G1K := make([]curve.G1Affine, numIC)
	for i, icPoint := range snarkVk.IC {
		icG1, err := stringToG1(icPoint)
		if err != nil {
			return nil, fmt.Errorf("failed to convert IC[%d]: %w", i, err)
		}
		G1K[i] = *icG1
	}

	// Construct the VerifyingKey
	vk := &groth16_bn254.VerifyingKey{}
	vk.G1.Alpha = *alphaG1
	vk.G1.K = G1K
	vk.G2.Beta = *betaG2
	vk.G2.Gamma = *gammaG2
	vk.G2.Delta = *deltaG2

	// Precompute the necessary values
	if err := vk.Precompute(); err != nil {
		return nil, fmt.Errorf("failed to precompute verification key: %w", err)
	}

	return vk, nil
}

// ConvertPublicInputs parses an array of strings representing public inputs
func ConvertPublicInputs(publicSignals []string) ([]bn254fr.Element, error) {
	publicInputs := make([]bn254fr.Element, len(publicSignals))
	for i, s := range publicSignals {
		bi, err := stringToBigInt(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public input %d: %w", i, err)
		}
		publicInputs[i].SetBigInt(bi)
	}
	return publicInputs, nil
}

// Utility functions from end-to-end-worklow/circom/util.go

// stringToBigInt parses a string as a big integer
func stringToBigInt(s string) (*big.Int, error) {
	bi := new(big.Int)
	_, ok := bi.SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid big integer: %s", s)
	}
	return bi, nil
}

// stringToG1 converts a Circom G1 point (slice of strings) to a curve.G1Affine
func stringToG1(point []string) (*curve.G1Affine, error) {
	if len(point) != 3 {
		return nil, fmt.Errorf("G1 point must have exactly 3 coordinates, got %d", len(point))
	}

	// Parse X coordinate
	xBig, err := stringToBigInt(point[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X coordinate: %w", err)
	}

	// Parse Y coordinate
	yBig, err := stringToBigInt(point[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Y coordinate: %w", err)
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

// stringToG2 converts a Circom G2 point (2D slice of strings) to a curve.G2Affine
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
		return nil, fmt.Errorf("failed to parse X.A0 coordinate: %w", err)
	}
	x1Big, err := stringToBigInt(point[0][1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.A1 coordinate: %w", err)
	}

	// Parse Y coordinates
	y0Big, err := stringToBigInt(point[1][0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Y.A0 coordinate: %w", err)
	}
	y1Big, err := stringToBigInt(point[1][1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse Y.A1 coordinate: %w", err)
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
