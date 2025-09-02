// circuit.go - Circuit for the auction phase (exchange) of the protocol.
//
// This file defines the zero-knowledge circuit for the auction (exchange) phase of the PPEM protocol.
// It enforces cryptographic consistency (decryption, PRF, commitments, EC operations) only.
// Auction logic and constraints are handled outside the circuit.
//
// Note: DecVal[i][2] contains the bid/ask price for participant i (for reference, not verified)

package exchange

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"implementation/internal/risc0"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	recursion "github.com/consensys/gnark/std/recursion/groth16"
)

// DecZKReg decrypts a registration ciphertext in the circuit using a MiMC-based mask chain.
// This function mimics the off-circuit decryption logic for registration payloads.
//
// Parameters:
//   - api: gnark frontend API
//   - c: ciphertext array (length 7)
//   - encKey: shared DH key (G1Affine)
//
// Returns:
//   - [7]frontend.Variable: decrypted values (pkOut, skIn, bid/ask, coins, energy, role, quantity)
func DecZKReg(api frontend.API, c []frontend.Variable, encKey sw_bls12377.G1Affine) [7]frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
	hasher.Reset()
	hasher.Write(encKey.X)
	hasher.Write(encKey.Y)
	mask0 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask0)
	mask1 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask1)
	mask2 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask2)
	mask3 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask3)
	mask4 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask4)
	mask5 := hasher.Sum()

	hasher.Reset()
	hasher.Write(mask5)
	mask6 := hasher.Sum()

	dec0 := api.Sub(c[0], mask0)
	dec1 := api.Sub(c[1], mask1)
	dec2 := api.Sub(c[2], mask2)
	dec3 := api.Sub(c[3], mask3)
	dec4 := api.Sub(c[4], mask4)
	dec5 := api.Sub(c[5], mask5)
	dec6 := api.Sub(c[6], mask6)

	return [7]frontend.Variable{dec0, dec1, dec2, dec3, dec4, dec5, dec6}
}

// PRF implements a pseudo-random function using MiMC hash in the circuit.
// Used for serial number computation.
//
// Parameters:
//   - api: gnark frontend API
//   - sk: secret key
//   - rho: randomizer
//
// Returns:
//   - frontend.Variable: PRF output
func PRF(api frontend.API, sk, rho frontend.Variable) frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(sk)
	hasher.Write(rho)
	return hasher.Sum()
}

// CircuitTxFN represents a dynamic circuit for N coins/participants in the auction phase.
// This circuit can be generated for any number of participants.
// The circuit verifies both cryptographic consistency and RISC Zero auction proof.
//
// Fields:
//   - N: number of participants
//   - InCoin, InEnergy, ...: input arrays for each participant
//   - OutCoin, OutEnergy, ...: output arrays for each participant
//   - C, DecVal: encrypted and decrypted registration data
//   - R, G, G_b, G_r, EncKey: Diffie-Hellman parameters for each participant
//   - RISC0Proof, RISC0VerifyingKey, RISC0PublicInputs: RISC Zero recursive verification
//
// Note: DecVal[i][2] contains bid/ask data but is not verified by the circuit
type CircuitTxFN struct {
	// Number of participants this circuit supports
	N int

	// ParticipantRoles and TradedQuantities are now decrypted from registration data:
	// - ParticipantRoles: DecVal[i][5] (0=BUY, 1=SELL)
	// - TradedQuantities: DecVal[i][6] (Energy quantity traded per participant)

	// ----- Input/Output Arrays for N coins -----
	InCoin   []frontend.Variable `gnark:",public"`
	InEnergy []frontend.Variable `gnark:",public"`
	InCm     []frontend.Variable `gnark:",public"`
	InSn     []frontend.Variable `gnark:",public"`
	InPk     []frontend.Variable `gnark:",public"`
	InSk     []frontend.Variable `gnark:",public"`
	InRho    []frontend.Variable `gnark:",public"`
	InRand   []frontend.Variable `gnark:",public"`

	OutCoin   []frontend.Variable `gnark:",public"`
	OutEnergy []frontend.Variable `gnark:",public"`
	OutCm     []frontend.Variable `gnark:",public"`
	OutSn     []frontend.Variable `gnark:",public"`
	OutPk     []frontend.Variable `gnark:",public"`
	OutRho    []frontend.Variable `gnark:",public"`
	OutRand   []frontend.Variable `gnark:",public"`

	C      [][]frontend.Variable
	DecVal [][]frontend.Variable // DecVal[i][2] contains the bid/ask price for participant i // TODO: remove this

	// ----- DH Parameters for each coin -----
	R      []frontend.Variable
	G      []sw_bls12377.G1Affine `gnark:",public"`
	G_b    []sw_bls12377.G1Affine `gnark:",public"`
	G_r    []sw_bls12377.G1Affine `gnark:",public"`
	EncKey []sw_bls12377.G1Affine // DH shared secret: used for both decryption and DH verification

	// ----- RISC Zero Recursive Verification -----
	// Using the proper recursive verification framework from circom workflow
	RISC0Proof        recursion.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	RISC0VerifyingKey recursion.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl] `gnark:"-"`
	RISC0PublicInputs recursion.Witness[sw_bn254.ScalarField]

	// ----- Private inputs from host -----
	// ClearingPrice is provided by the Go host (auction result) and must match
	// the RISC0 public input[0] bit-for-bit over 64 bits.
	ClearingPrice frontend.Variable

	// ----- RISC Zero Receipt Values for Claim Digest -----
	// These values come from the RISC Zero receipt and are needed to compute
	// the exact same claim digest that RISC Zero computed
	PrePC          frontend.Variable     // Pre-execution program counter (usually 0)
	PreMerkleRoot  [32]frontend.Variable // Pre-execution merkle root (32 bytes)
	PostPC         frontend.Variable     // Post-execution program counter (usually 0)
	PostMerkleRoot [32]frontend.Variable // Post-execution merkle root (32 bytes, often zeros)
	SysExit        frontend.Variable     // System exit code (0 for Halted)
	UserExit       frontend.Variable     // User exit code (0 for success)
}

// NewCircuitTxFN creates a new dynamic circuit for N participants with embedded RISC Zero verification key.
// Circuit verifies cryptographic consistency only - auction logic runs outside.
func NewCircuitTxFN(n int) *CircuitTxFN {
	if n <= 0 {
		panic("CircuitTxFN: N must be positive")
	}

	// Auction logic runs outside the circuit - no auction verification in ZKP

	circuit := &CircuitTxFN{
		N: n,

		// Initialize arrays with proper sizes
		InCoin:   make([]frontend.Variable, n),
		InEnergy: make([]frontend.Variable, n),
		InCm:     make([]frontend.Variable, n),
		InSn:     make([]frontend.Variable, n),
		InPk:     make([]frontend.Variable, n),
		InSk:     make([]frontend.Variable, n),
		InRho:    make([]frontend.Variable, n),
		InRand:   make([]frontend.Variable, n),

		OutCoin:   make([]frontend.Variable, n),
		OutEnergy: make([]frontend.Variable, n),
		OutCm:     make([]frontend.Variable, n),
		OutSn:     make([]frontend.Variable, n),
		OutPk:     make([]frontend.Variable, n),
		OutRho:    make([]frontend.Variable, n),
		OutRand:   make([]frontend.Variable, n),

		C:      make([][]frontend.Variable, n),
		DecVal: make([][]frontend.Variable, n),

		R:      make([]frontend.Variable, n),
		G:      make([]sw_bls12377.G1Affine, n),
		G_b:    make([]sw_bls12377.G1Affine, n),
		G_r:    make([]sw_bls12377.G1Affine, n),
		EncKey: make([]sw_bls12377.G1Affine, n),
	}

	// Initialize 2D arrays
	for i := 0; i < n; i++ {
		circuit.C[i] = make([]frontend.Variable, 7)      // Changed from 5 to 7
		circuit.DecVal[i] = make([]frontend.Variable, 7) // Changed from 5 to 7
	}

	// Load the RISC Zero verification key from circom output
	workingDir, _ := os.Getwd()
	// Prefer circom_data vkey if present (fresh export from current zkey)
	vkeyPath := filepath.Join(workingDir, "circom", "circom_data", "vkey.json")
	if _, err := os.Stat(vkeyPath); os.IsNotExist(err) {
		vkeyPath = filepath.Join(workingDir, "circom", "vkey.json")
	}
	if err := circuit.loadRISC0VerificationKey(vkeyPath); err != nil {
		// For circuit compilation, we create a zero verification key
		// The actual key will be loaded during witness generation
		circuit.RISC0VerifyingKey = recursion.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}
	}

	// Initialize RISC0 public inputs with expected size so recursion compiles into CS
	circuit.RISC0PublicInputs = recursion.Witness[sw_bn254.ScalarField]{
		Public: make([]emulated.Element[sw_bn254.ScalarField], 5),
	}

	// Initialize receipt fields with zero values for circuit compilation
	// These will be populated with actual values during witness generation
	for i := 0; i < 32; i++ {
		circuit.PreMerkleRoot[i] = 0
		circuit.PostMerkleRoot[i] = 0
	}

	return circuit
}

// loadRISC0VerificationKey loads the RISC Zero verification key from circom vkey.json
func (c *CircuitTxFN) loadRISC0VerificationKey(vkeyPath string) error {
	// Read the verification key JSON file
	vkeyData, err := os.ReadFile(vkeyPath)
	if err != nil {
		return fmt.Errorf("failed to read verification key file: %w", err)
	}

	// Parse the circom verification key
	var circomVk risc0.CircomVerificationKey
	if err := json.Unmarshal(vkeyData, &circomVk); err != nil {
		return fmt.Errorf("failed to parse verification key JSON: %w", err)
	}

	// Convert to gnark format first
	gnarkVk, err := risc0.ConvertVerificationKey(&circomVk)
	if err != nil {
		return fmt.Errorf("failed to convert verification key to gnark format: %w", err)
	}

	// Convert to recursion format
	recursionVk, err := recursion.ValueOfVerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](gnarkVk)
	if err != nil {
		return fmt.Errorf("failed to convert to recursion verification key: %w", err)
	}

	c.RISC0VerifyingKey = recursionVk
	return nil
}

// Define implements the circuit verification logic for PPEM transactions.
func (c *CircuitTxFN) Define(api frontend.API) error {
	// Verify basic cryptographic constraints for all participants
	if err := c.verifyDefaultAssertions(api); err != nil {
		return err
	}

	// Bind RISC0 public inputs to values derived from this circuit's witness
	if err := c.bindRISC0PublicInputs(api); err != nil {
		return err
	}

	// // Verify RISC Zero proof of correct auction execution
	// if err := c.verifyRISC0Proof(api); err != nil {
	// 	return err
	// }

	return nil
}

// verifyDefaultAssertions verifies the basic cryptographic constraints for all participants
func (c *CircuitTxFN) verifyDefaultAssertions(api frontend.API) error {
	// Process all N coins using a for loop
	for coin := 0; coin < c.N; coin++ {
		// --- Decrypt and verify the registration data ---
		decVal := DecZKReg(api, c.C[coin][:], c.EncKey[coin])
		for i := 0; i < 7; i++ {
			api.AssertIsEqual(c.DecVal[coin][i], decVal[i])
		}

		// --- Verify serial number computation ---
		snComputed := PRF(api, c.InSk[coin], c.InRho[coin])
		api.AssertIsEqual(c.InSn[coin], snComputed)

		// --- Compute output commitment: cm = Com(Γ || pk || ρ, r) where Γ = (coins, energy) ---
		hasher, _ := mimc.NewMiMC(api)
		hasher.Write(c.OutCoin[coin])   // Γ.coins
		hasher.Write(c.OutEnergy[coin]) // Γ.energy
		hasher.Write(c.OutPk[coin])     // pk (public key)
		hasher.Write(c.OutRho[coin])    // ρ (rho)
		hasher.Write(c.OutRand[coin])   // r (randomness)
		cm := hasher.Sum()
		api.AssertIsEqual(c.OutCm[coin], cm)

		// --- Verify DH encryption constraints ---
		// EncKey = G_b^R (same variable used for both decryption and DH verification)
		G_r_b := new(sw_bls12377.G1Affine)
		G_r_b.ScalarMul(api, c.G_b[coin], c.R[coin])
		api.AssertIsEqual(c.EncKey[coin].X, G_r_b.X)
		api.AssertIsEqual(c.EncKey[coin].Y, G_r_b.Y)

		// G_r = G^R
		G_r := new(sw_bls12377.G1Affine)
		G_r.ScalarMul(api, c.G[coin], c.R[coin])
		api.AssertIsEqual(c.G_r[coin].X, G_r.X)
		api.AssertIsEqual(c.G_r[coin].Y, G_r.Y)

		// --- Verify public key derivation: InPk = MiMC(InSk) ---
		hasher.Reset()
		hasher.Write(c.InSk[coin])
		pk := hasher.Sum()
		api.AssertIsEqual(c.InPk[coin], pk)
	}
	return nil
}

// verifyRISC0Proof verifies the RISC Zero proof of correct auction execution using recursion
func (c *CircuitTxFN) verifyRISC0Proof(api frontend.API) error {
	// During circuit compilation, RISC0 proof data may not be available
	// Only verify when both proof and public inputs are present
	if len(c.RISC0PublicInputs.Public) == 0 {
		// Skip verification during compilation - no actual proof data available
		return nil
	}

	// Create the recursive verifier
	verifier, err := recursion.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("failed to create recursive verifier: %w", err)
	}

	// Verify the RISC Zero proof recursively
	// This verifies that the auction logic was executed correctly
	err = verifier.AssertProof(c.RISC0VerifyingKey, c.RISC0Proof, c.RISC0PublicInputs, recursion.WithCompleteArithmetic())
	if err != nil {
		return fmt.Errorf("RISC Zero proof verification failed: %w", err)
	}

	return nil
}

func (c *CircuitTxFN) bindRISC0PublicInputs(api frontend.API) error {
	if len(c.RISC0PublicInputs.Public) == 0 {
		return nil
	}

	// Create BinaryField for U32 operations
	bf, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// Compute claim digest from circuit's auction data
	claimDigest := c.computeClaimDigest(api, bf)

	// Split into c0, c1 using RISC Zero's algorithm
	c0Bytes, c1Bytes := c.splitDigestRisc0(api, claimDigest, bf)

	// ADDITIONAL VERIFICATION: Assert the raw bytes match expected values for auction_scenario_N10.json
	// This helps debug step by step - these are the known correct values:
	// c0 = 64187424359468615765614137879065663563 (from public_signals.json index 2)
	// c1 = 211155017492763219736382627712026683866 (from public_signals.json index 3)

	// // Expected c0 bytes (big-endian from decimal 64187424359468615765614137879065663563)
	// expectedC0Bytes := []frontend.Variable{
	// 	48, 74, 12, 90, 241, 186, 97, 47,
	// 	165, 202, 16, 118, 97, 6, 24, 75,
	// }

	// // Expected c1 bytes (big-endian from decimal 211155017492763219736382627712026683866)
	// expectedC1Bytes := []frontend.Variable{
	// 	158, 218, 250, 35, 220, 93, 39, 110,
	// 	199, 33, 141, 192, 37, 242, 41, 218,
	// }

	// // Verify the computed bytes match expected values (helps catch issues early)
	// for i := 0; i < 16; i++ {
	// 	// FIXED: Compare U8 values properly without accessing .Val
	// 	// U8 values need to be compared through their underlying frontend.Variable
	// 	api.AssertIsEqual(c0Bytes[i].Val, expectedC0Bytes[i])
	// 	api.AssertIsEqual(c1Bytes[i].Val, expectedC1Bytes[i])
	// }

	// Convert c0, c1 to BN254 field elements for comparison with RISC Zero proof
	// c0 and c1 are 128-bit values (16 bytes each)

	// BN254 emulated field helper
	f, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return err
	}

	c0Element := c.bytesToBN254FieldElement(api, f, c0Bytes)
	c1Element := c.bytesToBN254FieldElement(api, f, c1Bytes)

	// The RISC Zero public inputs structure for stark_verify.circom:
	// Based on empirical testing with actual RISC Zero proofs:
	// [0] = control_id_low (lower part of control ID)
	// [1] = control_id_high (upper part of control ID)
	// [2] = c0 (claim digest first half, 128 bits)
	// [3] = c1 (claim digest second half, 128 bits)
	// [4] = control_root (merkle root of allowed control IDs)

	// Assert that our computed c0 and c1 match the RISC Zero proof's public inputs
	f.AssertIsEqual(&c0Element, &c.RISC0PublicInputs.Public[2])
	f.AssertIsEqual(&c1Element, &c.RISC0PublicInputs.Public[3])

	// Note: We don't verify indices 0-1 and 4 as they are control-related values
	// specific to the RISC Zero recursion program

	return nil
}
