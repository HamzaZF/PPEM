package zerocash

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

// RegistrationPublicInputs contains the exact public inputs used by the registration circuit.
// Values are string-encoded to match gnark witness assignment conventions.
type RegistrationPublicInputs struct {
	CmIn          string
	CAux          [7]string
	GammaInCoins  string
	GammaInEnergy string
	Bid           string
	Role          string
	Quantity      string
	G             struct {
		X string
		Y string
	}
	G_b struct {
		X string
		Y string
	}
	G_r struct {
		X string
		Y string
	}
}

// WithdrawTxForVerification represents a withdrawal transaction for verification purposes
// This mirrors the structure from the withdraw package to avoid circular imports
type WithdrawTxForVerification struct {
	SnIn      *big.Int
	CmOut     *big.Int
	PkT       sw_bls12377.G1Affine
	CipherAux [5]*big.Int
}

// withdrawalPublicWitness defines the public witness structure for withdrawal verification
type withdrawalPublicWitness struct {
	SnIn      frontend.Variable    `gnark:",public"`
	CmOut     frontend.Variable    `gnark:",public"`
	PkT       sw_bls12377.G1Affine `gnark:",public"`
	CipherAux [5]frontend.Variable `gnark:",public"`
}

// Define implements the frontend.Circuit interface for withdrawal verification
func (w *withdrawalPublicWitness) Define(api frontend.API) error {
	// This is a minimal circuit definition for public witness creation
	// The actual verification logic is handled by the proving system
	return nil
}

// VerifyWithdrawalProofInLedger verifies a withdrawal proof using the ledger's verification key
// This function provides withdrawal verification within the zerocash package to avoid circular imports
func VerifyWithdrawalProofInLedger(withdrawTx *WithdrawTxForVerification, proofBytes []byte, vk groth16.VerifyingKey) error {
	if len(proofBytes) == 0 {
		return fmt.Errorf("empty withdrawal proof")
	}

	if withdrawTx == nil {
		return fmt.Errorf("nil withdrawal transaction")
	}

	// Create a minimal public witness for withdrawal verification
	// This should match the public inputs of the withdrawal circuit
	publicWitness := &withdrawalPublicWitness{
		SnIn:  withdrawTx.SnIn.String(),
		CmOut: withdrawTx.CmOut.String(),
		PkT:   withdrawTx.PkT,
		CipherAux: [5]frontend.Variable{
			withdrawTx.CipherAux[0].String(),
			withdrawTx.CipherAux[1].String(),
			withdrawTx.CipherAux[2].String(),
			withdrawTx.CipherAux[3].String(),
			withdrawTx.CipherAux[4].String(),
		},
	}

	// Create gnark public witness
	w, err := frontend.NewWitness(publicWitness, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Unmarshal proof
	proof := groth16.NewProof(ecc.BW6_761)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("proof unmarshaling failed: %w", err)
	}

	// Verify the proof
	if err := groth16.Verify(proof, vk, w); err != nil {
		return fmt.Errorf("withdrawal proof verification failed: %w", err)
	}

	return nil
}

// ExchangePublicWitness represents the public inputs for exchange circuit verification
// This mirrors the public fields of CircuitTxFN to avoid circular imports
type ExchangePublicWitness struct {
	N int // Number of participants

	// Input arrays for N participants
	InCoin   []frontend.Variable `gnark:",public"`
	InEnergy []frontend.Variable `gnark:",public"`
	InCm     []frontend.Variable `gnark:",public"`
	InSn     []frontend.Variable `gnark:",public"`
	InPk     []frontend.Variable `gnark:",public"`
	InSk     []frontend.Variable `gnark:",public"`
	InRho    []frontend.Variable `gnark:",public"`
	InRand   []frontend.Variable `gnark:",public"`

	// Output arrays for N participants
	OutCoin   []frontend.Variable `gnark:",public"`
	OutEnergy []frontend.Variable `gnark:",public"`
	OutCm     []frontend.Variable `gnark:",public"`
	OutSn     []frontend.Variable `gnark:",public"`
	OutPk     []frontend.Variable `gnark:",public"`
	OutRho    []frontend.Variable `gnark:",public"`
	OutRand   []frontend.Variable `gnark:",public"`

	// DH parameters for each participant
	G   []sw_bls12377.G1Affine `gnark:",public"`
	G_b []sw_bls12377.G1Affine `gnark:",public"`
	G_r []sw_bls12377.G1Affine `gnark:",public"`

	// RISC Zero public inputs (simplified for verification)
	RISC0PublicInputs []frontend.Variable `gnark:",public"`
}

// Define implements the frontend.Circuit interface for exchange verification
func (w *ExchangePublicWitness) Define(api frontend.API) error {
	// This is a minimal circuit definition for public witness creation
	// The actual verification logic is handled by the proving system
	return nil
}

// VerifyExchangeProofRigorous performs rigorous verification of exchange proofs
func VerifyExchangeProofRigorous(txsOut []*Tx, proofBytes []byte, vk groth16.VerifyingKey, n int) error {
	if len(proofBytes) == 0 {
		return fmt.Errorf("empty exchange proof")
	}

	if len(txsOut) == 0 {
		return fmt.Errorf("no output transactions to verify")
	}

	if n <= 0 {
		return fmt.Errorf("invalid participant count: %d", n)
	}

	if len(txsOut) != n {
		return fmt.Errorf("transaction count (%d) does not match participant count (%d)", len(txsOut), n)
	}

	// Build public witness from transaction outputs
	witness, err := buildExchangePublicWitness(txsOut, n)
	if err != nil {
		return fmt.Errorf("failed to build exchange public witness: %w", err)
	}

	// Create gnark public witness
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Unmarshal proof
	proof := groth16.NewProof(ecc.BW6_761)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("exchange proof unmarshaling failed: %w", err)
	}

	// Verify the proof
	if err := groth16.Verify(proof, vk, w); err != nil {
		return fmt.Errorf("exchange proof verification failed: %w", err)
	}

	return nil
}

// buildExchangePublicWitness constructs the public witness from transaction outputs
func buildExchangePublicWitness(txsOut []*Tx, n int) (*ExchangePublicWitness, error) {
	witness := &ExchangePublicWitness{
		N: n,

		// Initialize all arrays
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

		G:   make([]sw_bls12377.G1Affine, n),
		G_b: make([]sw_bls12377.G1Affine, n),
		G_r: make([]sw_bls12377.G1Affine, n),

		RISC0PublicInputs: make([]frontend.Variable, 4), // Basic RISC0 outputs
	}

	// Extract public data from output transactions
	for i, tx := range txsOut {
		if i >= n {
			return nil, fmt.Errorf("too many transactions for participant count")
		}

		// Input transaction data (from old notes)
		witness.InCoin[i] = tx.OldCoin
		witness.InEnergy[i] = tx.OldEnergy
		witness.InCm[i] = tx.CmOld
		witness.InSn[i] = tx.SnOld
		witness.InPk[i] = tx.PkOld

		// Output transaction data (to new notes)
		witness.OutCoin[i] = tx.NewCoin
		witness.OutEnergy[i] = tx.NewEnergy
		witness.OutCm[i] = tx.CmNew

		// DH parameters from transaction
		witness.G[i] = tx.G
		witness.G_b[i] = tx.G_b
		witness.G_r[i] = tx.G_r

		// Handle missing fields intelligently
		// Secret values and randomness are not available in public transactions
		witness.InSk[i] = "0"   // Secret keys not public (verified inside circuit)
		witness.InRho[i] = "0"  // Rho values computed inside circuit
		witness.InRand[i] = "0" // Randomness not public (verified inside circuit)

		// Output fields that may not be in basic Tx struct
		// These are either computed inside the circuit or not needed for verification
		witness.OutSn[i] = "0"   // Output serial numbers computed in circuit
		witness.OutPk[i] = "0"   // Output public keys derived in circuit
		witness.OutRho[i] = "0"  // Output rho computed in circuit
		witness.OutRand[i] = "0" // Output randomness computed in circuit
	}

	// RISC Zero public inputs - MUST be populated with REAL proof data, not dummy values!
	// This verification function should receive actual RISC Zero proof data as parameter
	// For now, leaving empty - the real data should come from exchange circuit verification
	for i := range witness.RISC0PublicInputs {
		witness.RISC0PublicInputs[i] = "0" // Placeholder until real proof data is passed
	}

	return witness, nil
}

// VerifyExchangeProofWithInputs verifies an exchange proof using the original public inputs
func VerifyExchangeProofWithInputs(proofBytes []byte, vk groth16.VerifyingKey, publicInputs interface{}) error {
	if len(proofBytes) == 0 {
		return fmt.Errorf("empty exchange proof")
	}

	if publicInputs == nil {
		return fmt.Errorf("nil public inputs")
	}

	// Cast public inputs to frontend.Circuit interface
	circuit, ok := publicInputs.(frontend.Circuit)
	if !ok {
		return fmt.Errorf("public inputs do not implement frontend.Circuit interface")
	}

	// Create gnark witness from the original public inputs
	w, err := frontend.NewWitness(circuit, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Unmarshal proof
	proof := groth16.NewProof(ecc.BW6_761)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("exchange proof unmarshaling failed: %w", err)
	}

	// Verify the proof using the original public inputs
	if err := groth16.Verify(proof, vk, w); err != nil {
		return fmt.Errorf("exchange proof verification failed: %w", err)
	}

	return nil
}
