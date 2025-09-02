// ledger.go - Privacy-Preserving Energy Market Ledger Implementation
//
// This implements the ledger as described in the PPEM protocol paper:
// "Privacy-Preserving Exchange Mechanism and its Application to Energy Market"
//
// The ledger manages both permanent and temporary lists, handles protocol phases,
// and verifies zero-knowledge proofs before accepting transactions.

package zerocash

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

// ProtocolPhase represents the current phase of the protocol
type ProtocolPhase int

const (
	PhaseSetup ProtocolPhase = iota
	PhaseRegistration
	PhaseExchange
	PhaseWithdraw
	PhaseCompleted
)

// String returns the string representation of the phase
func (p ProtocolPhase) String() string {
	switch p {
	case PhaseSetup:
		return "Setup"
	case PhaseRegistration:
		return "Registration"
	case PhaseExchange:
		return "Exchange"
	case PhaseWithdraw:
		return "Withdraw"
	case PhaseCompleted:
		return "Completed"
	default:
		return "Unknown"
	}
}

// CircuitKeys holds all the circuit keys needed for verification
type CircuitKeys struct {
	// Algorithm 1 - Transaction
	VkTx  groth16.VerifyingKey
	CcsTx constraint.ConstraintSystem

	// Algorithm 2 - Register
	VkReg  groth16.VerifyingKey
	CcsReg constraint.ConstraintSystem

	// Algorithm 3 - Exchange
	VkExchange  groth16.VerifyingKey
	CcsExchange constraint.ConstraintSystem

	// Algorithm 4 - Withdraw
	VkWithdraw  groth16.VerifyingKey
	CcsWithdraw constraint.ConstraintSystem
}

// Ledger implements the protocol ledger as described in the PPEM paper
type Ledger struct {
	// Permanent Lists (as per protocol)
	CmList []string `json:"cm_list"` // Permanent commitment list
	SnList []string `json:"sn_list"` // Permanent serial number list
	TxList []*Tx    `json:"tx_list"` // Permanent transaction list

	// Temporary Lists (used during auction phases)
	CmListTemp []string `json:"cm_list_temp"` // Temporary commitment list
	SnListTemp []string `json:"sn_list_temp"` // Temporary serial number list
	TxListTemp []*Tx    `json:"tx_list_temp"` // Temporary transaction list

	// Protocol-specific lists
	AuxList []AuxiliaryInfo `json:"aux_list"` // Auxiliary information (proofs, encrypted data)
	InfList []AuctionInfo   `json:"inf_list"` // Auction information

	// Protocol state
	CurrentPhase ProtocolPhase `json:"current_phase"`
	AuctionID    string        `json:"auction_id"`
	Timestamp    time.Time     `json:"timestamp"`

	// Circuit keys for verification
	keys *CircuitKeys `json:"-"` // Not serialized

	// Auctioneer keys for decryption
	AuctioneerDHPub      *bls12377.G1Affine `json:"auctioneer_dh_pub"`
	AuctioneerECDHPubStr string             `json:"auctioneer_ecdh_pub"` // Serialized as string
}

// AuxiliaryInfo stores auxiliary information for the protocol
type AuxiliaryInfo struct {
	Type        string    `json:"type"`        // "register_proof", "exchange_proof", "encrypted_bid"
	Data        []byte    `json:"data"`        // Proof bytes or encrypted data
	Participant string    `json:"participant"` // Participant ID
	Timestamp   time.Time `json:"timestamp"`
}

// AuctionInfo stores auction/exchange information
type AuctionInfo struct {
	AuctionID    string    `json:"auction_id"`
	Results      []byte    `json:"results"`      // Serialized auction results
	Participants []string  `json:"participants"` // List of participant IDs
	Timestamp    time.Time `json:"timestamp"`
}

// NewLedger creates a new ledger instance
func NewLedger() *Ledger {
	return &Ledger{
		CmList:       make([]string, 0),
		SnList:       make([]string, 0),
		TxList:       make([]*Tx, 0),
		CmListTemp:   make([]string, 0),
		SnListTemp:   make([]string, 0),
		TxListTemp:   make([]*Tx, 0),
		AuxList:      make([]AuxiliaryInfo, 0),
		InfList:      make([]AuctionInfo, 0),
		CurrentPhase: PhaseSetup,
		AuctionID:    generateAuctionID(),
		Timestamp:    time.Now(),
	}
}

// SetCircuitKeys sets the circuit keys for proof verification
func (l *Ledger) SetCircuitKeys(keys *CircuitKeys) {
	l.keys = keys
}

// GetCircuitKeys returns the current circuit keys (for updating)
func (l *Ledger) GetCircuitKeys() *CircuitKeys {
	return l.keys
}

// SetAuctioneerKeys sets the auctioneer's public keys for decryption
func (l *Ledger) SetAuctioneerKeys(dhPub *bls12377.G1Affine, ecdhPub *ecdh.PublicKey) {
	l.AuctioneerDHPub = dhPub
	if ecdhPub != nil {
		l.AuctioneerECDHPubStr = fmt.Sprintf("%x", ecdhPub.Bytes())
	}
}

// StartRegistrationPhase starts the registration phase
func (l *Ledger) StartRegistrationPhase() error {
	if l.CurrentPhase != PhaseSetup {
		return fmt.Errorf("cannot start registration from phase %s", l.CurrentPhase)
	}

	l.CurrentPhase = PhaseRegistration
	l.Timestamp = time.Now()
	return nil
}

// SubmitRegistration submits a registration transaction (Algorithm 2)
func (l *Ledger) SubmitRegistration(txIn *Tx, pub RegistrationPublicInputs, proofReg []byte, participantID string) error {
	if l.CurrentPhase != PhaseRegistration {
		return fmt.Errorf("not in registration phase, current phase: %s", l.CurrentPhase)
	}

	// Check that sn^base is not already spent
	if l.HasSerialNumber(txIn.SnOld) {
		return errors.New("double-spend detected: serial number already in ledger")
	}

	// CRITICAL: Verify BOTH the underlying Algorithm 1 transaction AND the registration proof

	// 1. Verify the underlying Algorithm 1 transaction proof
	if l.keys != nil && l.keys.VkTx != nil {
		params := &Params{} // Empty params struct (currently unused)
		if err := VerifyTx(txIn, params, l.keys.VkTx); err != nil {
			return fmt.Errorf("underlying transaction proof verification failed for participant %s: %w", participantID, err)
		}
	} else {
		return fmt.Errorf("cannot verify underlying transaction proof: no verification keys available")
	}

	// 2. Verify the registration proof before accepting the transaction
	if l.keys != nil && l.keys.VkReg != nil {
		if err := VerifyRegistrationProof(pub, proofReg, l.keys.VkReg); err != nil {
			return fmt.Errorf("registration proof verification failed for participant %s: %w", participantID, err)
		}
	} else {
		return fmt.Errorf("cannot verify registration proof: no verification keys available")
	}

	// Add to permanent SnList (sn^base)
	l.SnList = append(l.SnList, txIn.SnOld)

	// Add to temporary lists
	l.TxListTemp = append(l.TxListTemp, txIn)
	l.CmListTemp = append(l.CmListTemp, txIn.CmNew)

	// Add auxiliary information
	l.AuxList = append(l.AuxList, AuxiliaryInfo{
		Type:        "register_proof",
		Data:        proofReg,
		Participant: participantID,
		Timestamp:   time.Now(),
	})

	return nil
}

// StartExchangePhase starts the exchange phase
func (l *Ledger) StartExchangePhase() error {
	if l.CurrentPhase != PhaseRegistration {
		return fmt.Errorf("cannot start exchange from phase %s", l.CurrentPhase)
	}

	l.CurrentPhase = PhaseExchange
	l.Timestamp = time.Now()
	return nil
}

// SubmitExchange submits an exchange transaction (Algorithm 3) with proof verification
func (l *Ledger) SubmitExchange(txsOut []*Tx, proofF []byte, auctionInfo []byte, publicInputs interface{}) error {
	if l.CurrentPhase != PhaseExchange {
		return fmt.Errorf("not in exchange phase, current phase: %s", l.CurrentPhase)
	}

	fmt.Printf("\x1b[32m▪ Exchange Proof Verification\x1b[0m\n")
	if l.keys != nil && l.keys.VkExchange != nil {
		err := VerifyExchangeProofWithInputs(proofF, l.keys.VkExchange, publicInputs)
		if err != nil {
			return fmt.Errorf("exchange proof verification failed: %w", err)
		}
	} else {
		return fmt.Errorf("cannot verify exchange proof: no verification keys available")
	}

	// Process each output transaction
	for i, txOut := range txsOut {
		// Check that sn^in is not already spent
		if l.HasSerialNumberTemp(txOut.SnOld) {
			return errors.New("double-spend detected: serial number already in temporary ledger")
		}

		// TX verification handled by caller labeling
		if l.keys != nil && l.keys.VkTx != nil {
			params := &Params{} // Empty params struct (currently unused)
			if err := VerifyTx(txOut, params, l.keys.VkTx); err != nil {
				return fmt.Errorf("underlying transaction proof verification failed for output transaction %d: %w", i, err)
			}
		} else {
			return fmt.Errorf("cannot verify underlying transaction proof for output transaction %d: no verification keys available", i)
		}

		// Add to temporary SnList (sn^in)
		l.SnListTemp = append(l.SnListTemp, txOut.SnOld)

		// Add to permanent CmList (cm^out)
		l.CmList = append(l.CmList, txOut.CmNew)
	}

	// Add auction information
	l.InfList = append(l.InfList, AuctionInfo{
		AuctionID:    l.AuctionID,
		Results:      auctionInfo,
		Participants: l.getParticipantIDs(),
		Timestamp:    time.Now(),
	})

	// Add exchange proof
	l.AuxList = append(l.AuxList, AuxiliaryInfo{
		Type:        "exchange_proof",
		Data:        proofF,
		Participant: "auctioneer",
		Timestamp:   time.Now(),
	})

	return nil
}

// CloseAuction closes the auction and moves to withdraw phase
func (l *Ledger) CloseAuction() error {
	if l.CurrentPhase != PhaseExchange {
		return fmt.Errorf("cannot close auction from phase %s", l.CurrentPhase)
	}

	// Move temporary lists to permanent lists
	l.SnList = append(l.SnList, l.SnListTemp...)
	l.CmList = append(l.CmList, l.CmListTemp...)
	l.TxList = append(l.TxList, l.TxListTemp...)

	// Clear temporary lists
	l.CmListTemp = make([]string, 0)
	l.SnListTemp = make([]string, 0)
	l.TxListTemp = make([]*Tx, 0)

	// Move to withdraw phase
	l.CurrentPhase = PhaseWithdraw
	l.Timestamp = time.Now()

	return nil
}

// SubmitWithdraw submits a withdrawal transaction (Algorithm 4) with proof verification
func (l *Ledger) SubmitWithdraw(withdrawTx interface{}, proofBytes []byte, participantID string) error {
	if l.CurrentPhase != PhaseWithdraw {
		return fmt.Errorf("not in withdraw phase, current phase: %s", l.CurrentPhase)
	}

	// Verify the withdrawal proof before accepting the transaction
	if l.keys != nil && l.keys.VkWithdraw != nil {
		// Import withdraw package for verification
		// We need to convert the withdrawTx to the proper type and verify
		if err := l.verifyWithdrawalProof(withdrawTx, proofBytes); err != nil {
			return fmt.Errorf("withdrawal proof verification failed for participant %s: %w", participantID, err)
		}
	} else {
		return fmt.Errorf("cannot verify withdrawal proof: no verification keys available")
	}

	// Convert withdrawal transaction to regular transaction for ledger storage
	var regularTx *Tx
	if txData, ok := withdrawTx.(map[string]interface{}); ok {
		regularTx = &Tx{
			SnOld:     fmt.Sprintf("%v", txData["sn_in"]),
			CmNew:     fmt.Sprintf("%v", txData["cm_out"]),
			OldCoin:   fmt.Sprintf("%v", txData["old_coin"]),
			OldEnergy: fmt.Sprintf("%v", txData["old_energy"]),
			NewCoin:   fmt.Sprintf("%v", txData["new_coin"]),
			NewEnergy: fmt.Sprintf("%v", txData["new_energy"]),
			Proof:     proofBytes,
		}
	} else {
		return fmt.Errorf("invalid withdrawal transaction format")
	}

	// If the underlying Alg.1 tx was already submitted, don't fail on duplicate SN
	// Otherwise, record it now.
	if !l.HasSerialNumber(regularTx.SnOld) {
		l.SnList = append(l.SnList, regularTx.SnOld)
		l.CmList = append(l.CmList, regularTx.CmNew)
		l.TxList = append(l.TxList, regularTx)
	}

	// Add auxiliary information (withdraw proof)
	l.AuxList = append(l.AuxList, AuxiliaryInfo{
		Type:        "withdraw_proof",
		Data:        proofBytes,
		Participant: participantID,
		Timestamp:   time.Now(),
	})

	return nil
}

// SubmitTransaction submits a regular transaction (Algorithm 1) with proof verification
func (l *Ledger) SubmitTransaction(tx *Tx, params *Params, participantID string) error {
	// Check current phase - transactions can be submitted in multiple phases
	if l.CurrentPhase == PhaseSetup {
		return fmt.Errorf("cannot submit transaction in setup phase")
	}

	// Check that sn^old is not already spent
	if l.HasSerialNumber(tx.SnOld) {
		return errors.New("double-spend detected: serial number already in ledger")
	}

	// Verify the transaction proof before accepting the transaction
	if l.keys != nil && l.keys.VkTx != nil {
		if err := VerifyTx(tx, params, l.keys.VkTx); err != nil {
			return fmt.Errorf("transaction proof verification failed for participant %s: %w", participantID, err)
		}
	} else {
		return fmt.Errorf("cannot verify transaction proof: no verification keys available")
	}

	// Add to permanent lists
	l.SnList = append(l.SnList, tx.SnOld)
	l.CmList = append(l.CmList, tx.CmNew)
	l.TxList = append(l.TxList, tx)

	// Add auxiliary information
	l.AuxList = append(l.AuxList, AuxiliaryInfo{
		Type:        "transaction_proof",
		Data:        tx.Proof,
		Participant: participantID,
		Timestamp:   time.Now(),
	})

	return nil
}

// HasSerialNumber checks if a serial number exists in the permanent list
func (l *Ledger) HasSerialNumber(sn string) bool {
	for _, s := range l.SnList {
		if s == sn {
			return true
		}
	}
	return false
}

// HasSerialNumberTemp checks if a serial number exists in the temporary list
func (l *Ledger) HasSerialNumberTemp(sn string) bool {
	for _, s := range l.SnListTemp {
		if s == sn {
			return true
		}
	}
	return false
}

// HasCommitment checks if a commitment exists in the permanent list
func (l *Ledger) HasCommitment(cm string) bool {
	for _, c := range l.CmList {
		if c == cm {
			return true
		}
	}
	return false
}

// HasCommitmentTemp checks if a commitment exists in the temporary list
func (l *Ledger) HasCommitmentTemp(cm string) bool {
	for _, c := range l.CmListTemp {
		if c == cm {
			return true
		}
	}
	return false
}

// GetTxs returns all permanent transactions
func (l *Ledger) GetTxs() []*Tx {
	return l.TxList
}

// GetTxsTemp returns all temporary transactions
func (l *Ledger) GetTxsTemp() []*Tx {
	return l.TxListTemp
}

// GetCurrentPhase returns the current protocol phase
func (l *Ledger) GetCurrentPhase() ProtocolPhase {
	return l.CurrentPhase
}

// SaveToFile saves the ledger to a JSON file
func (l *Ledger) SaveToFile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(l)
}

// LoadLedgerFromFile loads a ledger from a JSON file
func LoadLedgerFromFile(path string) (*Ledger, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var l Ledger
	dec := json.NewDecoder(f)
	if err := dec.Decode(&l); err != nil {
		return nil, err
	}

	return &l, nil
}

// Private helper functions

// verifyWithdrawalProof verifies a withdrawal proof using the withdrawal verification key
func (l *Ledger) verifyWithdrawalProof(withdrawTx interface{}, proofBytes []byte) error {
	if len(proofBytes) == 0 {
		return fmt.Errorf("empty withdrawal proof")
	}

	// Convert the withdrawal transaction to our verification format
	var verificationTx *WithdrawTxForVerification

	if txData, ok := withdrawTx.(map[string]interface{}); ok {
		// Parse values from the transaction data
		snIn := new(big.Int)
		cmOut := new(big.Int)

		// sn_in
		if snInRaw, ok := txData["sn_in"]; ok {
			snInStr := fmt.Sprintf("%v", snInRaw)
			if _, ok := snIn.SetString(snInStr, 10); !ok {
				return fmt.Errorf("invalid sn_in value: %v", snInRaw)
			}
		} else {
			return fmt.Errorf("missing sn_in in withdrawal transaction")
		}

		// cm_out
		if cmOutRaw, ok := txData["cm_out"]; ok {
			cmOutStr := fmt.Sprintf("%v", cmOutRaw)
			if _, ok := cmOut.SetString(cmOutStr, 10); !ok {
				return fmt.Errorf("invalid cm_out value: %v", cmOutRaw)
			}
		} else {
			return fmt.Errorf("missing cm_out in withdrawal transaction")
		}

		// pk_t
		var pkT sw_bls12377.G1Affine
		if pkTRaw, ok := txData["pk_t"]; ok {
			switch v := pkTRaw.(type) {
			case map[string]interface{}:
				xStr := fmt.Sprintf("%v", v["x"])
				yStr := fmt.Sprintf("%v", v["y"])
				pkT = sw_bls12377.G1Affine{X: xStr, Y: yStr}
			case map[string]string:
				pkT = sw_bls12377.G1Affine{X: v["x"], Y: v["y"]}
			default:
				return fmt.Errorf("invalid pk_t format")
			}
		} else {
			return fmt.Errorf("missing pk_t in withdrawal transaction")
		}

		// cipher_aux (array of 5)
		var cipherAux [5]*big.Int
		if caRaw, ok := txData["cipher_aux"]; ok {
			switch arr := caRaw.(type) {
			case []interface{}:
				if len(arr) != 5 {
					return fmt.Errorf("cipher_aux must be array of 5 values")
				}
				for i := 0; i < 5; i++ {
					bi := new(big.Int)
					vStr := fmt.Sprintf("%v", arr[i])
					if _, ok := bi.SetString(vStr, 10); !ok {
						return fmt.Errorf("invalid cipher_aux[%d] value: %v", i, arr[i])
					}
					cipherAux[i] = bi
				}
			case []string:
				if len(arr) != 5 {
					return fmt.Errorf("cipher_aux must be array of 5 values")
				}
				for i := 0; i < 5; i++ {
					bi := new(big.Int)
					if _, ok := bi.SetString(arr[i], 10); !ok {
						return fmt.Errorf("invalid cipher_aux[%d] value: %v", i, arr[i])
					}
					cipherAux[i] = bi
				}
			default:
				return fmt.Errorf("invalid cipher_aux format")
			}
		} else {
			return fmt.Errorf("missing cipher_aux in withdrawal transaction")
		}

		verificationTx = &WithdrawTxForVerification{
			SnIn:      snIn,
			CmOut:     cmOut,
			PkT:       pkT,
			CipherAux: cipherAux,
		}
	} else {
		return fmt.Errorf("unsupported withdrawal transaction format")
	}

	// Use the proper verification function
	return VerifyWithdrawalProofInLedger(verificationTx, proofBytes, l.keys.VkWithdraw)
}

func (l *Ledger) getParticipantIDs() []string {
	participantMap := make(map[string]bool)
	for _, aux := range l.AuxList {
		if aux.Type == "register_proof" || aux.Type == "encrypted_bid" {
			participantMap[aux.Participant] = true
		}
	}

	var participants []string
	for p := range participantMap {
		participants = append(participants, p)
	}

	return participants
}

// generateAuctionID generates a unique auction ID
func generateAuctionID() string {
	return fmt.Sprintf("auction_%d", time.Now().Unix())
}

type regPublicOnly struct {
	CmIn          frontend.Variable    `gnark:",public"`
	CAux          [7]frontend.Variable `gnark:",public"`
	GammaInEnergy frontend.Variable    `gnark:",public"`
	GammaInCoins  frontend.Variable    `gnark:",public"`
	Bid           frontend.Variable    `gnark:",public"`
	Role          frontend.Variable    `gnark:",public"`
	Quantity      frontend.Variable    `gnark:",public"`
	G             sw_bls12377.G1Affine `gnark:",public"`
	G_b           sw_bls12377.G1Affine `gnark:",public"`
	G_r           sw_bls12377.G1Affine `gnark:",public"`
}

func (r *regPublicOnly) Define(api frontend.API) error { return nil }

// VerifyRegistrationProof verifies a registration proof using the provided verifying key
func VerifyRegistrationProof(pub RegistrationPublicInputs, proofBytes []byte, vk groth16.VerifyingKey) error {
	if len(proofBytes) == 0 {
		return fmt.Errorf("empty registration proof")
	}

	// Unmarshal proof
	proof := groth16.NewProof(ecc.BW6_761)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("registration proof unmarshaling failed: %w", err)
	}

	toAff := func(x, y string) sw_bls12377.G1Affine { return sw_bls12377.G1Affine{X: x, Y: y} }

	assign := &regPublicOnly{
		CmIn:          pub.CmIn,
		CAux:          [7]frontend.Variable{pub.CAux[0], pub.CAux[1], pub.CAux[2], pub.CAux[3], pub.CAux[4], pub.CAux[5], pub.CAux[6]},
		GammaInEnergy: pub.GammaInEnergy,
		GammaInCoins:  pub.GammaInCoins,
		Bid:           pub.Bid,
		Role:          pub.Role,
		Quantity:      pub.Quantity,
		G:             toAff(pub.G.X, pub.G.Y),
		G_b:           toAff(pub.G_b.X, pub.G_b.Y),
		G_r:           toAff(pub.G_r.X, pub.G_r.Y),
	}

	witnessPub, err := frontend.NewWitness(assign, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to build public witness: %w", err)
	}

	return groth16.Verify(proof, vk, witnessPub)
}

// VerifyExchangeProof verifies an exchange proof using the provided verifying key
func VerifyExchangeProof(txsOut []*Tx, proofBytes []byte, vk groth16.VerifyingKey) error {
	if len(txsOut) == 0 {
		return fmt.Errorf("no output transactions to verify")
	}

	// Determine participant count from number of output transactions
	participantCount := len(txsOut)

	// Use rigorous verification with proper circuit witness reconstruction
	return VerifyExchangeProofRigorous(txsOut, proofBytes, vk, participantCount)
}

// AppendTx is kept for backward compatibility but should not be used in the new protocol
func (l *Ledger) AppendTx(tx *Tx) error {
	return errors.New("use protocol-specific methods instead of AppendTx")
}

// Simplified verification methods that can be enhanced later
func (l *Ledger) verifyProof(proofBytes []byte, proofType string) error {
	if len(proofBytes) == 0 {
		return errors.New("empty proof")
	}

	// For now, just check that proof is not empty
	// In a full implementation, this would verify the ZKP
	return nil
}
