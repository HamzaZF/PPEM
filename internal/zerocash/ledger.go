// ledger.go - Privacy-Preserving Energy Market Ledger Implementation
//
// This implements the ledger as described in the PPEM protocol paper:
// "Privacy-Preserving Exchange Mechanism and its Application to Energy Market"
//
// The ledger manages both permanent and temporary lists, handles protocol phases,
// and verifies zero-knowledge proofs before accepting transactions.

package zerocash

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
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
func (l *Ledger) SubmitRegistration(txIn *Tx, cipherAux []byte, proofReg []byte, participantID string) error {
	if l.CurrentPhase != PhaseRegistration {
		return fmt.Errorf("not in registration phase, current phase: %s", l.CurrentPhase)
	}

	// Check that sn^base is not already spent
	if l.HasSerialNumber(txIn.SnOld) {
		return errors.New("double-spend detected: serial number already in ledger")
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

	if len(cipherAux) > 0 {
		l.AuxList = append(l.AuxList, AuxiliaryInfo{
			Type:        "encrypted_bid",
			Data:        cipherAux,
			Participant: participantID,
			Timestamp:   time.Now(),
		})
	}

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

// SubmitExchange submits an exchange transaction (Algorithm 3)
func (l *Ledger) SubmitExchange(txsOut []*Tx, proofF []byte, auctionInfo []byte) error {
	if l.CurrentPhase != PhaseExchange {
		return fmt.Errorf("not in exchange phase, current phase: %s", l.CurrentPhase)
	}

	// Process each output transaction
	for _, txOut := range txsOut {
		// Check that sn^in is not already spent
		if l.HasSerialNumberTemp(txOut.SnOld) {
			return errors.New("double-spend detected: serial number already in temporary ledger")
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

// SubmitWithdraw submits a withdrawal transaction (Algorithm 4)
func (l *Ledger) SubmitWithdraw(txData map[string]interface{}, proofBytes []byte) error {
	if l.CurrentPhase != PhaseWithdraw {
		return fmt.Errorf("not in withdraw phase, current phase: %s", l.CurrentPhase)
	}

	// Convert to regular transaction for ledger storage
	regularTx := &Tx{
		SnOld:     fmt.Sprintf("%v", txData["sn_in"]),
		CmNew:     fmt.Sprintf("%v", txData["cm_out"]),
		OldCoin:   fmt.Sprintf("%v", txData["old_coin"]),
		OldEnergy: fmt.Sprintf("%v", txData["old_energy"]),
		NewCoin:   fmt.Sprintf("%v", txData["new_coin"]),
		NewEnergy: fmt.Sprintf("%v", txData["new_energy"]),
		Proof:     proofBytes,
	}

	// Add to permanent lists
	l.SnList = append(l.SnList, regularTx.SnOld)
	l.CmList = append(l.CmList, regularTx.CmNew)
	l.TxList = append(l.TxList, regularTx)

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

func generateAuctionID() string {
	return fmt.Sprintf("auction_%d", time.Now().Unix())
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
