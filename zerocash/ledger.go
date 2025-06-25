// ledger.go - Persistent, append-only global ledger for the zerocash protocol.
//
// The Ledger records all commitments, serial numbers, and transactions.
// It is append-only, supports double-spend detection, and is persisted as a single global JSON file (ledger.json).
//
// NOTE: Ledger is not thread-safe by itself; use a sync.Mutex for concurrent access.

package zerocash

import (
	"encoding/json"
	"errors"
	"os"
)

// Ledger is the canonical, append-only public ledger for Zerocash transactions.
// All participants read from and append to this file.
type Ledger struct {
	CmList []string // Commitments (hex/base64-encoded)
	SnList []string // Serial numbers (hex/base64-encoded)
	TxList []*Tx    // Full transactions
}

// NewLedger creates a new, empty ledger.
func NewLedger() *Ledger {
	return &Ledger{
		CmList: make([]string, 0),
		SnList: make([]string, 0),
		TxList: make([]*Tx, 0),
	}
}

// AppendTx appends a verified transaction to the ledger.
// It checks for double-spending and updates all lists.
// Returns an error if the serial number is already present.
func (l *Ledger) AppendTx(tx *Tx) error {
	sn := tx.SnOld
	cm := tx.CmNew
	if l.HasSerialNumber(sn) {
		return errors.New("double-spend detected: serial number already in ledger")
	}
	l.SnList = append(l.SnList, sn)
	l.CmList = append(l.CmList, cm)
	l.TxList = append(l.TxList, tx)
	return nil
}

// HasSerialNumber returns true if the serial number is already in the ledger.
func (l *Ledger) HasSerialNumber(sn string) bool {
	for _, s := range l.SnList {
		if s == sn {
			return true
		}
	}
	return false
}

// HasCommitment returns true if the commitment is already in the ledger.
func (l *Ledger) HasCommitment(cm string) bool {
	for _, c := range l.CmList {
		if c == cm {
			return true
		}
	}
	return false
}

// GetTxs returns all transactions in the ledger.
func (l *Ledger) GetTxs() []*Tx {
	return l.TxList
}

// SaveToFile saves the ledger to a JSON file (ledger.json).
// Overwrites the file if it exists.
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

// LoadLedgerFromFile loads the global ledger from a JSON file (ledger.json).
// Returns an error if the file is invalid or cannot be read.
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
