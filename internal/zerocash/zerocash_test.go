package zerocash

import (
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestZerocashEndToEnd(t *testing.T) {
	// Setup: Compile circuit and generate/load keys
	var circuit CircuitTx
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("circuit compilation failed: %v", err)
	}
	pkPath := "test_proving.key"
	vkPath := "test_verifying.key"
	pk, vk, err := SetupOrLoadKeys(ccs, pkPath, vkPath)
	if err != nil {
		t.Fatalf("SetupOrLoadKeys failed: %v", err)
	}
	defer os.Remove(pkPath)
	defer os.Remove(vkPath)

	params := &Params{}

	// Step 1: Create a note
	coins := big.NewInt(12345)
	energy := big.NewInt(67890)
	oldSk := randomBytes(32)
	newSk := randomBytes(32)
	oldNote := NewNote(coins, energy, oldSk)

	// Step 2: Create a transaction
	// Compute pk from sk as per Algorithm 1
	pkNew := mimcHash(newSk)
	tx, err := CreateTx(oldNote, oldSk, pkNew, coins, energy, params, ccs, pk)
	if err != nil {
		t.Fatalf("CreateTx failed: %v", err)
	}

	// Step 3: Verify the transaction
	if err := VerifyTx(tx, params, vk); err != nil {
		t.Fatalf("VerifyTx failed: %v", err)
	}

	// Step 4: Ledger integration
	ledger := NewLedger()
	if err := ledger.AppendTx(tx); err != nil {
		t.Fatalf("Ledger append failed: %v", err)
	}
	if !ledger.HasSerialNumber(tx.SnOld) {
		t.Errorf("Ledger should contain serial number after append")
	}
	if !ledger.HasCommitment(tx.CmNew) {
		t.Errorf("Ledger should contain commitment after append")
	}

	// Step 5: Double-spend detection
	err = ledger.AppendTx(tx)
	if err == nil {
		t.Errorf("Expected double-spend error, got nil")
	}

	// Step 6: Ledger save/load
	ledgerPath := "test_ledger.json"
	err = ledger.SaveToFile(ledgerPath)
	if err != nil {
		t.Fatalf("Ledger save failed: %v", err)
	}
	loadedLedger, err := LoadLedgerFromFile(ledgerPath)
	if err != nil {
		t.Fatalf("Ledger load failed: %v", err)
	}
	if len(loadedLedger.TxList) != 1 {
		t.Errorf("Loaded ledger should have 1 tx, got %d", len(loadedLedger.TxList))
	}
	defer os.Remove(ledgerPath)
}

func TestNoteCreationAndSerialization(t *testing.T) {
	coins := big.NewInt(42)
	energy := big.NewInt(99)
	sk := randomBytes(32)
	note := NewNote(coins, energy, sk)
	if note.Value.Coins.Cmp(coins) != 0 || note.Value.Energy.Cmp(energy) != 0 {
		t.Errorf("Note value mismatch")
	}
	if len(note.PkOwner) == 0 || len(note.Rho) == 0 || len(note.Rand) == 0 || len(note.Cm) == 0 {
		t.Errorf("Note fields should not be empty")
	}
}
