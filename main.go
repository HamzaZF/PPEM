package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	"implementation/zerocash"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	fmt.Println("=== Confidential Transaction System (Zerocash API) ===")
	fmt.Println("Generating zero-knowledge proof for transaction...")

	// Step 1: Generate value once for both notes
	coins := randomBigInt(32)
	energy := randomBigInt(32)
	fmt.Printf("[DEBUG] Generated coins: %s\n", coins.String())
	fmt.Printf("[DEBUG] Generated energy: %s\n", energy.String())
	os.Stdout.Sync()

	// Step 2: Generate keys
	oldSk := randomBytes(32)
	newSk := randomBytes(32)

	// Step 3: Create old note
	oldNote := zerocash.NewNote(coins, energy, oldSk)

	// Step 4: Compile the circuit and load or generate Groth16 keys
	var circuit zerocash.CircuitTx
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Errorf("circuit compilation failed: %w", err))
	}
	pkPath := "proving.key"
	vkPath := "verifying.key"
	pk, vk, err := zerocash.SetupOrLoadKeys(ccs, pkPath, vkPath)
	if err != nil {
		panic(fmt.Errorf("SetupOrLoadKeys failed: %w", err))
	}

	params := &zerocash.Params{}

	// Step 5: Create transaction using zerocash package
	tx, err := zerocash.CreateTx(oldNote, oldSk, newSk, coins, energy, params, pk)
	if err != nil {
		panic(fmt.Errorf("CreateTx failed: %w", err))
	}
	fmt.Println("Transaction created and proof generated successfully.")

	// Step 6: Verify transaction
	if err := zerocash.VerifyTx(tx, params, vk); err != nil {
		panic(fmt.Errorf("VerifyTx failed: %w", err))
	}
	fmt.Println("Proof verified successfully!")

	fmt.Println("\n=== Transaction Summary ===")
	fmt.Printf("Old note: %s coins, %s energy\n", tx.OldNote.Value.Coins, tx.OldNote.Value.Energy)
	fmt.Printf("New note: %s coins, %s energy\n", tx.NewNote.Value.Coins, tx.NewNote.Value.Energy)
	fmt.Println("\ntransaction completed successfully!")
}

// randomBigInt generates a random big integer of specified byte length
func randomBigInt(n int) *big.Int {
	b := make([]byte, n)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}

// randomBytes generates random bytes of specified length
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
