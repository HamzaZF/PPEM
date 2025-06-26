// main.go - Comprehensive N=10 participant + 1 auctioneer registration scenario.
//
// This demonstrates the complete registration phase of the auction protocol:
//   - 1 auctioneer starts and exposes their public key
//   - 10 participants each create a note and register with the auctioneer
//   - Each registration produces a Zerocash transaction (Algorithm 1) and encrypted payload (Algorithm 2)
//   - The auctioneer decrypts all registration payloads
//   - The global ledger shows all transactions
//
// Usage:
//   go run main.go
//
// Architecture:
//   - All transactions are appended to a single global ledger.json file (public, append-only)
//   - Each participant maintains their own wallet file (e.g., participant1_wallet.json)
//   - The auctioneer processes all registrations and decrypts the payloads

package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"implementation/transactions/exchange"
	"implementation/transactions/register"
	"implementation/zerocash"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

const N = 10

// toGnarkPoint converts a native BLS12-377 point to gnark format (pointer version).
func toGnarkPoint(p *bls12377.G1Affine) *sw_bls12377.G1Affine {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	return &sw_bls12377.G1Affine{
		X: new(big.Int).SetBytes(xBytes[:]).String(),
		Y: new(big.Int).SetBytes(yBytes[:]).String(),
	}
}

func main() {
	log.Println("=== Zerocash Auction Protocol: N=10 Scenario ===")

	// 1. Setup: Compile CircuitTxF10 and generate/load ZKP keys
	var circuit exchange.CircuitTxF10
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("circuit compilation failed: %v", err)
	}
	pkPath := "proving_f10.key"
	vkPath := "verifying_f10.key"
	pk, vk, err := zerocash.SetupOrLoadKeys(ccs, pkPath, vkPath)
	if err != nil {
		log.Fatalf("SetupOrLoadKeys failed: %v", err)
	}
	params := &zerocash.Params{}

	// 2. Create auctioneer and 10 participants
	auctioneer := zerocash.NewParticipant("Auctioneer", pk, vk, params, zerocash.RoleAuctioneer, nil)
	participants := make([]*zerocash.Participant, N)
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("Participant%d", i+1)
		participants[i] = zerocash.NewParticipant(name, pk, vk, params, zerocash.RoleParticipant, auctioneer.Pk)
	}

	// 3. Each participant creates a note and registration payload
	regPayloads := make([]exchange.RegistrationPayload, N)
	bids := make([]*big.Int, N)
	for i, p := range participants {
		coins := big.NewInt(100 + int64(i)) // Example: unique coins per participant
		energy := big.NewInt(50 + int64(i))
		skBytes := p.Sk.Bytes()
		note := zerocash.NewNote(coins, energy, skBytes[:])
		bid := big.NewInt(10 + int64(i)) // Example: unique bid per participant
		bids[i] = bid
		fmt.Printf("DEBUG: Registering participant %s with sk: %x\n", p.Name, skBytes[:])
		regResult, err := register.Register(p, note, bid, pk, skBytes[:])
		if err != nil {
			log.Fatalf("registration failed for %s: %v", p.Name, err)
		}
		// Save note to wallet
		p.Wallet.AddNote(note, skBytes[:])
		walletPath := fmt.Sprintf("%s_wallet.json", p.Name)
		if err := p.Wallet.Save(walletPath); err != nil {
			log.Fatalf("wallet save failed for %s: %v", p.Name, err)
		}
		// Prepare registration payload for auction phase
		regPayloads[i] = exchange.RegistrationPayload{
			Ciphertext: regResult.CAux,
			PubKey:     toGnarkPoint(p.Pk),
		}
		// Append tx^in to global ledger
		appendTxToLedger(regResult.TxIn)
	}

	log.Println("All participants registered. Starting auction phase...")

	// 4. Auction phase: run ExchangePhase
	txOut, info, proof, err := exchange.ExchangePhase(regPayloads, auctioneer.Sk.BigInt(new(big.Int)), params, pk, ccs)
	if err != nil {
		log.Fatalf("Auction phase failed: %v", err)
	}

	// 5. Output results
	fmt.Printf("\n=== Auction Phase Complete ===\n")
	fmt.Printf("Proof (hex): %x\n", proof)
	fmt.Printf("Output Transaction: %+v\n", txOut)
	fmt.Printf("Public Info: %+v\n", info)

	// (Optional) Save proof and txOut to files or ledger as needed
	// Withdraw phase not implemented yet
}

// appendTxToLedger appends a transaction to the global ledger.json file
func appendTxToLedger(tx *zerocash.Tx) {
	ledgerPath := "ledger.json"
	var ledger *zerocash.Ledger
	if l, err := zerocash.LoadLedgerFromFile(ledgerPath); err == nil {
		ledger = l
	} else {
		ledger = zerocash.NewLedger()
	}
	if err := ledger.AppendTx(tx); err != nil {
		log.Fatalf("ledger append failed: %v", err)
	}
	if err := ledger.SaveToFile(ledgerPath); err != nil {
		log.Fatalf("ledger save failed: %v", err)
	}
}
