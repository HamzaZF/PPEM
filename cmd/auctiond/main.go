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
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"implementation/internal/transactions/exchange"
	"implementation/internal/transactions/register"
	"implementation/internal/transactions/withdraw"
	"implementation/internal/zerocash"

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

// runReceivingPhase implements the receiving phase as per the protocol
func runReceivingPhase(participants []*zerocash.Participant, ledger *zerocash.Ledger, pk groth16.ProvingKey, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) {
	log.Println("=== Receiving Phase ===")

	// 1. Check if the auctioneer performed the exchange (TxList_temp has valid exchange tx/proof)
	exchangeSucceeded := ledger.HasValidExchange()
	if exchangeSucceeded {
		log.Println("Auctioneer performed the exchange. Distributing funds to participants...")
		for _, p := range participants {
			// Each participant reads TxList_temp and adds received funds for pk_out to their permanent wallet
			if err := p.Wallet.ClaimExchangeOutput(ledger); err != nil {
				log.Printf("[WARN] Participant %s failed to claim exchange output: %v", p.Name, err)
			} else {
				log.Printf("[INFO] Participant %s successfully claimed exchange output.", p.Name)
			}
		}
	} else {
		log.Println("Auctioneer failed to perform the exchange. Triggering withdrawal for all participants...")
		for _, p := range participants {
			if err := triggerWithdraw(p, ledger, pk, ccs, vk); err != nil {
				log.Printf("[ERROR] Participant %s withdrawal failed: %v", p.Name, err)
			} else {
				log.Printf("[INFO] Participant %s successfully withdrew their funds.", p.Name)
			}
		}
	}
}

func main() {
	log.Println("=== Zerocash Auction Protocol: N=10 Scenario ===")

	// 1. Setup: Compile all required circuits and generate/load ZKP keys

	// CircuitTx for Algorithm 1 (Transaction)
	var circuitTx zerocash.CircuitTx
	ccsTx, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx)
	if err != nil {
		log.Printf("ERROR: CircuitTx compilation failed: %v", err)
		return
	}
	pkTxPath := "keys/CircuitTx_pk.bin"
	vkTxPath := "keys/CircuitTx_vk.bin"
	pkTx, vkTx, err := zerocash.SetupOrLoadKeys(ccsTx, pkTxPath, vkTxPath)
	if err != nil {
		log.Printf("ERROR: CircuitTx key setup failed: %v", err)
		return
	}

	// CircuitTxRegister for Algorithm 2 (Registration)
	var circuitReg register.CircuitTxRegister
	ccsReg, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitReg)
	if err != nil {
		log.Printf("ERROR: CircuitTxRegister compilation failed: %v", err)
		return
	}
	pkRegPath := "keys/CircuitTxRegister_pk.bin"
	vkRegPath := "keys/CircuitTxRegister_vk.bin"
	pkReg, _, err := zerocash.SetupOrLoadKeys(ccsReg, pkRegPath, vkRegPath)
	if err != nil {
		log.Printf("ERROR: CircuitTxRegister key setup failed: %v", err)
		return
	}

	// CircuitTxF10 for Algorithm 3 (Exchange)
	var circuitF10 exchange.CircuitTxF10
	ccsF10, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitF10)
	if err != nil {
		log.Printf("ERROR: CircuitTxF10 compilation failed: %v", err)
		return
	}
	pkF10Path := "keys/proving_f10.key"
	vkF10Path := "keys/verifying_f10.key"
	pkF10, vkF10, err := zerocash.SetupOrLoadKeys(ccsF10, pkF10Path, vkF10Path)
	if err != nil {
		log.Printf("ERROR: CircuitTxF10 key setup failed: %v", err)
		return
	}

	params := &zerocash.Params{}

	// Load or create the ledger
	ledgerPath := "ledger.json"
	var ledger *zerocash.Ledger
	if l, err := zerocash.LoadLedgerFromFile(ledgerPath); err == nil {
		ledger = l
	} else {
		ledger = zerocash.NewLedger()
	}

	// 2. Create auctioneer and 10 participants
	auctioneer := zerocash.NewParticipant("Auctioneer", pkF10, vkF10, params, zerocash.RoleAuctioneer, nil)
	participants := make([]*zerocash.Participant, N)
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("Participant%d", i+1)
		participants[i] = zerocash.NewParticipant(name, pkTx, vkTx, params, zerocash.RoleParticipant, auctioneer.Pk)
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
		regResult, err := register.Register(p, note, bid, pkTx, ccsTx, pkReg, ccsReg, skBytes[:])
		if err != nil {
			log.Printf("ERROR: registration failed for %s: %v", p.Name, err)
			return
		}
		// Save note to wallet (use all 5 args, fill with nil/zero as needed)
		p.Wallet.AddNote(note, skBytes[:], nil, [5]byte{}, note)
		walletPath := fmt.Sprintf("%s_wallet.json", p.Name)
		if err := p.Wallet.Save(walletPath); err != nil {
			log.Printf("ERROR: wallet save failed for %s: %v", p.Name, err)
			return
		}
		// Prepare registration payload for auction phase
		regPayloads[i] = exchange.RegistrationPayload{
			Ciphertext: regResult.CAux,
			PubKey:     toGnarkPoint(p.Pk),
		}
		// Append tx^in to global ledger
		if err := appendTxToLedger(regResult.TxIn); err != nil {
			log.Printf("ERROR: ledger append failed: %v", err)
			return
		}
	}

	log.Println("All participants registered. Starting auction phase...")

	// 4. Auction phase: run ExchangePhase
	txOut, info, proof, err := exchange.ExchangePhase(regPayloads, auctioneer.Sk.BigInt(new(big.Int)), ledger, params, pkF10, ccsF10)
	if err != nil {
		log.Printf("ERROR: Auction phase failed: %v", err)
		return
	}

	// 5. Output results
	fmt.Printf("\n=== Auction Phase Complete ===\n")
	fmt.Printf("Proof (hex): %x\n", proof)
	fmt.Printf("Output Transaction: %+v\n", txOut)
	fmt.Printf("Public Info: %+v\n", info)

	// 6. Receiving phase (new)
	runReceivingPhase(participants, ledger, pkF10, ccsF10, vkF10)

	// (Optional) Save proof and txOut to files or ledger as needed
	// Withdraw phase not implemented yet
}

// appendTxToLedger appends a transaction to the global ledger.json file
func appendTxToLedger(tx *zerocash.Tx) error {
	ledgerPath := "ledger.json"
	var ledger *zerocash.Ledger
	if l, err := zerocash.LoadLedgerFromFile(ledgerPath); err == nil {
		ledger = l
	} else {
		ledger = zerocash.NewLedger()
	}
	if err := ledger.AppendTx(tx); err != nil {
		return fmt.Errorf("ledger append failed: %w", err)
	}
	if err := ledger.SaveToFile(ledgerPath); err != nil {
		return fmt.Errorf("ledger save failed: %w", err)
	}
	return nil
}

// Add a CLI command to trigger withdrawal for a participant
func triggerWithdraw(participant *zerocash.Participant, ledger *zerocash.Ledger, pk groth16.ProvingKey, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) error {
	// Gather required data from wallet/state using accessors
	unspentNotes := participant.Wallet.GetUnspentNotes()
	var nInZ *zerocash.Note
	if len(unspentNotes) > 0 {
		nInZ = unspentNotes[0]
	} else {
		nInZ = nil
	}
	skInBytes := participant.Wallet.GetWithdrawSk()
	rEncBytes := participant.Wallet.GetWithdrawREnc()
	nOutZ := participant.Wallet.GetWithdrawOutputNote()
	pkT := participant.Wallet.GetWithdrawPkT()
	cipherAuxBytes := participant.Wallet.GetWithdrawCipherAux()

	// Convert zerocash.Note to withdraw.Note
	noteToWithdrawNote := func(n *zerocash.Note) withdraw.Note {
		if n == nil {
			return withdraw.Note{}
		}
		return withdraw.Note{
			Coins:  n.Value.Coins,
			Energy: n.Value.Energy,
			Pk:     new(big.Int).SetBytes(n.PkOwner),
			Rho:    new(big.Int).SetBytes(n.Rho),
			R:      new(big.Int).SetBytes(n.Rand),
			Cm:     new(big.Int).SetBytes(n.Cm),
		}
	}
	nIn := noteToWithdrawNote(nInZ)
	nOut := noteToWithdrawNote(nOutZ)

	// Convert skIn and rEnc to *big.Int
	skIn := new(big.Int)
	if skInBytes != nil {
		skIn.SetBytes(skInBytes)
	}
	rEnc := new(big.Int)
	if rEncBytes != nil {
		rEnc.SetBytes(rEncBytes)
	}

	// Convert pkT to sw_bls12377.G1Affine
	var pkTgnark sw_bls12377.G1Affine
	if pkT != nil {
		pkTgnark.X = pkT.X.String()
		pkTgnark.Y = pkT.Y.String()
	}

	// Convert [3][]byte to [3]*big.Int
	var cipherAux [3]*big.Int
	for i := 0; i < 3; i++ {
		cipherAux[i] = new(big.Int)
		if cipherAuxBytes[i] != nil {
			cipherAux[i].SetBytes(cipherAuxBytes[i])
		}
	}

	if nInZ == nil || skInBytes == nil || rEncBytes == nil || nOutZ == nil {
		log.Printf("[ERROR] Withdraw input is nil: nIn=%v skIn=%v rEnc=%v nOut=%v", nInZ, skInBytes, rEncBytes, nOutZ)
		return fmt.Errorf("withdraw input is nil: nIn=%v skIn=%v rEnc=%v nOut=%v", nInZ, skInBytes, rEncBytes, nOutZ)
	}

	tx, proof, err := withdraw.Withdraw(nIn, skIn, rEnc, nOut, pkTgnark, cipherAux, pk, ccs)
	if err != nil {
		return err
	}
	if err := ledger.SubmitWithdrawTx(tx, proof, vk); err != nil {
		return err
	}
	return nil
}
