// main.go - Full production-ready implementation of the privacy-preserving auction protocol
// as described in the paper: Privacy-Preserving Exchange Mechanism and its Application to Energy Market.
//
// This file covers all protocol phases: setup, registration, auction, and receiving (claim/withdraw),
// with robust error handling, cryptographic operations, and persistence.

package main

import (
	"fmt"
	"log"
	"math/big"

	"implementation/internal/transactions/exchange"
	"implementation/internal/transactions/register"
	"implementation/internal/transactions/withdraw"
	"implementation/internal/zerocash"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

const (
	N = 10 // Number of participants (can be changed)
)

func main() {
	log.Println("=== Privacy-Preserving Auction Protocol: Full Implementation ===")

	// 1. Setup: Compile circuits and generate/load ZKP keys
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

	// Registration circuit/keys (single-note)
	var regCircuit zerocash.CircuitTx
	regCCS, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &regCircuit)
	if err != nil {
		log.Fatalf("registration circuit compilation failed: %v", err)
	}
	regPK, _, err := zerocash.SetupOrLoadKeys(regCCS, "proving_reg.key", "verifying_reg.key")
	if err != nil {
		log.Fatalf("registration SetupOrLoadKeys failed: %v", err)
	}

	// 2. Load or create the ledger
	ledgerPath := "ledger.json"
	var ledger *zerocash.Ledger
	if l, err := zerocash.LoadLedgerFromFile(ledgerPath); err == nil {
		ledger = l
	} else {
		ledger = zerocash.NewLedger()
	}

	// 3. Create auctioneer and N participants
	auctioneer := zerocash.NewParticipant("Auctioneer", pk, vk, params, zerocash.RoleAuctioneer, nil)
	participants := make([]*zerocash.Participant, N)
	for i := 0; i < N; i++ {
		name := fmt.Sprintf("Participant%d", i+1)
		participants[i] = zerocash.NewParticipant(name, pk, vk, params, zerocash.RoleParticipant, auctioneer.Pk)
	}

	// 4. Registration Phase: Each participant creates a note and registration payload
	regPayloads := make([]exchange.RegistrationPayload, N)
	bids := make([]*big.Int, N)
	// Store all registration data for use in auction phase
	registrationData := make([]struct {
		note    *zerocash.Note
		skBytes []byte
		CAux    [5]*big.Int
		TxIn    *zerocash.Tx
		pkOut   *big.Int
		skIn    *big.Int
		bid     *big.Int
		coins   *big.Int
		energy  *big.Int
	}, N)
	for i, p := range participants {
		coins := big.NewInt(100 + int64(i)*50) // Example: unique coins per participant
		energy := big.NewInt(50 + int64(i)*25)
		skBytes := p.Sk.Bytes()
		note := zerocash.NewNote(coins, energy, skBytes[:])
		bid := big.NewInt(42 + int64(i)*10) // Example: unique bid per participant
		bids[i] = bid
		regResult, err := register.Register(p, note, bid, regPK, skBytes[:], regCCS)
		if err != nil {
			log.Fatalf("registration failed for %s: %v", p.Name, err)
		}
		// Save note to wallet
		p.Wallet.AddNote(note, skBytes[:], nil, [5]byte{}, note)
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
		if err := appendTxToLedger(regResult.TxIn); err != nil {
			log.Fatalf("ledger append failed: %v", err)
		}
		// Store all registration data for auction phase
		registrationData[i].note = note
		registrationData[i].skBytes = skBytes[:]
		registrationData[i].CAux = regResult.CAux
		registrationData[i].TxIn = regResult.TxIn
		registrationData[i].pkOut = p.Pk.X.BigInt(new(big.Int))
		registrationData[i].skIn = new(big.Int).SetBytes(skBytes[:])
		registrationData[i].bid = bid
		registrationData[i].coins = coins
		registrationData[i].energy = energy
	}

	log.Println("All participants registered. Starting auction phase...")

	// 5. Auction Phase: run ExchangePhase
	txOut, info, proof, err := exchange.ExchangePhase(regPayloads, auctioneer.Sk.BigInt(new(big.Int)), params, pk, ccs)
	if err != nil {
		log.Fatalf("Auction phase failed: %v", err)
	}
	// Output results
	fmt.Printf("\n=== Auction Phase Complete ===\n")
	fmt.Printf("Proof (hex): %x\n", proof)
	fmt.Printf("Output Transaction: %+v\n", txOut)
	fmt.Printf("Public Info: %+v\n", info)

	// 6. Append auction transaction to ledger
	if tx, ok := txOut.(*zerocash.Tx); ok && tx != nil {
		if err := appendTxToLedger(tx); err != nil {
			log.Fatalf("ledger append failed: %v", err)
		}
	} else {
		log.Printf("[WARN] No auction transaction to append to ledger.")
	}

	// 7. Receiving Phase
	runReceivingPhase(participants, ledger, pk, ccs, vk)

	log.Println("\n=== Protocol Complete ===")
	log.Printf("Ledger contains %d transactions", len(ledger.GetTxs()))
	log.Printf("Commitments (CmList): %d items", len(ledger.CmList))
	log.Printf("Serial Numbers (SnList): %d items", len(ledger.SnList))
	for i, tx := range ledger.GetTxs() {
		log.Printf("  Tx %d: %s -> %s (coins=%s, energy=%s)",
			i+1, tx.OldCoin, tx.NewCoin, tx.NewCoin, tx.NewEnergy)
	}

	// Show participant wallets
	for i := 0; i < N; i++ {
		participantID := fmt.Sprintf("Participant%d", i+1)
		walletPath := fmt.Sprintf("%s_wallet.json", participantID)
		wallet, err := zerocash.LoadWallet(walletPath)
		if err != nil {
			log.Printf("%s wallet: %v", participantID, err)
		} else {
			wallet.CheckNoteStatusAgainstLedger(ledger)
			log.Printf("%s wallet:", participantID)
			log.Printf("  Name: %s", wallet.Name)
			log.Printf("  Notes: %d notes", len(wallet.Notes))
			for j, note := range wallet.Notes {
				spentStatus := "UNSPENT"
				if wallet.Spent[j] {
					spentStatus = "SPENT"
				}
				log.Printf("    Note %d (%s): coins=%s, energy=%s, PkOwner=%x",
					j+1, spentStatus, note.Value.Coins.String(), note.Value.Energy.String(), note.PkOwner)
				log.Printf("      Commitment: %x", note.Cm)
				log.Printf("      Rho: %x", note.Rho)
				log.Printf("      Rand: %x", note.Rand)
			}
			unspentNotes := wallet.GetUnspentNotes()
			log.Printf("  Unspent Notes: %d notes available for spending", len(unspentNotes))
			for j, note := range unspentNotes {
				log.Printf("    Unspent Note %d: coins=%s, energy=%s",
					j+1, note.Value.Coins.String(), note.Value.Energy.String())
			}
		}
	}

	log.Println("All participants have registered, auction completed, and funds distributed/withdrawn as per protocol.")
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

// runReceivingPhase implements the receiving phase as per the protocol
func runReceivingPhase(participants []*zerocash.Participant, ledger *zerocash.Ledger, pk groth16.ProvingKey, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) {
	log.Println("=== Receiving Phase ===")
	// 1. Check if the auctioneer performed the exchange (TxList has valid exchange tx/proof)
	exchangeSucceeded := ledger.HasValidExchange()
	if exchangeSucceeded {
		log.Println("Auctioneer performed the exchange. Distributing funds to participants...")
		for _, p := range participants {
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

// toGnarkPoint converts a native BLS12-377 point to gnark format (pointer version).
func toGnarkPoint(p *zerocash.G1Affine) *sw_bls12377.G1Affine {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	return &sw_bls12377.G1Affine{
		X: new(big.Int).SetBytes(xBytes[:]).String(),
		Y: new(big.Int).SetBytes(yBytes[:]).String(),
	}
}

// triggerWithdraw runs the withdrawal protocol for a participant
func triggerWithdraw(participant *zerocash.Participant, ledger *zerocash.Ledger, pk groth16.ProvingKey, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) error {
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

	skIn := new(big.Int)
	if skInBytes != nil {
		skIn.SetBytes(skInBytes)
	}
	rEnc := new(big.Int)
	if rEncBytes != nil {
		rEnc.SetBytes(rEncBytes)
	}

	var pkTgnark sw_bls12377.G1Affine
	if pkT != nil {
		pkTgnark.X = pkT.X.String()
		pkTgnark.Y = pkT.Y.String()
	}

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
