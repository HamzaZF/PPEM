// main.go - Comprehensive N=5 participant + 1 auctioneer registration scenario.
//
// This demonstrates the complete registration phase of the auction protocol:
//   - 1 auctioneer starts and exposes their public key
//   - 5 participants each create a note and register with the auctioneer
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
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"implementation/transactions/register"
	"implementation/zerocash"
)

const (
	numParticipants = 5
	auctioneerPort  = 8080
	participantPort = 8081
)

// RegistrationData holds the decrypted registration information
type RegistrationData struct {
	ParticipantID string   `json:"participant_id"`
	Coins         *big.Int `json:"coins"`
	Energy        *big.Int `json:"energy"`
	Bid           *big.Int `json:"bid"`
	SkIn          *big.Int `json:"sk_in"`
	PkOut         *big.Int `json:"pk_out"`
}

// Auctioneer manages the auction process
type Auctioneer struct {
	participant   *zerocash.Participant
	registrations []RegistrationData
	mu            sync.RWMutex
}

// NewAuctioneer creates a new auctioneer instance
func NewAuctioneer(participant *zerocash.Participant) *Auctioneer {
	return &Auctioneer{
		participant:   participant,
		registrations: make([]RegistrationData, 0),
	}
}

// DecryptRegistration decrypts a registration payload using the DH shared key
func (a *Auctioneer) DecryptRegistration(participantID string, cAux [5]*big.Int, participantPub *zerocash.G1Affine) (*RegistrationData, error) {
	// Compute DH shared key with this participant
	sharedKey := zerocash.ComputeDHShared(a.participant.Sk, participantPub)

	// Decrypt the payload (reverse of buildEncZKReg)
	h := zerocash.NewMiMC()
	encKeyX := sharedKey.X.BigInt(new(big.Int)).Bytes()
	encKeyY := sharedKey.Y.BigInt(new(big.Int)).Bytes()
	h.Write(encKeyX)
	h.Write(encKeyY)
	mask0 := h.Sum(nil)

	h.Reset()
	h.Write(mask0)
	mask1 := h.Sum(nil)

	h.Reset()
	h.Write(mask1)
	mask2 := h.Sum(nil)

	h.Reset()
	h.Write(mask2)
	mask3 := h.Sum(nil)

	h.Reset()
	h.Write(mask3)
	mask4 := h.Sum(nil)

	// Decrypt each field by subtracting the mask
	pkOut := new(big.Int).Sub(cAux[0], new(big.Int).SetBytes(mask0))
	skIn := new(big.Int).Sub(cAux[1], new(big.Int).SetBytes(mask1))
	bid := new(big.Int).Sub(cAux[2], new(big.Int).SetBytes(mask2))
	coins := new(big.Int).Sub(cAux[3], new(big.Int).SetBytes(mask3))
	energy := new(big.Int).Sub(cAux[4], new(big.Int).SetBytes(mask4))

	return &RegistrationData{
		ParticipantID: participantID,
		Coins:         coins,
		Energy:        energy,
		Bid:           bid,
		SkIn:          skIn,
		PkOut:         pkOut,
	}, nil
}

// AddRegistration adds a decrypted registration to the auctioneer's list
func (a *Auctioneer) AddRegistration(reg *RegistrationData) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.registrations = append(a.registrations, *reg)
}

// GetRegistrations returns all registrations
func (a *Auctioneer) GetRegistrations() []RegistrationData {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]RegistrationData, len(a.registrations))
	copy(result, a.registrations)
	return result
}

func main() {
	log.Println("=== Starting N=5 Participant + 1 Auctioneer Registration Scenario ===")

	// Setup ZKP circuit and keys (Groth16, BW6-761)
	params := &zerocash.Params{}
	pkPath := "proving.key"
	vkPath := "verifying.key"
	var circuit zerocash.CircuitTx
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("circuit compilation failed: %v", err)
	}
	pk, vk, err := zerocash.SetupOrLoadKeys(ccs, pkPath, vkPath)
	if err != nil {
		log.Fatalf("SetupOrLoadKeys failed: %v", err)
	}

	// Create auctioneer
	auctioneer := zerocash.NewParticipant("Auctioneer", pk, vk, params, zerocash.RoleAuctioneer, nil)
	auctioneerInstance := NewAuctioneer(auctioneer)

	// Start auctioneer server
	go func() {
		log.Printf("Starting auctioneer server on port %d", auctioneerPort)
		auctioneer.RunServer(auctioneerPort)
	}()

	// Wait for auctioneer to start
	time.Sleep(2 * time.Second)

	// Fetch auctioneer's public key
	auctioneerPub, err := zerocash.FetchPeerPubKey(fmt.Sprintf("localhost:%d", auctioneerPort))
	if err != nil {
		log.Fatalf("failed to fetch auctioneer pubkey: %v", err)
	}

	// Create and start participants
	participants := make([]*zerocash.Participant, numParticipants)
	var wg sync.WaitGroup

	for i := 0; i < numParticipants; i++ {
		participantID := fmt.Sprintf("Participant%d", i+1)
		port := participantPort + i

		// Create participant with auctioneer's public key
		participant := zerocash.NewParticipant(participantID, pk, vk, params, zerocash.RoleParticipant, auctioneerPub)
		participants[i] = participant

		// Start participant server
		wg.Add(1)
		go func(p *zerocash.Participant, port int, id string) {
			defer wg.Done()
			log.Printf("Starting %s server on port %d", id, port)
			p.RunServer(port)
		}(participant, port, participantID)

		// Wait a bit between starts
		time.Sleep(500 * time.Millisecond)
	}

	// Wait for all participants to start
	time.Sleep(3 * time.Second)

	log.Println("\n=== Starting Registration Phase ===")

	// Create or load the global ledger
	ledger, err := zerocash.LoadLedgerFromFile("ledger.json")
	if err != nil {
		log.Printf("Creating new ledger (previous load failed: %v)", err)
		ledger = zerocash.NewLedger()
	}

	// Each participant registers with the auctioneer
	for i, participant := range participants {
		participantID := fmt.Sprintf("Participant%d", i+1)

		// Create a note with different values for each participant
		coins := big.NewInt(int64(100 + i*50)) // 100, 150, 200, 250, 300
		energy := big.NewInt(int64(50 + i*25)) // 50, 75, 100, 125, 150
		bid := big.NewInt(int64(42 + i*10))    // 42, 52, 62, 72, 82

		// Generate a secret key and compute pk = H(sk)
		mySk := zerocash.RandomBytes(32)
		myNote := zerocash.NewNote(coins, energy, mySk)

		log.Printf("\n--- %s Registration ---", participantID)
		log.Printf("Note: coins=%s, energy=%s, bid=%s", coins.String(), energy.String(), bid.String())
		log.Printf("sk: %x", mySk)
		log.Printf("note.PkOwner: %x", myNote.PkOwner)

		// Register with the auctioneer
		regResult, err := register.Register(participant, myNote, bid, participant.PK, mySk)
		if err != nil {
			log.Fatalf("%s registration failed: %v", participantID, err)
		}

		log.Printf("%s registration successful!", participantID)
		log.Printf("  Ciphertext (c^Aux): [%s, %s, %s, %s, %s]",
			regResult.CAux[0].String(), regResult.CAux[1].String(),
			regResult.CAux[2].String(), regResult.CAux[3].String(), regResult.CAux[4].String())
		log.Printf("  InfoBid: %x", regResult.InfoBid)

		// Append transaction to ledger (as per paper: CmList, SnList, TxList)
		if err := ledger.AppendTx(regResult.TxIn); err != nil {
			log.Fatalf("Failed to append %s transaction to ledger: %v", participantID, err)
		}
		if err := ledger.SaveToFile("ledger.json"); err != nil {
			log.Fatalf("Failed to save ledger: %v", err)
		}

		// Update participant wallet with the new note from the transaction
		participant.Wallet.AddNote(regResult.TxIn.NewNote, mySk)

		// Mark the old note as spent (it was consumed in the transaction)
		// Note: In this case, myNote was just created for registration, so it's immediately spent
		// In a real scenario, this would be a note that was previously in the wallet
		log.Printf("  Note consumed in transaction (marked as spent)")

		walletPath := fmt.Sprintf("%s_wallet.json", participantID)
		if err := participant.Wallet.Save(walletPath); err != nil {
			log.Fatalf("Failed to save %s wallet: %v", participantID, err)
		}

		// Auctioneer decrypts the registration
		decryptedReg, err := auctioneerInstance.DecryptRegistration(participantID, regResult.CAux, participant.Pk)
		if err != nil {
			log.Fatalf("Failed to decrypt %s registration: %v", participantID, err)
		}

		auctioneerInstance.AddRegistration(decryptedReg)
		log.Printf("  Decrypted: coins=%s, energy=%s, bid=%s",
			decryptedReg.Coins.String(), decryptedReg.Energy.String(), decryptedReg.Bid.String())
	}

	// Wait for all registrations to complete
	time.Sleep(2 * time.Second)

	log.Println("\n=== Registration Summary ===")
	registrations := auctioneerInstance.GetRegistrations()
	for _, reg := range registrations {
		log.Printf("%s: coins=%s, energy=%s, bid=%s",
			reg.ParticipantID, reg.Coins.String(), reg.Energy.String(), reg.Bid.String())
	}

	// Show ledger state
	log.Println("\n=== Ledger State ===")
	log.Printf("Ledger contains %d transactions", len(ledger.GetTxs()))
	log.Printf("Commitments (CmList): %d items", len(ledger.CmList))
	log.Printf("Serial Numbers (SnList): %d items", len(ledger.SnList))
	for i, tx := range ledger.GetTxs() {
		log.Printf("  Tx %d: %s -> %s (coins=%s, energy=%s)",
			i+1, tx.OldCoin, tx.NewCoin, tx.NewCoin, tx.NewEnergy)
	}

	// Show participant wallets
	log.Println("\n=== Participant Wallets ===")
	for i := 0; i < numParticipants; i++ {
		participantID := fmt.Sprintf("Participant%d", i+1)
		walletPath := fmt.Sprintf("%s_wallet.json", participantID)
		wallet, err := zerocash.LoadWallet(walletPath)
		if err != nil {
			log.Printf("%s wallet: %v", participantID, err)
		} else {
			// Check note status against ledger dynamically
			wallet.CheckNoteStatusAgainstLedger(ledger)

			log.Printf("%s wallet:", participantID)
			log.Printf("  Name: %s", wallet.Name)
			log.Printf("  DH Public Key: X=%x, Y=%x", wallet.Pk.X.Bytes(), wallet.Pk.Y.Bytes())
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
			log.Printf("  Note Keys: %d secret keys", len(wallet.NoteKeys))
			for j, sk := range wallet.NoteKeys {
				log.Printf("    Key %d: %x", j+1, sk)
			}

			// Show unspent notes summary
			unspentNotes := wallet.GetUnspentNotes()
			log.Printf("  Unspent Notes: %d notes available for spending", len(unspentNotes))
			for j, note := range unspentNotes {
				log.Printf("    Unspent Note %d: coins=%s, energy=%s",
					j+1, note.Value.Coins.String(), note.Value.Energy.String())
			}
		}
	}

	log.Println("\n=== Scenario Complete ===")
	log.Println("All participants have registered with the auctioneer.")
	log.Println("The auctioneer has decrypted all registration payloads.")
	log.Println("The ledger contains all Zerocash transactions.")
	log.Println("Ready to proceed to the next phase of the protocol.")

	// Keep servers running
	select {}
}
