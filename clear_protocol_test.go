package main

import (
	"crypto/ecdh"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"implementation/internal/zerocash"
	"implementation/internal/zerocash/ecc"
	"implementation/internal/zerocash/exchange"
	"implementation/internal/zerocash/register"
	"implementation/internal/zerocash/withdraw"
)

// =============================================================================
// PROTOCOL STATE STRUCTURES
// =============================================================================

// Protocol state structures for clear data flow between phases
type ProtocolSetup struct {
	CircuitKeys             *CircuitKeys
	Ledger                  *zerocash.Ledger
	AuctioneerDHKp          *zerocash.DHKeyPair
	AuctioneerECDHPriv      *ecdh.PrivateKey // Auctioneer's ECDH private key for note decryption
	AuctioneerECDHPub       *ecdh.PublicKey
	Participants            []*zerocash.Participant
	ParticipantDHKeys       []*zerocash.DHKeyPair
	ParticipantECDHPrivKeys []*ecdh.PrivateKey // Permanent ECDH private keys for note encryption
	ParticipantECDHPubKeys  []*ecdh.PublicKey  // Permanent ECDH public keys for note encryption
	BaseNotes               []*zerocash.Note
	BaseNoteSecretKeys      [][]byte
	Bids                    []*big.Int
	SharedSecrets           []*bls12377.G1Affine
	N                       int
}

type RegistrationResult struct {
	RegistrationTxs    []*zerocash.Tx
	EncryptedBids      [][]byte
	RegistrationProofs [][]byte
	ParticipantSkIn    []*big.Int
	ParticipantPkIn    []*big.Int
	ParticipantSkOut   []*big.Int
	ParticipantPkOut   []*big.Int
	ParticipantCAux    [][5]*big.Int
}

type ExchangeResult struct {
	OutputTxs     []*zerocash.Tx
	ExchangeProof []byte
	AuctionInfo   []byte
}

type FinalizationResult struct {
	FinalLedgerState *zerocash.Ledger
	WithdrawalCount  int
}

type CircuitKeys struct {
	pkTx        groth16.ProvingKey
	vkTx        groth16.VerifyingKey
	ccsTx       constraint.ConstraintSystem
	pkReg       groth16.ProvingKey
	vkReg       groth16.VerifyingKey
	ccsReg      constraint.ConstraintSystem
	pkF10       groth16.ProvingKey
	vkF10       groth16.VerifyingKey
	ccsF10      constraint.ConstraintSystem
	pkWithdraw  groth16.ProvingKey
	vkWithdraw  groth16.VerifyingKey
	ccsWithdraw constraint.ConstraintSystem
}

// =============================================================================
// MAIN TEST FUNCTION
// =============================================================================

// TestFullProtocolFlowCorrectedCleared implements the complete PPEM protocol
// using functional decomposition for clarity
func TestFullProtocolFlowCorrectedCleared(t *testing.T) {
	t.Run("Complete PPEM Protocol - Clear Functional Decomposition", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping clear protocol test in short mode")
		}

		startTime := time.Now()
		t.Logf("🚀 Privacy-Preserving Energy Market Protocol - CLEAR IMPLEMENTATION")
		t.Logf("📋 Following exact scenario with functional decomposition")

		// =================================================================
		// PHASE 0: INITIAL SETUP (Protocol Setup)
		// =================================================================
		t.Logf("\n📋 PHASE 0: INITIAL SETUP")
		setupResult := setupProtocolInitialState(t)
		validateSetupPhase(t, setupResult)

		// =================================================================
		// PHASE 1: REGISTRATION
		// =================================================================
		t.Logf("\n📝 PHASE 1: REGISTRATION")
		registrationResult := executeRegistrationPhase(t, setupResult)
		validateRegistrationPhase(t, setupResult, registrationResult)

		// =================================================================
		// PHASE 2: AUCTION/EXCHANGE
		// =================================================================
		t.Logf("\n🔄 PHASE 2: AUCTION/EXCHANGE")
		exchangeResult := executeExchangePhase(t, setupResult, registrationResult)
		validateExchangePhase(t, setupResult, exchangeResult)

		// =================================================================
		// PHASE 3: FINALIZATION
		// =================================================================
		t.Logf("\n🔒 PHASE 3: FINALIZATION")
		finalResult := executeFinalizationPhase(t, setupResult, exchangeResult)
		validateFinalizationPhase(t, setupResult, finalResult)

		// =================================================================
		// FINAL VALIDATION & SUMMARY
		// =================================================================
		totalTime := time.Since(startTime)
		generateProtocolSummary(t, setupResult, finalResult, totalTime)
	})
}

// =============================================================================
// SETUP FUNCTIONS
// =============================================================================

func setupAllCircuitKeys(t *testing.T) *CircuitKeys {
	// CircuitTx
	var circuitTx zerocash.CircuitTx
	ccsTx, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx)
	if err != nil {
		t.Fatalf("CircuitTx compilation failed: %v", err)
	}
	pkTx, vkTx, err := groth16.Setup(ccsTx)
	if err != nil {
		t.Fatalf("CircuitTx key generation failed: %v", err)
	}

	// CircuitTxRegister
	var circuitReg register.CircuitTxRegister
	ccsReg, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitReg)
	if err != nil {
		t.Fatalf("CircuitTxRegister compilation failed: %v", err)
	}
	pkReg, vkReg, err := groth16.Setup(ccsReg)
	if err != nil {
		t.Fatalf("CircuitTxRegister key generation failed: %v", err)
	}

	// CircuitTxF10
	var circuitF10 exchange.CircuitTxF10
	ccsF10, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitF10)
	if err != nil {
		t.Fatalf("CircuitTxF10 compilation failed: %v", err)
	}
	pkF10, vkF10, err := groth16.Setup(ccsF10)
	if err != nil {
		t.Fatalf("CircuitTxF10 key generation failed: %v", err)
	}

	// CircuitWithdraw
	var circuitWithdraw withdraw.CircuitWithdraw
	ccsWithdraw, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitWithdraw)
	if err != nil {
		t.Fatalf("CircuitWithdraw compilation failed: %v", err)
	}
	pkWithdraw, vkWithdraw, err := groth16.Setup(ccsWithdraw)
	if err != nil {
		t.Fatalf("CircuitWithdraw key generation failed: %v", err)
	}

	return &CircuitKeys{
		pkTx:        pkTx,
		vkTx:        vkTx,
		ccsTx:       ccsTx,
		pkReg:       pkReg,
		vkReg:       vkReg,
		ccsReg:      ccsReg,
		pkF10:       pkF10,
		vkF10:       vkF10,
		ccsF10:      ccsF10,
		pkWithdraw:  pkWithdraw,
		vkWithdraw:  vkWithdraw,
		ccsWithdraw: ccsWithdraw,
	}
}

func setupWithdrawalKeys(t *testing.T) *CircuitKeys {
	// CircuitWithdraw
	var circuitWithdraw withdraw.CircuitWithdraw
	ccsWithdraw, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitWithdraw)
	if err != nil {
		t.Fatalf("CircuitWithdraw compilation failed: %v", err)
	}
	pkWithdraw, vkWithdraw, err := groth16.Setup(ccsWithdraw)
	if err != nil {
		t.Fatalf("CircuitWithdraw key generation failed: %v", err)
	}

	// Return a minimal CircuitKeys struct with only withdrawal fields set
	return &CircuitKeys{
		pkWithdraw:  pkWithdraw,
		vkWithdraw:  vkWithdraw,
		ccsWithdraw: ccsWithdraw,
		// Other fields will be zero values, which is fine for withdrawal-only operations
	}
}

// setupProtocolInitialState implements "📋 INITIAL SETUP (Protocol Setup)"
func setupProtocolInitialState(t *testing.T) *ProtocolSetup {
	t.Logf("🔑 Key Agreement Phase - Setting up DH + permanent ECDH parameters")
	t.Logf("📊 Architecture: DH+OTP for registration data, ECDH+AES with permanent keys for notes")

	// Setup circuit keys for all algorithms (1,2,3,4)
	circuitKeys := setupAllCircuitKeys(t)
	t.Logf("✅ Circuit keys setup complete")

	// Create ledger with circuit keys
	ledger := zerocash.NewLedger()
	ledgerKeys := &zerocash.CircuitKeys{
		VkTx:        circuitKeys.vkTx,
		CcsTx:       circuitKeys.ccsTx,
		VkReg:       circuitKeys.vkReg,
		CcsReg:      circuitKeys.ccsReg,
		VkExchange:  circuitKeys.vkF10,
		CcsExchange: circuitKeys.ccsF10,
		VkWithdraw:  circuitKeys.vkWithdraw,
		CcsWithdraw: circuitKeys.ccsWithdraw,
	}
	ledger.SetCircuitKeys(ledgerKeys)

	// 🏛️ Auctioneer State: Generate DH and ECDH keypairs
	t.Logf("🏛️ Creating Auctioneer with DH keypair (sk_T, pk_T)")
	auctioneerDHKp, _ := zerocash.GenerateDHKeyPair()
	auctioneerECDHPriv, auctioneerECDHPub, _ := generateECDHKeyPair()
	ledger.SetAuctioneerKeys(auctioneerDHKp.Pk, auctioneerECDHPub)

	// 🧑‍💼 Participants State: Create N=10 participants with initial notes
	N := 10
	t.Logf("🧑‍💼 Creating %d participants with DH keypairs (sk_i, pk_i) and ECDH keypairs", N)

	participants := make([]*zerocash.Participant, N)
	participantDHKeys := make([]*zerocash.DHKeyPair, N)
	participantECDHPrivKeys := make([]*ecdh.PrivateKey, N)
	participantECDHPubKeys := make([]*ecdh.PublicKey, N)
	baseNotes := make([]*zerocash.Note, N)
	baseNoteSecretKeys := make([][]byte, N)
	bids := make([]*big.Int, N)
	sharedSecrets := make([]*bls12377.G1Affine, N)

	for i := 0; i < N; i++ {
		// Generate DH keypair for each participant (for registration data encryption)
		participantDHKeys[i], _ = zerocash.GenerateDHKeyPair()

		// Generate permanent ECDH keypair for each participant (for note encryption)
		participantECDHPrivKeys[i], _ = ecdh.P256().GenerateKey(rand.Reader)
		participantECDHPubKeys[i] = participantECDHPrivKeys[i].PublicKey()

		// Create participant with energy market values
		participants[i] = &zerocash.Participant{
			Name:          fmt.Sprintf("Participant_%02d", i+1),
			Sk:            participantDHKeys[i].Sk,
			Pk:            participantDHKeys[i].Pk,
			Role:          zerocash.RoleParticipant,
			AuctioneerPub: auctioneerDHKp.Pk,
			Params:        &zerocash.Params{},
			Wallet: &zerocash.Wallet{
				Name:     fmt.Sprintf("Participant_%02d", i+1),
				Sk:       participantDHKeys[i].Sk,
				Pk:       participantDHKeys[i].Pk,
				Notes:    []*zerocash.Note{},
				NoteKeys: [][]byte{},
				Spent:    []bool{},
			},
		}

		// Create initial note n^base_i with energy market values
		coins := big.NewInt(int64(1000 + i*100)) // 1000-1900 coins
		energy := big.NewInt(int64(50 + i*10))   // 50-140 kWh
		bids[i] = big.NewInt(int64(20 + i*5))    // 20-65 bid price

		baseNoteSecretKeys[i] = zerocash.RandomBytesPublic(32)
		baseNotes[i] = zerocash.NewNote(coins, energy, baseNoteSecretKeys[i])
		participants[i].Wallet.AddNote(baseNotes[i], baseNoteSecretKeys[i], []byte{}, [5]byte{}, baseNotes[i])

		// Compute DH shared secret: shared_i = DH(sk_i, pk_T)
		sharedSecrets[i] = zerocash.ComputeDHShared(participantDHKeys[i].Sk, auctioneerDHKp.Pk)
	}

	// 📚 Initialize Ledger State with REAL base note commitments
	t.Logf("📚 Initializing ledger with actual cryptographic commitments")
	for i := range baseNotes {
		// Use the ACTUAL commitment from the note, not a fake string!
		cmBase := new(big.Int).SetBytes(baseNotes[i].Cm).String()
		ledger.CmList = append(ledger.CmList, cmBase)
		t.Logf("   Added real commitment for Participant_%02d: %s...", i+1, cmBase[:20])
	}

	// Save initial ledger state
	err := ledger.SaveToFile("output/ledger_initial.json")
	if err != nil {
		t.Logf("Warning: Could not save initial ledger: %v", err)
	}

	return &ProtocolSetup{
		CircuitKeys:             circuitKeys,
		Ledger:                  ledger,
		AuctioneerDHKp:          auctioneerDHKp,
		AuctioneerECDHPriv:      auctioneerECDHPriv,
		AuctioneerECDHPub:       auctioneerECDHPub,
		Participants:            participants,
		ParticipantDHKeys:       participantDHKeys,
		ParticipantECDHPrivKeys: participantECDHPrivKeys,
		ParticipantECDHPubKeys:  participantECDHPubKeys,
		BaseNotes:               baseNotes,
		BaseNoteSecretKeys:      baseNoteSecretKeys,
		Bids:                    bids,
		SharedSecrets:           sharedSecrets,
		N:                       N,
	}
}
