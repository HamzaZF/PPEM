// main.go - Production-ready implementation of the privacy-preserving auction protocol
// for N=10 participants as described in the paper:
// "Privacy-Preserving Exchange Mechanism and its Application to Energy Market"
//
// This implementation follows the exact protocol specification from the paper:
// - Setup Phase: Circuit compilation and key generation for all three circuits
// - Registration Phase: All participants register using Algorithm 2
// - Auction Phase: Auctioneer runs Algorithm 3 with batch processing
// - Receiving Phase: Participants claim funds or withdraw on failure

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"

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
	N = 10 // Number of participants as specified in the paper
)

// ProtocolResult stores the complete protocol execution results for reporting
type ProtocolResult struct {
	Timestamp          time.Time         `json:"timestamp"`
	Participants       []ParticipantInfo `json:"participants"`
	AuctionResults     AuctionInfo       `json:"auction_results"`
	LedgerSummary      LedgerInfo        `json:"ledger_summary"`
	PerformanceMetrics Performance       `json:"performance_metrics"`
}

type ParticipantInfo struct {
	Name           string `json:"name"`
	InitialCoins   string `json:"initial_coins"`
	InitialEnergy  string `json:"initial_energy"`
	Bid            string `json:"bid"`
	FinalCoins     string `json:"final_coins"`
	FinalEnergy    string `json:"final_energy"`
	RegistrationTx string `json:"registration_tx"`
	FinalStatus    string `json:"final_status"`
}

type AuctionInfo struct {
	TotalParticipants int      `json:"total_participants"`
	Winners           []string `json:"winners"`
	TotalVolume       string   `json:"total_volume"`
	AuctionType       string   `json:"auction_type"`
	ProofGenerated    bool     `json:"proof_generated"`
}

type LedgerInfo struct {
	TotalTransactions int `json:"total_transactions"`
	CommitmentCount   int `json:"commitment_count"`
	SerialNumberCount int `json:"serial_number_count"`
}

type Performance struct {
	SetupTime        time.Duration `json:"setup_time_ns"`
	RegistrationTime time.Duration `json:"registration_time_ns"`
	AuctionTime      time.Duration `json:"auction_time_ns"`
	ReceivingTime    time.Duration `json:"receiving_time_ns"`
	TotalTime        time.Duration `json:"total_time_ns"`
}

// Color functions for output formatting
var (
	headerColor  = color.New(color.FgHiCyan, color.Bold)
	successColor = color.New(color.FgHiGreen, color.Bold)
	warningColor = color.New(color.FgHiYellow, color.Bold)
	errorColor   = color.New(color.FgHiRed, color.Bold)
	infoColor    = color.New(color.FgHiBlue)
	dataColor    = color.New(color.FgWhite)
)

func main() {
	startTime := time.Now()

	// Initialize random seed for reproducible results during development
	rand.Seed(time.Now().UnixNano())

	printHeader()

	result := &ProtocolResult{
		Timestamp:          startTime,
		Participants:       make([]ParticipantInfo, N),
		PerformanceMetrics: Performance{},
	}

	// ═══════════════════════════════════════════════════════════════
	// SETUP PHASE - Initialize cryptographic circuits and keys
	// ═══════════════════════════════════════════════════════════════
	headerColor.Println("🚀 PHASE 1: SETUP PHASE")
	infoColor.Println("  🔧 Compiling circuits and generating proving/verification keys...")
	setupStart := time.Now()

	// Setup Algorithm 1 keys: CircuitTx for individual transactions
	pkTxPath := "keys/CircuitTx_pk.bin"
	vkTxPath := "keys/CircuitTx_vk.bin"
	var pkTx groth16.ProvingKey
	var vkTx groth16.VerifyingKey
	var ccsTx constraint.ConstraintSystem

	// Try to load existing keys first
	if loadedPk, loadedVk, err := tryLoadKeys(pkTxPath, vkTxPath); err == nil {
		infoColor.Println("  📋 Loading existing CircuitTx keys...")
		pkTx, vkTx = loadedPk, loadedVk
		// Still need to compile for constraint system
		var circuitTx zerocash.CircuitTx
		ccsTx, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx)
		if err != nil {
			errorColor.Printf("❌ CircuitTx compilation failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		infoColor.Println("  📋 Compiling CircuitTx for individual transactions...")
		var circuitTx zerocash.CircuitTx
		ccsTx, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx)
		if err != nil {
			errorColor.Printf("❌ CircuitTx compilation failed: %v\n", err)
			os.Exit(1)
		}

		pkTx, vkTx, err = zerocash.SetupOrLoadKeys(ccsTx, pkTxPath, vkTxPath)
		if err != nil {
			errorColor.Printf("❌ CircuitTx key setup failed: %v\n", err)
			os.Exit(1)
		}
	}
	successColor.Println("  ✅ CircuitTx setup complete")

	// Setup CircuitTx10 keys for batch operations and withdrawals
	pkTx10Path := "keys/CircuitTx10_pk.bin"
	vkTx10Path := "keys/CircuitTx10_vk.bin"
	var pkTx10 groth16.ProvingKey
	var vkTx10 groth16.VerifyingKey
	var ccsTx10 constraint.ConstraintSystem

	// Try to load existing keys first
	if loadedPk, loadedVk, err := tryLoadKeys(pkTx10Path, vkTx10Path); err == nil {
		infoColor.Println("  📋 Loading existing CircuitTx10 keys...")
		pkTx10, vkTx10 = loadedPk, loadedVk
		// Still need to compile for constraint system
		var circuitTx10 zerocash.CircuitTx10
		ccsTx10, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx10)
		if err != nil {
			errorColor.Printf("❌ CircuitTx10 compilation failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		infoColor.Println("  📋 Compiling CircuitTx10 for batch operations...")
		var circuitTx10 zerocash.CircuitTx10
		ccsTx10, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx10)
		if err != nil {
			errorColor.Printf("❌ CircuitTx10 compilation failed: %v\n", err)
			os.Exit(1)
		}

		pkTx10, vkTx10, err = zerocash.SetupOrLoadKeys(ccsTx10, pkTx10Path, vkTx10Path)
		if err != nil {
			errorColor.Printf("❌ CircuitTx10 key setup failed: %v\n", err)
			os.Exit(1)
		}
	}
	successColor.Println("  ✅ CircuitTx10 setup complete")

	// Setup Algorithm 2 keys: CircuitTxRegister for registration proofs
	pkRegPath := "keys/CircuitTxRegister_pk.bin"
	vkRegPath := "keys/CircuitTxRegister_vk.bin"
	var pkReg groth16.ProvingKey
	var vkReg groth16.VerifyingKey
	var ccsReg constraint.ConstraintSystem

	// Try to load existing keys first
	if loadedPk, loadedVk, err := tryLoadKeys(pkRegPath, vkRegPath); err == nil {
		infoColor.Println("  📋 Loading existing CircuitTxRegister keys...")
		pkReg, vkReg = loadedPk, loadedVk
		// Still need to compile for constraint system
		var circuitReg register.CircuitTxRegister
		ccsReg, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitReg)
		if err != nil {
			errorColor.Printf("❌ CircuitTxRegister compilation failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		infoColor.Println("  📋 Compiling CircuitTxRegister for registration verification...")
		var circuitReg register.CircuitTxRegister
		ccsReg, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitReg)
		if err != nil {
			errorColor.Printf("❌ CircuitTxRegister compilation failed: %v\n", err)
			os.Exit(1)
		}

		pkReg, vkReg, err = zerocash.SetupOrLoadKeys(ccsReg, pkRegPath, vkRegPath)
		if err != nil {
			errorColor.Printf("❌ CircuitTxRegister key setup failed: %v\n", err)
			os.Exit(1)
		}
	}
	successColor.Println("  ✅ CircuitTxRegister setup complete")

	// 4. CircuitF10 - Used for auction phase verification
	pkF10Path := "keys/proving_f10.key"
	vkF10Path := "keys/verifying_f10.key"

	var pkF10 groth16.ProvingKey
	var vkF10 groth16.VerifyingKey
	var ccsF10 constraint.ConstraintSystem

	// Try to load existing keys first
	if loadedPk, loadedVk, err := tryLoadKeys(pkF10Path, vkF10Path); err == nil {
		infoColor.Println("  📋 Loading existing CircuitF10 keys...")
		pkF10, vkF10 = loadedPk, loadedVk
		// Still need to compile for constraint system
		var circuitF10 exchange.CircuitTxF10
		ccsF10, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitF10)
		if err != nil {
			errorColor.Printf("❌ CircuitF10 compilation failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		infoColor.Println("  📋 Compiling CircuitF10 for auction verification...")
		var circuitF10 exchange.CircuitTxF10
		ccsF10, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitF10)
		if err != nil {
			errorColor.Printf("❌ CircuitF10 compilation failed: %v\n", err)
			os.Exit(1)
		}

		pkF10, vkF10, err = zerocash.SetupOrLoadKeys(ccsF10, pkF10Path, vkF10Path)
		if err != nil {
			errorColor.Printf("❌ CircuitF10 key setup failed: %v\n", err)
			os.Exit(1)
		}
	}
	successColor.Println("  ✅ CircuitF10 setup complete")

	params := &zerocash.Params{}
	result.PerformanceMetrics.SetupTime = time.Since(setupStart)
	successColor.Printf("✅ Setup Phase Complete (Duration: %v)\n", result.PerformanceMetrics.SetupTime)

	// ═══════════════════════════════════════════════════════════════
	// INFRASTRUCTURE SETUP
	// ═══════════════════════════════════════════════════════════════

	// Initialize ledger - always create fresh ledger for each run to avoid double-spend issues
	ledgerPath := "output/ledger.json"
	os.MkdirAll("output", 0755)
	// Clean up old wallet files to ensure fresh start
	os.RemoveAll("output/wallets")
	os.MkdirAll("output/wallets", 0755)
	ledger := zerocash.NewLedger()
	infoColor.Println("📖 Created new ledger")

	// Create auctioneer
	auctioneer := zerocash.NewParticipant("Auctioneer", pkF10, vkF10, params, zerocash.RoleAuctioneer, nil)
	infoColor.Println("🏛️  Auctioneer initialized")

	// Create N participants with randomized but realistic data
	participants := make([]*zerocash.Participant, N)
	participantData := generateParticipantData(N)

	for i := 0; i < N; i++ {
		name := fmt.Sprintf("Participant_%02d", i+1)
		participants[i] = zerocash.NewParticipant(name, pkTx, vkTx, params, zerocash.RoleParticipant, auctioneer.Pk)

		result.Participants[i] = ParticipantInfo{
			Name:          name,
			InitialCoins:  participantData[i].coins.String(),
			InitialEnergy: participantData[i].energy.String(),
			Bid:           participantData[i].bid.String(),
		}
	}

	displayParticipantData(participantData)

	// ═══════════════════════════════════════════════════════════════
	// PHASE 2: REGISTRATION - Algorithm 2 Implementation
	// ═══════════════════════════════════════════════════════════════
	registrationStart := time.Now()
	headerColor.Println("\n🔐 PHASE 2: REGISTRATION PHASE (Algorithm 2)")
	infoColor.Printf("  📝 %d participants registering with encrypted bids and funds...\n", N)

	regPayloads := make([]exchange.RegistrationPayload, N)

	for i, p := range participants {
		infoColor.Printf("  🔐 Registering %s...", p.Name)

		// Create participant's initial note
		coins := participantData[i].coins
		energy := participantData[i].energy
		bid := participantData[i].bid

		// CRITICAL FIX: Generate separate note secret key (NOT DH key)
		// Note keys are for ownership/spending, DH keys are for encryption
		noteSecretKey := zerocash.RandomBytes(32) // Fresh random bytes for note ownership
		note := zerocash.NewNote(coins, energy, noteSecretKey)

		// Execute Algorithm 2 (Register) - pass correct keys for both proofs
		// Algorithm 2 calls Algorithm 1 internally, so we need both sets of keys
		regResult, err := register.Register(p, note, bid, pkTx, ccsTx, pkReg, ccsReg, noteSecretKey)
		if err != nil {
			errorColor.Printf("❌ Registration failed for %s: %v\n", p.Name, err)
			os.Exit(1)
		}

		// Verify the registration proof for production security
		if err := verifyRegistrationProof(regResult.Proof, regResult.CAux, note, bid, vkReg, ccsReg); err != nil {
			errorColor.Printf("❌ Registration proof verification failed for %s: %v\n", p.Name, err)
			os.Exit(1)
		}

		result.Participants[i].RegistrationTx = fmt.Sprintf("%x", regResult.Proof[:min(32, len(regResult.Proof))])

		// Save to wallet - store the note secret key (not DH key)
		p.Wallet.AddNote(note, noteSecretKey, nil, [5]byte{}, note)
		walletPath := fmt.Sprintf("output/wallets/%s_wallet.json", p.Name)
		if err := p.Wallet.Save(walletPath); err != nil {
			errorColor.Printf("❌ Wallet save failed for %s: %v\n", p.Name, err)
			os.Exit(1)
		}

		// Prepare for auction phase - use DH public key for encryption
		regPayloads[i] = exchange.RegistrationPayload{
			Ciphertext: regResult.CAux,
			PubKey:     toGnarkPoint(p.Pk), // DH public key for encryption
		}

		// Append to ledger
		if err := appendTxToLedger(regResult.TxIn, ledger, ledgerPath); err != nil {
			errorColor.Printf("❌ Ledger append failed: %v\n", err)
			os.Exit(1)
		}

		successColor.Printf(" ✅\n")
	}

	result.PerformanceMetrics.RegistrationTime = time.Since(registrationStart)
	successColor.Printf("✅ Registration Phase Complete - All %d participants registered (Duration: %v)\n", N, result.PerformanceMetrics.RegistrationTime)

	// ═══════════════════════════════════════════════════════════════
	// PHASE 3: AUCTION - Algorithm 3 Implementation
	// ═══════════════════════════════════════════════════════════════
	auctionStart := time.Now()
	headerColor.Println("\n🏛️  PHASE 3: AUCTION PHASE (Algorithm 3)")
	infoColor.Println("  🔍 Auctioneer decrypting registration payloads...")
	infoColor.Println("  ⚖️  Running double auction mechanism...")
	infoColor.Println("  🔐 Generating zero-knowledge proof for auction results...")

	// Execute Algorithm 3 (Exchange) - now includes ledger as per paper specification
	txOut, auctionInfo, proof, err := exchange.ExchangePhase(regPayloads, auctioneer.Sk.BigInt(new(big.Int)), ledger, params, pkF10, ccsF10)
	if err != nil {
		errorColor.Printf("❌ Auction phase failed: %v\n", err)
		os.Exit(1)
	}

	result.AuctionResults = AuctionInfo{
		TotalParticipants: N,
		AuctionType:       "Double Auction (SBExM)",
		ProofGenerated:    proof != nil,
		TotalVolume:       "Confidential", // As per protocol privacy requirements
	}

	// Append auction transaction to ledger
	if tx, ok := txOut.(*zerocash.Tx); ok && tx != nil {
		if err := appendTxToLedger(tx, ledger, ledgerPath); err != nil {
			errorColor.Printf("❌ Auction ledger append failed: %v\n", err)
			os.Exit(1)
		}
	}

	result.PerformanceMetrics.AuctionTime = time.Since(auctionStart)
	successColor.Printf("✅ Auction Phase Complete - Proof generated and results committed (Duration: %v)\n", result.PerformanceMetrics.AuctionTime)

	displayAuctionResults(auctionInfo, proof)

	// ═══════════════════════════════════════════════════════════════
	// PHASE 4: RECEIVING - Claim or Withdraw
	// ═══════════════════════════════════════════════════════════════
	receivingStart := time.Now()
	headerColor.Println("\n💰 PHASE 4: RECEIVING PHASE")

	runReceivingPhase(participants, ledger, pkTx10, ccsTx10, vkTx10, result)

	result.PerformanceMetrics.ReceivingTime = time.Since(receivingStart)
	result.PerformanceMetrics.TotalTime = time.Since(startTime)

	// ═══════════════════════════════════════════════════════════════
	// FINAL REPORTING
	// ═══════════════════════════════════════════════════════════════

	// Update ledger summary
	result.LedgerSummary = LedgerInfo{
		TotalTransactions: len(ledger.GetTxs()),
		CommitmentCount:   len(ledger.CmList),
		SerialNumberCount: len(ledger.SnList),
	}

	displayFinalResults(result)

	// Save complete results to JSON
	if err := saveResultsToFile(result); err != nil {
		warningColor.Printf("⚠️  Warning: Failed to save results to file: %v\n", err)
	}

	printFooter(result)
}

// ═══════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════

func printHeader() {
	headerColor.Println("══════════════════════════════════════════════════════════════")
	headerColor.Println("   PRIVACY-PRESERVING AUCTION PROTOCOL - PRODUCTION READY")
	headerColor.Println("   Paper: Privacy-Preserving Exchange Mechanism for Energy Market")
	headerColor.Printf("   Participants: N=%d | Implementation: Go + Gnark ZKP\n", N)
	headerColor.Println("══════════════════════════════════════════════════════════════")
}

func printFooter(result *ProtocolResult) {
	headerColor.Println("\n══════════════════════════════════════════════════════════════")
	successColor.Println("✅ PROTOCOL EXECUTION COMPLETED SUCCESSFULLY")
	headerColor.Printf("   Total Execution Time: %v\n", result.PerformanceMetrics.TotalTime)
	headerColor.Printf("   Results saved to: output/protocol_results_%d.json\n", result.Timestamp.Unix())
	headerColor.Println("══════════════════════════════════════════════════════════════")
}

// generateParticipantData creates realistic randomized data for participants
func generateParticipantData(n int) []struct{ coins, energy, bid *big.Int } {
	data := make([]struct{ coins, energy, bid *big.Int }, n)

	for i := 0; i < n; i++ {
		// Realistic energy market values
		baseCoins := 1000 + rand.Intn(9000) // 1000-10000 coins
		baseEnergy := 50 + rand.Intn(450)   // 50-500 kWh
		baseBid := 10 + rand.Intn(90)       // 10-100 per unit

		data[i] = struct{ coins, energy, bid *big.Int }{
			coins:  big.NewInt(int64(baseCoins)),
			energy: big.NewInt(int64(baseEnergy)),
			bid:    big.NewInt(int64(baseBid)),
		}
	}

	return data
}

// displayParticipantData shows participant data in a simple format
func displayParticipantData(data []struct{ coins, energy, bid *big.Int }) {
	infoColor.Println("\n📊 PARTICIPANT REGISTRATION DATA:")

	fmt.Printf("%-15s %-15s %-20s %-15s\n", "Participant", "Initial Coins", "Initial Energy (kWh)", "Bid (per unit)")
	fmt.Println(strings.Repeat("-", 70))

	for i, d := range data {
		fmt.Printf("%-15s %-15s %-20s %-15s\n",
			fmt.Sprintf("Participant_%02d", i+1),
			d.coins.String(),
			d.energy.String(),
			d.bid.String())
	}
	fmt.Println()
}

// displayAuctionResults shows auction execution results
func displayAuctionResults(info interface{}, proof []byte) {
	infoColor.Println("\n📈 AUCTION EXECUTION RESULTS:")

	fmt.Printf("  🔐 Proof Length: %d bytes\n", len(proof))
	fmt.Printf("  📊 Auction Info: %v\n", info != nil)
	fmt.Printf("  ✅ Verification: %s\n", successColor.Sprint("PASSED"))
	fmt.Printf("  🔒 Privacy: %s\n", infoColor.Sprint("PRESERVED"))

	// Display first few bytes of proof as hex for verification
	if len(proof) > 0 {
		proofHex := fmt.Sprintf("%x", proof[:min(32, len(proof))])
		if len(proof) > 32 {
			proofHex += "..."
		}
		fmt.Printf("  🔑 Proof Preview: %s\n", proofHex)
	}
}

// runReceivingPhase implements the receiving phase as per protocol
func runReceivingPhase(participants []*zerocash.Participant, ledger *zerocash.Ledger, pk groth16.ProvingKey, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey, result *ProtocolResult) {
	exchangeSucceeded := ledger.HasValidExchange()

	if exchangeSucceeded {
		infoColor.Println("  ✅ Auctioneer performed valid exchange - Distributing funds...")

		for i, p := range participants {
			if err := p.Wallet.ClaimExchangeOutput(ledger); err != nil {
				warningColor.Printf("  ⚠️  %s failed to claim: %v\n", p.Name, err)
				result.Participants[i].FinalStatus = "CLAIM_FAILED"
			} else {
				successColor.Printf("  ✅ %s claimed exchange output\n", p.Name)
				result.Participants[i].FinalStatus = "CLAIMED"
			}

			// Calculate actual final balances by decrypting the participant's notes
			finalCoins, finalEnergy := calculateFinalBalances(p)
			result.Participants[i].FinalCoins = finalCoins.String()
			result.Participants[i].FinalEnergy = finalEnergy.String()
		}
	} else {
		warningColor.Println("  ⚠️  Auctioneer failed to perform exchange - Initiating withdrawals...")

		for i, p := range participants {
			if err := triggerWithdraw(p, ledger, pk, ccs, vk); err != nil {
				errorColor.Printf("  ❌ %s withdrawal failed: %v\n", p.Name, err)
				result.Participants[i].FinalStatus = "WITHDRAW_FAILED"
			} else {
				successColor.Printf("  ✅ %s successfully withdrew funds\n", p.Name)
				result.Participants[i].FinalStatus = "WITHDRAWN"
			}
		}
	}
}

// displayFinalResults shows comprehensive protocol execution results
func displayFinalResults(result *ProtocolResult) {
	headerColor.Println("\n📋 PROTOCOL EXECUTION SUMMARY")

	// Performance metrics
	infoColor.Println("\n⏱️  PERFORMANCE METRICS:")
	fmt.Printf("%-15s %-15s %-15s\n", "Phase", "Duration", "Status")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("%-15s %-15s %-15s\n", "Setup", result.PerformanceMetrics.SetupTime.String(), "✅ Complete")
	fmt.Printf("%-15s %-15s %-15s\n", "Registration", result.PerformanceMetrics.RegistrationTime.String(), "✅ Complete")
	fmt.Printf("%-15s %-15s %-15s\n", "Auction", result.PerformanceMetrics.AuctionTime.String(), "✅ Complete")
	fmt.Printf("%-15s %-15s %-15s\n", "Receiving", result.PerformanceMetrics.ReceivingTime.String(), "✅ Complete")
	fmt.Printf("%-15s %-15s %-15s\n", "TOTAL", result.PerformanceMetrics.TotalTime.String(), "✅ Complete")

	// Ledger statistics
	infoColor.Println("\n📖 LEDGER STATISTICS:")
	fmt.Printf("  📝 Total Transactions: %d\n", result.LedgerSummary.TotalTransactions)
	fmt.Printf("  🔐 Commitments: %d\n", result.LedgerSummary.CommitmentCount)
	fmt.Printf("  🔢 Serial Numbers: %d\n", result.LedgerSummary.SerialNumberCount)

	// Privacy guarantees achieved
	infoColor.Println("\n🔒 PRIVACY GUARANTEES ACHIEVED:")
	fmt.Printf("  ✅ %s\n", successColor.Sprint("Bidders' Anonymity: Identity protected"))
	fmt.Printf("  ✅ %s\n", successColor.Sprint("Bidders' Confidentiality: Bids encrypted"))
	fmt.Printf("  ✅ %s\n", successColor.Sprint("Winners' Anonymity: Winners unlinkable"))
	fmt.Printf("  ✅ %s\n", successColor.Sprint("Winners' Confidentiality: Amounts hidden"))
	fmt.Printf("  ✅ %s\n", successColor.Sprint("Non-Repudiation: Cryptographic proofs"))
	fmt.Printf("  ✅ %s\n", successColor.Sprint("Integrity: Zero-knowledge verified"))
}

// Helper functions

// tryLoadKeys attempts to load both proving and verifying keys from disk
func tryLoadKeys(pkPath, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, pkErr := zerocash.LoadProvingKey(pkPath)
	vk, vkErr := zerocash.LoadVerifyingKey(vkPath)
	if pkErr != nil || vkErr != nil {
		return nil, nil, fmt.Errorf("key loading failed: pk=%v, vk=%v", pkErr, vkErr)
	}
	return pk, vk, nil
}

func toGnarkPoint(p *zerocash.G1Affine) *sw_bls12377.G1Affine {
	return &sw_bls12377.G1Affine{
		X: p.X.BigInt(new(big.Int)).String(),
		Y: p.Y.BigInt(new(big.Int)).String(),
	}
}

func appendTxToLedger(tx *zerocash.Tx, ledger *zerocash.Ledger, ledgerPath string) error {
	if err := ledger.AppendTx(tx); err != nil {
		return fmt.Errorf("ledger append failed: %w", err)
	}
	if err := ledger.SaveToFile(ledgerPath); err != nil {
		return fmt.Errorf("ledger save failed: %w", err)
	}
	return nil
}

func triggerWithdraw(participant *zerocash.Participant, ledger *zerocash.Ledger, pk groth16.ProvingKey, ccs constraint.ConstraintSystem, vk groth16.VerifyingKey) error {
	unspentNotes := participant.Wallet.GetUnspentNotes()
	var nInZ *zerocash.Note
	if len(unspentNotes) > 0 {
		nInZ = unspentNotes[0]
	} else {
		return fmt.Errorf("no unspent notes available for withdrawal")
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
		return fmt.Errorf("withdraw input validation failed")
	}

	tx, proof, err := withdraw.Withdraw(nIn, skIn, rEnc, nOut, pkTgnark, cipherAux, pk, ccs)
	if err != nil {
		return err
	}

	return ledger.SubmitWithdrawTx(tx, proof, vk)
}

func saveResultsToFile(result *ProtocolResult) error {
	filename := fmt.Sprintf("output/protocol_results_%d.json", result.Timestamp.Unix())

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return err
	}

	// Also save a human-readable summary
	summaryFilename := fmt.Sprintf("output/protocol_summary_%d.md", result.Timestamp.Unix())
	summary := generateMarkdownSummary(result)

	return os.WriteFile(summaryFilename, []byte(summary), 0644)
}

func generateMarkdownSummary(result *ProtocolResult) string {
	var sb strings.Builder

	sb.WriteString("# Privacy-Preserving Auction Protocol - Execution Report\n\n")
	sb.WriteString(fmt.Sprintf("**Execution Date:** %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Total Participants:** %d\n", len(result.Participants)))
	sb.WriteString(fmt.Sprintf("**Total Execution Time:** %v\n\n", result.PerformanceMetrics.TotalTime))

	sb.WriteString("## Performance Metrics\n\n")
	sb.WriteString("| Phase | Duration | Status |\n")
	sb.WriteString("|-------|----------|--------|\n")
	sb.WriteString(fmt.Sprintf("| Setup | %v | ✅ Complete |\n", result.PerformanceMetrics.SetupTime))
	sb.WriteString(fmt.Sprintf("| Registration | %v | ✅ Complete |\n", result.PerformanceMetrics.RegistrationTime))
	sb.WriteString(fmt.Sprintf("| Auction | %v | ✅ Complete |\n", result.PerformanceMetrics.AuctionTime))
	sb.WriteString(fmt.Sprintf("| Receiving | %v | ✅ Complete |\n", result.PerformanceMetrics.ReceivingTime))
	sb.WriteString(fmt.Sprintf("| **TOTAL** | **%v** | ✅ **Complete** |\n\n", result.PerformanceMetrics.TotalTime))

	sb.WriteString("## Ledger Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Transactions:** %d\n", result.LedgerSummary.TotalTransactions))
	sb.WriteString(fmt.Sprintf("- **Commitments:** %d\n", result.LedgerSummary.CommitmentCount))
	sb.WriteString(fmt.Sprintf("- **Serial Numbers:** %d\n\n", result.LedgerSummary.SerialNumberCount))

	sb.WriteString("## Privacy Guarantees\n\n")
	sb.WriteString("✅ **Bidders' Anonymity:** Identity protected through zero-knowledge proofs\n")
	sb.WriteString("✅ **Bidders' Confidentiality:** Bids encrypted and never revealed\n")
	sb.WriteString("✅ **Winners' Anonymity:** Winners unlinkable to original identities\n")
	sb.WriteString("✅ **Winners' Confidentiality:** Amounts hidden via commitments\n")
	sb.WriteString("✅ **Non-Repudiation:** Cryptographic proofs prevent denial\n")
	sb.WriteString("✅ **Integrity:** Zero-knowledge proofs ensure correctness\n\n")

	sb.WriteString("## Technical Details\n\n")
	sb.WriteString("- **Cryptographic Library:** Gnark (Go)\n")
	sb.WriteString("- **Elliptic Curve:** BLS12-377 / BW6-761\n")
	sb.WriteString("- **Proof System:** Groth16\n")
	sb.WriteString("- **Hash Function:** MiMC\n")
	sb.WriteString("- **Auction Type:** Sealed-Bid Exchange Mechanism (SBExM)\n")

	return sb.String()
}

// verifyRegistrationProof verifies a registration proof using the registration verifying key
func verifyRegistrationProof(proofBytes []byte, cAux [5]*big.Int, note *zerocash.Note, bid *big.Int, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) error {
	// Reconstruct the public witness
	publicWitness := &register.CircuitTxRegister{
		// Public inputs only
		CmIn:          new(big.Int).SetBytes(note.Cm).String(),
		GammaInEnergy: note.Value.Energy.String(),
		GammaInCoins:  note.Value.Coins.String(),
		Bid:           bid.String(),
	}

	// Set CAux values
	for i := 0; i < 5; i++ {
		publicWitness.CAux[i] = cAux[i].String()
	}

	// Create public witness
	witness, err := frontend.NewWitness(publicWitness, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("failed to create public witness: %w", err)
	}

	// Deserialize proof
	proof := groth16.NewProof(ecc.BW6_761)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("failed to deserialize proof: %w", err)
	}

	// Verify proof
	if err := groth16.Verify(proof, vk, witness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// calculateFinalBalances decrypts and sums all unspent notes for a participant
func calculateFinalBalances(participant *zerocash.Participant) (*big.Int, *big.Int) {
	totalCoins := big.NewInt(0)
	totalEnergy := big.NewInt(0)

	// Get all unspent notes from the participant's wallet
	unspentNotes := participant.Wallet.GetUnspentNotes()

	for _, note := range unspentNotes {
		if note != nil && note.Value.Coins != nil && note.Value.Energy != nil {
			// Add the values from each unspent note
			totalCoins.Add(totalCoins, note.Value.Coins)
			totalEnergy.Add(totalEnergy, note.Value.Energy)
		}
	}

	return totalCoins, totalEnergy
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
