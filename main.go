package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"

	"implementation/internal/transactions/exchange"
	"implementation/internal/transactions/register"
	"implementation/internal/transactions/withdraw"
	"implementation/internal/zerocash"
)

// MarketConfig defines all configurable market parameters
type MarketConfig struct {
	// Basic market parameters
	NumParticipants int    `json:"num_participants"`
	AuctionType     string `json:"auction_type"`

	// Participant configuration
	Roles         map[int]zerocash.OrderType `json:"roles"`
	InitialCoins  []int64                    `json:"initial_coins"`
	InitialEnergy []int64                    `json:"initial_energy"`
	Orders        []zerocash.EnergyOrder     `json:"orders"`

	// Withdrawal scenario configuration
	WithdrawalMode string `json:"withdrawal_mode"` // "none", "emergency", "selective"
	WithdrawAll    bool   `json:"withdraw_all"`    // true = all participants withdraw
	WithdrawList   []int  `json:"withdraw_list"`   // specific participants (for testing)
}

// createDefaultMarketConfig creates a balanced energy market scenario
func createDefaultMarketConfig() MarketConfig {
	return MarketConfig{
		NumParticipants: 10,
		AuctionType:     "sealed-bid-double-auction",

		// Participant roles: mixed buyers and sellers with flexible ratio (configurable distribution)
		Roles: map[int]zerocash.OrderType{
			0: zerocash.BUY, 1: zerocash.SELL, 2: zerocash.BUY, 3: zerocash.SELL, 4: zerocash.BUY,
			5: zerocash.SELL, 6: zerocash.BUY, 7: zerocash.SELL, 8: zerocash.BUY, 9: zerocash.SELL,
		},

		// Initial balances: increasing coins and energy
		InitialCoins:  []int64{1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900},
		InitialEnergy: []int64{50, 60, 70, 80, 90, 100, 110, 120, 130, 140},

		// Orders: buyers willing to pay more, sellers asking for less (enables trades)
		// Buyers (0-4): prices 60, 55, 50, 45, 40 (descending - high to low willingness to pay)
		// Sellers (5-9): prices 30, 35, 40, 45, 50 (ascending - low to high asking price)
		// Each participant wants to trade 10 units of energy
		Orders: []zerocash.EnergyOrder{
			{Type: zerocash.BUY, Price: big.NewInt(60), Quantity: big.NewInt(10)},  // Buyer 0
			{Type: zerocash.BUY, Price: big.NewInt(55), Quantity: big.NewInt(10)},  // Buyer 1
			{Type: zerocash.BUY, Price: big.NewInt(50), Quantity: big.NewInt(10)},  // Buyer 2
			{Type: zerocash.BUY, Price: big.NewInt(45), Quantity: big.NewInt(10)},  // Buyer 3
			{Type: zerocash.BUY, Price: big.NewInt(40), Quantity: big.NewInt(10)},  // Buyer 4
			{Type: zerocash.SELL, Price: big.NewInt(30), Quantity: big.NewInt(10)}, // Seller 5
			{Type: zerocash.SELL, Price: big.NewInt(35), Quantity: big.NewInt(10)}, // Seller 6
			{Type: zerocash.SELL, Price: big.NewInt(40), Quantity: big.NewInt(10)}, // Seller 7
			{Type: zerocash.SELL, Price: big.NewInt(45), Quantity: big.NewInt(10)}, // Seller 8
			{Type: zerocash.SELL, Price: big.NewInt(50), Quantity: big.NewInt(10)}, // Seller 9
		},

		// No withdrawal by default (normal market operation)
		WithdrawalMode: "none",
		WithdrawAll:    false,
		WithdrawList:   []int{},
	}
}

// createMarketConfigForN creates a realistic market configuration for any number of participants
// buyerRatio specifies what fraction should be buyers (0.0 to 1.0). Default 0.5 means balanced market.
func createMarketConfigForN(n int, buyerRatio float64) MarketConfig {
	if n <= 0 {
		panic("createMarketConfigForN: N must be positive")
	}
	if buyerRatio < 0.0 || buyerRatio > 1.0 {
		panic("createMarketConfigForN: buyerRatio must be between 0.0 and 1.0")
	}

	// Create realistic mixed roles with flexible buyer/seller ratio
	roles := make(map[int]zerocash.OrderType)
	initialCoins := make([]int64, n)
	initialEnergy := make([]int64, n)
	orders := make([]zerocash.EnergyOrder, n)

	// Calculate number of buyers and sellers based on ratio
	numBuyers := int(float64(n) * buyerRatio)
	numSellers := n - numBuyers

	// Ensure at least one of each if both are needed and n >= 2
	if n >= 2 && numBuyers == 0 && buyerRatio > 0 {
		numBuyers = 1
		numSellers = n - 1
	}
	if n >= 2 && numSellers == 0 && buyerRatio < 1.0 {
		numSellers = 1
		numBuyers = n - 1
	}

	fmt.Printf("Market composition: %d buyers, %d sellers (%.1f%% buyers)\n",
		numBuyers, numSellers, buyerRatio*100)

	// Create a mixed pattern of buyers and sellers
	buyerCount := 0
	sellerCount := 0

	for i := 0; i < n; i++ {
		var role zerocash.OrderType

		// Distribute roles based on calculated counts
		if buyerCount < numBuyers && sellerCount < numSellers {
			// Both types available, alternate for good distribution
			if i%2 == 0 && buyerCount < numBuyers {
				role = zerocash.BUY
				buyerCount++
			} else if sellerCount < numSellers {
				role = zerocash.SELL
				sellerCount++
			} else {
				role = zerocash.BUY
				buyerCount++
			}
		} else if buyerCount < numBuyers {
			// Only buyers left
			role = zerocash.BUY
			buyerCount++
		} else {
			// Only sellers left
			role = zerocash.SELL
			sellerCount++
		}

		roles[i] = role

		// Initial balances: vary based on participant index
		initialCoins[i] = int64(1000 + i*100)
		initialEnergy[i] = 100 // Fixed energy for all participants

		// Create realistic market prices
		// Buyers: willing to pay 40-60 coins per unit (descending by eagerness)
		// Sellers: asking 20-50 coins per unit (ascending by desperation)
		if role == zerocash.BUY {
			// Buyers bid between 40-60, with earlier buyers bidding higher
			buyerIndex := buyerCount - 1 // 0-based buyer index
			maxBid := 60
			minBid := 40
			bidRange := maxBid - minBid

			var price int64
			if numBuyers == 1 {
				price = int64((maxBid + minBid) / 2) // Use middle price for single buyer
			} else {
				price = int64(maxBid - (buyerIndex*bidRange)/(numBuyers-1))
			}
			if price < int64(minBid) {
				price = int64(minBid)
			}

			orders[i] = zerocash.EnergyOrder{
				Type:     zerocash.BUY,
				Price:    big.NewInt(price),
				Quantity: big.NewInt(10),
			}
		} else {
			// Sellers ask between 20-50, with earlier sellers asking lower
			sellerIndex := sellerCount - 1 // 0-based seller index
			minAsk := 20
			maxAsk := 50
			askRange := maxAsk - minAsk

			var price int64
			if numSellers == 1 {
				price = int64((minAsk + maxAsk) / 2) // Use middle price for single seller
			} else {
				price = int64(minAsk + (sellerIndex*askRange)/(numSellers-1))
			}
			if price > int64(maxAsk) {
				price = int64(maxAsk)
			}

			orders[i] = zerocash.EnergyOrder{
				Type:     zerocash.SELL,
				Price:    big.NewInt(price),
				Quantity: big.NewInt(10),
			}
		}
	}

	return MarketConfig{
		NumParticipants: n,
		AuctionType:     "sealed-bid-double-auction",
		Roles:           roles,
		InitialCoins:    initialCoins,
		InitialEnergy:   initialEnergy,
		Orders:          orders,
		WithdrawalMode:  "none",
		WithdrawAll:     false,
		WithdrawList:    []int{},
	}
}

// validateConfig ensures the market configuration is valid
func validateConfig(config MarketConfig) error {
	if config.NumParticipants <= 0 {
		return fmt.Errorf("number of participants must be positive")
	}

	// Removed the divisible by 4 restriction - now supports any N

	if len(config.InitialCoins) != config.NumParticipants {
		return fmt.Errorf("initial coins array length (%d) must match number of participants (%d)",
			len(config.InitialCoins), config.NumParticipants)
	}

	if len(config.InitialEnergy) != config.NumParticipants {
		return fmt.Errorf("initial energy array length (%d) must match number of participants (%d)",
			len(config.InitialEnergy), config.NumParticipants)
	}

	if len(config.Orders) != config.NumParticipants {
		return fmt.Errorf("orders array length (%d) must match number of participants (%d)",
			len(config.Orders), config.NumParticipants)
	}

	if len(config.Roles) != config.NumParticipants {
		return fmt.Errorf("roles map length (%d) must match number of participants (%d)",
			len(config.Roles), config.NumParticipants)
	}

	// Validate withdrawal configuration
	if config.WithdrawalMode == "selective" && len(config.WithdrawList) == 0 {
		return fmt.Errorf("selective withdrawal mode requires non-empty withdraw list")
	}

	for _, id := range config.WithdrawList {
		if id < 0 || id >= config.NumParticipants {
			return fmt.Errorf("withdraw list contains invalid participant ID: %d", id)
		}
	}

	return nil
}

// Protocol configuration - now using MarketConfig instead of hardcoded values

// ProtocolState holds all the state needed for the PPEM protocol execution
type ProtocolState struct {
	// Market configuration
	Config MarketConfig

	// Cryptographic keys and parameters
	AuctioneerDHKp      *zerocash.DHKeyPair
	AuctioneerECDHPriv  *ecdh.PrivateKey
	AuctioneerECDHPub   *ecdh.PublicKey
	ParticipantDHKeys   []*zerocash.DHKeyPair
	ParticipantECDHKeys []*ecdh.PrivateKey
	CircuitKeys         *CircuitKeys

	// Participants and their data
	Participants  []*zerocash.Participant
	BaseNotes     []*zerocash.Note
	BaseNoteKeys  [][]byte
	OrderPrices   []*big.Int // Order prices for each participant
	SharedSecrets []*bls12377.G1Affine

	// Protocol execution data
	Ledger             *zerocash.Ledger
	RegistrationTxs    []*zerocash.Tx
	RegistrationProofs [][]byte
	ExchangeProof      []byte
	WithdrawalResults  []bool
	WithdrawalAttempts int // Track number of actual withdrawal attempts

	// Algorithm 2 outputs (Registration keypairs that must be stored)
	ParticipantSkIn  []*big.Int    // sk^in: Secret keys for notes TO auctioneer
	ParticipantPkIn  []*big.Int    // pk^in: Public keys for notes TO auctioneer
	ParticipantSkOut []*big.Int    // sk^out: Secret keys for notes FROM auctioneer
	ParticipantPkOut []*big.Int    // pk^out: Public keys for notes FROM auctioneer
	ParticipantCAux  [][5]*big.Int // C^Aux: Encrypted registration data
}

// CircuitKeys holds all the cryptographic circuit keys needed for ZK proofs
type CircuitKeys struct {
	// Fixed circuits (for backward compatibility)
	pkTx, pkReg, pkF10, pkF20, pkWithdraw      groth16.ProvingKey
	vkTx, vkReg, vkF10, vkF20, vkWithdraw      groth16.VerifyingKey
	ccsTx, ccsReg, ccsF10, ccsF20, ccsWithdraw constraint.ConstraintSystem

	// Dynamic circuit manager for any N participants
	DynamicManager *exchange.CircuitKeyManager
}

func main() {
	// Parse command-line flags
	var numParticipants int
	var buyerRatio float64
	flag.IntVar(&numParticipants, "n", 10, "Number of participants (any positive integer, default: 10)")
	flag.Float64Var(&buyerRatio, "buyer-ratio", 0.5, "Fraction of participants that should be buyers (0.0 to 1.0, default: 0.5)")
	flag.Parse()

	// Validate input parameters
	if numParticipants <= 0 {
		fmt.Printf("Error: Number of participants must be positive, got %d\n", numParticipants)
		os.Exit(1)
	}

	if buyerRatio < 0.0 || buyerRatio > 1.0 {
		fmt.Printf("Error: Buyer ratio must be between 0.0 and 1.0, got %.2f\n", buyerRatio)
		os.Exit(1)
	}

	fmt.Println("Privacy-Preserving Energy Market Protocol (PPEM)")
	fmt.Println("================================================")
	fmt.Printf("Configuration: N=%d participants, %.1f%% buyers\n", numParticipants, buyerRatio*100)
	fmt.Println()

	startTime := time.Now()

	// STEP 1: Configure market scenario
	config := createMarketConfigForN(numParticipants, buyerRatio) // Dynamic scaling based on flags
	// Uncomment to try different scenarios for benchmarking:
	// config := createMarketConfig5Participants()  // N=5 participants
	// config := createDefaultMarketConfig()        // N=10 participants
	// config := createMarketConfig15Participants() // N=15 participants
	// config := createMarketConfig20Participants() // N=20 participants
	// config := createMarketConfig25Participants() // N=25 participants
	// config := createHighDemandScenario()
	// config := createLowSupplyScenario()
	// config := createEmergencyScenario()
	// config := createTestingScenario()

	// DYNAMIC SCALING: Use this for any number of participants with flexible buyer/seller ratios
	// config := createMarketConfigForN(50, 0.6)   // N=50 participants, 60% buyers
	// config := createMarketConfigForN(100, 0.3)  // N=100 participants, 30% buyers
	// config := createMarketConfigForN(7, 0.43)   // N=7 participants, ~43% buyers (3 buyers, 4 sellers)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		log.Fatalf("Invalid market configuration: %v", err)
	}

	// STEP 2: Initialize protocol state with configuration
	state := &ProtocolState{
		Config:             config,
		Participants:       make([]*zerocash.Participant, config.NumParticipants),
		BaseNotes:          make([]*zerocash.Note, config.NumParticipants),
		BaseNoteKeys:       make([][]byte, config.NumParticipants),
		OrderPrices:        make([]*big.Int, config.NumParticipants),
		SharedSecrets:      make([]*bls12377.G1Affine, config.NumParticipants),
		ParticipantSkIn:    make([]*big.Int, config.NumParticipants),
		ParticipantPkIn:    make([]*big.Int, config.NumParticipants),
		ParticipantSkOut:   make([]*big.Int, config.NumParticipants),
		ParticipantPkOut:   make([]*big.Int, config.NumParticipants),
		ParticipantCAux:    make([][5]*big.Int, config.NumParticipants),
		RegistrationTxs:    make([]*zerocash.Tx, config.NumParticipants),
		RegistrationProofs: make([][]byte, config.NumParticipants),
		WithdrawalResults:  make([]bool, config.NumParticipants),
	}

	// PHASE 0: SETUP
	fmt.Println("SETUP PHASE")
	fmt.Println("===========")
	if err := setupProtocol(state); err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	// PHASE 1: REGISTRATION
	fmt.Println("\nREGISTRATION PHASE")
	fmt.Println("==================")
	if err := executeRegistrationPhase(state); err != nil {
		log.Fatalf("Registration failed: %v", err)
	}

	// PHASE 2: EXCHANGE
	fmt.Println("\nEXCHANGE PHASE")
	fmt.Println("==============")
	if err := executeExchangePhase(state); err != nil {
		log.Fatalf("Exchange failed: %v", err)
	}

	// PHASE 3: FINALIZATION
	fmt.Println("\nFINALIZATION PHASE")
	fmt.Println("==================")
	if err := executeFinalizationPhase(state); err != nil {
		log.Fatalf("Finalization failed: %v", err)
	}

	// PHASE 4: WITHDRAWAL
	fmt.Println("\nWITHDRAWAL PHASE")
	fmt.Println("================")
	executeWithdrawalDemo(state)

	// PROTOCOL SUMMARY
	totalTime := time.Since(startTime)
	printProtocolSummary(state, totalTime)
}

// setupProtocol implements the initial setup phase including key generation and circuit compilation
func setupProtocol(state *ProtocolState) error {
	fmt.Println("Initializing cryptographic system...")

	// Step 1: Compile ZK circuits
	fmt.Println("  - Compiling zero-knowledge circuits...")
	var err error
	state.CircuitKeys, err = setupCircuitKeys(state.Config.NumParticipants)
	if err != nil {
		return fmt.Errorf("circuit setup failed: %w", err)
	}

	// Step 2: Generate auctioneer keys
	fmt.Println("  - Generating auctioneer cryptographic keys...")
	state.AuctioneerDHKp, err = zerocash.GenerateDHKeyPair()
	if err != nil {
		return fmt.Errorf("auctioneer key generation failed: %w", err)
	}

	state.AuctioneerECDHPriv, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("auctioneer key generation failed: %w", err)
	}
	state.AuctioneerECDHPub = state.AuctioneerECDHPriv.PublicKey()

	// Step 3: Generate participant keys and initial balances
	fmt.Println("  - Setting up participant keypairs...")
	state.ParticipantDHKeys = make([]*zerocash.DHKeyPair, state.Config.NumParticipants)
	state.ParticipantECDHKeys = make([]*ecdh.PrivateKey, state.Config.NumParticipants)

	for i := 0; i < state.Config.NumParticipants; i++ {
		// Generate DH keypair for participant i
		state.ParticipantDHKeys[i], err = zerocash.GenerateDHKeyPair()
		if err != nil {
			return fmt.Errorf("participant %d DH key generation failed: %w", i, err)
		}

		// Generate ECDH keypair for participant i
		state.ParticipantECDHKeys[i], err = ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("participant %d ECDH key generation failed: %w", i, err)
		}

		// Create participant with proper keys
		state.Participants[i] = &zerocash.Participant{
			Name:          fmt.Sprintf("Participant_%02d", i+1),
			Sk:            state.ParticipantDHKeys[i].Sk,
			Pk:            state.ParticipantDHKeys[i].Pk,
			Role:          zerocash.RoleParticipant,
			AuctioneerPub: state.AuctioneerDHKp.Pk,
			Params:        &zerocash.Params{},
			Wallet: &zerocash.Wallet{
				Name: fmt.Sprintf("Participant_%02d", i+1),
				Sk:   state.ParticipantDHKeys[i].Sk,
				Pk:   state.ParticipantDHKeys[i].Pk,
			},
		}

		// Create initial energy market note using configuration
		coins := big.NewInt(state.Config.InitialCoins[i])
		energy := big.NewInt(state.Config.InitialEnergy[i])
		state.OrderPrices[i] = new(big.Int).Set(state.Config.Orders[i].Price)

		// Generate secret key for the base note
		state.BaseNoteKeys[i] = zerocash.RandomBytesPublic(32)
		state.BaseNotes[i] = zerocash.NewNote(coins, energy, state.BaseNoteKeys[i])

		// Add note to participant's wallet
		state.Participants[i].Wallet.AddNote(state.BaseNotes[i], state.BaseNoteKeys[i], []byte{}, [5]byte{}, state.BaseNotes[i])

		// Compute DH shared secret: shared_i = DH(sk_i, pk_T)
		// This is the cryptographic foundation for the DH-OTP encryption in Algorithm 2
		state.SharedSecrets[i] = zerocash.ComputeDHShared(state.ParticipantDHKeys[i].Sk, state.AuctioneerDHKp.Pk)
	}

	// Step 4: Initialize ledger with base note commitments
	state.Ledger = zerocash.NewLedger()
	state.Ledger.SetCircuitKeys(&zerocash.CircuitKeys{})
	state.Ledger.SetAuctioneerKeys(state.AuctioneerDHKp.Pk, state.AuctioneerECDHPub)

	for i := range state.BaseNotes {
		cmBase := new(big.Int).SetBytes(state.BaseNotes[i].Cm).String()
		state.Ledger.CmList = append(state.Ledger.CmList, cmBase)
	}

	fmt.Printf("Setup complete: %d participants initialized\n", state.Config.NumParticipants)
	return nil
}

// executeRegistrationPhase handles participant registration
func executeRegistrationPhase(state *ProtocolState) error {
	fmt.Println("Processing participant registrations...")

	// Start registration phase on the ledger
	if err := state.Ledger.StartRegistrationPhase(); err != nil {
		return fmt.Errorf("failed to start registration phase: %w", err)
	}

	// Execute registration for each participant
	for i := 0; i < state.Config.NumParticipants; i++ {
		role := state.Config.Roles[i]
		roleStr := role.String()
		var orderMeaning string
		if role == zerocash.BUY {
			orderMeaning = fmt.Sprintf("max willing to pay %s coins/unit", state.OrderPrices[i].String())
		} else {
			orderMeaning = fmt.Sprintf("min willing to accept %s coins/unit", state.OrderPrices[i].String())
		}

		fmt.Printf("Participant %d (%s): ", i+1, roleStr)

		fmt.Println("Generating keypairs, creating transaction, encrypting bid data, generating proof...")

		registerResult, err := register.Register(
			state.Participants[i],
			state.BaseNotes[i],
			state.OrderPrices[i],
			state.CircuitKeys.pkTx,
			state.CircuitKeys.ccsTx,
			state.CircuitKeys.pkReg,
			state.CircuitKeys.ccsReg,
			state.BaseNoteKeys[i],
			state.AuctioneerECDHPub,
			state.ParticipantECDHKeys[i],
		)
		if err != nil {
			return fmt.Errorf("Algorithm 2 failed for participant %d: %w", i, err)
		}

		// Store Algorithm 2 outputs (CRITICAL: These must be saved for Algorithm 4)
		state.RegistrationTxs[i] = registerResult.TxIn
		state.RegistrationProofs[i] = registerResult.Proof
		state.ParticipantSkIn[i] = registerResult.SkIn   // Needed for Algorithm 4
		state.ParticipantPkIn[i] = registerResult.PkIn   // Needed for Algorithm 4
		state.ParticipantSkOut[i] = registerResult.SkOut // Needed to spend exchange results
		state.ParticipantPkOut[i] = registerResult.PkOut // Needed for exchange
		state.ParticipantCAux[i] = registerResult.CAux

		// Submit registration to ledger for verification
		encryptedBidBytes := make([]byte, 0)
		for _, val := range state.ParticipantCAux[i] {
			encryptedBidBytes = append(encryptedBidBytes, val.Bytes()...)
		}

		err = state.Ledger.SubmitRegistration(
			state.RegistrationTxs[i],
			encryptedBidBytes,
			state.RegistrationProofs[i],
			state.Participants[i].Name,
		)
		if err != nil {
			return fmt.Errorf("failed to submit registration for participant %d: %w", i, err)
		}

		fmt.Printf("SUCCESS: ZK proof (%d bytes), %s coins, %s energy, %s\n",
			len(state.RegistrationProofs[i]),
			state.BaseNotes[i].Value.Coins.String(),
			state.BaseNotes[i].Value.Energy.String(),
			orderMeaning)
	}

	fmt.Printf("Registration complete: %d/%d participants registered\n",
		state.Config.NumParticipants, state.Config.NumParticipants)
	return nil
}

// executeExchangePhase handles the energy market auction
func executeExchangePhase(state *ProtocolState) error {
	fmt.Println("Executing energy market auction...")
	fmt.Println("  - Decrypting registration data...")
	fmt.Println("  - Matching buyers and sellers...")
	fmt.Println("  - Computing auction results...")

	// Create exchange payloads for the auctioneer
	// NOTE: Participants will be sorted by the exchange phase according to their roles:
	// - Buyers will be sorted by bid (descending - highest to lowest)
	// - Sellers will be sorted by ask (ascending - lowest to highest)
	// - Number of buyers/sellers is configurable via buyer-ratio parameter
	exchangePayloads := make([]exchange.RegistrationPayload, state.Config.NumParticipants)
	participantECDHPubKeys := make([]*ecdh.PublicKey, state.Config.NumParticipants)

	for i := 0; i < state.Config.NumParticipants; i++ {
		exchangePayloads[i] = exchange.RegistrationPayload{
			Ciphertext: state.ParticipantCAux[i],
			PubKey: &sw_bls12377.G1Affine{
				X: state.ParticipantDHKeys[i].Pk.X.String(),
				Y: state.ParticipantDHKeys[i].Pk.Y.String(),
			},
			TxNoteData: state.RegistrationTxs[i].CNew, // Use encrypted note data from Algorithm 1
		}
		participantECDHPubKeys[i] = state.ParticipantECDHKeys[i].PublicKey()
	}

	// Prepare DH private keys for circuit
	participantDHPrivKeys := make([]*bls12377_fr.Element, state.Config.NumParticipants)
	for i := 0; i < state.Config.NumParticipants; i++ {
		participantDHPrivKeys[i] = state.ParticipantDHKeys[i].Sk
	}

	// Declare variables that will be used after the if-else block
	var exchangeTx interface{}
	var auctionInfo interface{}
	var exchangeProof []byte
	var err error

	// Generate ZK proofs for cryptographic verification (auction logic runs outside)
	fmt.Println("  - Generating exchange proof...")

	// Get dynamic circuit keys for the actual number of participants
	dynamicKeys, err := state.CircuitKeys.DynamicManager.GetOrCreateCircuitKeys(state.Config.NumParticipants)
	if err != nil {
		return fmt.Errorf("failed to get circuit keys for %d participants: %w", state.Config.NumParticipants, err)
	}

	pk := dynamicKeys.ProvingKey
	ccs := dynamicKeys.ConstraintSystem

	exchangeTx, auctionInfo, exchangeProof, err = exchange.ExchangePhaseWithNotes(
		exchangePayloads,
		state.AuctioneerDHKp.Sk.BigInt(new(big.Int)),
		state.AuctioneerECDHPriv,
		participantECDHPubKeys,
		participantDHPrivKeys,
		state.AuctioneerDHKp.Pk,
		state.Config.Roles,
		state.Ledger,
		&zerocash.Params{},
		pk,
		ccs,
	)
	if err != nil {
		return fmt.Errorf("exchange execution failed: %w", err)
	}

	state.ExchangeProof = exchangeProof

	// Generate auction graphs for verification
	fmt.Println("  - Generating auction visualization graphs...")

	// Create graphs subdirectory
	graphsDir := "graphs"
	if err := os.MkdirAll(graphsDir, 0755); err != nil {
		fmt.Printf("Warning: Could not create graphs directory: %v\n", err)
	} else {
		// Extract auction execution result for plotting
		if compositeResult, ok := auctionInfo.(struct {
			AuctionResult    *exchange.AuctionResult
			AuctionExecution *exchange.AuctionExecutionResult
		}); ok {
			// Create timestamp for unique filenames
			timestamp := time.Now().Format("20060102_150405")
			plotTitle := fmt.Sprintf("PPEM_N%d_Buyers%.0f%%_%s",
				state.Config.NumParticipants,
				getBuyerRatio(state.Config.Roles)*100,
				timestamp)

			// Create plot configuration
			config := exchange.DefaultPlotConfig()
			config.OutputPath = fmt.Sprintf("%s/%s.png", graphsDir, plotTitle)
			config.Title = fmt.Sprintf("N=%d (%d buyers, %d sellers) | Clearing: %v | Commission: %v | Traded: %d units",
				state.Config.NumParticipants,
				countBuyers(state.Config.Roles),
				countSellers(state.Config.Roles),
				compositeResult.AuctionExecution.ClearingPrice,
				compositeResult.AuctionExecution.AuctioneerCommission,
				compositeResult.AuctionExecution.TotalEnergyTraded)

			// Create inputs array for plotting (reconstruct from exchange data)
			inputs := make([]exchange.DecryptedRegistration, 0)
			if exchangeResult, ok := exchangeTx.(*exchange.ExchangeTransaction); ok {
				for i, output := range exchangeResult.Outputs {
					if i < len(state.Config.Orders) {
						input := exchange.DecryptedRegistration{
							Price:    state.Config.Orders[i].Price,
							Quantity: state.Config.Orders[i].Quantity,
							Coins:    output.Coins,
							Energy:   output.Energy,
						}
						inputs = append(inputs, input)
					}
				}
			}

			// Generate the plot
			err := exchange.CreateSupplyDemandPlot(inputs, state.Config.Roles, compositeResult.AuctionExecution, config)
			if err != nil {
				fmt.Printf("Warning: Could not generate auction plot: %v\n", err)
			} else {
				fmt.Printf("✅ Auction graph saved: %s\n", config.OutputPath)
				fmt.Printf("   📊 Verify clearing price: %v coins/unit\n", compositeResult.AuctionExecution.ClearingPrice)
				fmt.Printf("   💰 Verify commission: %v coins\n", compositeResult.AuctionExecution.AuctioneerCommission)
				fmt.Printf("   📈 Verify volume: %d energy units\n", compositeResult.AuctionExecution.TotalEnergyTraded)
			}
		}
	}

	// Create individual output transactions from exchange results
	fmt.Println("  - Creating output transactions...")

	outputTxs := make([]*zerocash.Tx, 0)
	var auctioneerCommission *big.Int = big.NewInt(0)

	if exchangeResult, ok := exchangeTx.(*exchange.ExchangeTransaction); ok {
		// Extract auctioneer commission from the composite result
		if compositeResult, ok := auctionInfo.(struct {
			AuctionResult    *exchange.AuctionResult
			AuctionExecution *exchange.AuctionExecutionResult
		}); ok {
			// Get commission directly from auction execution result
			auctioneerCommission = compositeResult.AuctionExecution.AuctioneerCommission
		}

		// Create participant output transactions
		for i, output := range exchangeResult.Outputs {
			if i < len(state.RegistrationTxs) && output.Coins != nil && output.Energy != nil {
				// Create real output note for participant with proper cryptography
				participantOutputNote := zerocash.NewNote(output.Coins, output.Energy, state.BaseNoteKeys[i])

				// Create output transaction using real cryptographic data
				outputTx := &zerocash.Tx{
					SnOld:     state.RegistrationTxs[i].SnOld,   // Serial number from input note
					CmNew:     string(participantOutputNote.Cm), // Real commitment (not dummy)
					OldCoin:   state.RegistrationTxs[i].OldCoin,
					OldEnergy: state.RegistrationTxs[i].OldEnergy,
					NewCoin:   output.Coins.String(),
					NewEnergy: output.Energy.String(),
					Proof:     exchangeProof, // Same proof for all (batch verification)
				}
				outputTxs = append(outputTxs, outputTx)
			}
		}

		// Create auctioneer commission transaction with proper cryptography

		// Generate auctioneer secret key for notes (32 bytes)
		auctioneerSecretKey := zerocash.RandomBytesPublic(32)

		// Create auctioneer input note (starts with 0 coins, 0 energy)
		auctioneerInputNote := zerocash.NewNote(big.NewInt(0), big.NewInt(0), auctioneerSecretKey)

		// Create auctioneer output note (receives commission)
		auctioneerOutputNote := zerocash.NewNote(auctioneerCommission, big.NewInt(0), auctioneerSecretKey)

		// Compute real serial number from input note (following zerocash protocol)
		auctioneerSerialNumber := zerocash.SerialNumber(auctioneerSecretKey, auctioneerInputNote.Rho)

		auctioneerTx := &zerocash.Tx{
			SnOld:     string(auctioneerSerialNumber),             // Real serial number
			CmNew:     string(auctioneerOutputNote.Cm),            // Real commitment
			OldCoin:   auctioneerInputNote.Value.Coins.String(),   // Real input (0)
			OldEnergy: auctioneerInputNote.Value.Energy.String(),  // Real input (0)
			NewCoin:   auctioneerOutputNote.Value.Coins.String(),  // Real output (commission)
			NewEnergy: auctioneerOutputNote.Value.Energy.String(), // Real output (0)
			Proof:     exchangeProof,                              // Same proof
		}
		outputTxs = append(outputTxs, auctioneerTx)
		fmt.Printf("💰 Created auctioneer commission transaction: %v coins\n", auctioneerCommission)
	}

	// Transition ledger to exchange phase before submitting results
	if err := state.Ledger.StartExchangePhase(); err != nil {
		return fmt.Errorf("failed to start exchange phase: %w", err)
	}

	// Submit exchange results to ledger with individual output transactions
	auctionInfoBytes := []byte(fmt.Sprintf(`{"auction_type":"sealed_bid_double_auction","participants":%d}`, state.Config.NumParticipants))
	err = state.Ledger.SubmitExchange(outputTxs, state.ExchangeProof, auctionInfoBytes)
	if err != nil {
		return fmt.Errorf("failed to submit exchange results: %w", err)
	}

	fmt.Printf("Auction successful: proof generated (%d bytes)\n", len(state.ExchangeProof))
	fmt.Println("Energy market exchange completed")
	return nil
}

// executeFinalizationPhase finalizes the protocol
func executeFinalizationPhase(state *ProtocolState) error {
	fmt.Println("Finalizing ledger state...")

	// Close the auction and merge temporary lists to permanent
	if err := state.Ledger.CloseAuction(); err != nil {
		return fmt.Errorf("failed to close auction: %w", err)
	}

	// Save final ledger state
	if err := state.Ledger.SaveToFile("ledger_final.json"); err != nil {
		fmt.Printf("Warning: Could not save final ledger: %v\n", err)
	}

	fmt.Println("Ledger finalized")
	fmt.Printf("Final state: %d commitments, %d serial numbers, %d transactions\n",
		len(state.Ledger.CmList), len(state.Ledger.SnList), len(state.Ledger.TxList))

	return nil
}

// executeWithdrawalDemo demonstrates emergency withdrawal functionality
func executeWithdrawalDemo(state *ProtocolState) {
	// Check withdrawal mode from configuration
	if state.Config.WithdrawalMode == "none" {
		fmt.Println("WITHDRAWAL PHASE: Skipped (no withdrawals configured)")
		state.WithdrawalAttempts = 0
		return
	}

	fmt.Println("WITHDRAWAL PHASE")
	fmt.Println("=================")

	// Setup withdrawal circuit keys
	withdrawalKeys, err := setupWithdrawalKeys()
	if err != nil {
		fmt.Printf("ERROR: Failed to setup withdrawal keys: %v\n", err)
		return
	}

	// Determine which participants should withdraw
	var participantsToWithdraw []int
	if state.Config.WithdrawAll {
		// All participants withdraw
		participantsToWithdraw = make([]int, state.Config.NumParticipants)
		for i := 0; i < state.Config.NumParticipants; i++ {
			participantsToWithdraw[i] = i
		}
	} else if len(state.Config.WithdrawList) > 0 {
		// Specific participants withdraw
		participantsToWithdraw = state.Config.WithdrawList
	} else {
		// No withdrawals
		fmt.Println("No withdrawals configured")
		state.WithdrawalAttempts = 0
		return
	}

	fmt.Printf("Processing %d withdrawal(s)...\n", len(participantsToWithdraw))
	state.WithdrawalAttempts = len(participantsToWithdraw)

	successCount := 0
	for _, participantID := range participantsToWithdraw {
		if participantID >= state.Config.NumParticipants {
			fmt.Printf("ERROR: Invalid participant ID %d\n", participantID)
			continue
		}

		fmt.Printf("Participant %d: ", participantID+1)

		// Use the note created during registration
		registrationTx := state.RegistrationTxs[participantID]
		noteToWithdraw := registrationTx.NewNote
		skIn := state.ParticipantSkIn[participantID]

		// Create withdrawal note data structures
		inNote := withdraw.Note{
			Coins:  noteToWithdraw.Value.Coins,
			Energy: noteToWithdraw.Value.Energy,
			Pk:     new(big.Int).SetBytes(noteToWithdraw.PkOwner),
			Rho:    new(big.Int).SetBytes(noteToWithdraw.Rho),
			R:      new(big.Int).SetBytes(noteToWithdraw.Rand),
			Cm:     new(big.Int).SetBytes(noteToWithdraw.Cm),
		}

		// Create output note (participant gets their funds back)
		outNote := withdraw.Note{
			Coins:  new(big.Int).Set(noteToWithdraw.Value.Coins),
			Energy: new(big.Int).Set(noteToWithdraw.Value.Energy),
			Pk:     state.ParticipantPkOut[participantID],
			Rho:    new(big.Int).SetBytes(zerocash.RandomBytesPublic(32)),
			R:      new(big.Int).SetBytes(zerocash.RandomBytesPublic(32)),
		}

		// Compute commitment for output note
		outNote.Cm = computeMimcCommitment(outNote.Coins, outNote.Energy, outNote.Pk, outNote.Rho, outNote.R)

		// Create auctioneer public key in correct format
		pkT := sw_bls12377.G1Affine{
			X: state.AuctioneerDHKp.Pk.X.String(),
			Y: state.AuctioneerDHKp.Pk.Y.String(),
		}

		// Use the same ciphertext from registration
		cipherAux := [5]*big.Int{
			state.ParticipantCAux[participantID][0],
			state.ParticipantCAux[participantID][1],
			state.ParticipantCAux[participantID][2],
			state.ParticipantCAux[participantID][3],
			state.ParticipantCAux[participantID][4],
		}

		// Execute withdrawal
		sharedSecretGnark := sw_bls12377.G1Affine{
			X: state.SharedSecrets[participantID].X.String(),
			Y: state.SharedSecrets[participantID].Y.String(),
		}
		withdrawTx, withdrawProof, err := withdraw.Withdraw(
			inNote,
			skIn,
			outNote,
			pkT,
			cipherAux,
			state.OrderPrices[participantID],
			sharedSecretGnark,
			withdrawalKeys.pkWithdraw,
			withdrawalKeys.ccsWithdraw,
		)

		if err != nil {
			fmt.Printf("FAILED: %v\n", err)
			state.WithdrawalResults[participantID] = false
		} else {
			// Verify the withdrawal proof
			err = withdraw.VerifyWithdraw(withdrawTx, withdrawProof, withdrawalKeys.vkWithdraw)
			if err != nil {
				fmt.Printf("VERIFICATION FAILED: %v\n", err)
				state.WithdrawalResults[participantID] = false
			} else {
				fmt.Printf("SUCCESS: Recovered %s coins, %s energy\n",
					outNote.Coins.String(), outNote.Energy.String())
				state.WithdrawalResults[participantID] = true
				successCount++
			}
		}
	}

	fmt.Printf("Withdrawal Summary: %d/%d successful\n", successCount, len(participantsToWithdraw))
}

// Helper functions

func setupCircuitKeys(participantCount int) (*CircuitKeys, error) {
	keys := &CircuitKeys{}
	var err error

	// Initialize dynamic circuit manager
	keys.DynamicManager = exchange.NewCircuitKeyManager()

	// Compile circuits for all 4 algorithms
	var circuitTx zerocash.CircuitTx
	keys.ccsTx, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx)
	if err != nil {
		return nil, err
	}
	keys.pkTx, keys.vkTx, err = groth16.Setup(keys.ccsTx)
	if err != nil {
		return nil, err
	}

	var circuitReg register.CircuitTxRegister
	keys.ccsReg, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitReg)
	if err != nil {
		return nil, err
	}
	keys.pkReg, keys.vkReg, err = groth16.Setup(keys.ccsReg)
	if err != nil {
		return nil, err
	}

	// Compile exchange circuit for actual participant count (supports flexible buyer/seller ratios)
	fmt.Printf("  - Compiling exchange circuit for N=%d (flexible buyer/seller ratios supported)\n", participantCount)

	// Precompile the circuit for the actual participant count
	specificN := []int{participantCount}
	if err := keys.DynamicManager.PrecompileCircuits(specificN); err != nil {
		return nil, fmt.Errorf("failed to precompile circuit for N=%d: %w", participantCount, err)
	}

	return keys, nil
}

func setupWithdrawalKeys() (*CircuitKeys, error) {
	keys := &CircuitKeys{}
	var err error

	var circuitWithdraw withdraw.CircuitWithdraw
	keys.ccsWithdraw, err = frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitWithdraw)
	if err != nil {
		return nil, err
	}
	keys.pkWithdraw, keys.vkWithdraw, err = groth16.Setup(keys.ccsWithdraw)
	if err != nil {
		return nil, err
	}

	return keys, nil
}

// computeMimcCommitment computes a MiMC-based commitment
func computeMimcCommitment(coins, energy, pk, rho, rand *big.Int) *big.Int {
	h := zerocash.NewMiMC()
	h.Write(coins.Bytes())
	h.Write(energy.Bytes())
	h.Write(pk.Bytes())
	h.Write(rho.Bytes())
	h.Write(rand.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil))
}

// printProtocolSummary prints a summary of the protocol execution
func printProtocolSummary(state *ProtocolState, totalTime time.Duration) {
	fmt.Println("\nEXECUTION SUMMARY")
	fmt.Println("=================")
	fmt.Println()

	fmt.Printf("Total execution time: %v\n", totalTime)
	fmt.Printf("Participants: %d\n", state.Config.NumParticipants)
	fmt.Printf("Auctioneer: Configured\n")
	fmt.Println()

	fmt.Println("RESULTS:")
	fmt.Println("--------")

	// Registration Results
	registrationSuccess := 0
	for i := 0; i < state.Config.NumParticipants; i++ {
		if len(state.RegistrationProofs[i]) > 0 {
			registrationSuccess++
		}
	}
	fmt.Printf("Registration: %d/%d successful\n", registrationSuccess, state.Config.NumParticipants)
	fmt.Printf("  ZK proofs generated: %d\n", registrationSuccess)

	// Exchange Results
	exchangeSuccess := 0
	if len(state.ExchangeProof) > 0 {
		exchangeSuccess = 1
	}
	fmt.Printf("Exchange: %d/1 successful\n", exchangeSuccess)
	fmt.Printf("  Proof size: %d bytes\n", len(state.ExchangeProof))

	// Withdrawal Results
	withdrawalSuccess := 0
	for i := 0; i < state.Config.NumParticipants; i++ {
		if state.WithdrawalResults[i] {
			withdrawalSuccess++
		}
	}
	if state.WithdrawalAttempts == 0 {
		fmt.Printf("Withdrawal: skipped (no withdrawals configured)\n")
	} else {
		fmt.Printf("Withdrawal: %d/%d successful\n", withdrawalSuccess, state.WithdrawalAttempts)
	}
	fmt.Println()

	fmt.Printf("Final ledger state:\n")
	fmt.Printf("  Commitments: %d entries\n", len(state.Ledger.CmList))
	fmt.Printf("  Serial Numbers: %d entries\n", len(state.Ledger.SnList))
	fmt.Printf("  Transactions: %d entries\n", len(state.Ledger.TxList))
	fmt.Println()

	fmt.Println("Privacy-Preserving Energy Market Protocol: COMPLETED")
	fmt.Println("====================================================")
	fmt.Println()
}

// Helper functions for auction graph generation

// getBuyerRatio calculates the fraction of participants that are buyers
func getBuyerRatio(roles map[int]zerocash.OrderType) float64 {
	if len(roles) == 0 {
		return 0.0
	}

	buyers := 0
	for _, role := range roles {
		if role == zerocash.BUY {
			buyers++
		}
	}

	return float64(buyers) / float64(len(roles))
}

// countBuyers counts the number of buyers in the roles map
func countBuyers(roles map[int]zerocash.OrderType) int {
	buyers := 0
	for _, role := range roles {
		if role == zerocash.BUY {
			buyers++
		}
	}
	return buyers
}

// countSellers counts the number of sellers in the roles map
func countSellers(roles map[int]zerocash.OrderType) int {
	sellers := 0
	for _, role := range roles {
		if role == zerocash.SELL {
			sellers++
		}
	}
	return sellers
}
