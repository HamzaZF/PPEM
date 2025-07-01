package main

import (
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
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

// =============================================================================
// 1. INFRASTRUCTURE/BUILDING BLOCK TESTS
// =============================================================================

func TestCryptographicPrimitives(t *testing.T) {
	t.Run("MiMC Hash Function", func(t *testing.T) {
		// Test MiMC hash determinism and correctness
		data1 := []byte("test data 1")
		data2 := []byte("test data 2")

		hash1a := zerocash.MimcHashPublic(data1)
		hash1b := zerocash.MimcHashPublic(data1)
		hash2 := zerocash.MimcHashPublic(data2)

		if hash1a.Cmp(hash1b) != 0 {
			t.Error("MiMC hash is not deterministic")
		}
		if hash1a.Cmp(hash2) == 0 {
			t.Error("MiMC hash collision detected")
		}
	})

	t.Run("Diffie-Hellman Key Exchange", func(t *testing.T) {
		// Test DH key generation and shared secret computation
		kp1, err := zerocash.GenerateDHKeyPair()
		if err != nil {
			t.Fatalf("DH key generation failed: %v", err)
		}

		kp2, err := zerocash.GenerateDHKeyPair()
		if err != nil {
			t.Fatalf("DH key generation failed: %v", err)
		}

		// Compute shared secrets
		shared1 := zerocash.ComputeDHShared(kp1.Sk, kp2.Pk)
		shared2 := zerocash.ComputeDHShared(kp2.Sk, kp1.Pk)

		// Shared secrets should be equal
		if !shared1.Equal(shared2) {
			t.Error("DH shared secrets do not match")
		}
	})

	t.Run("Note Creation and Validation", func(t *testing.T) {
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)

		note := zerocash.NewNote(coins, energy, sk)

		// Validate note structure
		if note.Value.Coins.Cmp(coins) != 0 {
			t.Error("Note coins mismatch")
		}
		if note.Value.Energy.Cmp(energy) != 0 {
			t.Error("Note energy mismatch")
		}
		if len(note.PkOwner) == 0 {
			t.Error("Note public key is empty")
		}
		if len(note.Cm) == 0 {
			t.Error("Note commitment is empty")
		}
	})

	t.Run("Commitment Scheme", func(t *testing.T) {
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		rho := big.NewInt(123)
		rand := big.NewInt(456)

		// Test commitment determinism
		pk := zerocash.RandomBytesPublic(32)
		cm1 := zerocash.Commitment(coins, energy, pk, rho, rand)
		cm2 := zerocash.Commitment(coins, energy, pk, rho, rand)

		if new(big.Int).SetBytes(cm1).Cmp(new(big.Int).SetBytes(cm2)) != 0 {
			t.Error("Commitment scheme is not deterministic")
		}

		// Test commitment uniqueness
		cm3 := zerocash.Commitment(big.NewInt(101), energy, pk, rho, rand)
		if new(big.Int).SetBytes(cm1).Cmp(new(big.Int).SetBytes(cm3)) == 0 {
			t.Error("Commitment collision detected")
		}
	})

	t.Run("Serial Number Generation", func(t *testing.T) {
		sk := zerocash.RandomBytesPublic(32)
		rho := zerocash.RandomBytesPublic(32)

		// Test serial number determinism
		sn1 := zerocash.SerialNumber(sk, rho)
		sn2 := zerocash.SerialNumber(sk, rho)

		if new(big.Int).SetBytes(sn1).Cmp(new(big.Int).SetBytes(sn2)) != 0 {
			t.Error("Serial number generation is not deterministic")
		}

		// Test serial number uniqueness
		sn3 := zerocash.SerialNumber(zerocash.RandomBytesPublic(32), rho)
		if new(big.Int).SetBytes(sn1).Cmp(new(big.Int).SetBytes(sn3)) == 0 {
			t.Error("Serial number collision detected")
		}
	})
}

func TestEncryptionDecryption(t *testing.T) {
	t.Run("DH-OTP Encryption", func(t *testing.T) {
		// Test our DH-based encryption used in registration
		kp1, _ := zerocash.GenerateDHKeyPair()
		kp2, _ := zerocash.GenerateDHKeyPair()

		sharedKey := zerocash.ComputeDHShared(kp1.Sk, kp2.Pk)

		// Test data
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		bid := big.NewInt(25)
		skIn := big.NewInt(12345)
		pkOut := big.NewInt(67890)

		// Encrypt using DH-OTP (no additional randomness needed)
		ciphertext := register.EncryptRegistrationData(*sharedKey, coins, energy, bid, skIn, pkOut)

		// Decrypt using the same shared secret
		sharedKey2 := zerocash.ComputeDHShared(kp2.Sk, kp1.Pk)
		decrypted := register.DecryptRegistrationData(ciphertext, *sharedKey2)

		// Verify decryption
		if decrypted[0].Cmp(coins) != 0 {
			t.Error("Coins decryption failed")
		}
		if decrypted[1].Cmp(energy) != 0 {
			t.Error("Energy decryption failed")
		}
		if decrypted[2].Cmp(bid) != 0 {
			t.Error("Bid decryption failed")
		}
	})
}

// =============================================================================
// 2. CIRCUIT-SPECIFIC TESTS
// =============================================================================

func TestCircuitTx(t *testing.T) {
	t.Run("CircuitTx Compilation", func(t *testing.T) {
		var circuit zerocash.CircuitTx
		_, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitTx compilation failed: %v", err)
		}
	})

	t.Run("CircuitTx Key Generation", func(t *testing.T) {
		var circuit zerocash.CircuitTx
		ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitTx compilation failed: %v", err)
		}

		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatalf("CircuitTx key generation failed: %v", err)
		}

		if pk == nil || vk == nil {
			t.Error("Generated keys are nil")
		}
	})
}

func TestCircuitTxRegister(t *testing.T) {
	t.Run("CircuitTxRegister Compilation", func(t *testing.T) {
		var circuit register.CircuitTxRegister
		_, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitTxRegister compilation failed: %v", err)
		}
	})

	t.Run("CircuitTxRegister Key Generation", func(t *testing.T) {
		var circuit register.CircuitTxRegister
		ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitTxRegister compilation failed: %v", err)
		}

		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatalf("CircuitTxRegister key generation failed: %v", err)
		}

		if pk == nil || vk == nil {
			t.Error("Generated keys are nil")
		}
	})
}

func TestCircuitTxF10(t *testing.T) {
	t.Run("CircuitTxF10 Compilation", func(t *testing.T) {
		var circuit exchange.CircuitTxF10
		_, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitTxF10 compilation failed: %v", err)
		}
	})

	t.Run("CircuitTxF10 Key Generation", func(t *testing.T) {
		var circuit exchange.CircuitTxF10
		ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitTxF10 compilation failed: %v", err)
		}

		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatalf("CircuitTxF10 key generation failed: %v", err)
		}

		if pk == nil || vk == nil {
			t.Error("Generated keys are nil")
		}
	})
}

func TestCircuitWithdraw(t *testing.T) {
	t.Run("CircuitWithdraw Compilation", func(t *testing.T) {
		var circuit withdraw.CircuitWithdraw
		_, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitWithdraw compilation failed: %v", err)
		}
	})

	t.Run("CircuitWithdraw Key Generation", func(t *testing.T) {
		var circuit withdraw.CircuitWithdraw
		ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatalf("CircuitWithdraw compilation failed: %v", err)
		}

		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			t.Fatalf("CircuitWithdraw key generation failed: %v", err)
		}

		if pk == nil || vk == nil {
			t.Error("Generated keys are nil")
		}
	})
}

// =============================================================================
// 3. INDIVIDUAL ALGORITHM TESTS
// =============================================================================

func TestAlgorithm1Transaction(t *testing.T) {
	// Setup circuit keys
	var circuit zerocash.CircuitTx
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatalf("Circuit compilation failed: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("Key generation failed: %v", err)
	}

	t.Run("Valid Transaction Creation", func(t *testing.T) {
		// Create a note
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)

		// Create transaction
		newSk := zerocash.RandomBytesPublic(32)
		pkNew := zerocash.MimcHashPublic(newSk).Bytes() // Compute pk from sk as per Algorithm 1
		params := &zerocash.Params{}

		tx, err := zerocash.CreateTx(note, sk, pkNew, coins, energy, params, ccs, pk)
		if err != nil {
			t.Fatalf("Transaction creation failed: %v", err)
		}

		// Verify transaction
		err = zerocash.VerifyTx(tx, params, vk)
		if err != nil {
			t.Fatalf("Transaction verification failed: %v", err)
		}
	})

	t.Run("Invalid Transaction Rejection", func(t *testing.T) {
		// Create a note
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)

		// Try to create transaction with wrong secret key
		wrongSk := zerocash.RandomBytesPublic(32)
		newSk := zerocash.RandomBytesPublic(32)
		pkNew := zerocash.MimcHashPublic(newSk).Bytes()
		params := &zerocash.Params{}

		_, err := zerocash.CreateTx(note, wrongSk, pkNew, coins, energy, params, ccs, pk)
		if err == nil {
			t.Error("Transaction with wrong secret key should have failed")
		}
	})

	t.Run("Double Spending Prevention", func(t *testing.T) {
		// Create a note
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)

		// Create first transaction
		newSk1 := zerocash.RandomBytesPublic(32)
		pkNew1 := zerocash.MimcHashPublic(newSk1).Bytes()
		params := &zerocash.Params{}

		tx1, err := zerocash.CreateTx(note, sk, pkNew1, coins, energy, params, ccs, pk)
		if err != nil {
			t.Fatalf("First transaction creation failed: %v", err)
		}

		// Create second transaction with same note (double spending)
		newSk2 := zerocash.RandomBytesPublic(32)
		pkNew2 := zerocash.MimcHashPublic(newSk2).Bytes()
		tx2, err := zerocash.CreateTx(note, sk, pkNew2, coins, energy, params, ccs, pk)
		if err != nil {
			t.Fatalf("Second transaction creation failed: %v", err)
		}

		// Both transactions should have the same serial number (detecting double spend)
		if tx1.SnOld != tx2.SnOld {
			t.Error("Double spending not detected - serial numbers differ")
		}
	})
}

func TestAlgorithm2Register(t *testing.T) {
	// Setup circuit keys
	var circuitTx zerocash.CircuitTx
	ccsTx, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitTx)
	pkTx, vkTx, _ := groth16.Setup(ccsTx)

	var circuitReg register.CircuitTxRegister
	ccsReg, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitReg)
	pkReg, _, _ := groth16.Setup(ccsReg)

	t.Run("Valid Registration", func(t *testing.T) {
		// Create participant and auctioneer
		auctioneerKp, _ := zerocash.GenerateDHKeyPair()
		participantKp, _ := zerocash.GenerateDHKeyPair()

		params := &zerocash.Params{}
		participant := &zerocash.Participant{
			Name:          "TestParticipant",
			Sk:            participantKp.Sk,
			Pk:            participantKp.Pk,
			Params:        params,
			AuctioneerPub: auctioneerKp.Pk,
		}

		// Create a note
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)
		bid := big.NewInt(25)

		// Execute registration
		result, err := register.Register(participant, note, bid, pkTx, ccsTx, pkReg, ccsReg, sk)
		if err != nil {
			t.Fatalf("Registration failed: %v", err)
		}

		// Validate result structure
		if len(result.CAux) != 5 {
			t.Error("CAux should have 5 elements")
		}
		if result.TxIn == nil {
			t.Error("TxIn is nil")
		}
		if len(result.InfoBid) == 0 {
			t.Error("InfoBid is empty")
		}
		if len(result.Proof) == 0 {
			t.Error("Proof is empty")
		}

		// Verify the transaction proof
		err = zerocash.VerifyTx(result.TxIn, params, vkTx)
		if err != nil {
			t.Fatalf("Transaction verification failed: %v", err)
		}

		// Verify the registration proof (simplified check)
		if len(result.Proof) == 0 {
			t.Error("Registration proof is empty")
		}
	})

	t.Run("Registration with Invalid Participant", func(t *testing.T) {
		// Create participant without auctioneer public key
		participantKp, _ := zerocash.GenerateDHKeyPair()
		params := &zerocash.Params{}
		participant := &zerocash.Participant{
			Name:          "TestParticipant",
			Sk:            participantKp.Sk,
			Pk:            participantKp.Pk,
			Params:        params,
			AuctioneerPub: nil, // Missing auctioneer public key
		}

		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)
		bid := big.NewInt(25)

		// Registration should fail
		_, err := register.Register(participant, note, bid, pkTx, ccsTx, pkReg, ccsReg, sk)
		if err == nil {
			t.Error("Registration should fail with missing auctioneer public key")
		}
	})
}

func TestAlgorithm3Exchange(t *testing.T) {
	// Setup circuit keys
	var circuitF10 exchange.CircuitTxF10
	ccsF10, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitF10)
	pkF10, _, _ := groth16.Setup(ccsF10)

	t.Run("Valid Exchange with Multiple Participants", func(t *testing.T) {
		// Create auctioneer
		auctioneerKp, _ := zerocash.GenerateDHKeyPair()

		// Create registration payloads for 3 participants
		regPayloads := make([]exchange.RegistrationPayload, 3)
		for i := 0; i < 3; i++ {
			participantKp, _ := zerocash.GenerateDHKeyPair()

			// Create encrypted registration data
			coins := big.NewInt(int64(100 + i*10))
			energy := big.NewInt(int64(50 + i*5))
			bid := big.NewInt(int64(25 + i*2))
			skIn := big.NewInt(int64(12345 + i))
			pkOut := big.NewInt(int64(67890 + i))

			sharedKey := zerocash.ComputeDHShared(participantKp.Sk, auctioneerKp.Pk)
			ciphertext := register.EncryptRegistrationData(*sharedKey, coins, energy, bid, skIn, pkOut)

			regPayloads[i] = exchange.RegistrationPayload{
				Ciphertext: ciphertext,
				PubKey:     convertToGnarkPoint(participantKp.Pk),
			}
		}

		// Create ledger and params
		ledger := zerocash.NewLedger()
		params := &zerocash.Params{}

		// Execute exchange
		txOut, info, proof, err := exchange.ExchangePhase(regPayloads, auctioneerKp.Sk.BigInt(new(big.Int)), ledger, params, pkF10, ccsF10)
		if err != nil {
			t.Fatalf("Exchange failed: %v", err)
		}

		// Validate results
		if txOut == nil {
			t.Error("txOut is nil")
		}
		if info == nil {
			t.Error("info is nil")
		}
		if len(proof) == 0 {
			t.Error("proof is empty")
		}
	})

	t.Run("Exchange with Invalid Payloads", func(t *testing.T) {
		// Test with empty payloads
		var regPayloads []exchange.RegistrationPayload

		auctioneerKp, _ := zerocash.GenerateDHKeyPair()
		ledger := zerocash.NewLedger()
		params := &zerocash.Params{}

		_, _, _, err := exchange.ExchangePhase(regPayloads, auctioneerKp.Sk.BigInt(new(big.Int)), ledger, params, pkF10, ccsF10)
		if err == nil {
			t.Error("Exchange should fail with empty payloads")
		}
	})
}

func TestAlgorithm4Withdraw(t *testing.T) {
	// Setup circuit keys
	var circuitWithdraw withdraw.CircuitWithdraw
	ccsWithdraw, _ := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuitWithdraw)
	pkWithdraw, vkWithdraw, _ := groth16.Setup(ccsWithdraw)

	t.Run("Valid Withdrawal", func(t *testing.T) {
		// Create input note
		nIn := withdraw.Note{
			Coins:  big.NewInt(100),
			Energy: big.NewInt(50),
			Pk:     big.NewInt(12345),
			Rho:    big.NewInt(111),
			R:      big.NewInt(222),
			Cm:     big.NewInt(333),
		}

		// Create output note
		nOut := withdraw.Note{
			Coins:  big.NewInt(90), // Reduced by fee
			Energy: big.NewInt(45), // Reduced by fee
			Pk:     big.NewInt(54321),
			Rho:    big.NewInt(444),
			R:      big.NewInt(555),
			Cm:     big.NewInt(666),
		}

		skIn := big.NewInt(12345)
		rEnc := big.NewInt(789)

		// Create participant's public key
		participantKp, _ := zerocash.GenerateDHKeyPair()
		pkT := sw_bls12377.G1Affine{
			X: participantKp.Pk.X.String(),
			Y: participantKp.Pk.Y.String(),
		}

		// Create cipher aux
		var cipherAux [3]*big.Int
		for i := 0; i < 3; i++ {
			cipherAux[i] = big.NewInt(int64(1000 + i))
		}

		// Execute withdrawal
		tx, proof, err := withdraw.Withdraw(nIn, skIn, rEnc, nOut, pkT, cipherAux, pkWithdraw, ccsWithdraw)
		if err != nil {
			t.Fatalf("Withdrawal failed: %v", err)
		}

		// Validate results
		if tx == nil {
			t.Error("tx is nil")
		}
		if len(proof) == 0 {
			t.Error("proof is empty")
		}

		// Verify withdrawal proof
		err = withdraw.VerifyWithdraw(tx, proof, vkWithdraw)
		if err != nil {
			t.Fatalf("Withdrawal verification failed: %v", err)
		}
	})
}

// =============================================================================
// 4. INTEGRATION/PROTOCOL TESTS
// =============================================================================

func TestFullProtocolFlow(t *testing.T) {
	t.Run("Complete Protocol N=3", func(t *testing.T) {
		startTime := time.Now()

		// Setup all circuit keys
		setupKeys := setupAllCircuitKeys(t)

		// Create auctioneer
		auctioneerKp, _ := zerocash.GenerateDHKeyPair()
		params := &zerocash.Params{}
		auctioneer := &zerocash.Participant{
			Name:   "Auctioneer",
			Sk:     auctioneerKp.Sk,
			Pk:     auctioneerKp.Pk,
			Params: params,
			Role:   zerocash.RoleAuctioneer,
		}

		// Create 3 participants
		N := 3
		participants := make([]*zerocash.Participant, N)
		notes := make([]*zerocash.Note, N)
		bids := make([]*big.Int, N)

		for i := 0; i < N; i++ {
			participantKp, _ := zerocash.GenerateDHKeyPair()
			participants[i] = &zerocash.Participant{
				Name:          "Participant" + string(rune(i+1)),
				Sk:            participantKp.Sk,
				Pk:            participantKp.Pk,
				Params:        params,
				Role:          zerocash.RoleParticipant,
				AuctioneerPub: auctioneer.Pk,
			}

			// Create participant's note
			coins := big.NewInt(int64(100 + i*10))
			energy := big.NewInt(int64(50 + i*5))
			sk := zerocash.RandomBytesPublic(32)
			notes[i] = zerocash.NewNote(coins, energy, sk)
			bids[i] = big.NewInt(int64(25 + i*2))
		}

		// Phase 1: Registration
		t.Logf("Starting registration phase...")
		regPayloads := make([]exchange.RegistrationPayload, N)

		for i := 0; i < N; i++ {
			noteSecretKey := zerocash.RandomBytesPublic(32)
			result, err := register.Register(participants[i], notes[i], bids[i],
				setupKeys.pkTx, setupKeys.ccsTx, setupKeys.pkReg, setupKeys.ccsReg, noteSecretKey)
			if err != nil {
				t.Fatalf("Registration failed for participant %d: %v", i, err)
			}

			regPayloads[i] = exchange.RegistrationPayload{
				Ciphertext: result.CAux,
				PubKey:     convertToGnarkPoint(participants[i].Pk),
			}
		}

		// Phase 2: Exchange
		t.Logf("Starting exchange phase...")
		ledger := zerocash.NewLedger()
		txOut, info, proof, err := exchange.ExchangePhase(regPayloads, auctioneer.Sk.BigInt(new(big.Int)),
			ledger, params, setupKeys.pkF10, setupKeys.ccsF10)
		if err != nil {
			t.Fatalf("Exchange phase failed: %v", err)
		}

		// Phase 3: Receiving (simplified)
		t.Logf("Starting receiving phase...")
		if txOut != nil && info != nil && len(proof) > 0 {
			t.Logf("Exchange successful - participants can claim outputs")
		} else {
			t.Logf("Exchange failed - participants should withdraw")
		}

		totalTime := time.Since(startTime)
		t.Logf("Complete protocol completed in %v", totalTime)

		// Validate final state
		if len(proof) == 0 {
			t.Error("Final proof is empty")
		}
	})
}

func TestPrivacyProperties(t *testing.T) {
	t.Run("Bidder Anonymity", func(t *testing.T) {
		// Test that bidder identities are hidden
		// This involves testing that registration payloads don't reveal participant identity

		auctioneerKp, _ := zerocash.GenerateDHKeyPair()
		participant1Kp, _ := zerocash.GenerateDHKeyPair()
		participant2Kp, _ := zerocash.GenerateDHKeyPair()

		// Create identical bids from different participants
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		bid := big.NewInt(25)
		skIn := big.NewInt(12345)
		pkOut := big.NewInt(67890)

		// Encrypt for both participants using DH-OTP
		shared1 := zerocash.ComputeDHShared(participant1Kp.Sk, auctioneerKp.Pk)
		shared2 := zerocash.ComputeDHShared(participant2Kp.Sk, auctioneerKp.Pk)

		cipher1 := register.EncryptRegistrationData(*shared1, coins, energy, bid, skIn, pkOut)
		cipher2 := register.EncryptRegistrationData(*shared2, coins, energy, bid, skIn, pkOut)

		// Ciphertexts should be different even with same inputs (privacy)
		if cipher1[0].Cmp(cipher2[0]) == 0 && cipher1[1].Cmp(cipher2[1]) == 0 {
			t.Error("Ciphertexts are identical - privacy violation")
		}
	})

	t.Run("Bid Confidentiality", func(t *testing.T) {
		// Test that bid amounts are hidden in ciphertexts
		auctioneerKp, _ := zerocash.GenerateDHKeyPair()
		participantKp, _ := zerocash.GenerateDHKeyPair()

		coins := big.NewInt(100)
		energy := big.NewInt(50)
		bid1 := big.NewInt(25)
		bid2 := big.NewInt(50) // Different bid
		skIn := big.NewInt(12345)
		pkOut := big.NewInt(67890)

		shared := zerocash.ComputeDHShared(participantKp.Sk, auctioneerKp.Pk)

		cipher1 := register.EncryptRegistrationData(*shared, coins, energy, bid1, skIn, pkOut)
		cipher2 := register.EncryptRegistrationData(*shared, coins, energy, bid2, skIn, pkOut)

		// Bid field (index 2) should be different when encrypted
		if cipher1[2].Cmp(cipher2[2]) == 0 {
			t.Error("Same ciphertext for different bids - confidentiality violation")
		}
	})
}

func TestSecurityProperties(t *testing.T) {
	t.Run("Double Spending Prevention", func(t *testing.T) {
		// This is already tested in Algorithm 1 tests, but we test at protocol level
		ledger := zerocash.NewLedger()

		// Create a note
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)

		// Create two transactions with the same note
		setupKeys := setupAllCircuitKeys(t)
		params := &zerocash.Params{}

		newSk1 := zerocash.RandomBytesPublic(32)
		pkNew1 := zerocash.MimcHashPublic(newSk1).Bytes()
		tx1, err := zerocash.CreateTx(note, sk, pkNew1, coins, energy, params, setupKeys.ccsTx, setupKeys.pkTx)
		if err != nil {
			t.Fatalf("First transaction creation failed: %v", err)
		}

		newSk2 := zerocash.RandomBytesPublic(32)
		pkNew2 := zerocash.MimcHashPublic(newSk2).Bytes()
		tx2, err := zerocash.CreateTx(note, sk, pkNew2, coins, energy, params, setupKeys.ccsTx, setupKeys.pkTx)
		if err != nil {
			t.Fatalf("Second transaction creation failed: %v", err)
		}

		// Add first transaction to ledger
		err = ledger.AppendTx(tx1)
		if err != nil {
			t.Fatalf("First transaction append failed: %v", err)
		}

		// Try to add second transaction (should detect double spend)
		err = ledger.AppendTx(tx2)
		if err == nil {
			t.Error("Double spending not detected by ledger")
		}
	})

	t.Run("Transaction Integrity", func(t *testing.T) {
		// Test that tampered transactions are rejected
		setupKeys := setupAllCircuitKeys(t)

		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)
		params := &zerocash.Params{}

		newSk := zerocash.RandomBytesPublic(32)
		pkNew := zerocash.MimcHashPublic(newSk).Bytes()
		tx, err := zerocash.CreateTx(note, sk, pkNew, coins, energy, params, setupKeys.ccsTx, setupKeys.pkTx)
		if err != nil {
			t.Fatalf("Transaction creation failed: %v", err)
		}

		// Tamper with the transaction
		originalCoin := tx.NewCoin
		tx.NewCoin = "999999" // Tamper with coin amount

		// Verification should fail
		err = zerocash.VerifyTx(tx, params, setupKeys.vkTx)
		if err == nil {
			t.Error("Tampered transaction should fail verification")
		}

		// Restore original value
		tx.NewCoin = originalCoin

		// Verification should now pass
		err = zerocash.VerifyTx(tx, params, setupKeys.vkTx)
		if err != nil {
			t.Fatalf("Original transaction verification failed: %v", err)
		}
	})
}

func TestPerformanceBenchmarks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance benchmarks in short mode")
	}

	setupKeys := setupAllCircuitKeys(t)

	t.Run("Benchmark Transaction Creation", func(t *testing.T) {
		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)
		params := &zerocash.Params{}

		start := time.Now()
		numTests := 10

		for i := 0; i < numTests; i++ {
			newSk := zerocash.RandomBytesPublic(32)
			pkNew := zerocash.MimcHashPublic(newSk).Bytes()
			_, err := zerocash.CreateTx(note, sk, pkNew, coins, energy, params, setupKeys.ccsTx, setupKeys.pkTx)
			if err != nil {
				t.Fatalf("Transaction %d failed: %v", i, err)
			}
		}

		avgTime := time.Since(start) / time.Duration(numTests)
		t.Logf("Average transaction creation time: %v", avgTime)
	})

	t.Run("Benchmark Registration", func(t *testing.T) {
		auctioneerKp, _ := zerocash.GenerateDHKeyPair()
		participantKp, _ := zerocash.GenerateDHKeyPair()

		params := &zerocash.Params{}
		participant := &zerocash.Participant{
			Sk:            participantKp.Sk,
			Pk:            participantKp.Pk,
			Params:        params,
			AuctioneerPub: auctioneerKp.Pk,
		}

		coins := big.NewInt(100)
		energy := big.NewInt(50)
		sk := zerocash.RandomBytesPublic(32)
		note := zerocash.NewNote(coins, energy, sk)
		bid := big.NewInt(25)

		start := time.Now()
		numTests := 5 // Fewer tests as registration is more expensive

		for i := 0; i < numTests; i++ {
			_, err := register.Register(participant, note, bid, setupKeys.pkTx, setupKeys.ccsTx, setupKeys.pkReg, setupKeys.ccsReg, sk)
			if err != nil {
				t.Fatalf("Registration %d failed: %v", i, err)
			}
		}

		avgTime := time.Since(start) / time.Duration(numTests)
		t.Logf("Average registration time: %v", avgTime)
	})
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

type CircuitKeys struct {
	pkTx   groth16.ProvingKey
	vkTx   groth16.VerifyingKey
	ccsTx  constraint.ConstraintSystem
	pkReg  groth16.ProvingKey
	vkReg  groth16.VerifyingKey
	ccsReg constraint.ConstraintSystem
	pkF10  groth16.ProvingKey
	vkF10  groth16.VerifyingKey
	ccsF10 constraint.ConstraintSystem
}

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

	return &CircuitKeys{
		pkTx:   pkTx,
		vkTx:   vkTx,
		ccsTx:  ccsTx,
		pkReg:  pkReg,
		vkReg:  vkReg,
		ccsReg: ccsReg,
		pkF10:  pkF10,
		vkF10:  vkF10,
		ccsF10: ccsF10,
	}
}

func convertToGnarkPoint(p *bls12377.G1Affine) *sw_bls12377.G1Affine {
	return &sw_bls12377.G1Affine{
		X: p.X.String(),
		Y: p.Y.String(),
	}
}
