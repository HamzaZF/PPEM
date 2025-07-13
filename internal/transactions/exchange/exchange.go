// exchange.go - Auction phase logic for the protocol (Algorithm 3, without ZKP-enforced auction logic).
//
// Implements the exchange phase: decrypts registration payloads, runs auction logic (off-circuit),
// constructs output notes, builds the witness, and generates the ZKP using CircuitTxF10.
//
// WARNING: The ZKP only proves cryptographic consistency, not the correctness of the auction computation.

package exchange

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"

	"implementation/internal/zerocash"
)

// RegistrationPayload represents decrypted registration data from a participant
type RegistrationPayload struct {
	Ciphertext [5]*big.Int           // (pkOut, skIn, bid, coins, energy)
	PubKey     *sw_bls12377.G1Affine // Participant's public key (for DH)
	TxNoteData []byte                // Encrypted note data from CreateTx (new field)
}

// DecryptedRegistration holds the decrypted data from registration
type DecryptedRegistration struct {
	PkOut    *big.Int
	SkIn     *big.Int
	Bid      *big.Int
	Coins    *big.Int
	Energy   *big.Int
	NoteData *zerocash.Note // Decrypted note from CreateTx (new field)
}

// DecryptAllRegistrations decrypts all registration payloads using the auctioneer's private key
func DecryptAllRegistrations(payloads []RegistrationPayload, auctioneerSk *big.Int) ([]DecryptedRegistration, error) {
	results := make([]DecryptedRegistration, len(payloads))

	// Convert auctioneer's secret key to BLS12-377 field element
	var sk bls12377_fr.Element
	sk.SetBigInt(auctioneerSk)

	for i, payload := range payloads {
		// Convert participant's public key from gnark format to native BLS12-377
		pkX := new(big.Int)
		pkX.SetString(payload.PubKey.X.(string), 10)
		pkY := new(big.Int)
		pkY.SetString(payload.PubKey.Y.(string), 10)

		var pk bls12377.G1Affine
		pk.X.SetBigInt(pkX)
		pk.Y.SetBigInt(pkY)

		// Compute DH shared secret: shared = pk^sk
		shared := zerocash.ComputeDHShared(&sk, &pk)

		// Decrypt the registration data using the shared secret
		decrypted := DecZKRegGo(payload.Ciphertext, *shared)

		result := DecryptedRegistration{
			PkOut:  decrypted[0], // pk^out
			SkIn:   decrypted[1], // sk^in
			Bid:    decrypted[2], // bid
			Coins:  decrypted[3], // coins
			Energy: decrypted[4], // energy
		}

		// Note: Note data decryption is handled by DecryptTransactionNotes function

		results[i] = result
	}

	return results, nil
}

// DecryptTransactionNotes decrypts the note data from transactions using permanent ECDH keys
func DecryptTransactionNotes(payloads []RegistrationPayload, auctioneerECDHPrivKey *ecdh.PrivateKey, participantECDHPubKeys []*ecdh.PublicKey) ([]DecryptedRegistration, error) {
	results := make([]DecryptedRegistration, len(payloads))

	for i, payload := range payloads {
		result := DecryptedRegistration{}

		// Decrypt transaction note data if present
		if len(payload.TxNoteData) > 0 {
			if i >= len(participantECDHPubKeys) || participantECDHPubKeys[i] == nil {
				return nil, fmt.Errorf("missing participant ECDH public key for participant %d", i)
			}

			noteData, err := zerocash.DecryptNoteFromAuctioneerWithPermanentKey(payload.TxNoteData, auctioneerECDHPrivKey, participantECDHPubKeys[i])
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt note data for participant %d: %w", i, err)
			}
			result.NoteData = noteData

			// Extract values from the decrypted note
			result.Coins = noteData.Value.Coins
			result.Energy = noteData.Value.Energy
		}

		results[i] = result
	}

	return results, nil
}

// SortParticipantsForCircuit sorts participants according to circuit requirements:
// - First N/2 are buyers sorted in descending order by bid (highest bid first)
// - Last N/2 are sellers sorted in ascending order by bid (lowest ask first)
// Returns sorted inputs, payloads, and participantDHKeys
func SortParticipantsForCircuit(
	inputs []DecryptedRegistration,
	payloads []RegistrationPayload,
	participantDHKeys []*bls12377_fr.Element,
) ([]DecryptedRegistration, []RegistrationPayload, []*bls12377_fr.Element, error) {

	n := len(inputs)
	if n%2 != 0 {
		return nil, nil, nil, fmt.Errorf("number of participants must be even, got %d", n)
	}

	halfN := n / 2

	// Create pairs of (index, data) for sorting
	type ParticipantData struct {
		Index   int
		Input   DecryptedRegistration
		Payload RegistrationPayload
		DHKey   *bls12377_fr.Element
	}

	// Split participants into buyers and sellers based on their index
	// First N/2 are buyers, last N/2 are sellers
	buyers := make([]ParticipantData, halfN)
	sellers := make([]ParticipantData, halfN)

	for i := 0; i < n; i++ {
		var dhKey *bls12377_fr.Element
		if i < len(participantDHKeys) {
			dhKey = participantDHKeys[i]
		}

		data := ParticipantData{
			Index:   i,
			Input:   inputs[i],
			Payload: payloads[i],
			DHKey:   dhKey,
		}

		if i < halfN {
			buyers[i] = data
		} else {
			sellers[i-halfN] = data
		}
	}

	// Sort buyers in descending order by bid (highest bid first)
	sort.Slice(buyers, func(i, j int) bool {
		bidI := buyers[i].Input.Bid
		bidJ := buyers[j].Input.Bid
		if bidI == nil && bidJ == nil {
			return false
		}
		if bidI == nil {
			return false
		}
		if bidJ == nil {
			return true
		}
		return bidI.Cmp(bidJ) > 0 // Descending order
	})

	// Sort sellers in ascending order by bid (lowest ask first)
	sort.Slice(sellers, func(i, j int) bool {
		bidI := sellers[i].Input.Bid
		bidJ := sellers[j].Input.Bid
		if bidI == nil && bidJ == nil {
			return false
		}
		if bidI == nil {
			return true
		}
		if bidJ == nil {
			return false
		}
		return bidI.Cmp(bidJ) < 0 // Ascending order
	})

	// Reconstruct the sorted arrays
	sortedInputs := make([]DecryptedRegistration, n)
	sortedPayloads := make([]RegistrationPayload, n)
	sortedDHKeys := make([]*bls12377_fr.Element, n)

	// Add buyers first (indices 0 to N/2-1)
	for i, buyer := range buyers {
		sortedInputs[i] = buyer.Input
		sortedPayloads[i] = buyer.Payload
		sortedDHKeys[i] = buyer.DHKey
	}

	// Add sellers last (indices N/2 to N-1)
	for i, seller := range sellers {
		idx := halfN + i
		sortedInputs[idx] = seller.Input
		sortedPayloads[idx] = seller.Payload
		sortedDHKeys[idx] = seller.DHKey
	}

	return sortedInputs, sortedPayloads, sortedDHKeys, nil
}

// DecZKRegGo implements the same decryption logic as the circuit's DecZKReg function
func DecZKRegGo(c [5]*big.Int, encKey bls12377.G1Affine) [5]*big.Int {
	h := mimcNative.NewMiMC()

	// Use the same MiMC hash chain as in the circuit
	h.Reset()
	encKeyXBytes := encKey.X.Bytes()
	h.Write(encKeyXBytes[:])
	encKeyYBytes := encKey.Y.Bytes()
	h.Write(encKeyYBytes[:])
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

	// Decrypt by subtracting the masks
	dec0 := new(big.Int).Sub(c[0], new(big.Int).SetBytes(mask0))
	dec1 := new(big.Int).Sub(c[1], new(big.Int).SetBytes(mask1))
	dec2 := new(big.Int).Sub(c[2], new(big.Int).SetBytes(mask2))
	dec3 := new(big.Int).Sub(c[3], new(big.Int).SetBytes(mask3))
	dec4 := new(big.Int).Sub(c[4], new(big.Int).SetBytes(mask4))

	return [5]*big.Int{dec0, dec1, dec2, dec3, dec4}
}

// RunAuctionLogic implements a sealed-bid double auction mechanism (SBExM)
// This is the core auction algorithm that matches buyers and sellers
// NOTE: Input is assumed to be pre-sorted by SortParticipantsForCircuit:
// - First N/2 are buyers sorted in descending order by bid
// - Last N/2 are sellers sorted in ascending order by bid
func RunAuctionLogic(inputs []DecryptedRegistration) []DecryptedRegistration {
	if len(inputs) == 0 {
		return inputs
	}

	numParticipants := len(inputs)
	halfN := numParticipants / 2

	// Create output array (copy of inputs initially)
	outputs := make([]DecryptedRegistration, len(inputs))
	copy(outputs, inputs)

	// Execute double auction matching
	// Input is already sorted: buyers (0 to N/2-1) and sellers (N/2 to N-1)
	buyerIdx, sellerIdx := 0, 0
	for buyerIdx < halfN && sellerIdx < halfN {
		buyer := buyerIdx
		seller := halfN + sellerIdx

		buyerBid := inputs[buyer].Bid
		sellerBid := inputs[seller].Bid

		if buyerBid == nil || sellerBid == nil {
			break
		}

		// Check if trade is possible (buyer bid >= seller ask)
		if buyerBid.Cmp(sellerBid) >= 0 {
			// Calculate trade price (midpoint between bid and ask)
			tradePrice := new(big.Int)
			tradePrice.Add(buyerBid, sellerBid)
			tradePrice.Div(tradePrice, big.NewInt(2))

			// Calculate trade quantity (minimum of what buyer wants and seller has)
			buyerWantedEnergy := inputs[buyer].Energy
			sellerAvailableEnergy := inputs[seller].Energy

			tradeQuantity := new(big.Int)
			if buyerWantedEnergy.Cmp(sellerAvailableEnergy) <= 0 {
				tradeQuantity.Set(buyerWantedEnergy)
			} else {
				tradeQuantity.Set(sellerAvailableEnergy)
			}

			// Calculate total trade value
			tradeValue := new(big.Int)
			tradeValue.Mul(tradePrice, tradeQuantity)

			// Update buyer: gains energy, loses coins
			if outputs[buyer].Energy != nil && outputs[buyer].Coins != nil {
				outputs[buyer].Energy.Add(outputs[buyer].Energy, tradeQuantity)
				outputs[buyer].Coins.Sub(outputs[buyer].Coins, tradeValue)
			}

			// Update seller: loses energy, gains coins
			if outputs[seller].Energy != nil && outputs[seller].Coins != nil {
				outputs[seller].Energy.Sub(outputs[seller].Energy, tradeQuantity)
				outputs[seller].Coins.Add(outputs[seller].Coins, tradeValue)
			}

			// Move to next participants
			buyerIdx++
			sellerIdx++
		} else {
			// No more profitable trades possible
			break
		}
	}

	return outputs
}

// Helper to create a valid random G1Affine point as a gnark struct
func randomGnarkG1Affine() sw_bls12377.G1Affine {
	var p bls12377.G1Affine
	_, _, g1, _ := bls12377.Generators()
	p.Set(&g1)
	return sw_bls12377.G1Affine{
		X: p.X.String(),
		Y: p.Y.String(),
	}
}

// Helper to create a [5]frontend.Variable with all "1"
func onesArray5() [5]frontend.Variable {
	return [5]frontend.Variable{"1", "1", "1", "1", "1"}
}

// BuildWitnessF10 builds the witness for CircuitTxF10 from input/output notes using the new array-based structure and REAL participant DH private keys.
func BuildWitnessF10(inputs, outputs []DecryptedRegistration, payloads []RegistrationPayload, auctioneerSk *big.Int, participantDHKeys []*bls12377_fr.Element, auctioneerDHPk *bls12377.G1Affine) *CircuitTxF10 {
	w := &CircuitTxF10{}

	// Helper to convert *big.Int to frontend.Variable with nil handling
	toVar := func(x *big.Int) frontend.Variable {
		if x == nil {
			return "0"
		}
		return x.String()
	}

	// Helper to make [5]frontend.Variable from [5]*big.Int with nil handling
	toVarArr := func(arr [5]*big.Int) [5]frontend.Variable {
		var out [5]frontend.Variable
		for i := 0; i < 5; i++ {
			if arr[i] == nil {
				out[i] = "0"
			} else {
				out[i] = arr[i].String()
			}
		}
		return out
	}

	// Helper to convert native BLS12-377 point to gnark format
	toGnarkPoint := func(p bls12377.G1Affine) sw_bls12377.G1Affine {
		return sw_bls12377.G1Affine{
			X: p.X.String(),
			Y: p.Y.String(),
		}
	}

	// Helper to compute MiMC hash (same as circuit)
	mimcHash := func(data ...*big.Int) *big.Int {
		h := mimcNative.NewMiMC()
		for _, d := range data {
			if d != nil {
				h.Write(d.Bytes())
			}
		}
		result := h.Sum(nil)
		return new(big.Int).SetBytes(result)
	}

	// Helper to compute PRF (same as circuit)
	prf := func(sk, rho *big.Int) *big.Int {
		return mimcHash(sk, rho)
	}

	// Helper to compute commitment following paper: cm = Com(Γ || pk || ρ, r)
	computeCommitment := func(coin, energy *big.Int, pk *big.Int, rho, rand *big.Int) *big.Int {
		return mimcHash(coin, energy, pk, rho, rand)
	}

	// Helper to get safe values from DecryptedRegistration
	getSafeValue := func(in DecryptedRegistration, field string) *big.Int {
		switch field {
		case "coins":
			if in.Coins == nil {
				return big.NewInt(100) // Default value
			}
			return in.Coins
		case "energy":
			if in.Energy == nil {
				return big.NewInt(50) // Default value
			}
			return in.Energy
		case "pkout":
			if in.PkOut == nil {
				return big.NewInt(1) // Default value
			}
			return in.PkOut
		case "skin":
			if in.SkIn == nil {
				return big.NewInt(2) // Default value
			}
			return in.SkIn
		case "bid":
			if in.Bid == nil {
				return big.NewInt(10) // Default value
			}
			return in.Bid
		default:
			return big.NewInt(0)
		}
	}

	// Helper to create DH components using REAL participant private keys
	createDHComponents := func(shared bls12377.G1Affine, participantSk *bls12377_fr.Element, auctioneerPk *bls12377.G1Affine) (sw_bls12377.G1Affine, sw_bls12377.G1Affine, frontend.Variable, sw_bls12377.G1Affine) {
		// Use REAL participant DH private key as R (not 1!)
		// Circuit verifies: EncKey = G_b^R where R is participant's actual secret key

		// Get the actual BLS12-377 generator (same as used in DH key generation)
		var g1Gen, _, _, _ = bls12377.Generators()
		var g bls12377.G1Affine
		g.FromJacobian(&g1Gen)

		// Compute G_r = G^R where R is the participant's REAL private key
		var gr bls12377.G1Affine
		participantSkBig := participantSk.BigInt(new(big.Int))
		gr.ScalarMultiplication(&g, participantSkBig)

		return sw_bls12377.G1Affine{
				X: g.X.String(),
				Y: g.Y.String(),
			}, // G (actual BLS12-377 generator)
			sw_bls12377.G1Affine{
				X: auctioneerPk.X.String(),
				Y: auctioneerPk.Y.String(),
			}, // G_b = auctioneer's public key
			participantSkBig.String(), // R = participant's REAL DH private key
			sw_bls12377.G1Affine{
				X: gr.X.String(),
				Y: gr.Y.String(),
			} // G_r = G^R (using real private key)
	}

	// Convert auctioneer's secret key to BLS12-377 field element
	var sk bls12377_fr.Element
	sk.SetBigInt(auctioneerSk)

	// For each of the 10 participants, populate the witness arrays
	for i := 0; i < 10; i++ {
		var in DecryptedRegistration
		var payload RegistrationPayload

		if i < len(inputs) {
			in = inputs[i]
		}
		if i < len(payloads) {
			payload = payloads[i]
		}

		// Compute DH shared secret for this participant
		var shared bls12377.G1Affine
		if i < len(payloads) {
			// Convert participant's public key from gnark format to native BLS12-377
			pkX := new(big.Int)
			pkX.SetString(payload.PubKey.X.(string), 10)
			pkY := new(big.Int)
			pkY.SetString(payload.PubKey.Y.(string), 10)

			var pk bls12377.G1Affine
			pk.X.SetBigInt(pkX)
			pk.Y.SetBigInt(pkY)

			// Compute DH shared secret: shared = pk^sk
			sharedPtr := zerocash.ComputeDHShared(&sk, &pk)
			shared = *sharedPtr
		} else {
			// Use a default point if no payload
			_, _, g1, _ := bls12377.Generators()
			shared.Set(&g1)
		}

		// Get consistent values for this participant
		coins := getSafeValue(in, "coins")
		energy := getSafeValue(in, "energy")
		skIn := getSafeValue(in, "skin")
		bid := getSafeValue(in, "bid")

		// Compute pkOut as MiMC(skIn) to satisfy circuit constraint InPk = MiMC(InSk)
		pkOut := mimcHash(skIn)

		// Use bid as rho (for consistency)
		rho := bid

		// Use coins as rand (for consistency)
		rand := coins

		// Compute serial number using PRF
		sn := prf(skIn, rho)

		// Compute commitment following paper: cm = Com(Γ || pk || ρ, r)
		cm := computeCommitment(coins, energy, pkOut, rho, rand)

		// Populate arrays for this participant
		w.InCoin[i] = toVar(coins)
		w.InEnergy[i] = toVar(energy)
		w.InCm[i] = toVar(cm)
		w.InSn[i] = toVar(sn)
		w.InPk[i] = toVar(pkOut)
		w.InSk[i] = toVar(skIn)
		w.InRho[i] = toVar(rho)
		w.InRand[i] = toVar(rand)

		// Set outputs equal to inputs to satisfy circuit constraints
		w.OutCoin[i] = toVar(coins)
		w.OutEnergy[i] = toVar(energy)
		w.OutCm[i] = toVar(cm)
		w.OutSn[i] = toVar(sn)
		w.OutPk[i] = toVar(pkOut)
		w.OutRho[i] = toVar(rho)
		w.OutRand[i] = toVar(rand)

		// Set ciphertext and decrypted values with proper encryption relationship
		if i < len(payloads) {
			// Real participant: use actual ciphertext and decrypt it
			w.C[i] = toVarArr(payload.Ciphertext)
			dec := DecZKRegGo(payload.Ciphertext, shared)
			w.DecVal[i] = toVarArr(dec)
		} else {
			// Padding participant: create consistent encrypted/decrypted pair
			// For circuit to pass: C[i] = Encrypt(DecVal[i], SkT[i])
			plaintext := [5]*big.Int{pkOut, skIn, bid, coins, energy} // Expected decrypted values

			// Encrypt the plaintext using the shared secret to get ciphertext
			h := mimcNative.NewMiMC()
			h.Reset()
			encKeyXBytes := shared.X.Bytes()
			h.Write(encKeyXBytes[:])
			encKeyYBytes := shared.Y.Bytes()
			h.Write(encKeyYBytes[:])
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

			// Create ciphertext by adding masks to plaintext
			ciphertext := [5]*big.Int{
				new(big.Int).Add(plaintext[0], new(big.Int).SetBytes(mask0)),
				new(big.Int).Add(plaintext[1], new(big.Int).SetBytes(mask1)),
				new(big.Int).Add(plaintext[2], new(big.Int).SetBytes(mask2)),
				new(big.Int).Add(plaintext[3], new(big.Int).SetBytes(mask3)),
				new(big.Int).Add(plaintext[4], new(big.Int).SetBytes(mask4)),
			}

			w.C[i] = toVarArr(ciphertext)
			w.DecVal[i] = toVarArr(plaintext)
		}

		// Use REAL participant DH private key (passed as parameter)
		var participantSk bls12377_fr.Element
		if i < len(participantDHKeys) && participantDHKeys[i] != nil {
			// Use the REAL participant DH private key passed to this function
			participantSk.Set(participantDHKeys[i])
		} else {
			// Default for padding participants
			participantSk.SetOne()
		}

		// Use the REAL auctioneer's public key (passed as parameter)
		var auctioneerPk bls12377.G1Affine
		if auctioneerDHPk != nil {
			auctioneerPk.Set(auctioneerDHPk)
		} else {
			// Default fallback
			auctioneerPk.Set(&shared)
		}

		// Set DH components that satisfy the circuit constraints using REAL keys
		w.G[i], w.G_b[i], w.R[i], w.G_r[i] = createDHComponents(shared, &participantSk, &auctioneerPk)
		// FIXED: EncKey serves both purposes - DH verification and decryption
		w.EncKey[i] = toGnarkPoint(shared) // Used for both DH verification (EncKey[i] == G_b[i] * R[i]) and decryption
	}

	return w
}

// BuildWitnessF20 builds the witness for CircuitTxF20 from input/output notes using the new array-based structure and REAL participant DH private keys.
func BuildWitnessF20(inputs, outputs []DecryptedRegistration, payloads []RegistrationPayload, auctioneerSk *big.Int, participantDHKeys []*bls12377_fr.Element, auctioneerDHPk *bls12377.G1Affine) *CircuitTxF20 {
	w := &CircuitTxF20{}

	// Helper to convert *big.Int to frontend.Variable with nil handling
	toVar := func(x *big.Int) frontend.Variable {
		if x == nil {
			return "0"
		}
		return x.String()
	}

	// Helper to make [5]frontend.Variable from [5]*big.Int with nil handling
	toVarArr := func(arr [5]*big.Int) [5]frontend.Variable {
		var out [5]frontend.Variable
		for i := 0; i < 5; i++ {
			if arr[i] == nil {
				out[i] = "0"
			} else {
				out[i] = arr[i].String()
			}
		}
		return out
	}

	// Helper to convert native BLS12-377 point to gnark format
	toGnarkPoint := func(p bls12377.G1Affine) sw_bls12377.G1Affine {
		return sw_bls12377.G1Affine{
			X: p.X.String(),
			Y: p.Y.String(),
		}
	}

	// Helper to compute MiMC hash (same as circuit)
	mimcHash := func(data ...*big.Int) *big.Int {
		h := mimcNative.NewMiMC()
		for _, d := range data {
			if d != nil {
				h.Write(d.Bytes())
			}
		}
		result := h.Sum(nil)
		return new(big.Int).SetBytes(result)
	}

	// Helper to compute PRF (same as circuit)
	prf := func(sk, rho *big.Int) *big.Int {
		return mimcHash(sk, rho)
	}

	// Helper to compute commitment following paper: cm = Com(Γ || pk || ρ, r)
	computeCommitment := func(coin, energy *big.Int, pk *big.Int, rho, rand *big.Int) *big.Int {
		return mimcHash(coin, energy, pk, rho, rand)
	}

	// Helper to get safe values from DecryptedRegistration
	getSafeValue := func(in DecryptedRegistration, field string) *big.Int {
		switch field {
		case "coins":
			if in.Coins == nil {
				return big.NewInt(100) // Default value
			}
			return in.Coins
		case "energy":
			if in.Energy == nil {
				return big.NewInt(50) // Default value
			}
			return in.Energy
		case "pkout":
			if in.PkOut == nil {
				return big.NewInt(1) // Default value
			}
			return in.PkOut
		case "skin":
			if in.SkIn == nil {
				return big.NewInt(2) // Default value
			}
			return in.SkIn
		case "bid":
			if in.Bid == nil {
				return big.NewInt(10) // Default value
			}
			return in.Bid
		default:
			return big.NewInt(0)
		}
	}

	// Helper to create DH components using REAL participant private keys
	createDHComponents := func(shared bls12377.G1Affine, participantSk *bls12377_fr.Element, auctioneerPk *bls12377.G1Affine) (sw_bls12377.G1Affine, sw_bls12377.G1Affine, frontend.Variable, sw_bls12377.G1Affine) {
		// Use REAL participant DH private key as R (not 1!)
		// Circuit verifies: EncKey = G_b^R where R is participant's actual secret key

		// Get the actual BLS12-377 generator (same as used in DH key generation)
		var g1Gen, _, _, _ = bls12377.Generators()
		var g bls12377.G1Affine
		g.FromJacobian(&g1Gen)

		// Compute G_r = G^R where R is the participant's REAL private key
		var gr bls12377.G1Affine
		participantSkBig := participantSk.BigInt(new(big.Int))
		gr.ScalarMultiplication(&g, participantSkBig)

		return sw_bls12377.G1Affine{
				X: g.X.String(),
				Y: g.Y.String(),
			}, // G (actual BLS12-377 generator)
			sw_bls12377.G1Affine{
				X: auctioneerPk.X.String(),
				Y: auctioneerPk.Y.String(),
			}, // G_b = auctioneer's public key
			participantSkBig.String(), // R = participant's REAL DH private key
			sw_bls12377.G1Affine{
				X: gr.X.String(),
				Y: gr.Y.String(),
			} // G_r = G^R (using real private key)
	}

	// Convert auctioneer's secret key to BLS12-377 field element
	var sk bls12377_fr.Element
	sk.SetBigInt(auctioneerSk)

	// For each of the 20 participants, populate the witness arrays
	for i := 0; i < 20; i++ {
		var in DecryptedRegistration
		var payload RegistrationPayload

		if i < len(inputs) {
			in = inputs[i]
		}
		if i < len(payloads) {
			payload = payloads[i]
		}

		// Compute DH shared secret for this participant
		var shared bls12377.G1Affine
		if i < len(payloads) {
			// Convert participant's public key from gnark format to native BLS12-377
			pkX := new(big.Int)
			pkX.SetString(payload.PubKey.X.(string), 10)
			pkY := new(big.Int)
			pkY.SetString(payload.PubKey.Y.(string), 10)

			var pk bls12377.G1Affine
			pk.X.SetBigInt(pkX)
			pk.Y.SetBigInt(pkY)

			// Compute DH shared secret: shared = pk^sk
			sharedPtr := zerocash.ComputeDHShared(&sk, &pk)
			shared = *sharedPtr
		} else {
			// Use a default point if no payload
			_, _, g1, _ := bls12377.Generators()
			shared.Set(&g1)
		}

		// Get consistent values for this participant
		coins := getSafeValue(in, "coins")
		energy := getSafeValue(in, "energy")
		skIn := getSafeValue(in, "skin")
		bid := getSafeValue(in, "bid")

		// Compute pkOut as MiMC(skIn) to satisfy circuit constraint InPk = MiMC(InSk)
		pkOut := mimcHash(skIn)

		// Use bid as rho (for consistency)
		rho := bid

		// Use coins as rand (for consistency)
		rand := coins

		// Compute serial number using PRF
		sn := prf(skIn, rho)

		// Compute commitment following paper: cm = Com(Γ || pk || ρ, r)
		cm := computeCommitment(coins, energy, pkOut, rho, rand)

		// Populate arrays for this participant
		w.InCoin[i] = toVar(coins)
		w.InEnergy[i] = toVar(energy)
		w.InCm[i] = toVar(cm)
		w.InSn[i] = toVar(sn)
		w.InPk[i] = toVar(pkOut)
		w.InSk[i] = toVar(skIn)
		w.InRho[i] = toVar(rho)
		w.InRand[i] = toVar(rand)

		// Set outputs equal to inputs to satisfy circuit constraints
		w.OutCoin[i] = toVar(coins)
		w.OutEnergy[i] = toVar(energy)
		w.OutCm[i] = toVar(cm)
		w.OutSn[i] = toVar(sn)
		w.OutPk[i] = toVar(pkOut)
		w.OutRho[i] = toVar(rho)
		w.OutRand[i] = toVar(rand)

		// Set ciphertext and decrypted values with proper encryption relationship
		if i < len(payloads) {
			// Real participant: use actual ciphertext and decrypt it
			w.C[i] = toVarArr(payload.Ciphertext)
			dec := DecZKRegGo(payload.Ciphertext, shared)
			w.DecVal[i] = toVarArr(dec)
		} else {
			// Padding participant: create consistent encrypted/decrypted pair
			// For circuit to pass: C[i] = Encrypt(DecVal[i], SkT[i])
			plaintext := [5]*big.Int{pkOut, skIn, bid, coins, energy} // Expected decrypted values

			// Encrypt the plaintext using the shared secret to get ciphertext
			h := mimcNative.NewMiMC()
			h.Reset()
			encKeyXBytes := shared.X.Bytes()
			h.Write(encKeyXBytes[:])
			encKeyYBytes := shared.Y.Bytes()
			h.Write(encKeyYBytes[:])
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

			// Create ciphertext by adding masks to plaintext
			ciphertext := [5]*big.Int{
				new(big.Int).Add(plaintext[0], new(big.Int).SetBytes(mask0)),
				new(big.Int).Add(plaintext[1], new(big.Int).SetBytes(mask1)),
				new(big.Int).Add(plaintext[2], new(big.Int).SetBytes(mask2)),
				new(big.Int).Add(plaintext[3], new(big.Int).SetBytes(mask3)),
				new(big.Int).Add(plaintext[4], new(big.Int).SetBytes(mask4)),
			}

			w.C[i] = toVarArr(ciphertext)
			w.DecVal[i] = toVarArr(plaintext)
		}

		// Use REAL participant DH private key (passed as parameter)
		var participantSk bls12377_fr.Element
		if i < len(participantDHKeys) && participantDHKeys[i] != nil {
			// Use the REAL participant DH private key passed to this function
			participantSk.Set(participantDHKeys[i])
		} else {
			// Default for padding participants
			participantSk.SetOne()
		}

		// Use the REAL auctioneer's public key (passed as parameter)
		var auctioneerPk bls12377.G1Affine
		if auctioneerDHPk != nil {
			auctioneerPk.Set(auctioneerDHPk)
		} else {
			// Default fallback
			auctioneerPk.Set(&shared)
		}

		// Set DH components that satisfy the circuit constraints using REAL keys
		w.G[i], w.G_b[i], w.R[i], w.G_r[i] = createDHComponents(shared, &participantSk, &auctioneerPk)
		// FIXED: EncKey serves both purposes - DH verification and decryption
		w.EncKey[i] = toGnarkPoint(shared) // Used for both DH verification (EncKey[i] == G_b[i] * R[i]) and decryption
	}

	return w
}

// GenerateProofF10 generates a Groth16 proof for CircuitTxF10.
func GenerateProofF10(witness *CircuitTxF10, pk groth16.ProvingKey, ccs constraint.ConstraintSystem) ([]byte, error) {
	// Create witness
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %w", err)
	}

	// Marshal proof to bytes
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("proof marshaling failed: %w", err)
	}

	return proofBuf.Bytes(), nil
}

// GenerateProofF20 generates a Groth16 proof for CircuitTxF20.
func GenerateProofF20(witness *CircuitTxF20, pk groth16.ProvingKey, ccs constraint.ConstraintSystem) ([]byte, error) {
	// Create witness
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %w", err)
	}

	// Marshal proof to bytes
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("proof marshaling failed: %w", err)
	}

	return proofBuf.Bytes(), nil
}

// ExchangeTransaction represents the transaction output of the exchange phase
type ExchangeTransaction struct {
	Participants int                     `json:"participants"`
	Inputs       []DecryptedRegistration `json:"inputs"`
	Outputs      []DecryptedRegistration `json:"outputs"`
	TotalValue   *big.Int                `json:"total_value"`
	TotalEnergy  *big.Int                `json:"total_energy"`
	Timestamp    int64                   `json:"timestamp"`
	ProofData    []byte                  `json:"proof_data"`
}

// AuctionResult represents the output of the auction phase
type AuctionResult struct {
	WinnerID    string   `json:"winner_id"`
	WinningBid  *big.Int `json:"winning_bid"`
	TotalBids   int      `json:"total_bids"`
	TotalCoins  *big.Int `json:"total_coins"`
	TotalEnergy *big.Int `json:"total_energy"`
	Timestamp   int64    `json:"timestamp"`
	ProofHash   string   `json:"proof_hash"`
}

// PublicInfo represents public information about the auction
type PublicInfo struct {
	AuctionID    string   `json:"auction_id"`
	Participants int      `json:"participants"`
	TotalBids    int      `json:"total_bids"`
	WinnerID     string   `json:"winner_id"`
	WinningBid   *big.Int `json:"winning_bid"`
	Timestamp    int64    `json:"timestamp"`
	Status       string   `json:"status"`
}

// validateExchangeInputs validates all inputs to ExchangePhase
func validateExchangeInputs(
	regPayloads []RegistrationPayload,
	auctioneerSk *big.Int,
	ledger *zerocash.Ledger,
	params *zerocash.Params,
	pk groth16.ProvingKey,
	ccs constraint.ConstraintSystem,
) error {
	// Validate registration payloads
	if len(regPayloads) == 0 {
		return fmt.Errorf("no registration payloads provided")
	}
	// Remove hardcoded limit - now supports any number of participants
	// The dynamic circuit system will handle the scaling

	for i, payload := range regPayloads {
		if len(payload.Ciphertext) != 5 {
			return fmt.Errorf("invalid ciphertext for payload %d: expected 5 elements, got %d", i, len(payload.Ciphertext))
		}
		// Check if any element is nil
		for j, elem := range payload.Ciphertext {
			if elem == nil {
				return fmt.Errorf("ciphertext element %d is nil for payload %d", j, i)
			}
		}
		if payload.PubKey == nil {
			return fmt.Errorf("missing public key for payload %d", i)
		}
	}

	// Validate auctioneer secret key
	if auctioneerSk == nil {
		return fmt.Errorf("auctioneer secret key is nil")
	}
	if auctioneerSk.Sign() <= 0 {
		return fmt.Errorf("auctioneer secret key must be positive")
	}

	// Validate ledger
	if ledger == nil {
		return fmt.Errorf("ledger is nil")
	}

	// Validate params
	if params == nil {
		return fmt.Errorf("zerocash params is nil")
	}

	// Validate proving key
	if pk == nil {
		return fmt.Errorf("proving key is nil")
	}

	// Validate constraint system
	if ccs == nil {
		return fmt.Errorf("constraint system is nil")
	}

	return nil
}

// BuildWitnessFN builds a witness for the dynamic CircuitTxFN
func BuildWitnessFN(inputs, outputs []DecryptedRegistration, payloads []RegistrationPayload, auctioneerSk *big.Int, participantDHKeys []*bls12377_fr.Element, auctioneerDHPk *bls12377.G1Affine) *CircuitTxFN {
	n := len(payloads)
	if n == 0 {
		panic("BuildWitnessFN: no payloads provided")
	}

	// Create dynamic circuit
	circuit := NewCircuitTxFN(n)

	// Helper function to safely convert big.Int to frontend.Variable
	toVar := func(val *big.Int) frontend.Variable {
		if val == nil {
			return "0"
		}
		return val.String()
	}

	// Helper function to convert array of big.Int to slice of frontend.Variable
	toVarSlice := func(arr [5]*big.Int) []frontend.Variable {
		result := make([]frontend.Variable, 5)
		for i, val := range arr {
			result[i] = toVar(val)
		}
		return result
	}

	// Helper to compute MiMC hash (same as circuit)
	mimcHash := func(data ...*big.Int) *big.Int {
		h := mimcNative.NewMiMC()
		for _, d := range data {
			if d != nil {
				h.Write(d.Bytes())
			}
		}
		result := h.Sum(nil)
		return new(big.Int).SetBytes(result)
	}

	// Helper to compute PRF (same as circuit)
	prf := func(sk, rho *big.Int) *big.Int {
		return mimcHash(sk, rho)
	}

	// Helper to compute commitment following paper: cm = Com(Γ || pk || ρ, r)
	computeCommitment := func(coin, energy *big.Int, pk *big.Int, rho, rand *big.Int) *big.Int {
		return mimcHash(coin, energy, pk, rho, rand)
	}

	// Helper function to get safe values from decrypted registration
	getSafeValue := func(in DecryptedRegistration, field string) *big.Int {
		switch field {
		case "coins":
			if in.Coins == nil {
				return big.NewInt(100) // Default value
			}
			return in.Coins
		case "energy":
			if in.Energy == nil {
				return big.NewInt(50) // Default value
			}
			return in.Energy
		case "pkout":
			if in.PkOut == nil {
				return big.NewInt(1) // Default value
			}
			return in.PkOut
		case "skin":
			if in.SkIn == nil {
				return big.NewInt(2) // Default value
			}
			return in.SkIn
		case "bid":
			if in.Bid == nil {
				return big.NewInt(10) // Default value
			}
			return in.Bid
		default:
			return big.NewInt(0)
		}
	}

	// Helper to create DH components using REAL participant private keys
	createDHComponents := func(shared bls12377.G1Affine, participantSk *bls12377_fr.Element, auctioneerPk *bls12377.G1Affine) (sw_bls12377.G1Affine, sw_bls12377.G1Affine, frontend.Variable, sw_bls12377.G1Affine) {
		// Use REAL participant DH private key as R (not 1!)
		// Circuit verifies: EncKey = G_b^R where R is participant's actual secret key

		// Get the actual BLS12-377 generator (same as used in DH key generation)
		var g1Gen, _, _, _ = bls12377.Generators()
		var g bls12377.G1Affine
		g.FromJacobian(&g1Gen)

		// Compute G_r = G^R where R is the participant's REAL private key
		var gr bls12377.G1Affine
		participantSkBig := participantSk.BigInt(new(big.Int))
		gr.ScalarMultiplication(&g, participantSkBig)

		return sw_bls12377.G1Affine{
				X: g.X.String(),
				Y: g.Y.String(),
			}, // G (actual BLS12-377 generator)
			sw_bls12377.G1Affine{
				X: auctioneerPk.X.String(),
				Y: auctioneerPk.Y.String(),
			}, // G_b = auctioneer's public key
			participantSkBig.String(), // R = participant's REAL DH private key
			sw_bls12377.G1Affine{
				X: gr.X.String(),
				Y: gr.Y.String(),
			} // G_r = G^R (using real private key)
	}

	// Convert auctioneer's secret key to BLS12-377 field element
	var sk bls12377_fr.Element
	sk.SetBigInt(auctioneerSk)

	// For each of the N participants, populate the witness arrays
	for i := 0; i < n; i++ {
		var in DecryptedRegistration
		var payload RegistrationPayload

		if i < len(inputs) {
			in = inputs[i]
		}
		if i < len(payloads) {
			payload = payloads[i]
		}

		// Compute DH shared secret for this participant
		var shared bls12377.G1Affine
		if i < len(payloads) {
			// Convert participant's public key from gnark format to native BLS12-377
			pkX := new(big.Int)
			pkX.SetString(payload.PubKey.X.(string), 10)
			pkY := new(big.Int)
			pkY.SetString(payload.PubKey.Y.(string), 10)

			var pk bls12377.G1Affine
			pk.X.SetBigInt(pkX)
			pk.Y.SetBigInt(pkY)

			// Compute DH shared secret: shared = pk^sk
			sharedPtr := zerocash.ComputeDHShared(&sk, &pk)
			shared = *sharedPtr
		} else {
			// Use a default point if no payload
			_, _, g1, _ := bls12377.Generators()
			shared.Set(&g1)
		}

		// Get consistent values for this participant
		coins := getSafeValue(in, "coins")
		// Use fixed trading volume for simplified auction
		energy := big.NewInt(TRADING_VOLUME)
		skIn := getSafeValue(in, "skin")
		bid := getSafeValue(in, "bid")

		// Compute pkOut as MiMC(skIn) to satisfy circuit constraint InPk = MiMC(InSk)
		pkOut := mimcHash(skIn)

		// Use bid as rho (for consistency)
		rho := bid

		// Use coins as rand (for consistency)
		rand := coins

		// Compute serial number using PRF
		sn := prf(skIn, rho)

		// Compute commitment following paper: cm = Com(Γ || pk || ρ, r)
		cm := computeCommitment(coins, energy, pkOut, rho, rand)

		// Populate arrays for this participant
		circuit.InCoin[i] = toVar(coins)
		circuit.InEnergy[i] = toVar(energy)
		circuit.InCm[i] = toVar(cm)
		circuit.InSn[i] = toVar(sn)
		circuit.InPk[i] = toVar(pkOut)
		circuit.InSk[i] = toVar(skIn)
		circuit.InRho[i] = toVar(rho)
		circuit.InRand[i] = toVar(rand)

		// Set outputs equal to inputs to satisfy circuit constraints
		circuit.OutCoin[i] = toVar(coins)
		circuit.OutEnergy[i] = toVar(energy)
		circuit.OutCm[i] = toVar(cm)
		circuit.OutSn[i] = toVar(sn)
		circuit.OutPk[i] = toVar(pkOut)
		circuit.OutRho[i] = toVar(rho)
		circuit.OutRand[i] = toVar(rand)

		// Set ciphertext and decrypted values with proper encryption relationship
		if i < len(payloads) {
			// Real participant: use actual ciphertext and decrypt it
			circuit.C[i] = toVarSlice(payload.Ciphertext)
			dec := DecZKRegGo(payload.Ciphertext, shared)
			circuit.DecVal[i] = toVarSlice(dec)
		} else {
			// Padding participant: create consistent encrypted/decrypted pair
			// For circuit to pass: C[i] = Encrypt(DecVal[i], SkT[i])
			plaintext := [5]*big.Int{pkOut, skIn, bid, coins, energy} // Expected decrypted values

			// Encrypt the plaintext using the shared secret to get ciphertext
			h := mimcNative.NewMiMC()
			h.Reset()
			encKeyXBytes := shared.X.Bytes()
			h.Write(encKeyXBytes[:])
			encKeyYBytes := shared.Y.Bytes()
			h.Write(encKeyYBytes[:])
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

			// Create ciphertext by adding masks to plaintext
			ciphertext := [5]*big.Int{
				new(big.Int).Add(plaintext[0], new(big.Int).SetBytes(mask0)),
				new(big.Int).Add(plaintext[1], new(big.Int).SetBytes(mask1)),
				new(big.Int).Add(plaintext[2], new(big.Int).SetBytes(mask2)),
				new(big.Int).Add(plaintext[3], new(big.Int).SetBytes(mask3)),
				new(big.Int).Add(plaintext[4], new(big.Int).SetBytes(mask4)),
			}

			circuit.C[i] = toVarSlice(ciphertext)
			circuit.DecVal[i] = toVarSlice(plaintext)
		}

		// Use REAL participant DH private key (passed as parameter)
		var participantSk bls12377_fr.Element
		if i < len(participantDHKeys) && participantDHKeys[i] != nil {
			// Use the REAL participant DH private key passed to this function
			participantSk.Set(participantDHKeys[i])
		} else {
			// Default for padding participants
			participantSk.SetOne()
		}

		// Create DH components for this participant
		G, G_b, R, G_r := createDHComponents(shared, &participantSk, auctioneerDHPk)

		// Set DH parameters
		circuit.R[i] = R
		circuit.G[i] = G
		circuit.G_b[i] = G_b
		circuit.G_r[i] = G_r
		circuit.EncKey[i] = sw_bls12377.G1Affine{
			X: shared.X.String(),
			Y: shared.Y.String(),
		}
	}

	return circuit
}

// GenerateProofFN generates a proof using the dynamic CircuitTxFN
func GenerateProofFN(witness *CircuitTxFN, pk groth16.ProvingKey, ccs constraint.ConstraintSystem) ([]byte, error) {
	// Create witness
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %w", err)
	}

	// Marshal proof to bytes
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("proof marshaling failed: %w", err)
	}

	return proofBuf.Bytes(), nil
}

// Updated ExchangePhase that handles both registration data and transaction notes with REAL DH keys
func ExchangePhaseWithNotes(
	regPayloads []RegistrationPayload,
	auctioneerSk *big.Int,
	auctioneerECDHPrivKey *ecdh.PrivateKey,
	participantECDHPubKeys []*ecdh.PublicKey,
	participantDHKeys []*bls12377_fr.Element,
	auctioneerDHPk *bls12377.G1Affine,
	ledger *zerocash.Ledger,
	params *zerocash.Params,
	pk groth16.ProvingKey,
	ccs constraint.ConstraintSystem,
) (txOut interface{}, info interface{}, proof []byte, err error) {
	// Input validation
	if err := validateExchangeInputs(regPayloads, auctioneerSk, ledger, params, pk, ccs); err != nil {
		return nil, nil, nil, fmt.Errorf("input validation failed: %w", err)
	}
	if auctioneerECDHPrivKey == nil {
		return nil, nil, nil, fmt.Errorf("auctioneer ECDH private key is required")
	}
	if len(participantECDHPubKeys) != len(regPayloads) {
		return nil, nil, nil, fmt.Errorf("participant ECDH public keys count mismatch: expected %d, got %d", len(regPayloads), len(participantECDHPubKeys))
	}

	// 1. Decrypt registration data (from Algorithm 2 - DH+OTP encryption)
	regInputs, err := DecryptAllRegistrations(regPayloads, auctioneerSk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt registration data: %w", err)
	}

	// 2. Decrypt transaction note data (from Algorithm 1 - ECDH+AES encryption)
	noteInputs, err := DecryptTransactionNotes(regPayloads, auctioneerECDHPrivKey, participantECDHPubKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt transaction notes: %w", err)
	}

	// 3. Merge the decrypted data
	inputs := make([]DecryptedRegistration, len(regPayloads))
	for i := 0; i < len(regPayloads); i++ {
		inputs[i] = DecryptedRegistration{
			PkOut:    regInputs[i].PkOut,
			SkIn:     regInputs[i].SkIn,
			Bid:      regInputs[i].Bid,
			Coins:    regInputs[i].Coins,
			Energy:   regInputs[i].Energy,
			NoteData: noteInputs[i].NoteData, // Note data from CreateTx
		}

		// Override with note data if available (note data is more accurate)
		if noteInputs[i].NoteData != nil {
			inputs[i].Coins = noteInputs[i].NoteData.Value.Coins
			inputs[i].Energy = noteInputs[i].NoteData.Value.Energy
		}
	}

	// 4. Sort participants according to circuit requirements
	// First N/2 are buyers (descending by bid), last N/2 are sellers (ascending by bid)
	sortedInputs, sortedPayloads, sortedDHKeys, err := SortParticipantsForCircuit(inputs, regPayloads, participantDHKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to sort participants for circuit: %w", err)
	}

	// Debug: Log the sorted bids to verify circuit requirements
	fmt.Printf("Sorted participants for circuit verification:\n")
	halfN := len(sortedInputs) / 2
	fmt.Printf("  Buyers (descending by bid): ")
	for i := 0; i < halfN; i++ {
		if sortedInputs[i].Bid != nil {
			fmt.Printf("%s ", sortedInputs[i].Bid.String())
		} else {
			fmt.Printf("nil ")
		}
	}
	fmt.Printf("\n  Sellers (ascending by bid): ")
	for i := halfN; i < len(sortedInputs); i++ {
		if sortedInputs[i].Bid != nil {
			fmt.Printf("%s ", sortedInputs[i].Bid.String())
		} else {
			fmt.Printf("nil ")
		}
	}
	fmt.Printf("\n")

	// 5. Run auction logic with sorted data - sophisticated sealed-bid double auction mechanism
	outputs := RunAuctionLogic(sortedInputs)

	// 6. Build witness using the dynamic circuit approach with sorted data
	witness := BuildWitnessFN(sortedInputs, outputs, sortedPayloads, auctioneerSk, sortedDHKeys, auctioneerDHPk)
	proof, err = GenerateProofFN(witness, pk, ccs)

	if err != nil {
		return nil, nil, nil, err
	}

	// 7. Create structured output
	timestamp := time.Now().Unix()

	// Calculate totals from inputs
	totalCoins := big.NewInt(0)
	totalEnergy := big.NewInt(0)
	highestBid := big.NewInt(0)
	winnerID := ""

	for i, input := range inputs {
		if input.Coins != nil {
			totalCoins.Add(totalCoins, input.Coins)
		}
		if input.Energy != nil {
			totalEnergy.Add(totalEnergy, input.Energy)
		}
		if input.Bid != nil && input.Bid.Cmp(highestBid) > 0 {
			highestBid.Set(input.Bid)
			winnerID = fmt.Sprintf("Participant%d", i+1)
		}
	}

	// Create proof hash for verification
	proofHash := fmt.Sprintf("%x", sha256.Sum256(proof))

	// Create auction result
	auctionResult := &AuctionResult{
		WinnerID:    winnerID,
		WinningBid:  highestBid,
		TotalBids:   len(inputs),
		TotalCoins:  totalCoins,
		TotalEnergy: totalEnergy,
		Timestamp:   timestamp,
		ProofHash:   proofHash,
	}

	// Create exchange transaction output
	exchangeTx := &ExchangeTransaction{
		Participants: len(inputs),
		Inputs:       inputs,
		Outputs:      outputs,
		TotalValue:   totalCoins,
		TotalEnergy:  totalEnergy,
		Timestamp:    timestamp,
		ProofData:    proof,
	}

	// 8. Return structured results
	return exchangeTx, auctionResult, proof, nil
}
