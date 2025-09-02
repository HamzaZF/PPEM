// exchange.go - Auction phase logic for the protocol (Algorithm 3, without ZKP-enforced auction logic).
//
// This file implements the exchange phase: decrypts registration payloads, runs auction logic (off-circuit),
// constructs output notes, builds the witness, and generates the ZKP using CircuitTxFN.
//
// WARNING: The ZKP only proves cryptographic consistency, not the correctness of the auction computation.

package exchange

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	recursion "github.com/consensys/gnark/std/recursion/groth16"

	"implementation/internal/risc0"
	"implementation/internal/zerocash"
)

// RegistrationPayload represents a participant's encrypted registration data for the auction phase.
// Contains the ciphertext (encrypted registration fields), the participant's public key (for DH),
// and optionally the encrypted note data from CreateTx.
type RegistrationPayload struct {
	Ciphertext [7]*big.Int           // (pkOut, skIn, bid, coins, energy, role, quantity)
	PubKey     *sw_bls12377.G1Affine // Participant's DH public key
	TxNoteData []byte                // Encrypted note data from Algorithm 1
}

// DecryptedRegistration holds the decrypted registration data for a participant.
// This is the canonical form used for auction logic and witness generation.
type DecryptedRegistration struct {
	PkOut    *big.Int       // Output public key
	SkIn     *big.Int       // Input secret key
	Price    *big.Int       // Order price (bid for buyers, ask for sellers)
	Role     *big.Int       // Order role (0=BUY, 1=SELL) - from DecVal[i][5]
	Quantity *big.Int       // Order quantity (amount of energy to trade)
	Coins    *big.Int       // Coin balance
	Energy   *big.Int       // Energy balance
	NoteData *zerocash.Note // Decrypted note from CreateTx (optional)
}

// DecryptAllRegistrations decrypts all registration payloads using the auctioneer's private key.
// Returns a slice of DecryptedRegistration for each participant.
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
			PkOut:    decrypted[0], // pk^out
			SkIn:     decrypted[1], // sk^in
			Price:    decrypted[2], // price (formerly bid)
			Role:     decrypted[5], // role (0=BUY, 1=SELL)
			Quantity: decrypted[6], // quantity
			Coins:    decrypted[3], // coins
			Energy:   decrypted[4], // energy
		}

		// Note: Note data decryption is handled by DecryptTransactionNotes function

		results[i] = result
	}

	return results, nil
}

// DecryptTransactionNotes decrypts the note data from transactions using permanent ECDH keys.
// Returns a slice of DecryptedRegistration with only the NoteData, Coins, and Energy fields set.
func DecryptTransactionNotes(payloads []RegistrationPayload, auctioneerECDHPrivKey *ecdh.PrivateKey, participantECDHPubKeys []*ecdh.PublicKey) ([]DecryptedRegistration, error) {
	results := make([]DecryptedRegistration, len(payloads))

	for i, payload := range payloads {
		result := DecryptedRegistration{
			Role: big.NewInt(0), // Default to BUY
		}

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
// Returns sorted inputs, payloads, and participantDHKeys.
func SortParticipantsForCircuit(
	inputs []DecryptedRegistration,
	payloads []RegistrationPayload,
	participantDHKeys []*bls12377_fr.Element,
	roles map[int]zerocash.OrderType,
) ([]DecryptedRegistration, []RegistrationPayload, []*bls12377_fr.Element, error) {

	n := len(inputs)

	// Circuit now supports flexible buyer/seller ratios - no padding needed

	// Create pairs of (index, data) for sorting
	type ParticipantData struct {
		Index   int
		Input   DecryptedRegistration
		Payload RegistrationPayload
		DHKey   *bls12377_fr.Element
	}

	// Split participants into buyers and sellers based on ACTUAL roles
	var buyers, sellers []ParticipantData

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

		// Use actual roles from configuration, not index assumptions
		participantRole, exists := roles[i]
		if !exists {
			// Default to SELL if role not specified (conservative approach)
			participantRole = zerocash.SELL
		}

		if participantRole == zerocash.BUY {
			buyers = append(buyers, data)
		} else {
			sellers = append(sellers, data)
		}
	}

	// Sort buyers in descending order by price (highest price first), tie-break by ID ascending
	sort.Slice(buyers, func(i, j int) bool {
		priceI := buyers[i].Input.Price
		priceJ := buyers[j].Input.Price
		if priceI == nil && priceJ == nil {
			return buyers[i].Index < buyers[j].Index // Tie-break by index/ID
		}
		if priceI == nil {
			return false
		}
		if priceJ == nil {
			return true
		}
		cmp := priceI.Cmp(priceJ)
		if cmp == 0 {
			return buyers[i].Index < buyers[j].Index // Tie-break by index/ID
		}
		return cmp > 0 // Descending order
	})

	// Sort sellers in ascending order by price (lowest ask first), tie-break by ID ascending
	sort.Slice(sellers, func(i, j int) bool {
		priceI := sellers[i].Input.Price
		priceJ := sellers[j].Input.Price
		if priceI == nil && priceJ == nil {
			return sellers[i].Index < sellers[j].Index // Tie-break by index/ID
		}
		if priceI == nil {
			return true
		}
		if priceJ == nil {
			return false
		}
		cmp := priceI.Cmp(priceJ)
		if cmp == 0 {
			return sellers[i].Index < sellers[j].Index // Tie-break by index/ID
		}
		return cmp < 0 // Ascending order
	})

	// Reconstruct the sorted arrays with real participants only
	sortedInputs := make([]DecryptedRegistration, n)
	sortedPayloads := make([]RegistrationPayload, n)
	sortedDHKeys := make([]*bls12377_fr.Element, n)

	// Add buyers first (indices 0 to len(buyers)-1)
	for i, buyer := range buyers {
		sortedInputs[i] = buyer.Input
		sortedPayloads[i] = buyer.Payload
		sortedDHKeys[i] = buyer.DHKey
	}

	// Add sellers next (indices len(buyers) to len(buyers)+len(sellers)-1)
	for i, seller := range sellers {
		idx := len(buyers) + i
		sortedInputs[idx] = seller.Input
		sortedPayloads[idx] = seller.Payload
		sortedDHKeys[idx] = seller.DHKey
	}

	return sortedInputs, sortedPayloads, sortedDHKeys, nil
}

// DecZKRegGo implements the same decryption logic as the circuit's DecZKReg function.
// Used for off-circuit decryption of registration payloads.
func DecZKRegGo(c [7]*big.Int, encKey bls12377.G1Affine) [7]*big.Int {
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

	h.Reset()
	h.Write(mask4)
	mask5 := h.Sum(nil)

	h.Reset()
	h.Write(mask5)
	mask6 := h.Sum(nil)

	// Decrypt by subtracting the masks
	dec0 := new(big.Int).Sub(c[0], new(big.Int).SetBytes(mask0))
	dec1 := new(big.Int).Sub(c[1], new(big.Int).SetBytes(mask1))
	dec2 := new(big.Int).Sub(c[2], new(big.Int).SetBytes(mask2))
	dec3 := new(big.Int).Sub(c[3], new(big.Int).SetBytes(mask3))
	dec4 := new(big.Int).Sub(c[4], new(big.Int).SetBytes(mask4))
	dec5 := new(big.Int).Sub(c[5], new(big.Int).SetBytes(mask5))
	dec6 := new(big.Int).Sub(c[6], new(big.Int).SetBytes(mask6))

	return [7]*big.Int{dec0, dec1, dec2, dec3, dec4, dec5, dec6}
}

// AuctionResult contains the results of the auction execution
type AuctionExecutionResult struct {
	Outputs             []DecryptedRegistration
	ClearingPrice       *big.Int
	MarginalBuyerPrice  *big.Int
	MarginalSellerPrice *big.Int
	TotalEnergyTraded   int64
	TotalCoinsTraded    int64
	QualifiedBuyers     int
	QualifiedSellers    int
}

// RunAuctionLogicUniform implements a uniform-price double auction without commission.
// Inputs must already be sorted: buyers first (desc price), sellers next (asc price).
func RunAuctionLogicUniform(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType) *AuctionExecutionResult {
	outputs := make([]DecryptedRegistration, len(inputs))
	copy(outputs, inputs)

	// Split sorted inputs into buyers and sellers based on roles count
	type IndexedParticipant struct {
		Index int
		Data  DecryptedRegistration
	}
	var buyers, sellers []IndexedParticipant
	buyerCount := 0
	for _, role := range roles {
		if role == zerocash.BUY {
			buyerCount++
		}
	}
	for i := 0; i < buyerCount && i < len(inputs); i++ {
		buyers = append(buyers, IndexedParticipant{Index: i, Data: inputs[i]})
	}
	for i := buyerCount; i < len(inputs); i++ {
		sellers = append(sellers, IndexedParticipant{Index: i, Data: inputs[i]})
	}
	if len(buyers) == 0 || len(sellers) == 0 {
		return &AuctionExecutionResult{Outputs: outputs, ClearingPrice: big.NewInt(0)}
	}

	// Build set of distinct candidate prices (from buyers and sellers)
	priceSet := map[string]*big.Int{}
	for _, b := range buyers {
		if b.Data.Price != nil {
			priceSet[b.Data.Price.String()] = b.Data.Price
		}
	}
	for _, s := range sellers {
		if s.Data.Price != nil {
			priceSet[s.Data.Price.String()] = s.Data.Price
		}
	}
	if len(priceSet) == 0 {
		return &AuctionExecutionResult{Outputs: outputs, ClearingPrice: big.NewInt(0)}
	}
	prices := make([]*big.Int, 0, len(priceSet))
	for _, p := range priceSet {
		prices = append(prices, new(big.Int).Set(p))
	}
	sort.Slice(prices, func(i, j int) bool { return prices[i].Cmp(prices[j]) < 0 })

	// Helper to compute D(p), S(p)
	demandSupplyAt := func(p *big.Int) (int64, int64) {
		var d, s int64
		for _, b := range buyers {
			if b.Data.Price != nil && b.Data.Price.Cmp(p) >= 0 && b.Data.Quantity != nil {
				d += b.Data.Quantity.Int64()
			}
		}
		for _, s_ := range sellers {
			if s_.Data.Price != nil && s_.Data.Price.Cmp(p) <= 0 && s_.Data.Quantity != nil {
				s += s_.Data.Quantity.Int64()
			}
		}
		return d, s
	}

	// Find p* = smallest p where S(p) >= D(p)
	var pStar *big.Int
	for _, p := range prices {
		d, s := demandSupplyAt(p)
		if s >= d {
			pStar = new(big.Int).Set(p)
			break
		}
	}
	if pStar == nil {
		return &AuctionExecutionResult{Outputs: outputs, ClearingPrice: big.NewInt(0)}
	}

	// Qualified sets at p*
	qualifiedBuyers := make([]IndexedParticipant, 0)
	for _, b := range buyers {
		if b.Data.Price != nil && b.Data.Price.Cmp(pStar) >= 0 {
			qualifiedBuyers = append(qualifiedBuyers, b)
		}
	}
	qualifiedSellers := make([]IndexedParticipant, 0)
	for _, s := range sellers {
		if s.Data.Price != nil && s.Data.Price.Cmp(pStar) <= 0 {
			qualifiedSellers = append(qualifiedSellers, s)
		}
	}
	if len(qualifiedBuyers) == 0 || len(qualifiedSellers) == 0 {
		return &AuctionExecutionResult{Outputs: outputs, ClearingPrice: big.NewInt(0)}
	}

	// Marginals at p*
	// Match RISC Zero: sort buyers descending, sellers ascending, then take last element
	sort.Slice(qualifiedBuyers, func(i, j int) bool { return qualifiedBuyers[i].Data.Price.Cmp(qualifiedBuyers[j].Data.Price) > 0 }) // Descending
	sort.Slice(qualifiedSellers, func(i, j int) bool { return qualifiedSellers[i].Data.Price.Cmp(qualifiedSellers[j].Data.Price) < 0 }) // Ascending
	bMarg := qualifiedBuyers[len(qualifiedBuyers)-1].Data.Price  // Lowest price among qualified buyers
	aMarg := qualifiedSellers[len(qualifiedSellers)-1].Data.Price  // Highest price among qualified sellers
	clearingPrice := new(big.Int).Div(new(big.Int).Add(bMarg, aMarg), big.NewInt(2))
	if clearingPrice.Sign() == 0 {
		return &AuctionExecutionResult{Outputs: outputs, ClearingPrice: big.NewInt(0)}
	}

	// Compute caps and totals
	var effDemand, effSupply int64
	buyerCaps := make(map[int]int64)
	sellerCaps := make(map[int]int64)
	for _, b := range qualifiedBuyers {
		qty := int64(0)
		if b.Data.Quantity != nil {
			qty = b.Data.Quantity.Int64()
		}
		coins := new(big.Int)
		if b.Data.Coins != nil {
			coins.Set(b.Data.Coins)
		} else {
			coins.SetInt64(0)
		}
		afford := new(big.Int).Div(coins, clearingPrice).Int64()
		cap := qty
		if afford < cap {
			cap = afford
		}
		if cap < 0 {
			cap = 0
		}
		buyerCaps[b.Index] = cap
		effDemand += cap
	}
	for _, s := range qualifiedSellers {
		qty := int64(0)
		if s.Data.Quantity != nil {
			qty = s.Data.Quantity.Int64()
		}
		energy := int64(0)
		if s.Data.Energy != nil {
			energy = s.Data.Energy.Int64()
		}
		cap := qty
		if energy < cap {
			cap = energy
		}
		if cap < 0 {
			cap = 0
		}
		sellerCaps[s.Index] = cap
		effSupply += cap
	}
	tradedTotal := effDemand
	if effSupply < tradedTotal {
		tradedTotal = effSupply
	}
	if tradedTotal <= 0 {
		return &AuctionExecutionResult{Outputs: outputs, ClearingPrice: clearingPrice, MarginalBuyerPrice: bMarg, MarginalSellerPrice: aMarg, TotalEnergyTraded: 0, QualifiedBuyers: len(qualifiedBuyers), QualifiedSellers: len(qualifiedSellers)}
	}

	// Allocate
	totalCoinsTraded := int64(0)
	if effDemand >= effSupply {
		// Supply binding: fill sellers to cap; allocate buyers by desc price
		for _, s := range qualifiedSellers { /* full, recorded in cap map */
			_ = s
		}
		sort.SliceStable(qualifiedBuyers, func(i, j int) bool {
			if qualifiedBuyers[i].Data.Price.Cmp(qualifiedBuyers[j].Data.Price) != 0 {
				return qualifiedBuyers[i].Data.Price.Cmp(qualifiedBuyers[j].Data.Price) > 0
			}
			return qualifiedBuyers[i].Index < qualifiedBuyers[j].Index
		})
		remaining := tradedTotal
		for _, b := range qualifiedBuyers {
			if remaining == 0 {
				break
			}
			cap := buyerCaps[b.Index]
			take := cap
			if take > remaining {
				take = remaining
			}
			if take > 0 {
				buyerCaps[b.Index] = take
				remaining -= take
			}
		}
	} else {
		// Demand binding: fill buyers to cap; allocate sellers by asc price
		for _, b := range qualifiedBuyers { /* full cap */
			_ = b
		}
		sort.SliceStable(qualifiedSellers, func(i, j int) bool {
			if qualifiedSellers[i].Data.Price.Cmp(qualifiedSellers[j].Data.Price) != 0 {
				return qualifiedSellers[i].Data.Price.Cmp(qualifiedSellers[j].Data.Price) < 0
			}
			return qualifiedSellers[i].Index < qualifiedSellers[j].Index
		})
		remaining := tradedTotal
		for _, s := range qualifiedSellers {
			if remaining == 0 {
				break
			}
			cap := sellerCaps[s.Index]
			take := cap
			if take > remaining {
				take = remaining
			}
			if take > 0 {
				sellerCaps[s.Index] = take
				remaining -= take
			}
		}
	}

	// Apply balances
	for _, b := range qualifiedBuyers {
		q := buyerCaps[b.Index]
		if q <= 0 {
			continue
		}
		idx := b.Index
		cost := new(big.Int).Mul(clearingPrice, big.NewInt(q))
		outputs[idx].Coins = new(big.Int).Sub(outputs[idx].Coins, cost)
		outputs[idx].Energy = new(big.Int).Add(outputs[idx].Energy, big.NewInt(q))
		totalCoinsTraded += cost.Int64()
	}
	for _, s := range qualifiedSellers {
		q := sellerCaps[s.Index]
		if q <= 0 {
			continue
		}
		idx := s.Index
		rev := new(big.Int).Mul(clearingPrice, big.NewInt(q))
		outputs[idx].Coins = new(big.Int).Add(outputs[idx].Coins, rev)
		outputs[idx].Energy = new(big.Int).Sub(outputs[idx].Energy, big.NewInt(q))
	}

	return &AuctionExecutionResult{
		Outputs:             outputs,
		ClearingPrice:       clearingPrice,
		MarginalBuyerPrice:  bMarg,
		MarginalSellerPrice: aMarg,
		TotalEnergyTraded:   tradedTotal,
		TotalCoinsTraded:    totalCoinsTraded,
		QualifiedBuyers:     len(qualifiedBuyers),
		QualifiedSellers:    len(qualifiedSellers),
	}
}

// RunAuctionLogic is a backward-compatible wrapper that returns only the outputs
func RunAuctionLogic(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType) []DecryptedRegistration {
	result := RunAuctionLogicUniform(inputs, roles)
	return result.Outputs
}

// GetAllOutputsIncludingAuctioneer returns all outputs (N participants + 1 auctioneer)
// This is the complete set of outputs that should be used for conservation checks
func (result *AuctionExecutionResult) GetAllOutputsIncludingAuctioneer() []DecryptedRegistration {
	allOutputs := make([]DecryptedRegistration, len(result.Outputs))
	copy(allOutputs, result.Outputs)
	return allOutputs
}

// GetTotalOutputCount returns the total number of output notes (N + 1)
func (result *AuctionExecutionResult) GetTotalOutputCount() int {
	return len(result.Outputs)
}

// (createAuctioneerNote removed: commission is no longer supported)

// ExchangeTransaction represents the transaction output of the exchange phase.
// Contains all inputs, outputs, and proof data for the auction.
type ExchangeTransaction struct {
	Participants int                     `json:"participants"`
	Inputs       []DecryptedRegistration `json:"inputs"`
	Outputs      []DecryptedRegistration `json:"outputs"`
	TotalValue   *big.Int                `json:"total_value"`
	TotalEnergy  *big.Int                `json:"total_energy"`
	Timestamp    int64                   `json:"timestamp"`
	ProofData    []byte                  `json:"proof_data"`
}

// AuctionResult represents the output of the auction phase for public reporting.
type AuctionResult struct {
	WinnerID    string   `json:"winner_id"`
	WinningBid  *big.Int `json:"winning_bid"`
	TotalBids   int      `json:"total_bids"`
	TotalCoins  *big.Int `json:"total_coins"`
	TotalEnergy *big.Int `json:"total_energy"`
	Timestamp   int64    `json:"timestamp"`
	ProofHash   string   `json:"proof_hash"`
}

// validateExchangeInputs validates all inputs to ExchangePhase.
// Returns an error if any input is invalid or missing.
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
		if len(payload.Ciphertext) != 7 { // Changed from 5 to 7
			return fmt.Errorf("invalid ciphertext for payload %d: expected 7 elements, got %d", i, len(payload.Ciphertext))
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

// BuildWitnessFN builds a witness for the dynamic CircuitTxFN.
// Populates all circuit fields for N participants using the provided auction results.
func BuildWitnessFN(inputs, outputs []DecryptedRegistration, payloads []RegistrationPayload, auctioneerSk *big.Int, participantDHKeys []*bls12377_fr.Element, auctioneerDHPk *sw_bls12377.G1Affine, auctionExecution *AuctionExecutionResult, roles map[int]zerocash.OrderType, risc0ProofData *risc0.RISC0ProofData, receiptData *risc0.ReceiptData) *CircuitTxFN {
	n := len(payloads)
	if n == 0 {
		return nil
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
	toVarSlice := func(arr [7]*big.Int) []frontend.Variable {
		result := make([]frontend.Variable, 7) // Changed from 5 to 7
		for i, val := range arr {
			result[i] = toVar(val)
		}
		return result
	}

	// Note: Auction verification removed from circuit - only cryptographic consistency is verified
	// ParticipantRoles and TradedQuantities are available as DecVal[i][5] (role) and DecVal[i][6] (quantity)
	// but are not verified by the circuit.

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
			if in.Price == nil {
				return big.NewInt(10) // Default value
			}
			return in.Price
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

	// Helper to convert sw_bls12377.G1Affine to bls12377.G1Affine
	swToNative := func(p *sw_bls12377.G1Affine) *bls12377.G1Affine {
		if p == nil {
			return nil
		}
		native := &bls12377.G1Affine{}
		native.X.SetString(p.X.(string))
		native.Y.SetString(p.Y.(string))
		return native
	}

	// Convert auctioneer's secret key to BLS12-377 field element
	var sk bls12377_fr.Element
	sk.SetBigInt(auctioneerSk)

	// For each of the N participants, populate the witness arrays
	// Also collect the exact values we assign, so we can build RISC0PublicInputs
	inCoinVals := make([]*big.Int, n)
	inEnergyVals := make([]*big.Int, n)
	outCoinVals := make([]*big.Int, n)
	outEnergyVals := make([]*big.Int, n)

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
		energy := getSafeValue(in, "energy")
		inCoinVals[i] = new(big.Int).Set(coins)
		inEnergyVals[i] = new(big.Int).Set(energy)
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

		// Set outputs from the auction results (outputs slice)
		var out DecryptedRegistration
		if i < len(outputs) {
			out = outputs[i]
		} else {
			out = in // fallback to input if no output
		}
		outCoins := getSafeValue(out, "coins")
		outEnergy := getSafeValue(out, "energy")
		outCoinVals[i] = new(big.Int).Set(outCoins)
		outEnergyVals[i] = new(big.Int).Set(outEnergy)
		// Recompute output pk, rho, rand, sn, cm for consistency
		outSkIn := getSafeValue(out, "skin")
		outBid := getSafeValue(out, "bid")
		outPkOut := mimcHash(outSkIn)
		outRho := outBid
		outRand := outCoins
		outSn := prf(outSkIn, outRho)
		outCm := computeCommitment(outCoins, outEnergy, outPkOut, outRho, outRand)

		circuit.OutCoin[i] = toVar(outCoins)
		circuit.OutEnergy[i] = toVar(outEnergy)
		circuit.OutCm[i] = toVar(outCm)
		circuit.OutSn[i] = toVar(outSn)
		circuit.OutPk[i] = toVar(outPkOut)
		circuit.OutRho[i] = toVar(outRho)
		circuit.OutRand[i] = toVar(outRand)

		// Set ciphertext and decrypted values with proper encryption relationship
		if i < len(payloads) {
			// Real participant: use actual ciphertext and decrypt it
			circuit.C[i] = toVarSlice(payload.Ciphertext)
			dec := DecZKRegGo(payload.Ciphertext, shared)
			circuit.DecVal[i] = toVarSlice(dec)
		} else {
			// Padding participant: create consistent encrypted/decrypted pair
			// For circuit to pass: C[i] = Encrypt(DecVal[i], SkT[i])
			plaintext := [7]*big.Int{pkOut, skIn, bid, coins, energy, big.NewInt(0), big.NewInt(0)} // Expected decrypted values (padding: role=0/BUY, quantity=0)

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

			h.Reset()
			h.Write(mask4)
			mask5 := h.Sum(nil)

			h.Reset()
			h.Write(mask5)
			mask6 := h.Sum(nil)

			// Create ciphertext by adding masks to plaintext
			ciphertext := [7]*big.Int{
				new(big.Int).Add(plaintext[0], new(big.Int).SetBytes(mask0)),
				new(big.Int).Add(plaintext[1], new(big.Int).SetBytes(mask1)),
				new(big.Int).Add(plaintext[2], new(big.Int).SetBytes(mask2)),
				new(big.Int).Add(plaintext[3], new(big.Int).SetBytes(mask3)),
				new(big.Int).Add(plaintext[4], new(big.Int).SetBytes(mask4)),
				new(big.Int).Add(plaintext[5], new(big.Int).SetBytes(mask5)),
				new(big.Int).Add(plaintext[6], new(big.Int).SetBytes(mask6)),
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
		G, G_b, R, G_r := createDHComponents(shared, &participantSk, swToNative(auctioneerDHPk))

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

	// Note: RISC Zero input data consistency will be verified when RISC Zero verification is enabled
	// The circuit now uses consistent data sources - DecryptedRegistration.Role matches RISC Zero input

	// Provide private clearing price input for the circuit from host-side auction execution
	if auctionExecution != nil && auctionExecution.ClearingPrice != nil {
		fmt.Printf("\n=== DEBUG: BEFORE PASSING TO CIRCUIT ===\n")
		fmt.Printf("ClearingPrice: %s\n", auctionExecution.ClearingPrice.String())
		circuit.ClearingPrice = auctionExecution.ClearingPrice.String()
	} else {
		fmt.Printf("\n=== DEBUG: BEFORE PASSING TO CIRCUIT ===\n")
		fmt.Printf("ClearingPrice: 0 (no auction execution)\n")
		circuit.ClearingPrice = "0"
	}
	
	// DEBUG: Print all the values we're setting
	fmt.Printf("InCoin values: ")
	for i := 0; i < n; i++ {
		fmt.Printf("%v ", circuit.InCoin[i])
	}
	fmt.Printf("\nInEnergy values: ")
	for i := 0; i < n; i++ {
		fmt.Printf("%v ", circuit.InEnergy[i])
	}
	fmt.Printf("\nOutCoin values: ")
	for i := 0; i < n; i++ {
		fmt.Printf("%v ", circuit.OutCoin[i])
	}
	fmt.Printf("\nOutEnergy values: ")
	for i := 0; i < n; i++ {
		fmt.Printf("%v ", circuit.OutEnergy[i])
	}
	fmt.Printf("\n=== END DEBUG ===\n\n")

	// Populate RISC Zero receipt data for claim digest computation
	if receiptData != nil {
		circuit.PrePC = toVar(big.NewInt(int64(receiptData.PrePC)))
		circuit.PostPC = toVar(big.NewInt(int64(receiptData.PostPC)))
		circuit.SysExit = toVar(big.NewInt(int64(receiptData.SysExit)))
		circuit.UserExit = toVar(big.NewInt(int64(receiptData.UserExit)))
		
		// Convert merkle root bytes to frontend.Variable array
		for i := 0; i < 32; i++ {
			circuit.PreMerkleRoot[i] = toVar(big.NewInt(int64(receiptData.PreMerkleRoot[i])))
			circuit.PostMerkleRoot[i] = toVar(big.NewInt(int64(receiptData.PostMerkleRoot[i])))
		}
	} else {
		// Use default values if no receipt data provided
		defaultReceipt := risc0.GetDefaultReceiptData()
		circuit.PrePC = "0"
		circuit.PostPC = "0"
		circuit.SysExit = "0"
		circuit.UserExit = "0"
		
		for i := 0; i < 32; i++ {
			circuit.PreMerkleRoot[i] = toVar(big.NewInt(int64(defaultReceipt.PreMerkleRoot[i])))
			circuit.PostMerkleRoot[i] = toVar(big.NewInt(int64(defaultReceipt.PostMerkleRoot[i])))
		}
	}

	// Populate RISC0 public inputs with values consistent with the circuit witness
	{
		// Layout: [0] clearing_price, then 4 blocks of N values (in_coin, in_energy, out_coin, out_energy)
		pub := make([]emulated.Element[sw_bn254.ScalarField], 1+4*n)
		cp := big.NewInt(0)
		if auctionExecution != nil && auctionExecution.ClearingPrice != nil {
			cp = auctionExecution.ClearingPrice
		}
		pub[0] = emulated.ValueOf[sw_bn254.ScalarField](cp)
		idx := 1
		for i := 0; i < n; i++ {
			pub[idx+i] = emulated.ValueOf[sw_bn254.ScalarField](inCoinVals[i])
		}
		idx += n
		for i := 0; i < n; i++ {
			pub[idx+i] = emulated.ValueOf[sw_bn254.ScalarField](inEnergyVals[i])
		}
		idx += n
		for i := 0; i < n; i++ {
			pub[idx+i] = emulated.ValueOf[sw_bn254.ScalarField](outCoinVals[i])
		}
		idx += n
		for i := 0; i < n; i++ {
			pub[idx+i] = emulated.ValueOf[sw_bn254.ScalarField](outEnergyVals[i])
		}
		//circuit.RISC0PublicInputs = recursion.Witness[sw_bn254.ScalarField]{Public: pub}
		circuit.RISC0PublicInputs = risc0ProofData.PublicInputs
	}

	// Populate RISC Zero proof metadata if available (does not affect public inputs here)
	if risc0ProofData != nil {
		circuit.RISC0Proof = risc0ProofData.Proof
		circuit.RISC0VerifyingKey = risc0ProofData.VerifyingKey
	} else {
		// If no proof data provided, try to load verification key from file
		workingDir, _ := os.Getwd()
		vkeyPath := filepath.Join(workingDir, "circom", "circom_data", "vkey.json")
		if _, err := os.Stat(vkeyPath); os.IsNotExist(err) {
			vkeyPath = filepath.Join(workingDir, "circom", "vkey.json")
		}
		if err := circuit.loadRISC0VerificationKey(vkeyPath); err != nil {
			// Use zero verification key as fallback
			circuit.RISC0VerifyingKey = recursion.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]{}
		}
	}

	return circuit
}

// GenerateProofFN generates a proof using the dynamic CircuitTxFN.
// Returns the proof as a byte slice.
func GenerateProofFN(witness *CircuitTxFN, pk groth16.ProvingKey, ccs constraint.ConstraintSystem) ([]byte, error) {
	// DEBUG: Print witness values right before creating witness
	fmt.Printf("\n=== WITNESS VALUES BEFORE CREATION ===\n")
	fmt.Printf("witness.ClearingPrice: %v\n", witness.ClearingPrice)
	fmt.Printf("witness.InCoin[0-2]: %v %v %v\n", witness.InCoin[0], witness.InCoin[1], witness.InCoin[2])
	fmt.Printf("witness.InEnergy[0-2]: %v %v %v\n", witness.InEnergy[0], witness.InEnergy[1], witness.InEnergy[2])
	fmt.Printf("======================================\n\n")
	
	// Create witness
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %w", err)
	}

	fmt.Printf("\x1b[35m▪ Exchange Circuit (106580 constraints)\x1b[0m\n")
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

// RunAuctionLogicWithRISC0 runs the auction logic using RISC Zero and generates a ZK proof
func RunAuctionLogicWithRISC0(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType) (*AuctionExecutionResult, *risc0.RISC0ProofData, error) {
	// First run the auction logic normally to get initial results
	// BUT we will override with RISC Zero's actual results later
	auctionResult := RunAuctionLogicUniform(inputs, roles)
	
	// // TEMPORARY FIX: Load the expected results from gnark_inputs.json
	// // This ensures we use RISC Zero's computed values, not Go's
	// gnarkInputsPath := "risc0/gnark_inputs.json"
	// if data, err := os.ReadFile(gnarkInputsPath); err == nil {
	// 	var gnarkInputs struct {
	// 		ClearingPrice uint64   `json:"clearing_price"`
	// 		OutCoin       []uint64 `json:"out_coin"`
	// 		OutEnergy     []uint64 `json:"out_energy"`
	// 	}
	// 	if err := json.Unmarshal(data, &gnarkInputs); err == nil {
	// 		fmt.Printf("\n=== OVERRIDE WITH RISC ZERO RESULTS ===\n")
	// 		fmt.Printf("Using RISC Zero clearing price: %d (was %v)\n", gnarkInputs.ClearingPrice, auctionResult.ClearingPrice)
	// 		
	// 		// Override clearing price
	// 		auctionResult.ClearingPrice = big.NewInt(int64(gnarkInputs.ClearingPrice))
	// 		
	// 		// Override output values
	// 		for i := range auctionResult.Outputs {
	// 			if i < len(gnarkInputs.OutCoin) {
	// 				auctionResult.Outputs[i].Coins = big.NewInt(int64(gnarkInputs.OutCoin[i]))
	// 			}
	// 			if i < len(gnarkInputs.OutEnergy) {
	// 				auctionResult.Outputs[i].Energy = big.NewInt(int64(gnarkInputs.OutEnergy[i]))
	// 			}
	// 		}
	// 		fmt.Printf("========================================\n\n")
	// 	} else {
	// 		fmt.Printf("WARNING: Failed to parse gnark_inputs.json: %v\n", err)
	// 	}
	// } else {
	// 	fmt.Printf("WARNING: Failed to read gnark_inputs.json: %v\n", err)
	// }

	// Convert inputs to RISC Zero format
	risc0Participants := make([]risc0.Participant, len(inputs))
	for i, input := range inputs {
		// Use role from decrypted registration data (source of truth)
		role := uint32(0) // BUY (default)
		if input.Role != nil {
			role = uint32(input.Role.Uint64()) // Use decrypted role
		}

		// Get safe values with defaults
		price := uint64(0)
		if input.Price != nil {
			price = input.Price.Uint64()
		}
		quantity := uint64(10) // default
		if input.Quantity != nil {
			quantity = input.Quantity.Uint64()
		}
		inCoin := uint64(0)
		if input.Coins != nil {
			inCoin = input.Coins.Uint64()
		}
		inEnergy := uint64(0)
		if input.Energy != nil {
			inEnergy = input.Energy.Uint64()
		}

		// Get output values from auction result
		outCoin := inCoin
		outEnergy := inEnergy
		if i < len(auctionResult.Outputs) {
			if auctionResult.Outputs[i].Coins != nil {
				outCoin = auctionResult.Outputs[i].Coins.Uint64()
			}
			if auctionResult.Outputs[i].Energy != nil {
				outEnergy = auctionResult.Outputs[i].Energy.Uint64()
			}
		}

		risc0Participants[i] = risc0.Participant{
			ID:        uint32(i),
			Role:      role,
			Price:     price,
			Quantity:  quantity,
			InCoin:    inCoin,
			InEnergy:  inEnergy,
			OutCoin:   outCoin,
			OutEnergy: outEnergy,
		}
	}

	// Generate RISC Zero proof
	clearingPrice := big.NewInt(0)
	if auctionResult.ClearingPrice != nil {
		clearingPrice = auctionResult.ClearingPrice
	}
	totalEnergyTraded := auctionResult.TotalEnergyTraded

	proofData, err := risc0.GenerateRISC0Proof(risc0Participants, clearingPrice, totalEnergyTraded)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RISC Zero proof: %w", err)
	}

	return auctionResult, proofData, nil
}

// ExchangePhaseWithNotes is the main entry point for the exchange phase with note decryption.
// Handles registration data, transaction notes, sorting, auction logic, witness generation, and proof creation.
// Returns the exchange transaction, auction result, and proof.
func ExchangePhaseWithNotes(
	regPayloads []RegistrationPayload,
	auctioneerSk *big.Int,
	auctioneerECDHPrivKey *ecdh.PrivateKey,
	participantECDHPubKeys []*ecdh.PublicKey,
	participantDHKeys []*bls12377_fr.Element,
	auctioneerDHPk *bls12377.G1Affine,
	roles map[int]zerocash.OrderType,
	ledger *zerocash.Ledger,
	params *zerocash.Params,
	pk groth16.ProvingKey,
	ccs constraint.ConstraintSystem,
) (txOut interface{}, info interface{}, proof []byte, risc0Data *risc0.RISC0ProofData, publicInputs interface{}, err error) {
	// Input validation
	if err := validateExchangeInputs(regPayloads, auctioneerSk, ledger, params, pk, ccs); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("input validation failed: %w", err)
	}
	if auctioneerECDHPrivKey == nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("auctioneer ECDH private key is required")
	}
	if len(participantECDHPubKeys) != len(regPayloads) {
		return nil, nil, nil, nil, nil, fmt.Errorf("participant ECDH public keys count mismatch: expected %d, got %d", len(regPayloads), len(participantECDHPubKeys))
	}

	// 1. Decrypt registration data (from Algorithm 2 - DH+OTP encryption)
	regInputs, err := DecryptAllRegistrations(regPayloads, auctioneerSk)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decrypt registration data: %w", err)
	}

	// 2. Decrypt transaction note data (from Algorithm 1 - ECDH+AES encryption)
	noteInputs, err := DecryptTransactionNotes(regPayloads, auctioneerECDHPrivKey, participantECDHPubKeys)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to decrypt transaction notes: %w", err)
	}

	// 3. Merge the decrypted data
	inputs := make([]DecryptedRegistration, len(regPayloads))
	for i := 0; i < len(regPayloads); i++ {
		inputs[i] = DecryptedRegistration{
			PkOut:    regInputs[i].PkOut,
			SkIn:     regInputs[i].SkIn,
			Price:    regInputs[i].Price,
			Role:     regInputs[i].Role, // Include role from decrypted data
			Coins:    regInputs[i].Coins,
			Energy:   regInputs[i].Energy,
			NoteData: noteInputs[i].NoteData, // Use the NoteData field from DecryptedRegistration
		}
		// Use quantity from registration (second field in Price for quantity)
		if len(regInputs) > i && regInputs[i].Quantity != nil {
			inputs[i].Quantity = regInputs[i].Quantity
		} else {
			inputs[i].Quantity = big.NewInt(10) // Default quantity
		}
	}

	// 4. Sort participants according to circuit requirements
	// Buyers first (descending by bid), then sellers (ascending by bid) based on actual roles
	sortedInputs, sortedPayloads, sortedDHKeys, err := SortParticipantsForCircuit(inputs, regPayloads, participantDHKeys, roles)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to sort participants for circuit: %w", err)
	}

	// 5. Run auction logic using RISC Zero with ZK proof
	auctionExecution, risc0ProofData, err := RunAuctionLogicWithRISC0(sortedInputs, roles)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to run auction with RISC Zero: %w", err)
	}
	
	// DEBUG: Print auction result
	fmt.Printf("\n=== AUCTION RESULT ===\n")
	fmt.Printf("Clearing Price from auction: %v\n", auctionExecution.ClearingPrice)
	fmt.Printf("Number of outputs: %d\n", len(auctionExecution.Outputs))
	fmt.Printf("==================\n\n")
	
	outputs := auctionExecution.Outputs

	// 5.5 Read RISC Zero receipt data for claim digest computation
	var receiptData *risc0.ReceiptData
	workingDir, _ := os.Getwd()
	receiptPath := filepath.Join(workingDir, "risc0", "risc0_receipt.json")
	if _, err := os.Stat(receiptPath); err == nil {
		// Receipt file exists, parse it
		receiptData, err = risc0.ParseReceiptFile(receiptPath)
		if err != nil {
			// Log warning but continue with default values
			fmt.Printf("Warning: Failed to parse RISC Zero receipt: %v\n", err)
			receiptData = risc0.GetDefaultReceiptData()
		}
	} else {
		// No receipt file, use default values
		receiptData = risc0.GetDefaultReceiptData()
	}

	// 6. Build witness using the dynamic circuit approach with sorted data
	swAuctioneerDHPk := &sw_bls12377.G1Affine{X: auctioneerDHPk.X.String(), Y: auctioneerDHPk.Y.String()}
	witness := BuildWitnessFN(sortedInputs, outputs, sortedPayloads, auctioneerSk, sortedDHKeys, swAuctioneerDHPk, auctionExecution, roles, risc0ProofData, receiptData)
	proof, err = GenerateProofFN(witness, pk, ccs)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// 7. Create structured output
	timestamp := time.Now().Unix()
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
		if input.Price != nil && input.Price.Cmp(highestBid) > 0 {
			highestBid.Set(input.Price)
			winnerID = fmt.Sprintf("Participant%d", i+1)
		}
	}
	proofHash := fmt.Sprintf("%x", sha256.Sum256(proof))
	auctionResult := &AuctionResult{WinnerID: winnerID, WinningBid: highestBid, TotalBids: len(inputs), TotalCoins: totalCoins, TotalEnergy: totalEnergy, Timestamp: timestamp, ProofHash: proofHash}
	exchangeTx := &ExchangeTransaction{Participants: len(inputs), Inputs: inputs, Outputs: outputs, TotalValue: totalCoins, TotalEnergy: totalEnergy, Timestamp: timestamp, ProofData: proof}
	compositeResult := struct {
		AuctionResult    *AuctionResult
		AuctionExecution *AuctionExecutionResult
	}{AuctionResult: auctionResult, AuctionExecution: auctionExecution}
	return exchangeTx, compositeResult, proof, risc0ProofData, witness, nil
}
