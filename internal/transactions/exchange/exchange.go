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

// RegistrationPayload represents a participant's encrypted registration data for the auction phase.
// Contains the ciphertext (encrypted registration fields), the participant's public key (for DH),
// and optionally the encrypted note data from CreateTx.
type RegistrationPayload struct {
	Ciphertext [5]*big.Int           // (pkOut, skIn, bid, coins, energy)
	PubKey     *sw_bls12377.G1Affine // Participant's public key (for DH)
	TxNoteData []byte                // Encrypted note data from CreateTx (new field)
}

// DecryptedRegistration holds the decrypted registration data for a participant.
// This is the canonical form used for auction logic and witness generation.
type DecryptedRegistration struct {
	PkOut    *big.Int       // Output public key
	SkIn     *big.Int       // Input secret key
	Price    *big.Int       // Order price (bid for buyers, ask for sellers)
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
			PkOut:    decrypted[0],   // pk^out
			SkIn:     decrypted[1],   // sk^in
			Price:    decrypted[2],   // price (formerly bid)
			Quantity: big.NewInt(10), // TODO: quantity not yet encrypted, using default
			Coins:    decrypted[3],   // coins
			Energy:   decrypted[4],   // energy
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
// Returns sorted inputs, payloads, and participantDHKeys.
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

	// Sort buyers in descending order by price (highest price first)
	sort.Slice(buyers, func(i, j int) bool {
		priceI := buyers[i].Input.Price
		priceJ := buyers[j].Input.Price
		if priceI == nil && priceJ == nil {
			return false
		}
		if priceI == nil {
			return false
		}
		if priceJ == nil {
			return true
		}
		return priceI.Cmp(priceJ) > 0 // Descending order
	})

	// Sort sellers in ascending order by price (lowest ask first)
	sort.Slice(sellers, func(i, j int) bool {
		priceI := sellers[i].Input.Price
		priceJ := sellers[j].Input.Price
		if priceI == nil && priceJ == nil {
			return false
		}
		if priceI == nil {
			return true
		}
		if priceJ == nil {
			return false
		}
		return priceI.Cmp(priceJ) < 0 // Ascending order
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

// DecZKRegGo implements the same decryption logic as the circuit's DecZKReg function.
// Used for off-circuit decryption of registration payloads.
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

// RunAuctionLogic implements a simple double auction mechanism
// 1. Sort buyers (descending) and sellers (ascending) based on actual roles
// 2. Find intersection point where buyer_bid >= seller_ask
// 3. Calculate clearing price as average of intersecting bid/ask
// 4. Execute trades for all qualifying participants at clearing price
func RunAuctionLogic(inputs []DecryptedRegistration, roles map[int]zerocash.OrderType) []DecryptedRegistration {
	if len(inputs) == 0 {
		return inputs
	}

	numParticipants := len(inputs)

	// Create output array (copy of inputs initially)
	outputs := make([]DecryptedRegistration, len(inputs))
	copy(outputs, inputs)

	// Split into buyers and sellers with their original indices based on actual roles
	type IndexedParticipant struct {
		Index int
		Data  DecryptedRegistration
	}

	var buyers, sellers []IndexedParticipant

	// Use actual roles from configuration, not assumptions about index ranges
	for i := 0; i < numParticipants; i++ {
		participantRole, exists := roles[i]
		if !exists {
			// Default to SELL if role not specified (conservative approach)
			participantRole = zerocash.SELL
		}

		if participantRole == zerocash.BUY {
			buyers = append(buyers, IndexedParticipant{Index: i, Data: inputs[i]})
		} else {
			sellers = append(sellers, IndexedParticipant{Index: i, Data: inputs[i]})
		}
	}

	// Sort buyers by price (descending - highest bid first)
	sort.Slice(buyers, func(i, j int) bool {
		if buyers[i].Data.Price == nil && buyers[j].Data.Price == nil {
			return false
		}
		if buyers[i].Data.Price == nil {
			return false
		}
		if buyers[j].Data.Price == nil {
			return true
		}
		return buyers[i].Data.Price.Cmp(buyers[j].Data.Price) > 0
	})

	// Sort sellers by price (ascending - lowest ask first)
	sort.Slice(sellers, func(i, j int) bool {
		if sellers[i].Data.Price == nil && sellers[j].Data.Price == nil {
			return false
		}
		if sellers[i].Data.Price == nil {
			return true
		}
		if sellers[j].Data.Price == nil {
			return false
		}
		return sellers[i].Data.Price.Cmp(sellers[j].Data.Price) < 0
	})

	// Helper function to find intersection point using proper step-wise curve logic
	findClearingPrice := func(buyers, sellers []IndexedParticipant) (*big.Int, bool) {
		if len(buyers) == 0 || len(sellers) == 0 {
			return nil, false
		}

		// Build cumulative step-wise curves
		buyerSteps := make([]struct {
			price         *big.Int
			cumulativeQty int64
		}, 0)
		sellerSteps := make([]struct {
			price         *big.Int
			cumulativeQty int64
		}, 0)

		// Build buyer steps (demand curve - descending prices)
		var buyerCumQty int64 = 0
		for _, buyer := range buyers {
			if buyer.Data.Price != nil && buyer.Data.Quantity != nil {
				buyerCumQty += buyer.Data.Quantity.Int64()
				buyerSteps = append(buyerSteps, struct {
					price         *big.Int
					cumulativeQty int64
				}{
					price: buyer.Data.Price, cumulativeQty: buyerCumQty,
				})
			}
		}

		// Build seller steps (supply curve - ascending prices)
		var sellerCumQty int64 = 0
		for _, seller := range sellers {
			if seller.Data.Price != nil && seller.Data.Quantity != nil {
				sellerCumQty += seller.Data.Quantity.Int64()
				sellerSteps = append(sellerSteps, struct {
					price         *big.Int
					cumulativeQty int64
				}{
					price: seller.Data.Price, cumulativeQty: sellerCumQty,
				})
			}
		}

		// Find intersection: last step where buyer_price >= seller_price
		var lastValidBuyerPrice, lastValidSellerPrice *big.Int
		buyerIdx, sellerIdx := 0, 0

		for buyerIdx < len(buyerSteps) && sellerIdx < len(sellerSteps) {
			buyerStep := buyerSteps[buyerIdx]
			sellerStep := sellerSteps[sellerIdx]

			// Check if curves still intersect at this quantity level
			if buyerStep.price.Cmp(sellerStep.price) >= 0 {
				// Valid intersection - save these prices
				lastValidBuyerPrice = buyerStep.price
				lastValidSellerPrice = sellerStep.price

				// Move to next step based on cumulative quantity
				if buyerStep.cumulativeQty <= sellerStep.cumulativeQty {
					buyerIdx++
				} else {
					sellerIdx++
				}
			} else {
				// No more intersections
				break
			}
		}

		if lastValidBuyerPrice != nil && lastValidSellerPrice != nil {
			// Clearing price = average of last intersecting step prices
			// Note: Using integer division which rounds DOWN (truncates fractional part)
			sum := new(big.Int).Add(lastValidBuyerPrice, lastValidSellerPrice)
			clearingPrice := new(big.Int).Div(sum, big.NewInt(2))
			return clearingPrice, true
		}

		return nil, false
	}

	// Helper function to execute trades at clearing price with proper market clearing
	executeTradesAtClearingPrice := func(buyers, sellers []IndexedParticipant, clearingPrice *big.Int) {
		// Find qualifying buyers (bid >= clearing price)
		var qualifiedBuyers []IndexedParticipant
		for _, buyer := range buyers {
			if buyer.Data.Price != nil && buyer.Data.Price.Cmp(clearingPrice) >= 0 {
				qualifiedBuyers = append(qualifiedBuyers, buyer)
			}
		}

		// Find qualifying sellers (ask <= clearing price)
		var qualifiedSellers []IndexedParticipant
		for _, seller := range sellers {
			if seller.Data.Price != nil && seller.Data.Price.Cmp(clearingPrice) <= 0 {
				qualifiedSellers = append(qualifiedSellers, seller)
			}
		}

		fmt.Printf("Qualified buyers: %d, Qualified sellers: %d\n", len(qualifiedBuyers), len(qualifiedSellers))

		// Calculate total qualified demand and supply
		var totalDemand, totalSupply int64
		for _, buyer := range qualifiedBuyers {
			quantity := buyer.Data.Quantity
			if quantity == nil {
				quantity = big.NewInt(10) // Default trading quantity
			}
			totalDemand += quantity.Int64()
		}

		for _, seller := range qualifiedSellers {
			quantity := seller.Data.Quantity
			if quantity == nil {
				quantity = big.NewInt(10) // Default trading quantity
			}
			totalSupply += quantity.Int64()
		}

		// Market clearing: trade the minimum of total demand and supply
		tradeableQuantity := totalDemand
		if totalSupply < totalDemand {
			tradeableQuantity = totalSupply
		}

		fmt.Printf("Market clearing: Total demand=%d, Total supply=%d, Tradeable=%d\n",
			totalDemand, totalSupply, tradeableQuantity)

		if tradeableQuantity <= 0 {
			fmt.Printf("No trading occurs - zero tradeable quantity\n")
			return
		}

		// Priority-based allocation using price-time priority
		// Sort buyers by price (descending) - higher bidders get priority
		sort.Slice(qualifiedBuyers, func(i, j int) bool {
			if qualifiedBuyers[i].Data.Price.Cmp(qualifiedBuyers[j].Data.Price) != 0 {
				return qualifiedBuyers[i].Data.Price.Cmp(qualifiedBuyers[j].Data.Price) > 0
			}
			// Tie-breaker: original index (time priority)
			return qualifiedBuyers[i].Index < qualifiedBuyers[j].Index
		})

		// Sort sellers by price (ascending) - lower offers get priority
		sort.Slice(qualifiedSellers, func(i, j int) bool {
			if qualifiedSellers[i].Data.Price.Cmp(qualifiedSellers[j].Data.Price) != 0 {
				return qualifiedSellers[i].Data.Price.Cmp(qualifiedSellers[j].Data.Price) < 0
			}
			// Tie-breaker: original index (time priority)
			return qualifiedSellers[i].Index < qualifiedSellers[j].Index
		})

		// Execute trades with proper quantity allocation
		var totalEnergyTraded int64 = 0
		var totalCoinsTraded int64 = 0

		// Allocate to buyers (demand side)
		remainingDemand := tradeableQuantity
		buyerAllocation := make(map[int]int64) // buyer index -> allocated quantity

		for _, buyer := range qualifiedBuyers {
			if remainingDemand <= 0 {
				break
			}

			quantity := buyer.Data.Quantity
			if quantity == nil {
				quantity = big.NewInt(10)
			}
			desiredQty := quantity.Int64()

			// Allocate up to desired quantity or remaining demand
			allocatedQty := desiredQty
			if allocatedQty > remainingDemand {
				allocatedQty = remainingDemand
			}

			buyerAllocation[buyer.Index] = allocatedQty
			remainingDemand -= allocatedQty
		}

		// Allocate to sellers (supply side)
		remainingSupply := tradeableQuantity
		sellerAllocation := make(map[int]int64) // seller index -> allocated quantity

		for _, seller := range qualifiedSellers {
			if remainingSupply <= 0 {
				break
			}

			quantity := seller.Data.Quantity
			if quantity == nil {
				quantity = big.NewInt(10)
			}
			desiredQty := quantity.Int64()

			// Allocate up to desired quantity or remaining supply
			allocatedQty := desiredQty
			if allocatedQty > remainingSupply {
				allocatedQty = remainingSupply
			}

			sellerAllocation[seller.Index] = allocatedQty
			remainingSupply -= allocatedQty
		}

		// Execute buyer trades
		for _, buyer := range qualifiedBuyers {
			allocatedQty := buyerAllocation[buyer.Index]
			if allocatedQty <= 0 {
				continue
			}

			idx := buyer.Index
			tradingCost := new(big.Int).Mul(clearingPrice, big.NewInt(allocatedQty))

			// Buyer: lose coins, gain energy
			outputs[idx].Coins = new(big.Int).Sub(outputs[idx].Coins, tradingCost)
			outputs[idx].Energy = new(big.Int).Add(outputs[idx].Energy, big.NewInt(allocatedQty))

			totalEnergyTraded += allocatedQty
			totalCoinsTraded += tradingCost.Int64()

			fmt.Printf("Buyer %d: paid %v coins for %d energy at price %v\n",
				idx, tradingCost, allocatedQty, clearingPrice)
		}

		// Execute seller trades
		for _, seller := range qualifiedSellers {
			allocatedQty := sellerAllocation[seller.Index]
			if allocatedQty <= 0 {
				continue
			}

			idx := seller.Index
			tradingRevenue := new(big.Int).Mul(clearingPrice, big.NewInt(allocatedQty))

			// Seller: gain coins, lose energy
			outputs[idx].Coins = new(big.Int).Add(outputs[idx].Coins, tradingRevenue)
			outputs[idx].Energy = new(big.Int).Sub(outputs[idx].Energy, big.NewInt(allocatedQty))

			fmt.Printf("Seller %d: sold %d energy for %v coins at price %v\n",
				idx, allocatedQty, tradingRevenue, clearingPrice)
		}

		// Verification: ensure conservation laws
		fmt.Printf("📊 MARKET SUMMARY:\n")
		fmt.Printf("   Total energy traded: %d units\n", totalEnergyTraded)
		fmt.Printf("   Total coins exchanged: %d coins\n", totalCoinsTraded)
		fmt.Printf("   Average execution price: %v coins/unit\n", clearingPrice)

		// Sanity check: all allocations should sum to tradeable quantity
		var totalBuyerAllocation, totalSellerAllocation int64
		for _, qty := range buyerAllocation {
			totalBuyerAllocation += qty
		}
		for _, qty := range sellerAllocation {
			totalSellerAllocation += qty
		}

		if totalBuyerAllocation != totalSellerAllocation || totalBuyerAllocation != tradeableQuantity {
			fmt.Printf("⚠️  CONSERVATION ERROR: Buyer allocation=%d, Seller allocation=%d, Expected=%d\n",
				totalBuyerAllocation, totalSellerAllocation, tradeableQuantity)
		} else {
			fmt.Printf("✅ Conservation verified: %d units traded on both sides\n", tradeableQuantity)
		}
	}

	// Find intersection point
	clearingPrice, tradingOccurs := findClearingPrice(buyers, sellers)

	if !tradingOccurs {
		fmt.Printf("Auction debug: No intersection found - no trading occurs\n")
		return outputs
	}

	fmt.Printf("Auction debug: Clearing price found = %v\n", clearingPrice)

	// Execute trades for qualifying participants
	executeTradesAtClearingPrice(buyers, sellers, clearingPrice)

	return outputs
}

/*
// COMMENTED OUT: Original auction logic (not correct, will be reworked later)
// RunAuctionLogic implements the same auction logic as the circuit.
// This matches the circuit's clearing price mechanism exactly.
// Input must be pre-sorted by SortParticipantsForCircuit.
// Returns a slice of DecryptedRegistration with updated coin/energy balances for qualified traders.
func RunAuctionLogic(inputs []DecryptedRegistration) []DecryptedRegistration {
	if len(inputs) == 0 {
		return inputs
	}

	numParticipants := len(inputs)
	halfN := numParticipants / 2

	// Create output array (copy of inputs initially)
	outputs := make([]DecryptedRegistration, len(inputs))
	copy(outputs, inputs)

	// Define clearing price as the price of buyer number N/4 (matches circuit logic)
	clearingPriceIdx := halfN / 2
	if clearingPriceIdx >= len(inputs) || inputs[clearingPriceIdx].Price == nil {
		return outputs // No clearing price available
	}
	clearingPrice := new(big.Int).Set(inputs[clearingPriceIdx].Price)

	// Fixed trading volume (same as circuit TRADING_VOLUME constant)
	tradingVolume := big.NewInt(TRADING_VOLUME)

	// Process trading for all participants (matches circuit logic)
	fmt.Printf("Auction debug: clearingPrice=%v, tradingVolume=%v\n", clearingPrice, tradingVolume)
	for i := 0; i < numParticipants; i++ {
		if i < halfN {
			// This is a buyer (index 0 to N/2-1)
			// Buyer qualifies if their bid >= clearing price
			qualified := inputs[i].Price != nil && inputs[i].Price.Cmp(clearingPrice) >= 0
			fmt.Printf("Buyer %d: bid=%v, clearing=%v, qualified=%v, inEnergy=%v\n", i, inputs[i].Price, clearingPrice, qualified, inputs[i].Energy)

			if qualified {
				// Calculate trading cost
				tradingCost := new(big.Int).Mul(clearingPrice, tradingVolume)

				// Apply trading: buyer loses coins, gains energy (assign new values)
				outputs[i].Coins = new(big.Int).Sub(inputs[i].Coins, tradingCost)
				outputs[i].Energy = new(big.Int).Add(inputs[i].Energy, tradingVolume)
				fmt.Printf("  -> Updated: outCoins=%v, outEnergy=%v\n", outputs[i].Coins, outputs[i].Energy)
			} else {
				fmt.Printf("  -> Not qualified, keeping original values\n")
			}
		} else {
			// This is a seller (index N/2 to N-1)
			// Seller qualifies if their ask <= clearing price
			qualified := inputs[i].Price != nil && inputs[i].Price.Cmp(clearingPrice) <= 0
			fmt.Printf("Seller %d: ask=%v, clearing=%v, qualified=%v, inEnergy=%v\n", i, inputs[i].Price, clearingPrice, qualified, inputs[i].Energy)

			if qualified {
				// Calculate trading revenue
				tradingRevenue := new(big.Int).Mul(clearingPrice, tradingVolume)

				// Apply trading: seller gains coins, loses energy (assign new values)
				outputs[i].Coins = new(big.Int).Add(inputs[i].Coins, tradingRevenue)
				outputs[i].Energy = new(big.Int).Sub(inputs[i].Energy, tradingVolume)
				fmt.Printf("  -> Updated: outCoins=%v, outEnergy=%v\n", outputs[i].Coins, outputs[i].Energy)
			} else {
				fmt.Printf("  -> Not qualified, keeping original values\n")
			}
		}
	}

	return outputs
}
*/

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

// BuildWitnessFN builds a witness for the dynamic CircuitTxFN.
// Populates all circuit fields for N participants using the provided auction results.
func BuildWitnessFN(inputs, outputs []DecryptedRegistration, payloads []RegistrationPayload, auctioneerSk *big.Int, participantDHKeys []*bls12377_fr.Element, auctioneerDHPk *sw_bls12377.G1Affine) *CircuitTxFN {
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

	return circuit
}

// GenerateProofFN generates a proof using the dynamic CircuitTxFN.
// Returns the proof as a byte slice.
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
			Price:    regInputs[i].Price,
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
		if sortedInputs[i].Price != nil {
			fmt.Printf("%s ", sortedInputs[i].Price.String())
		} else {
			fmt.Printf("nil ")
		}
	}
	fmt.Println()

	fmt.Print("Sellers: ")
	for i := halfN; i < len(sortedInputs); i++ {
		if sortedInputs[i].Price != nil {
			fmt.Printf("%s ", sortedInputs[i].Price.String())
		} else {
			fmt.Printf("nil ")
		}
	}
	fmt.Printf("\n")

	// 5. Run auction logic with sorted data - sophisticated sealed-bid double auction mechanism
	outputs := RunAuctionLogic(sortedInputs, roles)

	// 6. Build witness using the dynamic circuit approach with sorted data
	// Convert auctioneerDHPk from *bls12377.G1Affine to *sw_bls12377.G1Affine
	swAuctioneerDHPk := &sw_bls12377.G1Affine{
		X: auctioneerDHPk.X.String(),
		Y: auctioneerDHPk.Y.String(),
	}
	witness := BuildWitnessFN(sortedInputs, outputs, sortedPayloads, auctioneerSk, sortedDHKeys, swAuctioneerDHPk)
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
		if input.Price != nil && input.Price.Cmp(highestBid) > 0 {
			highestBid.Set(input.Price)
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
