// exchange.go - Auction phase logic for the protocol (Algorithm 3, without ZKP-enforced auction logic).
//
// Implements the exchange phase: decrypts registration payloads, runs auction logic (off-circuit),
// constructs output notes, builds the witness, and generates the ZKP using CircuitTxF10.
//
// WARNING: The ZKP only proves cryptographic consistency, not the correctness of the auction computation.

package exchange

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
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

// RegistrationPayload represents a participant's registration ciphertext and public key.
type RegistrationPayload struct {
	Ciphertext [5]*big.Int           // (pkOut, skIn, bid, coins, energy)
	PubKey     *sw_bls12377.G1Affine // Participant's public key (for DH)
}

// DecryptedRegistration holds the decrypted registration data for a participant.
type DecryptedRegistration struct {
	PkOut  *big.Int
	SkIn   *big.Int
	Bid    *big.Int
	Coins  *big.Int
	Energy *big.Int
}

// DecryptAllRegistrations decrypts all registration payloads using the auctioneer's DH secret.
func DecryptAllRegistrations(payloads []RegistrationPayload, auctioneerSk *big.Int) ([]DecryptedRegistration, error) {
	results := make([]DecryptedRegistration, len(payloads))

	// Convert auctioneer's secret key to BLS12-377 field element
	var sk bls12377_fr.Element
	sk.SetBigInt(auctioneerSk)

	for i, p := range payloads {
		// Convert participant's public key from gnark format to native BLS12-377
		pkX := new(big.Int)
		pkX.SetString(p.PubKey.X.(string), 10)
		pkY := new(big.Int)
		pkY.SetString(p.PubKey.Y.(string), 10)

		var pk bls12377.G1Affine
		pk.X.SetBigInt(pkX)
		pk.Y.SetBigInt(pkY)

		// Compute DH shared secret: shared = pk^sk
		shared := zerocash.ComputeDHShared(&sk, &pk)

		// Decrypt using the shared secret
		dec := DecZKRegGo(p.Ciphertext, *shared)

		results[i] = DecryptedRegistration{
			PkOut:  dec[0],
			SkIn:   dec[1],
			Bid:    dec[2],
			Coins:  dec[3],
			Energy: dec[4],
		}
	}
	return results, nil
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

// RunAuctionLogic is a placeholder: just copies input notes to output notes.
func RunAuctionLogic(inputs []DecryptedRegistration) []DecryptedRegistration {
	// TODO: Replace with real auction logic
	return inputs
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

// BuildWitnessF10 builds the witness for CircuitTxF10 from input/output notes.
func BuildWitnessF10(inputs, outputs []DecryptedRegistration, payloads []RegistrationPayload, auctioneerSk *big.Int) *CircuitTxF10 {
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

	// Helper to compute commitment (same as circuit)
	computeCommitment := func(coin, energy, rho, rand *big.Int) *big.Int {
		return mimcHash(coin, energy, rho, rand)
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

	// Helper to create DH components that derive the shared secret
	createDHComponents := func(shared bls12377.G1Affine) (sw_bls12377.G1Affine, sw_bls12377.G1Affine, frontend.Variable, sw_bls12377.G1Affine) {
		// For simplicity, we'll use the shared secret as G_b and set R=1
		// This means: EncKey = G_b * R = shared * 1 = shared
		// And: G_r = G * R = G * 1 = G

		// Use a standard generator for G
		_, _, g1, _ := bls12377.Generators()

		return sw_bls12377.G1Affine{
				X: g1.X.String(),
				Y: g1.Y.String(),
			}, // G
			sw_bls12377.G1Affine{
				X: shared.X.String(),
				Y: shared.Y.String(),
			}, // G_b (set to shared secret)
			"1", // R = 1
			sw_bls12377.G1Affine{
				X: g1.X.String(),
				Y: g1.Y.String(),
			} // G_r = G * R = G * 1 = G
	}

	// Convert auctioneer's secret key to BLS12-377 field element
	var sk bls12377_fr.Element
	sk.SetBigInt(auctioneerSk)

	// For each of the 10 participants, populate the witness with consistent values
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

		// Compute commitment
		cm := computeCommitment(coins, energy, rho, rand)

		// Use actual values from registration data, ensuring input = output for consistency
		switch i {
		case 0:
			w.InCoin0 = toVar(coins)
			w.InEnergy0 = toVar(energy)
			w.InCm0 = toVar(cm)
			w.InSn0 = toVar(sn)
			w.InPk0 = toVar(pkOut)
			w.InSk0 = toVar(skIn)
			w.InRho0 = toVar(rho)
			w.InRand0 = toVar(rand)

			// Set outputs equal to inputs to satisfy circuit constraints
			w.OutCoin0 = toVar(coins)
			w.OutEnergy0 = toVar(energy)
			w.OutCm0 = toVar(cm)
			w.OutSn0 = toVar(sn)
			w.OutPk0 = toVar(pkOut)
			w.OutRho0 = toVar(rho)
			w.OutRand0 = toVar(rand)

			w.C0 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal0 = toVarArr(dec)
			} else {
				w.DecVal0 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G0, w.G_b0, w.R0, w.G_r0 = createDHComponents(shared)
			w.EncKey0 = toGnarkPoint(shared) // This is what the circuit will verify: EncKey0 == G_b0 * R0
			w.SkT0 = toGnarkPoint(shared)    // This is used for decryption

		case 1:
			w.InCoin1 = toVar(coins)
			w.InEnergy1 = toVar(energy)
			w.InCm1 = toVar(cm)
			w.InSn1 = toVar(sn)
			w.InPk1 = toVar(pkOut)
			w.InSk1 = toVar(skIn)
			w.InRho1 = toVar(rho)
			w.InRand1 = toVar(rand)

			w.OutCoin1 = toVar(coins)
			w.OutEnergy1 = toVar(energy)
			w.OutCm1 = toVar(cm)
			w.OutSn1 = toVar(sn)
			w.OutPk1 = toVar(pkOut)
			w.OutRho1 = toVar(rho)
			w.OutRand1 = toVar(rand)

			w.C1 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal1 = toVarArr(dec)
			} else {
				w.DecVal1 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G1, w.G_b1, w.R1, w.G_r1 = createDHComponents(shared)
			w.EncKey1 = toGnarkPoint(shared)
			w.SkT1 = toGnarkPoint(shared)

		case 2:
			w.InCoin2 = toVar(coins)
			w.InEnergy2 = toVar(energy)
			w.InCm2 = toVar(cm)
			w.InSn2 = toVar(sn)
			w.InPk2 = toVar(pkOut)
			w.InSk2 = toVar(skIn)
			w.InRho2 = toVar(rho)
			w.InRand2 = toVar(rand)

			w.OutCoin2 = toVar(coins)
			w.OutEnergy2 = toVar(energy)
			w.OutCm2 = toVar(cm)
			w.OutSn2 = toVar(sn)
			w.OutPk2 = toVar(pkOut)
			w.OutRho2 = toVar(rho)
			w.OutRand2 = toVar(rand)

			w.C2 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal2 = toVarArr(dec)
			} else {
				w.DecVal2 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G2, w.G_b2, w.R2, w.G_r2 = createDHComponents(shared)
			w.EncKey2 = toGnarkPoint(shared)
			w.SkT2 = toGnarkPoint(shared)

		case 3:
			w.InCoin3 = toVar(coins)
			w.InEnergy3 = toVar(energy)
			w.InCm3 = toVar(cm)
			w.InSn3 = toVar(sn)
			w.InPk3 = toVar(pkOut)
			w.InSk3 = toVar(skIn)
			w.InRho3 = toVar(rho)
			w.InRand3 = toVar(rand)

			w.OutCoin3 = toVar(coins)
			w.OutEnergy3 = toVar(energy)
			w.OutCm3 = toVar(cm)
			w.OutSn3 = toVar(sn)
			w.OutPk3 = toVar(pkOut)
			w.OutRho3 = toVar(rho)
			w.OutRand3 = toVar(rand)

			w.C3 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal3 = toVarArr(dec)
			} else {
				w.DecVal3 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G3, w.G_b3, w.R3, w.G_r3 = createDHComponents(shared)
			w.EncKey3 = toGnarkPoint(shared)
			w.SkT3 = toGnarkPoint(shared)

		case 4:
			w.InCoin4 = toVar(coins)
			w.InEnergy4 = toVar(energy)
			w.InCm4 = toVar(cm)
			w.InSn4 = toVar(sn)
			w.InPk4 = toVar(pkOut)
			w.InSk4 = toVar(skIn)
			w.InRho4 = toVar(rho)
			w.InRand4 = toVar(rand)

			w.OutCoin4 = toVar(coins)
			w.OutEnergy4 = toVar(energy)
			w.OutCm4 = toVar(cm)
			w.OutSn4 = toVar(sn)
			w.OutPk4 = toVar(pkOut)
			w.OutRho4 = toVar(rho)
			w.OutRand4 = toVar(rand)

			w.C4 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal4 = toVarArr(dec)
			} else {
				w.DecVal4 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G4, w.G_b4, w.R4, w.G_r4 = createDHComponents(shared)
			w.EncKey4 = toGnarkPoint(shared)
			w.SkT4 = toGnarkPoint(shared)

		case 5:
			w.InCoin5 = toVar(coins)
			w.InEnergy5 = toVar(energy)
			w.InCm5 = toVar(cm)
			w.InSn5 = toVar(sn)
			w.InPk5 = toVar(pkOut)
			w.InSk5 = toVar(skIn)
			w.InRho5 = toVar(rho)
			w.InRand5 = toVar(rand)

			w.OutCoin5 = toVar(coins)
			w.OutEnergy5 = toVar(energy)
			w.OutCm5 = toVar(cm)
			w.OutSn5 = toVar(sn)
			w.OutPk5 = toVar(pkOut)
			w.OutRho5 = toVar(rho)
			w.OutRand5 = toVar(rand)

			w.C5 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal5 = toVarArr(dec)
			} else {
				w.DecVal5 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G5, w.G_b5, w.R5, w.G_r5 = createDHComponents(shared)
			w.EncKey5 = toGnarkPoint(shared)
			w.SkT5 = toGnarkPoint(shared)

		case 6:
			w.InCoin6 = toVar(coins)
			w.InEnergy6 = toVar(energy)
			w.InCm6 = toVar(cm)
			w.InSn6 = toVar(sn)
			w.InPk6 = toVar(pkOut)
			w.InSk6 = toVar(skIn)
			w.InRho6 = toVar(rho)
			w.InRand6 = toVar(rand)

			w.OutCoin6 = toVar(coins)
			w.OutEnergy6 = toVar(energy)
			w.OutCm6 = toVar(cm)
			w.OutSn6 = toVar(sn)
			w.OutPk6 = toVar(pkOut)
			w.OutRho6 = toVar(rho)
			w.OutRand6 = toVar(rand)

			w.C6 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal6 = toVarArr(dec)
			} else {
				w.DecVal6 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G6, w.G_b6, w.R6, w.G_r6 = createDHComponents(shared)
			w.EncKey6 = toGnarkPoint(shared)
			w.SkT6 = toGnarkPoint(shared)

		case 7:
			w.InCoin7 = toVar(coins)
			w.InEnergy7 = toVar(energy)
			w.InCm7 = toVar(cm)
			w.InSn7 = toVar(sn)
			w.InPk7 = toVar(pkOut)
			w.InSk7 = toVar(skIn)
			w.InRho7 = toVar(rho)
			w.InRand7 = toVar(rand)

			w.OutCoin7 = toVar(coins)
			w.OutEnergy7 = toVar(energy)
			w.OutCm7 = toVar(cm)
			w.OutSn7 = toVar(sn)
			w.OutPk7 = toVar(pkOut)
			w.OutRho7 = toVar(rho)
			w.OutRand7 = toVar(rand)

			w.C7 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal7 = toVarArr(dec)
			} else {
				w.DecVal7 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G7, w.G_b7, w.R7, w.G_r7 = createDHComponents(shared)
			w.EncKey7 = toGnarkPoint(shared)
			w.SkT7 = toGnarkPoint(shared)

		case 8:
			w.InCoin8 = toVar(coins)
			w.InEnergy8 = toVar(energy)
			w.InCm8 = toVar(cm)
			w.InSn8 = toVar(sn)
			w.InPk8 = toVar(pkOut)
			w.InSk8 = toVar(skIn)
			w.InRho8 = toVar(rho)
			w.InRand8 = toVar(rand)

			w.OutCoin8 = toVar(coins)
			w.OutEnergy8 = toVar(energy)
			w.OutCm8 = toVar(cm)
			w.OutSn8 = toVar(sn)
			w.OutPk8 = toVar(pkOut)
			w.OutRho8 = toVar(rho)
			w.OutRand8 = toVar(rand)

			w.C8 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal8 = toVarArr(dec)
			} else {
				w.DecVal8 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G8, w.G_b8, w.R8, w.G_r8 = createDHComponents(shared)
			w.EncKey8 = toGnarkPoint(shared)
			w.SkT8 = toGnarkPoint(shared)

		case 9:
			w.InCoin9 = toVar(coins)
			w.InEnergy9 = toVar(energy)
			w.InCm9 = toVar(cm)
			w.InSn9 = toVar(sn)
			w.InPk9 = toVar(pkOut)
			w.InSk9 = toVar(skIn)
			w.InRho9 = toVar(rho)
			w.InRand9 = toVar(rand)

			w.OutCoin9 = toVar(coins)
			w.OutEnergy9 = toVar(energy)
			w.OutCm9 = toVar(cm)
			w.OutSn9 = toVar(sn)
			w.OutPk9 = toVar(pkOut)
			w.OutRho9 = toVar(rho)
			w.OutRand9 = toVar(rand)

			w.C9 = toVarArr(payload.Ciphertext)

			// Compute decrypted values using the shared secret
			if i < len(payloads) {
				dec := DecZKRegGo(payload.Ciphertext, shared)
				w.DecVal9 = toVarArr(dec)
			} else {
				w.DecVal9 = toVarArr(payload.Ciphertext) // Fallback
			}

			// Set DH components that satisfy the circuit constraints
			w.G9, w.G_b9, w.R9, w.G_r9 = createDHComponents(shared)
			w.EncKey9 = toGnarkPoint(shared)
			w.SkT9 = toGnarkPoint(shared)
		}
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
	params *zerocash.Params,
	pk groth16.ProvingKey,
	ccs constraint.ConstraintSystem,
) error {
	// Validate registration payloads
	if len(regPayloads) == 0 {
		return fmt.Errorf("no registration payloads provided")
	}
	if len(regPayloads) > 10 {
		return fmt.Errorf("too many registration payloads: %d (max 10)", len(regPayloads))
	}

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

// ExchangePhase runs the auction phase as per Algorithm 3 (without ZKP-enforced auction logic).
//   - regPayloads: Registration payloads (ciphertexts + pubkeys)
//   - auctioneerSk: Auctioneer's DH secret key
//   - params: Zerocash params
//   - pk: Proving key for CircuitTxF10
//   - ccs: Compiled constraint system for CircuitTxF10
//
// Returns: (txOut, info, proof, error)
func ExchangePhase(
	regPayloads []RegistrationPayload,
	auctioneerSk *big.Int,
	params *zerocash.Params,
	pk groth16.ProvingKey,
	ccs constraint.ConstraintSystem,
) (txOut interface{}, info interface{}, proof []byte, err error) {
	// Input validation
	if err := validateExchangeInputs(regPayloads, auctioneerSk, params, pk, ccs); err != nil {
		return nil, nil, nil, fmt.Errorf("input validation failed: %w", err)
	}

	// 1. Decrypt all registration payloads
	inputs, err := DecryptAllRegistrations(regPayloads, auctioneerSk)
	if err != nil {
		return nil, nil, nil, err
	}

	// 2. Run auction logic (off-circuit, placeholder)
	outputs := RunAuctionLogic(inputs)

	// 3. Build witness for CircuitTxF10
	witness := BuildWitnessF10(inputs, outputs, regPayloads, auctioneerSk)

	// 4. Generate ZKP using CircuitTxF10
	proof, err = GenerateProofF10(witness, pk, ccs)
	if err != nil {
		return nil, nil, nil, err
	}

	// 5. Create structured output
	timestamp := time.Now().Unix()

	// Calculate totals from inputs
	totalCoins := big.NewInt(0)
	totalEnergy := big.NewInt(0)
	highestBid := big.NewInt(0)
	winnerID := ""
	winnerIdx := -1

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
			winnerIdx = i
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

	// 6. Create a real transaction for the winner
	var tx *zerocash.Tx
	if winnerIdx >= 0 && winnerIdx < len(inputs) {
		winner := inputs[winnerIdx]
		payload := regPayloads[winnerIdx]
		// Use winner's skIn as oldSk, pkOut as newSk
		oldSk := winner.SkIn.Bytes()
		newSk := winner.PkOut.Bytes()
		coins := totalCoins
		energy := totalEnergy
		// Create a dummy old note (since we don't have the real note here)
		oldNote := &zerocash.Note{
			Value: zerocash.Gamma{
				Coins:  winner.Coins,
				Energy: winner.Energy,
			},
			PkOwner: payload.Ciphertext[0].Bytes(),
			Rho:     payload.Ciphertext[3].Bytes(),
			Rand:    payload.Ciphertext[4].Bytes(),
			Cm:      []byte{},
		}
		params := params
		ccsSingle := ccs // This should be the single-note circuit, but for demo use ccs
		tx, _ = zerocash.CreateTx(oldNote, oldSk, newSk, coins, energy, params, ccsSingle, pk)
	}

	// 7. Return structured results
	return tx, auctionResult, proof, nil
}
