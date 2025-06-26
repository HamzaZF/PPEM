package register

import (
	"errors"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"

	"implementation/internal/zerocash"
)

// RegisterResult matches the output of Algorithm 2 (Register) in the paper.
// TxIn is the output of Algorithm 1 (Transaction), as required by Algorithm 2.
type RegisterResult struct {
	CAux    [5]*big.Int  // c^Aux: Encrypted registration payload
	TxIn    *zerocash.Tx // tx^in: Zerocash transaction (Algorithm 1)
	InfoBid []byte       // info_bid: Public info about funds/bid (placeholder)
	Proof   []byte       // π_reg: ZK proof for registration
}

// Register creates a registration proof for a single participant using the single-note circuit and proving key.
func Register(participant *zerocash.Participant, note *zerocash.Note, bid *big.Int, pk groth16.ProvingKey, skBytes []byte, ccs constraint.ConstraintSystem) (*RegisterResult, error) {
	// Step 1: Use DH shared key between participant and auctioneer for encryption
	if participant.AuctioneerPub == nil {
		return nil, errors.New("participant.AuctioneerPub is nil; must be set for registration")
	}
	sharedKey := zerocash.ComputeDHShared(participant.Sk, participant.AuctioneerPub)

	// Step 2: Generate pk_out (for 1-to-1, can reuse pk_in or generate new)
	var skOut bls12377_fr.Element
	skOut.SetRandom()
	var pkOut bls12377.G1Affine
	pkOut.ScalarMultiplication(participant.Pk, skOut.BigInt(new(big.Int)))

	// Step 3: Call Algorithm 1 (Transaction) to produce tx^in
	coins := note.Value.Coins
	energy := note.Value.Energy
	pkOutBytes := pkOut.X.BigInt(new(big.Int)).Bytes()

	txIn, err := zerocash.CreateTx(note, skBytes, pkOutBytes, coins, energy, participant.Params, ccs, pk)
	if err != nil {
		return nil, err
	}

	// Step 4: Sample r_enc (b, r) for encryption randomness (already in CreateTx logic)

	// Step 5: Compute c^Aux = MiMC-based encryption using DH shared key
	// For registration, encrypt (coins, energy, bid, sk_in, pk_out)
	skInBig := new(big.Int).SetBytes(skBytes)
	pkOutBig := pkOut.X.BigInt(new(big.Int))
	encVals := buildEncZKReg(*sharedKey, pkOutBig, skInBig, bid, coins, energy)
	var cAux [5]*big.Int
	for i := 0; i < 5; i++ {
		cAux[i] = encVals[i]
	}

	// Step 6: Compute info_bid (placeholder: hash of coins, energy, bid)
	infoBid := mimcHash(append(append(coins.Bytes(), energy.Bytes()...), bid.Bytes()...))

	// Step 7: Marshal the ZK proof from tx^in
	proofBytes := txIn.Proof

	return &RegisterResult{
		CAux:    cAux,
		TxIn:    txIn,
		InfoBid: infoBid,
		Proof:   proofBytes,
	}, nil
}

// buildEncZKReg implements MiMC-based encryption for registration (off-circuit, Go version).
// Encrypts (pkOut, skIn, bid, coins, energy) as in Algorithm 2.
func buildEncZKReg(encKey bls12377.G1Affine, pkOut, skIn, bid, coins, energy *big.Int) [5]*big.Int {
	h := mimcNative.NewMiMC()
	encKeyX := encKey.X.Bytes()
	encKeyY := encKey.Y.Bytes()
	h.Write(encKeyX[:])
	h.Write(encKeyY[:])
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

	enc0 := new(big.Int).Add(pkOut, new(big.Int).SetBytes(mask0))
	enc1 := new(big.Int).Add(skIn, new(big.Int).SetBytes(mask1))
	enc2 := new(big.Int).Add(bid, new(big.Int).SetBytes(mask2))
	enc3 := new(big.Int).Add(coins, new(big.Int).SetBytes(mask3))
	enc4 := new(big.Int).Add(energy, new(big.Int).SetBytes(mask4))

	return [5]*big.Int{enc0, enc1, enc2, enc3, enc4}
}

// mimcHash computes MiMC hash of input bytes (local copy from zerocash/crypto.go)
func mimcHash(data []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(data)
	return h.Sum(nil)
}
