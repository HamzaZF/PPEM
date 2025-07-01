package register

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"math/big"

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

// RegisterResult matches the exact output of Algorithm 2 (Register) in the paper.
type RegisterResult struct {
	CAux    [5]*big.Int  // C^Aux: Encrypted registration payload (pk^out, sk^in, b, Γ^in.coins, Γ^in.energy)
	TxIn    *zerocash.Tx // tx^in: Output of Algorithm 1 (Transaction)
	InfoBid []byte       // info_bid: Public information about funds and bid (simplified, not used in circuit)
	Proof   []byte       // π_reg: ZK proof for registration
}

// Algorithm 2: Register(n^base, Γ^in, b_i) → (C^Aux, tx^in, info_bid, π_reg)
// Follows the paper exactly, excluding r_enc for DH-OTP encryption
// auctioneerECDHPubKey: Auctioneer's ECDH public key for note encryption in CreateTx
func Register(participant *zerocash.Participant, note *zerocash.Note, bid *big.Int,
	pkTx groth16.ProvingKey, ccsTx constraint.ConstraintSystem,
	pkReg groth16.ProvingKey, ccsReg constraint.ConstraintSystem,
	skBytes []byte, auctioneerECDHPubKey *ecdh.PublicKey) (*RegisterResult, error) {

	// Validate inputs according to paper
	if participant.AuctioneerPub == nil {
		return nil, errors.New("participant.AuctioneerPub is nil; auctioneer public key required")
	}
	if auctioneerECDHPubKey == nil {
		return nil, errors.New("auctioneer ECDH public key is nil")
	}

	// Step 1: Generate sk^in, Compute pk^in = KeyGen(sk^in)
	var skIn bls12377_fr.Element
	skIn.SetRandom()
	pkIn := computePkFromSk(skIn.BigInt(new(big.Int)))

	// Step 2: Generate sk^out, Compute pk^out = KeyGen(sk^out)
	var skOut bls12377_fr.Element
	skOut.SetRandom()
	pkOut := computePkFromSk(skOut.BigInt(new(big.Int)))

	// Step 3: Compute tx^in = Transaction(n^base, sk^base, Γ^in, pk^in)
	coins := note.Value.Coins
	energy := note.Value.Energy
	pkInBytes := pkIn.Bytes()

	txIn, err := zerocash.CreateTx(note, skBytes, pkInBytes, coins, energy, participant.Params, ccsTx, pkTx, auctioneerECDHPubKey)
	if err != nil {
		return nil, errors.New("Algorithm 1 (Transaction) failed: " + err.Error())
	}

	// Step 4: Parse tx^in as (sn^base, (cm^in, c^in), π)
	var cmIn []byte
	if txIn != nil && txIn.NewNote != nil && txIn.NewNote.Cm != nil {
		cmIn = txIn.NewNote.Cm
	}

	// Step 5: info_bid computation omitted (not used)
	infoBid := []byte("not used") // Placeholder

	// Step 6: Generate DH randomness and compute shared key for circuit protocol
	// Circuit expects: EncKey = G_b^R where G_b is auctioneer public key
	var rDH bls12377_fr.Element
	rDH.SetRandom()

	// Compute shared key as auctioneer_pk^R (to match circuit constraint)
	var sharedKey bls12377.G1Affine
	sharedKey.ScalarMultiplication(participant.AuctioneerPub, rDH.BigInt(new(big.Int)))

	// Step 7: Compute C^Aux = Enc(pk_T, (Γ^in, b, sk^in, pk^out)) using DH-OTP
	skInBig := skIn.BigInt(new(big.Int))
	cAux := EncryptRegistrationData(sharedKey, coins, energy, bid, skInBig, pkOut)

	// Step 8: Compute Prove(x, w) → π_reg with the correct DH values
	registrationProof, err := generateRegistrationProof(
		note, bid, coins, energy, skInBig, pkOut, cAux, cmIn,
		sharedKey, participant.AuctioneerPub, rDH, pkReg, ccsReg)
	if err != nil {
		return nil, errors.New("registration proof generation failed: " + err.Error())
	}

	return &RegisterResult{
		CAux:    cAux,
		TxIn:    txIn,
		InfoBid: infoBid,
		Proof:   registrationProof,
	}, nil
}

// EncryptRegistrationData implements DH-OTP encryption from Algorithm 2
// C^Aux = Enc(pk_T, (Γ^in, b, sk^in, pk^out)) - field order matches EncZKReg circuit
func EncryptRegistrationData(sharedKey bls12377.G1Affine, coins, energy, bid, skIn, pkOut *big.Int) [5]*big.Int {
	h := mimcNative.NewMiMC()

	// Derive base encryption key from DH shared secret
	encKeyX := sharedKey.X.Bytes()
	encKeyY := sharedKey.Y.Bytes()
	h.Write(encKeyX[:])
	h.Write(encKeyY[:])
	baseKey := h.Sum(nil)

	// Generate mask chain for each field - matches EncZKReg in circuit
	masks := make([][]byte, 5)
	masks[0] = baseKey
	for i := 1; i < 5; i++ {
		h.Reset()
		h.Write(masks[i-1])
		masks[i] = h.Sum(nil)
	}

	// Encrypt fields in same order as EncZKReg: (pk^out, sk^in, b, coins, energy)
	fields := []*big.Int{pkOut, skIn, bid, coins, energy}
	var cAux [5]*big.Int

	for i := 0; i < 5; i++ {
		maskBig := new(big.Int).SetBytes(masks[i])
		cAux[i] = new(big.Int).Add(fields[i], maskBig)
	}

	return cAux
}

// generateRegistrationProof creates ZK proof matching CircuitTxRegister
func generateRegistrationProof(note *zerocash.Note, bid *big.Int, coins, energy, skIn, pkOut *big.Int,
	cAux [5]*big.Int, cmIn []byte, sharedKey bls12377.G1Affine, auctioneerPub *bls12377.G1Affine,
	rDH bls12377_fr.Element, pk groth16.ProvingKey, ccs constraint.ConstraintSystem) ([]byte, error) {

	// Compute G (generator)
	var g1Gen, _, _, _ = bls12377.Generators()
	var g bls12377.G1Affine
	g.FromJacobian(&g1Gen)

	// Compute G^r (this should match the provided rDH)
	var gr bls12377.G1Affine
	gr.ScalarMultiplication(&g, rDH.BigInt(new(big.Int)))

	// Create witness for CircuitTxRegister
	witness := &CircuitTxRegister{
		// Public inputs (Instance x)
		CmIn:          new(big.Int).SetBytes(cmIn).String(),
		GammaInEnergy: energy.String(),
		GammaInCoins:  coins.String(),
		Bid:           bid.String(),
		G:             convertToG1Affine(g),
		G_b:           convertToG1Affine(*auctioneerPub), // pk_T
		G_r:           convertToG1Affine(gr),             // G^R

		// Private inputs (Witness w)
		InCoin:   coins.String(),                            // n^in.coins
		InEnergy: energy.String(),                           // n^in.energy
		RhoIn:    new(big.Int).SetBytes(note.Rho).String(),  // n^in.ρ
		RandIn:   new(big.Int).SetBytes(note.Rand).String(), // n^in.r
		SkIn:     skIn.String(),                             // sk^in
		PkIn:     computePkFromSk(skIn).String(),            // pk^in = KeyGen(sk^in)
		PkOut:    pkOut.String(),                            // pk^out
		EncKey:   convertToG1Affine(sharedKey),              // G_b^R (shared key)
		R:        rDH.BigInt(new(big.Int)).String(),         // R (DH randomness)
	}

	// Set CAux values
	for i := 0; i < 5; i++ {
		witness.CAux[i] = cAux[i].String()
	}

	// Create gnark witness and generate proof
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, err
	}

	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// computePkFromSk generates pk = KeyGen(sk) using MiMC hash (matches circuit)
func computePkFromSk(sk *big.Int) *big.Int {
	h := mimcNative.NewMiMC()
	h.Write(sk.Bytes())
	return new(big.Int).SetBytes(h.Sum(nil))
}

// convertToG1Affine converts native BLS12-377 point to gnark format
func convertToG1Affine(p bls12377.G1Affine) sw_bls12377.G1Affine {
	return sw_bls12377.G1Affine{
		X: p.X.String(),
		Y: p.Y.String(),
	}
}

// DecryptRegistrationData decrypts registration data for testing purposes
func DecryptRegistrationData(ciphertext [5]*big.Int, sharedKey bls12377.G1Affine) [5]*big.Int {
	h := mimcNative.NewMiMC()

	// Derive base encryption key from DH shared secret (same as encryption)
	encKeyX := sharedKey.X.Bytes()
	encKeyY := sharedKey.Y.Bytes()
	h.Write(encKeyX[:])
	h.Write(encKeyY[:])
	baseKey := h.Sum(nil)

	// Generate mask chain for each field (same as encryption)
	masks := make([][]byte, 5)
	masks[0] = baseKey
	for i := 1; i < 5; i++ {
		h.Reset()
		h.Write(masks[i-1])
		masks[i] = h.Sum(nil)
	}

	// Decrypt: subtract the masks
	var decrypted [5]*big.Int
	for i := 0; i < 5; i++ {
		maskBig := new(big.Int).SetBytes(masks[i])
		decrypted[i] = new(big.Int).Sub(ciphertext[i], maskBig)
	}

	return decrypted
}
