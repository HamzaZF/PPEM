package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	// Gnark cryptographic libraries
	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

// =============================================================================
// CONSTANTS AND CONFIGURATION
// =============================================================================

// bw6_761 curve identifier for gnark
var bw6_761_ID = ecc.BW6_761

// =============================================================================
// DATA STRUCTURES
// =============================================================================

// Gamma represents the value of a note (coins and energy)
type Gamma struct {
	Coins  *big.Int
	Energy *big.Int
}

// Note represents a confidential transaction note
type Note struct {
	Value   Gamma  // The value (coins and energy) of the note
	PkOwner []byte // Public key of the note owner
	Rho     []byte // Randomness for commitment
	Rand    []byte // Additional randomness
	Cm      []byte // Commitment to the note
}

// CircuitTx represents the zero-knowledge proof circuit for a transaction
// It defines the constraints that must be satisfied for a valid transaction
type CircuitTx struct {
	// Public inputs (visible to verifier)
	OldCoin   frontend.Variable    `gnark:",public"` // Old note's coin value
	OldEnergy frontend.Variable    `gnark:",public"` // Old note's energy value
	CmOld     frontend.Variable    `gnark:",public"` // Old note's commitment
	SnOld     frontend.Variable    `gnark:",public"` // Old note's serial number
	PkOld     frontend.Variable    `gnark:",public"` // Old note's public key
	NewCoin   frontend.Variable    `gnark:",public"` // New note's coin value
	NewEnergy frontend.Variable    `gnark:",public"` // New note's energy value
	CmNew     frontend.Variable    `gnark:",public"` // New note's commitment
	CNew      [6]frontend.Variable `gnark:",public"` // Encrypted new note data
	G         sw_bls12377.G1Affine `gnark:",public"` // Generator point
	G_b       sw_bls12377.G1Affine `gnark:",public"` // G^b point
	G_r       sw_bls12377.G1Affine `gnark:",public"` // G^r point

	// Private inputs (hidden from verifier)
	SkOld   frontend.Variable    // Old note's secret key
	RhoOld  frontend.Variable    // Old note's rho value
	RandOld frontend.Variable    // Old note's randomness
	PkNew   frontend.Variable    // New note's public key
	RhoNew  frontend.Variable    // New note's rho value
	RandNew frontend.Variable    // New note's randomness
	R       frontend.Variable    // Random scalar for encryption
	EncKey  sw_bls12377.G1Affine // Encryption key
}

// =============================================================================
// CIRCUIT IMPLEMENTATION
// =============================================================================

// Define implements the zero-knowledge proof constraints for the transaction circuit
func (c *CircuitTx) Define(api frontend.API) error {
	// 1. Verify old note commitment: cmOld = MiMC(coins, energy, rho, rand)
	hasher, _ := mimc.NewMiMC(api)
	hasher.Reset()
	hasher.Write(c.OldCoin)
	hasher.Write(c.OldEnergy)
	hasher.Write(c.RhoOld)
	hasher.Write(c.RandOld)
	cm := hasher.Sum()
	api.AssertIsEqual(c.CmOld, cm)

	// 2. Verify old note serial number: snOld = MiMC(sk, rho) (PRF)
	snComputed := PRF(api, c.SkOld, c.RhoOld)
	api.AssertIsEqual(c.SnOld, snComputed)

	// 3. Verify new note commitment: cmNew = MiMC(coins, energy, rho, rand)
	hasher.Reset()
	hasher.Write(c.NewCoin)
	hasher.Write(c.NewEnergy)
	hasher.Write(c.RhoNew)
	hasher.Write(c.RandNew)
	cm = hasher.Sum()
	api.AssertIsEqual(c.CmNew, cm)

	// 4. Verify encrypted new note data: cNew = Enc(pk, coins, energy, rho, rand, cm)
	encVal := EncZK(api, c.PkNew, c.NewCoin, c.NewEnergy, c.RhoNew, c.RandNew, c.CmNew, c.EncKey)
	for i := 0; i < 6; i++ {
		api.AssertIsEqual(c.CNew[i], encVal[i])
	}

	// 5. Verify value conservation (no coins/energy created or destroyed)
	api.AssertIsEqual(c.OldCoin, c.NewCoin)
	api.AssertIsEqual(c.OldEnergy, c.NewEnergy)

	// 6. Verify encryption key derivation: EncKey = (G^b)^r
	G_r_b := new(sw_bls12377.G1Affine)
	G_r_b.ScalarMul(api, c.G_b, c.R)
	api.AssertIsEqual(c.EncKey.X, G_r_b.X)
	api.AssertIsEqual(c.EncKey.Y, G_r_b.Y)

	// 7. Verify G_r = G^r
	G_r := new(sw_bls12377.G1Affine)
	G_r.ScalarMul(api, c.G, c.R)
	api.AssertIsEqual(c.G_r.X, G_r.X)
	api.AssertIsEqual(c.G_r.Y, G_r.Y)

	// 8. Verify public key derivation: pk = MiMC(sk)
	hasher.Reset()
	hasher.Write(c.SkOld)
	pk := hasher.Sum()
	api.AssertIsEqual(c.PkOld, pk)

	return nil
}

// =============================================================================
// CRYPTOGRAPHIC FUNCTIONS
// =============================================================================

// PRF implements a pseudo-random function using MiMC hash
func PRF(api frontend.API, sk, rho frontend.Variable) frontend.Variable {
	hasher, _ := mimc.NewMiMC(api)
	hasher.Write(sk)
	hasher.Write(rho)
	return hasher.Sum()
}

// EncZK encrypts note data using MiMC-based encryption in the circuit
func EncZK(api frontend.API, pk, coins, energy, rho, rand, cm frontend.Variable, enc_key sw_bls12377.G1Affine) []frontend.Variable {
	h, _ := mimc.NewMiMC(api)

	// Generate encryption masks using MiMC hash chain
	h.Write(enc_key.X)
	h.Write(enc_key.Y)
	h_enc_key := h.Sum()

	h.Write(h_enc_key)
	h_h_enc_key := h.Sum()

	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum()

	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum()

	// Encrypt each field by adding the corresponding mask
	pk_enc := api.Add(pk, h_enc_key)
	coins_enc := api.Add(coins, h_h_enc_key)
	energy_enc := api.Add(energy, h_h_h_enc_key)
	rho_enc := api.Add(rho, h_h_h_h_enc_key)
	rand_enc := api.Add(rand, h_h_h_h_h_enc_key)
	cm_enc := api.Add(cm, h_h_h_h_h_h_enc_key)

	return []frontend.Variable{pk_enc, coins_enc, energy_enc, rho_enc, rand_enc, cm_enc}
}

// =============================================================================
// NATIVE CRYPTOGRAPHIC FUNCTIONS (outside circuit)
// =============================================================================

// Commitment creates a commitment to note data using MiMC hash
func Commitment(coins, energy, rho, r *big.Int) []byte {
	h := mimcNative.NewMiMC()
	h.Write(coins.Bytes())
	h.Write(energy.Bytes())
	h.Write(rho.Bytes())
	h.Write(r.Bytes())
	return h.Sum(nil)
}

// BuildEncMimc encrypts note data using MiMC and the encryption key
func BuildEncMimc(encKey bls12377.G1Affine, pk []byte, coins, energy, rho, rand *big.Int, cm []byte) [6]bls12377_fp.Element {
	pk_int := new(big.Int).SetBytes(pk[:])
	h := mimcNative.NewMiMC()

	// Convert encryption key to bytes
	encKeyX := encKey.X.Bytes()
	encKeyXBytes := make([]byte, len(encKeyX))
	copy(encKeyXBytes[:], encKeyX[:])

	encKeyY := encKey.Y.Bytes()
	encKeyYBytes := make([]byte, len(encKeyY))
	copy(encKeyYBytes[:], encKeyY[:])

	// Generate encryption masks using MiMC hash chain
	h.Write(encKeyXBytes)
	h.Write(encKeyYBytes)
	h_enc_key := h.Sum(nil)

	h.Write(h_enc_key)
	h_h_enc_key := h.Sum(nil)

	h.Write(h_h_enc_key)
	h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_enc_key)
	h_h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_h_enc_key)
	h_h_h_h_h_enc_key := h.Sum(nil)

	h.Write(h_h_h_h_h_enc_key)
	h_h_h_h_h_h_enc_key := h.Sum(nil)

	// Encrypt each field by adding the corresponding mask
	pk_ := new(bls12377_fp.Element).SetBigInt(pk_int)
	pk_enc := new(bls12377_fp.Element).Add(pk_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_enc_key[:])))

	coins_ := new(bls12377_fp.Element).SetBigInt(coins)
	coins_enc := new(bls12377_fp.Element).Add(coins_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_enc_key[:])))

	energy_ := new(bls12377_fp.Element).SetBigInt(energy)
	energy_enc := new(bls12377_fp.Element).Add(energy_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_enc_key[:])))

	rho_ := new(bls12377_fp.Element).SetBigInt(rho)
	rho_enc := new(bls12377_fp.Element).Add(rho_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_enc_key[:])))

	rand_ := new(bls12377_fp.Element).SetBigInt(rand)
	rand_enc := new(bls12377_fp.Element).Add(rand_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_enc_key[:])))

	cm_ := new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(cm[:]))
	cm_enc := new(bls12377_fp.Element).Add(cm_, new(bls12377_fp.Element).SetBigInt(new(big.Int).SetBytes(h_h_h_h_h_h_enc_key[:])))

	return [6]bls12377_fp.Element{*pk_enc, *coins_enc, *energy_enc, *rho_enc, *rand_enc, *cm_enc}
}

// CalcSerialMimc computes a serial number as MiMC(sk || rho)
func CalcSerialMimc(sk, rho []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	h.Write(rho)
	return h.Sum(nil)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// randomBigInt generates a random big integer of specified byte length
func randomBigInt(n int) *big.Int {
	b := make([]byte, n)
	rand.Read(b)
	return new(big.Int).SetBytes(b)
}

// randomBytes generates random bytes of specified length
func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// mimcHash computes MiMC hash of input bytes
func mimcHash(sk []byte) []byte {
	h := mimcNative.NewMiMC()
	h.Write(sk)
	return h.Sum(nil)
}

// toGnarkPoint converts a native BLS12-377 point to gnark format
func toGnarkPoint(p bls12377.G1Affine) sw_bls12377.G1Affine {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	return sw_bls12377.G1Affine{
		X: new(big.Int).SetBytes(xBytes[:]).String(),
		Y: new(big.Int).SetBytes(yBytes[:]).String(),
	}
}

// CreateNote creates a new note with given coins, energy, and secret key
func CreateNote(coins, energy *big.Int, sk []byte) *Note {
	rho := randomBytes(32)
	rand := randomBytes(32)
	pk := mimcHash(sk)
	cm := Commitment(coins, energy, new(big.Int).SetBytes(rho), new(big.Int).SetBytes(rand))
	return &Note{
		Value: Gamma{
			Coins:  coins,
			Energy: energy,
		},
		PkOwner: pk,
		Rho:     rho,
		Rand:    rand,
		Cm:      cm,
	}
}

// Algorithm1 implements the confidential transaction as in the paper (Algorithm 1), for 1 input and 1 output
func Algorithm1() ([]byte, []byte, [6]bls12377_fp.Element, groth16.Proof) {
	coins := randomBigInt(32)
	energy := randomBigInt(32)
	oldSk := randomBytes(32)
	newSk := randomBytes(32)
	oldNote := CreateNote(coins, energy, oldSk)
	newNote := CreateNote(coins, energy, newSk)

	snOldBytes := CalcSerialMimc(oldSk, oldNote.Rho)
	snOldStr := new(big.Int).SetBytes(snOldBytes).String()

	var g1Jac, _, _, _ = bls12377.Generators()
	var g, g_b, g_r, encKey bls12377.G1Affine
	var b, r bls12377_fp.Element

	bSeed := randomBytes(32)
	bHash := mimcHash(bSeed)
	bBig := new(big.Int).SetBytes(bHash)
	bBig.Mod(bBig, bls12377_fr.Modulus())
	b.SetBigInt(bBig)

	rSeed := randomBytes(32)
	rHash := mimcHash(rSeed)
	rBig := new(big.Int).SetBytes(rHash)
	rBig.Mod(rBig, bls12377_fr.Modulus())
	r.SetBigInt(rBig)

	g.FromJacobian(&g1Jac)
	g_b.ScalarMultiplication(&g, b.BigInt(new(big.Int)))
	g_r.ScalarMultiplication(&g, r.BigInt(new(big.Int)))
	encKey.ScalarMultiplication(&g_b, r.BigInt(new(big.Int)))

	encVals := BuildEncMimc(encKey, newNote.PkOwner, newNote.Value.Coins, newNote.Value.Energy,
		new(big.Int).SetBytes(newNote.Rho), new(big.Int).SetBytes(newNote.Rand), newNote.Cm)
	var cNewStrs [6]string
	for i := 0; i < 6; i++ {
		cNewStrs[i] = encVals[i].String()
	}

	var cNewVars [6]frontend.Variable
	for i := 0; i < 6; i++ {
		cNewVars[i] = cNewStrs[i]
	}

	witness := &CircuitTx{
		OldCoin:   oldNote.Value.Coins.String(),
		OldEnergy: oldNote.Value.Energy.String(),
		CmOld:     new(big.Int).SetBytes(oldNote.Cm).String(),
		SnOld:     snOldStr,
		PkOld:     new(big.Int).SetBytes(oldNote.PkOwner).String(),
		NewCoin:   newNote.Value.Coins.String(),
		NewEnergy: newNote.Value.Energy.String(),
		CmNew:     new(big.Int).SetBytes(newNote.Cm).String(),
		CNew:      cNewVars,
		G:         toGnarkPoint(g),
		G_b:       toGnarkPoint(g_b),
		G_r:       toGnarkPoint(g_r),
		SkOld:     new(big.Int).SetBytes(oldSk).String(),
		RhoOld:    new(big.Int).SetBytes(oldNote.Rho).String(),
		RandOld:   new(big.Int).SetBytes(oldNote.Rand).String(),
		PkNew:     new(big.Int).SetBytes(newNote.PkOwner).String(),
		RhoNew:    new(big.Int).SetBytes(newNote.Rho).String(),
		RandNew:   new(big.Int).SetBytes(newNote.Rand).String(),
		R:         r.String(),
		EncKey:    toGnarkPoint(encKey),
	}

	var circuit CircuitTx
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Errorf("circuit compilation failed: %w", err))
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(fmt.Errorf("groth16 setup failed: %w", err))
	}

	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		panic(fmt.Errorf("witness creation failed: %w", err))
	}

	proofObj, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		panic(fmt.Errorf("proof generation failed: %w", err))
	}

	publicWitness, err := w.Public()
	if err != nil {
		panic(fmt.Errorf("public witness extraction failed: %w", err))
	}

	if err := groth16.Verify(proofObj, vk, publicWitness); err != nil {
		panic(fmt.Errorf("proof verification failed: %w", err))
	}

	var algProofBytes []byte
	buf := new(bytes.Buffer)
	_, err = proofObj.WriteTo(buf)
	if err != nil {
		panic(fmt.Errorf("proof marshaling failed: %w", err))
	}
	algProofBytes = buf.Bytes()

	fmt.Println("\n[Algorithm1] Transaction generated:")
	fmt.Printf("  snOld: %s\n", snOldStr)
	fmt.Printf("  cmNew: %s\n", new(big.Int).SetBytes(newNote.Cm).String())
	fmt.Printf("  cNew:  %v\n", cNewStrs)
	fmt.Printf("  proof: %x...\n", algProofBytes[:8])

	return snOldBytes, newNote.Cm, encVals, proofObj
}

// =============================================================================
// MAIN FUNCTION
// =============================================================================

func main() {
	fmt.Println("=== Confidential Transaction System ===")
	fmt.Println("Generating zero-knowledge proof for transaction...")

	// Step 1: Generate value once for both notes
	coins := randomBigInt(32)
	energy := randomBigInt(32)
	fmt.Printf("[DEBUG] Generated coins: %s\n", coins.String())
	fmt.Printf("[DEBUG] Generated energy: %s\n", energy.String())
	os.Stdout.Sync()

	// Create old and new notes using the CreateNote function
	oldSk := randomBytes(32)
	newSk := randomBytes(32)

	oldNote := CreateNote(coins, energy, oldSk)
	newNote := CreateNote(coins, energy, newSk)

	fmt.Printf("[DEBUG] OldNote coins: %s, energy: %s\n", oldNote.Value.Coins.String(), oldNote.Value.Energy.String())
	fmt.Printf("[DEBUG] NewNote coins: %s, energy: %s\n", newNote.Value.Coins.String(), newNote.Value.Energy.String())
	os.Stdout.Sync()

	fmt.Println("\n1. Creating notes...")
	fmt.Printf("Old note: %d coins, %d energy\n", oldNote.Value.Coins, oldNote.Value.Energy)
	fmt.Printf("New note: %d coins, %d energy\n", newNote.Value.Coins, newNote.Value.Energy)

	// Step 2: Compute serial number for old note
	fmt.Println("\n2. Computing serial number...")
	snOld := CalcSerialMimc(oldSk, oldNote.Rho)
	fmt.Printf("Serial number computed: %x\n", snOld[:8])

	// Step 3: Set up elliptic curve points for encryption
	fmt.Println("\n3. Setting up encryption parameters...")
	var g1Jac, _, _, _ = bls12377.Generators()
	var g, g_b, g_r, encKey bls12377.G1Affine
	var b, r bls12377_fp.Element

	// Generate random scalars using MiMC hash to ensure correct field format
	bSeed := randomBytes(32)
	bHash := mimcHash(bSeed)
	bBig := new(big.Int).SetBytes(bHash)
	bBig.Mod(bBig, bls12377_fr.Modulus())
	b.SetBigInt(bBig)

	rSeed := randomBytes(32)
	rHash := mimcHash(rSeed)
	rBig := new(big.Int).SetBytes(rHash)
	rBig.Mod(rBig, bls12377_fr.Modulus())
	r.SetBigInt(rBig)

	// Compute curve points
	g.FromJacobian(&g1Jac)
	g_b.ScalarMultiplication(&g, b.BigInt(new(big.Int)))
	g_r.ScalarMultiplication(&g, r.BigInt(new(big.Int)))
	encKey.ScalarMultiplication(&g_b, r.BigInt(new(big.Int)))

	fmt.Println("Encryption key generated successfully")

	// Debug prints for curve/scalar values
	fmt.Printf("[DEBUG] Go g_b.X: %s\n", g_b.X.String())
	fmt.Printf("[DEBUG] Go g_b.Y: %s\n", g_b.Y.String())
	fmt.Printf("[DEBUG] Go r: %s\n", r.String())
	fmt.Printf("[DEBUG] Go encKey.X: %s\n", encKey.X.String())
	fmt.Printf("[DEBUG] Go encKey.Y: %s\n", encKey.Y.String())

	// Step 4: Encrypt new note data
	fmt.Println("\n4. Encrypting new note data...")
	encVals := BuildEncMimc(encKey, newNote.PkOwner, newNote.Value.Coins, newNote.Value.Energy,
		new(big.Int).SetBytes(newNote.Rho), new(big.Int).SetBytes(newNote.Rand), newNote.Cm)
	fmt.Println("New note data encrypted successfully")

	// Step 5: Create witness for the circuit
	fmt.Println("\n5. Creating circuit witness...")
	witness := &CircuitTx{
		// Public inputs
		OldCoin:   oldNote.Value.Coins.String(),
		OldEnergy: oldNote.Value.Energy.String(),
		CmOld:     new(big.Int).SetBytes(oldNote.Cm).String(),
		SnOld:     new(big.Int).SetBytes(snOld).String(),
		PkOld:     new(big.Int).SetBytes(oldNote.PkOwner).String(),
		NewCoin:   newNote.Value.Coins.String(),
		NewEnergy: newNote.Value.Energy.String(),
		CmNew:     new(big.Int).SetBytes(newNote.Cm).String(),
		CNew: [6]frontend.Variable{
			encVals[0].String(), encVals[1].String(), encVals[2].String(),
			encVals[3].String(), encVals[4].String(), encVals[5].String(),
		},
		G:   toGnarkPoint(g),
		G_b: toGnarkPoint(g_b),
		G_r: toGnarkPoint(g_r),

		// Private inputs
		SkOld:   new(big.Int).SetBytes(oldSk).String(),
		RhoOld:  new(big.Int).SetBytes(oldNote.Rho).String(),
		RandOld: new(big.Int).SetBytes(oldNote.Rand).String(),
		PkNew:   new(big.Int).SetBytes(newNote.PkOwner).String(),
		RhoNew:  new(big.Int).SetBytes(newNote.Rho).String(),
		RandNew: new(big.Int).SetBytes(newNote.Rand).String(),
		R:       r.String(),
		EncKey:  toGnarkPoint(encKey),
	}

	// Print all debug info before any gnark calls
	fmt.Println("[DEBUG] Go-side encrypted new note values (CNew):")
	for i, v := range encVals {
		fmt.Printf("  Go CNew[%d]: %s\n", i, v.String())
	}
	fmt.Println("[DEBUG] Witness CNew values:")
	for i, v := range witness.CNew {
		fmt.Printf("  Witness CNew[%d]: %s\n", i, v)
	}
	fmt.Printf("[DEBUG] Witness CmOld: %s\n", witness.CmOld)
	fmt.Printf("[DEBUG] Witness CmNew: %s\n", witness.CmNew)
	fmt.Printf("[DEBUG] Witness SnOld: %s\n", witness.SnOld)
	fmt.Printf("[DEBUG] Witness PkOld: %s\n", witness.PkOld)
	fmt.Printf("[DEBUG] Witness PkNew: %s\n", witness.PkNew)
	fmt.Printf("[DEBUG] Witness G_b.X: %s\n", witness.G_b.X)
	fmt.Printf("[DEBUG] Witness G_b.Y: %s\n", witness.G_b.Y)
	fmt.Printf("[DEBUG] Witness R: %s\n", witness.R)
	fmt.Printf("[DEBUG] Witness EncKey.X: %s\n", witness.EncKey.X)
	fmt.Printf("[DEBUG] Witness EncKey.Y: %s\n", witness.EncKey.Y)
	os.Stdout.Sync()

	// Step 6: Compile the circuit
	fmt.Println("\n6. Compiling circuit...")
	var circuit CircuitTx
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(fmt.Errorf("circuit compilation failed: %w", err))
	}
	fmt.Printf("Circuit compiled successfully. Constraints: %d\n", ccs.GetNbConstraints())

	// Step 7: Generate proving and verifying keys
	fmt.Println("\n7. Generating proving and verifying keys...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(fmt.Errorf("groth16 setup failed: %w", err))
	}
	fmt.Println("Keys generated successfully")

	// Step 8: Create witness and generate proof
	fmt.Println("\n8. Generating zero-knowledge proof...")
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		panic(fmt.Errorf("witness creation failed: %w", err))
	}

	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		panic(fmt.Errorf("proof generation failed: %w", err))
	}
	fmt.Println("Zero-knowledge proof generated successfully")

	// Step 9: Verify the proof
	fmt.Println("\n9. Verifying proof...")
	publicWitness, err := w.Public()
	if err != nil {
		panic(fmt.Errorf("public witness extraction failed: %w", err))
	}

	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		fmt.Printf("❌ Proof verification failed: %v\n", err)
		return
	}

	fmt.Println("✅ Proof verified successfully!")
	fmt.Println("\n=== Transaction Summary ===")
	fmt.Printf("Old note: %d coins, %d energy\n", oldNote.Value.Coins, oldNote.Value.Energy)
	fmt.Printf("New note: %d coins, %d energy\n", newNote.Value.Coins, newNote.Value.Energy)
	fmt.Printf("Value conservation: ✅ Verified\n")
	fmt.Printf("Commitment integrity: ✅ Verified\n")
	fmt.Printf("Serial number validity: ✅ Verified\n")
	fmt.Printf("Encryption correctness: ✅ Verified\n")
	fmt.Println("\n🎉 Confidential transaction completed successfully!")

	// Test Algorithm1 function as well
	fmt.Println("\n=== Testing Algorithm1 Function ===")
	algSnOld, algCmNew, algCNew, algProof := Algorithm1()

	// Marshal proof to bytes for display
	var proofBuf bytes.Buffer
	_, err = algProof.WriteTo(&proofBuf)
	if err != nil {
		panic(fmt.Errorf("proof marshaling failed: %w", err))
	}
	algProofBytes := proofBuf.Bytes()

	fmt.Printf("Algorithm1 completed successfully:\n")
	fmt.Printf("  snOld: %x\n", algSnOld)
	fmt.Printf("  cmNew: %x\n", algCmNew)
	fmt.Printf("  cNew:  %v\n", algCNew)
	fmt.Printf("  proof: %x...\n", algProofBytes[:8])
}
