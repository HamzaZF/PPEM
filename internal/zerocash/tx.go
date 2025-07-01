// tx.go - Transaction logic and zero-knowledge proof integration for the zerocash protocol.
//
// Implements confidential transaction creation, proof generation/verification, and note encryption.
// All cryptographic operations use secure randomness and are designed for unlinkability and confidentiality.
//
// WARNING: All cryptographic operations must use secure randomness and constant-time primitives where possible.

package zerocash

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

// Tx represents a Zerocash-like transaction.
// Contains old/new notes, ZKP proof, and all public inputs for verification.
type Tx struct {
	OldNote *Note  // The note being spent
	NewNote *Note  // The note being created
	Proof   []byte // ZKP proof (opaque, Groth16)
	// Public inputs for verification
	OldCoin     string
	OldEnergy   string
	CmOld       string
	SnOld       string
	PkOld       string
	NewCoin     string
	NewEnergy   string
	CmNew       string
	CNew        []byte    // Encrypted note data using ECDH + AES for auctioneer
	CNewCircuit [6]string // Circuit-compatible encrypted values for verification
	G           sw_bls12377.G1Affine
	G_b         sw_bls12377.G1Affine
	G_r         sw_bls12377.G1Affine
}

// CreateTx creates a new confidential transaction following Algorithm 1 from the paper.
// Algorithm 1: Transaction([n_i^old]^n_{i=1}, [sk_i^old]^n_{i=1}, [Γ_j^new]^m_{j=1}, [pk_j]^m_{j=1}) → (tx)
// Note: pk is passed as parameter, not computed inside (as per Algorithm 1)
// auctioneerECDHPubKey: Auctioneer's ECDH public key for note encryption
func CreateTx(oldNote *Note, oldSk, pkNew []byte, value, energy *big.Int, params *Params,
	ccs constraint.ConstraintSystem, pk groth16.ProvingKey, auctioneerECDHPubKey *ecdh.PublicKey) (*Tx, error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("[PANIC RECOVERED] in CreateTx. Witness struct:")
			fmt.Printf("oldNote: %+v\n", oldNote)
			fmt.Printf("oldSk: %x\n", oldSk)
			fmt.Printf("pkNew: %x\n", pkNew)
			fmt.Printf("value: %v, energy: %v\n", value, energy)
		}
	}()
	// Step 1: Validate that the secret key corresponds to the note owner
	h := mimcNative.NewMiMC()
	h.Write(oldSk)
	expectedPkOwner := h.Sum(nil)
	if !bytes.Equal(expectedPkOwner, oldNote.PkOwner) {
		return nil, fmt.Errorf("secret key does not match note owner")
	}

	// Step 2: Compute serial number for old note (prevents double-spending)
	h.Reset()
	h.Write(oldSk)
	h.Write(oldNote.Rho)
	snOld := h.Sum(nil)

	// Step 3: Compute rhoNew as H(0||snOld) to match circuit constraint
	h.Reset()
	h.Write([]byte{0}) // Add index 0 for single note output
	h.Write(snOld)     // Add serial number
	rhoNew := h.Sum(nil)

	// Step 4: Generate randomness for new note
	randNew := randomBytes(32)

	// Step 5: Compute commitment for new note following paper: cm = Com(Γ || pk || ρ, r)
	cmNew := Commitment(value, energy, pkNew, new(big.Int).SetBytes(rhoNew), new(big.Int).SetBytes(randNew))

	// Step 6: Build new note
	newNote := &Note{
		Value: Gamma{
			Coins:  value,
			Energy: energy,
		},
		PkOwner: pkNew,
		Rho:     rhoNew,
		Rand:    randNew,
		Cm:      cmNew,
	}

	// Step 7: Set up EC points for ZK circuit (using DH protocol for circuit compatibility)
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

	// Step 8: Encrypt note data using ECDH + AES-256-GCM for auctioneer
	encryptedNoteData, err := encryptNoteForAuctioneer(newNote, auctioneerECDHPubKey)
	if err != nil {
		return nil, fmt.Errorf("note encryption failed: %w", err)
	}

	// Step 9: Build fake encrypted values for circuit compatibility (circuit expects [6]string)
	encVals := buildEncMimc(encKey, newNote.PkOwner, newNote.Value.Coins, newNote.Value.Energy,
		new(big.Int).SetBytes(newNote.Rho), new(big.Int).SetBytes(newNote.Rand), newNote.Cm)
	var cNewStrs [6]string
	for i := 0; i < 6; i++ {
		cNewStrs[i] = encVals[i].String()
	}

	// Step 10: Compute PkOld as H(skOld) to match circuit constraint
	h.Reset()
	h.Write(oldSk)
	pkOldComputed := h.Sum(nil)

	// Step 11: Build witness for the circuit
	witness := &CircuitTx{
		OldCoin:   oldNote.Value.Coins.String(),
		OldEnergy: oldNote.Value.Energy.String(),
		CmOld:     new(big.Int).SetBytes(oldNote.Cm).String(),
		SnOld:     new(big.Int).SetBytes(snOld).String(),
		PkOld:     new(big.Int).SetBytes(pkOldComputed).String(),
		NewCoin:   newNote.Value.Coins.String(),
		NewEnergy: newNote.Value.Energy.String(),
		CmNew:     new(big.Int).SetBytes(newNote.Cm).String(),
		CNew: [6]frontend.Variable{
			cNewStrs[0], cNewStrs[1], cNewStrs[2],
			cNewStrs[3], cNewStrs[4], cNewStrs[5],
		},
		G:       toGnarkPoint(g),
		G_b:     toGnarkPoint(g_b),
		G_r:     toGnarkPoint(g_r),
		SkOld:   new(big.Int).SetBytes(oldSk).String(),
		RhoOld:  new(big.Int).SetBytes(oldNote.Rho).String(),
		RandOld: new(big.Int).SetBytes(oldNote.Rand).String(),
		PkNew:   new(big.Int).SetBytes(newNote.PkOwner).String(),
		RhoNew:  new(big.Int).SetBytes(newNote.Rho).String(),
		RandNew: new(big.Int).SetBytes(newNote.Rand).String(),
		R:       r.String(),
		EncKey:  toGnarkPoint(encKey),
	}
	fmt.Printf("[DEBUG] About to create witness: %+v\n", witness)
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %w", err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %w", err)
	}
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return nil, fmt.Errorf("proof marshaling failed: %w", err)
	}
	return &Tx{
		OldNote:     oldNote,
		NewNote:     newNote,
		Proof:       proofBuf.Bytes(),
		OldCoin:     oldNote.Value.Coins.String(),
		OldEnergy:   oldNote.Value.Energy.String(),
		CmOld:       new(big.Int).SetBytes(oldNote.Cm).String(),
		SnOld:       new(big.Int).SetBytes(snOld).String(),
		PkOld:       new(big.Int).SetBytes(pkOldComputed).String(),
		NewCoin:     newNote.Value.Coins.String(),
		NewEnergy:   newNote.Value.Energy.String(),
		CmNew:       new(big.Int).SetBytes(newNote.Cm).String(),
		CNew:        encryptedNoteData, // Real encrypted note data for auctioneer
		CNewCircuit: cNewStrs,          // Circuit-compatible values for verification
		G:           toGnarkPoint(g),
		G_b:         toGnarkPoint(g_b),
		G_r:         toGnarkPoint(g_r),
	}, nil
}

// VerifyTx verifies a Zerocash-like transaction.
// Steps:
//  1. Rebuild the circuit and public witness
//  2. Unmarshal the proof
//  3. Verify the Groth16 proof
//
// Returns an error if verification fails.
func VerifyTx(tx *Tx, params *Params, vk groth16.VerifyingKey) error {
	// Step 1: Rebuild the circuit and public witness
	var circuit CircuitTx
	_, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return fmt.Errorf("circuit compilation failed: %w", err)
	}

	// Step 2: Rebuild the public witness
	witness := &CircuitTx{
		OldCoin:   tx.OldCoin,
		OldEnergy: tx.OldEnergy,
		CmOld:     tx.CmOld,
		SnOld:     tx.SnOld,
		PkOld:     tx.PkOld,
		NewCoin:   tx.NewCoin,
		NewEnergy: tx.NewEnergy,
		CmNew:     tx.CmNew,
		CNew: [6]frontend.Variable{
			tx.CNewCircuit[0], tx.CNewCircuit[1], tx.CNewCircuit[2],
			tx.CNewCircuit[3], tx.CNewCircuit[4], tx.CNewCircuit[5],
		},
		G:   tx.G,
		G_b: tx.G_b,
		G_r: tx.G_r,
	}
	w, err := frontend.NewWitness(witness, ecc.BW6_761.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("public witness creation failed: %w", err)
	}

	// Step 3: Unmarshal proof
	proof := groth16.NewProof(ecc.BW6_761)
	_, err = proof.ReadFrom(bytes.NewReader(tx.Proof))
	if err != nil {
		return fmt.Errorf("proof unmarshaling failed: %w", err)
	}

	// Step 5: Verify the proof
	if err := groth16.Verify(proof, vk, w); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}
	return nil
}

// buildEncMimc encrypts note data using MiMC and the encryption key.
// Returns an array of BLS12-377 field elements (for use in the circuit).
func buildEncMimc(encKey bls12377.G1Affine, pk []byte, coins, energy, rho, rand *big.Int, cm []byte) [6]bls12377_fp.Element {
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

// toGnarkPoint converts a native BLS12-377 point to gnark format.
func toGnarkPoint(p bls12377.G1Affine) sw_bls12377.G1Affine {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	return sw_bls12377.G1Affine{
		X: new(big.Int).SetBytes(xBytes[:]).String(),
		Y: new(big.Int).SetBytes(yBytes[:]).String(),
	}
}

// SaveProvingKey saves a Groth16 proving key to disk.
func SaveProvingKey(path string, pk groth16.ProvingKey) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = pk.WriteTo(f)
	return err
}

// SaveVerifyingKey saves a Groth16 verifying key to disk.
func SaveVerifyingKey(path string, vk groth16.VerifyingKey) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = vk.WriteTo(f)
	return err
}

// LoadProvingKey loads a Groth16 proving key from disk.
func LoadProvingKey(path string) (groth16.ProvingKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pk := groth16.NewProvingKey(ecc.BW6_761)
	_, err = pk.ReadFrom(f)
	return pk, err
}

// LoadVerifyingKey loads a Groth16 verifying key from disk.
func LoadVerifyingKey(path string) (groth16.VerifyingKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	vk := groth16.NewVerifyingKey(ecc.BW6_761)
	_, err = vk.ReadFrom(f)
	return vk, err
}

// SetupOrLoadKeys generates or loads Groth16 keys for the circuit.
// If keys exist on disk, loads them; otherwise, generates and saves new keys.
func SetupOrLoadKeys(ccs constraint.ConstraintSystem, pkPath, vkPath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, pkErr := LoadProvingKey(pkPath)
	vk, vkErr := LoadVerifyingKey(vkPath)
	if pkErr == nil && vkErr == nil {
		return pk, vk, nil
	}
	// Generate keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, err
	}
	if err := SaveProvingKey(pkPath, pk); err != nil {
		return nil, nil, err
	}
	if err := SaveVerifyingKey(vkPath, vk); err != nil {
		return nil, nil, err
	}
	return pk, vk, nil
}

// encryptNoteForAuctioneer encrypts note data using ECDH + AES-256-GCM
func encryptNoteForAuctioneer(note *Note, auctioneerECDHPubKey *ecdh.PublicKey) ([]byte, error) {
	// 1. Generate ephemeral ECDH key pair
	ephemeralPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPubKey := ephemeralPrivKey.PublicKey()

	// 2. Compute shared secret
	sharedSecret, err := ephemeralPrivKey.ECDH(auctioneerECDHPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	// 3. Derive AES key from shared secret
	aesKey := sha256.Sum256(sharedSecret)

	// 4. Prepare note data for encryption
	noteData := map[string]interface{}{
		"pk":     note.PkOwner,
		"coins":  note.Value.Coins.String(),
		"energy": note.Value.Energy.String(),
		"rho":    note.Rho,
		"rand":   note.Rand,
		"cm":     note.Cm,
	}

	plaintextBytes, err := json.Marshal(noteData)
	if err != nil {
		return nil, fmt.Errorf("JSON marshaling failed: %w", err)
	}

	// 5. Encrypt with AES-256-GCM
	aesCipher, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintextBytes, nil)

	// 6. Return (ephemeralPubKey + nonce + ciphertext)
	ephemeralPubKeyBytes := ephemeralPubKey.Bytes()
	result := make([]byte, 0, len(ephemeralPubKeyBytes)+len(nonce)+len(ciphertext))
	result = append(result, ephemeralPubKeyBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptNoteFromAuctioneer decrypts note data using ECDH + AES-256-GCM
func DecryptNoteFromAuctioneer(encryptedData []byte, auctioneerECDHPrivKey *ecdh.PrivateKey) (*Note, error) {
	// 1. Extract ephemeral public key (first 65 bytes for P256 uncompressed)
	if len(encryptedData) < 65 {
		return nil, fmt.Errorf("encrypted data too short")
	}

	ephemeralPubKeyBytes := encryptedData[:65]
	ephemeralPubKey, err := ecdh.P256().NewPublicKey(ephemeralPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// 2. Compute shared secret
	sharedSecret, err := auctioneerECDHPrivKey.ECDH(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}

	// 3. Derive AES key from shared secret
	aesKey := sha256.Sum256(sharedSecret)

	// 4. Create AES-GCM cipher
	aesCipher, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("AES cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("GCM creation failed: %w", err)
	}

	// 5. Extract nonce and ciphertext
	remaining := encryptedData[65:]
	if len(remaining) < gcm.NonceSize() {
		return nil, fmt.Errorf("encrypted data too short for nonce")
	}

	nonce := remaining[:gcm.NonceSize()]
	ciphertext := remaining[gcm.NonceSize():]

	// 6. Decrypt
	plaintextBytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// 7. Unmarshal note data
	var noteData map[string]interface{}
	if err := json.Unmarshal(plaintextBytes, &noteData); err != nil {
		return nil, fmt.Errorf("JSON unmarshaling failed: %w", err)
	}

	// 8. Reconstruct note
	coins := new(big.Int)
	coins.SetString(noteData["coins"].(string), 10)
	energy := new(big.Int)
	energy.SetString(noteData["energy"].(string), 10)

	note := &Note{
		Value: Gamma{
			Coins:  coins,
			Energy: energy,
		},
		PkOwner: noteData["pk"].([]byte),
		Rho:     noteData["rho"].([]byte),
		Rand:    noteData["rand"].([]byte),
		Cm:      noteData["cm"].([]byte),
	}

	return note, nil
}
