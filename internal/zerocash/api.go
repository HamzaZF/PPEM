// api.go - REST API and participant orchestration for the zerocash protocol.
//
// Exposes endpoints for public key retrieval and confidential transaction submission.
// Implements the Participant type, which manages keys, wallet, and protocol logic.
// All transactions are appended to the global ledger (ledger.json).
//
// Each participant maintains a Wallet file (e.g., bob_wallet.json) for their own notes and keys.
//
// WARNING: All REST endpoints must validate input and handle errors securely.

package zerocash

// This file re-exports the main API for the zerocash package.
// Users should import zerocash and use CreateTx, VerifyTx, etc.

// (All main types and functions are already public in their respective files.)

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
)

// PubKeyResponse is the REST response for a public key
// X, Y are hex-encoded BLS12-377 G1Affine coordinates
type PubKeyResponse struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// TxRequest is the REST request for sending a confidential transaction
type TxRequest struct {
	SenderPub PubKeyResponse `json:"sender_pub"`
	Tx        *Tx            `json:"tx"`
}

// Wallet stores a participant's private keys and recognized notes.
type Wallet struct {
	Name     string // Participant name
	Sk       *fr.Element
	Pk       *bls12377.G1Affine
	Notes    []*Note  // All notes recognized as belonging to this participant
	NoteKeys [][]byte // Secret keys for notes (optional, for spending)
	Spent    []bool   // Track whether each note has been spent (consumed)
	// Withdraw support fields
	rEnc            [][]byte    // Registration randomness for each note
	CAux            [][][5]byte // Registration ciphertext for each note (as array of 5 byte slices)
	WithdrawOutNote []*Note     // Output note for withdraw for each note
}

// LoadWallet loads a wallet from a JSON file.
func LoadWallet(path string) (*Wallet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var w Wallet
	dec := json.NewDecoder(f)
	if err := dec.Decode(&w); err != nil {
		return nil, err
	}
	return &w, nil
}

// Save saves the wallet to a JSON file.
func (w *Wallet) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(w)
}

// AddNote adds a recognized note to the wallet, with withdraw data.
func (w *Wallet) AddNote(note *Note, sk []byte, rEnc []byte, cAux [5]byte, outNote *Note) {
	w.Notes = append(w.Notes, note)
	w.NoteKeys = append(w.NoteKeys, sk)
	w.Spent = append(w.Spent, false)
	w.rEnc = append(w.rEnc, rEnc)
	w.CAux = append(w.CAux, [][5]byte{cAux})
	w.WithdrawOutNote = append(w.WithdrawOutNote, outNote)
}

// MarkNoteAsSpent marks a note as spent by its index.
func (w *Wallet) MarkNoteAsSpent(noteIndex int) error {
	if noteIndex < 0 || noteIndex >= len(w.Spent) {
		return fmt.Errorf("invalid note index: %d", noteIndex)
	}
	w.Spent[noteIndex] = true
	return nil
}

// GetUnspentNotes returns all notes that haven't been spent yet.
func (w *Wallet) GetUnspentNotes() []*Note {
	var unspent []*Note
	for i, spent := range w.Spent {
		if !spent {
			unspent = append(unspent, w.Notes[i])
		}
	}
	return unspent
}

// GetUnspentNoteKeys returns secret keys for unspent notes.
func (w *Wallet) GetUnspentNoteKeys() [][]byte {
	var unspentKeys [][]byte
	for i, spent := range w.Spent {
		if !spent {
			unspentKeys = append(unspentKeys, w.NoteKeys[i])
		}
	}
	return unspentKeys
}

// CheckNoteStatusAgainstLedger dynamically checks if notes have been spent by looking at the ledger.
// This is useful for detecting if notes were spent by other participants or in other sessions.
func (w *Wallet) CheckNoteStatusAgainstLedger(ledger *Ledger) {
	for i, note := range w.Notes {
		// Compute serial number for this note using its secret key
		sk := w.NoteKeys[i]
		h := mimcNative.NewMiMC()
		h.Write(sk)
		h.Write(note.Rho)
		sn := h.Sum(nil)
		snStr := new(big.Int).SetBytes(sn).String()

		// Check if this serial number exists in the ledger (meaning the note was spent)
		if ledger.HasSerialNumber(snStr) {
			w.Spent[i] = true
		}
	}
}

// Helper to convert [N]byte to []byte
func toBytes(arr interface{}) []byte {
	switch v := arr.(type) {
	case [32]byte:
		return v[:]
	case [48]byte:
		return v[:]
	default:
		return nil
	}
}

func (w *Wallet) ClaimExchangeOutput(ledger *Ledger) error {
	// For each tx in the ledger, check if NewNote matches this wallet's pk
	for _, tx := range ledger.TxList {
		if tx.NewNote != nil && bytes.Equal(tx.NewNote.PkOwner, toBytes(w.Pk.X)) {
			// Check if already claimed
			alreadyClaimed := false
			for _, note := range w.Notes {
				if bytes.Equal(note.Cm, tx.NewNote.Cm) {
					alreadyClaimed = true
					break
				}
			}
			if !alreadyClaimed {
				w.AddNote(tx.NewNote, toBytes(w.Sk.Bytes()), nil, [5]byte{}, tx.NewNote)
				return w.Save(fmt.Sprintf("%s_wallet.json", w.Name))
			}
			return nil // Already claimed
		}
	}
	return fmt.Errorf("no exchange output found for this wallet")
}

func (w *Wallet) GetWithdrawREnc() []byte {
	for i, spent := range w.Spent {
		if !spent {
			return w.rEnc[i]
		}
	}
	return nil
}

func (w *Wallet) GetWithdrawSk() []byte {
	// Return the secret key for the first unspent note
	for i, spent := range w.Spent {
		if !spent {
			return w.NoteKeys[i]
		}
	}
	return nil
}

func (w *Wallet) GetWithdrawOutputNote() *Note {
	// Placeholder: construct output note as needed
	return nil // Implement as per your protocol
}

func (w *Wallet) GetWithdrawPkT() *bls12377.G1Affine {
	// Return auctioneer's pk if stored
	return w.Pk // Update if you store auctioneer's pk separately
}

func (w *Wallet) GetWithdrawCipherAux() [3][]byte {
	// Placeholder: return registration ciphertext if stored
	return [3][]byte{} // Update if you store ciphertext in the wallet
}

type Role string

const (
	RoleParticipant = "participant"
	RoleAuctioneer  = "auctioneer"
)

// Participant represents a node in the protocol
// Holds DH keypair, ZKP keys, wallet, and REST logic
type Participant struct {
	Name          string
	Role          Role
	Sk            *fr.Element
	Pk            *bls12377.G1Affine
	Params        *Params
	PK            groth16.ProvingKey
	VK            groth16.VerifyingKey
	Wallet        *Wallet
	AuctioneerPub *bls12377.G1Affine // Only for participants
	Mu            sync.Mutex         // for wallet concurrency
}

// NewParticipant creates a new node with fresh DH keypair and ZKP keys
// Loads or creates a wallet file for the participant.
func NewParticipant(name string, pk groth16.ProvingKey, vk groth16.VerifyingKey, params *Params, role Role, auctioneerPub *bls12377.G1Affine) *Participant {
	kp, err := GenerateDHKeyPair()
	if err != nil {
		log.Fatalf("%s DH keygen failed: %v", name, err)
	}
	walletPath := fmt.Sprintf("%s_wallet.json", name)
	var wallet *Wallet
	if w, err := LoadWallet(walletPath); err == nil {
		wallet = w
	} else {
		wallet = &Wallet{
			Name:            name,
			Sk:              kp.Sk,
			Pk:              kp.Pk,
			Notes:           []*Note{},
			NoteKeys:        [][]byte{},
			Spent:           []bool{},
			rEnc:            [][]byte{},
			CAux:            [][][5]byte{},
			WithdrawOutNote: []*Note{},
		}
		wallet.Save(walletPath)
	}
	return &Participant{
		Name:          name,
		Role:          role,
		Sk:            kp.Sk,
		Pk:            kp.Pk,
		Params:        params,
		PK:            pk,
		VK:            vk,
		Wallet:        wallet,
		AuctioneerPub: auctioneerPub,
	}
}

// PubKeyResponse returns the public key as a REST response
func (p *Participant) PubKeyResponse() PubKeyResponse {
	xBytes := p.Pk.X.Bytes()
	yBytes := p.Pk.Y.Bytes()
	xHex := hex.EncodeToString(xBytes[:])
	yHex := hex.EncodeToString(yBytes[:])
	return PubKeyResponse{X: xHex, Y: yHex}
}

// SharedSecret computes the DH shared secret with another public key
func (p *Participant) SharedSecret(otherPub *bls12377.G1Affine) *bls12377.G1Affine {
	return ComputeDHShared(p.Sk, otherPub)
}

// DeriveNoteKey hashes the shared secret to produce a 32-byte note secret key
func DeriveNoteKey(shared *bls12377.G1Affine) []byte {
	h := sha256.New()
	xBytes := shared.X.Bytes()
	yBytes := shared.Y.Bytes()
	h.Write(xBytes[:])
	h.Write(yBytes[:])
	return h.Sum(nil)
}

// RunServer starts the REST server for this participant
func (p *Participant) RunServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/pubkey", p.handlePubKey)
	mux.HandleFunc("/tx", p.handleTx)
	go func() {
		log.Printf("[%s] Listening on :%d", p.Name, port)
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), mux); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()
}

// handlePubKey serves the public key as JSON
func (p *Participant) handlePubKey(w http.ResponseWriter, r *http.Request) {
	resp := p.PubKeyResponse()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleTx receives a confidential transaction and processes it
func (p *Participant) handleTx(w http.ResponseWriter, r *http.Request) {
	var req TxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid request: %v", err)
		return
	}
	// Rebuild sender's pubkey
	var senderPub bls12377.G1Affine
	xBytes, err := hex.DecodeString(req.SenderPub.X)
	if err != nil || len(xBytes) != 48 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid sender pubkey X")
		return
	}
	yBytes, err := hex.DecodeString(req.SenderPub.Y)
	if err != nil || len(yBytes) != 48 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid sender pubkey Y")
		return
	}
	senderPub.X.SetBytes(xBytes)
	senderPub.Y.SetBytes(yBytes)
	// Verify transaction
	if err := VerifyTx(req.Tx, p.Params, p.VK); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid tx: %v", err)
		return
	}
	// Compute shared secret
	shared := ComputeDHShared(p.Sk, &senderPub)
	// Try to recognize/decrypt the note
	enc := EncryptNoteWithSharedKey(req.Tx.NewNote, shared)
	ok, note, err := RecognizeNote(enc, shared, req.Tx.NewNote.PkOwner)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "decryption failed: %v", err)
		return
	}
	if ok {
		p.Mu.Lock()
		// Append to global ledger
		ledgerPath := "ledger.json"
		var ledger *Ledger
		if l, err := LoadLedgerFromFile(ledgerPath); err == nil {
			ledger = l
		} else {
			ledger = NewLedger()
		}
		if err := ledger.AppendTx(req.Tx); err != nil {
			p.Mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintf(w, "ledger append failed: %v", err)
			return
		}
		if err := ledger.SaveToFile(ledgerPath); err != nil {
			p.Mu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "ledger save failed: %v", err)
			return
		}
		// Update wallet
		skBytes := p.Sk.Bytes()
		p.Wallet.AddNote(note, skBytes[:], nil, [5]byte{}, note)
		walletPath := fmt.Sprintf("%s_wallet.json", p.Name)
		if err := p.Wallet.Save(walletPath); err != nil {
			p.Mu.Unlock()
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, "wallet save failed: %v", err)
			return
		}
		p.Mu.Unlock()
		fmt.Fprintf(w, "note received: coins=%s, energy=%s", note.Value.Coins, note.Value.Energy)
		log.Printf("[%s] Received and decrypted note: coins=%s, energy=%s", p.Name, note.Value.Coins, note.Value.Energy)
	} else {
		fmt.Fprintf(w, "note not recognized as mine")
	}
}

// FetchPeerPubKey fetches a peer's public key from their REST endpoint
func FetchPeerPubKey(addr string) (*bls12377.G1Affine, error) {
	resp, err := http.Get(fmt.Sprintf("http://%s/pubkey", addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var pkResp PubKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&pkResp); err != nil {
		return nil, err
	}
	xBytes, err := hex.DecodeString(pkResp.X)
	if err != nil || len(xBytes) != 48 {
		return nil, fmt.Errorf("invalid pubkey X")
	}
	yBytes, err := hex.DecodeString(pkResp.Y)
	if err != nil || len(yBytes) != 48 {
		return nil, fmt.Errorf("invalid pubkey Y")
	}
	var pk bls12377.G1Affine
	pk.X.SetBytes(xBytes)
	pk.Y.SetBytes(yBytes)
	return &pk, nil
}

// SendTxToPeer sends a confidential transaction to a peer's REST endpoint
func SendTxToPeer(addr string, senderPub *bls12377.G1Affine, tx *Tx) error {
	xBytes := senderPub.X.Bytes()
	yBytes := senderPub.Y.Bytes()
	req := TxRequest{
		SenderPub: PubKeyResponse{
			X: hex.EncodeToString(xBytes[:]),
			Y: hex.EncodeToString(yBytes[:]),
		},
		Tx: tx,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("http://%s/tx", addr), "application/json", bytesReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("[client] Peer response: %s", string(body))
	return nil
}

// bytesReader is a helper for io.Reader from []byte
func bytesReader(b []byte) io.Reader {
	return &byteReader{b: b}
}

type byteReader struct {
	b []byte
	p int
}

func (r *byteReader) Read(p []byte) (int, error) {
	n := copy(p, r.b[r.p:])
	r.p += n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

type G1Affine = bls12377.G1Affine
