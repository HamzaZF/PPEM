package p2p

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// Node represents a participant or auctioneer in the network.
type Node struct {
	ID        string
	Address   string
	Peers     map[string]string // Map of Node ID to its address
	server    *http.Server
	waitGroup *sync.WaitGroup

	// DH Exchange state management
	dhMutex              sync.Mutex
	DHKeys               map[string]*DHState // Map of peer ID to their DH state
	dhCompletionChannels map[string]chan error
}

// NewNode creates and initializes a new Node.
func NewNode(id, address string, peers map[string]string, wg *sync.WaitGroup) *Node {
	return &Node{
		ID:                   id,
		Address:              address,
		Peers:                peers,
		waitGroup:            wg,
		DHKeys:               make(map[string]*DHState),
		dhCompletionChannels: make(map[string]chan error),
	}
}

// messageHandler is the HTTP handler for receiving messages.
// It decodes the message envelope and then processes the payload based on its type.
func (n *Node) messageHandler(w http.ResponseWriter, r *http.Request) {
	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("[%s] Received a bad request: %v", n.ID, err)
		return
	}

	log.Printf("[%s] Received message of type '%s'", n.ID, msg.Type)

	// Here we decide what to do based on the message type.
	// This is where the flexible deserialization happens.
	switch msg.Type {
	case "dh_initiate":
		var payload DHInitiatePayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			log.Printf("[%s] Error unmarshalling DHInitiatePayload: %v", n.ID, err)
			return
		}
		n.handleDHInitiate(payload)

	case "dh_response":
		var payload DHResponsePayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			log.Printf("[%s] Error unmarshalling DHResponsePayload: %v", n.ID, err)
			return
		}
		n.handleDHResponse(payload)

	case "simple_text":
		var textPayload SimpleTextMessage
		if err := json.Unmarshal(msg.Payload, &textPayload); err != nil {
			log.Printf("[%s] Error unmarshalling SimpleTextMessage payload: %v", n.ID, err)
			return
		}
		log.Printf("    -> Text Message: '%s'", textPayload.Content)

	default:
		log.Printf("[%s] Received unknown message type: %s", n.ID, msg.Type)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Message received")
}

// handleDHInitiate is called by the responder when it receives an initiation request.
// It generates its own key, computes the shared secret, stores it, and
// sends its own public key `B` back in a `dh_response` message.
func (n *Node) handleDHInitiate(payload DHInitiatePayload) {
	n.dhMutex.Lock()
	defer n.dhMutex.Unlock()

	log.Printf("[%s] Handling DH initiation from %s", n.ID, payload.SenderID)

	// 1. Generate our own ephemeral key pair (secret_b, public_B)
	var secret_b fr.Element
	_, err := secret_b.SetRandom()
	if err != nil {
		log.Printf("[%s] Failed to generate random secret: %v", n.ID, err)
		return
	}

	g1Jac, _, _, _ := bls12377.Generators()
	var g1Gen bls12377.G1Affine
	g1Gen.FromJacobian(&g1Jac)

	var public_B bls12377.G1Affine
	var secret_b_bigint big.Int
	public_B.ScalarMultiplication(&g1Gen, secret_b.BigInt(&secret_b_bigint))

	// 2. Compute the shared secret: S = public_A ^ secret_b
	// public_A is the key received from the initiator.
	var sharedSecret bls12377.G1Affine
	var secret_b_bigint2 big.Int
	sharedSecret.ScalarMultiplication(&payload.PublicKey.G1Affine, secret_b.BigInt(&secret_b_bigint2))

	// 3. Store the complete state of the exchange
	n.DHKeys[payload.SenderID] = &DHState{
		OurSecret:    secret_b,
		OurPublic:    public_B,
		TheirPublic:  payload.PublicKey.G1Affine,
		SharedSecret: sharedSecret,
		Status:       "completed",
	}

	log.Printf("[%s] Computed shared secret with %s: X=%s", n.ID, payload.SenderID, sharedSecret.X.String())

	// 4. Send our public key back to the initiator
	responsePayload := DHResponsePayload{
		SenderID:  n.ID,
		PublicKey: G1AffineJSON{public_B},
	}

	// Sending the response in a goroutine so we don't block the handler
	go func() {
		err := n.SendMessage(payload.SenderID, "dh_response", responsePayload)
		if err != nil {
			log.Printf("[%s] Error sending DH response to %s: %v", n.ID, payload.SenderID, err)
		}
	}()
}

// handleDHResponse is called by the initiator when it receives the responder's public key.
func (n *Node) handleDHResponse(payload DHResponsePayload) {
	n.dhMutex.Lock()
	defer n.dhMutex.Unlock()

	log.Printf("[%s] Handling DH response from %s", n.ID, payload.SenderID)

	// 1. Find the original state we stored for this peer
	state, ok := n.DHKeys[payload.SenderID]
	if !ok || state.Status != "initiated" {
		log.Printf("[%s] Received a DH response for an unknown or completed session from %s", n.ID, payload.SenderID)
		return
	}

	// 2. Compute the shared secret: S = public_B ^ secret_a
	// public_B is the key received from the responder. secret_a is our original secret.
	var sharedSecret bls12377.G1Affine
	var secret_a_bigint big.Int
	sharedSecret.ScalarMultiplication(&payload.PublicKey.G1Affine, state.OurSecret.BigInt(&secret_a_bigint))

	// 3. Update the state
	state.TheirPublic = payload.PublicKey.G1Affine
	state.SharedSecret = sharedSecret
	state.Status = "completed"

	log.Printf("[%s] Computed shared secret with %s: X=%s", n.ID, payload.SenderID, sharedSecret.X.String())

	// 4. Signal completion on the channel
	if ch, ok := n.dhCompletionChannels[payload.SenderID]; ok {
		ch <- nil
		close(ch)
		delete(n.dhCompletionChannels, payload.SenderID)
	}
}

// InitiateDHExchange starts the key exchange process with a target peer.
// It returns a channel that will receive an error or nil upon completion.
func (n *Node) InitiateDHExchange(targetID string) <-chan error {
	doneCh := make(chan error)

	go func() {
		n.dhMutex.Lock()
		defer n.dhMutex.Unlock()

		log.Printf("[%s] Initiating DH exchange with %s", n.ID, targetID)

		// 1. Generate our ephemeral key pair (secret_a, public_A)
		var secret_a fr.Element
		_, err := secret_a.SetRandom()
		if err != nil {
			doneCh <- fmt.Errorf("failed to generate random secret: %v", err)
			close(doneCh)
			return
		}

		g1Jac, _, _, _ := bls12377.Generators()
		var g1Gen bls12377.G1Affine
		g1Gen.FromJacobian(&g1Jac)

		var public_A bls12377.G1Affine
		var secret_a_bigint big.Int
		public_A.ScalarMultiplication(&g1Gen, secret_a.BigInt(&secret_a_bigint))

		// 2. Store our half of the state, marking it as "initiated"
		n.DHKeys[targetID] = &DHState{
			OurSecret: secret_a,
			OurPublic: public_A,
			Status:    "initiated",
		}

		// Store the completion channel
		n.dhCompletionChannels[targetID] = doneCh

		// 3. Send our public key to the target
		payload := DHInitiatePayload{
			SenderID:  n.ID,
			PublicKey: G1AffineJSON{public_A},
		}

		if err := n.SendMessage(targetID, "dh_initiate", payload); err != nil {
			doneCh <- fmt.Errorf("failed to send dh_initiate message: %v", err)
			close(doneCh)
			delete(n.dhCompletionChannels, targetID)
		}
	}()

	return doneCh
}

// StartServer starts the node's HTTP server in a new goroutine.
// It signals on the 'ready' channel once the server is actively listening.
func (n *Node) StartServer(ready chan<- struct{}) {
	mux := http.NewServeMux()
	mux.HandleFunc("/message", n.messageHandler)

	n.server = &http.Server{
		Addr:    n.Address,
		Handler: mux,
	}

	listener, err := net.Listen("tcp", n.Address)
	if err != nil {
		log.Fatalf("[%s] failed to listen: %v", n.ID, err)
	}

	n.waitGroup.Add(1)
	go func() {
		defer n.waitGroup.Done()
		log.Printf("[%s] Server starting on %s", n.ID, n.Address)

		// Signal that the server is up and ready
		ready <- struct{}{}

		if err := n.server.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("[%s] Server failed: %v", n.ID, err)
		}
		log.Printf("[%s] Server stopped.", n.ID)
	}()
}

// SendMessage sends a message to another node in the network.
// The payload can be any struct that is marshallable to JSON.
func (n *Node) SendMessage(targetID, messageType string, payload interface{}) error {
	targetAddress, ok := n.Peers[targetID]
	if !ok {
		return fmt.Errorf("peer '%s' not found in directory", targetID)
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	msg := Message{
		Type:    messageType,
		Payload: payloadBytes,
	}

	messageBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message envelope: %v", err)
	}

	log.Printf("[%s] Sending message of type '%s' to %s at %s", n.ID, messageType, targetID, targetAddress)
	req, err := http.NewRequest("POST", "http://"+targetAddress+"/message", bytes.NewBuffer(messageBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer returned non-OK status: %s", resp.Status)
	}

	return nil
}
