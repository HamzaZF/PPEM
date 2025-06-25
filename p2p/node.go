package p2p

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// HandlerFunc is the type for message handlers.
type HandlerFunc func(*Node, Message)

// Node represents a participant or auctioneer in the network.
type Node struct {
	ID        string
	Address   string
	Peers     map[string]string // Map of Node ID to its address
	server    *http.Server
	waitGroup *sync.WaitGroup

	// Message routing
	handlers map[string]HandlerFunc

	// DH Exchange state management
	dhMutex              sync.Mutex
	DHKeys               map[string]*DHState // Map of peer ID to their DH state
	dhCompletionChannels map[string]chan error

	// Health check
	health      map[string]bool
	healthMutex sync.Mutex
}

// NewNode creates and initializes a new Node.
func NewNode(id, address string, peers map[string]string, wg *sync.WaitGroup) *Node {
	n := &Node{
		ID:                   id,
		Address:              address,
		Peers:                peers,
		waitGroup:            wg,
		DHKeys:               make(map[string]*DHState),
		dhCompletionChannels: make(map[string]chan error),
		handlers:             make(map[string]HandlerFunc),
		health:               make(map[string]bool),
	}
	// Register default handlers
	n.RegisterHandler("dh_initiate", handleDHInitiate)
	n.RegisterHandler("dh_response", handleDHResponse)
	n.RegisterHandler("simple_text", handleSimpleText)
	n.RegisterHandler("ping", handlePing)
	n.RegisterHandler("pong", handlePong)
	return n
}

// RegisterHandler registers a handler for a message type.
func (n *Node) RegisterHandler(msgType string, handler HandlerFunc) {
	n.handlers[msgType] = handler
}

// messageHandler is the HTTP handler for receiving messages.
func (n *Node) messageHandler(w http.ResponseWriter, r *http.Request) {
	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		log.Printf("[%s] Received a bad request: %v", n.ID, err)
		return
	}
	log.Printf("[%s] Received message of type '%s'", n.ID, msg.Type)
	if handler, ok := n.handlers[msg.Type]; ok {
		handler(n, msg)
	} else {
		log.Printf("[%s] No handler for message type: %s", n.ID, msg.Type)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Message received")
}

// SendMessage sends a message to another node in the network with retry and timeout.
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
		Type:     messageType,
		Payload:  payloadBytes,
		SenderID: n.ID,
	}
	messageBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message envelope: %v", err)
	}

	var lastErr error
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, "POST", "http://"+targetAddress+"/message", bytes.NewBuffer(messageBytes))
		if err != nil {
			cancel()
			return fmt.Errorf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{}
		resp, err := client.Do(req)
		cancel()
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			log.Printf("[%s] Sent message '%s' to %s at %s", n.ID, messageType, targetID, targetAddress)
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		lastErr = err
		log.Printf("[%s] Retry %d for message '%s' to %s: %v", n.ID, attempt+1, messageType, targetID, err)
		time.Sleep(time.Duration(1<<attempt) * 100 * time.Millisecond) // Exponential backoff
	}
	return fmt.Errorf("failed to send message after retries: %v", lastErr)
}

// Broadcast sends a message to all peers.
func (n *Node) Broadcast(messageType string, payload interface{}) {
	for peerID := range n.Peers {
		if peerID == n.ID {
			continue
		}
		go n.SendMessage(peerID, messageType, payload)
	}
}

// HealthCheck pings all peers and updates health status.
func (n *Node) HealthCheck() {
	for peerID := range n.Peers {
		if peerID == n.ID {
			continue
		}
		go func(pid string) {
			err := n.SendMessage(pid, "ping", nil)
			n.healthMutex.Lock()
			n.health[pid] = (err == nil)
			n.healthMutex.Unlock()
		}(peerID)
	}
}

// handlePing responds to a ping with a pong.
func handlePing(n *Node, msg Message) {
	_ = n.SendMessage(msg.SenderID, "pong", nil)
}

// handlePong marks a peer as healthy.
func handlePong(n *Node, msg Message) {
	n.healthMutex.Lock()
	defer n.healthMutex.Unlock()
	n.health[msg.SenderID] = true
}

// StartServer starts the node's HTTP server in a new goroutine and supports graceful shutdown.
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
		ready <- struct{}{}
		if err := n.server.Serve(listener); err != http.ErrServerClosed {
			log.Fatalf("[%s] Server failed: %v", n.ID, err)
		}
		log.Printf("[%s] Server stopped.", n.ID)
	}()

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		log.Printf("[%s] Shutting down server...", n.ID)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = n.server.Shutdown(ctx)
	}()
}

// --- Example Handlers for Protocol Messages ---

// handleDHInitiate processes a DH initiation message.
func handleDHInitiate(n *Node, msg Message) {
	var payload DHInitiatePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		log.Printf("[%s] Error unmarshalling DHInitiatePayload: %v", n.ID, err)
		return
	}
	n.dhMutex.Lock()
	defer n.dhMutex.Unlock()
	log.Printf("[%s] Handling DH initiation from %s", n.ID, payload.SenderID)
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
	var sharedSecret bls12377.G1Affine
	var secret_b_bigint2 big.Int
	sharedSecret.ScalarMultiplication(&payload.PublicKey.G1Affine, secret_b.BigInt(&secret_b_bigint2))
	n.DHKeys[payload.SenderID] = &DHState{
		OurSecret:    secret_b,
		OurPublic:    public_B,
		TheirPublic:  payload.PublicKey.G1Affine,
		SharedSecret: sharedSecret,
		Status:       "completed",
	}
	log.Printf("[%s] Computed shared secret with %s: X=%s", n.ID, payload.SenderID, sharedSecret.X.String())
	responsePayload := DHResponsePayload{
		SenderID:  n.ID,
		PublicKey: G1AffineJSON{public_B},
	}
	go n.SendMessage(payload.SenderID, "dh_response", responsePayload)
}

// handleDHResponse processes a DH response message.
func handleDHResponse(n *Node, msg Message) {
	var payload DHResponsePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		log.Printf("[%s] Error unmarshalling DHResponsePayload: %v", n.ID, err)
		return
	}
	n.dhMutex.Lock()
	defer n.dhMutex.Unlock()
	log.Printf("[%s] Handling DH response from %s", n.ID, payload.SenderID)
	state, ok := n.DHKeys[payload.SenderID]
	if !ok || state.Status != "initiated" {
		log.Printf("[%s] Received a DH response for an unknown or completed session from %s", n.ID, payload.SenderID)
		return
	}
	var sharedSecret bls12377.G1Affine
	var secret_a_bigint big.Int
	sharedSecret.ScalarMultiplication(&payload.PublicKey.G1Affine, state.OurSecret.BigInt(&secret_a_bigint))
	state.TheirPublic = payload.PublicKey.G1Affine
	state.SharedSecret = sharedSecret
	state.Status = "completed"
	log.Printf("[%s] Computed shared secret with %s: X=%s", n.ID, payload.SenderID, sharedSecret.X.String())
	if ch, ok := n.dhCompletionChannels[payload.SenderID]; ok {
		ch <- nil
		close(ch)
		delete(n.dhCompletionChannels, payload.SenderID)
	}
}

// handleSimpleText processes a simple text message.
func handleSimpleText(n *Node, msg Message) {
	var textPayload SimpleTextMessage
	if err := json.Unmarshal(msg.Payload, &textPayload); err != nil {
		log.Printf("[%s] Error unmarshalling SimpleTextMessage payload: %v", n.ID, err)
		return
	}
	log.Printf("    -> Text Message: '%s'", textPayload.Content)
}

// InitiateDHExchange starts the key exchange process with a target peer.
// It returns a channel that will receive an error or nil upon completion.
func (n *Node) InitiateDHExchange(targetID string) <-chan error {
	doneCh := make(chan error)
	go func() {
		n.dhMutex.Lock()
		defer n.dhMutex.Unlock()
		log.Printf("[%s] Initiating DH exchange with %s", n.ID, targetID)
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
		n.DHKeys[targetID] = &DHState{
			OurSecret: secret_a,
			OurPublic: public_A,
			Status:    "initiated",
		}
		n.dhCompletionChannels[targetID] = doneCh
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
