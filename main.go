package main

import (
	"log"
	"sync"

	"implementation/p2p"
)

func main() {
	var wg sync.WaitGroup

	// --- 1. Define Network Topology ---
	nodeConfigs := map[string]string{
		"auctioneer":    "localhost:8080",
		"participant-1": "localhost:8081",
		"participant-2": "localhost:8082",
		"participant-3": "localhost:8083",
	}

	// Create a complete peer directory for every node
	peerDirectory := make(map[string]string)
	for id, addr := range nodeConfigs {
		peerDirectory[id] = addr
	}

	// --- 2. Create and Start All Nodes ---
	nodes := make(map[string]*p2p.Node)
	for id, addr := range nodeConfigs {
		nodes[id] = p2p.NewNode(id, addr, peerDirectory, &wg)
	}

	readyCh := make(chan struct{})
	for _, node := range nodes {
		node.StartServer(readyCh)
	}

	// Wait for all nodes to signal that their servers are ready.
	for i := 0; i < len(nodes); i++ {
		<-readyCh
	}
	log.Println("--- All nodes are ready and listening ---")

	// --- 3. Run Simulation ---
	log.Println("--- Network simulation starting ---")

	// Participant-1 initiates a Diffie-Hellman key exchange with Participant-2
	log.Println("Initiating DH exchange between P1 and P2...")
	doneCh := nodes["participant-1"].InitiateDHExchange("participant-2")

	// Wait for the exchange to complete.
	err := <-doneCh
	if err != nil {
		log.Fatalf("DH exchange failed: %v", err)
	}
	log.Println("DH exchange completed.")

	// Verify that both nodes have the same shared secret
	// Note: We are accessing the DHKeys map directly for verification here.
	// In a real app, you might have a method like `GetSharedSecret(peerID)`.
	p1State := nodes["participant-1"].DHKeys["participant-2"]
	p2State := nodes["participant-2"].DHKeys["participant-1"]

	if p1State != nil && p2State != nil && p1State.SharedSecret.Equal(&p2State.SharedSecret) {
		log.Println("✅ SUCCESS: Participant-1 and Participant-2 have the same shared secret.")
	} else {
		log.Println("❌ FAILURE: Shared secrets do not match or are missing.")
		log.Printf("P1 Secret: %+v", p1State)
		log.Printf("P2 Secret: %+v", p2State)
	}

	log.Println("--- Network simulation finished ---")
}
