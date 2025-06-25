package p2p

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// Helper to create a test network of nodes with unique ports
func setupTestNetwork(t *testing.T, nodeIDs []string, basePort int) map[string]*Node {
	peerDirectory := make(map[string]string)
	for i, id := range nodeIDs {
		peerDirectory[id] = fmt.Sprintf("localhost:%d", basePort+i)
	}
	nodes := make(map[string]*Node)
	var wg sync.WaitGroup
	readyCh := make(chan struct{})
	for id, addr := range peerDirectory {
		nodes[id] = NewNode(id, addr, peerDirectory, &wg)
	}
	for _, node := range nodes {
		node.StartServer(readyCh)
	}
	for i := 0; i < len(nodes); i++ {
		<-readyCh
	}
	return nodes
}

func shutdownNetwork(nodes map[string]*Node) {
	for _, n := range nodes {
		n.server.Close()
	}
}

func TestSimpleTextMessage(t *testing.T) {
	nodes := setupTestNetwork(t, []string{"A", "B"}, 9100)
	defer shutdownNetwork(nodes)
	done := make(chan struct{}, 1) // Buffered to avoid blocking
	var once sync.Once
	nodes["B"].RegisterHandler("test_text", func(n *Node, msg Message) {
		once.Do(func() { done <- struct{}{} })
	})
	err := nodes["A"].SendMessage("B", "test_text", SimpleTextMessage{Content: "hello"})
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for message")
	}
}

func TestBroadcast(t *testing.T) {
	nodes := setupTestNetwork(t, []string{"A", "B", "C"}, 9200)
	defer shutdownNetwork(nodes)
	var mu sync.Mutex
	received := make(map[string]bool)
	for _, id := range []string{"B", "C"} {
		nodes[id].RegisterHandler("broadcast", func(n *Node, msg Message) {
			mu.Lock()
			received[n.ID] = true
			mu.Unlock()
		})
	}
	nodes["A"].Broadcast("broadcast", SimpleTextMessage{Content: "hi all"})
	time.Sleep(500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if !received["B"] || !received["C"] {
		t.Fatal("Broadcast not received by all nodes")
	}
}

func TestDHExchange(t *testing.T) {
	nodes := setupTestNetwork(t, []string{"A", "B"}, 9300)
	defer shutdownNetwork(nodes)
	doneCh := nodes["A"].InitiateDHExchange("B")
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("DH exchange failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for DH exchange")
	}
	aState := nodes["A"].DHKeys["B"]
	bState := nodes["B"].DHKeys["A"]
	if aState == nil || bState == nil || !aState.SharedSecret.Equal(&bState.SharedSecret) {
		t.Fatal("Shared secrets do not match or are missing")
	}
}

func TestSendToNonExistentPeer(t *testing.T) {
	nodes := setupTestNetwork(t, []string{"A"}, 9400)
	defer shutdownNetwork(nodes)
	err := nodes["A"].SendMessage("B", "test_text", SimpleTextMessage{Content: "hello"})
	if err == nil {
		t.Fatal("Expected error when sending to non-existent peer, got nil")
	}
}

func TestHealthCheck(t *testing.T) {
	nodes := setupTestNetwork(t, []string{"A", "B"}, 9500)
	defer shutdownNetwork(nodes)
	nodes["A"].HealthCheck()
	time.Sleep(500 * time.Millisecond)
	nodes["A"].healthMutex.Lock()
	healthy := nodes["A"].health["B"]
	nodes["A"].healthMutex.Unlock()
	if !healthy {
		t.Fatal("Node B should be healthy after ping/pong")
	}
}
