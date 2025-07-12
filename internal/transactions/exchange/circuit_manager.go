// circuit_manager.go - Dynamic circuit key management for scalable participant support
//
// This file provides a flexible system for generating and managing circuit keys
// for any number of participants

package exchange

import (
	"fmt"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// CircuitKeyManager provides dynamic circuit key management for any N participants
type CircuitKeyManager struct {
	mu    sync.RWMutex
	cache map[int]*CircuitKeys // Cache for compiled circuits
}

// CircuitKeys holds proving and verifying keys for a specific participant count
type CircuitKeys struct {
	ProvingKey       groth16.ProvingKey
	VerifyingKey     groth16.VerifyingKey
	ConstraintSystem constraint.ConstraintSystem
	ParticipantCount int
}

// NewCircuitKeyManager creates a new circuit key manager
func NewCircuitKeyManager() *CircuitKeyManager {
	return &CircuitKeyManager{
		cache: make(map[int]*CircuitKeys),
	}
}

// GetOrCreateCircuitKeys returns cached circuit keys or creates new ones for N participants
func (cm *CircuitKeyManager) GetOrCreateCircuitKeys(n int) (*CircuitKeys, error) {
	if n <= 0 {
		return nil, fmt.Errorf("participant count must be positive, got %d", n)
	}

	// Check cache first
	cm.mu.RLock()
	if keys, exists := cm.cache[n]; exists {
		cm.mu.RUnlock()
		return keys, nil
	}
	cm.mu.RUnlock()

	// Create new circuit keys
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Double-check cache after acquiring write lock
	if keys, exists := cm.cache[n]; exists {
		return keys, nil
	}

	// Create new circuit for N participants
	circuit := NewCircuitTxFN(n)

	// Compile the circuit
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit for %d participants: %w", n, err)
	}

	// Generate proving and verifying keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("failed to setup keys for %d participants: %w", n, err)
	}

	// Create and cache the keys
	keys := &CircuitKeys{
		ProvingKey:       pk,
		VerifyingKey:     vk,
		ConstraintSystem: ccs,
		ParticipantCount: n,
	}

	cm.cache[n] = keys
	return keys, nil
}

// GetCircuitKeys returns cached circuit keys for N participants (does not create if missing)
func (cm *CircuitKeyManager) GetCircuitKeys(n int) (*CircuitKeys, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	keys, exists := cm.cache[n]
	return keys, exists
}

// PrecompileCircuits precompiles circuits for common participant counts
func (cm *CircuitKeyManager) PrecompileCircuits(participantCounts []int) error {
	for _, n := range participantCounts {
		if _, err := cm.GetOrCreateCircuitKeys(n); err != nil {
			return fmt.Errorf("failed to precompile circuit for %d participants: %w", n, err)
		}
	}
	return nil
}

// GetCacheStats returns statistics about the circuit cache
func (cm *CircuitKeyManager) GetCacheStats() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["cache_size"] = len(cm.cache)

	participantCounts := make([]int, 0, len(cm.cache))
	for n := range cm.cache {
		participantCounts = append(participantCounts, n)
	}
	stats["cached_participant_counts"] = participantCounts

	return stats
}

// ClearCache clears all cached circuit keys
func (cm *CircuitKeyManager) ClearCache() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.cache = make(map[int]*CircuitKeys)
}

// Global circuit key manager instance
var globalCircuitManager = NewCircuitKeyManager()

// GetCircuitKeysForN is a convenience function to get circuit keys for N participants
func GetCircuitKeysForN(n int) (*CircuitKeys, error) {
	return globalCircuitManager.GetOrCreateCircuitKeys(n)
}

// PrecompileCommonCircuits precompiles circuits for commonly used participant counts
func PrecompileCommonCircuits() error {
	commonCounts := []int{5, 10, 15, 20, 25, 30, 50, 100}
	return globalCircuitManager.PrecompileCircuits(commonCounts)
}
