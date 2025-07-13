// circuit_manager.go - Dynamic circuit key management for scalable participant support.
//
// This file provides a flexible system for generating and managing circuit keys
// for any number of participants. It implements a thread-safe caching mechanism
// to avoid recompiling circuits for the same participant count.
//
// Key features:
// - Thread-safe caching of compiled circuits
// - Dynamic circuit generation for any N participants
// - Precompilation of common participant counts
// - Memory-efficient key management
//
// Usage:
//   - Use GetCircuitKeysForN(n) for one-off circuit key generation
//   - Use CircuitKeyManager for long-running applications with multiple participant counts
//   - Use PrecompileCommonCircuits() to warm up the cache for common scenarios

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

// CircuitKeyManager provides dynamic circuit key management for any N participants.
// Implements thread-safe caching to avoid recompiling circuits for the same participant count.
//
// Thread safety: All operations are protected by read-write mutex for concurrent access.
// Cache management: Automatically caches compiled circuits by participant count.
type CircuitKeyManager struct {
	mu    sync.RWMutex         // Read-write mutex for thread-safe cache access
	cache map[int]*CircuitKeys // Cache mapping participant count to compiled circuit keys
}

// CircuitKeys holds proving and verifying keys for a specific participant count.
// These keys are generated once per participant count and cached for reuse.
//
// Fields:
//   - ProvingKey: Used to generate ZK proofs for the circuit
//   - VerifyingKey: Used to verify ZK proofs for the circuit
//   - ConstraintSystem: The compiled constraint system for the circuit
//   - ParticipantCount: The number of participants this circuit supports
type CircuitKeys struct {
	ProvingKey       groth16.ProvingKey          // Key for generating ZK proofs
	VerifyingKey     groth16.VerifyingKey        // Key for verifying ZK proofs
	ConstraintSystem constraint.ConstraintSystem // Compiled constraint system
	ParticipantCount int                         // Number of participants supported
}

// NewCircuitKeyManager creates a new circuit key manager with an empty cache.
// Returns a thread-safe manager ready for circuit key generation and caching.
func NewCircuitKeyManager() *CircuitKeyManager {
	return &CircuitKeyManager{
		cache: make(map[int]*CircuitKeys),
	}
}

// GetOrCreateCircuitKeys returns cached circuit keys or creates new ones for N participants.
// This is the main entry point for obtaining circuit keys for a specific participant count.
//
// Thread safety: Uses read-write mutex to ensure thread-safe cache access and circuit compilation.
// Caching: If keys for N participants already exist in cache, returns them immediately.
// Compilation: If keys don't exist, compiles a new CircuitTxFN for N participants and caches the result.
//
// Parameters:
//   - n: Number of participants (must be positive and even)
//
// Returns:
//   - *CircuitKeys: Compiled circuit keys for N participants
//   - error: Compilation or setup error if any
//
// Errors:
//   - "participant count must be positive": if n <= 0
//   - "failed to compile circuit": if circuit compilation fails
//   - "failed to setup keys": if key generation fails
func (cm *CircuitKeyManager) GetOrCreateCircuitKeys(n int) (*CircuitKeys, error) {
	if n <= 0 {
		return nil, fmt.Errorf("participant count must be positive, got %d", n)
	}

	// Check cache first (read lock for better concurrency)
	cm.mu.RLock()
	if keys, exists := cm.cache[n]; exists {
		cm.mu.RUnlock()
		return keys, nil
	}
	cm.mu.RUnlock()

	// Create new circuit keys (write lock for cache modification)
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Double-check cache after acquiring write lock (prevents race conditions)
	if keys, exists := cm.cache[n]; exists {
		return keys, nil
	}

	// Create new circuit for N participants
	circuit := NewCircuitTxFN(n)

	// Compile the circuit using BW6-761 curve and R1CS builder
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("failed to compile circuit for %d participants: %w", n, err)
	}

	// Generate proving and verifying keys using Groth16
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

// GetCircuitKeys returns cached circuit keys for N participants (does not create if missing).
// This is a read-only operation that only checks the cache without triggering compilation.
//
// Thread safety: Uses read lock for thread-safe cache access.
//
// Parameters:
//   - n: Number of participants to look up
//
// Returns:
//   - *CircuitKeys: Cached circuit keys (may be nil if not found)
//   - bool: true if keys were found in cache, false otherwise
func (cm *CircuitKeyManager) GetCircuitKeys(n int) (*CircuitKeys, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	keys, exists := cm.cache[n]
	return keys, exists
}

// PrecompileCircuits precompiles circuits for common participant counts.
// This is useful for warming up the cache before the main protocol execution.
//
// Thread safety: Uses GetOrCreateCircuitKeys which handles its own thread safety.
//
// Parameters:
//   - participantCounts: Slice of participant counts to precompile
//
// Returns:
//   - error: Compilation error if any circuit fails to compile
//
// Usage: Call this during initialization to avoid compilation delays during protocol execution.
func (cm *CircuitKeyManager) PrecompileCircuits(participantCounts []int) error {
	for _, n := range participantCounts {
		if _, err := cm.GetOrCreateCircuitKeys(n); err != nil {
			return fmt.Errorf("failed to precompile circuit for %d participants: %w", n, err)
		}
	}
	return nil
}

// GetCacheStats returns statistics about the circuit cache.
// Provides information about cache size and cached participant counts.
//
// Thread safety: Uses read lock for thread-safe cache access.
//
// Returns:
//   - map[string]interface{}: Statistics including cache size and cached participant counts
//
// Example return value:
//
//	{
//	  "cache_size": 3,
//	  "cached_participant_counts": [10, 20, 30]
//	}
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

// ClearCache clears all cached circuit keys.
// This frees memory but requires recompilation for subsequent requests.
//
// Thread safety: Uses write lock for thread-safe cache modification.
//
// Usage: Call this when memory usage becomes a concern or when switching to different
// participant count ranges.
func (cm *CircuitKeyManager) ClearCache() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.cache = make(map[int]*CircuitKeys)
}

// Global circuit key manager instance for convenience functions.
// This provides a singleton pattern for easy access to circuit key management.
var globalCircuitManager = NewCircuitKeyManager()

// GetCircuitKeysForN is a convenience function to get circuit keys for N participants.
// Uses the global circuit manager to avoid passing manager instances around.
//
// Parameters:
//   - n: Number of participants (must be positive and even)
//
// Returns:
//   - *CircuitKeys: Compiled circuit keys for N participants
//   - error: Compilation or setup error if any
//
// Usage: This is the primary function for obtaining circuit keys in most scenarios.
func GetCircuitKeysForN(n int) (*CircuitKeys, error) {
	return globalCircuitManager.GetOrCreateCircuitKeys(n)
}

// PrecompileCommonCircuits precompiles circuits for commonly used participant counts.
// This warms up the cache for typical market scenarios to avoid compilation delays.
//
// Common participant counts: 5, 10, 15, 20, 25, 30, 50, 100
//
// Returns:
//   - error: Compilation error if any circuit fails to compile
//
// Usage: Call this during application initialization to prepare for common scenarios.
func PrecompileCommonCircuits() error {
	commonCounts := []int{5, 10, 15, 20, 25, 30, 50, 100}
	return globalCircuitManager.PrecompileCircuits(commonCounts)
}
