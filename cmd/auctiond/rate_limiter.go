// rate_limiter.go - Rate limiting for the auction protocol
package main

import (
	"sync"
	"time"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	mu           sync.Mutex
	tokens       int
	maxTokens    int
	refillRate   int
	lastRefill   time.Time
	refillPeriod time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(maxTokens int, refillRate int, refillPeriod time.Duration) *RateLimiter {
	return &RateLimiter{
		tokens:       maxTokens,
		maxTokens:    maxTokens,
		refillRate:   refillRate,
		lastRefill:   time.Now(),
		refillPeriod: refillPeriod,
	}
}

// Allow checks if a request is allowed and consumes a token if so
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	timeElapsed := now.Sub(rl.lastRefill)
	refillCount := int(timeElapsed / rl.refillPeriod)

	if refillCount > 0 {
		rl.tokens += refillCount * rl.refillRate
		if rl.tokens > rl.maxTokens {
			rl.tokens = rl.maxTokens
		}
		rl.lastRefill = now
	}

	// Check if we have tokens available
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// GetTokens returns the current number of available tokens
func (rl *RateLimiter) GetTokens() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.tokens
}

// Reset resets the rate limiter to its initial state
func (rl *RateLimiter) Reset() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.tokens = rl.maxTokens
	rl.lastRefill = time.Now()
}

// ParticipantRateLimiter manages rate limiting per participant
type ParticipantRateLimiter struct {
	limiters     map[string]*RateLimiter
	mu           sync.RWMutex
	maxTokens    int
	refillRate   int
	refillPeriod time.Duration
}

// NewParticipantRateLimiter creates a new participant rate limiter
func NewParticipantRateLimiter(maxTokens int, refillRate int, refillPeriod time.Duration) *ParticipantRateLimiter {
	return &ParticipantRateLimiter{
		limiters:     make(map[string]*RateLimiter),
		maxTokens:    maxTokens,
		refillRate:   refillRate,
		refillPeriod: refillPeriod,
	}
}

// Allow checks if a request from a participant is allowed
func (prl *ParticipantRateLimiter) Allow(participantID string) bool {
	prl.mu.Lock()
	limiter, exists := prl.limiters[participantID]
	if !exists {
		limiter = NewRateLimiter(prl.maxTokens, prl.refillRate, prl.refillPeriod)
		prl.limiters[participantID] = limiter
	}
	prl.mu.Unlock()

	return limiter.Allow()
}

// GetTokens returns the current number of available tokens for a participant
func (prl *ParticipantRateLimiter) GetTokens(participantID string) int {
	prl.mu.RLock()
	limiter, exists := prl.limiters[participantID]
	prl.mu.RUnlock()

	if !exists {
		return prl.maxTokens
	}

	return limiter.GetTokens()
}

// Reset resets the rate limiter for a specific participant
func (prl *ParticipantRateLimiter) Reset(participantID string) {
	prl.mu.Lock()
	if limiter, exists := prl.limiters[participantID]; exists {
		limiter.Reset()
	}
	prl.mu.Unlock()
}

// ResetAll resets all participant rate limiters
func (prl *ParticipantRateLimiter) ResetAll() {
	prl.mu.Lock()
	for _, limiter := range prl.limiters {
		limiter.Reset()
	}
	prl.mu.Unlock()
}
