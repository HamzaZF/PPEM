// health.go - Health monitoring for the auction protocol
package main

import (
	"sync"
	"time"
)

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	Healthy   HealthStatus = "healthy"
	Degraded  HealthStatus = "degraded"
	Unhealthy HealthStatus = "unhealthy"
)

// ComponentHealth represents the health of a specific component
type ComponentHealth struct {
	Name      string        `json:"name"`
	Status    HealthStatus  `json:"status"`
	Message   string        `json:"message"`
	LastCheck time.Time     `json:"last_check"`
	Latency   time.Duration `json:"latency,omitempty"`
}

// SystemHealth represents the overall system health
type SystemHealth struct {
	OverallStatus HealthStatus      `json:"overall_status"`
	Timestamp     time.Time         `json:"timestamp"`
	Components    []ComponentHealth `json:"components"`
	Uptime        time.Duration     `json:"uptime"`
	Version       string            `json:"version"`
}

// HealthChecker manages health checks for the auction system
type HealthChecker struct {
	mu         sync.RWMutex
	components map[string]*ComponentHealth
	startTime  time.Time
	version    string
	checkers   map[string]func() error
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(version string) *HealthChecker {
	return &HealthChecker{
		components: make(map[string]*ComponentHealth),
		startTime:  time.Now(),
		version:    version,
		checkers:   make(map[string]func() error),
	}
}

// RegisterComponent registers a health check for a component
func (hc *HealthChecker) RegisterComponent(name string, checker func() error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	hc.components[name] = &ComponentHealth{
		Name:      name,
		Status:    Healthy,
		Message:   "Component registered",
		LastCheck: time.Now(),
	}
	hc.checkers[name] = checker
}

// UpdateComponent updates the health status of a component
func (hc *HealthChecker) UpdateComponent(name string, status HealthStatus, message string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if component, exists := hc.components[name]; exists {
		component.Status = status
		component.Message = message
		component.LastCheck = time.Now()
	}
}

// CheckHealth performs health checks for all registered components
func (hc *HealthChecker) CheckHealth() *SystemHealth {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	overallStatus := Healthy
	components := make([]ComponentHealth, 0, len(hc.components))

	for name, component := range hc.components {
		// Perform health check if checker exists
		if checker, exists := hc.checkers[name]; exists {
			start := time.Now()
			err := checker()
			latency := time.Since(start)

			if err != nil {
				component.Status = Unhealthy
				component.Message = err.Error()
			} else {
				component.Status = Healthy
				component.Message = "OK"
			}

			component.LastCheck = time.Now()
			component.Latency = latency
		}

		// Update overall status
		if component.Status == Unhealthy {
			overallStatus = Unhealthy
		} else if component.Status == Degraded && overallStatus == Healthy {
			overallStatus = Degraded
		}

		components = append(components, *component)
	}

	return &SystemHealth{
		OverallStatus: overallStatus,
		Timestamp:     time.Now(),
		Components:    components,
		Uptime:        time.Since(hc.startTime),
		Version:       hc.version,
	}
}

// GetHealth returns the current health status
func (hc *HealthChecker) GetHealth() *SystemHealth {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	overallStatus := Healthy
	components := make([]ComponentHealth, 0, len(hc.components))

	for _, component := range hc.components {
		if component.Status == Unhealthy {
			overallStatus = Unhealthy
		} else if component.Status == Degraded && overallStatus == Healthy {
			overallStatus = Degraded
		}
		components = append(components, *component)
	}

	return &SystemHealth{
		OverallStatus: overallStatus,
		Timestamp:     time.Now(),
		Components:    components,
		Uptime:        time.Since(hc.startTime),
		Version:       hc.version,
	}
}

// HealthCheckResponse represents the response format for health check endpoints
type HealthCheckResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// CreateHealthResponse creates a standardized health check response
func CreateHealthResponse(health *SystemHealth) *HealthCheckResponse {
	status := "success"
	message := "System is healthy"

	if health.OverallStatus == Unhealthy {
		status = "error"
		message = "System is unhealthy"
	} else if health.OverallStatus == Degraded {
		status = "warning"
		message = "System is degraded"
	}

	return &HealthCheckResponse{
		Status:  status,
		Message: message,
		Data:    health,
	}
}
