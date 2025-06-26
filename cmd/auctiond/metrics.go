// metrics.go - Metrics collection for the auction protocol
package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType represents the type of metric
type MetricType string

const (
	Counter   MetricType = "counter"
	Gauge     MetricType = "gauge"
	Histogram MetricType = "histogram"
)

// Metric represents a single metric
type Metric struct {
	Name      string            `json:"name"`
	Type      MetricType        `json:"type"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// MetricsCollector manages metrics collection
type MetricsCollector struct {
	mu         sync.RWMutex
	metrics    map[string]*Metric
	counters   map[string]*int64
	gauges     map[string]*float64
	histograms map[string][]float64
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics:    make(map[string]*Metric),
		counters:   make(map[string]*int64),
		gauges:     make(map[string]*float64),
		histograms: make(map[string][]float64),
	}
}

// IncrementCounter increments a counter metric
func (mc *MetricsCollector) IncrementCounter(name string, labels map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.makeKey(name, labels)
	if counter, exists := mc.counters[key]; exists {
		atomic.AddInt64(counter, 1)
	} else {
		var value int64 = 1
		mc.counters[key] = &value
	}

	mc.updateMetric(name, Counter, float64(*mc.counters[key]), labels)
}

// SetGauge sets a gauge metric value
func (mc *MetricsCollector) SetGauge(name string, value float64, labels map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.makeKey(name, labels)
	if gauge, exists := mc.gauges[key]; exists {
		*gauge = value
	} else {
		mc.gauges[key] = &value
	}

	mc.updateMetric(name, Gauge, value, labels)
}

// RecordHistogram records a value in a histogram
func (mc *MetricsCollector) RecordHistogram(name string, value float64, labels map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.makeKey(name, labels)
	if histogram, exists := mc.histograms[key]; exists {
		mc.histograms[key] = append(histogram, value)
	} else {
		mc.histograms[key] = []float64{value}
	}

	// Keep only last 1000 values for memory efficiency
	if len(mc.histograms[key]) > 1000 {
		mc.histograms[key] = mc.histograms[key][len(mc.histograms[key])-1000:]
	}

	mc.updateMetric(name, Histogram, value, labels)
}

// GetMetric retrieves a metric by name and labels
func (mc *MetricsCollector) GetMetric(name string, labels map[string]string) *Metric {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	key := mc.makeKey(name, labels)
	return mc.metrics[key]
}

// GetAllMetrics returns all collected metrics
func (mc *MetricsCollector) GetAllMetrics() []*Metric {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics := make([]*Metric, 0, len(mc.metrics))
	for _, metric := range mc.metrics {
		metrics = append(metrics, metric)
	}
	return metrics
}

// GetMetricsSummary returns a summary of all metrics
func (mc *MetricsCollector) GetMetricsSummary() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	summary := make(map[string]interface{})

	// Counters
	counters := make(map[string]int64)
	for key, counter := range mc.counters {
		counters[key] = atomic.LoadInt64(counter)
	}
	summary["counters"] = counters

	// Gauges
	gauges := make(map[string]float64)
	for key, gauge := range mc.gauges {
		gauges[key] = *gauge
	}
	summary["gauges"] = gauges

	// Histograms
	histograms := make(map[string]map[string]float64)
	for key, values := range mc.histograms {
		if len(values) > 0 {
			histogram := make(map[string]float64)
			histogram["count"] = float64(len(values))
			histogram["min"] = values[0]
			histogram["max"] = values[0]
			histogram["sum"] = 0

			for _, value := range values {
				if value < histogram["min"] {
					histogram["min"] = value
				}
				if value > histogram["max"] {
					histogram["max"] = value
				}
				histogram["sum"] += value
			}

			histogram["avg"] = histogram["sum"] / histogram["count"]
			histograms[key] = histogram
		}
	}
	summary["histograms"] = histograms

	return summary
}

// Reset resets all metrics
func (mc *MetricsCollector) Reset() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.metrics = make(map[string]*Metric)
	mc.counters = make(map[string]*int64)
	mc.gauges = make(map[string]*float64)
	mc.histograms = make(map[string][]float64)
}

// makeKey creates a unique key for a metric name and labels
func (mc *MetricsCollector) makeKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	// Create a deterministic key by sorting labels
	key := name
	for k, v := range labels {
		key += fmt.Sprintf("_%s_%s", k, v)
	}
	return key
}

// updateMetric updates or creates a metric
func (mc *MetricsCollector) updateMetric(name string, metricType MetricType, value float64, labels map[string]string) {
	key := mc.makeKey(name, labels)

	mc.metrics[key] = &Metric{
		Name:      name,
		Type:      metricType,
		Value:     value,
		Labels:    labels,
		Timestamp: time.Now(),
	}
}

// Predefined metric names
const (
	MetricRegistrationCount   = "registration_count"
	MetricAuctionCount        = "auction_count"
	MetricProofGenerationTime = "proof_generation_time"
	MetricCircuitCompileTime  = "circuit_compile_time"
	MetricActiveParticipants  = "active_participants"
	MetricTotalBids           = "total_bids"
	MetricHighestBid          = "highest_bid"
	MetricSystemUptime        = "system_uptime"
	MetricErrorCount          = "error_count"
)

// Convenience methods for common metrics
func (mc *MetricsCollector) RecordRegistration(participantID string) {
	mc.IncrementCounter(MetricRegistrationCount, map[string]string{"participant": participantID})
}

func (mc *MetricsCollector) RecordAuction(auctionID string, participantCount int) {
	mc.IncrementCounter(MetricAuctionCount, map[string]string{"auction_id": auctionID})
	mc.SetGauge(MetricActiveParticipants, float64(participantCount), map[string]string{"auction_id": auctionID})
}

func (mc *MetricsCollector) RecordProofGeneration(duration time.Duration) {
	mc.RecordHistogram(MetricProofGenerationTime, duration.Seconds(), nil)
}

func (mc *MetricsCollector) RecordCircuitCompile(duration time.Duration) {
	mc.RecordHistogram(MetricCircuitCompileTime, duration.Seconds(), nil)
}

func (mc *MetricsCollector) RecordError(errorType string) {
	mc.IncrementCounter(MetricErrorCount, map[string]string{"type": errorType})
}
