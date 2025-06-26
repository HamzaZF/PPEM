// config.go - Configuration management for the auction protocol
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the application configuration
type Config struct {
	// Protocol settings
	NumParticipants int   `json:"num_participants"`
	BaseCoins       int64 `json:"base_coins"`
	BaseEnergy      int64 `json:"base_energy"`
	BaseBid         int64 `json:"base_bid"`

	// File paths
	LedgerPath string `json:"ledger_path"`
	WalletDir  string `json:"wallet_dir"`
	KeyDir     string `json:"key_dir"`

	// Logging
	LogLevel string `json:"log_level"`
	LogFile  string `json:"log_file"`

	// Performance
	MaxConcurrency int `json:"max_concurrency"`
	TimeoutSeconds int `json:"timeout_seconds"`

	// Security
	EnableAudit  bool   `json:"enable_audit"`
	AuditLogPath string `json:"audit_log_path"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		NumParticipants: 10,
		BaseCoins:       100,
		BaseEnergy:      50,
		BaseBid:         10,
		LedgerPath:      "ledger.json",
		WalletDir:       "wallets",
		KeyDir:          "keys",
		LogLevel:        "info",
		LogFile:         "auction.log",
		MaxConcurrency:  4,
		TimeoutSeconds:  30,
		EnableAudit:     true,
		AuditLogPath:    "audit.log",
	}
}

// LoadConfig loads configuration from file or creates default
func LoadConfig(configPath string) (*Config, error) {
	// Try to load from file
	if _, err := os.Stat(configPath); err == nil {
		file, err := os.Open(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open config file: %w", err)
		}
		defer file.Close()

		var config Config
		if err := json.NewDecoder(file).Decode(&config); err != nil {
			return nil, fmt.Errorf("failed to decode config file: %w", err)
		}

		return &config, nil
	}

	// Create default config and save it
	config := DefaultConfig()
	if err := SaveConfig(config, configPath); err != nil {
		return nil, fmt.Errorf("failed to save default config: %w", err)
	}

	return config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *Config, configPath string) error {
	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// ValidateConfig validates the configuration
func (c *Config) Validate() error {
	if c.NumParticipants <= 0 {
		return fmt.Errorf("num_participants must be positive")
	}
	if c.BaseCoins <= 0 {
		return fmt.Errorf("base_coins must be positive")
	}
	if c.BaseEnergy <= 0 {
		return fmt.Errorf("base_energy must be positive")
	}
	if c.BaseBid <= 0 {
		return fmt.Errorf("base_bid must be positive")
	}
	if c.MaxConcurrency <= 0 {
		return fmt.Errorf("max_concurrency must be positive")
	}
	if c.TimeoutSeconds <= 0 {
		return fmt.Errorf("timeout_seconds must be positive")
	}
	return nil
}
