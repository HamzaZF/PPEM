package main

import (
	"flag"
	"fmt"
	"os"

	"implementation/internal/config"
	"implementation/internal/risc0"
	logger "implementation/internal/logging"
)

var (
	configPath     string
	generateConfig bool
	validateOnly   bool
)

func init() {
	// Define command-line flags
	flag.StringVar(&configPath, "config", "ppem.config.json", "Path to configuration file")
	flag.BoolVar(&generateConfig, "generate-config", false, "Generate default configuration file")
	flag.BoolVar(&validateOnly, "validate-config", false, "Validate configuration and exit")
}

// InitializeToolConfig loads and validates the tool configuration
func InitializeToolConfig() error {
	// If generate-config flag is set, create config and exit
	if generateConfig {
		cfg := config.DefaultToolConfig()
		if err := cfg.SaveToolConfig(configPath); err != nil {
			return fmt.Errorf("failed to generate config: %w", err)
		}
		fmt.Printf("Configuration file generated: %s\n", configPath)
		os.Exit(0)
	}
	
	// Try environment variable first
	if envConfig := os.Getenv("PPEM_CONFIG"); envConfig != "" {
		configPath = envConfig
		logger.Debugf("Using config from environment: %s", configPath)
	}
	
	// Load configuration
	cfg, err := config.LoadToolConfig(configPath)
	if err != nil {
		// If config doesn't exist, try to use defaults
		if os.IsNotExist(err) {
			logger.Infof("Config file not found, using default configuration")
			cfg = config.DefaultToolConfig()
			
			// Save default config for next time
			if err := cfg.SaveToolConfig(configPath); err != nil {
				logger.Debugf("Could not save default config: %v", err)
			}
		} else {
			return fmt.Errorf("failed to load config: %w", err)
		}
	}
	
	// Override with environment variables if set
	applyEnvironmentOverrides(cfg)
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	
	// If validate-only flag is set, exit after validation
	if validateOnly {
		fmt.Println("Configuration validation successful!")
		printConfiguration(cfg)
		os.Exit(0)
	}
	
	// Initialize RISC0 package with config
	if err := risc0.InitializeConfig(configPath); err != nil {
		return fmt.Errorf("failed to initialize RISC0 config: %w", err)
	}
	
	logger.Infof("Tool configuration loaded successfully")
	return nil
}

// applyEnvironmentOverrides applies environment variable overrides to config
func applyEnvironmentOverrides(cfg *config.ToolConfig) {
	// Check for individual tool overrides
	if val := os.Getenv("PPEM_CARGO_PATH"); val != "" {
		cfg.CargoPath = val
		logger.Debugf("Overriding cargo path from environment: %s", val)
	}
	if val := os.Getenv("PPEM_CIRCOM_PATH"); val != "" {
		cfg.CircomPath = val
		logger.Debugf("Overriding circom path from environment: %s", val)
	}
	if val := os.Getenv("PPEM_STARK_VERIFY_PATH"); val != "" {
		cfg.StarkVerifyPath = val
		logger.Debugf("Overriding stark_verify path from environment: %s", val)
	}
	if val := os.Getenv("PPEM_PROVER_PATH"); val != "" {
		cfg.ProverPath = val
		logger.Debugf("Overriding prover path from environment: %s", val)
	}
	if val := os.Getenv("PPEM_SNARKJS_PATH"); val != "" {
		cfg.SnarkJSPath = val
		logger.Debugf("Overriding snarkjs path from environment: %s", val)
	}
	if val := os.Getenv("PPEM_RISC0_DIR"); val != "" {
		cfg.Risc0Dir = val
		logger.Debugf("Overriding risc0 dir from environment: %s", val)
	}
	if val := os.Getenv("PPEM_CIRCOM_DIR"); val != "" {
		cfg.CircomDir = val
		logger.Debugf("Overriding circom dir from environment: %s", val)
	}
}

// printConfiguration prints the current configuration
func printConfiguration(cfg *config.ToolConfig) {
	fmt.Println("\nCurrent Configuration:")
	fmt.Println("----------------------")
	fmt.Printf("Cargo:        %s\n", cfg.CargoPath)
	fmt.Printf("Circom:       %s\n", cfg.CircomPath)
	fmt.Printf("StarkVerify:  %s\n", cfg.StarkVerifyPath)
	fmt.Printf("Prover:       %s\n", cfg.ProverPath)
	fmt.Printf("Node:         %s\n", cfg.NodePath)
	fmt.Printf("SnarkJS:      %s\n", cfg.SnarkJSPath)
	fmt.Printf("Python:       %s\n", cfg.PythonPath)
	fmt.Printf("RISC0 Dir:    %s\n", cfg.Risc0Dir)
	fmt.Printf("Circom Dir:   %s\n", cfg.CircomDir)
	fmt.Println("----------------------")
}

// Example usage in main.go:
/*
func main() {
	flag.Parse()
	
	// Initialize configuration first
	if err := InitializeToolConfig(); err != nil {
		log.Fatalf("Failed to initialize configuration: %v", err)
	}
	
	// Rest of your application...
}
*/