package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ToolConfig holds the paths to all external tools
type ToolConfig struct {
	// Rust/Cargo tools
	CargoPath string `json:"cargo_path"`
	
	// Circom tools
	CircomPath      string `json:"circom_path"`
	StarkVerifyPath string `json:"stark_verify_path"`
	ProverPath      string `json:"prover_path"`
	
	// Node.js tools
	NodePath    string `json:"node_path"`
	SnarkJSPath string `json:"snarkjs_path"`
	
	// Python (for scripts)
	PythonPath string `json:"python_path"`
	
	// Working directories
	Risc0Dir  string `json:"risc0_dir"`
	CircomDir string `json:"circom_dir"`
}

// DefaultToolConfig returns the default tool configuration
func DefaultToolConfig() *ToolConfig {
	// Get working directory
	pwd, _ := os.Getwd()
	
	return &ToolConfig{
		// Try to find tools in PATH first, fallback to common locations
		CargoPath:       findInPath("cargo", "cargo"),
		CircomPath:      findInPath("circom", "circom"),
		StarkVerifyPath: filepath.Join(pwd, "circom", "stark_verify"),
		ProverPath:      filepath.Join(pwd, "circom", "prover"),
		NodePath:        findInPath("node", "node"),
		SnarkJSPath:     findInPath("snarkjs", "snarkjs"),
		PythonPath:      findInPath("python3", "python3", "python"),
		Risc0Dir:        filepath.Join(pwd, "risc0"),
		CircomDir:       filepath.Join(pwd, "circom"),
	}
}

// LoadToolConfig loads configuration from a JSON file
func LoadToolConfig(configPath string) (*ToolConfig, error) {
	// Start with defaults
	config := DefaultToolConfig()
	
	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// No config file, use defaults
		return config, nil
	}
	
	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse JSON, overlaying on defaults
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	return config, nil
}

// SaveToolConfig saves the configuration to a JSON file
func (tc *ToolConfig) SaveToolConfig(configPath string) error {
	data, err := json.MarshalIndent(tc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// Validate checks if all required tools are available
func (tc *ToolConfig) Validate() error {
	checks := []struct {
		name string
		path string
		required bool
	}{
		{"Cargo", tc.CargoPath, true},
		{"Circom", tc.CircomPath, false},
		{"StarkVerify", tc.StarkVerifyPath, true},
		{"Prover", tc.ProverPath, true},
		{"SnarkJS", tc.SnarkJSPath, true},
		{"Python", tc.PythonPath, false},
	}
	
	var errors []string
	for _, check := range checks {
		if check.path == "" {
			if check.required {
				errors = append(errors, fmt.Sprintf("%s path is not configured", check.name))
			}
			continue
		}
		
		if !fileExists(check.path) {
			if check.required {
				errors = append(errors, fmt.Sprintf("%s not found at %s", check.name, check.path))
			}
		} else if !isExecutable(check.path) {
			errors = append(errors, fmt.Sprintf("%s at %s is not executable", check.name, check.path))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("tool configuration errors:\n  - %s", 
			joinStrings(errors, "\n  - "))
	}
	
	return nil
}

// GetCargoCommand returns exec.Cmd for cargo with proper path
func (tc *ToolConfig) GetCargoCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(tc.CargoPath, args...)
	cmd.Dir = tc.Risc0Dir
	return cmd
}

// GetStarkVerifyCommand returns exec.Cmd for stark_verify
func (tc *ToolConfig) GetStarkVerifyCommand(inputJSON, outputWTNS string) *exec.Cmd {
	// If path is relative to circom dir, use just the binary name when running from circom dir
	binaryPath := tc.StarkVerifyPath
	if tc.StarkVerifyPath == "./circom/stark_verify" {
		binaryPath = "./stark_verify"
	}
	cmd := exec.Command(binaryPath, inputJSON, outputWTNS)
	cmd.Dir = tc.CircomDir
	return cmd
}

// GetProverCommand returns exec.Cmd for rapidsnark prover
func (tc *ToolConfig) GetProverCommand(zkeyPath, witnessPath, proofPath, publicPath string) *exec.Cmd {
	// If path is relative to circom dir, use just the binary name when running from circom dir
	binaryPath := tc.ProverPath
	if tc.ProverPath == "./circom/prover" {
		binaryPath = "./prover"
	}
	cmd := exec.Command(binaryPath, zkeyPath, witnessPath, proofPath, publicPath)
	cmd.Dir = tc.CircomDir
	return cmd
}

// GetSnarkJSCommand returns exec.Cmd for snarkjs
func (tc *ToolConfig) GetSnarkJSCommand(args ...string) *exec.Cmd {
	return exec.Command(tc.SnarkJSPath, args...)
}

// Helper functions

func findInPath(name string, candidates ...string) string {
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	// Return the first candidate as fallback
	if len(candidates) > 0 {
		return candidates[0]
	}
	return name
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&0111 != 0
}

func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}