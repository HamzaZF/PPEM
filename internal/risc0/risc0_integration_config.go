package risc0

import (
	"fmt"
	"os"
	"path/filepath"

	"implementation/internal/config"
	logger "implementation/internal/logging"
)

// GlobalToolConfig holds the tool configuration for the package
var GlobalToolConfig *config.ToolConfig

// InitializeConfig loads the tool configuration
func InitializeConfig(configPath string) error {
	var err error
	GlobalToolConfig, err = config.LoadToolConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load tool config: %w", err)
	}
	
	// Validate the configuration
	if err := GlobalToolConfig.Validate(); err != nil {
		return fmt.Errorf("invalid tool configuration: %w", err)
	}
	
	logger.Debugf("Tool configuration loaded successfully from %s", configPath)
	return nil
}

// GetConfig returns the current tool configuration or loads default
func GetConfig() *config.ToolConfig {
	if GlobalToolConfig == nil {
		GlobalToolConfig = config.DefaultToolConfig()
	}
	return GlobalToolConfig
}

// runRISC0WithScenarioFile runs RISC Zero with the provided scenario file
func runRISC0WithScenarioFile(scenarioFilePath string) error {
	cfg := GetConfig()
	
	// Copy the scenario file to RISC Zero directory
	scenarioPath := filepath.Join(cfg.Risc0Dir, "auction_scenario.json")
	
	// Read the original scenario file
	scenarioData, err := os.ReadFile(scenarioFilePath)
	if err != nil {
		return fmt.Errorf("failed to read scenario file %s: %w", scenarioFilePath, err)
	}
	
	// Write it to RISC Zero directory
	if err := os.WriteFile(scenarioPath, scenarioData, 0644); err != nil {
		return fmt.Errorf("failed to write scenario file: %w", err)
	}
	
	logger.Debugf("RISC0: running with scenario file: %s", scenarioPath)
	
	// Use config to get cargo command - pass the local filename since cargo runs from risc0/ directory
	cmd := cfg.GetCargoCommand("run", "--release", "--", "auction_scenario.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	logger.Debugf("RISC0: executing command: %s run --release -- auction_scenario.json", cfg.CargoPath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("RISC Zero execution failed: %w", err)
	}
	
	// Copy generated input.json to circom directory
	inputJsonPath := filepath.Join(cfg.Risc0Dir, "input.json")
	circomInputPath := filepath.Join(cfg.CircomDir, "input.json")
	
	// Check if input.json was generated
	if _, err := os.Stat(inputJsonPath); os.IsNotExist(err) {
		return fmt.Errorf("RISC Zero did not generate input.json at %s", inputJsonPath)
	}
	
	inputData, err := os.ReadFile(inputJsonPath)
	if err != nil {
		return fmt.Errorf("failed to read RISC Zero input.json: %w", err)
	}
	
	if err := os.WriteFile(circomInputPath, inputData, 0644); err != nil {
		return fmt.Errorf("failed to write circom input.json: %w", err)
	}
	
	logger.Debugf("RISC0: copied input.json to circom directory: %s", circomInputPath)
	return nil
}

// runCircomProofGenerationConfig is the config-aware version
func runCircomProofGenerationConfig() error {
	cfg := GetConfig()
	
	// Create circom_data directory if it doesn't exist
	circomDataDir := filepath.Join(cfg.CircomDir, "circom_data")
	if err := os.MkdirAll(circomDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create circom_data directory: %w", err)
	}
	
	// Define required files and paths
	inputJsonPath := filepath.Join(cfg.CircomDir, "input.json")
	witnessPath := filepath.Join(cfg.CircomDir, "witness.wtns")
	zkeyPath := filepath.Join(cfg.CircomDir, "stark_verify_final.zkey")
	proofPath := filepath.Join(cfg.CircomDir, "proof.json")
	publicPath := filepath.Join(cfg.CircomDir, "public.json")
	vkeyPath := filepath.Join(cfg.CircomDir, "vkey.json")
	
	// Final output paths in circom_data
	finalProofPath := filepath.Join(circomDataDir, "proof.json")
	finalVkeyPath := filepath.Join(circomDataDir, "vkey.json")
	finalPublicSignalsPath := filepath.Join(circomDataDir, "public_signals.json")
	
	// Check required files exist
	requiredFiles := []string{cfg.StarkVerifyPath, cfg.ProverPath, inputJsonPath, zkeyPath}
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("required file not found: %s", file)
		}
	}
	
	// Make executables executable (in case they're not)
	if err := os.Chmod(cfg.StarkVerifyPath, 0755); err != nil {
		logger.Debugf("Note: could not chmod stark_verify: %v", err)
	}
	if err := os.Chmod(cfg.ProverPath, 0755); err != nil {
		logger.Debugf("Note: could not chmod prover: %v", err)
	}
	
	// Step 1: Run stark_verify to generate witness
	needWitness := true
	if wfi, err := os.Stat(witnessPath); err == nil {
		if ifi, err2 := os.Stat(inputJsonPath); err2 == nil {
			if !ifi.ModTime().After(wfi.ModTime()) {
				needWitness = false
			}
		}
	}
	
	if needWitness {
		logger.Debugf("Circom: Running stark_verify to generate witness...")
		cmd := cfg.GetStarkVerifyCommand("input.json", "witness.wtns")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("stark_verify failed: %w", err)
		}
	} else {
		logger.Debugf("Circom: witness.wtns is up-to-date; skipping stark_verify")
	}
	
	// Ensure witness exists
	if _, err := os.Stat(witnessPath); os.IsNotExist(err) {
		return fmt.Errorf("witness.wtns was not generated by stark_verify")
	}
	
	// Step 2: Run prover (rapidsnark)
	needProof := true
	if pfi, err := os.Stat(proofPath); err == nil {
		if pubfi, err2 := os.Stat(publicPath); err2 == nil {
			if wfi, err3 := os.Stat(witnessPath); err3 == nil {
				if zfi, err4 := os.Stat(zkeyPath); err4 == nil {
					if !(wfi.ModTime().After(pfi.ModTime()) || wfi.ModTime().After(pubfi.ModTime()) ||
						zfi.ModTime().After(pfi.ModTime()) || zfi.ModTime().After(pubfi.ModTime())) {
						needProof = false
					}
				}
			}
		}
	}
	
	if needProof {
		logger.Debugf("Circom: Running prover (rapidsnark) to generate proof...")
		cmd := cfg.GetProverCommand("stark_verify_final.zkey", "witness.wtns", "proof.json", "public.json")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("prover (rapidsnark) failed: %w", err)
		}
		
		// Check if proof files were generated
		if _, err := os.Stat(proofPath); os.IsNotExist(err) {
			return fmt.Errorf("proof.json was not generated by prover")
		}
		if _, err := os.Stat(publicPath); os.IsNotExist(err) {
			return fmt.Errorf("public.json was not generated by prover")
		}
	} else {
		logger.Debugf("Circom: proof.json/public.json are up-to-date; skipping proving")
	}
	
	// Step 3: Export verification key from zkey using snarkjs
	needVKey := true
	if vfi, err := os.Stat(vkeyPath); err == nil {
		if zfi, err2 := os.Stat(zkeyPath); err2 == nil {
			if !zfi.ModTime().After(vfi.ModTime()) {
				needVKey = false
			}
		}
	}
	
	if needVKey {
		logger.Debugf("Circom: Exporting verification key from zkey via snarkjs...")
		cmd := cfg.GetSnarkJSCommand("zkey", "export", "verificationkey", "stark_verify_final.zkey", "vkey.json")
		cmd.Dir = cfg.CircomDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("verification key export failed: %w", err)
		}
	}
	
	// Step 4: Copy files to circom_data directory
	logger.Debugf("Circom: Syncing files to circom_data folder...")
	filesToCopy := map[string]string{
		proofPath:  finalProofPath,
		vkeyPath:   finalVkeyPath,
		publicPath: finalPublicSignalsPath,
	}
	
	for src, dst := range filesToCopy {
		if _, err := os.Stat(src); err == nil {
			data, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", src, err)
			}
			if err := os.WriteFile(dst, data, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", dst, err)
			}
			logger.Debugf("  ✓ Copied %s", filepath.Base(dst))
		}
	}
	
	// Step 5: Verify all required files are in circom_data
	requiredOutputFiles := []string{finalProofPath, finalVkeyPath, finalPublicSignalsPath}
	for _, file := range requiredOutputFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return fmt.Errorf("required output file missing: %s", file)
		}
	}
	
	logger.Debugf("✓ All required files generated successfully in circom_data/")
	return nil
}