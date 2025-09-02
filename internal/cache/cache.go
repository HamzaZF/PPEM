package cache

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"implementation/internal/zerocash"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// RISC0Cache manages the RISC Zero build cache
type RISC0Cache struct {
	CacheDir  string
	SourceDir string
}

// CircomCache manages the Circom setup cache
type CircomCache struct {
	CacheDir  string
	SourceDir string
}

// SimpleCircuitCache provides basic save/load for circuit keys
type SimpleCircuitCache struct {
	baseDir string
}

// NewSimpleCache creates a new simple cache in the specified directory
func NewSimpleCache(baseDir string) *SimpleCircuitCache {
	return &SimpleCircuitCache{baseDir: baseDir}
}

// Load loads pk, vk, and ccs for a given circuit name
// Returns (pk, vk, ccs, found) where found=true if all files exist and load successfully
func (c *SimpleCircuitCache) Load(name string) (groth16.ProvingKey, groth16.VerifyingKey, constraint.ConstraintSystem, bool) {
	pkPath := filepath.Join(c.baseDir, name+".pk")
	vkPath := filepath.Join(c.baseDir, name+".vk")
	ccsPath := filepath.Join(c.baseDir, name+".ccs")

	// Check if all files exist
	if _, err := os.Stat(pkPath); os.IsNotExist(err) {
		return nil, nil, nil, false
	}
	if _, err := os.Stat(vkPath); os.IsNotExist(err) {
		return nil, nil, nil, false
	}
	if _, err := os.Stat(ccsPath); os.IsNotExist(err) {
		return nil, nil, nil, false
	}

	// Load proving key using existing working function
	pk, err := zerocash.LoadProvingKey(pkPath)
	if err != nil {
		return nil, nil, nil, false
	}

	// Load verifying key using existing working function
	vk, err := zerocash.LoadVerifyingKey(vkPath)
	if err != nil {
		return nil, nil, nil, false
	}

	// Load constraint system using proper gnark deserialization pattern
	ccsFile, err := os.Open(ccsPath)
	if err != nil {
		return nil, nil, nil, false
	}
	defer ccsFile.Close()

	// Create a new constraint system using the proper gnark pattern
	// This is the correct way according to gnark docs and examples
	ccs := groth16.NewCS(ecc.BW6_761)

	// Deserialize the cached constraint system data
	_, err = ccs.ReadFrom(ccsFile)
	if err != nil {
		return nil, nil, nil, false
	}

	return pk, vk, ccs, true
}

// Save saves pk, vk, and ccs for a given circuit name
func (c *SimpleCircuitCache) Save(name string, pk groth16.ProvingKey, vk groth16.VerifyingKey, ccs constraint.ConstraintSystem) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(c.baseDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache dir: %w", err)
	}

	// Save proving key
	pkPath := filepath.Join(c.baseDir, name+".pk")
	if f, err := os.Create(pkPath); err != nil {
		return fmt.Errorf("failed to create pk file: %w", err)
	} else {
		_, writeErr := pk.WriteTo(f)
		f.Close()
		if writeErr != nil {
			return fmt.Errorf("failed to write pk: %w", writeErr)
		}
	}

	// Save verifying key
	vkPath := filepath.Join(c.baseDir, name+".vk")
	if f, err := os.Create(vkPath); err != nil {
		return fmt.Errorf("failed to create vk file: %w", err)
	} else {
		_, writeErr := vk.WriteTo(f)
		f.Close()
		if writeErr != nil {
			return fmt.Errorf("failed to write vk: %w", writeErr)
		}
	}

	// Save constraint system using gnark's native WriteTo method
	ccsPath := filepath.Join(c.baseDir, name+".ccs")
	if f, err := os.Create(ccsPath); err != nil {
		return fmt.Errorf("failed to create ccs file: %w", err)
	} else {
		_, writeErr := ccs.WriteTo(f)
		f.Close()
		if writeErr != nil {
			return fmt.Errorf("failed to write ccs: %w", writeErr)
		}
	}

	return nil
}

// NewRISC0Cache creates a new RISC Zero cache manager
func NewRISC0Cache(cacheDir, sourceDir string) *RISC0Cache {
	return &RISC0Cache{
		CacheDir:  cacheDir,
		SourceDir: sourceDir,
	}
}

// NewCircomCache creates a new Circom cache manager
func NewCircomCache(cacheDir, sourceDir string) *CircomCache {
	return &CircomCache{
		CacheDir:  cacheDir,
		SourceDir: sourceDir,
	}
}

// GetOrBuildRISC0 ensures RISC Zero is built, using cache if available
func (c *RISC0Cache) GetOrBuildRISC0() error {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(c.CacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Check if already built by looking for the target directory
	targetDir := filepath.Join(c.SourceDir, "target")
	if _, err := os.Stat(targetDir); err == nil {
		fmt.Printf("   ✓ RISC Zero already built (using cache)\n")
		return nil
	}

	// Build RISC Zero
	fmt.Printf("   🔨 Building RISC Zero program...\n")
	cmd := exec.Command("cargo", "build", "--release")
	cmd.Dir = c.SourceDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	start := time.Now()
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build RISC Zero: %w", err)
	}

	fmt.Printf("   ✓ RISC Zero build completed in %v\n", time.Since(start))
	return nil
}

// EnsureCircomSetup ensures Circom setup files are available
func (c *CircomCache) EnsureCircomSetup() error {
	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(c.CacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Check for required Circom files
	requiredFiles := []string{
		"stark_verify.cs",
		"stark_verify_final.zkey",
		"vkey.json",
	}

	allExist := true
	for _, file := range requiredFiles {
		filePath := filepath.Join(c.SourceDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			allExist = false
			break
		}
	}

	if allExist {
		fmt.Printf("   ✓ Circom setup files already available (using cache)\n")
		return nil
	}

	// If files don't exist, we need to generate them (handled by populate_circom_data.sh)
	fmt.Printf("   ⚠️  Some Circom setup files missing - they will be generated during execution\n")
	return nil
}
