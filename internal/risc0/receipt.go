package risc0

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// RISC Zero Receipt Data Structures
// These match the JSON format from risc0_receipt.json

// Receipt is the top-level receipt structure
type Receipt struct {
	Inner  InnerReceipt `json:"inner"`
	Journal Journal     `json:"journal"`
}

// InnerReceipt can be Succinct, Composite, or Fake
type InnerReceipt struct {
	Succinct *SuccinctReceipt `json:"Succinct,omitempty"`
	Fake     *FakeReceipt     `json:"Fake,omitempty"`
}

// SuccinctReceipt contains the claim and seal
type SuccinctReceipt struct {
	Claim MaybePrunedClaim `json:"claim"`
	Seal  []uint32         `json:"seal"`
}

// FakeReceipt for testing
type FakeReceipt struct {
	Claim MaybePrunedClaim `json:"claim"`
}

// MaybePrunedClaim can be Value or Pruned
type MaybePrunedClaim struct {
	Value  *ReceiptClaim `json:"Value,omitempty"`
	Pruned *Digest       `json:"Pruned,omitempty"`
}

// ReceiptClaim contains all the claim data
type ReceiptClaim struct {
	Pre      MaybePrunedSystemState `json:"pre"`
	Post     MaybePrunedSystemState `json:"post"`
	ExitCode ExitCode              `json:"exit_code"`
	Input    MaybePruned           `json:"input"`
	Output   MaybePruned           `json:"output"`
}

// MaybePrunedSystemState for pre/post states
type MaybePrunedSystemState struct {
	Value  *SystemState `json:"Value,omitempty"`
	Pruned *Digest      `json:"Pruned,omitempty"`
}

// SystemState contains PC and merkle root
type SystemState struct {
	PC         uint32   `json:"pc"`
	MerkleRoot []uint32 `json:"merkle_root"` // Array of 8 u32 words
}

// MaybePruned for input/output
type MaybePruned struct {
	Value  *OutputValue `json:"Value,omitempty"`
	Pruned []uint32     `json:"Pruned,omitempty"` // Array of 8 u32 words
}

// OutputValue contains journal and assumptions
type OutputValue struct {
	Journal     Digest      `json:"journal"`
	Assumptions Assumptions `json:"assumptions"`
}

// Assumptions can be Pruned or Value (list)
type Assumptions struct {
	Pruned *Digest  `json:"Pruned,omitempty"`
	Value  []Digest `json:"Value,omitempty"`
}

// ExitCode represents the exit status
type ExitCode struct {
	Halted      *uint32 `json:"Halted,omitempty"`
	Paused      *uint32 `json:"Paused,omitempty"`
	SystemSplit bool    `json:"SystemSplit,omitempty"`
}

// Digest represents a 32-byte hash (8 u32 words)
type Digest struct {
	Words []uint32 `json:"words,omitempty"`
	Bytes []uint8  `json:"bytes,omitempty"`
}

// Journal contains the encoded journal bytes
type Journal struct {
	Bytes []uint8 `json:"bytes"`
}

// ReceiptData contains the extracted values needed for claim digest computation
type ReceiptData struct {
	// Pre-execution state
	PrePC         uint32
	PreMerkleRoot [32]byte
	
	// Post-execution state
	PostPC         uint32
	PostMerkleRoot [32]byte
	
	// Exit codes
	SysExit  uint32
	UserExit uint32
	
	// Journal data (raw bytes)
	JournalBytes []byte
	
	// Assumptions digest (usually zero)
	AssumptionsDigest [32]byte
	
	// Input digest (usually zero)
	InputDigest [32]byte
}

// ParseReceiptFile reads and parses a RISC Zero receipt JSON file
func ParseReceiptFile(filepath string) (*ReceiptData, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read receipt file: %w", err)
	}
	
	var receipt Receipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, fmt.Errorf("failed to parse receipt JSON: %w", err)
	}
	
	return ExtractReceiptData(&receipt)
}

// ExtractReceiptData extracts the necessary data from a parsed receipt
func ExtractReceiptData(receipt *Receipt) (*ReceiptData, error) {
	data := &ReceiptData{
		JournalBytes: receipt.Journal.Bytes,
		InputDigest: [32]byte{}, // Default to zero
		AssumptionsDigest: [32]byte{}, // Default to zero
	}
	
	// Extract claim based on receipt type
	var claim *ReceiptClaim
	if receipt.Inner.Succinct != nil {
		if receipt.Inner.Succinct.Claim.Value != nil {
			claim = receipt.Inner.Succinct.Claim.Value
		} else {
			return nil, fmt.Errorf("succinct receipt claim is pruned")
		}
	} else if receipt.Inner.Fake != nil {
		if receipt.Inner.Fake.Claim.Value != nil {
			claim = receipt.Inner.Fake.Claim.Value
		} else {
			return nil, fmt.Errorf("fake receipt claim is pruned")
		}
	} else {
		return nil, fmt.Errorf("unsupported receipt type")
	}
	
	// Extract pre-state
	if claim.Pre.Value != nil {
		data.PrePC = claim.Pre.Value.PC
		data.PreMerkleRoot = u32ArrayToBytes(claim.Pre.Value.MerkleRoot)
	} else {
		return nil, fmt.Errorf("pre-state is pruned")
	}
	
	// Extract post-state
	if claim.Post.Value != nil {
		data.PostPC = claim.Post.Value.PC
		data.PostMerkleRoot = u32ArrayToBytes(claim.Post.Value.MerkleRoot)
	} else {
		return nil, fmt.Errorf("post-state is pruned")
	}
	
	// Extract exit codes
	if claim.ExitCode.Halted != nil {
		data.SysExit = 0
		data.UserExit = *claim.ExitCode.Halted
	} else if claim.ExitCode.Paused != nil {
		data.SysExit = 1
		data.UserExit = *claim.ExitCode.Paused
	} else if claim.ExitCode.SystemSplit {
		data.SysExit = 2
		data.UserExit = 0
	} else {
		return nil, fmt.Errorf("unknown exit code format")
	}
	
	// Extract input digest if present
	if claim.Input.Value != nil {
		// Input has actual value - this shouldn't happen for typical RISC Zero proofs
		return nil, fmt.Errorf("non-zero input not supported")
	} else if claim.Input.Pruned != nil && len(claim.Input.Pruned) > 0 {
		data.InputDigest = u32ArrayToBytes(claim.Input.Pruned)
	}
	
	// Extract assumptions digest if present
	if claim.Output.Value != nil {
		if claim.Output.Value.Assumptions.Pruned != nil {
			data.AssumptionsDigest = digestToBytes(claim.Output.Value.Assumptions.Pruned)
		} else if claim.Output.Value.Assumptions.Value != nil && len(claim.Output.Value.Assumptions.Value) > 0 {
			return nil, fmt.Errorf("non-empty assumptions list not supported")
		}
	}
	
	return data, nil
}

// digestToBytes converts a Digest to 32 bytes
func digestToBytes(digest *Digest) [32]byte {
	var result [32]byte
	
	if digest == nil {
		return result // Return zeros
	}
	
	if len(digest.Bytes) == 32 {
		// Direct byte representation
		copy(result[:], digest.Bytes)
	} else if len(digest.Words) == 8 {
		// Convert u32 words to bytes (little-endian)
		for i := 0; i < 8; i++ {
			word := digest.Words[i]
			result[i*4] = byte(word)
			result[i*4+1] = byte(word >> 8)
			result[i*4+2] = byte(word >> 16)
			result[i*4+3] = byte(word >> 24)
		}
	}
	
	return result
}

// u32ArrayToBytes converts an array of u32 to 32 bytes
func u32ArrayToBytes(words []uint32) [32]byte {
	var result [32]byte
	
	if len(words) != 8 {
		return result // Return zeros if not 8 words
	}
	
	// Convert u32 words to bytes (little-endian)
	for i := 0; i < 8; i++ {
		word := words[i]
		result[i*4] = byte(word)
		result[i*4+1] = byte(word >> 8)
		result[i*4+2] = byte(word >> 16)
		result[i*4+3] = byte(word >> 24)
	}
	
	return result
}

// BytesToHex converts bytes to hex string
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// GetDefaultReceiptData returns typical default values for a RISC Zero receipt
func GetDefaultReceiptData() *ReceiptData {
	// Default pre-merkle root from typical RISC Zero execution
	preMerkleRoot, _ := hex.DecodeString("5b29320148ffdc023dfd8139b0daa1369c1abc2684e6e02f448ed329d75e0835")
	
	var preMerkleRootArray [32]byte
	copy(preMerkleRootArray[:], preMerkleRoot)
	
	return &ReceiptData{
		PrePC:             0,
		PreMerkleRoot:     preMerkleRootArray,
		PostPC:            0,
		PostMerkleRoot:    [32]byte{}, // All zeros
		SysExit:           0,
		UserExit:          0,
		JournalBytes:      []byte{},
		AssumptionsDigest: [32]byte{}, // All zeros
		InputDigest:       [32]byte{}, // All zeros
	}
}

// ConvertReceiptDataToBigInts converts receipt data to big.Int values for circuit
func ConvertReceiptDataToBigInts(data *ReceiptData) map[string]interface{} {
	result := make(map[string]interface{})
	
	result["PrePC"] = new(big.Int).SetUint64(uint64(data.PrePC))
	result["PostPC"] = new(big.Int).SetUint64(uint64(data.PostPC))
	result["SysExit"] = new(big.Int).SetUint64(uint64(data.SysExit))
	result["UserExit"] = new(big.Int).SetUint64(uint64(data.UserExit))
	
	// Convert merkle roots to arrays of bytes as big.Int
	preMerkleRoot := make([]*big.Int, 32)
	for i := 0; i < 32; i++ {
		preMerkleRoot[i] = new(big.Int).SetUint64(uint64(data.PreMerkleRoot[i]))
	}
	result["PreMerkleRoot"] = preMerkleRoot
	
	postMerkleRoot := make([]*big.Int, 32)
	for i := 0; i < 32; i++ {
		postMerkleRoot[i] = new(big.Int).SetUint64(uint64(data.PostMerkleRoot[i]))
	}
	result["PostMerkleRoot"] = postMerkleRoot
	
	return result
}