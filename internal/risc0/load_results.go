package risc0

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
)

// GnarkInputs represents the data from gnark_inputs.json
type GnarkInputs struct {
	ClearingPrice uint64   `json:"clearing_price"`
	InCoin        []uint64 `json:"in_coin"`
	InEnergy      []uint64 `json:"in_energy"`
	OutCoin       []uint64 `json:"out_coin"`
	OutEnergy     []uint64 `json:"out_energy"`
	JournalDigest string   `json:"journal_digest"`
}

// LoadRISC0Results loads the RISC Zero computation results from gnark_inputs.json
func LoadRISC0Results(risc0Dir string) (*GnarkInputs, error) {
	gnarkInputsPath := filepath.Join(risc0Dir, "gnark_inputs.json")
	
	data, err := ioutil.ReadFile(gnarkInputsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read gnark_inputs.json: %w", err)
	}
	
	var inputs GnarkInputs
	if err := json.Unmarshal(data, &inputs); err != nil {
		return nil, fmt.Errorf("failed to parse gnark_inputs.json: %w", err)
	}
	
	return &inputs, nil
}

// ConvertToAuctionResult is commented out to avoid circular import
// This function would convert RISC Zero results to AuctionExecutionResult format
// but it requires importing the exchange package which would create a circular dependency.
// The exchange package already imports risc0, so risc0 cannot import exchange.
//
// func ConvertToAuctionResult(inputs *GnarkInputs, originalOutputs []exchange.DecryptedRegistration) *exchange.AuctionExecutionResult {
// 	// Create outputs with RISC Zero's computed values
// 	outputs := make([]exchange.DecryptedRegistration, len(originalOutputs))
// 	for i := range outputs {
// 		outputs[i] = originalOutputs[i] // Copy original
// 		// Override with RISC Zero results
// 		if i < len(inputs.OutCoin) {
// 			outputs[i].Coins = big.NewInt(int64(inputs.OutCoin[i]))
// 		}
// 		if i < len(inputs.OutEnergy) {
// 			outputs[i].Energy = big.NewInt(int64(inputs.OutEnergy[i]))
// 		}
// 	}
// 	
// 	return &exchange.AuctionExecutionResult{
// 		Outputs:       outputs,
// 		ClearingPrice: big.NewInt(int64(inputs.ClearingPrice)),
// 	}
// }