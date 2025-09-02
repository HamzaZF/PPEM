// json.go - JSON utility functions
package io

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReadJSONFile reads and unmarshals JSON from a file
func ReadJSONFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", path, err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON from %s: %w", path, err)
	}

	return nil
}

// WriteJSONFile marshals and writes JSON to a file
func WriteJSONFile(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	return nil
}

// MarshalJSON safely marshals to JSON with indentation
func MarshalJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// UnmarshalJSON safely unmarshals JSON
func UnmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

