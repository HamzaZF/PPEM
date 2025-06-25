package p2p

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// --- Custom JSON Marshaling for gnark-crypto types ---

// G1AffineJSON is a wrapper around bls12377.G1Affine to implement custom JSON marshaling.
type G1AffineJSON struct {
	bls12377.G1Affine
}

// MarshalJSON implements the json.Marshaler interface.
func (p G1AffineJSON) MarshalJSON() ([]byte, error) {
	bytes := p.G1Affine.Marshal()
	// Wrap the base64 encoded string in quotes to make it a valid JSON string.
	return []byte(`"` + base64.StdEncoding.EncodeToString(bytes) + `"`), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (p *G1AffineJSON) UnmarshalJSON(data []byte) error {
	// Unquote the JSON string
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("invalid JSON string for G1AffineJSON")
	}
	b, err := base64.StdEncoding.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	return p.G1Affine.Unmarshal(b)
}

// Message is the generic envelope for any message sent over the network.
// It allows for flexible communication of different data structures.
type Message struct {
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
	SenderID string          `json:"senderId"`
}

// --- Diffie-Hellman State and Payloads ---

// DHState holds the state of a single Diffie-Hellman exchange.
type DHState struct {
	OurSecret    fr.Element
	OurPublic    bls12377.G1Affine
	TheirPublic  bls12377.G1Affine
	SharedSecret bls12377.G1Affine
	Status       string // e.g., "initiated", "completed"
}

// DHInitiatePayload is used to send the initiator's public key.
type DHInitiatePayload struct {
	SenderID  string
	PublicKey G1AffineJSON
}

// DHResponsePayload is used by the responder to send their public key back.
type DHResponsePayload struct {
	SenderID  string
	PublicKey G1AffineJSON
}

// SimpleTextMessage is another example of a payload.
type SimpleTextMessage struct {
	Content string `json:"content"`
}
