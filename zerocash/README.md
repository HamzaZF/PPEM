# zerocash

A production-ready Go package implementing Zerocash-like confidential transactions with zero-knowledge proofs, as described in the referenced research paper.

## Features
- Confidential note creation and transfer
- Serial number and commitment generation
- MiMC-based cryptography
- Groth16 zkSNARK circuit (via gnark)
- Clean, idiomatic Go API

## Usage

```
go get ./zerocash

import "yourmodule/zerocash"

// Create and verify a transaction
oldNote := ... // *zerocash.Note
oldSk := ...   // []byte
newOwnerPk := ... // []byte
value := ...   // *big.Int
energy := ...  // *big.Int
params := &zerocash.Params{}

// Create a transaction
zTx, err := zerocash.CreateTx(oldNote, oldSk, newOwnerPk, value, energy, params)
if err != nil {
    // handle error
}

// Verify a transaction
err = zerocash.VerifyTx(zTx, params)
if err != nil {
    // handle error
}
```

## License
See project root. 