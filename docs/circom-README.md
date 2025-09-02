# Circom Gro Program

This program replicates the functionality of the `/example` folder but operates in the circom environment. It performs recursive verification of Circom proofs using Gnark.

## Files Structure

- `main.go` - Main program logic for recursive proof verification
- `types.go` - Data structure definitions
- `json.go` - JSON parsing/marshaling functions
- `convert.go` - Circom to Gnark conversion functions
- `util.go` - Utility functions for point conversions
- `recursion.go` - Recursive proof handling functions
- `tocircom.go` - Gnark to Circom conversion functions
- `populate_circom_data.sh` - Script to generate proof data
- `go.mod` - Go module dependencies

## Usage

### Step 1: Generate Proof Data

First, run the script to populate the `circom_data` folder:

```bash
./populate_circom_data.sh
```

This script will:
1. Run `./stark_verify input.json witness.wtns` to generate the witness
2. Run `snarkjs groth16 prove stark_verify_final.zkey witness.wtns proof.json public.json`
3. Extract the verification key if needed
4. Copy all generated files to the `circom_data/` directory

**Prerequisites:**
- `stark_verify` executable (already present)
- `input.json` file (already present)
- `stark_verify_final.zkey` proving key (may need to be generated)
- `snarkjs` installed globally (`npm install -g snarkjs`)

### Step 2: Run the Gro Program

After generating the proof data, run the main program:

```bash
# Build the program
go build -o circom-gro .

# Run the program
./circom-gro
```

**Options:**
- `-test` - Run as test (validates circuit without full proof generation)
- `-circom-data <dir>` - Specify custom circom data directory (default: "circom_data")

### Step 3: Program Flow

The program will:

1. **Load Circom Data**: Read `proof.json`, `vkey.json`, and `public_signals.json`
2. **Verify Original Proof**: Verify the Circom proof using Gnark verifier
3. **Setup Recursive Circuit**: Create placeholders and convert to recursion format
4. **Compile/Load Circuit**: Either compile new circuit or load existing `pk.bin`, `vk.bin`, `circuit.r1cs`
5. **Generate Recursive Proof**: Create witness and prove the recursive circuit
6. **Verify Recursive Proof**: Verify the new recursive proof
7. **Export Results**: Convert back to Circom format and save to temporary directory

## Generated Files

The program generates the following files (if they don't exist):
- `pk.bin` - Proving key
- `vk.bin` - Verifying key  
- `circuit.r1cs` - Compiled circuit

## Dependencies

- Go 1.24+
- github.com/consensys/gnark v0.13.1+
- github.com/consensys/gnark-crypto v0.18.0+
- snarkjs (for proof generation script)

## Example Output

```
=== Populating circom_data folder ===
Step 1: Running stark_verify to generate witness...
Step 2: Running snarkjs groth16 prove...
Step 3: Moving files to circom_data folder...
✓ All required files generated successfully!

Verifying proof with Gnark verifier...
Proof verification succeeded!
Now let's build a new circuit to verify the Circom proof recursively
Compiling circuit...
Compilation time: 2.5s
Setting up proving and verifying keys...
Setup time: 15.3s
Creating witness...
Witness creation time: 100ms
Proving...
Proving Recursion time: 30.2s
Verifying...
Recursive proof verification succeeded! took 50ms
Transforming the proof to Circom format...
To verify run: snarkjs groth16 verify /tmp/circom_json123/vkey.json /tmp/circom_json123/public_signals.json /tmp/circom_json123/proof.json
All done!
```

## Troubleshooting

### Missing stark_verify_final.zkey
If you see "stark_verify_final.zkey not found", you need to generate the proving key:

```bash
# Generate trusted setup (if you have the .r1cs file)
snarkjs groth16 setup stark_verify.r1cs powersOfTau28_hez_final_20.ptau stark_verify_0000.zkey
snarkjs zkey contribute stark_verify_0000.zkey stark_verify_final.zkey
```

### snarkjs not found
Install snarkjs globally:
```bash
npm install -g snarkjs
```

### Import errors
Run go mod tidy:
```bash
go mod tidy
``` 