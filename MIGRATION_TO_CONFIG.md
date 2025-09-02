# Migration Guide: Using the Configuration System

## Overview
The PPEM system now uses a configuration file (`ppem.config.json`) instead of hardcoded tool paths. This makes the system more portable and easier to deploy.

## Quick Start

1. **Generate default configuration**:
   ```bash
   ./ppem --generate-config
   ```

2. **Validate configuration**:
   ```bash
   ./ppem --validate-config
   ```

3. **Run with custom config**:
   ```bash
   ./ppem --config /path/to/custom.config.json
   ```

## Configuration File Format

```json
{
  "cargo_path": "cargo",
  "circom_path": "circom",
  "stark_verify_path": "./circom/stark_verify",
  "prover_path": "./circom/prover",
  "node_path": "node",
  "snarkjs_path": "snarkjs",
  "python_path": "python3",
  "risc0_dir": "./risc0",
  "circom_dir": "./circom"
}
```

## Environment Variables

You can override any configuration setting using environment variables:

```bash
# Override config file location
export PPEM_CONFIG=/custom/path/config.json

# Override individual tools
export PPEM_CARGO_PATH=/usr/local/bin/cargo
export PPEM_STARK_VERIFY_PATH=/opt/ppem/stark_verify
export PPEM_PROVER_PATH=/opt/ppem/prover
export PPEM_SNARKJS_PATH=/usr/local/bin/snarkjs

# Override directories
export PPEM_RISC0_DIR=/data/risc0
export PPEM_CIRCOM_DIR=/data/circom
```

## Code Migration

### Old Code (hardcoded):
```go
cmd := exec.Command("cargo", "run", "--release", "--", scenarioPath)
cmd.Dir = risc0Dir
```

### New Code (config-based):
```go
cfg := GetConfig()
cmd := cfg.GetCargoCommand("run", "--release", "--", scenarioPath)
// Dir is automatically set by the helper method
```

### In risc0_integration.go:

Replace direct calls:
```go
// OLD:
cmd := exec.Command("./stark_verify", "input.json", "witness.wtns")

// NEW:
cmd := cfg.GetStarkVerifyCommand("input.json", "witness.wtns")
```

### In main.go:

Add initialization:
```go
func main() {
    flag.Parse()
    
    // Initialize configuration first
    if err := InitializeToolConfig(); err != nil {
        log.Fatalf("Failed to initialize configuration: %v", err)
    }
    
    // Rest of your application...
}
```

## Docker Usage

In Docker, the config is automatically generated with container paths:

```dockerfile
RUN cat > /app/ppem.config.json <<EOF
{
  "stark_verify_path": "/app/circom/stark_verify",
  "prover_path": "/app/circom/prover",
  ...
}
EOF
```

## Troubleshooting

### "Tool not found" errors
1. Check the config file exists: `ls -la ppem.config.json`
2. Validate the configuration: `./ppem --validate-config`
3. Ensure tools are executable: `chmod +x circom/stark_verify circom/prover`

### Different environments
Create environment-specific configs:
- `ppem.config.dev.json` - Development
- `ppem.config.prod.json` - Production
- `ppem.config.docker.json` - Docker

Then use:
```bash
./ppem --config ppem.config.prod.json
```

## Benefits

1. **Portability**: Same code works on different systems
2. **CI/CD friendly**: Easy to configure for different environments
3. **No recompilation**: Change paths without rebuilding
4. **Debugging**: Clear error messages about missing tools
5. **Docker ready**: Automatic configuration in containers