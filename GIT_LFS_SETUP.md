# Git LFS Setup for PPEM

## Overview

This repository uses Git LFS (Large File Storage) to track large binaries that are time-consuming to build. This allows users to either:
1. **Use pre-built binaries** (x86_64 Linux) - Download via Git LFS
2. **Build from source** - Follow instructions in `SETUP.md`

## Files Tracked with Git LFS

### Critical Binaries (Pre-built for x86_64 Linux)
| File | Size | Build Time | Purpose |
|------|------|------------|---------|
| `circom/stark_verify` | 142MB | ~30 min | STARK proof verifier |
| `circom/stark_verify.dat` | 46MB | Generated with above | Data file for stark_verify |
| `circom/prover` | 500KB | ~5 min | RapidSNARK prover |
| `circom/stark_verify_final.zkey` | 3.6GB | ~1 hour | Proving key |

## Setup Instructions

### Option 1: Use Pre-built Binaries (Recommended for x86_64 Linux)

```bash
# 1. Install Git LFS
git lfs install

# 2. Clone the repository (will download LFS files)
git clone https://github.com/yourusername/PPEM-Final.git
cd PPEM-Final

# 3. Verify LFS files were downloaded
git lfs ls-files
# Should show:
# circom/stark_verify (142 MB)
# circom/stark_verify.dat (46 MB)
# circom/prover (511 KB)
# circom/stark_verify_final.zkey (3.6 GB)

# 4. Make binaries executable
chmod +x circom/stark_verify circom/prover

# 5. You're ready to go!
./ppem
```

### Option 2: Build from Source (Required for ARM/other architectures)

```bash
# 1. Clone without LFS files
GIT_LFS_SKIP_SMUDGE=1 git clone https://github.com/yourusername/PPEM-Final.git
cd PPEM-Final

# 2. Build the binaries
./scripts/setup.sh

# This will:
# - Build stark_verify from circom/stark_verify.circom
# - Build prover from RapidSNARK
# - Generate or download the proving key
```

## Files Ignored (Runtime Generated)

These files are generated during runtime and are NOT tracked in Git:

### Build Caches
- `/risc0/target/` - Rust build cache (5.2GB when built)
- `/.ppem_cache/` - PPEM circuit cache (900MB+)
- `/out/circom_cache/` - Test tool cache (500MB)

### Test Data
- `/exchange_data/*.json` - Auction results
- `/graphs/*.svg` - Visualization graphs
- `/ledger_final.json` - Final ledger state

### Runtime Files
- `circom/input.json`, `proof.json`, `public.json`, `witness.wtns`
- `risc0/input.json`, `risc0_receipt.*`, `auction_scenario*.json`

## Troubleshooting

### "File too large" error when committing
```bash
# File should be in .gitattributes for LFS
git lfs track "path/to/large/file"
git add .gitattributes
git add path/to/large/file
git commit
```

### LFS files not downloading
```bash
# Manually fetch LFS files
git lfs fetch
git lfs checkout
```

### Want to skip LFS download (build from source)
```bash
# Clone without LFS files
GIT_LFS_SKIP_SMUDGE=1 git clone <repo>
```

### Check LFS status
```bash
# See which files are managed by LFS
git lfs ls-files

# Check LFS file sizes
du -h circom/stark_verify circom/prover circom/*.zkey
```

## Platform Support

| Platform | Pre-built Binaries | Build from Source |
|----------|-------------------|-------------------|
| Linux x86_64 | ✅ Yes (via LFS) | ✅ Yes |
| Linux ARM64 | ❌ No | ✅ Yes |
| macOS x86_64 | ❌ No | ✅ Yes |
| macOS ARM64 (M1/M2) | ❌ No | ✅ Yes (with --no_asm) |
| Windows | ❌ No | ⚠️ WSL2 required |

## Storage Requirements

- **With LFS files**: ~4GB (includes pre-built binaries)
- **Without LFS files**: ~200MB (source only)
- **After full build**: ~10GB (includes all caches)

## Contributing

When contributing:
1. **Don't commit**: Build caches, test data, runtime files (they're in `.gitignore`)
2. **Do commit with LFS**: Updated binaries if you rebuild them for x86_64 Linux
3. **Document**: Any architecture-specific build issues

---
*Note: Pre-built binaries are provided for convenience but you should verify or rebuild them for production use.*