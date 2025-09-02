# RISC Zero Claim Digest Computation - Python Implementation

This README explains exactly how `compute_claim_digest.py` computes the RISC Zero claim digest from raw values.

## Overview

The Python script computes the RISC Zero claim digest by replicating the exact same computation as the Rust `compute_claim_digest_from_raw_values` function, using only standard Python libraries.

## Input Files

1. **`risc0_receipt.json`**: Contains the RISC Zero receipt with claim data
2. **`auction_scenario_N10.json`**: Contains auction participant data (used for journal construction)

## Step-by-Step Computation

### Step 1: Extract Raw Values from Receipt

```python
# From risc0_receipt.json, extract:
claim = receipt['inner']['Succinct']['claim']['Value']

pre_pc = claim['pre']['Value']['pc']
pre_merkle_root = digest_to_bytes(claim['pre']['Value']['merkle_root'])

post_pc = claim['post']['Value']['pc']
post_merkle_root = digest_to_bytes(claim['post']['Value']['merkle_root'])

sys_exit, user_exit = extract_exit_codes(claim['exit_code'])
assumptions_digest = extract_assumptions_digest(claim['output'])
```

### Step 2: Build Journal Data

```python
# PublicJournal with exact participant order from RISC Zero execution
journal = {
    'clearing_price': 45,
    'in_coin': [2976, 2151, 3149, 3020, 1684, 1614, 2645, 2008, 2184, 2848],
    'in_energy': [115, 171, 115, 128, 173, 89, 160, 86, 177, 119],
    'out_coin': [2121, 1926, 2564, 2075, 1684, 2289, 3050, 2818, 2904, 2848],
    'out_energy': [134, 176, 128, 149, 173, 74, 151, 68, 161, 119]
}

# Serialize to 344 bytes using RISC Zero format
journal_bytes = serialize_journal_risc0_format(journal)
```

### Step 3: Compute Pre-State Digest

```python
# tagged_struct("risc0.SystemState", &[merkle_root], &[pc])
tag = sha256(b"risc0.SystemState")  
# → 0x...(32 bytes)

buf = bytearray()
buf.extend(tag)                           # 32 bytes: tag digest
buf.extend(pre_merkle_root)               # 32 bytes: merkle root digest  
buf.extend(struct.pack('<I', pre_pc))     # 4 bytes: pc as little-endian u32
buf.extend(struct.pack('<H', 1))          # 2 bytes: down_count=1 as little-endian u16

pre_state_digest = to_risc0_digest_format(sha256(bytes(buf)))
# → 0xba231fa8677943ad184710b9448eaff866744e86f8b74ba00d67fcbc7cf80b1e
```

### Step 4: Compute Post-State Digest

```python
# Same as pre-state but with post-execution values
tag = sha256(b"risc0.SystemState")
buf = bytearray()
buf.extend(tag)
buf.extend(post_merkle_root)              # All zeros
buf.extend(struct.pack('<I', post_pc))    # 0
buf.extend(struct.pack('<H', 1))

post_state_digest = to_risc0_digest_format(sha256(bytes(buf)))
# → 0xa3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2
```

### Step 5: Compute Journal Digest

```python
journal_digest = to_risc0_digest_format(sha256(journal_bytes))
# → 0x4e57730ff2ecfe390e311a37f4db871d0aa823364549790f2113922bdcd1b112
```

### Step 6: Compute Output Digest

```python
# tagged_struct("risc0.Output", &[journal_digest, assumptions_digest], &[])
tag = sha256(b"risc0.Output")

buf = bytearray()
buf.extend(tag)                           # 32 bytes: tag digest
buf.extend(journal_digest)                # 32 bytes: journal digest
buf.extend(assumptions_digest)            # 32 bytes: assumptions digest (zeros)
# No data array for Output
buf.extend(struct.pack('<H', 2))          # 2 bytes: down_count=2

output_digest = to_risc0_digest_format(sha256(bytes(buf)))
# → 0x19c5a08e1f414ea9b79386865d59fc8c5e51710aff0d3a217b8f67479b7159e7
```

### Step 7: Compute Final Claim Digest

```python
# Input digest is always zero
input_digest = bytes(32)  # 32 zero bytes

# tagged_struct("risc0.ReceiptClaim", &[input, pre, post, output], &[sys_exit, user_exit])
tag = sha256(b"risc0.ReceiptClaim")

buf = bytearray()
buf.extend(tag)                           # 32 bytes: tag digest
buf.extend(input_digest)                  # 32 bytes: input digest (zeros)
buf.extend(pre_state_digest)              # 32 bytes: pre-state digest
buf.extend(post_state_digest)             # 32 bytes: post-state digest  
buf.extend(output_digest)                 # 32 bytes: output digest
buf.extend(struct.pack('<I', sys_exit))   # 4 bytes: sys_exit=0 as little-endian u32
buf.extend(struct.pack('<I', user_exit))  # 4 bytes: user_exit=0 as little-endian u32
buf.extend(struct.pack('<H', 4))          # 2 bytes: down_count=4 as little-endian u16

claim_digest = to_risc0_digest_format(sha256(bytes(buf)))
# → 0x4b1806617610caa52f61baf15a0c4a30da29f225c08d21c76e275ddc23fada9e
```

## Key Helper Functions

### `to_risc0_digest_format(hash_bytes: bytes) -> bytes`

Converts standard SHA256 output to RISC Zero's internal digest format:

```python
# SHA256 produces 32 bytes
# RISC Zero stores as [u32; 8] in little-endian format

words = []
for i in range(8):
    word_bytes = hash_bytes[i*4:(i+1)*4]
    # Convert 4 bytes to u32 using little-endian (matches Rust from_le_bytes)
    words.append(struct.unpack('<I', word_bytes)[0])

# Convert back to bytes (matches Rust .as_bytes() on Digest)  
result = b''
for word in words:
    result += struct.pack('<I', word)  # Store as little-endian

return result
```

### `serialize_journal_risc0_format(journal: dict) -> bytes`

Serializes PublicJournal to RISC Zero's binary format:

```python
words = []

# clearing_price as u64 → 2 u32 words (little-endian)
price_bytes = struct.pack('<Q', journal['clearing_price'])
words.append(struct.unpack('<I', price_bytes[0:4])[0])
words.append(struct.unpack('<I', price_bytes[4:8])[0])

# Each Vec<u64> field
for field in ['in_coin', 'in_energy', 'out_coin', 'out_energy']:
    vec = journal[field]
    words.append(len(vec))  # Length as u32
    
    # Each u64 value → 2 u32 words (little-endian)
    for val in vec:
        val_bytes = struct.pack('<Q', val)
        words.append(struct.unpack('<I', val_bytes[0:4])[0])
        words.append(struct.unpack('<I', val_bytes[4:8])[0])

# Convert all u32 words to bytes (little-endian)
result = bytearray()
for word in words:
    result.extend(struct.pack('<I', word))

return bytes(result)  # 344 bytes total
```

## Tagged Struct Format

RISC Zero uses this specific format for all structured hashing:

```
tagged_struct(tag_string, digest_array, data_array) = SHA256(
    SHA256(tag_string) ||                    # 32 bytes: type identifier  
    digest_array[0] || digest_array[1] || ... ||  # 32*N bytes: digest values
    data_array[0] || data_array[1] || ... ||      # 4*M bytes: u32 values (little-endian)
    len(digest_array)                        # 2 bytes: array length (little-endian u16)
)
```

## Final Result

The claim digest computation produces:
```
0x4b1806617610caa52f61baf15a0c4a30da29f225c08d21c76e275ddc23fada9e
```

This matches exactly the output from RISC Zero's internal computation, proving the implementation is correct.

## Groth16 Public Inputs

The claim digest is split into two halves for Groth16:
- **c0**: `0x4b1806617610caa52f61baf15a0c4a30` (first 16 bytes)
- **c1**: `0xda29f225c08d21c76e275ddc23fada9e` (last 16 bytes)

## Verification

Run both implementations to verify they produce identical results:

```bash
# Rust implementation  
cargo run --release ./auction_scenario_N10.json

# Python implementation
python3 compute_claim_digest.py
```

Both should output the same claim digest: `0x4b1806617610caa52f61baf15a0c4a30da29f225c08d21c76e275ddc23fada9e`