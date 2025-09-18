# zig-uricrypt

A Zig library and CLI tool for prefix-preserving, deterministic URI encryption that maintains path hierarchy in encrypted form.

## Purpose

This library provides privacy-preserving URI encryption where URIs sharing the same prefix components produce ciphertexts with common prefixes. This property:

- Preserves Path Hierarchy: Encrypted URIs maintain the same structural relationships as their plaintext counterparts
- Enables Privacy-Preserving Analysis: Allows operations like prefix matching, range queries, and hierarchical data analysis without decrypting the URIs
- Maintains Determinism: Same input URI always produces the same encrypted output

This is particularly useful for applications that need to:

- Store encrypted URIs while preserving their hierarchical relationships
- Perform analytics on encrypted URI patterns
- Implement access controls based on URI prefixes
- Migrate sensitive URIs to encrypted storage without losing structural information

## API Reference

### `encryptUri(allocator, uri, secret_key, context) ![]u8`

Encrypts a URI using the provided secret key and context.

- `allocator`: Memory allocator for the encrypted output
- `uri`: URI to encrypt (e.g., `"https://example.com/path"` or `"/path/to/file"`)
- `secret_key`: Secret key for encryption (any string)
- `context`: Context string for domain separation

Returns encrypted URI as allocated slice. Caller must free the result.

### `decryptUri(allocator, encrypted_uri, secret_key, context) ![]u8`

Decrypts a previously encrypted URI.

- `allocator`: Memory allocator for the decrypted output
- `encrypted_uri`: Encrypted URI from `encryptUri`
- `secret_key`: Same secret key used for encryption
- `context`: Same context used for encryption

Returns original URI as allocated slice. Caller must free the result.

## How It Works

1. URI Parsing: Splits URI into scheme and path components
2. Key Derivation: Uses TurboShake128 to derive cryptographic material from key + context
3. Component Processing: For each URI component:
   - Generate a unique SIV using the component data
   - Generate keystream from key + context + SIV
   - XOR the component with the keystream
   - Apply padding for base64 compatibility
4. Encoding: Concatenate SIVs and encrypted components, encode as base64
5. Scheme Handling: Preserves original scheme or adds `/` prefix for path-only URIs

## Prefix Preservation Example

Given these related URIs:
```
https://api.example.com/v1/users
https://api.example.com/v1/users/123
https://api.example.com/v1/users/123/profile
```

Their encrypted forms will share common prefixes:
```
YWJjZGVmZ2hpams=
YWJjZGVmZ2hpams=bG1ub3BxcnN0dXY=
YWJjZGVmZ2hpams=bG1ub3BxcnN0dXY=eHl6MDEyMzQ1Njc4OQ==
```

This allows you to:
- Find all encrypted URIs under `/v1/users/` without decryption
- Implement hierarchical access controls on encrypted data
- Perform analytics on URI patterns while preserving privacy

## Security Notes

- The encryption is deterministic - same inputs always produce same outputs
- Each component has its own SIV for authentication
- Wrong key or context will cause decryption to fail
- Uses TurboShake128 (SHA3 variant) for all cryptographic operations

## Examples

### Basic URI Encryption
```zig
const encrypted = try uricrypt.encryptUri(
    allocator,
    "https://api.example.com/v1/users/123",
    "api_key_123",
    "production"
);
```

### Path-only URI
```zig
const encrypted = try uricrypt.encryptUri(
    allocator,
    "/uploads/2024/documents/report.pdf",
    "file_storage_key",
    "user_uploads"
);
```
