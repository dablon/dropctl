# dropctl - Secure Peer-to-Peer File Transfer

A fast, secure CLI tool for transferring files between hosts using native cryptographic protocols.

## Features

- 🔐 **X25519 Key Exchange** - Elliptic curve Diffie-Hellman for secure session establishment
- 🔒 **ChaCha20-Poly1305 AEAD** - Authenticated encryption with no TLS overhead
- 👤 **Ed25519 Identity** - EdDSA signatures for peer verification
- 📦 **Chunked Transfer** - Efficient file transfer with progress tracking
- 🚀 **Zero Dependencies** - Single binary, no runtime dependencies

## Installation

### From Source

```bash
cargo build --release
./target/release/dropctl
```

### Pre-built

Download from [Releases](https://github.com/buildermaleon/dropctl/releases)

## Usage

### 1. Show Your Public Key

```bash
./dropctl show-key
```

Share this key with your peer for identity verification.

### 2. Receive Files (Server Mode)

```bash
./dropctl listen 7777 --output /path/to/save
```

### 3. Send Files (Client Mode)

```bash
./dropctl send localhost:7777 path/to/file.zip
```

### With Peer Verification

```bash
# On receiver, show key first
./dropctl show-key

# On sender, use peer's key
./dropctl send 192.168.1.100:7777 file.zip --peer-key "BASE64_KEY"
```

## Security

### Protocol

1. **Handshake**: X25519 ECDH to establish shared secret
2. **Key Derivation**: HKDF-SHA256 to derive send/receive keys
3. **Encryption**: ChaCha20-Poly1305 with per-chunk nonces
4. **Authentication**: Ed25519 signatures for identity verification

### Key Features

- Perfect forward secrecy (ephemeral keys per session)
- Authenticated encryption (AEAD)
- No PKI required (key-based verification)
- Minimal attack surface

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    dropctl                           │
├──────────────────────────────────────────────────────┤
│  CLI (clap)                                         │
├──────────────────────────────────────────────────────┤
│  Protocol (JSON messages)                           │
├──────────────────────────────────────────────────────┤
│  Crypto: X25519 → HKDF → ChaCha20-Poly1305         │
├──────────────────────────────────────────────────────┤
│  Transport: TCP                                     │
└──────────────────────────────────────────────────────┘
```

## Development

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test
```

### Coverage

```bash
cargo tarpaulin --out Html
```

### Run E2E Tests

```bash
# Using Docker
docker compose up e2e

# Or manually
cargo run -- listen 7777 --output /tmp &
sleep 1
cargo run -- send localhost:7777 /etc/hostname
```

## License

MIT
