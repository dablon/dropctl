# dropctl - Secure Peer-to-Peer File Transfer

A blazing fast, secure CLI tool for transferring files between hosts using native cryptographic protocols. No dependencies, no PKI, just pure security.

<p align="center">
  <img src="https://img.shields.io/badge/Rust-stable-blue?style=flat-square" alt="Rust">
  <img src="https://img.shields.io/github/license/dablon/dropctl" alt="License">
  <img src="https://img.shields.io/github/v/release/dablon/dropctl" alt="Release">
</p>

## Why dropctl?

Traditional file transfer tools either lack security or require complex setup (SSH keys, TLS certificates, FTP servers). **dropctl** gives you:

- 🔐 **Military-grade encryption** - X25519 + ChaCha20-Poly1305
- 🚀 **Blazing fast** - Zero overhead, native performance  
- 📦 **Single binary** - No runtime dependencies
- 🌐 **P2P** - Direct host-to-host transfer, no intermediary
- 🔑 **No PKI** - Key-based verification, no certificates needed

## Installation

### Pre-built Binaries

Download from [Releases](https://github.com/dablon/dropctl/releases):

```bash
# Linux
curl -L https://github.com/dablon/dropctl/releases/latest/download/dropctl-linux-x86_64 -o dropctl
chmod +x dropctl

# macOS
curl -L https://github.com/dablon/dropctl/releases/latest/download/dropctl-macos-x86_64 -o dropctl
chmod +x dropctl

# Windows
curl -L -o dropctl.exe https://github.com/dablon/dropctl/releases/latest/download/dropctl-windows-x86_64.exe
```

### From Source

```bash
git clone https://github.com/dablon/dropctl.git
cd dropctl
cargo install --locked
# Or build manually:
cargo build --release
./target/release/dropctl
```

## Quick Start

### 1. Get Your Public Key

```bash
./dropctl show-key
```

Example output:
```
Your public key:
4sKj8R2...:Ax9Ym7...

Share this with your peer so they can verify your identity.
```

**Share this key with your peer!** They need it to verify your identity.

### 2. Receive Files (Server Mode)

```bash
# Listen on default port 7777, save to current directory
./dropctl listen

# Or with options
./dropctl listen 7777 --output /path/to/save --hostname my machine
```

### 3. Send Files (Client Mode)

```bash
# Simple send (no peer verification)
./dropctl send 192.168.1.100:7777 path/to/file.zip

# With peer verification (recommended!)
./dropctl send 192.168.1.100:7777 file.zip --peer-key "PEER_PUBLIC_KEY"
```

## Security

### Cryptographic Protocol

```
┌──────────────────────────────────────────────────────┐
│                  dropctl Protocol                    │
├──────────────────────────────────────────────────────┤
│  1. Key Exchange (X25519 ECDH)                     │
│     ├── Generate ephemeral keypair                   │
│     └── Derive shared secret                        │
│                                                      │
│  2. Key Derivation (HKDF-SHA256)                   │
│     ├── send_key = HKDF(secret, "dropctl-send")    │
│     └── recv_key = HKDF(secret, "dropctl-recv")    │
│                                                      │
│  3. Encryption (ChaCha20-Poly1305)                  │
│     ├── AEAD - Authentication + Encryption          │
│     └── Per-chunk nonces for replay protection      │
│                                                      │
│  4. Identity (Ed25519)                              │
│     └── Sign handshake transcript                   │
└──────────────────────────────────────────────────────┘
```

### Security Features

| Feature | Description |
|---------|-------------|
| **Perfect Forward Secrecy** | New ephemeral keys per session |
| **AEAD Encryption** | ChaCha20-Poly1305 - authenticated encryption |
| **Replay Protection** | Unique nonces per chunk |
| **Identity Verification** | Ed25519 signatures |
| **Zero PKI** | No certificates needed |

### Threat Model

- ✅ Protects against eavesdropping
- ✅ Protects against tampering  
- ✅ Verifies peer identity
- ✅ Provides forward secrecy

- ❌ Does not protect against compromised endpoints
- ❌ Does not provide anonymity

## Usage Examples

### Local Network Transfer

```bash
# Machine A (receiver)
./dropctl listen 7777 --output ~/Downloads

# Machine B (sender)
./dropctl send 192.168.1.50:7777 backup.tar.gz
```

### With Peer Verification

```bash
# Both machines show their keys first
./dropctl show-key

# Receiver starts listening
./dropctl listen 7777

# Sender uses receiver's key for verification
./dropctl send 192.168.1.50:7777 large_file.iso \
  --peer-key "receiver_public_key_here"
```

### Behind Firewall (SSH Tunnel) - RECOMMENDED

If you're behind a firewall or NAT, use an SSH tunnel:

```bash
# On your local machine, create SSH tunnel:
ssh -L 7777:localhost:7777 -N user@remote-server

# Now use dropctl through the tunnel:
./dropctl send localhost:7777 large_file.zip
```

### Alternative: Using a Relay Server

If SSH tunnel is not available, use a relay service:

```bash
# Option 1: Serveo.net (free, no setup)
# On remote server:
ssh -R 7777:localhost:7777 serveo.net

# Option 2: Using a public relay (requires setup)
# See examples/ folder for relay server code

# Option 3: Open port on router/firewall
# Port forward 7777 TCP to your machine
```

### Custom Port

```bash
./dropctl listen 9000
./dropctl send example.com:9000 file.txt
```

## Configuration

### Key Storage

Keys are stored in:
- Linux/macOS: `~/.config/dropctl/identity.key`
- Windows: `%APPDATA%\dropctl\identity.key`

### Known Hosts

Store peer keys for easier connections:

```bash
# Add a known host
./dropctl known-hosts add office-pc "PEER_PUBLIC_KEY"

# List known hosts
./dropctl known-hosts list

# Remove a host
./dropctl known-hosts remove office-pc
```

## Development

### Build

```bash
cargo build --release
```

### Test

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test

# E2E tests (requires network)
cargo test --test e2e_test
```

### Docker

```bash
# Run tests
docker compose up test

# Run e2e tests
docker compose up e2e

# Coverage report
docker compose up coverage
```

## Performance

Transfer speeds are limited only by your network bandwidth:

| File Size | Typical Time (1 Gbps LAN) |
|-----------|--------------------------|
| 100 MB    | ~1 second                |
| 1 GB      | ~10 seconds              |
| 10 GB     | ~1.5 minutes             |

## Alternatives

| Tool | Pros | Cons |
|------|------|------|
| dropctl | P2P, no server, encrypted | Newer, less tested |
| SCP/SFTP | Mature, widely used | Requires SSH setup |
| rsync | Efficient, delta transfer | No encryption by default |
| FTP | Simple | No encryption (usually) |
| AirDrop | Easy (Apple) | Apple only, closed source |

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## Support

- 📖 [Documentation](https://github.com/dablon/dropctl#readme)
- 🐛 [Issues](https://github.com/dablon/dropctl/issues)
- 💬 [Discussions](https://github.com/dablon/dropctl/discussions)

---

<p align="center">
Made with ⚡ by <a href="https://github.com/dablon">dablon</a>
</p>
