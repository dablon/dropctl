# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-03-02

### Added
- Initial release
- X25519 key exchange for secure session establishment
- ChaCha20-Poly1305 AEAD encryption
- Ed25519 identity verification
- Chunked file transfer with progress tracking
- CLI with clap
- Unit tests for crypto and protocol
- E2E tests for file transfer
- Docker and docker-compose for testing

### Features
- `dropctl show-key` - Show public key
- `dropctl listen` - Start server to receive files
- `dropctl send` - Send files to peer
- `dropctl known-hosts` - Manage known peers

### Security
- Perfect forward secrecy (ephemeral keys)
- No PKI required
- Per-chunk nonces
- AEAD encryption

## [0.0.1] - 2026-03-01

### Added
- Internal development version
