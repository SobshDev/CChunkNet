# ChunkNet

A secure, chunk-based file transfer protocol written in C.

## Overview

ChunkNet is a custom file transfer protocol designed for reliable, secure, and resumable file transfers across any network. It splits files into fixed-size chunks, encrypts everything with modern AEAD ciphers, and verifies integrity at both chunk and file levels.

## Features

- **Chunk-based transmission**: Files are split into 256KB chunks for independent transfer
- **End-to-end encryption**: X25519 key exchange with AES-256-GCM or ChaCha20-Poly1305
- **Integrity verification**: Per-chunk SHA-256 checksums plus whole-file hash validation
- **Resumable transfers**: Interrupted transfers can resume from the last acknowledged chunk
- **Simple CLI**: Easy-to-use send and receive modes

## Quick Start

### Build

```bash
make        # Build the project
make clean  # Remove object files
make fclean # Remove object files and executable
make re     # Rebuild from scratch
```

### Usage

**Receive a file:**
```bash
./chunknet receive --port 4200
```

**Send a file:**
```bash
./chunknet send --host 192.168.1.100 --port 4200 --file document.pdf
```

## Protocol

ChunkNet uses a binary protocol with length-prefixed messages. The transfer flow is:

```
┌────────┐                              ┌──────────┐
│ Sender │                              │ Receiver │
└───┬────┘                              └────┬─────┘
    │                                        │
    │  ─────────── HELLO ──────────────────► │
    │  ◄────────── HELLO_ACK ─────────────── │
    │                                        │
    │  ─────────── KEY_EXCHANGE ───────────► │
    │  ◄────────── KEY_EXCHANGE_ACK ──────── │
    │                                        │
    │  ══════ [Encrypted from here] ═══════  │
    │                                        │
    │  ─────────── FILE_INFO ──────────────► │
    │  ◄────────── FILE_INFO_ACK ─────────── │
    │                                        │
    │  ─────────── CHUNK [0] ──────────────► │
    │  ◄────────── CHUNK_ACK [0] ─────────── │
    │  ─────────── CHUNK [1] ──────────────► │
    │  ◄────────── CHUNK_ACK [1] ─────────── │
    │              ...                       │
    │  ─────────── TRANSFER_COMPLETE ──────► │
    │  ◄────────── TRANSFER_VERIFIED ─────── │
    │                                        │
```

For the complete protocol specification, see [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Architecture

```
src/
├── main.c                # Entry point and CLI
├── common/               # Types, messages, utilities
├── crypto/               # Key exchange, AEAD encryption, hashing
├── protocol/             # Handshake, chunking, transfer logic
├── network/              # Socket abstraction, client/server
└── cli/                  # Command-line interface
```

## Security

ChunkNet prioritizes security:

- **Authenticated Key Exchange**: X25519 ECDH establishes shared secrets
- **AEAD Encryption**: All data encrypted with AES-256-GCM or ChaCha20-Poly1305
- **Forward Secrecy**: Ephemeral keys ensure past sessions remain secure
- **Integrity**: SHA-256 hashes detect any tampering

## Requirements

- C99 compatible compiler
- OpenSSL or libsodium (for cryptographic operations)
- POSIX-compatible system (Linux, macOS, BSD)

## License

MIT License - See [LICENSE](LICENSE) for details.
