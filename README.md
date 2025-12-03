# ChunkNet

A secure, chunk-based file transfer tool written in C.

## Demo

https://github.com/user-attachments/assets/demo.mov

See [docs/Demo.mov](docs/Demo.mov) for a demonstration of ChunkNet in action.

## Overview

ChunkNet is a file transfer tool that splits files into fixed-size chunks, encrypts everything with modern AEAD ciphers, and verifies integrity at both chunk and file levels.

## Features

- **Chunk-based transmission**: Files are split into 256KB chunks for efficient transfer
- **End-to-end encryption**: X25519 key exchange with ChaCha20-Poly1305 or AES-256-GCM
- **Integrity verification**: SHA-256 checksums per-chunk and whole-file hash validation
- **Simple CLI**: Easy-to-use send and receive commands

## Quick Start

### Requirements

- C99 compatible compiler (gcc, clang)
- libsodium (`brew install libsodium` on macOS, `apt install libsodium-dev` on Debian/Ubuntu)
- POSIX-compatible system (Linux, macOS, BSD)

### Build

```bash
make        # Build the project
make test   # Run all tests (88 tests)
make clean  # Remove object files
make re     # Rebuild from scratch
```

### Usage

**Receive a file:**
```bash
# Start receiver (waits for incoming connection)
./chunknet receive

# Or specify a custom port
./chunknet receive --port 8080
```

**Send a file:**
```bash
# Send a file to a receiver
./chunknet send 192.168.1.100 document.pdf

# Or specify a custom port
./chunknet send 192.168.1.100 document.pdf --port 8080
```

**Example session:**
```bash
# Terminal 1 - Receiver
$ ./chunknet receive
Initializing receiver...
Listening on port 4200...
Waiting for connection...
Connection accepted. Receiving file...
File received and verified successfully!

# Terminal 2 - Sender
$ ./chunknet send 127.0.0.1 myfile.zip
Initializing sender...
Connecting to 127.0.0.1:4200...
Connected. Sending file: myfile.zip
File sent successfully!
```

## Protocol

ChunkNet uses a binary protocol with a 12-byte header and length-prefixed messages. The transfer flow:

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
├── main.c                  # Entry point, CLI dispatch
├── cli/
│   ├── cli.h               # CLI types
│   └── parse.c             # Argument parsing
├── protocol/
│   ├── message.h/c         # Message serialization (12-byte header, all payloads)
│   ├── sender.h/c          # Sender state machine
│   └── receiver.h/c        # Receiver state machine
├── network/
│   └── socket.h/c          # TCP socket abstraction
├── crypto/
│   └── crypto.h/c          # libsodium wrappers (X25519, ChaCha20, SHA-256, HKDF)
├── file/
│   └── file.h/c            # File reading, writing, chunking, hashing
├── common/
│   └── dbgprintf.h/c       # Debug utilities
└── const.h                 # Protocol constants
```

## Testing

ChunkNet has comprehensive test coverage with 88 unit and integration tests:

```bash
make test
```

| Test Suite | Tests | Description |
|------------|-------|-------------|
| parse_receive | 16 | CLI parsing for receive command |
| parse_send | 22 | CLI parsing for send command |
| message | 13 | Protocol message serialization |
| socket | 7 | TCP socket operations |
| crypto | 13 | Cryptographic operations |
| file | 14 | File I/O and chunking |
| transfer | 3 | End-to-end transfer integration |

## Security

- **X25519 Key Exchange**: Ephemeral ECDH for forward secrecy
- **ChaCha20-Poly1305**: Authenticated encryption (AES-256-GCM also supported)
- **HKDF-SHA256**: Secure session key derivation
- **SHA-256**: Integrity verification at chunk and file level
- **Constant-time operations**: Via libsodium to prevent timing attacks

## Constants

| Name | Value | Description |
|------|-------|-------------|
| `DEFAULT_PORT` | 4200 | Default listening port |
| `CHUNK_SIZE` | 256 KB | Size of each file chunk |
| `MAGIC_NUMBER` | 0x434E4554 | Protocol identifier ("CNET") |

## License

MIT License
