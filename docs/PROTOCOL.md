# ChunkNet Protocol Specification

**Version:** 1.0
**Status:** Draft

## Overview

ChunkNet is a chunk-based file transfer protocol that provides secure, reliable, and resumable file transfers. This document defines the wire protocol, message formats, and state machines for ChunkNet implementations.

## Design Principles

1. **Chunk-based**: Files are split into fixed-size chunks for independent transmission
2. **Secure by default**: All data is encrypted after handshake
3. **Resumable**: Transfers can be resumed from the last acknowledged chunk
4. **Verifiable**: Per-chunk checksums and whole-file hash validation
5. **Extensible**: Versioned messages with reserved fields for future use

---

## Constants

| Name | Value | Description |
|------|-------|-------------|
| `DEFAULT_PORT` | 4200 | Default listening port |
| `CHUNK_SIZE` | 262144 (256 KB) | Default chunk size in bytes |
| `MAX_FILENAME_LEN` | 4096 | Maximum filename length |
| `PROTOCOL_VERSION` | 1 | Current protocol version |
| `MAGIC_NUMBER` | 0x434E4554 ("CNET") | Protocol identifier |

---

## Message Format

All messages follow a common header structure using **little-endian** byte order.

### Message Header (12 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Type      |            Flags              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Magic Number | 4 bytes | `0x434E4554` ("CNET") |
| Version | 1 byte | Protocol version (currently 1) |
| Type | 1 byte | Message type (see below) |
| Flags | 2 bytes | Message-specific flags |
| Payload Length | 4 bytes | Length of payload in bytes |

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| `HELLO` | 0x01 | Initial handshake from sender |
| `HELLO_ACK` | 0x02 | Handshake response from receiver |
| `KEY_EXCHANGE` | 0x03 | Public key for session key derivation |
| `KEY_EXCHANGE_ACK` | 0x04 | Key exchange confirmation |
| `FILE_INFO` | 0x10 | File metadata before transfer |
| `FILE_INFO_ACK` | 0x11 | File metadata acknowledgment |
| `CHUNK` | 0x20 | File chunk data |
| `CHUNK_ACK` | 0x21 | Chunk acknowledgment |
| `TRANSFER_COMPLETE` | 0x30 | All chunks sent |
| `TRANSFER_VERIFIED` | 0x31 | Whole-file hash verified |
| `ERROR` | 0xFF | Error condition |

---

## Handshake Phase

The handshake establishes identity and negotiates encryption parameters.

### State Diagram

```
Sender                                          Receiver
  |                                                 |
  |  -------- HELLO (version, capabilities) ----->  |
  |                                                 |
  |  <------ HELLO_ACK (version, capabilities) ---  |
  |                                                 |
  |  -------- KEY_EXCHANGE (public_key) --------->  |
  |                                                 |
  |  <------ KEY_EXCHANGE_ACK (public_key) -------  |
  |                                                 |
  |  [Both derive shared session key]               |
  |  [All subsequent messages are encrypted]        |
  |                                                 |
```

### HELLO Message (Type 0x01)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Min Version |   Max Version |        Capabilities           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Client ID (16 bytes)                   |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Min Version | 1 byte | Minimum supported protocol version |
| Max Version | 1 byte | Maximum supported protocol version |
| Capabilities | 2 bytes | Supported features bitmap |
| Client ID | 16 bytes | Random client identifier (UUID) |

#### Capability Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | `CAP_AES_GCM` | Supports AES-256-GCM |
| 1 | `CAP_CHACHA20` | Supports ChaCha20-Poly1305 |
| 2 | `CAP_COMPRESSION` | Supports chunk compression |
| 3 | `CAP_RESUME` | Supports transfer resume |
| 4-15 | Reserved | Must be zero |

### HELLO_ACK Message (Type 0x02)

Same format as HELLO. The receiver selects the highest common version and preferred cipher.

### KEY_EXCHANGE Message (Type 0x03)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Cipher     |   Reserved    |         Key Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Public Key (32 bytes)                      |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Cipher | 1 byte | Selected cipher (0=AES-GCM, 1=ChaCha20) |
| Reserved | 1 byte | Must be zero |
| Key Length | 2 bytes | Public key length (32 for X25519) |
| Public Key | 32 bytes | X25519 public key |

### KEY_EXCHANGE_ACK Message (Type 0x04)

Same format as KEY_EXCHANGE. After this message, both parties derive the session key using X25519 ECDH and HKDF.

---

## Session Key Derivation

```
shared_secret = X25519(local_private_key, remote_public_key)
session_key = HKDF-SHA256(
    salt = sender_client_id || receiver_client_id,
    ikm = shared_secret,
    info = "chunknet-session-v1",
    length = 32
)
```

---

## Encrypted Message Format

After key exchange, all messages are wrapped in an authenticated encryption envelope.

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Message Header (12 bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Nonce (12 bytes)                       |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              Encrypted Payload (variable length)              |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Auth Tag (16 bytes)                      |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The nonce is constructed as:
- Bytes 0-3: Message counter (incrementing, little-endian)
- Bytes 4-11: Random bytes (from handshake)

The header is used as Additional Authenticated Data (AAD).

---

## File Transfer Phase

### FILE_INFO Message (Type 0x10)

Sent by the sender to describe the file being transferred.

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        File Size (8 bytes)                    |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Chunk Size (4 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Total Chunks (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Filename Length (2 bytes)  |    Reserved   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   File Hash SHA-256 (32 bytes)                |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Filename (UTF-8, variable)                 |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| File Size | 8 bytes | Total file size in bytes |
| Chunk Size | 4 bytes | Size of each chunk |
| Total Chunks | 4 bytes | Total number of chunks |
| Filename Length | 2 bytes | Length of filename |
| Reserved | 1 byte | Must be zero |
| File Hash | 32 bytes | SHA-256 hash of complete file |
| Filename | variable | UTF-8 encoded filename |

### FILE_INFO_ACK Message (Type 0x11)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Status     |                   Reserved                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Resume From Chunk (4 bytes)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Status | 1 byte | 0=Accept, 1=Reject, 2=Resume |
| Reserved | 3 bytes | Must be zero |
| Resume From | 4 bytes | Chunk index to resume from (if Status=2) |

### CHUNK Message (Type 0x20)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Chunk Index (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Chunk Size (4 bytes)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                  Chunk Hash SHA-256 (32 bytes)                |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Chunk Data (variable)                      |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Chunk Index | 4 bytes | Zero-based chunk index |
| Chunk Size | 4 bytes | Size of chunk data |
| Chunk Hash | 32 bytes | SHA-256 hash of chunk data |
| Chunk Data | variable | Raw chunk bytes |

### CHUNK_ACK Message (Type 0x21)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Chunk Index (4 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Status     |                   Reserved                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|-------|------|-------------|
| Chunk Index | 4 bytes | Acknowledged chunk index |
| Status | 1 byte | 0=OK, 1=Hash mismatch, 2=Out of order |
| Reserved | 3 bytes | Must be zero |

---

## Transfer Completion

### TRANSFER_COMPLETE Message (Type 0x30)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Total Chunks Sent (4 bytes)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Total Bytes Sent (8 bytes)                |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### TRANSFER_VERIFIED Message (Type 0x31)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Status     |                   Reserved                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Status | Description |
|--------|-------------|
| 0 | Success - file hash verified |
| 1 | Failure - hash mismatch |

---

## Error Handling

### ERROR Message (Type 0xFF)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Error Code  |  Error Level  |       Message Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                Error Message (UTF-8, variable)                |
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | `ERR_VERSION_MISMATCH` | Incompatible protocol versions |
| 0x02 | `ERR_CIPHER_MISMATCH` | No common cipher available |
| 0x03 | `ERR_KEY_EXCHANGE_FAILED` | Key exchange failure |
| 0x04 | `ERR_DECRYPTION_FAILED` | Message decryption failed |
| 0x05 | `ERR_HASH_MISMATCH` | Chunk or file hash mismatch |
| 0x06 | `ERR_FILE_NOT_FOUND` | Requested file not found |
| 0x07 | `ERR_PERMISSION_DENIED` | Permission denied |
| 0x08 | `ERR_DISK_FULL` | Insufficient disk space |
| 0x09 | `ERR_TRANSFER_CANCELLED` | Transfer cancelled by user |
| 0x0A | `ERR_TIMEOUT` | Operation timed out |
| 0xFF | `ERR_UNKNOWN` | Unknown error |

### Error Levels

| Level | Name | Description |
|-------|------|-------------|
| 0 | `LEVEL_WARNING` | Non-fatal, transfer may continue |
| 1 | `LEVEL_ERROR` | Fatal, transfer must abort |

---

## State Machine

### Sender States

```
    ┌──────────────┐
    │  IDLE        │
    └──────┬───────┘
           │ connect()
           v
    ┌──────────────┐
    │  CONNECTING  │
    └──────┬───────┘
           │ HELLO_ACK received
           v
    ┌──────────────┐
    │  KEY_EXCHANGE│
    └──────┬───────┘
           │ KEY_EXCHANGE_ACK received
           v
    ┌──────────────┐
    │  READY       │
    └──────┬───────┘
           │ send_file()
           v
    ┌──────────────┐
    │  SENDING     │◄────────┐
    └──────┬───────┘         │
           │ all chunks ack'd│ CHUNK_ACK (retry)
           v                 │
    ┌──────────────┐         │
    │  COMPLETING  │─────────┘
    └──────┬───────┘
           │ TRANSFER_VERIFIED
           v
    ┌──────────────┐
    │  DONE        │
    └──────────────┘
```

### Receiver States

```
    ┌──────────────┐
    │  LISTENING   │
    └──────┬───────┘
           │ HELLO received
           v
    ┌──────────────┐
    │  HANDSHAKING │
    └──────┬───────┘
           │ KEY_EXCHANGE received
           v
    ┌──────────────┐
    │  READY       │
    └──────┬───────┘
           │ FILE_INFO received
           v
    ┌──────────────┐
    │  RECEIVING   │◄────────┐
    └──────┬───────┘         │
           │                 │ CHUNK received
           │ TRANSFER_COMPLETE
           v                 │
    ┌──────────────┐         │
    │  VERIFYING   │─────────┘
    └──────┬───────┘
           │ hash verified
           v
    ┌──────────────┐
    │  DONE        │
    └──────────────┘
```

---

## Timeouts

| Operation | Default Timeout | Description |
|-----------|-----------------|-------------|
| Connect | 10 seconds | Initial TCP connection |
| Handshake | 30 seconds | Complete handshake phase |
| Chunk ACK | 5 seconds | Wait for chunk acknowledgment |
| Idle | 60 seconds | No activity on connection |

---

## Security Considerations

1. **Nonce Reuse**: Never reuse nonces with the same key. The counter-based nonce prevents this.
2. **Timing Attacks**: Use constant-time comparison for hashes and authentication tags.
3. **Key Erasure**: Zero out keys from memory after use.
4. **Forward Secrecy**: Ephemeral X25519 keys provide forward secrecy per session.
5. **Downgrade Attacks**: Refuse connections if no secure cipher is available.
