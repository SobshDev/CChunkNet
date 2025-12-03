#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stddef.h>
#include "../const.h"

/*
 * Protocol Message Definitions
 * All values use little-endian byte order
 */

/* Message Header Size */
#define HEADER_SIZE 12

/* Client ID Size (UUID) */
#define CLIENT_ID_SIZE 16

/* Public Key Size (X25519) */
#define PUBLIC_KEY_SIZE 32

/* SHA-256 Hash Size */
#define HASH_SIZE 32

/* AEAD Nonce Size */
#define NONCE_SIZE 12

/* AEAD Auth Tag Size */
#define AUTH_TAG_SIZE 16

/* ========================================
 * Message Types
 * ======================================== */

typedef enum {
    MSG_HELLO              = 0x01,
    MSG_HELLO_ACK          = 0x02,
    MSG_KEY_EXCHANGE       = 0x03,
    MSG_KEY_EXCHANGE_ACK   = 0x04,
    MSG_FILE_INFO          = 0x10,
    MSG_FILE_INFO_ACK      = 0x11,
    MSG_CHUNK              = 0x20,
    MSG_CHUNK_ACK          = 0x21,
    MSG_TRANSFER_COMPLETE  = 0x30,
    MSG_TRANSFER_VERIFIED  = 0x31,
    MSG_ERROR              = 0xFF
} MessageType;

/* ========================================
 * Capability Flags
 * ======================================== */

typedef enum {
    CAP_AES_GCM      = (1 << 0),  /* Supports AES-256-GCM */
    CAP_CHACHA20     = (1 << 1),  /* Supports ChaCha20-Poly1305 */
    CAP_COMPRESSION  = (1 << 2),  /* Supports chunk compression */
    CAP_RESUME       = (1 << 3)   /* Supports transfer resume */
} CapabilityFlags;

/* ========================================
 * Cipher Selection
 * ======================================== */

typedef enum {
    CIPHER_AES_GCM   = 0,
    CIPHER_CHACHA20  = 1
} CipherType;

/* ========================================
 * Error Codes
 * ======================================== */

typedef enum {
    ERR_VERSION_MISMATCH    = 0x01,
    ERR_CIPHER_MISMATCH     = 0x02,
    ERR_KEY_EXCHANGE_FAILED = 0x03,
    ERR_DECRYPTION_FAILED   = 0x04,
    ERR_HASH_MISMATCH       = 0x05,
    ERR_FILE_NOT_FOUND      = 0x06,
    ERR_PERMISSION_DENIED   = 0x07,
    ERR_DISK_FULL           = 0x08,
    ERR_TRANSFER_CANCELLED  = 0x09,
    ERR_TIMEOUT             = 0x0A,
    ERR_UNKNOWN             = 0xFF
} ErrorCode;

/* ========================================
 * Error Levels
 * ======================================== */

typedef enum {
    LEVEL_WARNING = 0,  /* Non-fatal, transfer may continue */
    LEVEL_ERROR   = 1   /* Fatal, transfer must abort */
} ErrorLevel;

/* ========================================
 * FILE_INFO_ACK Status
 * ======================================== */

typedef enum {
    FILE_STATUS_ACCEPT = 0,
    FILE_STATUS_REJECT = 1,
    FILE_STATUS_RESUME = 2
} FileInfoStatus;

/* ========================================
 * CHUNK_ACK Status
 * ======================================== */

typedef enum {
    CHUNK_STATUS_OK           = 0,
    CHUNK_STATUS_HASH_MISMATCH = 1,
    CHUNK_STATUS_OUT_OF_ORDER  = 2
} ChunkAckStatus;

/* ========================================
 * Message Header (12 bytes)
 * ======================================== */

typedef struct {
    uint32_t magic;        /* 0x434E4554 ("CNET") */
    uint8_t  version;      /* Protocol version (1) */
    uint8_t  type;         /* Message type */
    uint16_t flags;        /* Message-specific flags */
    uint32_t payload_len;  /* Payload length in bytes */
} MessageHeader;

/* ========================================
 * HELLO / HELLO_ACK Payload (20 bytes)
 * ======================================== */

typedef struct {
    uint8_t  min_version;              /* Minimum supported version */
    uint8_t  max_version;              /* Maximum supported version */
    uint16_t capabilities;             /* Capability flags bitmap */
    uint8_t  client_id[CLIENT_ID_SIZE]; /* Random client identifier */
} HelloPayload;

#define HELLO_PAYLOAD_SIZE 20

/* ========================================
 * KEY_EXCHANGE / KEY_EXCHANGE_ACK Payload (36 bytes)
 * ======================================== */

typedef struct {
    uint8_t  cipher;                     /* Selected cipher */
    uint8_t  reserved;                   /* Must be zero */
    uint16_t key_length;                 /* Public key length (32) */
    uint8_t  public_key[PUBLIC_KEY_SIZE]; /* X25519 public key */
} KeyExchangePayload;

#define KEY_EXCHANGE_PAYLOAD_SIZE 36

/* ========================================
 * FILE_INFO Payload (variable length)
 * Fixed part: 8 + 4 + 4 + 2 + 1 + 32 = 51 bytes + filename
 * ======================================== */

typedef struct {
    uint64_t file_size;               /* Total file size in bytes */
    uint32_t chunk_size;              /* Size of each chunk */
    uint32_t total_chunks;            /* Total number of chunks */
    uint16_t filename_length;         /* Length of filename */
    uint8_t  reserved;                /* Must be zero */
    uint8_t  file_hash[HASH_SIZE];    /* SHA-256 hash of complete file */
    char     filename[];              /* UTF-8 encoded filename (flexible array) */
} FileInfoPayload;

#define FILE_INFO_FIXED_SIZE 51

/* ========================================
 * FILE_INFO_ACK Payload (8 bytes)
 * ======================================== */

typedef struct {
    uint8_t  status;           /* 0=Accept, 1=Reject, 2=Resume */
    uint8_t  reserved[3];      /* Must be zero */
    uint32_t resume_from;      /* Chunk index to resume from */
} FileInfoAckPayload;

#define FILE_INFO_ACK_PAYLOAD_SIZE 8

/* ========================================
 * CHUNK Payload (variable length)
 * Fixed part: 4 + 4 + 32 = 40 bytes + data
 * ======================================== */

typedef struct {
    uint32_t chunk_index;             /* Zero-based chunk index */
    uint32_t chunk_size;              /* Size of chunk data */
    uint8_t  chunk_hash[HASH_SIZE];   /* SHA-256 hash of chunk data */
    uint8_t  data[];                  /* Raw chunk bytes (flexible array) */
} ChunkPayload;

#define CHUNK_FIXED_SIZE 40

/* ========================================
 * CHUNK_ACK Payload (8 bytes)
 * ======================================== */

typedef struct {
    uint32_t chunk_index;      /* Acknowledged chunk index */
    uint8_t  status;           /* 0=OK, 1=Hash mismatch, 2=Out of order */
    uint8_t  reserved[3];      /* Must be zero */
} ChunkAckPayload;

#define CHUNK_ACK_PAYLOAD_SIZE 8

/* ========================================
 * TRANSFER_COMPLETE Payload (12 bytes)
 * ======================================== */

typedef struct {
    uint32_t total_chunks_sent;   /* Total chunks sent */
    uint64_t total_bytes_sent;    /* Total bytes sent */
} TransferCompletePayload;

#define TRANSFER_COMPLETE_PAYLOAD_SIZE 12

/* ========================================
 * TRANSFER_VERIFIED Payload (4 bytes)
 * ======================================== */

typedef struct {
    uint8_t  status;           /* 0=Success, 1=Hash mismatch */
    uint8_t  reserved[3];      /* Must be zero */
} TransferVerifiedPayload;

#define TRANSFER_VERIFIED_PAYLOAD_SIZE 4

/* ========================================
 * ERROR Payload (variable length)
 * Fixed part: 1 + 1 + 2 = 4 bytes + message
 * ======================================== */

typedef struct {
    uint8_t  error_code;       /* Error code */
    uint8_t  error_level;      /* 0=Warning, 1=Error */
    uint16_t message_length;   /* Length of error message */
    char     message[];        /* UTF-8 encoded error message (flexible array) */
} ErrorPayload;

#define ERROR_FIXED_SIZE 4

/* ========================================
 * Serialization Functions
 * ======================================== */

/* Header serialization */
size_t serialize_header(const MessageHeader *header, uint8_t *buffer, size_t buffer_size);
int deserialize_header(const uint8_t *buffer, size_t buffer_size, MessageHeader *header);

/* HELLO payload serialization */
size_t serialize_hello(const HelloPayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_hello(const uint8_t *buffer, size_t buffer_size, HelloPayload *payload);

/* KEY_EXCHANGE payload serialization */
size_t serialize_key_exchange(const KeyExchangePayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_key_exchange(const uint8_t *buffer, size_t buffer_size, KeyExchangePayload *payload);

/* FILE_INFO payload serialization */
size_t serialize_file_info(const FileInfoPayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_file_info(const uint8_t *buffer, size_t buffer_size, FileInfoPayload *payload, char *filename_out, size_t filename_buf_size);

/* FILE_INFO_ACK payload serialization */
size_t serialize_file_info_ack(const FileInfoAckPayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_file_info_ack(const uint8_t *buffer, size_t buffer_size, FileInfoAckPayload *payload);

/* CHUNK payload serialization */
size_t serialize_chunk(const ChunkPayload *payload, const uint8_t *data, uint32_t data_size, uint8_t *buffer, size_t buffer_size);
int deserialize_chunk(const uint8_t *buffer, size_t buffer_size, ChunkPayload *payload, uint8_t *data_out, size_t data_buf_size);

/* CHUNK_ACK payload serialization */
size_t serialize_chunk_ack(const ChunkAckPayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_chunk_ack(const uint8_t *buffer, size_t buffer_size, ChunkAckPayload *payload);

/* TRANSFER_COMPLETE payload serialization */
size_t serialize_transfer_complete(const TransferCompletePayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_transfer_complete(const uint8_t *buffer, size_t buffer_size, TransferCompletePayload *payload);

/* TRANSFER_VERIFIED payload serialization */
size_t serialize_transfer_verified(const TransferVerifiedPayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_transfer_verified(const uint8_t *buffer, size_t buffer_size, TransferVerifiedPayload *payload);

/* ERROR payload serialization */
size_t serialize_error(const ErrorPayload *payload, uint8_t *buffer, size_t buffer_size);
int deserialize_error(const uint8_t *buffer, size_t buffer_size, ErrorPayload *payload, char *message_out, size_t message_buf_size);

#endif /* MESSAGE_H */
