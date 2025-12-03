#include <string.h>
#include <stdio.h>
#include "sender.h"
#include "../const.h"

static int send_message(Sender *sender, uint8_t type, const uint8_t *payload, size_t payload_len);
static int recv_message(Sender *sender, MessageHeader *header, uint8_t *payload, size_t payload_max);
static int send_encrypted(Sender *sender, uint8_t type, const uint8_t *payload, size_t payload_len);
static int recv_encrypted(Sender *sender, MessageHeader *header, uint8_t *payload, size_t payload_max);

static void set_error(Sender *sender, const char *msg)
{
    strncpy(sender->error_msg, msg, sizeof(sender->error_msg) - 1);
    sender->state = SENDER_ERROR;
}

int sender_init(Sender *sender)
{
    memset(sender, 0, sizeof(*sender));
    sender->state = SENDER_IDLE;
    sender->sock.fd = -1;

    if (crypto_init() < 0) {
        set_error(sender, "Failed to initialize crypto");
        return -1;
    }

    crypto_generate_keypair(&sender->keypair);
    crypto_random_bytes(sender->client_id, CLIENT_ID_SIZE);

    return 0;
}

int sender_connect(Sender *sender, const uint8_t addr[4], uint16_t port)
{
    if (sender->state != SENDER_IDLE) {
        set_error(sender, "Invalid state for connect");
        return -1;
    }

    if (socket_connect(addr, port, &sender->sock) < 0) {
        set_error(sender, "Failed to connect");
        return -1;
    }

    socket_set_timeout(&sender->sock, 30000);
    sender->state = SENDER_CONNECTING;

    HelloPayload hello = {
        .min_version = 1,
        .max_version = 1,
        .capabilities = CAP_CHACHA20 | CAP_AES_GCM
    };
    memcpy(hello.client_id, sender->client_id, CLIENT_ID_SIZE);

    uint8_t hello_buf[HELLO_PAYLOAD_SIZE];
    serialize_hello(&hello, hello_buf, sizeof(hello_buf));

    if (send_message(sender, MSG_HELLO, hello_buf, HELLO_PAYLOAD_SIZE) < 0) {
        set_error(sender, "Failed to send HELLO");
        return -1;
    }

    MessageHeader resp_header;
    uint8_t resp_buf[256];
    if (recv_message(sender, &resp_header, resp_buf, sizeof(resp_buf)) < 0) {
        set_error(sender, "Failed to receive HELLO_ACK");
        return -1;
    }

    if (resp_header.type != MSG_HELLO_ACK) {
        set_error(sender, "Expected HELLO_ACK");
        return -1;
    }

    HelloPayload hello_ack;
    if (deserialize_hello(resp_buf, resp_header.payload_len, &hello_ack) < 0) {
        set_error(sender, "Invalid HELLO_ACK");
        return -1;
    }
    memcpy(sender->peer_id, hello_ack.client_id, CLIENT_ID_SIZE);

    sender->state = SENDER_KEY_EXCHANGE;

    CryptoCipher cipher = (hello_ack.capabilities & CAP_CHACHA20) ?
                          CRYPTO_CIPHER_CHACHA20 : CRYPTO_CIPHER_AES_GCM;

    KeyExchangePayload kex = {
        .cipher = cipher,
        .reserved = 0,
        .key_length = PUBLIC_KEY_SIZE
    };
    memcpy(kex.public_key, sender->keypair.public_key, PUBLIC_KEY_SIZE);

    uint8_t kex_buf[KEY_EXCHANGE_PAYLOAD_SIZE];
    serialize_key_exchange(&kex, kex_buf, sizeof(kex_buf));

    if (send_message(sender, MSG_KEY_EXCHANGE, kex_buf, KEY_EXCHANGE_PAYLOAD_SIZE) < 0) {
        set_error(sender, "Failed to send KEY_EXCHANGE");
        return -1;
    }

    if (recv_message(sender, &resp_header, resp_buf, sizeof(resp_buf)) < 0) {
        set_error(sender, "Failed to receive KEY_EXCHANGE_ACK");
        return -1;
    }

    if (resp_header.type != MSG_KEY_EXCHANGE_ACK) {
        set_error(sender, "Expected KEY_EXCHANGE_ACK");
        return -1;
    }

    KeyExchangePayload kex_ack;
    if (deserialize_key_exchange(resp_buf, resp_header.payload_len, &kex_ack) < 0) {
        set_error(sender, "Invalid KEY_EXCHANGE_ACK");
        return -1;
    }

    uint8_t shared_secret[CRYPTO_KEY_SIZE];
    if (crypto_key_exchange(shared_secret, sender->keypair.secret_key, kex_ack.public_key) < 0) {
        set_error(sender, "Key exchange failed");
        return -1;
    }

    crypto_derive_session_key(&sender->session, shared_secret,
                              sender->client_id, sender->peer_id,
                              CLIENT_ID_SIZE, cipher);
    crypto_zero(shared_secret, sizeof(shared_secret));

    sender->state = SENDER_READY;
    return 0;
}

int sender_send_file(Sender *sender, const char *filepath)
{
    if (sender->state != SENDER_READY) {
        set_error(sender, "Not ready to send file");
        return -1;
    }

    if (file_reader_open(&sender->file, filepath, CHUNK_SIZE) < 0) {
        set_error(sender, "Failed to open file");
        return -1;
    }

    sender->state = SENDER_SENDING;

    uint8_t file_info_buf[512];
    size_t filename_len = strlen(sender->file.filename);

    uint8_t temp[512];
    FileInfoPayload *info = (FileInfoPayload *)temp;
    info->file_size = sender->file.file_size;
    info->chunk_size = sender->file.chunk_size;
    info->total_chunks = sender->file.total_chunks;
    info->filename_length = filename_len;
    info->reserved = 0;
    memcpy(info->file_hash, sender->file.file_hash, HASH_SIZE);
    memcpy(info->filename, sender->file.filename, filename_len);

    size_t info_len = serialize_file_info(info, file_info_buf, sizeof(file_info_buf));

    if (send_encrypted(sender, MSG_FILE_INFO, file_info_buf, info_len) < 0) {
        set_error(sender, "Failed to send FILE_INFO");
        return -1;
    }

    MessageHeader resp_header;
    uint8_t resp_buf[256];
    if (recv_encrypted(sender, &resp_header, resp_buf, sizeof(resp_buf)) < 0) {
        set_error(sender, "Failed to receive FILE_INFO_ACK");
        return -1;
    }

    if (resp_header.type != MSG_FILE_INFO_ACK) {
        set_error(sender, "Expected FILE_INFO_ACK");
        return -1;
    }

    FileInfoAckPayload info_ack;
    deserialize_file_info_ack(resp_buf, resp_header.payload_len, &info_ack);

    if (info_ack.status == FILE_STATUS_REJECT) {
        set_error(sender, "Receiver rejected file");
        return -1;
    }

    sender->current_chunk = (info_ack.status == FILE_STATUS_RESUME) ? info_ack.resume_from : 0;

    uint8_t *chunk_data = malloc(CHUNK_SIZE);
    uint8_t *chunk_buf = malloc(CHUNK_SIZE + 256);
    if (!chunk_data || !chunk_buf) {
        free(chunk_data);
        free(chunk_buf);
        set_error(sender, "Memory allocation failed");
        return -1;
    }

    while (sender->current_chunk < sender->file.total_chunks) {
        uint32_t chunk_len;
        uint8_t chunk_hash[HASH_SIZE];

        if (file_reader_read_chunk(&sender->file, sender->current_chunk,
                                   chunk_data, &chunk_len, chunk_hash) < 0) {
            free(chunk_data);
            free(chunk_buf);
            set_error(sender, "Failed to read chunk");
            return -1;
        }

        ChunkPayload chunk = {
            .chunk_index = sender->current_chunk,
            .chunk_size = chunk_len
        };
        memcpy(chunk.chunk_hash, chunk_hash, HASH_SIZE);

        size_t chunk_msg_len = serialize_chunk(&chunk, chunk_data, chunk_len,
                                                chunk_buf, CHUNK_SIZE + 256);

        if (send_encrypted(sender, MSG_CHUNK, chunk_buf, chunk_msg_len) < 0) {
            free(chunk_data);
            free(chunk_buf);
            set_error(sender, "Failed to send chunk");
            return -1;
        }

        if (recv_encrypted(sender, &resp_header, resp_buf, sizeof(resp_buf)) < 0) {
            free(chunk_data);
            free(chunk_buf);
            set_error(sender, "Failed to receive CHUNK_ACK");
            return -1;
        }

        if (resp_header.type != MSG_CHUNK_ACK) {
            free(chunk_data);
            free(chunk_buf);
            set_error(sender, "Expected CHUNK_ACK");
            return -1;
        }

        ChunkAckPayload ack;
        deserialize_chunk_ack(resp_buf, resp_header.payload_len, &ack);

        if (ack.status != CHUNK_STATUS_OK) {
            free(chunk_data);
            free(chunk_buf);
            set_error(sender, "Chunk rejected by receiver");
            return -1;
        }

        sender->current_chunk++;
    }

    free(chunk_data);
    free(chunk_buf);

    sender->state = SENDER_COMPLETING;

    TransferCompletePayload complete = {
        .total_chunks_sent = sender->file.total_chunks,
        .total_bytes_sent = sender->file.file_size
    };

    uint8_t complete_buf[TRANSFER_COMPLETE_PAYLOAD_SIZE];
    serialize_transfer_complete(&complete, complete_buf, sizeof(complete_buf));

    if (send_encrypted(sender, MSG_TRANSFER_COMPLETE, complete_buf, TRANSFER_COMPLETE_PAYLOAD_SIZE) < 0) {
        set_error(sender, "Failed to send TRANSFER_COMPLETE");
        return -1;
    }

    if (recv_encrypted(sender, &resp_header, resp_buf, sizeof(resp_buf)) < 0) {
        set_error(sender, "Failed to receive TRANSFER_VERIFIED");
        return -1;
    }

    if (resp_header.type != MSG_TRANSFER_VERIFIED) {
        set_error(sender, "Expected TRANSFER_VERIFIED");
        return -1;
    }

    TransferVerifiedPayload verified;
    deserialize_transfer_verified(resp_buf, resp_header.payload_len, &verified);

    if (verified.status != 0) {
        set_error(sender, "File verification failed on receiver");
        return -1;
    }

    sender->state = SENDER_DONE;
    return 0;
}

void sender_cleanup(Sender *sender)
{
    file_reader_close(&sender->file);
    socket_close(&sender->sock);
    crypto_zero(&sender->keypair, sizeof(sender->keypair));
    crypto_zero(&sender->session, sizeof(sender->session));
}

const char *sender_state_name(SenderState state)
{
    switch (state) {
        case SENDER_IDLE: return "IDLE";
        case SENDER_CONNECTING: return "CONNECTING";
        case SENDER_KEY_EXCHANGE: return "KEY_EXCHANGE";
        case SENDER_READY: return "READY";
        case SENDER_SENDING: return "SENDING";
        case SENDER_COMPLETING: return "COMPLETING";
        case SENDER_DONE: return "DONE";
        case SENDER_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

const char *sender_error(Sender *sender)
{
    return sender->error_msg;
}

static int send_message(Sender *sender, uint8_t type, const uint8_t *payload, size_t payload_len)
{
    MessageHeader header = {
        .magic = MAGIC_NUMBER,
        .version = 1,
        .type = type,
        .flags = 0,
        .payload_len = payload_len
    };

    uint8_t header_buf[HEADER_SIZE];
    serialize_header(&header, header_buf, HEADER_SIZE);

    if (socket_send_all(&sender->sock, header_buf, HEADER_SIZE) < 0)
        return -1;
    if (payload_len > 0 && socket_send_all(&sender->sock, payload, payload_len) < 0)
        return -1;

    return 0;
}

static int recv_message(Sender *sender, MessageHeader *header, uint8_t *payload, size_t payload_max)
{
    uint8_t header_buf[HEADER_SIZE];

    if (socket_recv_all(&sender->sock, header_buf, HEADER_SIZE) < 0)
        return -1;

    if (deserialize_header(header_buf, HEADER_SIZE, header) < 0)
        return -1;

    if (header->magic != MAGIC_NUMBER)
        return -1;

    if (header->payload_len > payload_max)
        return -1;

    if (header->payload_len > 0) {
        if (socket_recv_all(&sender->sock, payload, header->payload_len) < 0)
            return -1;
    }

    return 0;
}

static int send_encrypted(Sender *sender, uint8_t type, const uint8_t *payload, size_t payload_len)
{
    size_t encrypted_len = payload_len + CRYPTO_TAG_SIZE;
    uint8_t *encrypted = malloc(NONCE_SIZE + encrypted_len);
    if (!encrypted)
        return -1;

    uint8_t *nonce = encrypted;
    uint8_t *ciphertext = encrypted + NONCE_SIZE;

    MessageHeader header = {
        .magic = MAGIC_NUMBER,
        .version = 1,
        .type = type,
        .flags = 0,
        .payload_len = NONCE_SIZE + encrypted_len
    };

    uint8_t header_buf[HEADER_SIZE];
    serialize_header(&header, header_buf, HEADER_SIZE);

    size_t ciphertext_len;
    if (crypto_encrypt(&sender->session, ciphertext, &ciphertext_len,
                       payload, payload_len, header_buf, HEADER_SIZE, nonce) < 0) {
        free(encrypted);
        return -1;
    }

    if (socket_send_all(&sender->sock, header_buf, HEADER_SIZE) < 0) {
        free(encrypted);
        return -1;
    }

    if (socket_send_all(&sender->sock, encrypted, NONCE_SIZE + ciphertext_len) < 0) {
        free(encrypted);
        return -1;
    }

    free(encrypted);
    return 0;
}

static int recv_encrypted(Sender *sender, MessageHeader *header, uint8_t *payload, size_t payload_max)
{
    uint8_t header_buf[HEADER_SIZE];

    if (socket_recv_all(&sender->sock, header_buf, HEADER_SIZE) < 0)
        return -1;

    if (deserialize_header(header_buf, HEADER_SIZE, header) < 0)
        return -1;

    if (header->magic != MAGIC_NUMBER)
        return -1;

    if (header->payload_len < NONCE_SIZE + CRYPTO_TAG_SIZE)
        return -1;

    uint8_t *encrypted = malloc(header->payload_len);
    if (!encrypted)
        return -1;

    if (socket_recv_all(&sender->sock, encrypted, header->payload_len) < 0) {
        free(encrypted);
        return -1;
    }

    uint8_t *nonce = encrypted;
    uint8_t *ciphertext = encrypted + NONCE_SIZE;
    size_t ciphertext_len = header->payload_len - NONCE_SIZE;

    size_t decrypted_len;
    if (crypto_decrypt(&sender->session, payload, &decrypted_len,
                       ciphertext, ciphertext_len, header_buf, HEADER_SIZE, nonce) < 0) {
        free(encrypted);
        return -1;
    }

    header->payload_len = decrypted_len;
    free(encrypted);
    return 0;
}
