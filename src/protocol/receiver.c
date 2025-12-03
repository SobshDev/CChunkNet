#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "receiver.h"
#include "../const.h"

static int send_message(Receiver *receiver, uint8_t type, const uint8_t *payload, size_t payload_len);
static int recv_message(Receiver *receiver, MessageHeader *header, uint8_t *payload, size_t payload_max);
static int send_encrypted(Receiver *receiver, uint8_t type, const uint8_t *payload, size_t payload_len);
static int recv_encrypted(Receiver *receiver, MessageHeader *header, uint8_t *payload, size_t payload_max);

static void set_error(Receiver *receiver, const char *msg)
{
    strncpy(receiver->error_msg, msg, sizeof(receiver->error_msg) - 1);
    receiver->state = RECEIVER_ERROR;
}

int receiver_init(Receiver *receiver, const char *output_dir)
{
    memset(receiver, 0, sizeof(*receiver));
    receiver->state = RECEIVER_IDLE;
    receiver->server_fd = -1;
    receiver->sock.fd = -1;

    if (crypto_init() < 0) {
        set_error(receiver, "Failed to initialize crypto");
        return -1;
    }

    crypto_generate_keypair(&receiver->keypair);
    crypto_random_bytes(receiver->client_id, CLIENT_ID_SIZE);

    if (output_dir) {
        strncpy(receiver->output_dir, output_dir, MAX_FILENAME_LEN - 1);
    } else {
        strcpy(receiver->output_dir, ".");
    }

    return 0;
}

int receiver_listen(Receiver *receiver, uint16_t port)
{
    if (receiver->state != RECEIVER_IDLE) {
        set_error(receiver, "Invalid state for listen");
        return -1;
    }

    receiver->server_fd = socket_listen(port);
    if (receiver->server_fd < 0) {
        set_error(receiver, "Failed to listen on port");
        return -1;
    }

    receiver->state = RECEIVER_LISTENING;
    return 0;
}

int receiver_accept(Receiver *receiver)
{
    if (receiver->state != RECEIVER_LISTENING) {
        set_error(receiver, "Not listening");
        return -1;
    }

    if (socket_accept(receiver->server_fd, &receiver->sock) < 0) {
        set_error(receiver, "Failed to accept connection");
        return -1;
    }

    socket_set_timeout(&receiver->sock, 30000);
    receiver->state = RECEIVER_HANDSHAKING;

    MessageHeader header;
    uint8_t payload[256];

    if (recv_message(receiver, &header, payload, sizeof(payload)) < 0) {
        set_error(receiver, "Failed to receive HELLO");
        return -1;
    }

    if (header.type != MSG_HELLO) {
        set_error(receiver, "Expected HELLO");
        return -1;
    }

    HelloPayload hello;
    if (deserialize_hello(payload, header.payload_len, &hello) < 0) {
        set_error(receiver, "Invalid HELLO");
        return -1;
    }
    memcpy(receiver->peer_id, hello.client_id, CLIENT_ID_SIZE);

    HelloPayload hello_ack = {
        .min_version = 1,
        .max_version = 1,
        .capabilities = CAP_CHACHA20 | CAP_AES_GCM
    };
    memcpy(hello_ack.client_id, receiver->client_id, CLIENT_ID_SIZE);

    uint8_t hello_buf[HELLO_PAYLOAD_SIZE];
    serialize_hello(&hello_ack, hello_buf, sizeof(hello_buf));

    if (send_message(receiver, MSG_HELLO_ACK, hello_buf, HELLO_PAYLOAD_SIZE) < 0) {
        set_error(receiver, "Failed to send HELLO_ACK");
        return -1;
    }

    if (recv_message(receiver, &header, payload, sizeof(payload)) < 0) {
        set_error(receiver, "Failed to receive KEY_EXCHANGE");
        return -1;
    }

    if (header.type != MSG_KEY_EXCHANGE) {
        set_error(receiver, "Expected KEY_EXCHANGE");
        return -1;
    }

    KeyExchangePayload kex;
    if (deserialize_key_exchange(payload, header.payload_len, &kex) < 0) {
        set_error(receiver, "Invalid KEY_EXCHANGE");
        return -1;
    }

    CryptoCipher cipher = kex.cipher;

    KeyExchangePayload kex_ack = {
        .cipher = cipher,
        .reserved = 0,
        .key_length = PUBLIC_KEY_SIZE
    };
    memcpy(kex_ack.public_key, receiver->keypair.public_key, PUBLIC_KEY_SIZE);

    uint8_t kex_buf[KEY_EXCHANGE_PAYLOAD_SIZE];
    serialize_key_exchange(&kex_ack, kex_buf, sizeof(kex_buf));

    if (send_message(receiver, MSG_KEY_EXCHANGE_ACK, kex_buf, KEY_EXCHANGE_PAYLOAD_SIZE) < 0) {
        set_error(receiver, "Failed to send KEY_EXCHANGE_ACK");
        return -1;
    }

    uint8_t shared_secret[CRYPTO_KEY_SIZE];
    if (crypto_key_exchange(shared_secret, receiver->keypair.secret_key, kex.public_key) < 0) {
        set_error(receiver, "Key exchange failed");
        return -1;
    }

    crypto_derive_session_key(&receiver->session, shared_secret,
                              receiver->peer_id, receiver->client_id,
                              CLIENT_ID_SIZE, cipher);
    crypto_zero(shared_secret, sizeof(shared_secret));

    receiver->state = RECEIVER_READY;
    return 0;
}

int receiver_receive_file(Receiver *receiver)
{
    if (receiver->state != RECEIVER_READY) {
        set_error(receiver, "Not ready to receive file");
        return -1;
    }

    receiver->state = RECEIVER_RECEIVING;

    MessageHeader header;
    uint8_t *payload = malloc(CHUNK_SIZE + 256);
    if (!payload) {
        set_error(receiver, "Memory allocation failed");
        return -1;
    }

    if (recv_encrypted(receiver, &header, payload, CHUNK_SIZE + 256) < 0) {
        free(payload);
        set_error(receiver, "Failed to receive FILE_INFO");
        return -1;
    }

    if (header.type != MSG_FILE_INFO) {
        free(payload);
        set_error(receiver, "Expected FILE_INFO");
        return -1;
    }

    FileInfoPayload file_info;
    char filename[MAX_FILENAME_LEN];
    if (deserialize_file_info(payload, header.payload_len, &file_info, filename, sizeof(filename)) < 0) {
        free(payload);
        set_error(receiver, "Invalid FILE_INFO");
        return -1;
    }

    if (file_writer_create(&receiver->file, receiver->output_dir, filename,
                           file_info.file_size, file_info.chunk_size, file_info.file_hash) < 0) {
        free(payload);
        set_error(receiver, "Failed to create output file");
        return -1;
    }

    FileInfoAckPayload info_ack = {
        .status = FILE_STATUS_ACCEPT,
        .reserved = {0, 0, 0},
        .resume_from = 0
    };

    uint8_t ack_buf[FILE_INFO_ACK_PAYLOAD_SIZE];
    serialize_file_info_ack(&info_ack, ack_buf, sizeof(ack_buf));

    if (send_encrypted(receiver, MSG_FILE_INFO_ACK, ack_buf, FILE_INFO_ACK_PAYLOAD_SIZE) < 0) {
        free(payload);
        set_error(receiver, "Failed to send FILE_INFO_ACK");
        return -1;
    }

    uint8_t *chunk_data = malloc(CHUNK_SIZE);
    if (!chunk_data) {
        free(payload);
        set_error(receiver, "Memory allocation failed");
        return -1;
    }

    uint32_t chunks_received = 0;
    while (chunks_received < receiver->file.total_chunks) {
        if (recv_encrypted(receiver, &header, payload, CHUNK_SIZE + 256) < 0) {
            free(payload);
            free(chunk_data);
            set_error(receiver, "Failed to receive chunk");
            return -1;
        }

        if (header.type != MSG_CHUNK) {
            free(payload);
            free(chunk_data);
            set_error(receiver, "Expected CHUNK");
            return -1;
        }

        ChunkPayload chunk;
        if (deserialize_chunk(payload, header.payload_len, &chunk, chunk_data, CHUNK_SIZE) < 0) {
            free(payload);
            free(chunk_data);
            set_error(receiver, "Invalid CHUNK");
            return -1;
        }

        int write_result = file_writer_write_chunk(&receiver->file, chunk.chunk_index,
                                                    chunk_data, chunk.chunk_size, chunk.chunk_hash);

        ChunkAckPayload chunk_ack = {
            .chunk_index = chunk.chunk_index,
            .status = (write_result == 0) ? CHUNK_STATUS_OK :
                      (write_result == -2) ? CHUNK_STATUS_HASH_MISMATCH : CHUNK_STATUS_OUT_OF_ORDER,
            .reserved = {0, 0, 0}
        };

        uint8_t chunk_ack_buf[CHUNK_ACK_PAYLOAD_SIZE];
        serialize_chunk_ack(&chunk_ack, chunk_ack_buf, sizeof(chunk_ack_buf));

        if (send_encrypted(receiver, MSG_CHUNK_ACK, chunk_ack_buf, CHUNK_ACK_PAYLOAD_SIZE) < 0) {
            free(payload);
            free(chunk_data);
            set_error(receiver, "Failed to send CHUNK_ACK");
            return -1;
        }

        if (write_result != 0) {
            free(payload);
            free(chunk_data);
            set_error(receiver, "Chunk write failed");
            return -1;
        }

        chunks_received++;
    }

    free(chunk_data);

    receiver->state = RECEIVER_VERIFYING;

    if (recv_encrypted(receiver, &header, payload, CHUNK_SIZE + 256) < 0) {
        free(payload);
        set_error(receiver, "Failed to receive TRANSFER_COMPLETE");
        return -1;
    }

    if (header.type != MSG_TRANSFER_COMPLETE) {
        free(payload);
        set_error(receiver, "Expected TRANSFER_COMPLETE");
        return -1;
    }

    int verify_result = file_writer_verify(&receiver->file);

    TransferVerifiedPayload verified = {
        .status = (verify_result == 0) ? 0 : 1,
        .reserved = {0, 0, 0}
    };

    uint8_t verified_buf[TRANSFER_VERIFIED_PAYLOAD_SIZE];
    serialize_transfer_verified(&verified, verified_buf, sizeof(verified_buf));

    if (send_encrypted(receiver, MSG_TRANSFER_VERIFIED, verified_buf, TRANSFER_VERIFIED_PAYLOAD_SIZE) < 0) {
        free(payload);
        set_error(receiver, "Failed to send TRANSFER_VERIFIED");
        return -1;
    }

    free(payload);

    if (verify_result != 0) {
        set_error(receiver, "File verification failed");
        return -1;
    }

    receiver->state = RECEIVER_DONE;
    return 0;
}

void receiver_cleanup(Receiver *receiver)
{
    file_writer_close(&receiver->file);
    socket_close(&receiver->sock);
    if (receiver->server_fd >= 0) {
        socket_close_fd(receiver->server_fd);
        receiver->server_fd = -1;
    }
    crypto_zero(&receiver->keypair, sizeof(receiver->keypair));
    crypto_zero(&receiver->session, sizeof(receiver->session));
}

const char *receiver_state_name(ReceiverState state)
{
    switch (state) {
        case RECEIVER_IDLE: return "IDLE";
        case RECEIVER_LISTENING: return "LISTENING";
        case RECEIVER_HANDSHAKING: return "HANDSHAKING";
        case RECEIVER_READY: return "READY";
        case RECEIVER_RECEIVING: return "RECEIVING";
        case RECEIVER_VERIFYING: return "VERIFYING";
        case RECEIVER_DONE: return "DONE";
        case RECEIVER_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

const char *receiver_error(Receiver *receiver)
{
    return receiver->error_msg;
}

static int send_message(Receiver *receiver, uint8_t type, const uint8_t *payload, size_t payload_len)
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

    if (socket_send_all(&receiver->sock, header_buf, HEADER_SIZE) < 0)
        return -1;
    if (payload_len > 0 && socket_send_all(&receiver->sock, payload, payload_len) < 0)
        return -1;

    return 0;
}

static int recv_message(Receiver *receiver, MessageHeader *header, uint8_t *payload, size_t payload_max)
{
    uint8_t header_buf[HEADER_SIZE];

    if (socket_recv_all(&receiver->sock, header_buf, HEADER_SIZE) < 0)
        return -1;

    if (deserialize_header(header_buf, HEADER_SIZE, header) < 0)
        return -1;

    if (header->magic != MAGIC_NUMBER)
        return -1;

    if (header->payload_len > payload_max)
        return -1;

    if (header->payload_len > 0) {
        if (socket_recv_all(&receiver->sock, payload, header->payload_len) < 0)
            return -1;
    }

    return 0;
}

static int send_encrypted(Receiver *receiver, uint8_t type, const uint8_t *payload, size_t payload_len)
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
    if (crypto_encrypt(&receiver->session, ciphertext, &ciphertext_len,
                       payload, payload_len, header_buf, HEADER_SIZE, nonce) < 0) {
        free(encrypted);
        return -1;
    }

    if (socket_send_all(&receiver->sock, header_buf, HEADER_SIZE) < 0) {
        free(encrypted);
        return -1;
    }

    if (socket_send_all(&receiver->sock, encrypted, NONCE_SIZE + ciphertext_len) < 0) {
        free(encrypted);
        return -1;
    }

    free(encrypted);
    return 0;
}

static int recv_encrypted(Receiver *receiver, MessageHeader *header, uint8_t *payload, size_t payload_max)
{
    (void)payload_max;
    uint8_t header_buf[HEADER_SIZE];

    if (socket_recv_all(&receiver->sock, header_buf, HEADER_SIZE) < 0)
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

    if (socket_recv_all(&receiver->sock, encrypted, header->payload_len) < 0) {
        free(encrypted);
        return -1;
    }

    uint8_t *nonce = encrypted;
    uint8_t *ciphertext = encrypted + NONCE_SIZE;
    size_t ciphertext_len = header->payload_len - NONCE_SIZE;

    size_t decrypted_len;
    if (crypto_decrypt(&receiver->session, payload, &decrypted_len,
                       ciphertext, ciphertext_len, header_buf, HEADER_SIZE, nonce) < 0) {
        free(encrypted);
        return -1;
    }

    header->payload_len = decrypted_len;
    free(encrypted);
    return 0;
}
