#include <string.h>
#include "message.h"

static inline void write_u16_le(uint8_t *buf, uint16_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
}

static inline void write_u32_le(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

static inline void write_u64_le(uint8_t *buf, uint64_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    buf[4] = (uint8_t)((val >> 32) & 0xFF);
    buf[5] = (uint8_t)((val >> 40) & 0xFF);
    buf[6] = (uint8_t)((val >> 48) & 0xFF);
    buf[7] = (uint8_t)((val >> 56) & 0xFF);
}

static inline uint16_t read_u16_le(const uint8_t *buf)
{
    return (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
}

static inline uint32_t read_u32_le(const uint8_t *buf)
{
    return (uint32_t)buf[0] |
           ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[3] << 24);
}

static inline uint64_t read_u64_le(const uint8_t *buf)
{
    return (uint64_t)buf[0] |
           ((uint64_t)buf[1] << 8) |
           ((uint64_t)buf[2] << 16) |
           ((uint64_t)buf[3] << 24) |
           ((uint64_t)buf[4] << 32) |
           ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) |
           ((uint64_t)buf[7] << 56);
}

size_t serialize_header(const MessageHeader *header, uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < HEADER_SIZE)
        return 0;

    write_u32_le(buffer, header->magic);
    buffer[4] = header->version;
    buffer[5] = header->type;
    write_u16_le(buffer + 6, header->flags);
    write_u32_le(buffer + 8, header->payload_len);

    return HEADER_SIZE;
}

int deserialize_header(const uint8_t *buffer, size_t buffer_size, MessageHeader *header)
{
    if (buffer_size < HEADER_SIZE)
        return -1;

    header->magic = read_u32_le(buffer);
    header->version = buffer[4];
    header->type = buffer[5];
    header->flags = read_u16_le(buffer + 6);
    header->payload_len = read_u32_le(buffer + 8);

    return 0;
}

size_t serialize_hello(const HelloPayload *payload, uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < HELLO_PAYLOAD_SIZE)
        return 0;

    buffer[0] = payload->min_version;
    buffer[1] = payload->max_version;
    write_u16_le(buffer + 2, payload->capabilities);
    memcpy(buffer + 4, payload->client_id, CLIENT_ID_SIZE);

    return HELLO_PAYLOAD_SIZE;
}

int deserialize_hello(const uint8_t *buffer, size_t buffer_size, HelloPayload *payload)
{
    if (buffer_size < HELLO_PAYLOAD_SIZE)
        return -1;

    payload->min_version = buffer[0];
    payload->max_version = buffer[1];
    payload->capabilities = read_u16_le(buffer + 2);
    memcpy(payload->client_id, buffer + 4, CLIENT_ID_SIZE);

    return 0;
}

size_t serialize_key_exchange(const KeyExchangePayload *payload, uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < KEY_EXCHANGE_PAYLOAD_SIZE)
        return 0;

    buffer[0] = payload->cipher;
    buffer[1] = payload->reserved;
    write_u16_le(buffer + 2, payload->key_length);
    memcpy(buffer + 4, payload->public_key, PUBLIC_KEY_SIZE);

    return KEY_EXCHANGE_PAYLOAD_SIZE;
}

int deserialize_key_exchange(const uint8_t *buffer, size_t buffer_size, KeyExchangePayload *payload)
{
    if (buffer_size < KEY_EXCHANGE_PAYLOAD_SIZE)
        return -1;

    payload->cipher = buffer[0];
    payload->reserved = buffer[1];
    payload->key_length = read_u16_le(buffer + 2);
    memcpy(payload->public_key, buffer + 4, PUBLIC_KEY_SIZE);

    return 0;
}

size_t serialize_file_info(const FileInfoPayload *payload, uint8_t *buffer, size_t buffer_size)
{
    size_t total_size = FILE_INFO_FIXED_SIZE + payload->filename_length;

    if (buffer_size < total_size)
        return 0;

    write_u64_le(buffer, payload->file_size);
    write_u32_le(buffer + 8, payload->chunk_size);
    write_u32_le(buffer + 12, payload->total_chunks);
    write_u16_le(buffer + 16, payload->filename_length);
    buffer[18] = payload->reserved;
    memcpy(buffer + 19, payload->file_hash, HASH_SIZE);
    memcpy(buffer + 51, payload->filename, payload->filename_length);

    return total_size;
}

int deserialize_file_info(const uint8_t *buffer, size_t buffer_size, FileInfoPayload *payload,
                          char *filename_out, size_t filename_buf_size)
{
    if (buffer_size < FILE_INFO_FIXED_SIZE)
        return -1;

    payload->file_size = read_u64_le(buffer);
    payload->chunk_size = read_u32_le(buffer + 8);
    payload->total_chunks = read_u32_le(buffer + 12);
    payload->filename_length = read_u16_le(buffer + 16);
    payload->reserved = buffer[18];
    memcpy(payload->file_hash, buffer + 19, HASH_SIZE);

    if (buffer_size < FILE_INFO_FIXED_SIZE + payload->filename_length)
        return -1;
    if (filename_buf_size < payload->filename_length + 1)
        return -1;

    memcpy(filename_out, buffer + 51, payload->filename_length);
    filename_out[payload->filename_length] = '\0';

    return 0;
}

size_t serialize_file_info_ack(const FileInfoAckPayload *payload, uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < FILE_INFO_ACK_PAYLOAD_SIZE)
        return 0;

    buffer[0] = payload->status;
    buffer[1] = payload->reserved[0];
    buffer[2] = payload->reserved[1];
    buffer[3] = payload->reserved[2];
    write_u32_le(buffer + 4, payload->resume_from);

    return FILE_INFO_ACK_PAYLOAD_SIZE;
}

int deserialize_file_info_ack(const uint8_t *buffer, size_t buffer_size, FileInfoAckPayload *payload)
{
    if (buffer_size < FILE_INFO_ACK_PAYLOAD_SIZE)
        return -1;

    payload->status = buffer[0];
    payload->reserved[0] = buffer[1];
    payload->reserved[1] = buffer[2];
    payload->reserved[2] = buffer[3];
    payload->resume_from = read_u32_le(buffer + 4);

    return 0;
}

size_t serialize_chunk(const ChunkPayload *payload, const uint8_t *data, uint32_t data_size,
                       uint8_t *buffer, size_t buffer_size)
{
    size_t total_size = CHUNK_FIXED_SIZE + data_size;

    if (buffer_size < total_size)
        return 0;

    write_u32_le(buffer, payload->chunk_index);
    write_u32_le(buffer + 4, payload->chunk_size);
    memcpy(buffer + 8, payload->chunk_hash, HASH_SIZE);
    memcpy(buffer + 40, data, data_size);

    return total_size;
}

int deserialize_chunk(const uint8_t *buffer, size_t buffer_size, ChunkPayload *payload,
                      uint8_t *data_out, size_t data_buf_size)
{
    if (buffer_size < CHUNK_FIXED_SIZE)
        return -1;

    payload->chunk_index = read_u32_le(buffer);
    payload->chunk_size = read_u32_le(buffer + 4);
    memcpy(payload->chunk_hash, buffer + 8, HASH_SIZE);

    if (buffer_size < CHUNK_FIXED_SIZE + payload->chunk_size)
        return -1;
    if (data_buf_size < payload->chunk_size)
        return -1;

    memcpy(data_out, buffer + 40, payload->chunk_size);

    return 0;
}

size_t serialize_chunk_ack(const ChunkAckPayload *payload, uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < CHUNK_ACK_PAYLOAD_SIZE)
        return 0;

    write_u32_le(buffer, payload->chunk_index);
    buffer[4] = payload->status;
    buffer[5] = payload->reserved[0];
    buffer[6] = payload->reserved[1];
    buffer[7] = payload->reserved[2];

    return CHUNK_ACK_PAYLOAD_SIZE;
}

int deserialize_chunk_ack(const uint8_t *buffer, size_t buffer_size, ChunkAckPayload *payload)
{
    if (buffer_size < CHUNK_ACK_PAYLOAD_SIZE)
        return -1;

    payload->chunk_index = read_u32_le(buffer);
    payload->status = buffer[4];
    payload->reserved[0] = buffer[5];
    payload->reserved[1] = buffer[6];
    payload->reserved[2] = buffer[7];

    return 0;
}

size_t serialize_transfer_complete(const TransferCompletePayload *payload, uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < TRANSFER_COMPLETE_PAYLOAD_SIZE)
        return 0;

    write_u32_le(buffer, payload->total_chunks_sent);
    write_u64_le(buffer + 4, payload->total_bytes_sent);

    return TRANSFER_COMPLETE_PAYLOAD_SIZE;
}

int deserialize_transfer_complete(const uint8_t *buffer, size_t buffer_size, TransferCompletePayload *payload)
{
    if (buffer_size < TRANSFER_COMPLETE_PAYLOAD_SIZE)
        return -1;

    payload->total_chunks_sent = read_u32_le(buffer);
    payload->total_bytes_sent = read_u64_le(buffer + 4);

    return 0;
}

size_t serialize_transfer_verified(const TransferVerifiedPayload *payload, uint8_t *buffer, size_t buffer_size)
{
    if (buffer_size < TRANSFER_VERIFIED_PAYLOAD_SIZE)
        return 0;

    buffer[0] = payload->status;
    buffer[1] = payload->reserved[0];
    buffer[2] = payload->reserved[1];
    buffer[3] = payload->reserved[2];

    return TRANSFER_VERIFIED_PAYLOAD_SIZE;
}

int deserialize_transfer_verified(const uint8_t *buffer, size_t buffer_size, TransferVerifiedPayload *payload)
{
    if (buffer_size < TRANSFER_VERIFIED_PAYLOAD_SIZE)
        return -1;

    payload->status = buffer[0];
    payload->reserved[0] = buffer[1];
    payload->reserved[1] = buffer[2];
    payload->reserved[2] = buffer[3];

    return 0;
}

size_t serialize_error(const ErrorPayload *payload, uint8_t *buffer, size_t buffer_size)
{
    size_t total_size = ERROR_FIXED_SIZE + payload->message_length;

    if (buffer_size < total_size)
        return 0;

    buffer[0] = payload->error_code;
    buffer[1] = payload->error_level;
    write_u16_le(buffer + 2, payload->message_length);
    memcpy(buffer + 4, payload->message, payload->message_length);

    return total_size;
}

int deserialize_error(const uint8_t *buffer, size_t buffer_size, ErrorPayload *payload,
                      char *message_out, size_t message_buf_size)
{
    if (buffer_size < ERROR_FIXED_SIZE)
        return -1;

    payload->error_code = buffer[0];
    payload->error_level = buffer[1];
    payload->message_length = read_u16_le(buffer + 2);

    if (buffer_size < ERROR_FIXED_SIZE + payload->message_length)
        return -1;
    if (message_buf_size < payload->message_length + 1)
        return -1;

    memcpy(message_out, buffer + 4, payload->message_length);
    message_out[payload->message_length] = '\0';

    return 0;
}
