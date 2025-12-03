#ifndef FILE_H
#define FILE_H

#include <stdint.h>
#include <stddef.h>
#include "../const.h"
#include "../crypto/crypto.h"

typedef struct {
    int fd;
    uint64_t file_size;
    uint32_t chunk_size;
    uint32_t total_chunks;
    uint8_t file_hash[CRYPTO_HASH_SIZE];
    char filename[MAX_FILENAME_LEN];
} FileReader;

typedef struct {
    int fd;
    uint64_t file_size;
    uint32_t chunk_size;
    uint32_t total_chunks;
    uint32_t chunks_written;
    uint8_t expected_hash[CRYPTO_HASH_SIZE];
    char filepath[MAX_FILENAME_LEN];
} FileWriter;

/* FileReader operations (sender side) */
int file_reader_open(FileReader *reader, const char *path, uint32_t chunk_size);
int file_reader_read_chunk(FileReader *reader, uint32_t chunk_index,
                           uint8_t *buffer, uint32_t *chunk_len,
                           uint8_t hash[CRYPTO_HASH_SIZE]);
void file_reader_close(FileReader *reader);

/* FileWriter operations (receiver side) */
int file_writer_create(FileWriter *writer, const char *dir, const char *filename,
                       uint64_t file_size, uint32_t chunk_size,
                       const uint8_t expected_hash[CRYPTO_HASH_SIZE]);
int file_writer_write_chunk(FileWriter *writer, uint32_t chunk_index,
                            const uint8_t *data, uint32_t data_len,
                            const uint8_t expected_hash[CRYPTO_HASH_SIZE]);
int file_writer_verify(FileWriter *writer);
void file_writer_close(FileWriter *writer);

/* Utility functions */
int file_compute_hash(const char *path, uint8_t hash[CRYPTO_HASH_SIZE]);
int file_exists(const char *path);
uint64_t file_get_size(const char *path);
const char *file_basename(const char *path);

#endif /* FILE_H */
