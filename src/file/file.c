#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sodium.h>
#include "file.h"

int file_reader_open(FileReader *reader, const char *path, uint32_t chunk_size)
{
    memset(reader, 0, sizeof(*reader));

    reader->fd = open(path, O_RDONLY);
    if (reader->fd < 0)
        return -1;

    struct stat st;
    if (fstat(reader->fd, &st) < 0) {
        close(reader->fd);
        reader->fd = -1;
        return -1;
    }

    reader->file_size = st.st_size;
    reader->chunk_size = chunk_size;
    reader->total_chunks = (reader->file_size + chunk_size - 1) / chunk_size;
    if (reader->file_size == 0)
        reader->total_chunks = 0;

    const char *basename = file_basename(path);
    size_t name_len = strlen(basename);
    if (name_len >= MAX_FILENAME_LEN)
        name_len = MAX_FILENAME_LEN - 1;
    memcpy(reader->filename, basename, name_len);
    reader->filename[name_len] = '\0';

    if (file_compute_hash(path, reader->file_hash) < 0) {
        close(reader->fd);
        reader->fd = -1;
        return -1;
    }

    return 0;
}

int file_reader_read_chunk(FileReader *reader, uint32_t chunk_index,
                           uint8_t *buffer, uint32_t *chunk_len,
                           uint8_t hash[CRYPTO_HASH_SIZE])
{
    if (chunk_index >= reader->total_chunks)
        return -1;

    off_t offset = (off_t)chunk_index * reader->chunk_size;
    if (lseek(reader->fd, offset, SEEK_SET) < 0)
        return -1;

    uint32_t remaining = reader->file_size - offset;
    uint32_t to_read = remaining < reader->chunk_size ? remaining : reader->chunk_size;

    ssize_t bytes_read = 0;
    uint32_t total_read = 0;
    while (total_read < to_read) {
        bytes_read = read(reader->fd, buffer + total_read, to_read - total_read);
        if (bytes_read <= 0)
            return -1;
        total_read += bytes_read;
    }

    *chunk_len = total_read;
    crypto_sha256(hash, buffer, total_read);

    return 0;
}

void file_reader_close(FileReader *reader)
{
    if (reader->fd >= 0) {
        close(reader->fd);
        reader->fd = -1;
    }
}

int file_writer_create(FileWriter *writer, const char *dir, const char *filename,
                       uint64_t file_size, uint32_t chunk_size,
                       const uint8_t expected_hash[CRYPTO_HASH_SIZE])
{
    memset(writer, 0, sizeof(*writer));

    size_t dir_len = dir ? strlen(dir) : 0;
    size_t name_len = strlen(filename);

    if (dir_len + name_len + 2 >= MAX_FILENAME_LEN)
        return -1;

    if (dir && dir_len > 0) {
        snprintf(writer->filepath, MAX_FILENAME_LEN, "%s/%s", dir, filename);
    } else {
        strncpy(writer->filepath, filename, MAX_FILENAME_LEN - 1);
    }

    writer->fd = open(writer->filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (writer->fd < 0)
        return -1;

    if (file_size > 0 && ftruncate(writer->fd, file_size) < 0) {
        close(writer->fd);
        writer->fd = -1;
        return -1;
    }

    writer->file_size = file_size;
    writer->chunk_size = chunk_size;
    writer->total_chunks = (file_size + chunk_size - 1) / chunk_size;
    if (file_size == 0)
        writer->total_chunks = 0;
    writer->chunks_written = 0;
    memcpy(writer->expected_hash, expected_hash, CRYPTO_HASH_SIZE);

    return 0;
}

int file_writer_write_chunk(FileWriter *writer, uint32_t chunk_index,
                            const uint8_t *data, uint32_t data_len,
                            const uint8_t expected_hash[CRYPTO_HASH_SIZE])
{
    if (chunk_index >= writer->total_chunks)
        return -1;

    uint8_t computed_hash[CRYPTO_HASH_SIZE];
    crypto_sha256(computed_hash, data, data_len);

    if (memcmp(computed_hash, expected_hash, CRYPTO_HASH_SIZE) != 0)
        return -2;

    off_t offset = (off_t)chunk_index * writer->chunk_size;
    if (lseek(writer->fd, offset, SEEK_SET) < 0)
        return -1;

    ssize_t written = 0;
    uint32_t total_written = 0;
    while (total_written < data_len) {
        written = write(writer->fd, data + total_written, data_len - total_written);
        if (written <= 0)
            return -1;
        total_written += written;
    }

    writer->chunks_written++;
    return 0;
}

int file_writer_verify(FileWriter *writer)
{
    if (writer->chunks_written != writer->total_chunks)
        return -1;

    fsync(writer->fd);

    uint8_t computed_hash[CRYPTO_HASH_SIZE];
    if (file_compute_hash(writer->filepath, computed_hash) < 0)
        return -1;

    if (memcmp(computed_hash, writer->expected_hash, CRYPTO_HASH_SIZE) != 0)
        return -2;

    return 0;
}

void file_writer_close(FileWriter *writer)
{
    if (writer->fd >= 0) {
        close(writer->fd);
        writer->fd = -1;
    }
}

int file_compute_hash(const char *path, uint8_t hash[CRYPTO_HASH_SIZE])
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    uint8_t buffer[65536];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        crypto_hash_sha256_update(&state, buffer, bytes_read);
    }

    close(fd);

    if (bytes_read < 0)
        return -1;

    crypto_hash_sha256_final(&state, hash);
    return 0;
}

int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

uint64_t file_get_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0)
        return 0;
    return st.st_size;
}

const char *file_basename(const char *path)
{
    const char *last_slash = strrchr(path, '/');
    if (last_slash)
        return last_slash + 1;
    return path;
}
