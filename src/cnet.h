#ifndef CNET_H
#define CNET_H

typedef struct CNET_S {
    float protocol_version;
    unsigned short port;
    unsigned int chunk_size;
    unsigned int max_filename_len;
    unsigned int magic_number;
} CNET_T;


#endif // CNET_H