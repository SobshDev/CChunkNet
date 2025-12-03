#ifndef SENDER_H
#define SENDER_H

#include <stdint.h>
#include "../network/socket.h"
#include "../crypto/crypto.h"
#include "../file/file.h"
#include "message.h"

typedef enum {
    SENDER_IDLE,
    SENDER_CONNECTING,
    SENDER_KEY_EXCHANGE,
    SENDER_READY,
    SENDER_SENDING,
    SENDER_COMPLETING,
    SENDER_DONE,
    SENDER_ERROR
} SenderState;

typedef struct {
    SenderState state;
    Socket sock;
    CryptoKeyPair keypair;
    CryptoSession session;
    FileReader file;
    uint8_t client_id[CLIENT_ID_SIZE];
    uint8_t peer_id[CLIENT_ID_SIZE];
    uint32_t current_chunk;
    char error_msg[256];
} Sender;

int sender_init(Sender *sender);
int sender_connect(Sender *sender, const uint8_t addr[4], uint16_t port);
int sender_send_file(Sender *sender, const char *filepath);
void sender_cleanup(Sender *sender);

const char *sender_state_name(SenderState state);
const char *sender_error(Sender *sender);

#endif /* SENDER_H */
