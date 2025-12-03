#ifndef RECEIVER_H
#define RECEIVER_H

#include <stdint.h>
#include "../network/socket.h"
#include "../crypto/crypto.h"
#include "../file/file.h"
#include "message.h"

typedef enum {
    RECEIVER_IDLE,
    RECEIVER_LISTENING,
    RECEIVER_HANDSHAKING,
    RECEIVER_READY,
    RECEIVER_RECEIVING,
    RECEIVER_VERIFYING,
    RECEIVER_DONE,
    RECEIVER_ERROR
} ReceiverState;

typedef struct {
    ReceiverState state;
    int server_fd;
    Socket sock;
    CryptoKeyPair keypair;
    CryptoSession session;
    FileWriter file;
    uint8_t client_id[CLIENT_ID_SIZE];
    uint8_t peer_id[CLIENT_ID_SIZE];
    char output_dir[MAX_FILENAME_LEN];
    char error_msg[256];
} Receiver;

int receiver_init(Receiver *receiver, const char *output_dir);
int receiver_listen(Receiver *receiver, uint16_t port);
int receiver_accept(Receiver *receiver);
int receiver_receive_file(Receiver *receiver);
void receiver_cleanup(Receiver *receiver);

const char *receiver_state_name(ReceiverState state);
const char *receiver_error(Receiver *receiver);

#endif /* RECEIVER_H */
