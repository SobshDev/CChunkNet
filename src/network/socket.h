#ifndef SOCKET_H
#define SOCKET_H

#include <stddef.h>
#include <stdint.h>

#define SOCKET_ERROR -1
#define SOCKET_TIMEOUT -2
#define SOCKET_CLOSED -3

typedef struct {
    int fd;
    uint8_t remote_addr[4];
    uint16_t remote_port;
    uint16_t local_port;
} Socket;

/* Server operations */
int socket_listen(uint16_t port);
int socket_accept(int server_fd, Socket *client);

/* Client operations */
int socket_connect(const uint8_t addr[4], uint16_t port, Socket *sock);

/* Data transfer */
ssize_t socket_send(Socket *sock, const void *buf, size_t len);
ssize_t socket_recv(Socket *sock, void *buf, size_t len);
ssize_t socket_send_all(Socket *sock, const void *buf, size_t len);
ssize_t socket_recv_all(Socket *sock, void *buf, size_t len);

/* Configuration */
int socket_set_timeout(Socket *sock, int timeout_ms);
int socket_set_nonblocking(Socket *sock, int nonblocking);

/* Cleanup */
void socket_close(Socket *sock);
void socket_close_fd(int fd);

#endif /* SOCKET_H */
