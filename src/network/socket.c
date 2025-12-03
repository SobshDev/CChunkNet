#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "socket.h"

int socket_listen(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return SOCKET_ERROR;

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(fd);
        return SOCKET_ERROR;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return SOCKET_ERROR;
    }

    if (listen(fd, 5) < 0) {
        close(fd);
        return SOCKET_ERROR;
    }

    return fd;
}

int socket_accept(int server_fd, Socket *client)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    int fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd < 0)
        return SOCKET_ERROR;

    client->fd = fd;
    uint32_t ip = ntohl(addr.sin_addr.s_addr);
    client->remote_addr[0] = (ip >> 24) & 0xFF;
    client->remote_addr[1] = (ip >> 16) & 0xFF;
    client->remote_addr[2] = (ip >> 8) & 0xFF;
    client->remote_addr[3] = ip & 0xFF;
    client->remote_port = ntohs(addr.sin_port);

    struct sockaddr_in local_addr;
    socklen_t local_len = sizeof(local_addr);
    if (getsockname(fd, (struct sockaddr *)&local_addr, &local_len) == 0)
        client->local_port = ntohs(local_addr.sin_port);

    return 0;
}

int socket_connect(const uint8_t addr[4], uint16_t port, Socket *sock)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return SOCKET_ERROR;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(
        ((uint32_t)addr[0] << 24) |
        ((uint32_t)addr[1] << 16) |
        ((uint32_t)addr[2] << 8) |
        (uint32_t)addr[3]
    );

    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(fd);
        return SOCKET_ERROR;
    }

    sock->fd = fd;
    memcpy(sock->remote_addr, addr, 4);
    sock->remote_port = port;

    struct sockaddr_in local_addr;
    socklen_t local_len = sizeof(local_addr);
    if (getsockname(fd, (struct sockaddr *)&local_addr, &local_len) == 0)
        sock->local_port = ntohs(local_addr.sin_port);

    return 0;
}

ssize_t socket_send(Socket *sock, const void *buf, size_t len)
{
    ssize_t sent = send(sock->fd, buf, len, 0);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return SOCKET_TIMEOUT;
        if (errno == EPIPE || errno == ECONNRESET)
            return SOCKET_CLOSED;
        return SOCKET_ERROR;
    }
    return sent;
}

ssize_t socket_recv(Socket *sock, void *buf, size_t len)
{
    ssize_t received = recv(sock->fd, buf, len, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return SOCKET_TIMEOUT;
        if (errno == ECONNRESET)
            return SOCKET_CLOSED;
        return SOCKET_ERROR;
    }
    if (received == 0)
        return SOCKET_CLOSED;
    return received;
}

ssize_t socket_send_all(Socket *sock, const void *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t sent = socket_send(sock, ptr, remaining);
        if (sent < 0)
            return sent;
        ptr += sent;
        remaining -= sent;
    }
    return (ssize_t)len;
}

ssize_t socket_recv_all(Socket *sock, void *buf, size_t len)
{
    uint8_t *ptr = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t received = socket_recv(sock, ptr, remaining);
        if (received < 0)
            return received;
        ptr += received;
        remaining -= received;
    }
    return (ssize_t)len;
}

int socket_set_timeout(Socket *sock, int timeout_ms)
{
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return SOCKET_ERROR;
    if (setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
        return SOCKET_ERROR;

    return 0;
}

int socket_set_nonblocking(Socket *sock, int nonblocking)
{
    int flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags < 0)
        return SOCKET_ERROR;

    if (nonblocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(sock->fd, F_SETFL, flags) < 0)
        return SOCKET_ERROR;

    return 0;
}

void socket_close(Socket *sock)
{
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
}

void socket_close_fd(int fd)
{
    if (fd >= 0)
        close(fd);
}
