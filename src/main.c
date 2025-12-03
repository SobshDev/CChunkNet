#include <stdio.h>
#include <stdlib.h>
#include "cli/cli.h"
#include "protocol/sender.h"
#include "protocol/receiver.h"
#include "const.h"

static int run_sender(CLI_T *cli)
{
    Sender sender;

    printf("Initializing sender...\n");
    if (sender_init(&sender) < 0) {
        fprintf(stderr, "Error: %s\n", sender_error(&sender));
        return 1;
    }

    printf("Connecting to %d.%d.%d.%d:%d...\n",
           cli->address[0], cli->address[1], cli->address[2], cli->address[3], cli->port);

    if (sender_connect(&sender, cli->address, cli->port) < 0) {
        fprintf(stderr, "Error: %s\n", sender_error(&sender));
        sender_cleanup(&sender);
        return 1;
    }

    printf("Connected. Sending file: %s\n", cli->path);

    if (sender_send_file(&sender, cli->path) < 0) {
        fprintf(stderr, "Error: %s\n", sender_error(&sender));
        sender_cleanup(&sender);
        return 1;
    }

    printf("File sent successfully!\n");
    sender_cleanup(&sender);
    return 0;
}

static int run_receiver(CLI_T *cli)
{
    Receiver receiver;

    printf("Initializing receiver...\n");
    if (receiver_init(&receiver, ".") < 0) {
        fprintf(stderr, "Error: %s\n", receiver_error(&receiver));
        return 1;
    }

    printf("Listening on port %d...\n", cli->port);

    if (receiver_listen(&receiver, cli->port) < 0) {
        fprintf(stderr, "Error: %s\n", receiver_error(&receiver));
        receiver_cleanup(&receiver);
        return 1;
    }

    printf("Waiting for connection...\n");

    if (receiver_accept(&receiver) < 0) {
        fprintf(stderr, "Error: %s\n", receiver_error(&receiver));
        receiver_cleanup(&receiver);
        return 1;
    }

    printf("Connection accepted. Receiving file...\n");

    if (receiver_receive_file(&receiver) < 0) {
        fprintf(stderr, "Error: %s\n", receiver_error(&receiver));
        receiver_cleanup(&receiver);
        return 1;
    }

    printf("File received and verified successfully!\n");
    receiver_cleanup(&receiver);
    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s send <ip> <file> [--port <port>]\n", prog);
    printf("  %s receive [--port <port>]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --port <port>  Port number (default: %d)\n", DEFAULT_PORT);
}

int main(int ac, char *av[])
{
    CLI_T cli = parse(ac, av);

    if (cli.operation_type == 0) {
        print_usage(av[0]);
        return 1;
    }

    if (cli.operation_type == 1) {
        return run_sender(&cli);
    } else {
        return run_receiver(&cli);
    }
}
