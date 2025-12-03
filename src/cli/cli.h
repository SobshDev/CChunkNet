#ifndef CLI_H
#define CLI_H


typedef struct CLI_S {
    unsigned char operation_type; // 0 = Error, 1 = Send, 2 = Receive
    unsigned char address[4];
    unsigned int port;
    char *path;
} CLI_T;

CLI_T parse(int ac, char *av[]);

#endif // CLI_H