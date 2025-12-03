#ifndef CLI_H
#define CLI_H


typedef struct CLI_S {
    unsigned char operation_type; // 1 = Receive, 0 = Send
    unsigned char address[4];
    unsigned int port;
    char *path;
} CLI_T;

#endif // CLI_H