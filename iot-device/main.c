#include "initialization.h"
#include "ownership.h"
#include "update.h"
#include "utils.h"

#define SERVER "127.0.0.1"
#define PORT 12000
#define MAX_CONN 5
#define BUFF_SIZE 1024

typedef enum {
    INIT,
    OWNR,
    UPDT,
    NONE
} cmd;

cmd get_cmd(char *command) {
    if (strcmp(command, "INIT") == 0)
        return INIT;
    else if (strcmp(command, "OWNR") == 0)
        return OWNR;
    else if (strcmp(command, "UPDT") == 0)
        return UPDT;
    else
        return NONE;
}

int dispatch_message(int sock) {
    unsigned char buffer[4 * BUFF_SIZE] = {0};
    char tmpkey[16] = {0};
    char command[4 + 1] = {0};
    int ret = 0;

    jsmn_parser parser;
    jsmntok_t tokens[16];
    jsmn_init(&parser);

    unsigned char *p = buffer;
    int valread = 0;
    int sumValread = 0;
    while ( (valread = read(sock, p, 256) ) == 256) {
        if (valread <= 0) {
            printf("! error - dispatch_message() : empty message from receiver.\n");
            return -1;
        }
        p += valread;
        sumValread += valread;
    }
    sumValread = sumValread == 0 ? valread : sumValread;
    jsmn_parse(&parser, buffer, sumValread, tokens, 16);
    strncpy(tmpkey, buffer + tokens[1].start, tokens[1].end - tokens[1].start);
    if (strcmp(tmpkey, "command")) {
        printf("! error - dispatch_message() : 'command' attribute not found.\n");
        return -1;
    }
    strncpy(command, buffer + tokens[2].start, tokens[2].end - tokens[2].start);
    switch(get_cmd(command)) {
        case INIT:
            ret = initializazion(buffer, sumValread, sock);
            break;
        case OWNR:
            ret = ownership(buffer, sumValread, sock);
            break;
        case UPDT:
            ret = update(buffer, sumValread, sock);
            break;
        default:
            break;
    }
    return ret;
}


int main() {
    int ret = 0;
    int sock = 0;
    int server_fd;
    int valread;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    char buffer[4*BUFF_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0 )) < 0) {
        printf("\nSocket creation error.\n");
        return -1;
    }

    const int enable = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &enable, sizeof(int)) > 0) {
        printf("!   setsockopt() failed. \n");
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        printf("\n!   Bind failed!\n");
        return -1;
    }

    if (listen(server_fd, MAX_CONN) < 0) {
        printf("\n!   Listen failed!\n");
        return -1;
    }

    while(1) {
        printf("\nWaiting for a connection with DM...\n");
        if ( (sock = accept(server_fd, (struct sockaddr *) &addr, (socklen_t *) &addrlen)) < 0) {
            printf("\n!   Accept failed!\n");
            return -1;
        }
        dispatch_message(sock);
    }

    close(sock);
    shutdown(server_fd, SHUT_RDWR);

    return 0;
}
