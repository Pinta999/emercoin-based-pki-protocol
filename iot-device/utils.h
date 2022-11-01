//
// Created by nzazzo on 11/07/22.
//

#ifndef PROTOCOL_CLIENT_UTILS_H
#define PROTOCOL_CLIENT_UTILS_H
#ifndef JSMN_STATIC
#define JSMN_STATIC


#include "crypto.h"
#include "jsmn.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>



int from_hex_to_bytes(char *hex_string, char *result);

void get_msg_without_signature(char *dest, char *src, jsmntok_t token);

int get_conf_device_id(char *id);

#endif //JSMN_STATIC
#endif //PROTOCOL_CLIENT_UTILS_H
