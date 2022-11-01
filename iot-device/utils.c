//
// Created by nzazzo on 11/07/22.
//

#include "utils.h"


int from_hex_to_bytes(char *hex_string, char *result) {
    const char *pos = hex_string;
    size_t result_size;
    if (strlen(hex_string) % 2 != 0) {
        result_size = strlen(hex_string) / 2 + 1;
        hex_string[0] = '0';
    }
    else
        result_size = strlen(hex_string) / 2;

    for (size_t count = 0; count < result_size/sizeof *result; count++) {
        sscanf(pos, "%2hhx", &result[count]);
        pos += 2;
    }

    return result_size;
}

void get_msg_without_signature(char *dest, char *src, jsmntok_t token) {
    strncpy(dest, src, token.end);
    dest[token.end] = '"';
    dest[token.end + 1] = '}';
    dest[token.end + 2] = '\0';
}

int get_conf_device_id(char *id) {
    FILE *fp;
    fp = fopen("configuration", "r");
    char key[16] = {0};
    char value[64 + 1] = {0};
    int end = 0;
    while (fscanf(fp, "%s %s", key, value) != EOF && !end) {
        if (strcmp(key, "ID") == 0) {
            end = 1;
            strcpy(id, value);
        }
        else {
            memset(key, 0, 16);
            memset(value, 0, 64 + 1);
        }
    }
    return end ? 0 : -1;
}
