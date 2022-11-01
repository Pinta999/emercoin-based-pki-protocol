//
// Created by nzazzo on 14/07/22.
//

#ifndef PROTOCOL_CLIENT_UPDATE_H
#define PROTOCOL_CLIENT_UPDATE_H

#include "crypto.h"
#include "utils.h"
#include <tss2/tss2_common.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

int update(char *message, const int size, int sock);

#endif //PROTOCOL_CLIENT_UPDATE_H
