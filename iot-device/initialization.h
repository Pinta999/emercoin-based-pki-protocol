//
// Created by nzazzo on 20/06/22.
//

#ifndef PROTOCOL_CLIENT_INITIALIZATION_H
#define PROTOCOL_CLIENT_INITIALIZATION_H

#include "crypto.h"
#include "utils.h"
#include "idevid.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

int initializazion(char *m_init, const int size, int sock);

#endif //PROTOCOL_CLIENT_INITIALIZATION_H
