#ifndef HACTOOL_SWIPC_H
#define HACTOOL_SWIPC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

typedef struct {
    char input_dir[0x400];
    char output_dir[0x400];
    void *tool_ctx;
} swipc_ctx_t;

void swipc_process(swipc_ctx_t *ctx);

#endif
