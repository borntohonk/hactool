#ifndef HACTOOL_FIND_PATTERNS_H
#define HACTOOL_FIND_PATTERNS_H

#include "settings.h"

typedef struct {
    FILE           *file;
    hactool_ctx_t  *tool_ctx;
    uint8_t        *buffer;
    size_t          buffer_size;
} find_patterns_ctx_t;

void find_patterns_process(find_patterns_ctx_t *ctx);

#endif
