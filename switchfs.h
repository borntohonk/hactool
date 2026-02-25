#ifndef HACTOOL_SWITCHFS_H
#define HACTOOL_SWITCHFS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

/* Content type name mapping. */
#define SWITCHFS_CONTENT_TYPE_PROGRAM   0
#define SWITCHFS_CONTENT_TYPE_META      1
#define SWITCHFS_CONTENT_TYPE_CONTROL   2
#define SWITCHFS_CONTENT_TYPE_MANUAL    3
#define SWITCHFS_CONTENT_TYPE_DATA      4
#define SWITCHFS_CONTENT_TYPE_PUBLICDATA 5

typedef struct {
    char input_dir[0x400];           /* Input directory path. */
    char output_dir[0x400];          /* Output directory path. */
    void *tool_ctx;                  /* Tool context for decryption (cast to hactool_ctx_t*). */
} switchfs_ctx_t;

void switchfs_process(switchfs_ctx_t *ctx);

#endif
