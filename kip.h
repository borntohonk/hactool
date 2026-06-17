#ifndef HACTOOL_KIP_H
#define HACTOOL_KIP_H
#include "types.h"
#include "utils.h"
#include "settings.h"

#define MAGIC_INI1 0x31494E49
#define MAGIC_KIP1 0x3150494B
#define INI1_MAX_KIPS 0x50

typedef struct {
    uint32_t magic;
    uint32_t size;
    uint32_t num_processes;
    uint32_t _0xC;
    char kip_data[];
} ini1_header_t;

typedef struct {
    uint32_t out_offset;
    uint32_t out_size;
    uint32_t compressed_size;
    uint32_t attribute;
} kip_section_header_t;

typedef struct {
    uint32_t magic;
    char name[0xC];
    uint64_t title_id;
    uint32_t process_category;
    uint8_t main_thread_priority;
    uint8_t default_core;
    uint8_t _0x1E;
    uint8_t flags;
    kip_section_header_t section_headers[6];
    uint32_t capabilities[0x20];
    unsigned char data[];
} kip1_header_t;

typedef struct {
    FILE *file;
    hactool_ctx_t *tool_ctx;
    kip1_header_t *header;
} kip1_ctx_t;

typedef struct {
    FILE *file;
    hactool_ctx_t *tool_ctx;
    ini1_header_t *header;
    kip1_ctx_t kips[INI1_MAX_KIPS];
} ini1_ctx_t;

void ini1_process(ini1_ctx_t *ctx);
void ini1_print(ini1_ctx_t *ctx);
void ini1_save(ini1_ctx_t *ctx);

char *kip1_get_json(kip1_ctx_t *ctx);
void kip1_process(kip1_ctx_t *ctx);
void kip1_print(kip1_ctx_t *ctx, int suppress);
void kip1_save(kip1_ctx_t *ctx);

/* Decompress a raw KIP1 buffer in memory (BLZ decompression).
 * Returns a newly malloc'd decompressed KIP1 (caller must free), sets *out_size.
 * Returns NULL if src is not a valid KIP1. */
void *kip1_decompress_buf(const void *src, size_t src_size, size_t *out_size);

/* Re-compress a decompressed KIP1 (flags bits 0-2 all clear) using BLZ.
 * Each section is compressed if it shrinks; otherwise left uncompressed.
 * Returns a newly malloc'd re-compressed KIP1 (caller must free), sets *out_size.
 * SHA256 of the result is the canonical module ID when only a decompressed KIP1
 * is available (matches sgg convention). Returns NULL on failure. */
void *kip1_recompress_buf(const void *src, size_t src_size, size_t *out_size);

static inline uint64_t kip1_get_size(kip1_ctx_t *ctx) {
    /* Header + .text + .rodata + .rwdata */
    return 0x100 + ctx->header->section_headers[0].compressed_size + ctx->header->section_headers[1].compressed_size + ctx->header->section_headers[2].compressed_size;
}

static inline uint64_t kip1_get_size_from_header(kip1_header_t *header) {
    /* Header + .text + .rodata + .rwdata */
    return 0x100 + header->section_headers[0].compressed_size + header->section_headers[1].compressed_size + header->section_headers[2].compressed_size;
}

#endif
