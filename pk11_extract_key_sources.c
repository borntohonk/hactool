/*
 * pk11_extract_key_sources.c
 *
 * packages.h is included FIRST so that pk11_ctx_t is fully defined
 * before pk11_extract_key_sources.h is processed.  This is required
 * because packages.h defines pk11_ctx_t as an anonymous struct typedef
 * and our header must not introduce a conflicting forward-declaration.
 */
#include "packages.h"                /* defines pk11_ctx_t — must come first */
#include "pk11_extract_key_sources.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* =========================================================================
 * Internal helpers
 * ====================================================================== */

static const uint8_t *find_pattern(const uint8_t *haystack, size_t haystack_len,
                                   const uint8_t *needle,   size_t needle_len)
{
    if (needle_len == 0 || needle_len > haystack_len)
        return NULL;
    const uint8_t *end = haystack + haystack_len - needle_len;
    for (const uint8_t *p = haystack; p <= end; p++)
        if (memcmp(p, needle, needle_len) == 0)
            return p;
    return NULL;
}

static int safe_copy_key(uint8_t out[PK11_KEY_SIZE],
                         const uint8_t *base, size_t size,
                         const uint8_t *src)
{
    if (src < base)
        return PK11_KEYSRC_ERR_OOB;
    size_t offset = (size_t)(src - base);
    if (offset + PK11_KEY_SIZE > size)
        return PK11_KEYSRC_ERR_OOB;
    memcpy(out, src, PK11_KEY_SIZE);
    return PK11_KEYSRC_OK;
}

/* =========================================================================
 * Byte-pattern constants
 * ====================================================================== */

/* "OYASUMI" — 4F 59 41 53 55 4D 49 */
static const uint8_t MAGIC_OYASUMI[] = {
    0x4F, 0x59, 0x41, 0x53, 0x55, 0x4D, 0x49
};
#define MAGIC_OYASUMI_LEN  (sizeof(MAGIC_OYASUMI))

/* "package2" — 70 61 63 6B 61 67 65 32 */
static const uint8_t MAGIC_PACKAGE2[] = {
    0x70, 0x61, 0x63, 0x6B, 0x61, 0x67, 0x65, 0x32
};
#define MAGIC_PACKAGE2_LEN (sizeof(MAGIC_PACKAGE2))

/* =========================================================================
 * Low-level blob functions
 * ====================================================================== */

/*
 * Erista:
 *   master_kek_source               = data[OYASUMI match_end  + 0x42 : +0x10]
 *   device_master_key_source_source = data["package2" match_start - 0x14 : +0x10]
 */
int erista_extract_key_sources_from_package1(
        const uint8_t *data,
        size_t         size,
        uint8_t        out_master_kek_source[PK11_KEY_SIZE],
        uint8_t        out_device_master_key_source_source[PK11_KEY_SIZE])
{
    int rc;

    const uint8_t *oyasumi = find_pattern(data, size, MAGIC_OYASUMI, MAGIC_OYASUMI_LEN);
    if (!oyasumi)
        return PK11_KEYSRC_ERR_NO_OYASUMI;

    rc = safe_copy_key(out_master_kek_source, data, size,
                       oyasumi + MAGIC_OYASUMI_LEN + 0x42);
    if (rc != PK11_KEYSRC_OK) return rc;

    const uint8_t *pkg2 = find_pattern(data, size, MAGIC_PACKAGE2, MAGIC_PACKAGE2_LEN);
    if (!pkg2)
        return PK11_KEYSRC_ERR_NO_PACKAGE2;

    rc = safe_copy_key(out_device_master_key_source_source, data, size,
                       pkg2 - 0x14);
    if (rc != PK11_KEYSRC_OK) return rc;

    return PK11_KEYSRC_OK;
}

/*
 * Mariko:
 *   mariko_master_kek_source_dev = data[OYASUMI match_start + 0x29 : +0x10]
 *   mariko_master_kek_source     = data[OYASUMI match_start + 0x39 : +0x10]
 */
int mariko_extract_key_sources_from_package1(
        const uint8_t *data,
        size_t         size,
        uint8_t        out_mariko_master_kek_source[PK11_KEY_SIZE],
        uint8_t        out_mariko_master_kek_source_dev[PK11_KEY_SIZE])
{
    int rc;

    const uint8_t *oyasumi = find_pattern(data, size, MAGIC_OYASUMI, MAGIC_OYASUMI_LEN);
    if (!oyasumi)
        return PK11_KEYSRC_ERR_NO_OYASUMI;

    const uint8_t *dev_ptr = oyasumi + 0x29;
    rc = safe_copy_key(out_mariko_master_kek_source_dev, data, size, dev_ptr);
    if (rc != PK11_KEYSRC_OK) return rc;

    rc = safe_copy_key(out_mariko_master_kek_source, data, size,
                       dev_ptr + PK11_KEY_SIZE);
    if (rc != PK11_KEYSRC_OK) return rc;

    return PK11_KEYSRC_OK;
}

/* =========================================================================
 * High-level ctx functions
 * ====================================================================== */

int extract_key_sources_from_pk11_ctx(
        pk11_ctx_t *ctx,
        uint8_t     out_master_kek_source[PK11_KEY_SIZE],
        uint8_t     out_device_master_key_source_source[PK11_KEY_SIZE],
        uint8_t     out_mariko_master_kek_source[PK11_KEY_SIZE],
        uint8_t     out_mariko_master_kek_source_dev[PK11_KEY_SIZE])
{
    if (!ctx->is_decrypted) {
        fprintf(stderr, "extract_key_sources: PK11 is not decrypted\n");
        return PK11_KEYSRC_ERR_NOT_DECRYPTED;
    }

    int rc;

    if (ctx->is_mariko) {
        /*
         * Mariko Decrypted.bin layout (mirrors pk11_save):
         *   [mariko_oem_header]  [mariko_bl  (bl_size bytes)]
         */
        size_t blob_size = sizeof(ctx->mariko_oem_header)
                         + ctx->mariko_oem_header.bl_size;
        uint8_t *blob = malloc(blob_size);
        if (!blob) {
            fprintf(stderr, "extract_key_sources: malloc failed\n");
            return PK11_KEYSRC_ERR_ALLOC;
        }
        memcpy(blob,
               &ctx->mariko_oem_header, sizeof(ctx->mariko_oem_header));
        memcpy(blob + sizeof(ctx->mariko_oem_header),
               ctx->mariko_bl, ctx->mariko_oem_header.bl_size);

        rc = mariko_extract_key_sources_from_package1(
                blob, blob_size,
                out_mariko_master_kek_source,
                out_mariko_master_kek_source_dev);
        free(blob);
    } else {
        /*
         * Erista Decrypted.bin layout (mirrors pk11_save):
         *   [stage1  (sizeof pk11_stage1_t bytes)]  [pk11  (pk11_size bytes)]
         */
        size_t blob_size = sizeof(ctx->stage1) + ctx->pk11_size;
        uint8_t *blob = malloc(blob_size);
        if (!blob) {
            fprintf(stderr, "extract_key_sources: malloc failed\n");
            return PK11_KEYSRC_ERR_ALLOC;
        }
        memcpy(blob, &ctx->stage1, sizeof(ctx->stage1));
        memcpy(blob + sizeof(ctx->stage1), ctx->pk11, ctx->pk11_size);

        rc = erista_extract_key_sources_from_package1(
                blob, blob_size,
                out_master_kek_source,
                out_device_master_key_source_source);
        free(blob);
    }

    return rc;
}

void pk11_extract_and_print_key_sources(pk11_ctx_t *ctx)
{
    uint8_t master_kek_source[PK11_KEY_SIZE]               = {0};
    uint8_t device_master_key_source_source[PK11_KEY_SIZE] = {0};
    uint8_t mariko_master_kek_source[PK11_KEY_SIZE]        = {0};
    uint8_t mariko_master_kek_source_dev[PK11_KEY_SIZE]    = {0};

    int rc = extract_key_sources_from_pk11_ctx(
                ctx,
                master_kek_source,
                device_master_key_source_source,
                mariko_master_kek_source,
                mariko_master_kek_source_dev);

    if (rc != PK11_KEYSRC_OK) {
        fprintf(stderr, "Failed to extract key sources (error %d)\n", rc);
        return;
    }

    printf("Key Sources:\n");
    if (ctx->is_mariko) {
        printf("    Mariko Master KEK Source:           ");
        for (int i = 0; i < PK11_KEY_SIZE; i++) printf("%02x", mariko_master_kek_source[i]);
        printf("\n");
        printf("    Mariko Master KEK Source (Dev):     ");
        for (int i = 0; i < PK11_KEY_SIZE; i++) printf("%02x", mariko_master_kek_source_dev[i]);
        printf("\n");
    } else {
        printf("    Master KEK Source:                  ");
        for (int i = 0; i < PK11_KEY_SIZE; i++) printf("%02x", master_kek_source[i]);
        printf("\n");
        printf("    Device Master Key Source Source:    ");
        for (int i = 0; i < PK11_KEY_SIZE; i++) printf("%02x", device_master_key_source_source[i]);
        printf("\n");
    }
    printf("\n");
}
