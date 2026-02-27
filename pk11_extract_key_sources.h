#ifndef PK11_EXTRACT_KEY_SOURCES_H
#define PK11_EXTRACT_KEY_SOURCES_H

/*
 * pk11_extract_key_sources.h
 *
 * IMPORTANT: packages.h must be #included before this header.
 * packages.h defines pk11_ctx_t; we must not redefine it here.
 *
 * Typical use in packages.c — add at the top after packages.h:
 *
 *     #include "packages.h"
 *     #include "pk11_extract_key_sources.h"
 *
 * Then at the end of pk11_process():
 *
 *     if (ctx->is_decrypted)
 *         pk11_extract_and_print_key_sources(ctx);
 *
 * Or to get the raw bytes:
 *
 *     uint8_t mks[PK11_KEY_SIZE], dmkss[PK11_KEY_SIZE];
 *     uint8_t mmks[PK11_KEY_SIZE], mmks_dev[PK11_KEY_SIZE];
 *     extract_key_sources_from_pk11_ctx(ctx, mks, dmkss, mmks, mmks_dev);
 */

#include <stdint.h>
#include <stddef.h>

/* Return codes */
#define PK11_KEYSRC_OK                 0
#define PK11_KEYSRC_ERR_NOT_DECRYPTED (-1)  /* ctx->is_decrypted == 0    */
#define PK11_KEYSRC_ERR_NO_OYASUMI   (-2)  /* "OYASUMI" magic not found */
#define PK11_KEYSRC_ERR_NO_PACKAGE2  (-3)  /* "package2" magic not found*/
#define PK11_KEYSRC_ERR_OOB          (-4)  /* offset out of range       */
#define PK11_KEYSRC_ERR_ALLOC        (-5)  /* malloc failed             */

#define PK11_KEY_SIZE 0x10

/* ---------------------------------------------------------------------- */
/* Low-level blob functions — take a flat decrypted package1 byte buffer   */
/* ---------------------------------------------------------------------- */

int erista_extract_key_sources_from_package1(
        const uint8_t *data,
        size_t         size,
        uint8_t        out_master_kek_source[PK11_KEY_SIZE],
        uint8_t        out_device_master_key_source_source[PK11_KEY_SIZE]);

int mariko_extract_key_sources_from_package1(
        const uint8_t *data,
        size_t         size,
        uint8_t        out_mariko_master_kek_source[PK11_KEY_SIZE],
        uint8_t        out_mariko_master_kek_source_dev[PK11_KEY_SIZE]);

/* ---------------------------------------------------------------------- */
/* High-level ctx functions — work directly on hactool's pk11_ctx_t        */
/* (pk11_ctx_t must be fully defined before these are called)              */
/* ---------------------------------------------------------------------- */

int extract_key_sources_from_pk11_ctx(
        pk11_ctx_t *ctx,
        uint8_t     out_master_kek_source[PK11_KEY_SIZE],
        uint8_t     out_device_master_key_source_source[PK11_KEY_SIZE],
        uint8_t     out_mariko_master_kek_source[PK11_KEY_SIZE],
        uint8_t     out_mariko_master_kek_source_dev[PK11_KEY_SIZE]);

void pk11_extract_and_print_key_sources(pk11_ctx_t *ctx);

#endif /* PK11_EXTRACT_KEY_SOURCES_H */
