#ifndef HACTOOL_CNMT_H
#define HACTOOL_CNMT_H

#include "types.h"
#include "settings.h"
#include "cJSON.h"

/* PackagedContentMetaHeader is always 0x20 bytes. */
#define CNMT_HEADER_SIZE              0x20
/* v15.0.0+ PackagedContentInfo entry size. */
#define CNMT_CONTENT_INFO_SIZE        0x38
/* ContentMetaInfo entry size. */
#define CNMT_CONTENT_META_INFO_SIZE   0x10
/* Trailing digest size. */
#define CNMT_DIGEST_SIZE              0x20

/* ------------------------------------------------------------------ */
/* Enumerations                                                          */
/* ------------------------------------------------------------------ */

typedef enum {
    CNMT_TYPE_SYSTEM_PROGRAM    = 0x00,
    CNMT_TYPE_SYSTEM_DATA       = 0x01,
    CNMT_TYPE_SYSTEM_UPDATE     = 0x02,
    CNMT_TYPE_FIRMWARE_PACKAGE_A = 0x03,
    CNMT_TYPE_FIRMWARE_PACKAGE_B = 0x04,
    CNMT_TYPE_APPLICATION       = 0x80,
    CNMT_TYPE_PATCH             = 0x81,
    CNMT_TYPE_ADD_ON_CONTENT    = 0x82,
    CNMT_TYPE_DELTA             = 0x83,
    CNMT_TYPE_DATA_PATCH        = 0x84,
} cnmt_content_meta_type_t;

typedef enum {
    CNMT_CONTENT_TYPE_META              = 0x00,
    CNMT_CONTENT_TYPE_PROGRAM           = 0x01,
    CNMT_CONTENT_TYPE_DATA              = 0x02,
    CNMT_CONTENT_TYPE_CONTROL           = 0x03,
    CNMT_CONTENT_TYPE_HTML_DOCUMENT     = 0x04,
    CNMT_CONTENT_TYPE_LEGAL_INFORMATION = 0x05,
    CNMT_CONTENT_TYPE_DELTA_FRAGMENT    = 0x06,
} cnmt_content_type_t;

typedef enum {
    CNMT_PLATFORM_NX = 0x00,
} cnmt_platform_t;

/* ------------------------------------------------------------------ */
/* Packed binary structs                                                */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

/* PackagedContentMetaHeader — 0x20 bytes */
typedef struct {
    uint64_t title_id;                        /* 0x00 */
    uint32_t version;                         /* 0x08 */
    uint8_t  content_meta_type;               /* 0x0C */
    uint8_t  content_meta_platform;           /* 0x0D */
    uint16_t extended_header_size;            /* 0x0E */
    uint16_t content_count;                   /* 0x10 */
    uint16_t content_meta_count;              /* 0x12 */
    uint8_t  attributes;                      /* 0x14 */
    uint8_t  _0x15[3];                        /* 0x15 reserved */
    uint32_t required_download_system_version; /* 0x18 */
    uint8_t  _0x1C[4];                        /* 0x1C reserved */
} cnmt_header_t;

/* PackagedContentInfo — 0x38 bytes (v15.0.0+) */
typedef struct {
    uint8_t  hash[0x20];                      /* 0x00 SHA-256 */
    uint8_t  content_id[0x10];               /* 0x20 */
    uint8_t  size[5];                         /* 0x30 48-bit LE */
    uint8_t  content_attributes;             /* 0x35 */
    uint8_t  content_type;                   /* 0x36 */
    uint8_t  id_offset;                      /* 0x37 */
} cnmt_content_info_t;

/* ContentMetaInfo — 0x10 bytes */
typedef struct {
    uint64_t title_id;                        /* 0x00 */
    uint32_t version;                         /* 0x08 */
    uint8_t  content_meta_type;               /* 0x0C */
    uint8_t  attributes;                      /* 0x0D */
    uint8_t  _0x0E[2];                        /* 0x0E reserved */
} cnmt_content_meta_info_t;

/* Extended headers — one per meta type */
typedef struct {
    uint64_t patch_id;                        /* 0x00 */
    uint32_t required_system_version;         /* 0x08 */
    uint32_t required_application_version;    /* 0x0C */
} cnmt_application_extended_header_t;         /* 0x10 bytes */

typedef struct {
    uint64_t application_id;                  /* 0x00 */
    uint32_t required_system_version;         /* 0x08 */
    uint32_t extended_data_size;              /* 0x0C */
    uint8_t  _0x10[8];                        /* 0x10 reserved */
} cnmt_patch_extended_header_t;               /* 0x18 bytes */

typedef struct {
    uint64_t application_id;                  /* 0x00 */
    uint32_t required_application_version;    /* 0x08 */
    uint8_t  content_accessibilities;         /* 0x0C */
    uint8_t  _0x0D[3];                        /* 0x0D reserved */
    uint64_t data_patch_id;                   /* 0x10 */
} cnmt_addon_extended_header_t;               /* 0x18 bytes */

typedef struct {
    uint64_t application_id;                  /* 0x00 */
    uint32_t extended_data_size;              /* 0x08 */
    uint32_t _0x0C;                           /* 0x0C reserved */
} cnmt_delta_extended_header_t;               /* 0x10 bytes */

typedef struct {
    uint32_t extended_data_size;              /* 0x00 */
} cnmt_system_update_extended_header_t;       /* 0x04 bytes */

typedef struct {
    uint64_t data_id;                         /* 0x00 */
    uint64_t application_id;                  /* 0x08 */
    uint32_t required_application_version;    /* 0x10 */
    uint32_t extended_data_size;              /* 0x14 */
    uint8_t  _0x18[8];                        /* 0x18 reserved */
} cnmt_data_patch_extended_header_t;          /* 0x20 bytes */

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/* Runtime context                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t        *data;               /* Pointer into raw buffer */
    size_t                data_size;

    cnmt_header_t         header;

    /* Extended header — only one will be valid, determined by meta_type */
    cnmt_content_meta_type_t meta_type;
    union {
        cnmt_application_extended_header_t    application;
        cnmt_patch_extended_header_t          patch;
        cnmt_addon_extended_header_t          addon;
        cnmt_delta_extended_header_t          delta;
        cnmt_system_update_extended_header_t  system_update;
        cnmt_data_patch_extended_header_t     data_patch;
    } extended_header;
    int has_extended_header;

    /* Content and meta info arrays — malloced, count from header */
    cnmt_content_info_t      *content_infos;      /* header.content_count entries */
    cnmt_content_meta_info_t *content_meta_infos; /* header.content_meta_count entries */

    /* Extended data (raw) — only Patch / Delta / SystemUpdate / DataPatch */
    uint8_t  *extended_data;
    uint32_t  extended_data_size;

    /* Trailing digest */
    uint8_t   digest[CNMT_DIGEST_SIZE];
    int       has_digest;
} cnmt_ctx_t;

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void cnmt_process(cnmt_ctx_t *ctx, hactool_ctx_t *tool_ctx);
void cnmt_print(cnmt_ctx_t *ctx);
void cnmt_save(cnmt_ctx_t *ctx, hactool_ctx_t *tool_ctx);
char *cnmt_get_json(cnmt_ctx_t *ctx);

/* Parse raw bytes into ctx. Returns 1 on success, 0 on failure. */
int cnmt_parse(cnmt_ctx_t *ctx, const uint8_t *data, size_t size);
void cnmt_free(cnmt_ctx_t *ctx);

#endif
