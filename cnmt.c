#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "cnmt.h"
#include "utils.h"
#include "settings.h"
#include "cJSON.h"

static const char *cnmt_meta_type_str(uint8_t t) {
    switch (t) {
        case CNMT_TYPE_SYSTEM_PROGRAM:      return "SystemProgram";
        case CNMT_TYPE_SYSTEM_DATA:         return "SystemData";
        case CNMT_TYPE_SYSTEM_UPDATE:       return "SystemUpdate";
        case CNMT_TYPE_FIRMWARE_PACKAGE_A:  return "FirmwarePackageA";
        case CNMT_TYPE_FIRMWARE_PACKAGE_B:  return "FirmwarePackageB";
        case CNMT_TYPE_APPLICATION:         return "Application";
        case CNMT_TYPE_PATCH:               return "Patch";
        case CNMT_TYPE_ADD_ON_CONTENT:      return "AddOnContent";
        case CNMT_TYPE_DELTA:               return "Delta";
        case CNMT_TYPE_DATA_PATCH:          return "DataPatch";
        default:                            return "Unknown";
    }
}

static const char *cnmt_content_type_str(uint8_t t) {
    switch (t) {
        case CNMT_CONTENT_TYPE_META:               return "Meta";
        case CNMT_CONTENT_TYPE_PROGRAM:            return "Program";
        case CNMT_CONTENT_TYPE_DATA:               return "Data";
        case CNMT_CONTENT_TYPE_CONTROL:            return "Control";
        case CNMT_CONTENT_TYPE_HTML_DOCUMENT:      return "HtmlDocument";
        case CNMT_CONTENT_TYPE_LEGAL_INFORMATION:  return "LegalInformation";
        case CNMT_CONTENT_TYPE_DELTA_FRAGMENT:     return "DeltaFragment";
        default:                                   return "Unknown";
    }
}

static const char *cnmt_platform_str(uint8_t p) {
    switch (p) {
        case CNMT_PLATFORM_NX: return "NX";
        default:               return "Unknown";
    }
}

static uint64_t cnmt_read_size5(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 5; i++) {
        v |= (uint64_t)b[i] << (8 * i);
    }
    return v;
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static char *hex_string(const uint8_t *data, size_t len) {
    char *s = malloc(len * 2 + 1);
    if (s == NULL) return NULL;
    for (size_t i = 0; i < len; i++) {
        snprintf(s + i * 2, 3, "%02x", data[i]);
    }
    s[len * 2] = '\0';
    return s;
}

static size_t extended_header_expected_size(uint8_t meta_type) {
    switch (meta_type) {
        case CNMT_TYPE_SYSTEM_UPDATE:   return sizeof(cnmt_system_update_extended_header_t);
        case CNMT_TYPE_APPLICATION:     return sizeof(cnmt_application_extended_header_t);
        case CNMT_TYPE_PATCH:           return sizeof(cnmt_patch_extended_header_t);
        case CNMT_TYPE_ADD_ON_CONTENT:  return sizeof(cnmt_addon_extended_header_t);
        case CNMT_TYPE_DELTA:           return sizeof(cnmt_delta_extended_header_t);
        case CNMT_TYPE_DATA_PATCH:      return sizeof(cnmt_data_patch_extended_header_t);
        default:                        return 0;
    }
}

int cnmt_parse(cnmt_ctx_t *ctx, const uint8_t *data, size_t size) {
    if (size < CNMT_HEADER_SIZE) {
        fprintf(stderr, "CNMT: file too small (0x%zx bytes, need at least 0x%x)\n",
                size, CNMT_HEADER_SIZE);
        return 0;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->data = data;
    ctx->data_size = size;

    memcpy(&ctx->header, data, sizeof(cnmt_header_t));
    ctx->meta_type = (cnmt_content_meta_type_t)ctx->header.content_meta_type;

    size_t pos = CNMT_HEADER_SIZE;

    /* Extended header */
    if (ctx->header.extended_header_size > 0) {
        if (pos + ctx->header.extended_header_size > size) {
            fprintf(stderr, "CNMT: truncated extended header\n");
            return 0;
        }
        size_t expected = extended_header_expected_size(ctx->header.content_meta_type);
        size_t to_copy = (expected < ctx->header.extended_header_size)
                         ? expected : ctx->header.extended_header_size;
        if (to_copy > 0) {
            memcpy(&ctx->extended_header, data + pos, to_copy);
            ctx->has_extended_header = 1;
        }
        pos += ctx->header.extended_header_size;
    }

    /* Content infos */
    if (ctx->header.content_count > 0) {
        size_t ci_total = (size_t)ctx->header.content_count * sizeof(cnmt_content_info_t);
        if (pos + ci_total > size) {
            fprintf(stderr, "CNMT: truncated content infos\n");
            return 0;
        }
        ctx->content_infos = malloc(ci_total);
        if (ctx->content_infos == NULL) {
            fprintf(stderr, "CNMT: failed to allocate content infos\n");
            return 0;
        }
        memcpy(ctx->content_infos, data + pos, ci_total);
        pos += ci_total;
    }

    /* Content meta infos */
    if (ctx->header.content_meta_count > 0) {
        size_t cm_total = (size_t)ctx->header.content_meta_count
                          * sizeof(cnmt_content_meta_info_t);
        if (pos + cm_total > size) {
            fprintf(stderr, "CNMT: truncated content meta infos\n");
            return 0;
        }
        ctx->content_meta_infos = malloc(cm_total);
        if (ctx->content_meta_infos == NULL) {
            fprintf(stderr, "CNMT: failed to allocate content meta infos\n");
            return 0;
        }
        memcpy(ctx->content_meta_infos, data + pos, cm_total);
        pos += cm_total;
    }

    /* Extended data (optional, before digest) */
    uint32_t ext_data_size = 0;
    switch (ctx->header.content_meta_type) {
        case CNMT_TYPE_PATCH:
            if (ctx->has_extended_header)
                ext_data_size = ctx->extended_header.patch.extended_data_size;
            break;
        case CNMT_TYPE_DELTA:
            if (ctx->has_extended_header)
                ext_data_size = ctx->extended_header.delta.extended_data_size;
            break;
        case CNMT_TYPE_SYSTEM_UPDATE:
            if (ctx->has_extended_header)
                ext_data_size = ctx->extended_header.system_update.extended_data_size;
            break;
        case CNMT_TYPE_DATA_PATCH:
            if (ctx->has_extended_header)
                ext_data_size = ctx->extended_header.data_patch.extended_data_size;
            break;
        default:
            break;
    }

    if (ext_data_size > 0) {
        if (pos + ext_data_size > size) {
            fprintf(stderr, "CNMT: truncated extended data\n");
            return 0;
        }
        ctx->extended_data = malloc(ext_data_size);
        if (ctx->extended_data == NULL) {
            fprintf(stderr, "CNMT: failed to allocate extended data\n");
            return 0;
        }
        memcpy(ctx->extended_data, data + pos, ext_data_size);
        ctx->extended_data_size = ext_data_size;
        pos += ext_data_size;
    }

    /* Digest: last CNMT_DIGEST_SIZE bytes */
    if (size >= CNMT_DIGEST_SIZE && size - CNMT_DIGEST_SIZE >= pos) {
        memcpy(ctx->digest, data + size - CNMT_DIGEST_SIZE, CNMT_DIGEST_SIZE);
        ctx->has_digest = 1;
    }

    return 1;
}

void cnmt_free(cnmt_ctx_t *ctx) {
    free(ctx->content_infos);
    free(ctx->content_meta_infos);
    free(ctx->extended_data);
    ctx->content_infos = NULL;
    ctx->content_meta_infos = NULL;
    ctx->extended_data = NULL;
}

void cnmt_process(cnmt_ctx_t *ctx, hactool_ctx_t *tool_ctx) {
    if (tool_ctx->action & ACTION_INFO) {
        cnmt_print(ctx);
    }
    if (tool_ctx->action & ACTION_EXTRACT) {
        cnmt_save(ctx, tool_ctx);
    }
}

void cnmt_print(cnmt_ctx_t *ctx) {
    char buf[0x40];

    printf("[PackagedContentMeta]\n");
    printf("    Title ID:                       0x%016"PRIx64"\n", ctx->header.title_id);
    printf("    Version:                        %"PRIu32"\n", ctx->header.version);
    printf("    Type:                           %s (0x%02X)\n",
           cnmt_meta_type_str(ctx->header.content_meta_type),
           ctx->header.content_meta_type);
    printf("    Platform:                       %s\n",
           cnmt_platform_str(ctx->header.content_meta_platform));
    printf("    Extended Header Size:           0x%04"PRIx16"\n",
           ctx->header.extended_header_size);
    printf("    Content Count:                  %"PRIu16"\n", ctx->header.content_count);
    printf("    Content Meta Count:             %"PRIu16"\n", ctx->header.content_meta_count);
    printf("    Attributes:                     0x%02X\n", ctx->header.attributes);
    printf("    Required Download Version:      %"PRIu32"\n",
           ctx->header.required_download_system_version);

    if (ctx->has_extended_header) {
        switch (ctx->header.content_meta_type) {
            case CNMT_TYPE_APPLICATION:
                printf("    [ApplicationExtendedHeader]\n");
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.application.patch_id);
                printf("        Patch ID:                   %s\n", buf);
                printf("        Required System Version:    %"PRIu32"\n",
                       ctx->extended_header.application.required_system_version);
                printf("        Required App Version:       %"PRIu32"\n",
                       ctx->extended_header.application.required_application_version);
                break;
            case CNMT_TYPE_PATCH:
                printf("    [PatchExtendedHeader]\n");
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.patch.application_id);
                printf("        Application ID:             %s\n", buf);
                printf("        Required System Version:    %"PRIu32"\n",
                       ctx->extended_header.patch.required_system_version);
                printf("        Extended Data Size:         0x%"PRIx32"\n",
                       ctx->extended_header.patch.extended_data_size);
                break;
            case CNMT_TYPE_ADD_ON_CONTENT:
                printf("    [AddOnContentExtendedHeader]\n");
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.addon.application_id);
                printf("        Application ID:             %s\n", buf);
                printf("        Required App Version:       %"PRIu32"\n",
                       ctx->extended_header.addon.required_application_version);
                printf("        Content Accessibilities:    0x%02X\n",
                       ctx->extended_header.addon.content_accessibilities);
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.addon.data_patch_id);
                printf("        Data Patch ID:              %s\n", buf);
                break;
            case CNMT_TYPE_DELTA:
                printf("    [DeltaExtendedHeader]\n");
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.delta.application_id);
                printf("        Application ID:             %s\n", buf);
                printf("        Extended Data Size:         0x%"PRIx32"\n",
                       ctx->extended_header.delta.extended_data_size);
                break;
            case CNMT_TYPE_SYSTEM_UPDATE:
                printf("    [SystemUpdateExtendedHeader]\n");
                printf("        Extended Data Size:         0x%"PRIx32"\n",
                       ctx->extended_header.system_update.extended_data_size);
                break;
            case CNMT_TYPE_DATA_PATCH:
                printf("    [DataPatchExtendedHeader]\n");
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.data_patch.data_id);
                printf("        Data ID:                    %s\n", buf);
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.data_patch.application_id);
                printf("        Application ID:             %s\n", buf);
                printf("        Required App Version:       %"PRIu32"\n",
                       ctx->extended_header.data_patch.required_application_version);
                printf("        Extended Data Size:         0x%"PRIx32"\n",
                       ctx->extended_header.data_patch.extended_data_size);
                break;
            default:
                break;
        }
    }

    if (ctx->header.content_count > 0) {
        printf("    Content Infos (%"PRIu16"):\n", ctx->header.content_count);
        for (unsigned int i = 0; i < ctx->header.content_count; i++) {
            const cnmt_content_info_t *ci = &ctx->content_infos[i];
            uint64_t sz = cnmt_read_size5(ci->size);
            printf("        [%u] Type: %-20s  IdOffset: %u  Size: 0x%"PRIx64"\n",
                   i, cnmt_content_type_str(ci->content_type), ci->id_offset, sz);
            printf("             ID:   ");
            print_hex(ci->content_id, 0x10);
            printf("\n");
            printf("             Hash: ");
            print_hex(ci->hash, 0x20);
            printf("\n");
        }
    }

    if (ctx->header.content_meta_count > 0) {
        printf("    Content Meta Infos (%"PRIu16"):\n", ctx->header.content_meta_count);
        for (unsigned int i = 0; i < ctx->header.content_meta_count; i++) {
            const cnmt_content_meta_info_t *cm = &ctx->content_meta_infos[i];
            printf("        [%u] TitleID: 0x%016"PRIx64
                   "  Version: %"PRIu32"  Type: %s  Attributes: 0x%02X\n",
                   i, cm->title_id, cm->version,
                   cnmt_meta_type_str(cm->content_meta_type), cm->attributes);
        }
    }

    if (ctx->has_digest) {
        printf("    Digest:                         ");
        print_hex(ctx->digest, CNMT_DIGEST_SIZE);
        printf("\n");
    }
}

void cnmt_save(cnmt_ctx_t *ctx, hactool_ctx_t *tool_ctx) {
    filepath_t *json_path = &tool_ctx->settings.cnmt_json_path;
    if (json_path->valid != VALIDITY_VALID) {
        return;
    }

    FILE *f_json = os_fopen(json_path->os_path, OS_MODE_WRITE);
    if (f_json == NULL) {
        fprintf(stderr, "Failed to open %s!\n", json_path->char_path);
        return;
    }

    char *json = cnmt_get_json(ctx);
    if (fwrite(json, 1, strlen(json), f_json) != strlen(json)) {
        fprintf(stderr, "Failed to write CNMT JSON!\n");
        exit(EXIT_FAILURE);
    }
    cJSON_free(json);
    fclose(f_json);
}

char *cnmt_get_json(cnmt_ctx_t *ctx) {
    char buf[0x40];
    cJSON *root = cJSON_CreateObject();

    snprintf(buf, sizeof(buf), "0x%016"PRIx64, ctx->header.title_id);
    cJSON_AddStringToObject(root, "title_id", buf);
    cJSON_AddNumberToObject(root, "version", (double)ctx->header.version);
    cJSON_AddStringToObject(root, "content_meta_type",
                            cnmt_meta_type_str(ctx->header.content_meta_type));
    cJSON_AddStringToObject(root, "content_meta_platform",
                            cnmt_platform_str(ctx->header.content_meta_platform));
    cJSON_AddNumberToObject(root, "content_count", ctx->header.content_count);
    cJSON_AddNumberToObject(root, "content_meta_count", ctx->header.content_meta_count);
    cJSON_AddNumberToObject(root, "attributes", ctx->header.attributes);
    cJSON_AddNumberToObject(root, "required_download_system_version",
                            (double)ctx->header.required_download_system_version);

    if (ctx->has_extended_header) {
        cJSON *ext = cJSON_CreateObject();
        switch (ctx->header.content_meta_type) {
            case CNMT_TYPE_APPLICATION:
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.application.patch_id);
                cJSON_AddStringToObject(ext, "patch_id", buf);
                cJSON_AddNumberToObject(ext, "required_system_version",
                    (double)ctx->extended_header.application.required_system_version);
                cJSON_AddNumberToObject(ext, "required_application_version",
                    (double)ctx->extended_header.application.required_application_version);
                break;
            case CNMT_TYPE_PATCH:
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.patch.application_id);
                cJSON_AddStringToObject(ext, "application_id", buf);
                cJSON_AddNumberToObject(ext, "required_system_version",
                    (double)ctx->extended_header.patch.required_system_version);
                cJSON_AddNumberToObject(ext, "extended_data_size",
                    (double)ctx->extended_header.patch.extended_data_size);
                break;
            case CNMT_TYPE_ADD_ON_CONTENT:
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.addon.application_id);
                cJSON_AddStringToObject(ext, "application_id", buf);
                cJSON_AddNumberToObject(ext, "required_application_version",
                    (double)ctx->extended_header.addon.required_application_version);
                cJSON_AddNumberToObject(ext, "content_accessibilities",
                    ctx->extended_header.addon.content_accessibilities);
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.addon.data_patch_id);
                cJSON_AddStringToObject(ext, "data_patch_id", buf);
                break;
            case CNMT_TYPE_DELTA:
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.delta.application_id);
                cJSON_AddStringToObject(ext, "application_id", buf);
                cJSON_AddNumberToObject(ext, "extended_data_size",
                    (double)ctx->extended_header.delta.extended_data_size);
                break;
            case CNMT_TYPE_SYSTEM_UPDATE:
                cJSON_AddNumberToObject(ext, "extended_data_size",
                    (double)ctx->extended_header.system_update.extended_data_size);
                break;
            case CNMT_TYPE_DATA_PATCH:
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.data_patch.data_id);
                cJSON_AddStringToObject(ext, "data_id", buf);
                snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                         ctx->extended_header.data_patch.application_id);
                cJSON_AddStringToObject(ext, "application_id", buf);
                cJSON_AddNumberToObject(ext, "required_application_version",
                    (double)ctx->extended_header.data_patch.required_application_version);
                cJSON_AddNumberToObject(ext, "extended_data_size",
                    (double)ctx->extended_header.data_patch.extended_data_size);
                break;
            default:
                break;
        }
        cJSON_AddItemToObject(root, "extended_header", ext);
    }

    cJSON *ci_arr = cJSON_CreateArray();
    for (unsigned int i = 0; i < ctx->header.content_count; i++) {
        const cnmt_content_info_t *ci = &ctx->content_infos[i];
        cJSON *entry = cJSON_CreateObject();
        char *id_hex = hex_string(ci->content_id, 0x10);
        char *hash_hex = hex_string(ci->hash, 0x20);
        cJSON_AddStringToObject(entry, "content_id", id_hex ? id_hex : "");
        cJSON_AddStringToObject(entry, "hash", hash_hex ? hash_hex : "");
        free(id_hex);
        free(hash_hex);
        cJSON_AddNumberToObject(entry, "size", (double)cnmt_read_size5(ci->size));
        cJSON_AddStringToObject(entry, "content_type",
                                cnmt_content_type_str(ci->content_type));
        cJSON_AddNumberToObject(entry, "content_attributes", ci->content_attributes);
        cJSON_AddNumberToObject(entry, "id_offset", ci->id_offset);
        cJSON_AddItemToArray(ci_arr, entry);
    }
    cJSON_AddItemToObject(root, "content_infos", ci_arr);

    cJSON *cm_arr = cJSON_CreateArray();
    for (unsigned int i = 0; i < ctx->header.content_meta_count; i++) {
        const cnmt_content_meta_info_t *cm = &ctx->content_meta_infos[i];
        cJSON *entry = cJSON_CreateObject();
        snprintf(buf, sizeof(buf), "0x%016"PRIx64, cm->title_id);
        cJSON_AddStringToObject(entry, "title_id", buf);
        cJSON_AddNumberToObject(entry, "version", (double)cm->version);
        cJSON_AddStringToObject(entry, "content_meta_type",
                                cnmt_meta_type_str(cm->content_meta_type));
        cJSON_AddNumberToObject(entry, "attributes", cm->attributes);
        cJSON_AddItemToArray(cm_arr, entry);
    }
    cJSON_AddItemToObject(root, "content_meta_infos", cm_arr);

    if (ctx->has_digest) {
        char *digest_hex = hex_string(ctx->digest, CNMT_DIGEST_SIZE);
        cJSON_AddStringToObject(root, "digest", digest_hex ? digest_hex : "");
        free(digest_hex);
    }

    char *out = cJSON_Print(root);
    cJSON_Delete(root);
    return out;
}
