#include <string.h>
#include <stdio.h>
#include "kip.h"
#include "npdm.h"
#include "cJSON.h"

void ini1_process(ini1_ctx_t *ctx) {
    /* Read *just* safe amount. */
    ini1_header_t raw_header;
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&raw_header, 1, sizeof(raw_header), ctx->file) != sizeof(raw_header)) {
        fprintf(stderr, "Failed to read INI1 header!\n");
        exit(EXIT_FAILURE);
    }

    if (raw_header.magic != MAGIC_INI1 || raw_header.num_processes > INI1_MAX_KIPS) {
        printf("Error: INI1 is corrupt!\n");
        exit(EXIT_FAILURE);
    }

    ctx->header = malloc(raw_header.size);
    if (ctx->header == NULL) {
        fprintf(stderr, "Failed to allocate INI1 header!\n");
        exit(EXIT_FAILURE);
    }

    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(ctx->header, 1, raw_header.size, ctx->file) != raw_header.size) {
        fprintf(stderr, "Failed to read INI1!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t offset = 0;
    for (unsigned int i = 0; i < ctx->header->num_processes; i++) {
        ctx->kips[i].tool_ctx = ctx->tool_ctx;
        ctx->kips[i].header = (kip1_header_t *)&ctx->header->kip_data[offset];
        if (ctx->kips[i].header->magic != MAGIC_KIP1) {
            fprintf(stderr, "INI1 is corrupted!\n");
            exit(EXIT_FAILURE);
        }
        offset += kip1_get_size(&ctx->kips[i]);
    }

    if (ctx->tool_ctx->action & ACTION_INFO) {
        ini1_print(ctx);
    }

    if (ctx->tool_ctx->action & ACTION_EXTRACT) {
        ini1_save(ctx);
    }
}

void ini1_print(ini1_ctx_t *ctx) {
    printf("INI1:\n");
    printf("    Number of Processes:            %02"PRIx32"\n", ctx->header->num_processes);
    printf("    Size:                           %08"PRIx32"\n", ctx->header->size);
    printf("\n");
    for (unsigned int i = 0; i < ctx->header->num_processes; i++) {
        printf("Process %02"PRIx32":\n", i);
        kip1_print(&ctx->kips[i], 1);
        printf("\n");
    }
    printf("\n");
}

void ini1_save(ini1_ctx_t *ctx) {
    filepath_t *dirpath = NULL;
    if (ctx->tool_ctx->file_type == FILETYPE_INI1 && ctx->tool_ctx->settings.out_dir_path.enabled) {
        dirpath = &ctx->tool_ctx->settings.out_dir_path.path;
    }
    if (dirpath == NULL || dirpath->valid != VALIDITY_VALID) {
        dirpath = &ctx->tool_ctx->settings.ini1_dir_path;
    }
    if (dirpath != NULL && dirpath->valid == VALIDITY_VALID) {
        os_makedir(dirpath->os_path);
        for (unsigned int i = 0; i < ctx->header->num_processes; i++) {
            char padded_name[0x20];
            memset(&padded_name, 0, sizeof(padded_name));
            memcpy(&padded_name, ctx->kips[i].header->name, sizeof(ctx->kips[i].header->name));
            strcat(padded_name, ".kip1");
            printf("Saving %s to %s/%s...\n", padded_name, dirpath->char_path, padded_name);
            save_buffer_to_directory_file(ctx->kips[i].header, kip1_get_size(&ctx->kips[i]), dirpath, padded_name);
            if (ctx->tool_ctx->action & ACTION_SAVEINIJSON) {
                printf("SAVING INI JSON!\n");
                memset(&padded_name, 0, sizeof(padded_name));
                memcpy(&padded_name, ctx->kips[i].header->name, sizeof(ctx->kips[i].header->name));
                strcat(padded_name, ".json");
                filepath_t json_path;
                filepath_init(&json_path);
                filepath_copy(&json_path, dirpath);
                filepath_append(&json_path, padded_name);
                FILE *f_json = os_fopen(json_path.os_path, OS_MODE_WRITE);
                if (f_json == NULL) {
                    fprintf(stderr, "Failed to open %s!\n", json_path.char_path);
                    return;
                }
                const char *json = kip1_get_json(&ctx->kips[i]);
                if (fwrite(json, 1, strlen(json), f_json) != strlen(json)) {
                    fprintf(stderr, "Failed to write JSON file!\n");
                    exit(EXIT_FAILURE);
                }
                fclose(f_json);
            }
        }
    }
}

char *kip1_get_json(kip1_ctx_t *ctx) {
    cJSON *kip_json = cJSON_CreateObject();
    char *output_str = NULL;
    char work_buffer[0x300] = {0};

    /* Add KIP1 header fields. */
    strcpy(work_buffer, ctx->header->name);
    cJSON_AddStringToObject(kip_json, "name", work_buffer);
    cJSON_AddU64ToObject(kip_json, "title_id", ctx->header->title_id);
    cJSON_AddU32ToObject(kip_json, "main_thread_stack_size", ctx->header->section_headers[1].attribute);
    cJSON_AddNumberToObject(kip_json, "main_thread_priority", ctx->header->main_thread_priority);
    cJSON_AddNumberToObject(kip_json, "default_cpu_id", ctx->header->default_core);
    cJSON_AddNumberToObject(kip_json, "process_category", ctx->header->process_category);

     /* Add KAC. */
    cJSON *kac_json = kac_get_json(ctx->header->capabilities, sizeof(ctx->header->capabilities) / sizeof(uint32_t));
    cJSON_AddItemToObject(kip_json, "kernel_capabilities", kac_json);

    output_str = cJSON_Print(kip_json);

    cJSON_Delete(kip_json);
    return output_str;
}

static void kip1_blz_uncompress(void *hdr_end) {
    uint32_t addl_size = ((uint32_t *)hdr_end)[-1];
    uint32_t header_size = ((uint32_t *)hdr_end)[-2];
    uint32_t cmp_and_hdr_size = ((uint32_t *)hdr_end)[-3];

    unsigned char *cmp_start = (unsigned char *)(((uintptr_t)hdr_end) - cmp_and_hdr_size);
    uint32_t cmp_ofs = cmp_and_hdr_size - header_size;
    uint32_t out_ofs = cmp_and_hdr_size + addl_size;

    while (out_ofs) {
        unsigned char control = cmp_start[--cmp_ofs];
        for (unsigned int i = 0; i < 8; i++) {
            if (control & 0x80) {
                if (cmp_ofs < 2) {
                    fprintf(stderr, "KIP1 decompression out of bounds!\n");
                    exit(EXIT_FAILURE);
                }
                cmp_ofs -= 2;
                uint16_t seg_val = ((unsigned int)cmp_start[cmp_ofs+1] << 8) | cmp_start[cmp_ofs];
                uint32_t seg_size = ((seg_val >> 12) & 0xF) + 3;
                uint32_t seg_ofs = (seg_val & 0x0FFF) + 3;
                if (out_ofs < seg_size) {
                    /* Kernel restricts segment copy to stay in bounds. */
                    seg_size = out_ofs;
                }
                out_ofs -= seg_size;

                for (unsigned int j = 0; j < seg_size; j++) {
                    cmp_start[out_ofs + j] = cmp_start[out_ofs + j + seg_ofs];
                }
            } else {
                /* Copy directly. */
                if (cmp_ofs < 1) {
                    fprintf(stderr, "KIP1 decompression out of bounds!\n");
                    exit(EXIT_FAILURE);
                }
                cmp_start[--out_ofs] = cmp_start[--cmp_ofs];
            }
            control <<= 1;
            if (out_ofs == 0) {
                return;
            }
        }
    }
}

static void *kip1_uncompress(kip1_ctx_t *ctx, uint64_t *size) {
    /* Make new header with correct sizes, fixed flags. */
    kip1_header_t new_header = *ctx->header;
    for (unsigned int i = 0; i < 3; i++) {
        new_header.section_headers[i].compressed_size = new_header.section_headers[i].out_size;
    }
    new_header.flags &= 0xF8;

    *size = kip1_get_size_from_header(&new_header);
    unsigned char *new_kip = calloc(1, *size);
    if (new_kip == NULL) {
        fprintf(stderr, "Failed to allocate uncompressed KIP1!\n");
        exit(EXIT_FAILURE);
    }
    *((kip1_header_t *)new_kip) = new_header;

    uint64_t new_offset = 0x100;
    uint64_t old_offset = 0x100;
    for (unsigned int i = 0; i < 3; i++) {
        // Copy in section data */
        memcpy(new_kip + new_offset, (unsigned char *)ctx->header + old_offset, ctx->header->section_headers[i].compressed_size);
        if (ctx->header->flags & (1 << i)) {
            kip1_blz_uncompress(new_kip + new_offset + ctx->header->section_headers[i].compressed_size);
        }
        new_offset += ctx->header->section_headers[i].out_size;
        old_offset += ctx->header->section_headers[i].compressed_size;
    }

    return new_kip;
}

void kip1_process(kip1_ctx_t *ctx) {
    /* Read *just* safe amount. */
    kip1_header_t raw_header;
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&raw_header, 1, sizeof(raw_header), ctx->file) != sizeof(raw_header)) {
        fprintf(stderr, "Failed to read KIP1 header!\n");
        exit(EXIT_FAILURE);
    }

    if (raw_header.magic != MAGIC_KIP1) {
        printf("Error: KIP1 is corrupt!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t size = kip1_get_size_from_header(&raw_header);
    ctx->header = malloc(size);
    if (ctx->header == NULL) {
        fprintf(stderr, "Failed to allocate KIP1!\n");
        exit(EXIT_FAILURE);
    }

    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(ctx->header, 1, size, ctx->file) != size) {
        fprintf(stderr, "Failed to read KIP1!\n");
        exit(EXIT_FAILURE);
    }

    if (ctx->tool_ctx->action & ACTION_INFO) {
        kip1_print(ctx, 0);
    }

    if (ctx->tool_ctx->action & ACTION_EXTRACT) {
        kip1_save(ctx);
    }
}

void kip1_print(kip1_ctx_t *ctx, int suppress) {
    if (!suppress) printf("KIP1:\n");
    printf("    Title ID:                       %016"PRIx64"\n", ctx->header->title_id);
    char padded_name[13];
    memset(&padded_name, 0, sizeof(padded_name));
    memcpy(&padded_name, ctx->header->name, sizeof(ctx->header->name));
    printf("    Name:                           %s\n", padded_name);
    printf("    Process Category:               %s\n", npdm_get_proc_category(ctx->header->process_category));
    printf("    Main Thread Priority:           %"PRId8"\n", ctx->header->main_thread_priority);
    printf("    Default CPU Core:               %"PRId8"\n", ctx->header->default_core);
    printf("    Is 64 Bit:                      %s\n", (ctx->header->flags & (1 << 3)) ? "True" : "False");
    printf("    Is Address Space 64 Bit:        %s\n", (ctx->header->flags & (1 << 4)) ? "True" : "False");
    printf("    Sections:\n");
    printf("        .text:                      %08"PRIx32"-%08"PRIx32"\n", ctx->header->section_headers[0].out_offset, ctx->header->section_headers[0].out_offset + align(ctx->header->section_headers[0].out_size, 0x1000));
    printf("        .rodata:                    %08"PRIx32"-%08"PRIx32"\n", ctx->header->section_headers[1].out_offset, ctx->header->section_headers[1].out_offset + align(ctx->header->section_headers[1].out_size, 0x1000));
    printf("        .rwdata:                    %08"PRIx32"-%08"PRIx32"\n", ctx->header->section_headers[2].out_offset, ctx->header->section_headers[2].out_offset + ctx->header->section_headers[2].out_size);
    printf("        .bss:                       %08"PRIx32"-%08"PRIx32"\n", ctx->header->section_headers[2].out_offset + ctx->header->section_headers[2].out_size, align(ctx->header->section_headers[3].out_offset + ctx->header->section_headers[3].out_size, 0x1000));
    printf("    Kernel Access Control:\n");
    kac_print(ctx->header->capabilities, 0x20);
    printf("\n");
}

void kip1_save(kip1_ctx_t *ctx) {
    filepath_t *json_path = &ctx->tool_ctx->settings.npdm_json_path;
    filepath_t *uncmp_path = &ctx->tool_ctx->settings.uncompressed_path;
    if (ctx->tool_ctx->file_type == FILETYPE_KIP1) {
        if (json_path->valid == VALIDITY_VALID) {
            FILE *f_json = os_fopen(json_path->os_path, OS_MODE_WRITE);
            if (f_json == NULL) {
                fprintf(stderr, "Failed to open %s!\n", json_path->char_path);
                return;
            }
            char *json = kip1_get_json(ctx);
            if (json == NULL) {
                fprintf(stderr, "Failed to allocate KIP1 JSON\n");
                exit(EXIT_FAILURE);
            }
            if (fwrite(json, 1, strlen(json), f_json) != strlen(json)) {
                fprintf(stderr, "Failed to write JSON file!\n");
                exit(EXIT_FAILURE);
            }
            cJSON_free(json);
            fclose(f_json);
        }

        if (uncmp_path->valid == VALIDITY_VALID) {
            FILE *f_uncmp = os_fopen(uncmp_path->os_path, OS_MODE_WRITE);
            if (f_uncmp == NULL) {
                fprintf(stderr, "Failed to open %s!\n", uncmp_path->char_path);
                return;
            }
            uint64_t sz = 0;
            void *uncmp = kip1_uncompress(ctx, &sz);
            if (fwrite(uncmp, 1, sz, f_uncmp) != sz) {
                fprintf(stderr, "Failed to write uncompressed kip!\n");
                exit(EXIT_FAILURE);
            }
            free(uncmp);
            fclose(f_uncmp);
        }
    }
}

/* BLZ (Backward LZ77) compressor for a single KIP1 section.
 *
 * The decompressor (kip1_blz_uncompress) reads the compressed buffer
 * BACKWARD: cmp_ofs starts at the end and decrements toward 0.  The
 * compressor must therefore write its output BACKWARD too — the control
 * byte and its associated literal/reference bytes must appear at
 * DECREASING buffer addresses so that the decompressor reads them in the
 * correct order.
 *
 * Layout of one group (8 operations) as seen by the decompressor (highest
 * address first):
 *   ctrl_byte | op7_hi [op7_lo] | op6_byte | op5_hi [op5_lo] | ...
 *
 * For a back-reference the two bytes are:
 *   hi = ((len-3) << 4) | ((ofs-3) >> 8)
 *   lo = (ofs-3) & 0xFF
 * and hi is at the higher address (read first by decompressor as
 * cmp_start[cmp_ofs+1]), lo at the lower address (cmp_start[cmp_ofs]).
 *
 * Returns a malloc'd buffer (caller must free) with compressed data + 12-byte
 * footer, sets *out_size.  Returns NULL if compression yields no benefit. */
static void *kip1_blz_compress_section(const uint8_t *src, uint32_t src_size,
                                        uint32_t *out_size) {
    if (src_size == 0) { *out_size = 0; return NULL; }

    /* Worst case: all literals → 1 control byte per 8 data bytes */
    uint32_t max_cmp = src_size + (src_size + 7) / 8 + 16; /* +16 extra safety */
    uint8_t *cmp = (uint8_t *)calloc(1, max_cmp);
    if (!cmp) return NULL;

    /* Write backward: write_pos decrements from max_cmp toward 0.
     * The compressed data occupies cmp[write_pos..max_cmp-1] when done. */
    uint32_t write_pos = max_cmp;
    int32_t  pos = (int32_t)src_size;  /* next byte to emit, decrements toward 0 */

    while (pos > 0) {
        /* Collect up to 8 operations for this group */
        uint8_t ctrl = 0;
        uint8_t group_data[8 * 2]; /* at most 2 bytes per op (back-ref) */
        int     gd_len = 0;

        for (int bit = 7; bit >= 0 && pos > 0; bit--) {
            /* Search for a back-reference.  A match of length L at offset O means:
             *   src[pos-1-k] == src[pos-1-k+O]  for k in [0, L-1]
             * (we're working backward; the match source is O positions ahead in
             * the buffer, i.e. at a higher address / already emitted region). */
            uint32_t best_len = 0, best_ofs = 0;
            uint32_t max_ofs  = (uint32_t)(src_size - pos);
            if (max_ofs > 4098) max_ofs = 4098;

            if (max_ofs >= 3) {
                for (uint32_t ofs = 3; ofs <= max_ofs; ofs++) {
                    uint32_t max_len = ((uint32_t)pos < 18u) ? (uint32_t)pos : 18u;
                    uint32_t len = 0;
                    while (len < max_len &&
                           src[pos - 1 - len] == src[pos - 1 - len + ofs])
                        len++;
                    if (len > best_len) {
                        best_len = len;
                        best_ofs = ofs;
                        if (best_len == 18) break;
                    }
                }
            }

            if (best_len >= 3) {
                ctrl |= (1u << bit);
                /* hi byte: upper 4 bits = (len-3), lower 4 bits = high nibble of (ofs-3)
                 * lo byte: lower 8 bits of (ofs-3)
                 * Decompressor reads hi at cmp_start[cmp_ofs+1], lo at cmp_start[cmp_ofs].
                 * Writing backward: hi goes at higher address (first write), lo at lower. */
                uint8_t hi = (uint8_t)(((best_len - 3u) << 4) | (((best_ofs - 3u) >> 8) & 0xFu));
                uint8_t lo = (uint8_t)((best_ofs - 3u) & 0xFFu);
                group_data[gd_len++] = hi;
                group_data[gd_len++] = lo;
                pos -= (int32_t)best_len;
            } else {
                group_data[gd_len++] = src[--pos];
            }
        }

        /* Write this group backward into cmp[]:
         * ctrl byte goes at the highest position (first written → highest --write_pos),
         * then group_data bytes at consecutively lower positions.
         * Decompressor reads highest-address byte first (as ctrl), then decrements. */
        if (write_pos < (uint32_t)(1 + gd_len)) {
            free(cmp);
            return NULL; /* shouldn't happen with correct max_cmp */
        }
        cmp[--write_pos] = ctrl;
        for (int i = 0; i < gd_len; i++)
            cmp[--write_pos] = group_data[i];
    }

    /* Compressed data occupies cmp[write_pos..max_cmp-1] */
    uint32_t cmp_data_size = max_cmp - write_pos;
    uint32_t total         = cmp_data_size + 12;

    if (total >= src_size) {
        free(cmp);
        *out_size = 0;
        return NULL;
    }

    uint8_t *result = (uint8_t *)malloc(total);
    if (!result) { free(cmp); return NULL; }

    memcpy(result, cmp + write_pos, cmp_data_size);
    free(cmp);

    /* 12-byte footer: [cmp_and_hdr_size][header_size=12][addl_size]
     * cmp_and_hdr_size = total (includes footer)
     * addl_size = src_size - cmp_data_size  (extra buffer space for decompressor) */
    uint32_t *footer = (uint32_t *)(result + cmp_data_size);
    footer[0] = total;
    footer[1] = 12;
    footer[2] = src_size - cmp_data_size;

    *out_size = total;
    return result;
}

/* Re-compress a decompressed KIP1 (flags bits 0-2 all clear) back to a compressed
 * KIP1.  Each section is BLZ-compressed; if a section does not shrink it is left
 * uncompressed.  Returns a malloc'd buffer (caller must free) with the full
 * re-compressed KIP1, sets *out_size.  Returns NULL on failure.
 * Use kip1_blz_compress_section / SHA256 of the result as the canonical module ID
 * when only a decompressed KIP1 is available. */
void *kip1_recompress_buf(const void *src, size_t src_size, size_t *out_size) {
    if (src_size < sizeof(kip1_header_t)) return NULL;
    const kip1_header_t *hdr = (const kip1_header_t *)src;
    if (hdr->magic != MAGIC_KIP1) return NULL;

    /* Build the new compressed KIP1 in a temporary buffer.
     * Worst case size = original decompressed KIP1 size (nothing compresses). */
    uint8_t *result = (uint8_t *)calloc(1, src_size + 128); /* +128 for safety */
    if (!result) return NULL;

    kip1_header_t new_hdr = *hdr;

    const uint8_t *sec_data = (const uint8_t *)src + 0x100;
    uint32_t       write_ofs = 0x100;
    uint32_t       read_ofs  = 0;

    for (unsigned int i = 0; i < 3; i++) {
        uint32_t sec_size = hdr->section_headers[i].out_size;

        if (sec_size == 0) {
            new_hdr.section_headers[i].compressed_size = 0;
            read_ofs += 0;
            continue;
        }

        uint32_t cmp_size = 0;
        void *cmp = kip1_blz_compress_section(sec_data + read_ofs, sec_size, &cmp_size);

        if (cmp && cmp_size < sec_size) {
            /* Use compressed version */
            new_hdr.section_headers[i].compressed_size = cmp_size;
            new_hdr.flags |= (1u << i);
            memcpy(result + write_ofs, cmp, cmp_size);
            write_ofs += cmp_size;
            free(cmp);
        } else {
            /* Section does not compress — store as-is */
            if (cmp) free(cmp);
            new_hdr.section_headers[i].compressed_size = sec_size;
            new_hdr.flags &= ~(1u << i);
            memcpy(result + write_ofs, sec_data + read_ofs, sec_size);
            write_ofs += sec_size;
        }

        read_ofs += sec_size;
    }

    /* Copy in the new header */
    *((kip1_header_t *)result) = new_hdr;

    *out_size = write_ofs;
    return result;
}

void *kip1_decompress_buf(const void *src, size_t src_size, size_t *out_size) {
    if (src_size < sizeof(kip1_header_t)) return NULL;
    const kip1_header_t *hdr = (const kip1_header_t *)src;
    if (hdr->magic != MAGIC_KIP1) return NULL;

    kip1_header_t new_hdr = *hdr;
    for (unsigned int i = 0; i < 3; i++)
        new_hdr.section_headers[i].compressed_size = new_hdr.section_headers[i].out_size;
    new_hdr.flags &= 0xF8;

    uint64_t new_size = kip1_get_size_from_header(&new_hdr);
    unsigned char *out = calloc(1, (size_t)new_size);
    if (out == NULL) return NULL;
    *((kip1_header_t *)out) = new_hdr;

    uint64_t new_ofs = 0x100;
    uint64_t old_ofs = 0x100;
    for (unsigned int i = 0; i < 3; i++) {
        uint32_t cmp_sz = hdr->section_headers[i].compressed_size;
        uint32_t out_sz = hdr->section_headers[i].out_size;
        memcpy(out + new_ofs, (const unsigned char *)src + old_ofs, cmp_sz);
        if (hdr->flags & (1u << i))
            kip1_blz_uncompress(out + new_ofs + cmp_sz);
        new_ofs += out_sz;
        old_ofs += cmp_sz;
    }

    if (out_size != NULL) *out_size = (size_t)new_size;
    return out;
}
