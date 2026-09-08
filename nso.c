#include <string.h>
#include "nso.h"
#include "lz4.h"
#include "sha.h"
#include "zstd.h"

int nso0_decompress_segment(void *dst, size_t decomp_size,
                             const void *src, size_t comp_size,
                             int is_zbic) {
    if (is_zbic) {
        size_t ret = ZSTD_decompress(dst, decomp_size, src, comp_size);
        if (ZSTD_isError(ret) || ret != decomp_size) {
            fprintf(stderr,
                "    [zbic] decompress failed: %s (raw=%zu), "
                "comp_size=%zu decl_decomp_size=%zu\n",
                ZSTD_isError(ret) ? ZSTD_getErrorName(ret) : "size mismatch",
                ret, comp_size, decomp_size);
            return 0;
        }
        return 1;
    } else {
        return LZ4_decompress_safe((const char *)src, (char *)dst,
                   (int)comp_size, (int)decomp_size) == (int)decomp_size;
    }
}

static void *nso_uncompress(nso0_ctx_t *ctx) {
    /* Make new header with correct sizes, fixed flags. */
    nso0_header_t new_header = *ctx->header;
    for (unsigned int i = 0; i < 3; i++) {
        new_header.segments[i].file_off = new_header.segments[i].dst_off + sizeof(nso0_header_t);
        new_header.compressed_sizes[i] = new_header.segments[i].decomp_size;
    }
    /* Clear module offset/size. */
    new_header.segments[0].align_or_total_size = 0x100;
    new_header.segments[1].align_or_total_size = 0;
    /* Clear compression flags. */
    new_header.flags &= 0x78;

    uint64_t size = nso_get_size(&new_header);
    nso0_header_t *new_nso = calloc(1, size);
    if (new_nso == NULL) {
        fprintf(stderr, "Failed to allocate uncompressed NSO0!\n");
        exit(EXIT_FAILURE);
    }
    *((nso0_header_t *)new_nso) = new_header;

    for (unsigned int segment = 0; segment < 3; segment++) {
        char *src = (char *)ctx->header + ctx->header->segments[segment].file_off;
        char *dst = (char *)new_nso + new_header.segments[segment].file_off;
                if ((ctx->header->flags >> segment) & 1) {
            int is_zbic = (ctx->header->flags & NSO_FLAG_ZBIC) != 0;
            if (!nso0_decompress_segment(dst, new_header.segments[segment].decomp_size,
                    src, ctx->header->compressed_sizes[segment], is_zbic)) {
                fprintf(stderr, "Error: Failed to decompress NSO0 segment %u (%s)!\n",
                    segment, is_zbic ? "zbic" : "lz4");
                exit(EXIT_FAILURE);
            }
        } else {
            memcpy(dst, src, new_header.segments[segment].decomp_size);
        }
        if ((ctx->tool_ctx->action & ACTION_VERIFY) && ((ctx->header->flags >> (segment + 3)) & 1)) {
            unsigned char calc_hash[0x20];
            sha256_hash_buffer(calc_hash, dst, new_header.segments[segment].decomp_size);
            if (memcmp(calc_hash, new_header.section_hashes[segment], sizeof(calc_hash)) == 0) {
                ctx->segment_validities[segment] = VALIDITY_VALID;
            } else {
                ctx->segment_validities[segment] = VALIDITY_INVALID;
            }
        }
    }

    return new_nso;
}

void nso0_process(nso0_ctx_t *ctx) {
    /* Read *just* safe amount. */
    nso0_header_t raw_header;
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&raw_header, 1, sizeof(raw_header), ctx->file) != sizeof(raw_header)) {
        fprintf(stderr, "Failed to read NSO0 header!\n");
        exit(EXIT_FAILURE);
    }

    if (raw_header.magic != MAGIC_NSO0) {
        printf("Error: NSO0 is corrupt!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t size = nso_get_size(&raw_header);
    ctx->header = malloc(size);
    if (ctx->header == NULL) {
        fprintf(stderr, "Failed to allocate NSO0!\n");
        exit(EXIT_FAILURE);
    }

    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(ctx->header, 1, size, ctx->file) != size) {
        fprintf(stderr, "Failed to read NSO0!\n");
        exit(EXIT_FAILURE);
    }

    ctx->uncompressed_header = nso_uncompress(ctx);

    if (ctx->tool_ctx->action & ACTION_INFO) {
        nso0_print(ctx);
    }

    if (ctx->tool_ctx->action & ACTION_EXTRACT) {
        nso0_save(ctx);
    }
}

const char *nso0_segment_algorithm_str(nso0_header_t *header, unsigned int segment) {
    if (!((header->flags >> segment) & 1)) {
        return "Uncompressed";
    }
    return (header->flags & NSO_FLAG_ZBIC) ? "ZBIC (zstd)" : "LZ4";
}

void nso0_print(nso0_ctx_t *ctx) {
    printf("NSO0:\n");
    memdump(stdout, "    Build Id:                       ", ctx->header->build_id, 0x20);

    static const char *seg_names[3] = { ".text", ".rodata", ".rwdata" };
    printf("    Compression:\n");
    for (unsigned int i = 0; i < 3; i++) {
        int is_compressed = (ctx->header->flags >> i) & 1;
        if (is_compressed) {
            printf("        %-8s%-14s(0x%08"PRIx32" -> 0x%08"PRIx32" bytes)\n",
                seg_names[i],
                nso0_segment_algorithm_str(ctx->header, i),
                ctx->header->compressed_sizes[i],
                ctx->header->segments[i].decomp_size);
        } else {
            printf("        %-8s%s\n", seg_names[i], nso0_segment_algorithm_str(ctx->header, i));
        }
    }

    printf("    Sections:\n");
    if ((ctx->tool_ctx->action & ACTION_VERIFY) && ctx->segment_validities[0] != VALIDITY_UNCHECKED) {
        printf("        .text   (%s):             %08"PRIx32"-%08"PRIx32"\n", GET_VALIDITY_STR(ctx->segment_validities[0]), ctx->header->segments[0].dst_off, ctx->header->segments[0].dst_off + align(ctx->header->segments[0].decomp_size, 0x1000));
    } else {
        printf("        .text:                      %08"PRIx32"-%08"PRIx32"\n", ctx->header->segments[0].dst_off, ctx->header->segments[0].dst_off + align(ctx->header->segments[0].decomp_size, 0x1000));
    }
    if ((ctx->tool_ctx->action & ACTION_VERIFY) && ctx->segment_validities[1] != VALIDITY_UNCHECKED) {
        printf("        .rodata (%s):             %08"PRIx32"-%08"PRIx32"\n", GET_VALIDITY_STR(ctx->segment_validities[1]), ctx->header->segments[1].dst_off, ctx->header->segments[1].dst_off + align(ctx->header->segments[1].decomp_size, 0x1000));
    } else {
        printf("        .rodata:                    %08"PRIx32"-%08"PRIx32"\n", ctx->header->segments[1].dst_off, ctx->header->segments[1].dst_off + align(ctx->header->segments[1].decomp_size, 0x1000));
    }
    if ((ctx->tool_ctx->action & ACTION_VERIFY) && ctx->segment_validities[2] != VALIDITY_UNCHECKED) {
        printf("        .rwdata (%s):             %08"PRIx32"-%08"PRIx32"\n", GET_VALIDITY_STR(ctx->segment_validities[2]), ctx->header->segments[2].dst_off, ctx->header->segments[2].dst_off + ctx->header->segments[2].decomp_size);
    } else {
        printf("        .rwdata:                    %08"PRIx32"-%08"PRIx32"\n", ctx->header->segments[2].dst_off, ctx->header->segments[2].dst_off + ctx->header->segments[2].decomp_size);
    }
    printf("        .bss:                       %08"PRIx32"-%08"PRIx32"\n", ctx->header->segments[2].dst_off + ctx->header->segments[2].decomp_size, ctx->header->segments[2].dst_off + align(ctx->header->segments[2].decomp_size + ctx->header->segments[2].align_or_total_size, 0x1000));
}

void nso0_save(nso0_ctx_t *ctx) {
    filepath_t *uncmp_path = &ctx->tool_ctx->settings.uncompressed_path;
    if (ctx->tool_ctx->file_type == FILETYPE_NSO0 && uncmp_path->valid == VALIDITY_VALID) {
        FILE *f_uncmp = os_fopen(uncmp_path->os_path, OS_MODE_WRITE);
        if (f_uncmp == NULL) {
            fprintf(stderr, "Failed to open %s!\n", uncmp_path->char_path);
            return;
        }
        if (fwrite(ctx->uncompressed_header, 1, nso_get_size(ctx->uncompressed_header), f_uncmp) != nso_get_size(ctx->uncompressed_header)) {
            fprintf(stderr, "Failed to write uncompressed nso!\n");
            exit(EXIT_FAILURE);
        }
        fclose(f_uncmp);
    }
}

void *nso0_decompress_buf(const void *src, size_t src_size, size_t *out_size) {
    if (src_size < sizeof(nso0_header_t)) return NULL;
    const nso0_header_t *hdr = (const nso0_header_t *)src;
    if (hdr->magic != MAGIC_NSO0) return NULL;

    nso0_header_t new_hdr = *hdr;
    for (unsigned int i = 0; i < 3; i++) {
        new_hdr.segments[i].file_off = new_hdr.segments[i].dst_off + sizeof(nso0_header_t);
        new_hdr.compressed_sizes[i]  = new_hdr.segments[i].decomp_size;
    }
    new_hdr.segments[0].align_or_total_size = 0x100;
    new_hdr.segments[1].align_or_total_size = 0;
    new_hdr.flags &= 0x78;

    uint64_t total = nso_get_size(&new_hdr);
    nso0_header_t *out = calloc(1, (size_t)total);
    if (out == NULL) return NULL;
    *out = new_hdr;

    for (unsigned int seg = 0; seg < 3; seg++) {
        const char *seg_src = (const char *)src + hdr->segments[seg].file_off;
        char       *seg_dst = (char *)out   + new_hdr.segments[seg].file_off;
                if ((hdr->flags >> seg) & 1) {
            int is_zbic = (hdr->flags & NSO_FLAG_ZBIC) != 0;
            if (!nso0_decompress_segment(seg_dst, new_hdr.segments[seg].decomp_size,
                    seg_src, hdr->compressed_sizes[seg], is_zbic)) {
                free(out);
                return NULL;
            }
        } else {
            memcpy(seg_dst, seg_src, new_hdr.segments[seg].decomp_size);
        }
    }

    if (out_size != NULL) *out_size = (size_t)total;
    return out;
}
