#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "nsp.h"
#include "utils.h"
#include "extkeys.h"
#include "filepath.h"
#include "nca.h"

/* Return a human-readable type label for an NSP file entry. */
static const char *nsp_file_label(const char *name) {
    size_t len = strlen(name);
    /* Check .cnmt.nca before .nca — order matters. */
    if (len > 8 && strcmp(name + len - 9, ".cnmt.nca") == 0) return "CNMT NCA";
    if (len > 3 && strcmp(name + len - 4, ".nca") == 0)      return "NCA";
    if (len > 3 && strcmp(name + len - 4, ".tik") == 0)      return "Ticket";
    if (len > 4 && strcmp(name + len - 5, ".cert") == 0)     return "Certificate";
    if (len > 3 && strcmp(name + len - 4, ".xml") == 0)      return "XML";
    if (len > 4 && strcmp(name + len - 5, ".cnmt") == 0)     return "CNMT";
    if (len > 3 && strcmp(name + len - 4, ".nsp") == 0)      return "NSP";
    return "";
}

/*
 * Scan all .tik entries and register any titlekeys found.
 * The titlekey (16 bytes) is at TICKET_TITLEKEY_OFFSET.
 * The rights ID (16 bytes) is at TICKET_RIGHTS_ID_OFFSET.
 */
static void nsp_scan_tickets(nsp_ctx_t *ctx) {
    pfs0_ctx_t *pfs = &ctx->pfs0_ctx;
    uint64_t data_base = pfs0_get_header_size(pfs->header);

    for (uint32_t i = 0; i < pfs->header->num_files; i++) {
        const char *name = pfs0_get_file_name(pfs->header, i);
        size_t len = strlen(name);
        if (len < 4 || strcmp(name + len - 4, ".tik") != 0) continue;

        pfs0_file_entry_t *entry = pfs0_get_file_entry(pfs->header, i);
        if (entry->size < TICKET_MIN_SIZE) {
            fprintf(stderr, "[NSP] Ticket %s too small (0x%"PRIx64" bytes), skipping\n",
                    name, entry->size);
            continue;
        }

        uint8_t tik_buf[TICKET_MIN_SIZE];
        fseeko64(ctx->file, (long long)(data_base + entry->offset), SEEK_SET);
        if (fread(tik_buf, 1, TICKET_MIN_SIZE, ctx->file) != TICKET_MIN_SIZE) {
            fprintf(stderr, "[NSP] Failed to read ticket %s\n", name);
            continue;
        }

        const uint8_t *titlekey  = tik_buf + TICKET_TITLEKEY_OFFSET;
        const uint8_t *rights_id = tik_buf + TICKET_RIGHTS_ID_OFFSET;

        /* Skip tickets with all-zero rights ID. */
        int all_zero = 1;
        for (int j = 0; j < 0x10; j++) {
            if (rights_id[j]) { all_zero = 0; break; }
        }
        if (all_zero) continue;

        if (!settings_has_titlekey(&ctx->tool_ctx->settings, rights_id)) {
            settings_add_titlekey(&ctx->tool_ctx->settings, rights_id, titlekey);
        }
    }
}

/* Return non-zero if any NCA content output directories are configured. */
static int nsp_has_nca_output(nsp_ctx_t *ctx) {
    hactool_settings_t *s = &ctx->tool_ctx->settings;
    if (s->exefs_dir_path.enabled) return 1;
    if (s->romfs_dir_path.enabled) return 1;
    for (int i = 0; i < 4; i++) {
        if (s->section_dir_paths[i].valid == VALIDITY_VALID) return 1;
    }
    return 0;
}

/*
 * If --exefsdir / --romfsdir were not explicitly set but a base extraction
 * directory (--outdir or --pfs0dir) was given, auto-configure
 * <basepath>/exefs and <basepath>/romfs so that nca_process extracts them.
 */
static void nsp_auto_nca_dirs(nsp_ctx_t *ctx, filepath_t *basepath) {
    hactool_settings_t *s = &ctx->tool_ctx->settings;
    if (basepath == NULL || basepath->valid != VALIDITY_VALID) return;
    if (!s->exefs_dir_path.enabled) {
        filepath_copy(&s->exefs_dir_path.path, basepath);
        filepath_append(&s->exefs_dir_path.path, "exefs");
        s->exefs_dir_path.enabled = 1;
    }
    if (!s->romfs_dir_path.enabled) {
        filepath_copy(&s->romfs_dir_path.path, basepath);
        filepath_append(&s->romfs_dir_path.path, "romfs");
        s->romfs_dir_path.enabled = 1;
    }
}

/*
 * Find and process the primary NCA from within the NSP file.
 *
 * The primary NCA is the largest non-CNMT NCA — in standard NSPs this is
 * always the Program NCA containing ExeFS (section 0) and optionally RomFS
 * (section 1).  This matches the Python reference: nca_files are sorted by
 * size and the first non-CNMT entry is treated as primary.
 *
 * The NCA is read directly from the NSP file via file_offset, so no
 * intermediate extraction to disk is needed.  Titlekeys registered by
 * nsp_scan_tickets are already in tool_ctx->settings.known_titlekeys.
 */
static void nsp_process_ncas_direct(nsp_ctx_t *ctx) {
    pfs0_header_t *hdr = ctx->pfs0_ctx.header;
    uint64_t data_base = pfs0_get_header_size(hdr);

    /* Find the largest non-CNMT NCA (= primary / Program NCA). */
    uint32_t primary_idx = UINT32_MAX;
    uint64_t primary_size = 0;

    for (uint32_t i = 0; i < hdr->num_files; i++) {
        const char *name = pfs0_get_file_name(hdr, i);
        size_t len = strlen(name);
        if (len < 4  || strcmp(name + len - 4, ".nca") != 0) continue;
        if (len > 8  && strcmp(name + len - 9, ".cnmt.nca") == 0) continue;

        pfs0_file_entry_t *entry = pfs0_get_file_entry(hdr, i);
        if (entry->size > primary_size) {
            primary_size = entry->size;
            primary_idx  = i;
        }
    }

    if (primary_idx == UINT32_MAX) {
        fprintf(stderr, "[NSP] No program NCA found in NSP.\n");
        return;
    }

    const char *name = pfs0_get_file_name(hdr, primary_idx);
    pfs0_file_entry_t *entry = pfs0_get_file_entry(hdr, primary_idx);

    printf("[NSP] Processing primary NCA: %s\n", name);

    nca_ctx_t nca_ctx;
    nca_init(&nca_ctx);
    nca_ctx.file        = ctx->file;
    nca_ctx.file_offset = data_base + entry->offset;
    nca_ctx.file_size   = entry->size;
    nca_ctx.tool_ctx    = ctx->tool_ctx;
    nca_ctx.is_cli_target = 1;

    nca_process(&nca_ctx);
    nca_free_section_contexts(&nca_ctx);
    /* Do not fclose — ctx->file is owned by the NSP context. */
}

void nsp_process(nsp_ctx_t *ctx) {
    /* Load PFS0 header. */
    pfs0_header_t raw_header;
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(&raw_header, 1, sizeof(raw_header), ctx->file) != sizeof(raw_header)) {
        fprintf(stderr, "Failed to read NSP header!\n");
        exit(EXIT_FAILURE);
    }
    if (raw_header.magic != MAGIC_PFS0) {
        fprintf(stderr, "Error: NSP is corrupt (bad PFS0 magic)!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t header_size = pfs0_get_header_size(&raw_header);
    ctx->pfs0_ctx.header = malloc(header_size);
    if (ctx->pfs0_ctx.header == NULL) {
        fprintf(stderr, "Failed to allocate NSP header!\n");
        exit(EXIT_FAILURE);
    }
    fseeko64(ctx->file, 0, SEEK_SET);
    if (fread(ctx->pfs0_ctx.header, 1, header_size, ctx->file) != header_size) {
        fprintf(stderr, "Failed to read NSP header!\n");
        exit(EXIT_FAILURE);
    }

    ctx->pfs0_ctx.file     = ctx->file;
    ctx->pfs0_ctx.tool_ctx = ctx->tool_ctx;

    /* Register titlekeys from .tik files before anything else. */
    nsp_scan_tickets(ctx);

    if (ctx->tool_ctx->action & ACTION_INFO) {
        nsp_print(ctx);
    }
    if (ctx->tool_ctx->action & ACTION_EXTRACT) {
        nsp_save(ctx);
    }
}

void nsp_print(nsp_ctx_t *ctx) {
    pfs0_header_t *hdr = ctx->pfs0_ctx.header;
    uint64_t data_base = pfs0_get_header_size(hdr);

    printf("\nNSP:\n");
    print_magic("    Magic:                          ", hdr->magic);
    printf("    Number of files:                %"PRIu32"\n", hdr->num_files);
    if (hdr->num_files > 0) {
        printf("    Files:\n");
        for (uint32_t i = 0; i < hdr->num_files; i++) {
            pfs0_file_entry_t *f = pfs0_get_file_entry(hdr, i);
            const char *name  = pfs0_get_file_name(hdr, i);
            const char *label = nsp_file_label(name);
            uint64_t abs_start = data_base + f->offset;
            uint64_t abs_end   = abs_start + f->size;
            if (label[0] != '\0') {
                printf("        nsp:/%-48s %012"PRIx64"-%012"PRIx64" (%"PRIu64" bytes) [%s]\n",
                       name, abs_start, abs_end, f->size, label);
            } else {
                printf("        nsp:/%-48s %012"PRIx64"-%012"PRIx64" (%"PRIu64" bytes)\n",
                       name, abs_start, abs_end, f->size);
            }
        }
    }
}

void nsp_save(nsp_ctx_t *ctx) {
    /* Resolve base extraction directory (--outdir takes priority over --pfs0dir). */
    filepath_t *dirpath = NULL;
    if (ctx->tool_ctx->settings.out_dir_path.enabled) {
        dirpath = &ctx->tool_ctx->settings.out_dir_path.path;
    }
    if (dirpath == NULL || dirpath->valid != VALIDITY_VALID) {
        dirpath = &ctx->tool_ctx->settings.pfs0_dir_path;
    }

    /* Extract container files to disk. */
    if (dirpath != NULL && dirpath->valid == VALIDITY_VALID) {
        pfs0_header_t *hdr = ctx->pfs0_ctx.header;
        uint64_t data_base = pfs0_get_header_size(hdr);
        os_makedir(dirpath->os_path);
        for (uint32_t i = 0; i < hdr->num_files; i++) {
            pfs0_file_entry_t *f = pfs0_get_file_entry(hdr, i);
            const char *name = pfs0_get_file_name(hdr, i);
            filepath_t fp;
            filepath_copy(&fp, dirpath);
            filepath_append(&fp, "%s", name);
            printf("Saving %s to %s...\n", name, fp.char_path);
            save_file_section(ctx->file, data_base + f->offset, f->size, &fp);
        }

        /* Auto-create exefs/ and romfs/ under the base dir when not explicitly set. */
        nsp_auto_nca_dirs(ctx, dirpath);
    }

    /* Process NCAs in-place (reads directly from the NSP file). */
    if (nsp_has_nca_output(ctx)) {
        nsp_process_ncas_direct(ctx);
    }
}
