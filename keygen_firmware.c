#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#endif
#include <inttypes.h>

#include "keygen_firmware.h"
#include "nca.h"
#include "packages.h"
#include "pk11_extract_key_sources.h"
#include "pki.h"
#include "utils.h"
#include "filepath.h"

#define TITLEID_FS_DATA        0x0100000000000819ULL
#define TITLEID_SYSTEM_VERSION 0x0100000000000809ULL

static const unsigned char keygen_zeroes[0x10] = {0};

/* ── Folder scan ────────────────────────────────────────────────────────── */

typedef struct {
    hactool_ctx_t *tool_ctx;
    char fs_nca_path[MAX_PATH];
    int  fs_nca_found;
    int  sysver_found;
    unsigned char sysver_master_key_rev;
} keygen_scan_ctx_t;

static int keygen_has_suffix(const char *filename, const char *suffix) {
    size_t nlen = strlen(filename);
    size_t slen = strlen(suffix);
    if (nlen < slen) return 0;
    return strcmp(filename + nlen - slen, suffix) == 0;
}

/* Header-only inspection of one NCA: never decrypts sections, never prints
 * or extracts anything. Records whichever of the two title IDs we care
 * about this file matches. */
static void keygen_scan_nca(keygen_scan_ctx_t *sctx, const char *nca_filename, const char *input_path) {
    if (keygen_has_suffix(nca_filename, ".cnmt.nca")) return;
    if (!keygen_has_suffix(nca_filename, ".nca")) return;

    char nca_path[MAX_PATH];
    snprintf(nca_path, sizeof(nca_path), "%s%c%s", input_path, PATH_SEPERATOR, nca_filename);

    FILE *f = fopen(nca_path, "rb");
    if (f == NULL) return;

    fseek(f, 0, SEEK_END);
    size_t fsize = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    hactool_ctx_t silent_ctx = *sctx->tool_ctx;
    silent_ctx.action = 0; /* header-only: nca_decrypt_header never prints or extracts */

    nca_ctx_t inspect_ctx;
    nca_init(&inspect_ctx);
    inspect_ctx.file      = f;
    inspect_ctx.file_size = fsize;
    inspect_ctx.tool_ctx  = &silent_ctx;

    if (!nca_decrypt_header(&inspect_ctx)) {
        fclose(f);
        return;
    }

    uint64_t title_id    = inspect_ctx.header.ProgramId;
    uint8_t  content_type = inspect_ctx.header.ContentType;

    if (title_id == TITLEID_SYSTEM_VERSION && !sctx->sysver_found) {
        /* Same crypto_type computation nca_process() performs. */
        uint8_t ct = inspect_ctx.header.KeyGenerationOld;
        if (inspect_ctx.header.KeyGeneration > ct) ct = inspect_ctx.header.KeyGeneration;
        if (ct) ct--; /* 0, 1 are both master key 0. */
        sctx->sysver_master_key_rev = ct;
        sctx->sysver_found = 1;
        printf("[keygen] Found System Version NCA: %s (Master Key Revision %02x)\n", nca_filename, ct);
    }

    if (title_id == TITLEID_FS_DATA && content_type == NCACONTENTTYPE_DATA && !sctx->fs_nca_found) {
        snprintf(sctx->fs_nca_path, sizeof(sctx->fs_nca_path), "%s", nca_path);
        sctx->fs_nca_found = 1;
        printf("[keygen] Found FS Data NCA: %s\n", nca_filename);
    }

    fclose(f);
}

static void keygen_enumerate_files(keygen_scan_ctx_t *sctx, const char *input_path) {
#ifdef _WIN32
    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s%c*", input_path, PATH_SEPERATOR);

    HANDLE h = FindFirstFileA(search_path, &find_data);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[keygen] Failed to enumerate: %s\n", input_path);
        return;
    }
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (sctx->fs_nca_found && sctx->sysver_found) break;
        keygen_scan_nca(sctx, find_data.cFileName, input_path);
    } while (FindNextFileA(h, &find_data));
    FindClose(h);
#else
    DIR *dir = opendir(input_path);
    if (dir == NULL) {
        fprintf(stderr, "[keygen] Failed to enumerate: %s\n", input_path);
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (sctx->fs_nca_found && sctx->sysver_found) break;

        char full_path[MAX_PATH];
        int full_path_len = snprintf(full_path, sizeof(full_path), "%s%c%s", input_path, PATH_SEPERATOR, ent->d_name);
        if (full_path_len < 0 || (size_t)full_path_len >= sizeof(full_path)) continue;

        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) continue;

        keygen_scan_nca(sctx, ent->d_name, input_path);
    }
    closedir(dir);
#endif
}

/* ── Keyfile merge/write ───────────────────────────────────────────────── */

static void keygen_hex_encode(char *dst, const unsigned char *data, size_t len) {
    static const char hexch[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[i * 2]     = hexch[(data[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hexch[data[i] & 0xF];
    }
    dst[len * 2] = '\0';
}

/* Renders pki_fprint_keys()'s complete, canonically-ordered dump of the
 * current keyset (every static key it knows: secure_boot_key, hovi_kek,
 * tsec/package1 KEK+key families, keyblob sources, the master_kek_source /
 * master_kek / master_key / package2_key / titlekek / key_area_key chains
 * across all revisions, header keys, sd/save keys, etc — not just the
 * per-revision chain this feature derives) into a heap buffer.
 * Returns NULL on failure; caller frees the result. *out_len excludes the
 * NUL terminator. */
static char *keygen_render_keyset(nca_keyset_t *keyset, int is_dev, size_t *out_len) {
    FILE *tmp = tmpfile();
    if (tmp == NULL) return NULL;

    pki_fprint_keys(tmp, keyset, is_dev);

    long len = ftell(tmp);
    if (len < 0) { fclose(tmp); return NULL; }
    rewind(tmp);

    char *buf = malloc((size_t)len + 1);
    if (buf == NULL) { fclose(tmp); return NULL; }

    if (len > 0 && fread(buf, 1, (size_t)len, tmp) != (size_t)len) {
        free(buf);
        fclose(tmp);
        return NULL;
    }
    buf[len] = '\0';
    fclose(tmp);

    if (out_len != NULL) *out_len = (size_t)len;
    return buf;
}

/* Extracts the "name" token (everything up to the first '=', space, tab, or
 * line ending) from a "name = hex" style line into dst (size must be >=
 * len+1). Returns the token length, or 0 if the line doesn't look like a
 * key assignment (blank, comment, or no recognizable name). */
static size_t keygen_line_key_name(const char *line, char *dst, size_t dst_size) {
    while (*line == ' ' || *line == '\t') line++;
    if (*line == '\0' || *line == '\r' || *line == '\n' || *line == '#' || *line == ';') return 0;

    size_t n = 0;
    while (line[n] != '\0' && line[n] != '=' && line[n] != ' ' && line[n] != '\t' &&
           line[n] != '\r' && line[n] != '\n' && n + 1 < dst_size) {
        n++;
    }
    if (n == 0) return 0;

    memcpy(dst, line, n);
    dst[n] = '\0';
    return n;
}

/* Writes `dump` (pki_fprint_keys()'s full render) to out_path, creating the
 * parent directory if needed. Any line already in the existing file whose
 * key name pki_fprint_keys() doesn't know about (custom/hand-added entries
 * not covered by nca_keyset_t) is preserved, appended after a comment
 * marker. Lines whose name IS covered are dropped from the preserved set —
 * they're already present (possibly re-cased/re-derived) in `dump`, so
 * keeping the old copy too would just create a duplicate/conflicting entry
 * for the same key. Returns the number of custom lines preserved. */
static int keygen_write_keyset_dump(filepath_t *out_path, const char *dump, size_t dump_len) {
    char *existing = NULL;
    long  existing_len = 0;

    FILE *rf = os_fopen(out_path->os_path, OS_MODE_READ);
    if (rf != NULL) {
        fseeko64(rf, 0, SEEK_END);
        existing_len = (long)ftello64(rf);
        fseeko64(rf, 0, SEEK_SET);
        if (existing_len > 0) {
            existing = malloc((size_t)existing_len + 1);
            if (existing != NULL) {
                if (fread(existing, 1, (size_t)existing_len, rf) != (size_t)existing_len) {
                    free(existing);
                    existing = NULL;
                    existing_len = 0;
                } else {
                    existing[existing_len] = '\0';
                }
            }
        }
        fclose(rf);
    }

    /* Best-effort: ensure the parent directory exists (matters only the
     * first time a fresh default keyfile is created). */
    {
        char tmp[MAX_PATH];
        strncpy(tmp, out_path->char_path, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char *sep = strrchr(tmp, PATH_SEPERATOR);
        if (sep != NULL) {
            *sep = '\0';
            if (tmp[0] != '\0') {
                filepath_t dir_path;
                filepath_init(&dir_path);
                filepath_set(&dir_path, tmp);
                if (dir_path.valid == VALIDITY_VALID) {
                    os_makedir(dir_path.os_path);
                }
            }
        }
    }

    FILE *wf = os_fopen(out_path->os_path, OS_MODE_WRITE);
    if (wf == NULL) {
        fprintf(stderr, "[keygen] Error: failed to open %s for writing\n", out_path->char_path);
        free(existing);
        return 0;
    }

    fwrite(dump, 1, dump_len, wf);

    /* Carry over any pre-existing line whose key name isn't part of the
     * standard schema pki_fprint_keys() just rendered (e.g. hand-added
     * entries, or titlekeys someone pasted in here). Deduplicated against
     * both the new dump and each other, so repeated runs don't pile up
     * copies. */
    int preserved = 0;
    if (existing != NULL && existing_len > 0) {
        char *carried = malloc((size_t)existing_len + 2);
        size_t carried_len = 0;
        if (carried != NULL) carried[0] = '\0';

        char *saveptr = NULL;
        char *line = strtok_r(existing, "\n", &saveptr);
        while (line != NULL) {
            char name[128];
            size_t name_len = keygen_line_key_name(line, name, sizeof(name));

            int already_covered = 0;
            if (name_len > 0) {
                /* pki_fprint_keys() pads names to a 32-char field before
                 * "= "; a name at/over that width instead gets no padding
                 * space, so "=" follows it directly. Check for either. */
                char search_sp[136], search_eq[136];
                snprintf(search_sp, sizeof(search_sp), "%s ", name);
                snprintf(search_eq, sizeof(search_eq), "%s=", name);
                if (strstr(dump, search_sp) != NULL || strstr(dump, search_eq) != NULL) already_covered = 1;
            } else if (strncmp(line, "# Preserved from previous ", strlen("# Preserved from previous ")) == 0) {
                /* Our own marker comment from an earlier run: drop it here —
                 * a single fresh one is (re-)written below instead of
                 * letting it accumulate one copy per run. */
                already_covered = 1;
            } else {
                /* Other comment or otherwise-unparseable line: preserve
                 * verbatim, deduped against what's already queued to avoid
                 * pile-up. */
            }

            if (!already_covered && carried != NULL) {
                /* strip trailing \r if present */
                size_t line_len = strlen(line);
                if (line_len > 0 && line[line_len - 1] == '\r') line_len--;
                if (line_len > 0) {
                    char linebuf[512];
                    size_t copy_len = line_len < sizeof(linebuf) - 1 ? line_len : sizeof(linebuf) - 1;
                    memcpy(linebuf, line, copy_len);
                    linebuf[copy_len] = '\0';

                    if (strstr(carried, linebuf) == NULL) {
                        size_t need = carried_len + copy_len + 2;
                        if (need + 1 > (size_t)existing_len + 2) {
                            char *grown = realloc(carried, need + 1);
                            if (grown != NULL) carried = grown;
                        }
                        carried_len += (size_t)snprintf(carried + carried_len, need - carried_len, "%s\n", linebuf);
                        preserved++;
                    }
                }
            }

            line = strtok_r(NULL, "\n", &saveptr);
        }

        if (preserved > 0 && carried != NULL) {
            fprintf(wf, "\n# Preserved from previous %s (not part of the standard key schema):\n", out_path->char_path);
            fwrite(carried, 1, carried_len, wf);
        }
        free(carried);
    }

    fclose(wf);
    free(existing);
    return preserved;
}

static void keygen_write_full_keyset(hactool_ctx_t *tool_ctx, filepath_t *out_path, unsigned int new_rev, int rev_is_new) {
    nca_keyset_t *keyset = &tool_ctx->settings.keyset;

    if (rev_is_new) {
        static const char *names[] = {
            "master_kek_source", "master_kek", "master_key",
            "key_area_key_application", "key_area_key_ocean", "key_area_key_system",
            "titlekek", "package2_key"
        };
        const unsigned char *vals[] = {
            keyset->master_kek_sources[new_rev], keyset->master_keks[new_rev], keyset->master_keys[new_rev],
            keyset->key_area_keys[new_rev][0], keyset->key_area_keys[new_rev][1], keyset->key_area_keys[new_rev][2],
            keyset->titlekeks[new_rev], keyset->package2_keys[new_rev]
        };
        printf("[keygen] New keys for revision %02x (%s):\n", new_rev, get_key_revision_summary((uint8_t)new_rev));
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            if (memcmp(vals[i], keygen_zeroes, 0x10) == 0) continue;
            char hex[0x41];
            keygen_hex_encode(hex, vals[i], 0x10);
            printf("    %s_%02x = %s\n", names[i], new_rev, hex);
        }
    }

    /* Full canonical dump (pki_fprint_keys() layout: grouped by key type,
     * covering every static/derived key in the keyset, not just the
     * per-revision chain this feature derives) merged non-destructively
     * into whatever's already at out_path. */
    size_t dump_len = 0;
    char *dump = keygen_render_keyset(keyset, tool_ctx->action & ACTION_DEV, &dump_len);
    if (dump == NULL) {
        fprintf(stderr, "[keygen] Error: failed to render keyset for writing\n");
        return;
    }

    int preserved = keygen_write_keyset_dump(out_path, dump, dump_len);
    free(dump);

    if (preserved > 0) {
        printf("[keygen] Wrote complete keyset to %s (%d pre-existing custom line(s) preserved)\n", out_path->char_path, preserved);
    } else {
        printf("[keygen] Wrote complete keyset to %s\n", out_path->char_path);
    }
}

/* ── Entry point ────────────────────────────────────────────────────────── */

void keygen_firmware_process(hactool_ctx_t *tool_ctx, const char *input_dir, filepath_t *cli_keypath) {
    keygen_scan_ctx_t sctx;
    memset(&sctx, 0, sizeof(sctx));
    sctx.tool_ctx = tool_ctx;

    printf("[keygen] Scanning firmware NCAs in: %s\n", input_dir);
    keygen_enumerate_files(&sctx, input_dir);

    if (!sctx.sysver_found) {
        fprintf(stderr, "[keygen] Error: System Version NCA (title 0100000000000809) not found in %s\n", input_dir);
        return;
    }
    if (!sctx.fs_nca_found) {
        fprintf(stderr, "[keygen] Error: FS Data NCA (title 0100000000000819) not found in %s\n", input_dir);
        return;
    }

    unsigned int new_rev = sctx.sysver_master_key_rev;
    printf("[keygen] Firmware Master Key Revision: %02x (%s)\n", new_rev, get_key_revision_summary((uint8_t)new_rev));

    if (new_rev < 0x09 || new_rev >= 0x20) {
        fprintf(stderr, "[keygen] Error: Master Key Revision %02x is outside the supported range (09-1f)\n", new_rev);
        return;
    }

    /* Fully process the FS Data NCA (standard key-area decryption, since its
     * RomFS section uses KeyAreaEncryptionKeyIndex == 0, i.e. the
     * Application key), then pull package1 out of its RomFS. */
    FILE *f = fopen(sctx.fs_nca_path, "rb");
    if (f == NULL) {
        fprintf(stderr, "[keygen] Error: unable to reopen %s\n", sctx.fs_nca_path);
        return;
    }
    fseek(f, 0, SEEK_END);
    size_t fsize = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    hactool_ctx_t silent_ctx = *tool_ctx;
    silent_ctx.action = 0; /* nca_process must not print or extract anything to disk */

    nca_ctx_t fs_ctx;
    nca_init(&fs_ctx);
    fs_ctx.file      = f;
    fs_ctx.file_size = fsize;
    fs_ctx.tool_ctx  = &silent_ctx;
    nca_process(&fs_ctx);

    uint64_t pkg1_size = 0;
    unsigned char *pkg1_data = nca_extract_romfs_file(&fs_ctx, "nx/package1", &pkg1_size);
    nca_free_section_contexts(&fs_ctx);
    fclose(f);

    if (pkg1_data == NULL) {
        fprintf(stderr, "[keygen] Error: failed to extract nx/package1 from %s\n", sctx.fs_nca_path);
        return;
    }
    printf("[keygen] Extracted nx/package1 (0x%" PRIx64 " bytes)\n", pkg1_size);

    pk11_ctx_t pk11_ctx;
    if (!pk11_process_buffer(pkg1_data, (size_t)pkg1_size, tool_ctx, &pk11_ctx)) {
        fprintf(stderr, "[keygen] Error: failed to decrypt package1 (is package1_key_06/_07/_08 loaded?)\n");
        free(pkg1_data);
        return;
    }
    free(pkg1_data);

    if (pk11_ctx.is_mariko) {
        fprintf(stderr, "[keygen] Error: package1 is a Mariko image; this feature only harvests the Erista master_kek_source\n");
        pk11_free_buffer_ctx(&pk11_ctx);
        return;
    }

    unsigned char master_kek_source[PK11_KEY_SIZE];
    unsigned char device_master_key_source_source[PK11_KEY_SIZE];
    unsigned char mariko_mks[PK11_KEY_SIZE];
    unsigned char mariko_mks_dev[PK11_KEY_SIZE];
    int rc = extract_key_sources_from_pk11_ctx(&pk11_ctx, master_kek_source,
                                               device_master_key_source_source,
                                               mariko_mks, mariko_mks_dev);
    pk11_free_buffer_ctx(&pk11_ctx);

    if (rc != PK11_KEYSRC_OK) {
        fprintf(stderr, "[keygen] Error: failed to extract key sources from package1 (error %d)\n", rc);
        return;
    }

    /* Resolve the output keyfile: explicit -k/--keyset path if given, else
     * the default $HOME/.switch/<prod|dev>.keys location. */
    filepath_t out_path;
    if (cli_keypath != NULL && cli_keypath->valid == VALIDITY_VALID) {
        filepath_copy(&out_path, cli_keypath);
    } else {
        get_key_file_path(&out_path, (tool_ctx->action & ACTION_DEV) ? "dev" : "prod");
    }
    if (out_path.valid != VALIDITY_VALID) {
        filepath_set(&out_path, "prod.keys");
    }

    /* Highest master key revision already present in the loaded keyset,
     * checked BEFORE we inject the harvested source below — this is purely
     * informational (used for the "new keys detected" vs "no new keys
     * detected" message); it no longer gates whether we write the file. */
    int current_max = -1;
    for (int i = 0; i < 0x20; i++) {
        if (memcmp(tool_ctx->settings.keyset.master_keys[i], keygen_zeroes, 0x10) != 0) current_max = i;
    }
    int rev_is_new = (int)new_rev > current_max;

    /* Inject the harvested source for this revision (a no-op overwrite if
     * it was already known and matches) and re-run the existing derivation
     * pipeline; it fills in master_key/key_area_keys/titlekek/package2_key
     * for every non-zero master_kek_sources[i], including the one we just
     * set. */
    memcpy(tool_ctx->settings.keyset.master_kek_sources[new_rev], master_kek_source, 0x10);
    pki_derive_keys(&tool_ctx->settings.keyset, tool_ctx->action & ACTION_DEV);

    if (rev_is_new) {
        printf("[keygen] new keys detected, writing to file at %s\n", out_path.char_path);
    } else {
        printf("[keygen] no new keys detected, writing to file at %s\n", out_path.char_path);
    }

    /* Always write: this is a full dump of everything currently known
     * (every revision, not just the one just harvested), merged
     * non-destructively into whatever's already at out_path. This is what
     * makes the file complete/standalone rather than an incremental diff,
     * and ensures it gets created even on a "no new keys" run. */
    keygen_write_full_keyset(tool_ctx, &out_path, new_rev, rev_is_new);
}