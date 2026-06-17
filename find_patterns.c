#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <capstone/capstone.h>
/* Project headers must come before <windows.h> so that utils.h defines
 * MAX_PATH=1023 first; windef.h also uses #ifndef MAX_PATH and would
 * otherwise win with 260, breaking every filepath_t offset. */
#include "find_patterns.h"
#include "cJSON.h"
#include "sha.h"
#include "kip.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <errno.h>
#endif

/* ------------------------------------------------------------------ */
/* Pattern parsing                                                      */
/* ------------------------------------------------------------------ */

static int fp_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Convert nibble-wildcard hex string to parallel byte + mask arrays.
 * '?' matches any nibble; '??' matches any byte; '0?' / '?F' = half-wild.
 * Returns number of bytes on success, -1 on error. */
static int fp_parse_pattern(const char *hex, uint8_t *bytes, uint8_t *mask, size_t max_bytes) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: pattern \"%s\" has odd length\n", hex);
        return -1;
    }
    size_t nbytes = hex_len / 2;
    if (nbytes == 0 || nbytes > max_bytes) {
        fprintf(stderr, "Error: pattern \"%s\" length out of range\n", hex);
        return -1;
    }
    for (size_t i = 0; i < nbytes; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        int hiv = (hi == '?') ? 0 : fp_hex_nibble(hi);
        int lov = (lo == '?') ? 0 : fp_hex_nibble(lo);
        if (hiv < 0 || lov < 0) {
            fprintf(stderr, "Error: invalid char in pattern \"%s\" at byte %zu\n", hex, i);
            return -1;
        }
        bytes[i] = (uint8_t)((hiv << 4) | lov);
        mask[i]  = (uint8_t)(((hi == '?') ? 0x00 : 0xF0) | ((lo == '?') ? 0x00 : 0x0F));
    }
    return (int)nbytes;
}

/* Convert plain hex string (no wildcards) to raw bytes.
 * Returns byte count on success, -1 on error. */
static int fp_parse_hex_bytes(const char *hex, uint8_t *out, size_t max_bytes) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t nbytes = hex_len / 2;
    if (nbytes == 0 || nbytes > max_bytes) return -1;
    for (size_t i = 0; i < nbytes; i++) {
        int hi = fp_hex_nibble(hex[i * 2]);
        int lo = fp_hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)nbytes;
}

/* ------------------------------------------------------------------ */
/* Match scanning                                                       */
/* ------------------------------------------------------------------ */

#define FP_MAX_MATCH_OFFSETS 4096

static size_t fp_find_matches(const uint8_t *buf, size_t buf_len,
                              const uint8_t *pat, const uint8_t *msk, size_t pat_len,
                              size_t *offsets, size_t max_offsets) {
    if (pat_len == 0 || pat_len > buf_len) return 0;
    size_t count = 0;
    size_t limit = buf_len - pat_len;
    for (size_t i = 0; i <= limit && count < max_offsets; i++) {
        int hit = 1;
        for (size_t j = 0; j < pat_len; j++) {
            if ((buf[i + j] & msk[j]) != (pat[j] & msk[j])) { hit = 0; break; }
        }
        if (hit) offsets[count++] = i;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Capstone disassembly context                                         */
/* ------------------------------------------------------------------ */

#define DISASM_BEFORE 0x20u
#define DISASM_AFTER  0x40u

static void fp_print_disasm(const uint8_t *buf, size_t buf_len,
                             size_t match_off, size_t pat_len) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        fprintf(stderr, "    [capstone] failed to initialize ARM64 disassembler\n");
        return;
    }

    size_t ctx_start = (match_off > DISASM_BEFORE) ? (match_off - DISASM_BEFORE) : 0;
    ctx_start &= ~(size_t)3u; /* align down to 4-byte boundary */
    size_t ctx_end = match_off + pat_len + DISASM_AFTER;
    if (ctx_end > buf_len) ctx_end = buf_len;

    count = cs_disasm(handle, buf + ctx_start, ctx_end - ctx_start, ctx_start, 0, &insn);
    if (count > 0) {
        for (size_t k = 0; k < count; k++) {
            int in_match = ((size_t)insn[k].address >= match_off &&
                            (size_t)insn[k].address <  match_off + pat_len);
            printf("    %s 0x%08llX:  %-10s %s\n",
                   in_match ? "=>" : "  ",
                   (unsigned long long)insn[k].address,
                   insn[k].mnemonic,
                   insn[k].op_str);
        }
        cs_free(insn, count);
    } else {
        printf("    (disassembly unavailable for this region)\n");
    }
    cs_close(&handle);
}

/* ------------------------------------------------------------------ */
/* IPS / IPS32 output                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    size_t  offset;
    uint8_t patch[128];
    uint8_t orig[128];  /* original bytes at offset before patching */
    int     patch_size;
} fp_patch_result_t;

static void write_be24(FILE *f, uint32_t v) {
    uint8_t b[3] = { (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    fwrite(b, 1, 3, f);
}
static void write_be32(FILE *f, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    fwrite(b, 1, 4, f);
}
static void write_be16(FILE *f, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    fwrite(b, 1, 2, f);
}

static void fp_write_ips(const char *path, const fp_patch_result_t *results, int n) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "Error: cannot write IPS to \"%s\"\n", path); return; }

    int ips32 = 0;
    for (int i = 0; i < n; i++) {
        if (results[i].offset > 0xFFFFFFu) { ips32 = 1; break; }
    }

    fwrite(ips32 ? "IPS32" : "PATCH", 1, 5, f);
    for (int i = 0; i < n; i++) {
        if (ips32)
            write_be32(f, (uint32_t)results[i].offset);
        else
            write_be24(f, (uint32_t)results[i].offset);
        write_be16(f, (uint16_t)results[i].patch_size);
        fwrite(results[i].patch, 1, (size_t)results[i].patch_size, f);
    }
    fwrite(ips32 ? "EEOF" : "EOF", 1, ips32 ? 4 : 3, f);
    fclose(f);
    printf("Wrote %s patch file \"%s\" (%d record%s)\n",
           ips32 ? "IPS32" : "IPS", path, n, n == 1 ? "" : "s");
}

/* ------------------------------------------------------------------ */
/* Hekate-style text output                                             */
/* ------------------------------------------------------------------ */

/* Write Hekate/Atmosphere KIP patch block.
 *
 * Format (one block per module):
 *   [MODNAME:XXXXXXXXXXXXXXXX]
 *     .nosigchk=0:0xOFFSET:0xSIZE:ORIG_BYTES,PATCH_BYTES
 *
 * offset_adjust: subtracted from each patch offset (0x100 for KIP1 files,
 *   because the KIP1 header is not part of the runtime address space).
 * append: if non-zero, opens in "a" mode (subsequent modules in the same file);
 *   if zero, opens in "w" mode (first module / new file). */
static void fp_write_hekate(const char *path, const fp_patch_result_t *results, int n,
                              const char *mod_name, const char *build_id_hex,
                              size_t offset_adjust, int append) {
    if (n == 0) return;

    FILE *f = fopen(path, append ? "a" : "w");
    if (!f) { fprintf(stderr, "Error: cannot write Hekate patch to \"%s\"\n", path); return; }

    /* First 16 hex chars of SHA256 = 8 bytes of build ID */
    char id16[17] = "????????????????";
    if (build_id_hex) {
        size_t blen = strlen(build_id_hex);
        size_t copy = blen < 16 ? blen : 16;
        memcpy(id16, build_id_hex, copy);
    }
    id16[16] = '\0';

    /* Uppercase module name */
    char mod_upper[64] = "UNKNOWN";
    if (mod_name) {
        int i = 0;
        for (; mod_name[i] && i < 63; i++)
            mod_upper[i] = (char)toupper((unsigned char)mod_name[i]);
        mod_upper[i] = '\0';
    }

    fprintf(f, "   [%s:%s]\n", mod_upper, id16);
    for (int i = 0; i < n; i++) {
        size_t off = (results[i].offset >= offset_adjust)
                     ? results[i].offset - offset_adjust
                     : results[i].offset;
        char orig_hex[257] = {0};
        char patch_hex[257] = {0};
        for (int j = 0; j < results[i].patch_size; j++) {
            sprintf(orig_hex  + j * 2, "%02X", results[i].orig[j]);
            sprintf(patch_hex + j * 2, "%02X", results[i].patch[j]);
        }
        fprintf(f, "     .nosigchk=0:0x%06X:0x%X:%s,%s\n",
                (unsigned)off, (unsigned)results[i].patch_size, orig_hex, patch_hex);
    }
    fprintf(f, "\n");

    fclose(f);
    printf("Wrote Hekate patch file \"%s\" (%d record%s)\n", path, n, n == 1 ? "" : "s");
}

/* ------------------------------------------------------------------ */
/* Directory helpers                                                    */
/* ------------------------------------------------------------------ */

/* Create a directory and all its parents (mkdir -p equivalent). */
static int fp_mkdir_p(const char *path) {
    char tmp[4096];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    if (tmp[0] == '\0') return 1;

#ifdef _WIN32
    for (char *p = tmp; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
            if (tmp[0] != '\0') {
                wchar_t wp[4096];
                MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wp, (int)(sizeof(wp) / sizeof(wp[0])));
                if (!CreateDirectoryW(wp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    *p = sep;
                    return 0;
                }
            }
            *p = sep;
        }
    }
    {
        wchar_t wp[4096];
        MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wp, (int)(sizeof(wp) / sizeof(wp[0])));
        return CreateDirectoryW(wp, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    }
#else
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return 0;
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
#endif
}

/* Create all parent directories of a file path. */
static void fp_ensure_parent_dir(const char *filepath) {
    char tmp[4096];
    strncpy(tmp, filepath, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *last = NULL;
    for (char *p = tmp; *p; p++)
        if (*p == '/' || *p == '\\') last = p;
    if (last) { *last = '\0'; fp_mkdir_p(tmp); }
}

/* ------------------------------------------------------------------ */
/* Batch processing (--batch <json>)                                    */
/* ------------------------------------------------------------------ */

/* Extract NSO0 build ID (20 bytes at offset 0x40) as uppercase hex string.
 * Returns 1 on success, 0 if the buffer is not a recognisable NSO0. */
static int fp_get_nso_build_id(const uint8_t *buf, size_t buf_size, char *hex_out) {
    static const uint8_t nso_magic[4] = { 0x4E, 0x53, 0x4F, 0x30 }; /* "NSO0" */
    if (buf_size < 0x54) return 0;
    if (memcmp(buf, nso_magic, 4) != 0) return 0;
    for (int i = 0; i < 20; i++)
        sprintf(hex_out + i * 2, "%02X", buf[0x40 + i]);
    hex_out[40] = '\0';
    return 1;
}

/* ------------------------------------------------------------------ */
/* Log helpers                                                          */
/* ------------------------------------------------------------------ */

/* Replace '?' with '.' (sys-patch pattern format). */
static void fp_to_syspatch(const char *pattern, char *dst, size_t dst_size) {
    size_t i;
    for (i = 0; pattern[i] && i + 1 < dst_size; i++)
        dst[i] = (pattern[i] == '?') ? '.' : pattern[i];
    dst[i] = '\0';
}

/* Insert a space between every byte pair (Ghidra pattern format). */
static void fp_to_ghidra(const char *syspatch, char *dst, size_t dst_size) {
    size_t len = strlen(syspatch);
    size_t out = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        if (i > 0 && out + 1 < dst_size) dst[out++] = ' ';
        if (out + 2 < dst_size) {
            dst[out++] = syspatch[i];
            dst[out++] = syspatch[i + 1];
        }
    }
    if (out < dst_size) dst[out] = '\0';
}

/* 96 bytes (0x60) starting from patch_addr-0x20, 4-byte aligned, as uppercase hex. */
static void fp_pattern_diff_hex(const uint8_t *buf, size_t buf_size, size_t patch_addr,
                                 char *out, size_t out_size) {
    size_t ctx_start = (patch_addr >= 0x20) ? (patch_addr - 0x20) : 0;
    ctx_start &= ~(size_t)3u;
    size_t ctx_end = ctx_start + 0x60;
    if (ctx_end > buf_size) ctx_end = buf_size;
    size_t i;
    for (i = 0; i < (ctx_end - ctx_start) && i * 2 + 2 < out_size; i++)
        sprintf(out + i * 2, "%02X", buf[ctx_start + i]);
    if (i * 2 < out_size) out[i * 2] = '\0';
}

/* Build and add all disassembly log fields to patch_obj.
 * - "instruction": mnemonic at patch_addr
 * - "from" / "to": arrays of formatted instruction strings
 * - "disasm_context": full context instruction objects
 * - "instruction_order": array of mnemonics from context */
static void fp_add_disasm_to_log(cJSON *patch_obj, const uint8_t *buf, size_t buf_size,
                                   size_t patch_addr, size_t patch_size,
                                   const uint8_t *pbuf) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) return;

    /* existing bytes → "instruction" + "from" */
    if (patch_addr < buf_size) {
        size_t avail = buf_size - patch_addr;
        size_t to_disasm = patch_size + 16;
        if (to_disasm > avail) to_disasm = avail;

        count = cs_disasm(handle, buf + patch_addr, to_disasm, patch_addr, 0, &insn);
        if (count > 0) {
            cJSON_AddStringToObject(patch_obj, "instruction", insn[0].mnemonic);

            cJSON *from_arr = cJSON_CreateArray();
            size_t remaining = patch_size;
            for (size_t k = 0; k < count && remaining > 0; k++) {
                char hbytes[33] = {0};
                for (int b = 0; b < insn[k].size && b < 16; b++)
                    sprintf(hbytes + b * 2, "%02X", insn[k].bytes[b]);
                char line[256];
                snprintf(line, sizeof(line), "0x%06llX: (%s) %s %s",
                         (unsigned long long)insn[k].address,
                         hbytes, insn[k].mnemonic, insn[k].op_str);
                cJSON_AddItemToArray(from_arr, cJSON_CreateString(line));
                remaining = (remaining >= (size_t)insn[k].size)
                            ? remaining - (size_t)insn[k].size : 0;
            }
            cJSON_AddItemToObject(patch_obj, "from", from_arr);
            cs_free(insn, count);
        }
    }

    /* patch bytes → "to" */
    if (patch_size > 0) {
        count = cs_disasm(handle, pbuf, patch_size, patch_addr, 0, &insn);
        if (count > 0) {
            cJSON *to_arr = cJSON_CreateArray();
            size_t remaining = patch_size;
            for (size_t k = 0; k < count && remaining > 0; k++) {
                char hbytes[33] = {0};
                for (int b = 0; b < insn[k].size && b < 16; b++)
                    sprintf(hbytes + b * 2, "%02X", insn[k].bytes[b]);
                char line[256];
                snprintf(line, sizeof(line), "0x%06llX: (%s) %s %s",
                         (unsigned long long)insn[k].address,
                         hbytes, insn[k].mnemonic, insn[k].op_str);
                cJSON_AddItemToArray(to_arr, cJSON_CreateString(line));
                remaining = (remaining >= (size_t)insn[k].size)
                            ? remaining - (size_t)insn[k].size : 0;
            }
            cJSON_AddItemToObject(patch_obj, "to", to_arr);
            cs_free(insn, count);
        }
    }

    /* context window → "disasm_context" + "instruction_order" */
    size_t ctx_start = (patch_addr > DISASM_BEFORE) ? (patch_addr - DISASM_BEFORE) : 0;
    ctx_start &= ~(size_t)3u;
    size_t ctx_end = patch_addr + patch_size + DISASM_AFTER;
    if (ctx_end > buf_size) ctx_end = buf_size;

    count = cs_disasm(handle, buf + ctx_start, ctx_end - ctx_start, ctx_start, 0, &insn);
    if (count > 0) {
        cJSON *ctx_arr   = cJSON_CreateArray();
        cJSON *order_arr = cJSON_CreateArray();

        for (size_t k = 0; k < count; k++) {
            int is_target = ((size_t)insn[k].address >= patch_addr &&
                             (size_t)insn[k].address <  patch_addr + patch_size);

            char hbytes[33] = {0};
            for (int b = 0; b < insn[k].size && b < 16; b++)
                sprintf(hbytes + b * 2, "%02X", insn[k].bytes[b]);

            char addr_str[24];
            snprintf(addr_str, sizeof(addr_str), "0x%06llX",
                     (unsigned long long)insn[k].address);

            cJSON *iobj = cJSON_CreateObject();
            cJSON_AddStringToObject(iobj, "address",  addr_str);
            cJSON_AddStringToObject(iobj, "bytes",    hbytes);
            cJSON_AddStringToObject(iobj, "mnemonic", insn[k].mnemonic);
            cJSON_AddStringToObject(iobj, "operands", insn[k].op_str);
            cJSON_AddItemToObject(iobj, "is_patch_target",
                                  is_target ? cJSON_CreateTrue() : cJSON_CreateFalse());
            cJSON_AddItemToArray(ctx_arr, iobj);

            cJSON_AddItemToArray(order_arr, cJSON_CreateString(insn[k].mnemonic));
        }

        cJSON_AddItemToObject(patch_obj, "disasm_context",    ctx_arr);
        cJSON_AddItemToObject(patch_obj, "instruction_order", order_arr);
        cs_free(insn, count);
    }

    cs_close(&handle);
}

static void fp_run_batch(find_patterns_ctx_t *ctx) {
    const char *json_path = ctx->tool_ctx->settings.fp_batch_path.path.char_path;

    FILE *jf = fopen(json_path, "r");
    if (!jf) {
        fprintf(stderr, "Error: cannot open batch file \"%s\"\n", json_path);
        return;
    }
    fseek(jf, 0, SEEK_END);
    long jsize = ftell(jf);
    rewind(jf);
    char *jbuf = malloc((size_t)jsize + 1);
    if (!jbuf) { fclose(jf); fprintf(stderr, "Error: out of memory\n"); return; }
    fread(jbuf, 1, (size_t)jsize, jf);
    jbuf[jsize] = '\0';
    fclose(jf);

    cJSON *root = cJSON_Parse(jbuf);
    free(jbuf);
    if (!root) {
        const char *err = cJSON_GetErrorPtr();
        fprintf(stderr, "Error: failed to parse JSON batch file%s%s\n",
                err ? " near: " : "", err ? err : "");
        return;
    }

    int want_log = ctx->tool_ctx->settings.fp_log_path.enabled;
    cJSON *log_root = want_log ? cJSON_CreateObject() : NULL;

    static size_t  s_offsets[FP_MAX_MATCH_OFFSETS];
    static uint8_t s_pat_bytes[FP_PATTERN_LEN / 2];
    static uint8_t s_pat_mask[FP_PATTERN_LEN / 2];

    /* Track which hekate output paths have been written this run:
     * first write uses "w" (truncate), subsequent use "a" (append). */
    const char *hekate_paths_seen[64] = {0};
    int hekate_seen_count = 0;

    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, root) {
        const char *mod_name = entry->string ? entry->string : "(unnamed)";

        cJSON *jfile = cJSON_GetObjectItemCaseSensitive(entry, "file");
        if (!cJSON_IsString(jfile)) {
            fprintf(stderr, "[%s] missing \"file\" key — skipping\n", mod_name);
            continue;
        }
        const char *bin_path = jfile->valuestring;

        cJSON *jrules = cJSON_GetObjectItemCaseSensitive(entry, "rules");
        if (!cJSON_IsArray(jrules)) {
            fprintf(stderr, "[%s] missing \"rules\" array — skipping\n", mod_name);
            continue;
        }

        /* Output spec: "output": { "dir": "...", "hekate": "..." }
         * IPS filename is always <BUILD_ID>.ips inside "dir".
         * "module_id" can override auto-detected build ID. */
        const char *out_dir    = NULL;
        const char *out_hekate = NULL;
        cJSON *jout = cJSON_GetObjectItemCaseSensitive(entry, "output");
        if (cJSON_IsObject(jout)) {
            cJSON *jdir    = cJSON_GetObjectItemCaseSensitive(jout, "dir");
            cJSON *jhekate = cJSON_GetObjectItemCaseSensitive(jout, "hekate");
            if (cJSON_IsString(jdir))    out_dir    = jdir->valuestring;
            if (cJSON_IsString(jhekate)) out_hekate = jhekate->valuestring;
        }

        /* Optional explicit module ID override */
        const char *explicit_mod_id = NULL;
        cJSON *jmodid = cJSON_GetObjectItemCaseSensitive(entry, "module_id");
        if (cJSON_IsString(jmodid)) explicit_mod_id = jmodid->valuestring;

        /* Open and read binary */
        FILE *bf = fopen(bin_path, "rb");
        if (!bf) {
            fprintf(stderr, "[%s] cannot open \"%s\" — skipping\n", mod_name, bin_path);
            if (want_log && log_root) {
                cJSON *mod_log = cJSON_CreateObject();
                cJSON_AddStringToObject(mod_log, "input_file", bin_path);
                cJSON_AddStringToObject(mod_log, "status", "error");
                cJSON_AddStringToObject(mod_log, "error", "cannot open file");
                cJSON_AddItemToObject(log_root, mod_name, mod_log);
            }
            continue;
        }
        fseek(bf, 0, SEEK_END);
        long bsize = ftell(bf);
        rewind(bf);
        uint8_t *buf = malloc((size_t)bsize);
        if (!buf) {
            fprintf(stderr, "[%s] out of memory — skipping\n", mod_name);
            fclose(bf);
            continue;
        }
        if (fread(buf, 1, (size_t)bsize, bf) != (size_t)bsize) {
            fprintf(stderr, "[%s] read error on \"%s\" — skipping\n", mod_name, bin_path);
            free(buf);
            fclose(bf);
            continue;
        }
        fclose(bf);

        /* KIP1 build ID resolution:
         *  - Compressed KIP1 (flags bits 0-2 set): SHA256 raw bytes → build ID,
         *    then decompress in memory for pattern searching.
         *  - Decompressed KIP1 (flags bits 0-2 clear): re-compress via BLZ to
         *    produce a canonical compressed form, SHA256 that → build ID.
         *    Pattern searching uses the already-decompressed buf as-is. */
        /* Check for a .buildid sidecar written by swipc at extraction time.
         * The sidecar holds the SHA256 of the original compressed KIP1 bytes,
         * which is the correct module ID for IPS patch filenames. */
        char kip1_build_id[65] = {0};
        {
            char sidecar[4096];
            snprintf(sidecar, sizeof(sidecar), "%s.buildid", bin_path);
            FILE *f_bid = fopen(sidecar, "r");
            if (f_bid) {
                if (fgets(kip1_build_id, sizeof(kip1_build_id), f_bid)) {
                    /* Strip trailing newline / CR / space */
                    int slen = (int)strlen(kip1_build_id);
                    while (slen > 0 && (kip1_build_id[slen-1] == '\n' ||
                                        kip1_build_id[slen-1] == '\r' ||
                                        kip1_build_id[slen-1] == ' '))
                        kip1_build_id[--slen] = '\0';
                }
                fclose(f_bid);
            }
        }

        /* KIP1 decompression: if the file is a compressed KIP1, decompress it
         * in-memory for pattern searching.  Also hash the compressed bytes for
         * the build ID when no sidecar is present (e.g. files from other tools). */
        if ((size_t)bsize >= sizeof(kip1_header_t)) {
            const kip1_header_t *khdr = (const kip1_header_t *)buf;
            if (khdr->magic == MAGIC_KIP1 && (khdr->flags & 0x7u)) {
                /* Hash compressed bytes if we don't already have a build ID */
                if (!kip1_build_id[0]) {
                    unsigned char digest[32];
                    sha256_hash_buffer(digest, buf, (size_t)bsize);
                    for (int i = 0; i < 32; i++)
                        sprintf(kip1_build_id + i * 2, "%02X", (unsigned)digest[i]);
                    kip1_build_id[64] = '\0';
                }
                /* Decompress for searching */
                size_t decompressed_size = 0;
                void *decompressed = kip1_decompress_buf(buf, (size_t)bsize, &decompressed_size);
                if (decompressed) {
                    free(buf);
                    buf   = (uint8_t *)decompressed;
                    bsize = (long)decompressed_size;
                } else {
                    fprintf(stderr, "[%s] Warning: KIP1 decompression failed\n", mod_name);
                    kip1_build_id[0] = '\0';
                }
            } else if (khdr->magic == MAGIC_KIP1 && !kip1_build_id[0]) {
                /* Decompressed KIP1 without a sidecar: re-compress and hash as fallback */
                size_t rcmp_size = 0;
                void *rcmp = kip1_recompress_buf(buf, (size_t)bsize, &rcmp_size);
                if (rcmp && rcmp_size > 0) {
                    unsigned char digest[32];
                    sha256_hash_buffer(digest, rcmp, rcmp_size);
                    for (int i = 0; i < 32; i++)
                        sprintf(kip1_build_id + i * 2, "%02X", (unsigned)digest[i]);
                    kip1_build_id[64] = '\0';
                    free(rcmp);
                } else {
                    if (rcmp) free(rcmp);
                    fprintf(stderr, "[%s] Warning: KIP1 re-compression failed\n", mod_name);
                }
            }
        }

        /* Resolve build ID for IPS filename */
        char build_id_hex[65] = {0};
        if (explicit_mod_id) {
            strncpy(build_id_hex, explicit_mod_id, sizeof(build_id_hex) - 1);
        } else if (kip1_build_id[0]) {
            memcpy(build_id_hex, kip1_build_id, sizeof(build_id_hex));
        } else if (!fp_get_nso_build_id(buf, (size_t)bsize, build_id_hex)) {
            fprintf(stderr, "[%s] Warning: not NSO0 and no \"module_id\" provided — IPS output disabled\n", mod_name);
            out_dir = NULL;
        }

        /* Build IPS output path: <dir>/<BUILD_ID>.ips */
        char ips_out_path[4096] = {0};
        if (out_dir && build_id_hex[0]) {
            snprintf(ips_out_path, sizeof(ips_out_path), "%s/%s.ips", out_dir, build_id_hex);
        }

        printf("\n=== [%s] %s (0x%lX bytes) ===\n", mod_name, bin_path, bsize);
        if (build_id_hex[0])
            printf("    Build ID: %s\n", build_id_hex);
        if (ips_out_path[0])
            printf("    IPS out:  %s\n", ips_out_path);

        fp_patch_result_t ips_results[FP_MAX_PATTERNS];
        fp_patch_result_t hekate_results[FP_MAX_PATTERNS];
        int ips_count    = 0;
        int hekate_count = 0;

        /* Per-module log objects */
        cJSON *patches_arr = want_log ? cJSON_CreateArray() : NULL;

        cJSON *jrule = NULL;
        int rule_idx = 0;
        cJSON_ArrayForEach(jrule, jrules) {
            cJSON *jpat = cJSON_GetObjectItemCaseSensitive(jrule, "pattern");
            if (!cJSON_IsString(jpat)) {
                fprintf(stderr, "  Rule[%d]: missing \"pattern\" — skipping\n", rule_idx);
                rule_idx++;
                continue;
            }
            const char *pat_str = jpat->valuestring;

            cJSON *jpatch  = cJSON_GetObjectItemCaseSensitive(jrule, "patch");
            cJSON *joffset = cJSON_GetObjectItemCaseSensitive(jrule, "offset");
            cJSON *jmpos   = cJSON_GetObjectItemCaseSensitive(jrule, "match_position");

            int has_patch    = cJSON_IsString(jpatch);
            int patch_offset = cJSON_IsNumber(joffset) ? (int)joffset->valuedouble : 0;
            int match_pos    = cJSON_IsNumber(jmpos)   ? (int)jmpos->valuedouble   : 0;

            printf("  Rule[%d]: \"%s\"", rule_idx, pat_str);
            if (has_patch)
                printf("  patch -> \"%s\" offset=%d matchpos=%d",
                       jpatch->valuestring, patch_offset, match_pos);
            printf("\n");

            int pat_len = fp_parse_pattern(pat_str, s_pat_bytes, s_pat_mask, sizeof(s_pat_bytes));
            if (pat_len < 0) { rule_idx++; continue; }

            /* Compute sys-patch / ghidra strings once (used by log entries) */
            char syspatch[FP_PATTERN_LEN];
            char ghidra[512];
            fp_to_syspatch(pat_str, syspatch, sizeof(syspatch));
            fp_to_ghidra(syspatch, ghidra, sizeof(ghidra));

            size_t n_matches = fp_find_matches(buf, (size_t)bsize,
                                               s_pat_bytes, s_pat_mask, (size_t)pat_len,
                                               s_offsets, FP_MAX_MATCH_OFFSETS);
            if (n_matches == 0) {
                printf("    No matches.\n");
                if (patches_arr) {
                    cJSON *fail = cJSON_CreateObject();
                    cJSON_AddStringToObject(fail, "rule_pattern",     pat_str);
                    cJSON_AddStringToObject(fail, "sys_patch_pattern", syspatch);
                    cJSON_AddStringToObject(fail, "ghidra_pattern",   ghidra);
                    cJSON_AddStringToObject(fail, "status",           "no_match");
                    cJSON_AddItemToArray(patches_arr, fail);
                }
                rule_idx++;
                continue;
            }
            printf("    %zu match%s:\n", n_matches, n_matches == 1 ? "" : "es");
            for (size_t mi = 0; mi < n_matches; mi++) {
                size_t off = s_offsets[mi];
                printf("    [%zu] 0x%08zX:", mi, off);
                for (int b = 0; b < pat_len; b++)
                    printf(" %02X", buf[off + b]);
                printf("\n");
                fp_print_disasm(buf, (size_t)bsize, off, (size_t)pat_len);
            }

            if (has_patch) {
                if (match_pos < 0 || (size_t)match_pos >= n_matches) {
                    fprintf(stderr, "    Warning: match_position %d out of range (%zu matches) — skipping\n",
                            match_pos, n_matches);
                    if (patches_arr) {
                        cJSON *fail = cJSON_CreateObject();
                        cJSON_AddStringToObject(fail, "rule_pattern",     pat_str);
                        cJSON_AddStringToObject(fail, "sys_patch_pattern", syspatch);
                        cJSON_AddStringToObject(fail, "ghidra_pattern",   ghidra);
                        cJSON_AddStringToObject(fail, "status",           "error");
                        cJSON_AddStringToObject(fail, "error",            "match_position out of range");
                        cJSON_AddItemToArray(patches_arr, fail);
                    }
                    rule_idx++;
                    continue;
                }
                uint8_t pbuf[128];
                int psz = fp_parse_hex_bytes(jpatch->valuestring, pbuf, sizeof(pbuf));
                if (psz < 0) {
                    fprintf(stderr, "    Warning: invalid patch bytes \"%s\" — skipping\n",
                            jpatch->valuestring);
                    if (patches_arr) {
                        cJSON *fail = cJSON_CreateObject();
                        cJSON_AddStringToObject(fail, "rule_pattern",     pat_str);
                        cJSON_AddStringToObject(fail, "sys_patch_pattern", syspatch);
                        cJSON_AddStringToObject(fail, "ghidra_pattern",   ghidra);
                        cJSON_AddStringToObject(fail, "status",           "error");
                        cJSON_AddStringToObject(fail, "error",            "invalid patch bytes");
                        cJSON_AddItemToArray(patches_arr, fail);
                    }
                    rule_idx++;
                    continue;
                }
                size_t match_base = s_offsets[(size_t)match_pos];
                size_t patch_addr;
                if (patch_offset >= 0) {
                    patch_addr = match_base + (size_t)patch_offset;
                } else {
                    size_t abs_off = (size_t)(-(long)patch_offset);
                    if (abs_off > match_base) {
                        fprintf(stderr, "    Warning: patch_offset %d underflows — skipping\n",
                                patch_offset);
                        if (patches_arr) {
                            cJSON *fail = cJSON_CreateObject();
                            cJSON_AddStringToObject(fail, "rule_pattern",     pat_str);
                            cJSON_AddStringToObject(fail, "sys_patch_pattern", syspatch);
                            cJSON_AddStringToObject(fail, "ghidra_pattern",   ghidra);
                            cJSON_AddStringToObject(fail, "status",           "error");
                            cJSON_AddStringToObject(fail, "error",            "patch_offset underflows match address");
                            cJSON_AddItemToArray(patches_arr, fail);
                        }
                        rule_idx++;
                        continue;
                    }
                    patch_addr = match_base - abs_off;
                }
                if (match_pos != 0 || patch_offset != 0)
                    printf("    Using match[%d] 0x%08zX, patch at 0x%08zX (%+d)\n",
                           match_pos, match_base, patch_addr, patch_offset);

                fp_patch_result_t res;
                memset(&res, 0, sizeof(res));
                res.offset     = patch_addr;
                res.patch_size = psz;
                memcpy(res.patch, pbuf, (size_t)psz);
                for (int b = 0; b < psz && patch_addr + (size_t)b < (size_t)bsize; b++)
                    res.orig[b] = buf[patch_addr + (size_t)b];
                if (ips_out_path[0] && ips_count    < FP_MAX_PATTERNS) ips_results[ips_count++]       = res;
                if (out_hekate      && hekate_count < FP_MAX_PATTERNS) hekate_results[hekate_count++] = res;

                if (patches_arr) {
                    cJSON *plog = cJSON_CreateObject();

                    cJSON_AddStringToObject(plog, "rule_pattern",     pat_str);
                    cJSON_AddStringToObject(plog, "sys_patch_pattern", syspatch);
                    cJSON_AddStringToObject(plog, "ghidra_pattern",   ghidra);

                    char addr_str[32];
                    snprintf(addr_str, sizeof(addr_str), "0x%06zX", match_base);
                    cJSON_AddStringToObject(plog, "match_offset", addr_str);
                    snprintf(addr_str, sizeof(addr_str), "0x%06zX", patch_addr);
                    cJSON_AddStringToObject(plog, "patch_offset", addr_str);

                    /* existing bytes at patch_addr */
                    char exist_hex[257] = {0};
                    for (int b = 0; b < psz && patch_addr + (size_t)b < (size_t)bsize; b++)
                        sprintf(exist_hex + b * 2, "%02X", buf[patch_addr + (size_t)b]);
                    cJSON_AddStringToObject(plog, "existing_bytes", exist_hex);
                    cJSON_AddStringToObject(plog, "patch_bytes",    jpatch->valuestring);

                    char diff_hex[200] = {0};
                    fp_pattern_diff_hex(buf, (size_t)bsize, patch_addr, diff_hex, sizeof(diff_hex));
                    cJSON_AddStringToObject(plog, "pattern_diff", diff_hex);

                    fp_add_disasm_to_log(plog, buf, (size_t)bsize,
                                         patch_addr, (size_t)psz, pbuf);

                    cJSON_AddStringToObject(plog, "status", "ok");
                    cJSON_AddItemToArray(patches_arr, plog);
                }
            }
            rule_idx++;
        }

        if (ips_out_path[0]) {
            fp_ensure_parent_dir(ips_out_path);
            fp_write_ips(ips_out_path, ips_results, ips_count);
        }
        if (out_hekate) {
            fp_ensure_parent_dir(out_hekate);
            /* KIP1 runtime offsets exclude the 0x100 header */
            size_t hek_adjust = 0;
            if ((size_t)bsize >= sizeof(kip1_header_t) &&
                ((const kip1_header_t *)buf)->magic == MAGIC_KIP1)
                hek_adjust = 0x100;
            /* First write to this path truncates; subsequent append */
            int hek_append = 0;
            for (int _hi = 0; _hi < hekate_seen_count; _hi++) {
                if (strcmp(out_hekate, hekate_paths_seen[_hi]) == 0) {
                    hek_append = 1;
                    break;
                }
            }
            if (!hek_append && hekate_seen_count < 64)
                hekate_paths_seen[hekate_seen_count++] = out_hekate;
            fp_write_hekate(out_hekate, hekate_results, hekate_count,
                            mod_name, build_id_hex, hek_adjust, hek_append);
        }

        if (want_log && log_root && patches_arr) {
            cJSON *mod_log = cJSON_CreateObject();
            if (build_id_hex[0])
                cJSON_AddStringToObject(mod_log, "module_id", build_id_hex);
            cJSON_AddStringToObject(mod_log, "input_file", bin_path);
            if (ips_out_path[0])
                cJSON_AddStringToObject(mod_log, "ips_output", ips_out_path);
            else
                cJSON_AddNullToObject(mod_log, "ips_output");
            if (out_hekate)
                cJSON_AddStringToObject(mod_log, "hekate_output", out_hekate);
            else
                cJSON_AddNullToObject(mod_log, "hekate_output");
            cJSON_AddNumberToObject(mod_log, "patches_found", (double)ips_count);
            cJSON_AddItemToObject(mod_log, "patches", patches_arr);
            cJSON_AddItemToObject(log_root, mod_name, mod_log);
        } else if (patches_arr) {
            cJSON_Delete(patches_arr);
        }

        free(buf);
    }

    if (want_log && log_root) {
        char *log_str = cJSON_Print(log_root);
        if (log_str) {
            const char *log_path = ctx->tool_ctx->settings.fp_log_path.path.char_path;
            FILE *lf = fopen(log_path, "w");
            if (lf) {
                fputs(log_str, lf);
                fclose(lf);
                printf("\nBatch log written to \"%s\"\n", log_path);
            } else {
                fprintf(stderr, "Error: cannot write log to \"%s\"\n", log_path);
            }
            free(log_str);
        }
        cJSON_Delete(log_root);
    }

    cJSON_Delete(root);
}

/* ------------------------------------------------------------------ */
/* Main entry point                                                     */
/* ------------------------------------------------------------------ */

void find_patterns_process(find_patterns_ctx_t *ctx) {
    hactool_settings_t *settings = &ctx->tool_ctx->settings;

    if (settings->fp_batch_path.enabled || settings->fp_batch_path.path.char_path[0] != '\0') {
        fp_run_batch(ctx);
        return;
    }

    if (!ctx->file) {
        fprintf(stderr, "Error: no input file (use --batch for batch mode)\n");
        return;
    }

    /* Load entire input file into memory. */
    if (fseek(ctx->file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error: seek failed on input file\n");
        return;
    }
    long fsize = ftell(ctx->file);
    if (fsize <= 0) {
        fprintf(stderr, "Error: cannot determine file size\n");
        return;
    }
    ctx->buffer_size = (size_t)fsize;
    ctx->buffer = malloc(ctx->buffer_size);
    if (!ctx->buffer) {
        fprintf(stderr, "Error: out of memory (%zu bytes)\n", ctx->buffer_size);
        return;
    }
    rewind(ctx->file);
    if (fread(ctx->buffer, 1, ctx->buffer_size, ctx->file) != ctx->buffer_size) {
        fprintf(stderr, "Error: failed to read input file\n");
        free(ctx->buffer);
        ctx->buffer = NULL;
        return;
    }

    if (settings->fp_num_patterns == 0) {
        fprintf(stderr, "No patterns specified. Use --pattern <hex> or --patch <hex:patchbytes>.\n");
        free(ctx->buffer);
        ctx->buffer = NULL;
        return;
    }

    printf("File size: 0x%zX bytes\n\n", ctx->buffer_size);

    /* Scratch buffers reused per pattern. */
    static size_t  s_offsets[FP_MAX_MATCH_OFFSETS];
    static uint8_t s_pat_bytes[FP_PATTERN_LEN / 2];
    static uint8_t s_pat_mask[FP_PATTERN_LEN / 2];

    /* Patch result accumulators (one entry per pattern, first match only). */
    fp_patch_result_t ips_results[FP_MAX_PATTERNS];
    fp_patch_result_t hekate_results[FP_MAX_PATTERNS];
    int ips_count    = 0;
    int hekate_count = 0;

    int want_ips    = settings->fp_ips_path.enabled;
    int want_hekate = settings->fp_hekate_path.enabled;

    for (int pi = 0; pi < settings->fp_num_patterns; pi++) {
        fp_pattern_entry_t *entry = &settings->fp_patterns[pi];

        printf("Pattern[%d]: \"%s\"", pi, entry->pattern);
        if (entry->has_patch)
            printf("  patch -> \"%s\"", entry->patch_bytes);
        printf("\n");

        int pat_len = fp_parse_pattern(entry->pattern,
                                       s_pat_bytes, s_pat_mask, sizeof(s_pat_bytes));
        if (pat_len < 0) { printf("\n"); continue; }

        size_t n_matches = fp_find_matches(ctx->buffer, ctx->buffer_size,
                                           s_pat_bytes, s_pat_mask, (size_t)pat_len,
                                           s_offsets, FP_MAX_MATCH_OFFSETS);

        if (n_matches == 0) {
            printf("  No matches.\n\n");
            continue;
        }

        printf("  %zu match%s found:\n", n_matches, n_matches == 1 ? "" : "es");

        for (size_t mi = 0; mi < n_matches; mi++) {
            size_t off = s_offsets[mi];
            printf("  [%zu] 0x%08zX:", mi, off);
            for (int b = 0; b < pat_len; b++)
                printf(" %02X", ctx->buffer[off + b]);
            printf("\n");
            fp_print_disasm(ctx->buffer, ctx->buffer_size, off, (size_t)pat_len);
        }

        /* Accumulate selected match for patch output files. */
        if (entry->has_patch && (want_ips || want_hekate)) {
            int mpos = entry->match_position;
            if (mpos < 0 || (size_t)mpos >= n_matches) {
                fprintf(stderr, "  Warning: match_position %d out of range (%zu matches) — skipping output\n",
                        mpos, n_matches);
                printf("\n");
                continue;
            }
            uint8_t pbuf[128];
            int psz = fp_parse_hex_bytes(entry->patch_bytes, pbuf, sizeof(pbuf));
            if (psz < 0) {
                fprintf(stderr, "  Warning: invalid patch bytes \"%s\" — skipping output for this pattern\n",
                        entry->patch_bytes);
            } else {
                size_t match_base = s_offsets[(size_t)mpos];
                size_t patch_addr;
                if (entry->patch_offset >= 0) {
                    patch_addr = match_base + (size_t)entry->patch_offset;
                } else {
                    size_t abs_off = (size_t)(-(long)entry->patch_offset);
                    if (abs_off > match_base) {
                        fprintf(stderr, "  Warning: patch_offset %d underflows match address 0x%08zX — skipping\n",
                                entry->patch_offset, match_base);
                        printf("\n");
                        continue;
                    }
                    patch_addr = match_base - abs_off;
                }
                if (mpos != 0 || entry->patch_offset != 0)
                    printf("  Using match[%d] 0x%08zX, patch at 0x%08zX (%+d)\n",
                           mpos, match_base, patch_addr, entry->patch_offset);
                fp_patch_result_t res;
                memset(&res, 0, sizeof(res));
                res.offset     = patch_addr;
                res.patch_size = psz;
                memcpy(res.patch, pbuf, (size_t)psz);
                for (int b = 0; b < psz && patch_addr + (size_t)b < ctx->buffer_size; b++)
                    res.orig[b] = ctx->buffer[patch_addr + (size_t)b];

                if (want_ips    && ips_count    < FP_MAX_PATTERNS) ips_results[ips_count++]       = res;
                if (want_hekate && hekate_count < FP_MAX_PATTERNS) hekate_results[hekate_count++] = res;
            }
        }
        printf("\n");
    }

    if (want_ips)
        fp_write_ips(settings->fp_ips_path.path.char_path, ips_results, ips_count);
    if (want_hekate) {
        size_t hek_adjust = 0;
        char nb_build_id[65] = {0};
        if (ctx->buffer_size >= sizeof(kip1_header_t) &&
            ((const kip1_header_t *)ctx->buffer)->magic == MAGIC_KIP1)
            hek_adjust = 0x100;
        else
            fp_get_nso_build_id(ctx->buffer, ctx->buffer_size, nb_build_id);
        fp_write_hekate(settings->fp_hekate_path.path.char_path, hekate_results, hekate_count,
                        NULL, nb_build_id[0] ? nb_build_id : NULL, hek_adjust, 0);
    }

    free(ctx->buffer);
    ctx->buffer = NULL;
}
