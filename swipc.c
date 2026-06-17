#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#endif
#include "swipc.h"
#include "nca.h"
#include "pfs0.h"
#include "packages.h"
#include "kip.h"
#include "filepath.h"
#include "utils.h"
#include "sha.h"

typedef enum {
    SWIPC_TYPE_PROGRAM,
    SWIPC_TYPE_APPLET,
    SWIPC_TYPE_KERNEL
} swipc_titleid_type_t;

typedef struct {
    uint64_t titleid;
    const char *name;
    swipc_titleid_type_t type;
} swipc_entry_t;

static const swipc_entry_t swipc_table[] = {
    /* FS kernel NCA — package2 carries embedded KIPs */
    { 0x0100000000000819ULL, "fs",                        SWIPC_TYPE_KERNEL  },
    { 0x010000000000081BULL, "fs_exfat",                  SWIPC_TYPE_KERNEL  },
    /* System service programs */
    { 0x0100000000000006ULL, "USB_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000007ULL, "TMA_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000009ULL, "Settings_services",         SWIPC_TYPE_PROGRAM },
    { 0x010000000000000AULL, "Bus_services",              SWIPC_TYPE_PROGRAM },
    { 0x010000000000000BULL, "Bluetooth_Driver_services", SWIPC_TYPE_PROGRAM },
    { 0x010000000000000CULL, "BCAT_services",             SWIPC_TYPE_PROGRAM },
    { 0x010000000000000EULL, "Friend_services",           SWIPC_TYPE_PROGRAM },
    { 0x010000000000000FULL, "Network_Interface_services",SWIPC_TYPE_PROGRAM },
    { 0x0100000000000010ULL, "PTM_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000012ULL, "Sockets_services",          SWIPC_TYPE_PROGRAM },
    { 0x0100000000000013ULL, "HID_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000014ULL, "Audio_services",            SWIPC_TYPE_PROGRAM },
    { 0x0100000000000015ULL, "Log_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000016ULL, "WLAN_services",             SWIPC_TYPE_PROGRAM },
    { 0x0100000000000018ULL, "LDN_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000019ULL, "NV_services",               SWIPC_TYPE_PROGRAM },
    { 0x010000000000001AULL, "PCV_services",              SWIPC_TYPE_PROGRAM },
    { 0x010000000000001BULL, "Capmtp_services",           SWIPC_TYPE_PROGRAM },
    { 0x010000000000001CULL, "Nvnflinger_services",       SWIPC_TYPE_PROGRAM },
    { 0x010000000000001DULL, "PCIe_services",             SWIPC_TYPE_PROGRAM },
    { 0x010000000000001EULL, "Account_services",          SWIPC_TYPE_PROGRAM },
    { 0x010000000000001FULL, "NS_services",               SWIPC_TYPE_PROGRAM },
    { 0x0100000000000020ULL, "NFC_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000021ULL, "PSC_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000022ULL, "Capture_services",          SWIPC_TYPE_PROGRAM },
    { 0x0100000000000023ULL, "Applet_Manager_services",   SWIPC_TYPE_PROGRAM },
    { 0x0100000000000024ULL, "SSL_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000025ULL, "NIM_services",              SWIPC_TYPE_PROGRAM },
    { 0x010000000000002AULL, "BTM_services",              SWIPC_TYPE_PROGRAM },
    { 0x010000000000002BULL, "Error_Report_services",     SWIPC_TYPE_PROGRAM },
    { 0x010000000000002DULL, "Display_services",          SWIPC_TYPE_PROGRAM },
    { 0x010000000000002EULL, "Parental_Control_services", SWIPC_TYPE_PROGRAM },
    { 0x010000000000002FULL, "NPNS_services",             SWIPC_TYPE_PROGRAM },
    { 0x0100000000000030ULL, "Error_Upload_services",     SWIPC_TYPE_PROGRAM },
    { 0x0100000000000031ULL, "Glue_services",             SWIPC_TYPE_PROGRAM },
    { 0x0100000000000033ULL, "ETicket_services",          SWIPC_TYPE_PROGRAM },
    { 0x0100000000000034ULL, "Fatal_services",            SWIPC_TYPE_PROGRAM },
    { 0x0100000000000035ULL, "GRC_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000037ULL, "RO_services",               SWIPC_TYPE_PROGRAM },
    { 0x0100000000000039ULL, "Shared_Database_services",  SWIPC_TYPE_PROGRAM },
    { 0x010000000000003AULL, "Migration_services",        SWIPC_TYPE_PROGRAM },
    { 0x010000000000003BULL, "JIT_services",              SWIPC_TYPE_PROGRAM },
    { 0x010000000000003CULL, "Jpegdec_services",          SWIPC_TYPE_PROGRAM },
    { 0x010000000000003EULL, "OLSC_services",             SWIPC_TYPE_PROGRAM },
    { 0x0100000000000042ULL, "PGL_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000045ULL, "OMM_services",              SWIPC_TYPE_PROGRAM },
    { 0x0100000000000046ULL, "Ethernet_services",         SWIPC_TYPE_PROGRAM },
    { 0x0100000000000050ULL, "NGC_services",              SWIPC_TYPE_PROGRAM },
    /* Applets */
    { 0x0100000000001000ULL, "qlaunch",                   SWIPC_TYPE_APPLET  },
    { 0x0100000000001001ULL, "auth",                      SWIPC_TYPE_APPLET  },
    { 0x0100000000001002ULL, "cabinet",                   SWIPC_TYPE_APPLET  },
    { 0x0100000000001003ULL, "controller",                SWIPC_TYPE_APPLET  },
    { 0x0100000000001004ULL, "dataErase",                 SWIPC_TYPE_APPLET  },
    { 0x0100000000001005ULL, "error",                     SWIPC_TYPE_APPLET  },
    { 0x0100000000001006ULL, "netConnect",                SWIPC_TYPE_APPLET  },
    { 0x0100000000001007ULL, "playerSelect",              SWIPC_TYPE_APPLET  },
    { 0x0100000000001008ULL, "swkbd",                     SWIPC_TYPE_APPLET  },
    { 0x0100000000001009ULL, "miiEdit",                   SWIPC_TYPE_APPLET  },
    { 0x010000000000100AULL, "LibAppletWeb",              SWIPC_TYPE_APPLET  },
    { 0x010000000000100BULL, "LibAppletShop",             SWIPC_TYPE_APPLET  },
    { 0x010000000000100CULL, "overlayDisp",               SWIPC_TYPE_APPLET  },
    { 0x010000000000100DULL, "photoViewer",               SWIPC_TYPE_APPLET  },
    { 0x010000000000100FULL, "LibAppletOff",              SWIPC_TYPE_APPLET  },
    { 0x0100000000001010ULL, "LibAppletLns",              SWIPC_TYPE_APPLET  },
    { 0x0100000000001011ULL, "LibAppletAuth",             SWIPC_TYPE_APPLET  },
    { 0x0100000000001012ULL, "starter",                   SWIPC_TYPE_APPLET  },
    { 0x0100000000001013ULL, "myPage",                    SWIPC_TYPE_APPLET  },
    { 0x0100000000001015ULL, "maintenance",               SWIPC_TYPE_APPLET  },
    { 0x0100000000001048ULL, "splay",                     SWIPC_TYPE_APPLET  },
};

static const size_t swipc_table_count = sizeof(swipc_table) / sizeof(swipc_table[0]);

static const swipc_entry_t *swipc_lookup(uint64_t titleid) {
    for (size_t i = 0; i < swipc_table_count; i++) {
        if (swipc_table[i].titleid == titleid)
            return &swipc_table[i];
    }
    return NULL;
}

static int swipc_mkdir(const char *path) {
    char tmp[0x400];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

#ifdef _WIN32
    for (char *p = tmp; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
            if (tmp[0] != '\0') {
                wchar_t wpath[0x400];
                MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wpath, sizeof(wpath) / sizeof(wpath[0]));
                if (!CreateDirectoryW(wpath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    *p = sep;
                    return 0;
                }
            }
            *p = sep;
        }
    }
    {
        wchar_t wpath[0x400];
        MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wpath, sizeof(wpath) / sizeof(wpath[0]));
        return CreateDirectoryW(wpath, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
    }
#else
    for (char *p = tmp; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (tmp[0] != '\0' && mkdir(tmp, 0755) != 0 && errno != EEXIST)
                return 0;
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
#endif
}

static int swipc_has_suffix(const char *filename, const char *suffix) {
    size_t nlen = strlen(filename);
    size_t slen = strlen(suffix);
    if (nlen < slen) return 0;
    return strcmp(filename + nlen - slen, suffix) == 0;
}

/* ── Kernel KIP extraction via pk21_process_buffer ─────────────────────────
 * Maps KIP names (from kip1_header_t.name) to the output filenames used by
 * sgg/scripts/process_swipc.py.  "boot" is skipped; unknown KIPs are skipped.
 */
typedef struct {
    const char *programs_dir;
    int         exfat_only; /* when set: only extract the FS KIP, named Filesystem_services_exfat */
} swipc_kip_ctx_t;

static void swipc_kip_callback(const char *kip_name,
                                const unsigned char *kip_data,
                                uint64_t kip_size,
                                void *userdata) {
    swipc_kip_ctx_t *kctx = (swipc_kip_ctx_t *)userdata;

    if (strcmp(kip_name, "boot") == 0) return;

    const char *out_name = NULL;
    if (kctx->exfat_only) {
        /* exFAT FS NCA: only extract the FS KIP under a distinct output name */
        if (strcmp(kip_name, "FS") == 0) out_name = "Filesystem_services_exfat";
    } else {
        if      (strcmp(kip_name, "FS")          == 0) out_name = "Filesystem_services";
        else if (strcmp(kip_name, "Loader")      == 0) out_name = "Loader_services";
        else if (strcmp(kip_name, "NCM")         == 0) out_name = "NCM_services";
        else if (strcmp(kip_name, "ProcessMana") == 0) out_name = "Process_Manager_services";
        else if (strcmp(kip_name, "sm")          == 0) out_name = "Services_API";
        else if (strcmp(kip_name, "spl")         == 0) out_name = "SPL_services";
    }

    if (out_name == NULL) return;

    char out_path[MAX_PATH];
    snprintf(out_path, sizeof(out_path), "%s%c%s",
             kctx->programs_dir, PATH_SEPERATOR, out_name);

    size_t       dec_size = 0;
    void        *dec_buf  = kip1_decompress_buf(kip_data, (size_t)kip_size, &dec_size);
    const void  *write_data = (dec_buf != NULL) ? dec_buf : (const void *)kip_data;
    size_t       write_size = (dec_buf != NULL) ? dec_size : (size_t)kip_size;

    FILE *f = fopen(out_path, "wb");
    if (f == NULL) {
        fprintf(stderr, "[swipc] Failed to open output: %s\n", out_path);
        free(dec_buf);
        return;
    }
    fwrite(write_data, 1, write_size, f);
    fclose(f);
    free(dec_buf);

    /* Write SHA256 of the original compressed KIP1 bytes as a .buildid sidecar.
     * find_patterns uses this as the module ID for IPS patch filenames. */
    {
        unsigned char digest[32];
        sha256_hash_buffer(digest, kip_data, (size_t)kip_size);
        char build_id_hex[65] = {0};
        for (int i = 0; i < 32; i++)
            sprintf(build_id_hex + i * 2, "%02X", (unsigned)digest[i]);
        char sidecar[MAX_PATH];
        snprintf(sidecar, sizeof(sidecar), "%s.buildid", out_path);
        FILE *f_bid = fopen(sidecar, "w");
        if (f_bid) {
            fprintf(f_bid, "%s\n", build_id_hex);
            fclose(f_bid);
        }
    }

    printf("[swipc] Saved KIP %s -> %s\n", kip_name, out_path);
}

/* Extract KIP1 objects from the FS kernel NCA.
 * The FS Data NCA has a RomFS containing nx/package2 which embeds INI1 KIPs.
 * Uses nca_extract_romfs_file() + pk21_process_buffer(). */
static void swipc_extract_kernel_kips(nca_ctx_t *nca_ctx, const char *programs_dir, int exfat_only) {
    uint64_t       pkg2_size = 0;
    unsigned char *pkg2_data = nca_extract_romfs_file(nca_ctx, "nx/package2", &pkg2_size);
    if (pkg2_data == NULL) {
        fprintf(stderr, "[swipc] Failed to extract nx/package2 from FS kernel NCA\n");
        return;
    }

    printf("[swipc] Extracted nx/package2 (0x%"PRIx64" bytes), processing KIPs...\n", pkg2_size);

    swipc_kip_ctx_t kctx;
    kctx.programs_dir = programs_dir;
    kctx.exfat_only   = exfat_only;
    pk21_process_buffer(pkg2_data, (size_t)pkg2_size, nca_ctx->tool_ctx,
                        swipc_kip_callback, &kctx);
    free(pkg2_data);
}

static void swipc_process_nca(swipc_ctx_t *ctx, const char *nca_filename, const char *input_path) {
    if (swipc_has_suffix(nca_filename, ".cnmt.nca")) return;
    if (!swipc_has_suffix(nca_filename, ".nca")) return;

    char nca_path[MAX_PATH];
    snprintf(nca_path, sizeof(nca_path), "%s%c%s", input_path, PATH_SEPERATOR, nca_filename);

    hactool_ctx_t *tool_ctx = (hactool_ctx_t *)ctx->tool_ctx;

    /* Use a local ctx copy with action=0 so nca_process never calls nca_print or nca_save. */
    hactool_ctx_t silent_ctx = *tool_ctx;
    silent_ctx.action = 0;

    /* ---- Step 1: inspect header with a minimal ctx ---- */
    FILE *f = fopen(nca_path, "rb");
    if (f == NULL) {
        fprintf(stderr, "[swipc] Failed to open: %s\n", nca_path);
        return;
    }

    fseek(f, 0, SEEK_END);
    size_t fsize = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

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
    uint8_t content_type = inspect_ctx.header.ContentType;

    const swipc_entry_t *entry = swipc_lookup(title_id);
    if (entry == NULL) {
        fclose(f);
        return;
    }

    /* ---- Step 2: build output file path ---- */
    const char *subdir = NULL;
    if (entry->type == SWIPC_TYPE_APPLET)  subdir = "applets";
    if (entry->type == SWIPC_TYPE_PROGRAM) subdir = "programs";

    char programs_dir[MAX_PATH];
    snprintf(programs_dir, sizeof(programs_dir), "%s%cprograms", ctx->output_dir, PATH_SEPERATOR);

    /* ---- Step 3: full NCA processing with a fresh ctx ---- */
    nca_ctx_t proc_ctx;
    nca_init(&proc_ctx);
    proc_ctx.file      = f;
    proc_ctx.file_size = fsize;
    proc_ctx.tool_ctx  = &silent_ctx;

    /* silent_ctx.action == 0 — nca_process sets up sections without printing or extracting */
    nca_process(&proc_ctx);

    /* ---- Step 4: dispatch by NCA type ---- */
    if (entry->type == SWIPC_TYPE_KERNEL) {
        if (content_type == NCACONTENTTYPE_DATA) {
            int exfat = (strcmp(entry->name, "fs_exfat") == 0);
            printf("[swipc] Processing %s kernel NCA (0x%016"PRIx64") -> KIP1 objects\n", entry->name, title_id);
            swipc_extract_kernel_kips(&proc_ctx, programs_dir, exfat);
        }
    } else if (content_type == NCACONTENTTYPE_PROGRAM && subdir != NULL) {
        char out_file[MAX_PATH];
        snprintf(out_file, sizeof(out_file), "%s%c%s%c%s",
                 ctx->output_dir, PATH_SEPERATOR,
                 subdir, PATH_SEPERATOR,
                 entry->name);
        printf("[swipc] Processing %s/%s (0x%016"PRIx64")\n", subdir, entry->name, title_id);
        /* nca_extract_pfs0_main: SectionExtractor.extract_section_pfs0_main_only */
        nca_extract_pfs0_main(&proc_ctx, out_file);
    }

    nca_free_section_contexts(&proc_ctx);
    fclose(f);
}

static void swipc_enumerate_files(swipc_ctx_t *ctx, const char *input_path) {
#ifdef _WIN32
    WIN32_FIND_DATAA find_data;
    char search_path[MAX_PATH];
    snprintf(search_path, sizeof(search_path), "%s%c*", input_path, PATH_SEPERATOR);

    HANDLE h = FindFirstFileA(search_path, &find_data);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[swipc] Failed to enumerate: %s\n", input_path);
        return;
    }
    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        swipc_process_nca(ctx, find_data.cFileName, input_path);
    } while (FindNextFileA(h, &find_data));
    FindClose(h);
#else
    DIR *dir = opendir(input_path);
    if (dir == NULL) {
        fprintf(stderr, "[swipc] Failed to enumerate: %s\n", input_path);
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s%c%s", input_path, PATH_SEPERATOR, ent->d_name);
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) continue;
        swipc_process_nca(ctx, ent->d_name, input_path);
    }
    closedir(dir);
#endif
}

void swipc_process(swipc_ctx_t *ctx) {
    if (ctx->output_dir[0] == '\0') {
        fprintf(stderr, "[swipc] Error: --outdir is required\n");
        return;
    }

    printf("[swipc] Input:  %s\n", ctx->input_dir);
    printf("[swipc] Output: %s\n", ctx->output_dir);

    if (!swipc_mkdir(ctx->output_dir)) {
        fprintf(stderr, "[swipc] Failed to create output directory: %s\n", ctx->output_dir);
        return;
    }

    char programs_dir[MAX_PATH];
    char applets_dir[MAX_PATH];
    snprintf(programs_dir, sizeof(programs_dir), "%s%cprograms", ctx->output_dir, PATH_SEPERATOR);
    snprintf(applets_dir,  sizeof(applets_dir),  "%s%capplets",  ctx->output_dir, PATH_SEPERATOR);
    swipc_mkdir(programs_dir);
    swipc_mkdir(applets_dir);

    swipc_enumerate_files(ctx, ctx->input_dir);
    printf("[swipc] Done.\n");
}
