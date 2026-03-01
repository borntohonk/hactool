#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <dirent.h>
#endif
#include "switchfs.h"
#include "nca.h"
#include "filepath.h"
#include "utils.h"

/* Get content type name string. */
static const char *switchfs_get_content_type_name(uint8_t content_type) {
    switch (content_type) {
        case SWITCHFS_CONTENT_TYPE_PROGRAM:
            return "Program";
        case SWITCHFS_CONTENT_TYPE_META:
            return "Meta";
        case SWITCHFS_CONTENT_TYPE_CONTROL:
            return "Control";
        case SWITCHFS_CONTENT_TYPE_MANUAL:
            return "Manual";
        case SWITCHFS_CONTENT_TYPE_DATA:
            return "Data";
        case SWITCHFS_CONTENT_TYPE_PUBLICDATA:
            return "PublicData";
        default:
            return "Unknown";
    }
}

/* Create directory and all parent directories if needed. */
static int switchfs_mkdir(const char *path) {
    char path_copy[0x400];
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    
#ifdef _WIN32
    /* Windows: recursively create directories */
    for (char *p = path_copy; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
            
            if (path_copy[0] != '\0') {
                wchar_t wpath[0x400];
                MultiByteToWideChar(CP_UTF8, 0, path_copy, -1, wpath, sizeof(wpath) / sizeof(wpath[0]));
                
                if (!CreateDirectoryW(wpath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    *p = sep;
                    return 0;
                }
            }
            *p = sep;
        }
    }
    
    /* Create final directory */
    wchar_t wpath[0x400];
    MultiByteToWideChar(CP_UTF8, 0, path_copy, -1, wpath, sizeof(wpath) / sizeof(wpath[0]));
    if (CreateDirectoryW(wpath, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return 1;
    } else {
        return 0;
    }
#else
    /* Unix: recursively create directories */
    for (char *p = path_copy; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (path_copy[0] != '\0' && mkdir(path_copy, 0755) != 0 && errno != EEXIST) {
                return 0;
            }
            *p = '/';
        }
    }
    
    /* Create final directory */
    if (mkdir(path_copy, 0755) == 0 || errno == EEXIST) {
        return 1;
    } else {
        return 0;
    }
#endif
}

/* Copy a file from source to destination. */
static int switchfs_copy_file(const char *src, const char *dst) {
    FILE *f_src = fopen(src, "rb");
    if (f_src == NULL) {
        fprintf(stderr, "Failed to open source file: %s\n", src);
        return 0;
    }
    
    FILE *f_dst = fopen(dst, "wb");
    if (f_dst == NULL) {
        fprintf(stderr, "Failed to open destination file: %s\n", dst);
        fclose(f_src);
        return 0;
    }
    
    uint8_t buf[0x10000]; /* 64KB buffer */
    size_t read_size;
    while ((read_size = fread(buf, 1, sizeof(buf), f_src)) > 0) {
        if (fwrite(buf, 1, read_size, f_dst) != read_size) {
            fprintf(stderr, "Failed to write to destination file: %s\n", dst);
            fclose(f_src);
            fclose(f_dst);
            return 0;
        }
    }
    
    fclose(f_src);
    fclose(f_dst);
    return 1;
}

/* Check if filename ends with a given suffix. */
static int switchfs_has_suffix(const char *filename, const char *suffix) {
    size_t name_len = strlen(filename);
    size_t suffix_len = strlen(suffix);
    
    if (name_len < suffix_len) {
        return 0;
    }
    
    return strcmp(filename + (name_len - suffix_len), suffix) == 0;
}

/* Process a single NCA file. */
static void switchfs_process_nca(switchfs_ctx_t *ctx, const char *nca_filename, const char *input_path) {
    /* Skip CNMT files */
    if (switchfs_has_suffix(nca_filename, ".cnmt.nca")) {
        return;
    }
    
    /* Skip non-NCA files */
    if (!switchfs_has_suffix(nca_filename, ".nca")) {
        return;
    }
    
    char nca_path[MAX_PATH];
    snprintf(nca_path, sizeof(nca_path), "%s%c%s", input_path, PATH_SEPERATOR, nca_filename);
    
    /* Open and read NCA header */
    FILE *nca_file = fopen(nca_path, "rb");
    if (nca_file == NULL) {
        fprintf(stderr, "[WARN] Failed to open NCA file: %s\n", nca_path);
        return;
    }
    
    /* Read NCA header (at minimum, we need the first 0x300 bytes for header info) */
    nca_header_t nca_header;
    memset(&nca_header, 0, sizeof(nca_header));
    
    if (fread(&nca_header, 1, sizeof(nca_header), nca_file) != sizeof(nca_header)) {
        fprintf(stderr, "[WARN] Failed to read NCA header: %s\n", nca_path);
        fclose(nca_file);
        return;
    }
    
    fclose(nca_file);
    
    /* Decrypt the header if needed */
    FILE *temp_file = fopen(nca_path, "rb");
    if (temp_file == NULL) {
        fprintf(stderr, "[WARN] Failed to reopen NCA file: %s\n", nca_path);
        return;
    }
    
    /* Create a temporary NCA context to decrypt the header */
    nca_ctx_t temp_nca_ctx;
    nca_init(&temp_nca_ctx);
    temp_nca_ctx.file = temp_file;
    temp_nca_ctx.tool_ctx = (hactool_ctx_t *)ctx->tool_ctx;
    temp_nca_ctx.is_cli_target = false;
    
    /* Get file size */
    fseek(temp_file, 0, SEEK_END);
    temp_nca_ctx.file_size = ftell(temp_file);
    fseek(temp_file, 0, SEEK_SET);
    
    /* Decrypt the NCA header */
    if (!nca_decrypt_header(&temp_nca_ctx)) {
        fprintf(stderr, "[WARN] Failed to decrypt NCA header: %s\n", nca_path);
        fclose(temp_file);
        return;
    }
    
    /* Extract title ID and content type */
    uint64_t title_id = temp_nca_ctx.header.ProgramId;
    uint8_t content_type = temp_nca_ctx.header.ContentType;
    
    fclose(temp_file);
    
    /* Get content type name */
    const char *content_type_name = switchfs_get_content_type_name(content_type);
    
    /* Create output directory structure: out/by-type/{ContentType}/{TitleId}/ */
    char output_dir[MAX_PATH];
    snprintf(output_dir, sizeof(output_dir), "%s%cby-type%c%s%c%016"PRIX64, 
            ctx->output_dir,
            PATH_SEPERATOR,
            PATH_SEPERATOR,
            content_type_name,
            PATH_SEPERATOR,
            title_id);
    
    if (!switchfs_mkdir(output_dir)) {
        fprintf(stderr, "[WARN] Failed to create output directory: %s\n", output_dir);
        return;
    }
    
    /* Copy the NCA file to the output directory */
    char output_file[MAX_PATH];
    snprintf(output_file, sizeof(output_file), "%s%cdata.nca", output_dir, PATH_SEPERATOR);
    
    if (switchfs_copy_file(nca_path, output_file)) {
        printf("[INFO] Copied %s to %s\n", nca_filename, output_file);
    } else {
        fprintf(stderr, "[WARN] Failed to copy NCA file: %s\n", nca_filename);
    }
}

/* Enumerate files in directory and process NCAs. */
static void switchfs_enumerate_files(switchfs_ctx_t *ctx, const char *input_path) {
#ifdef _WIN32
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;
    char search_path[MAX_PATH];
    
    snprintf(search_path, sizeof(search_path), "%s%c*", input_path, PATH_SEPERATOR);
    
    find_handle = FindFirstFileA(search_path, &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to enumerate directory: %s\n", input_path);
        return;
    }
    
    do {
        /* Skip directories */
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        
        switchfs_process_nca(ctx, find_data.cFileName, input_path);
    } while (FindNextFileA(find_handle, &find_data));
    
    FindClose(find_handle);
#else
    DIR *dir = opendir(input_path);
    if (dir == NULL) {
        fprintf(stderr, "Failed to enumerate directory: %s\n", input_path);
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip directories by checking with stat */
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s%c%s", input_path, PATH_SEPERATOR, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            continue;
        }
        
        switchfs_process_nca(ctx, entry->d_name, input_path);
    }
    
    closedir(dir);
#endif
}

/* Main switchfs processing function. */
void switchfs_process(switchfs_ctx_t *ctx) {
    printf("Processing firmware files from: %s\n", ctx->input_dir);
    printf("Output directory: %s\n", ctx->output_dir);
    
    /* Validate output directory is set */
    if (ctx->output_dir[0] == '\0') {
        fprintf(stderr, "Error: --outdir option is required for switchfs mode!\n");
        return;
    }
    
    /* Create the base output directory */
    if (!switchfs_mkdir(ctx->output_dir)) {
        fprintf(stderr, "Error: Failed to create output directory!\n");
        return;
    }
    
    /* Enumerate and process NCA files */
    switchfs_enumerate_files(ctx, ctx->input_dir);
    
    printf("Firmware processing complete!\n");
}
