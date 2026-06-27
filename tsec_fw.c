#include "tsec_fw.h"
#include "aes.h"
#include <string.h>
#include <stdio.h>

/* "HOVI_COMMON_01\x00\x00" — the howi_common_seed field at key_table offset 0x60 */
static const uint8_t HOVI_COMMON_MAGIC[0x10] = {
    'H','O','V','I','_','C','O','M','M','O','N','_','0','1',0x00,0x00
};

/* "CODE_ENC_01\x00\x00\x00\x00\x00" — source for deriving code_enc_kek */
static const uint8_t CODE_ENC_SOURCE[0x10] = {
    'C','O','D','E','_','E','N','C','_','0','1',0x00,0x00,0x00,0x00,0x00
};

/* keygen_ldr auth signature — the csigenc operand for code_enc_key */
static const uint8_t KEYGEN_LDR_AUTH_SIG[0x10] = {
    0x9C,0x8B,0x75,0xD3,0xDF,0x0B,0xF0,0x6C,0x95,0xFC,0x91,0xC0,0x76,0x1E,0xF0,0x62
};

/* ECB(zeros, tsec_secret_06) — the sentinel block that appears 3× at the end of
 * the encrypted region in secure_boot_encrypted */
static const uint8_t SECURE_BOOT_SENTINEL[0x10] = {
    0x1D,0xE3,0x64,0x58,0xFA,0x9E,0xC2,0x98,0xD5,0xB4,0x57,0x74,0xB5,0x82,0xE7,0x11
};

#define SECURE_BOOT_PREAMBLE      0x300
#define SECURE_BOOT_SENTINEL_REPS 3
#define SECURE_BOOT_SENTINEL_LEN  (SECURE_BOOT_SENTINEL_REPS * 0x10)
#define KEYGEN_TRAILING_ZEROS     0x30

static inline uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static const uint8_t *mem_find(const uint8_t *haystack, size_t hlen,
                               const uint8_t *needle,   size_t nlen) {
    if (nlen == 0 || nlen > hlen) return NULL;
    const uint8_t *end = haystack + hlen - nlen;
    for (const uint8_t *p = haystack; p <= end; p++)
        if (memcmp(p, needle, nlen) == 0) return p;
    return NULL;
}

int tsec_fw_split_sections(const uint8_t *data, size_t size,
                           tsec_fw_section_t *sections_out, int *count_out) {
    /* Locate the HOVI_COMMON_01 magic which lives at key_table+0x60 */
    const uint8_t *hovi_ptr = mem_find(data, size, HOVI_COMMON_MAGIC, sizeof(HOVI_COMMON_MAGIC));
    if (!hovi_ptr) return -1;

    size_t hovi_off = (size_t)(hovi_ptr - data);
    if (hovi_off < 0x60) return -1;
    size_t table_off = hovi_off - 0x60;

    /* 5 × u32 sizes packed after the 7 × 16-byte key fields (7 * 0x10 = 0x70) */
    size_t sizes_off = table_off + 7 * 0x10;
    if (sizes_off + 5 * 4 > size) return -1;

    uint32_t boot_size          = read_le32(data + sizes_off + 0x00);
    uint32_t keygen_ldr_size    = read_le32(data + sizes_off + 0x04);
    uint32_t keygen_size        = read_le32(data + sizes_off + 0x08);
    uint32_t secboot_ldr_size   = read_le32(data + sizes_off + 0x0C);
    uint32_t secboot_size       = read_le32(data + sizes_off + 0x10);

    if (boot_size > table_off) return -1;

    size_t table_end = table_off + 0x100;
    size_t kgl_end   = table_end + keygen_ldr_size;
    size_t kg_end    = kgl_end   + keygen_size;

    int n = 0;
    sections_out[n++] = (tsec_fw_section_t){ "boot",             table_off - boot_size, table_off  };
    sections_out[n++] = (tsec_fw_section_t){ "key_table",        table_off,             table_end  };
    sections_out[n++] = (tsec_fw_section_t){ "keygen_ldr",       table_end,             kgl_end    };
    sections_out[n++] = (tsec_fw_section_t){ "keygen", kgl_end, kg_end };

    if (secboot_ldr_size != 0 && secboot_size != 0) {
        size_t sb_end  = kg_end  + secboot_size;
        size_t sbl_end = sb_end  + secboot_ldr_size;
        if (sbl_end > size) return -1;
        sections_out[n++] = (tsec_fw_section_t){ "secure_boot",     kg_end, sb_end  };
        sections_out[n++] = (tsec_fw_section_t){ "secure_boot_ldr", sb_end, sbl_end };
    }

    *count_out = n;
    return 0;
}

void tsec_fw_derive_code_enc_key(const uint8_t *hovi_kek, uint8_t *out_code_enc_key) {
    uint8_t code_enc_kek[0x10];

    /* code_enc_kek = AES_ECB_encrypt(CODE_ENC_SOURCE, hovi_kek) */
    aes_ctx_t *ctx = new_aes_ctx(hovi_kek, 0x10, AES_MODE_ECB);
    aes_encrypt(ctx, code_enc_kek, CODE_ENC_SOURCE, 0x10);
    free_aes_ctx(ctx);

    /* code_enc_key = AES_ECB_encrypt(KEYGEN_LDR_AUTH_SIG, code_enc_kek) */
    ctx = new_aes_ctx(code_enc_kek, 0x10, AES_MODE_ECB);
    aes_encrypt(ctx, out_code_enc_key, KEYGEN_LDR_AUTH_SIG, 0x10);
    free_aes_ctx(ctx);
}

int tsec_fw_decrypt_keygen(uint8_t *data, size_t size, const uint8_t *code_enc_key) {
    if (size < KEYGEN_TRAILING_ZEROS || size % 0x10 != 0) return -1;

    uint8_t zero_iv[0x10] = {0};
    aes_ctx_t *ctx = new_aes_ctx(code_enc_key, 0x10, AES_MODE_CBC);
    aes_setiv(ctx, zero_iv, 0x10);
    aes_decrypt(ctx, data, data, size);
    free_aes_ctx(ctx);

    uint8_t zeros[KEYGEN_TRAILING_ZEROS] = {0};
    if (memcmp(data + size - KEYGEN_TRAILING_ZEROS, zeros, KEYGEN_TRAILING_ZEROS) != 0) {
        fprintf(stderr, "tsec_fw: keygen trailing-zero sentinel mismatch\n");
        return -1;
    }
    return 0;
}

int tsec_fw_decrypt_secure_boot(uint8_t *data, size_t size,
                                const uint8_t *falcon_decryption_key) {
    if (size <= SECURE_BOOT_PREAMBLE) return -1;

    uint8_t *payload      = data + SECURE_BOOT_PREAMBLE;
    size_t   payload_size = size  - SECURE_BOOT_PREAMBLE;

    /* Build the 3× sentinel pattern to search for */
    uint8_t sentinel_pattern[SECURE_BOOT_SENTINEL_LEN];
    for (int i = 0; i < SECURE_BOOT_SENTINEL_REPS; i++)
        memcpy(sentinel_pattern + i * 0x10, SECURE_BOOT_SENTINEL, 0x10);

    const uint8_t *sp = mem_find(payload, payload_size,
                                 sentinel_pattern, SECURE_BOOT_SENTINEL_LEN);
    if (!sp) {
        fprintf(stderr, "tsec_fw: secure_boot sentinel not found in ciphertext\n");
        return -1;
    }

    size_t decrypt_end = (size_t)(sp - payload) + SECURE_BOOT_SENTINEL_LEN;
    if (decrypt_end % 0x10 != 0) return -1;

    aes_ctx_t *ctx = new_aes_ctx(falcon_decryption_key, 0x10, AES_MODE_ECB);
    aes_decrypt(ctx, payload, payload, decrypt_end);
    free_aes_ctx(ctx);

    /* Verify the sentinel decrypted to all zeros */
    uint8_t zeros[SECURE_BOOT_SENTINEL_LEN] = {0};
    size_t sentinel_off = (size_t)(sp - payload);
    if (memcmp(payload + sentinel_off, zeros, SECURE_BOOT_SENTINEL_LEN) != 0) {
        fprintf(stderr, "tsec_fw: secure_boot sentinel did not decrypt to zeros — wrong key?\n");
        return -1;
    }
    return 0;
}
