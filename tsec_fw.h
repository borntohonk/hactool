#ifndef HACTOOL_TSEC_FW_H
#define HACTOOL_TSEC_FW_H

#include <stdint.h>
#include <stddef.h>

#define TSEC_FW_MAX_SECTIONS 6

typedef struct {
    const char *name;
    size_t start;
    size_t end;
} tsec_fw_section_t;

/* Find TSEC firmware sections by searching for HOVI_COMMON_01 in raw stage1 data.
 * Returns 0 on success, -1 if the magic was not found or layout is invalid. */
int tsec_fw_split_sections(const uint8_t *data, size_t size,
                           tsec_fw_section_t *sections_out, int *count_out);

/* Derive code_enc_key from hovi_kek (= tsec_secret_26).
 * code_enc_kek  = AES_ECB_encrypt(CODE_ENC_01, howi_kek)
 * code_enc_key  = AES_ECB_encrypt(keygen_ldr_auth_sig, code_enc_kek) */
void tsec_fw_derive_code_enc_key(const uint8_t *hovi_kek, uint8_t *out_code_enc_key);

/* Decrypt keygen_encrypted section in-place (AES-128-CBC, zero IV).
 * Returns 0 on success, -1 on size error or sentinel mismatch. */
int tsec_fw_decrypt_keygen(uint8_t *data, size_t size, const uint8_t *code_enc_key);

/* Decrypt secure_boot_encrypted section in-place (AES-128-ECB, 0x300 byte preamble).
 * Returns 0 on success, -1 if sentinel not found or did not decrypt to zeros. */
int tsec_fw_decrypt_secure_boot(uint8_t *data, size_t size, const uint8_t *falcon_decryption_key);

#endif /* HACTOOL_TSEC_FW_H */
