#ifndef HACTOOL_KEYGEN_FIRMWARE_H
#define HACTOOL_KEYGEN_FIRMWARE_H

#include "types.h"
#include "settings.h"
#include "filepath.h"

/*
 * keygen_firmware_process()
 *
 * Invoked by `-t keygen <folder> [--keys prod.keys]`.
 *
 * Given a folder of extracted firmware NCAs:
 *   1. Scans NCA headers in the folder.
 *   2. Finds the System Version NCA (title 0100000000000809) and records
 *      its Master Key Revision (nca header crypto_type).
 *   3. Finds the FS module's Data NCA (title 0100000000000819), fully
 *      processes it (decrypting its key area/RomFS with the standard
 *      Application key area key), and extracts /nx/package1 from its RomFS.
 *   4. Decrypts that package1 image (pk11_process_buffer) and pulls the
 *      Erista master_kek_source out of it (pk11_extract_key_sources.c).
 *   5. Attributes that source to the Master Key Revision found in step 2,
 *      derives master_kek -> master_key -> key_area_keys/titlekek/package2_key
 *      for that revision via the existing pki_derive_keys() pipeline.
 *   6. Compares that revision against the highest revision already present
 *      in the loaded keyset (informational only). Always writes a complete
 *      canonical dump of the current keyset, merging any pre-existing
 *      custom/non-schema lines non-destructively into the target keyfile.
 *
 * tool_ctx  : already has settings.keyset populated from whatever keyfile
 *             was loaded at startup via -k/--keyset (input only).
 * input_dir : the folder of firmware NCAs (positional CLI argument).
 * cli_keypath : the --keys OUTPUT path as parsed in main(), or an
 *             uninitialized filepath_t if --keys was not given. This is
 *             NOT -k/--keyset. When invalid, the default
 *             $HOME/.switch/<prod|dev>.keys location is used (created if
 *             it does not exist yet).
 *
 * Never writes any file other than the resolved output keyfile.
 */
void keygen_firmware_process(hactool_ctx_t *tool_ctx, const char *input_dir, filepath_t *cli_keypath);

#endif