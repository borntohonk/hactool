#ifndef HACTOOL_NSP_H
#define HACTOOL_NSP_H

#include "types.h"
#include "settings.h"
#include "pfs0.h"

/*
 * NSP (Nintendo Submission Package) is a PFS0 container holding NCA files,
 * tickets (.tik), certificates (.cert), and optionally CNMT metadata.
 *
 * Ticket layout (sig type 0x10004 = RSA-2048 SHA-256, the common NSP format):
 *   0x180  Title Key Block  (0x100 bytes; first 0x10 bytes = encrypted titlekey)
 *   0x2A0  Rights ID        (0x10 bytes; matches the NCA's RightsId field)
 */
#define TICKET_TITLEKEY_OFFSET 0x180
#define TICKET_RIGHTS_ID_OFFSET 0x2A0
#define TICKET_MIN_SIZE (TICKET_RIGHTS_ID_OFFSET + 0x10)  /* 0x2B0 */

typedef struct {
    FILE *file;
    hactool_ctx_t *tool_ctx;
    pfs0_ctx_t pfs0_ctx;
} nsp_ctx_t;

void nsp_process(nsp_ctx_t *ctx);
void nsp_print(nsp_ctx_t *ctx);
void nsp_save(nsp_ctx_t *ctx);

#endif
