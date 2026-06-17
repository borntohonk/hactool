#ifndef HACTOOL_BKTR_H
#define HACTOOL_BKTR_H

#include "types.h"
#include <stdint.h>

#define MAGIC_BKTR 0x52544B42 /* "BKTR" in little-endian */
#define BKTR_VERSION 1

/* ============================= */
/* BKTR Header (Legacy Format) */
/* ============================= */

/**
 * Legacy BKTR Header from PatchInfo superblock.
 * This is used to describe the relocation and subsection tables within
 * the NCA section, including their offset and size within the section.
 * Size: 0x20 bytes
 */
#pragma pack(push, 1)
typedef struct {
    uint64_t offset;      /* Offset of this BKTR table within the section */
    uint64_t size;        /* Size of this BKTR table */
    uint32_t magic;       /* MAGIC_BKTR ("BKTR") */
    uint32_t version;     /* Version (matches bktr_table_header_t.version) */
    uint32_t num_entries; /* Number of entries in the BKTR */
    uint32_t reserved;    /* Reserved */
} bktr_header_t;
#pragma pack(pop)

/**
 * Formal BucketTree Header - From official specification.
 * This is the header found at the beginning of actual BKTR node data.
 * Size: 0x10 bytes
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;      /* MAGIC_BKTR ("BKTR") */
    uint32_t version;    /* Version (usually 1) */
    int32_t entry_count; /* Total number of entries across all buckets */
    uint32_t reserved;   /* Reserved, must be 0 */
} bktr_table_header_t;
#pragma pack(pop)

/**
 * BucketTree Node Header - Standard node header used in bucket tree.
 * Size: 0x10 bytes
 */
#pragma pack(push, 1)
typedef struct {
    int32_t index;  /* Node index (bucket number) */
    int32_t count;  /* Number of entries in this node */
    int64_t offset; /* End offset for this node */
} bktr_node_header_t;
#pragma pack(pop)

/* =========================== */
/* Relocation Table Structures */
/* =========================== */

/**
 * Relocation Entry - Maps virtual offsets to physical offsets in RomFS patches.
 * Size: 0x14 bytes
 * 
 * Used in the Relocation BKTR table (first BKTR entry in PatchInfo).
 * Entries are sorted by virt_offset in ascending order.
 */
#pragma pack(push, 1)
typedef struct {
    uint64_t virt_offset;  /* Virtual offset in patched RomFS */
    uint64_t phys_offset;  /* Physical offset in source RomFS */
    uint32_t is_patch;     /* 1 = from patch RomFS, 0 = from base RomFS */
} bktr_relocation_entry_t;
#pragma pack(pop)

/**
 * Relocation Bucket - Container for relocation entries in a flat structure.
 * This is NOT the standard hierarchical bucket tree format, but rather
 * the simplified format used by the ROM patching system.
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint32_t num_entries;
    uint64_t virtual_offset_end;
    bktr_relocation_entry_t entries[0x3FF0/sizeof(bktr_relocation_entry_t)];
    uint8_t padding[0x3FF0 % sizeof(bktr_relocation_entry_t)];
} bktr_relocation_bucket_t;
#pragma pack(pop)

/**
 * Relocation Block - Root node containing offset table for all relocation buckets.
 * This is the top-level structure that maps virtual offsets to buckets.
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint32_t num_buckets;
    uint64_t total_size;
    uint64_t bucket_virtual_offsets[0x3FF0/sizeof(uint64_t)];
    bktr_relocation_bucket_t buckets[];
} bktr_relocation_block_t;
#pragma pack(pop)

/* ========================= */
/* Subsection Table Structures */
/* ========================= */

/**
 * Subsection Entry - Defines CTR and offset information for encrypted subsections.
 * Size: 0xC bytes
 * 
 * Used in the Subsection BKTR table (second BKTR entry in PatchInfo).
 * Entries are sorted by offset in ascending order.
 * Each subsection has its own AES-CTR counter value.
 */
#pragma pack(push, 1)
typedef struct {
    uint64_t  offset;  /* Offset within patch RomFS */
    uint32_t _0x8;    /* Reserved/padding */
    uint32_t ctr_val; /* AES-CTR counter value for this subsection */
} bktr_subsection_entry_t;
#pragma pack(pop)

/**
 * Subsection Bucket - Container for subsection entries.
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint32_t num_entries;
    uint64_t physical_offset_end;
    bktr_subsection_entry_t entries[0x3FF];
} bktr_subsection_bucket_t;
#pragma pack(pop)

/**
 * Subsection Block - Root node containing offset table for all subsection buckets.
 */
#pragma pack(push, 1)
typedef struct {
    uint32_t index;
    uint32_t num_buckets;
    uint64_t total_size;
    uint64_t bucket_physical_offsets[0x3FF0/sizeof(uint64_t)];
    bktr_subsection_bucket_t buckets[];
} bktr_subsection_block_t;
#pragma pack(pop)


/* ===================== */
/* BKTR Validation Functions */
/* ===================== */

/**
 * Verify a bucket tree table header structure (formal header from spec).
 * Checks magic, version, and entry count validity.
 * Returns: 0 if valid, non-zero if invalid.
 */
int bktr_table_header_verify(const bktr_table_header_t *header);

/**
 * Verify a bucket tree node header structure.
 * Checks index, count, offset, and bounds.
 * Returns: 0 if valid, non-zero if invalid.
 */
int bktr_node_header_verify(const bktr_node_header_t *header,
                            int32_t expected_index,
                            size_t node_size,
                            size_t entry_size);

/* ================================ */
/* Relocation Table Access Functions */
/* ================================ */

/**
 * Get a pointer to a relocation bucket within the relocation block.
 * 
 * @param block: Relocation block root
 * @param i: Bucket index
 * @return: Pointer to the bucket, or NULL if index out of range
 */
bktr_relocation_bucket_t *bktr_get_relocation_bucket(bktr_relocation_block_t *block, uint32_t i);

/**
 * Get a relocation entry from offset and relocation block.
 * Performs binary search through the appropriate bucket to find the entry
 * whose virt_offset is less than or equal to the target offset.
 * 
 * @param block: Relocation block (root node)
 * @param offset: Virtual offset to search for
 * @return: Pointer to matching relocation entry, or NULL on error
 */
bktr_relocation_entry_t *bktr_get_relocation(bktr_relocation_block_t *block, uint64_t offset);

/* ================================ */
/* Subsection Table Access Functions */
/* ================================ */

/**
 * Get a pointer to a subsection bucket within the subsection block.
 * 
 * @param block: Subsection block root  
 * @param i: Bucket index
 * @return: Pointer to the bucket, or NULL if index out of range
 */
bktr_subsection_bucket_t *bktr_get_subsection_bucket(bktr_subsection_block_t *block, uint32_t i);

/**
 * Get a subsection entry from offset and subsection block.
 * Performs binary search through the appropriate bucket to find the entry
 * whose offset is less than or equal to the target offset.
 * 
 * @param block: Subsection block (root node)
 * @param offset: Physical offset to search for
 * @return: Pointer to matching subsection entry, or NULL on error
 */
bktr_subsection_entry_t *bktr_get_subsection(bktr_subsection_block_t *block, uint64_t offset);

#endif
