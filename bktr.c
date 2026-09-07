#include "bktr.h"
#include "utils.h"
#include <string.h>
#include <stddef.h>

/* ================================ */
/* Header Validation Functions */
/* ================================ */

/**
 * Verify a bucket tree table header (formal header from specification).
 * Checks:
 * - Magic is MAGIC_BKTR
 * - Version is BKTR_VERSION or lower
 * - Entry count is valid (not negative)
 * 
 * @param header: Header to verify
 * @return: 0 if valid, non-zero if invalid
 */
int bktr_table_header_verify(const bktr_table_header_t *header) {
    if (header == NULL) {
        fprintf(stderr, "BKTR table header is NULL\n");
        return 1;
    }
    
    if (header->magic != MAGIC_BKTR) {
        fprintf(stderr, "Invalid BKTR magic: 0x%08X (expected 0x%08X)\n", 
                header->magic, MAGIC_BKTR);
        return 1;
    }
    
    if (header->version > BKTR_VERSION) {
        fprintf(stderr, "Unsupported BKTR version: %u (max supported: %u)\n",
                header->version, BKTR_VERSION);
        return 1;
    }
    
    if (header->entry_count < 0) {
        fprintf(stderr, "Invalid BKTR entry count: %d\n", header->entry_count);
        return 1;
    }
    
    if (header->reserved != 0) {
        fprintf(stderr, "Warning: BKTR header reserved field is non-zero: 0x%08X\n",
                header->reserved);
        /* Non-fatal, continue */
    }
    
    return 0;
}

/**
 * Verify a bucket tree node header.
 * Checks:
 * - Node index matches expected index
 * - Entry count is within valid range for the node size and entry size
 * - Offset is non-negative
 * 
 * @param header: Node header to verify
 * @param expected_index: Expected node index
 * @param node_size: Size of this node in bytes
 * @param entry_size: Size of each entry in bytes
 * @return: 0 if valid, non-zero if invalid
 */
int bktr_node_header_verify(const bktr_node_header_t *header,
                            int32_t expected_index,
                            size_t node_size,
                            size_t entry_size) {
    if (header == NULL) {
        fprintf(stderr, "BKTR node header is NULL\n");
        return 1;
    }
    
    if (header->index != expected_index) {
        fprintf(stderr, "BKTR node index mismatch: got %d, expected %d\n",
                header->index, expected_index);
        return 1;
    }
    
    if (entry_size == 0 || node_size < entry_size + sizeof(bktr_node_header_t)) {
        fprintf(stderr, "Invalid BKTR node size/entry size: node_size=%zu, entry_size=%zu\n",
                node_size, entry_size);
        return 1;
    }
    
    /* Calculate maximum number of entries that can fit in this node */
    size_t max_entry_count = (node_size - sizeof(bktr_node_header_t)) / entry_size;
    
    if (header->count <= 0 || (size_t)header->count > max_entry_count) {
        fprintf(stderr, "Invalid BKTR node entry count: %d (max: %zu)\n",
                header->count, max_entry_count);
        return 1;
    }
    
    if (header->offset < 0) {
        fprintf(stderr, "Invalid BKTR node offset: %lld\n", (long long)header->offset);
        return 1;
    }
    
    return 0;
}

/* ================================ */
/* Relocation Bucket Access */
/* ================================ */

/**
 * Get a relocation bucket from the relocation block.
 *
 * Buckets are stored packed (one 0x4000 node after another) on disk, but are
 * respread in memory by nca_process_bktr_section() with a gap of one entry
 * after each bucket. That gap holds the sentinel entry written at
 * entries[num_entries], which would otherwise overrun a full bucket. The
 * stride below must therefore stay sizeof(bucket) + sizeof(entry), matching
 * the slack reserved by the calloc() in nca_process_bktr_section().
 * 
 * @param block: Relocation block root
 * @param i: Bucket index (0-based)
 * @return: Pointer to the bucket
 */
bktr_relocation_bucket_t *bktr_get_relocation_bucket(bktr_relocation_block_t *block, uint32_t i) {
    if (block == NULL) {
        return NULL;
    }
    
    if (i >= block->num_buckets) {
        /* Note: do not report "max = num_buckets - 1"; num_buckets is unsigned and
         * this check is reached precisely when the block is empty, where it underflows. */
        fprintf(stderr, "BKTR relocation bucket index %u out of range (block has %u bucket(s))\n", i, block->num_buckets);
        return NULL;
    }
    
    return (bktr_relocation_bucket_t *)((uint8_t *)block->buckets + (sizeof(bktr_relocation_bucket_t) + sizeof(bktr_relocation_entry_t)) * i);
}

/* ================================ */
/* Relocation Entry Search */
/* ================================ */

/**
 * Binary search for a relocation entry within a bucket.
 * Finds the entry with the largest virt_offset that is <= target_offset.
 * 
 * @param entries: Array of relocation entries
 * @param entry_count: Number of entries in the array
 * @param target_offset: Virtual offset to search for
 * @return: Index of matching entry (0 to entry_count-1), or -1 if not found
 */
static int32_t bktr_binary_search_relocation_in_bucket(const bktr_relocation_entry_t *entries,
                                                       uint32_t entry_count,
                                                       uint64_t target_offset) {
    if (entry_count == 0 || entries == NULL) {
        return -1;
    }
    
    /* Check if target is before first entry */
    if (target_offset < entries[0].virt_offset) {
        return -1;
    }
    
    int32_t left = 0, right = (int32_t)entry_count - 1;
    int32_t result = -1;
    
    /* Binary search for the largest offset <= target */
    while (left <= right) {
        int32_t mid = left + (right - left) / 2;
        
        if (entries[mid].virt_offset <= target_offset) {
            result = mid;
            left = mid + 1;  /* Look for potentially larger matching offset */
        } else {
            right = mid - 1; /* This offset is too large */
        }
    }
    
    return result;
}

/**
 * Get a relocation entry from the relocation block by virtual offset.
 * Determines which bucket to search based on the bucket virtual offset array,
 * then performs binary search within that bucket.
 * 
 * @param block: Relocation block (root node)
 * @param offset: Virtual offset to search for
 * @return: Pointer to matching relocation entry, or NULL on error
 */
bktr_relocation_entry_t *bktr_get_relocation(bktr_relocation_block_t *block, uint64_t offset) {
    if (block == NULL) {
        fprintf(stderr, "BKTR relocation block is NULL\n");
        return NULL;
    }
    
    if (offset > block->total_size) {
        fprintf(stderr, "Virtual offset 0x%"PRIx64" exceeds total relocation size 0x%"PRIx64"\n", 
                offset, block->total_size);
        return NULL;
    }
    
    /* Find which bucket contains this offset */
    uint32_t bucket_num = 0;
    for (unsigned int i = 1; i < block->num_buckets; i++) {
        if (block->bucket_virtual_offsets[i] <= offset) {
            bucket_num = i;
        } else {
            break;
        }
    }
    
    if (bucket_num >= block->num_buckets) {
        fprintf(stderr, "BKTR relocation bucket number %u invalid (block has %u bucket(s))\n", bucket_num, block->num_buckets);
        return NULL;
    }
    
    /* Get the bucket and verify it */
    bktr_relocation_bucket_t *bucket = bktr_get_relocation_bucket(block, bucket_num);
    if (bucket == NULL) {
        return NULL;
    }
    
    /* Special case: edge case with single entry for optimization */
    if (bucket->num_entries == 1) {
        return &bucket->entries[0];
    }
    
    /* Binary search within the bucket */
    int32_t entry_idx = bktr_binary_search_relocation_in_bucket(
        bucket->entries, bucket->num_entries, offset);
    
    if (entry_idx < 0) {
        fprintf(stderr, "Failed to find virtual offset 0x%"PRIx64" in BKTR relocation bucket %u\n", 
                offset, bucket_num);
        return NULL;
    }
    
    return &bucket->entries[entry_idx];
}

/* ================================ */
/* Subsection Bucket Access */
/* ================================ */

/**
 * Get a subsection bucket from the subsection block.
 *
 * As with bktr_get_relocation_bucket(), the stride includes one extra entry
 * so that the sentinel written at entries[num_entries] does not overrun a full
 * bucket into the next bucket's header.
 * 
 * @param block: Subsection block root
 * @param i: Bucket index (0-based)
 * @return: Pointer to the bucket
 */
bktr_subsection_bucket_t *bktr_get_subsection_bucket(bktr_subsection_block_t *block, uint32_t i) {
    if (block == NULL) {
        return NULL;
    }
    
    if (i >= block->num_buckets) {
        /* Note: do not report "max = num_buckets - 1"; num_buckets is unsigned and
         * this check is reached precisely when the block is empty, where it underflows. */
        fprintf(stderr, "BKTR subsection bucket index %u out of range (block has %u bucket(s))\n", i, block->num_buckets);
        return NULL;
    }
    
    return (bktr_subsection_bucket_t *)((uint8_t *)block->buckets + (sizeof(bktr_subsection_bucket_t) + sizeof(bktr_subsection_entry_t)) * i);
}

/* ================================ */
/* Subsection Entry Search */
/* ================================ */

/**
 * Binary search for a subsection entry within a bucket.
 * Finds the entry with the largest offset that is <= target_offset.
 * 
 * @param entries: Array of subsection entries
 * @param entry_count: Number of entries in the array
 * @param target_offset: Physical offset to search for
 * @return: Index of matching entry (0 to entry_count-1), or -1 if not found
 */
static int32_t bktr_binary_search_subsection_in_bucket(const bktr_subsection_entry_t *entries,
                                                       uint32_t entry_count,
                                                       uint64_t target_offset) {
    if (entry_count == 0 || entries == NULL) {
        return -1;
    }
    
    /* Check if target is before first entry */
    if (target_offset < entries[0].offset) {
        return -1;
    }
    
    int32_t left = 0, right = (int32_t)entry_count - 1;
    int32_t result = -1;
    
    /* Binary search for the largest offset <= target */
    while (left <= right) {
        int32_t mid = left + (right - left) / 2;
        
        if (entries[mid].offset <= target_offset) {
            result = mid;
            left = mid + 1;  /* Look for potentially larger matching offset */
        } else {
            right = mid - 1; /* This offset is too large */
        }
    }
    
    return result;
}

/**
 * Get a subsection entry from the subsection block by physical offset.
 * Determines which bucket to search based on the bucket physical offset array,
 * then performs binary search within that bucket.
 * 
 * Special case: If offset is >= the end of the last bucket, returns the last
 * subsection entry (represents the BKTR header subsection).
 * 
 * @param block: Subsection block (root node)
 * @param offset: Physical offset to search for
 * @return: Pointer to matching subsection entry, or NULL on error
 */
bktr_subsection_entry_t *bktr_get_subsection(bktr_subsection_block_t *block, uint64_t offset) {
    if (block == NULL) {
        fprintf(stderr, "BKTR subsection block is NULL\n");
        return NULL;
    }
    
    /* Special case handling for offset past the physical data */
    /* This represents reading from the BKTR header subsection */
    if (block->num_buckets > 0) {
        bktr_subsection_bucket_t *last_bucket = bktr_get_subsection_bucket(block, block->num_buckets - 1);
        if (last_bucket != NULL && offset >= last_bucket->entries[last_bucket->num_entries].offset) {
            return &last_bucket->entries[last_bucket->num_entries];
        }
    }
    
    /* Find which bucket contains this offset */
    uint32_t bucket_num = 0;
    for (unsigned int i = 1; i < block->num_buckets; i++) {
        if (block->bucket_physical_offsets[i] <= offset) {
            bucket_num = i;
        } else {
            break;
        }
    }
    
    if (bucket_num >= block->num_buckets) {
        fprintf(stderr, "BKTR subsection bucket number %u invalid (block has %u bucket(s))\n", bucket_num, block->num_buckets);
        return NULL;
    }
    
    /* Get the bucket and verify it */
    bktr_subsection_bucket_t *bucket = bktr_get_subsection_bucket(block, bucket_num);
    if (bucket == NULL) {
        return NULL;
    }
    
    /* Special case: edge case with single entry for optimization */
    if (bucket->num_entries == 1) {
        return &bucket->entries[0];
    }
    
    /* Binary search within the bucket */
    int32_t entry_idx = bktr_binary_search_subsection_in_bucket(
        bucket->entries, bucket->num_entries, offset);
    
    if (entry_idx < 0) {
        fprintf(stderr, "Failed to find physical offset 0x%"PRIx64" in BKTR subsection bucket %u\n", 
                offset, bucket_num);
        return NULL;
    }
    
    return &bucket->entries[entry_idx];
}
