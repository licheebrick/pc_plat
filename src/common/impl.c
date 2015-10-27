/*
 *     Filename: impl.c
 *  Description: Source file for template implementation
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include "common/impl.h"

/* buffer */
VECTOR_GENERATE(extern, prefix_vector, struct prefix)

VECTOR_GENERATE(extern, rule_vector, struct rule)

/* mpool */
MPOOL_GENERATE(extern, hsn_pool)

/* sort */
static inline long int_cmp(const int *p_left, const int *p_right)
{
    return *p_left - *p_right;
}

ISORT_GENERATE(extern, int, int, int_cmp)
QSORT_GENERATE(extern, int, int, int_cmp)

static inline long int64_cmp(const int64_t *p_left, const int64_t *p_right)
{
    return (*p_left > *p_right) - (*p_left < *p_right);
}

ISORT_GENERATE(extern, int64, int64_t, int64_cmp)
QSORT_GENERATE(extern, int64, int64_t, int64_cmp)

static inline long rfg_rng_rid_cmp(const struct rfg_rng_rid *p_left,
        const struct rfg_rng_rid *p_right)
{
    return (p_left->value > p_right->value) - (p_left->value < p_right->value);
}

ISORT_GENERATE(extern, rng_rid, struct rfg_rng_rid, rfg_rng_rid_cmp)
QSORT_GENERATE(extern, rng_rid, struct rfg_rng_rid, rfg_rng_rid_cmp)

static inline long rfg_rng_idx_cmp(const struct rfg_rng_idx *p_left,
        const struct rfg_rng_idx *p_right)
{
    if (p_left->range[0] <= p_right->range[1] &&
        p_left->range[1] >= p_right->range[0]) {
        return 0;
    }

    return p_right->range[0] > p_left->range[1] ? -1 : 1;
}

BSEARCH_GENERATE(extern, rng_idx, struct rfg_rng_idx, rfg_rng_idx_cmp)

