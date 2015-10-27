/*
 *     Filename: impl.h
 *  Description: Header file for template implementation
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include <stdint.h>

#include "common/buffer.h"
#include "common/mpool.h"
#include "common/sort.h"

#include "common/point_range.h"
#include "common/rule_trace.h"
#include "clsfy/hypersplit.h"
#include "group/rfg.h"

/* buffer */
VECTOR_PROTOTYPE(extern, prefix_vector, struct prefix)

VECTOR_PROTOTYPE(extern, rule_vector, struct rule)

/* mpool */
MPOOL_PROTOTYPE(extern, hsn_pool)

/* sort */
ISORT_PROTOTYPE(extern, int, int)
QSORT_PROTOTYPE(extern, int, int)

ISORT_PROTOTYPE(extern, int64, int64_t)
QSORT_PROTOTYPE(extern, int64, int64_t)

ISORT_PROTOTYPE(extern, rng_rid, struct rfg_rng_rid)
QSORT_PROTOTYPE(extern, rng_rid, struct rfg_rng_rid)

BSEARCH_PROTOTYPE(extern, rng_idx, struct rfg_rng_idx)

