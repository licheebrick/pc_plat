/*
 *     Filename: rfg.h
 *  Description: Header file for Replication Free Grouping
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __RFG_H__
#define __RFG_H__

#include <stdint.h>
#include "common/rule_trace.h"


struct rfg_rng_rid {
    uint64_t value; /* (range_len << 32 | range_begin) */
    int rule_id;
};

struct rfg_rng_idx {
    uint32_t range[2];
    uint32_t index[2];
};


int rf_group(struct partition *p_pa_grp, const struct partition *p_pa_orig);

#endif /* __RFG_H__ */

