/*
 *     Filename: hypersplit.h
 *  Description: Header file for HyperSplit
 *
 *       Author: Yaxuan Qi (yaxuan@tsinghua.edu.cn)
 *               Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *         Note: The implementation is totally refactored by Xiang Wang
 */

#ifndef __HYPERSPLIT_H__
#define __HYPERSPLIT_H__

#include <stdint.h>
#include "common/mpool.h"
#include "common/rule_trace.h"

#define NODE_NUM_BITS 29
#define NODE_NUM_MAX (1 << NODE_NUM_BITS)


struct hs_node {
    uint64_t thresh;
    uint32_t dim    : 32 - NODE_NUM_BITS;
    uint32_t lchild : NODE_NUM_BITS;
    uint32_t pack   : 32 - NODE_NUM_BITS;
    uint32_t rchild : NODE_NUM_BITS;
};

struct hs_tree {
    struct hs_node *p_root;
    int inode_num;
    int enode_num;
    int depth_max;
    double depth_avg;
};

struct hs_result {
    struct hs_tree *trees;
    int tree_num;
    int def_rule;
};

MPOOL(hsn_pool, struct hs_node);


int hs_build(void *built_result, const struct partition *p_pa);
int hs_search(const struct trace *p_t, const void *built_result);
void hs_destroy(void *built_result);

#endif /* __HYPERSPLIT_H__ */

