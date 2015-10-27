/*
 *     Filename: hypersplit.c
 *  Description: Source file for HyperSplit
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <float.h>
#include <sys/queue.h>

#include "common/impl.h"
#include "common/utils.h"
#include "clsfy/hypersplit.h"


struct hs_queue_entry {
    uint32_t space[DIM_MAX][2];
    STAILQ_ENTRY(hs_queue_entry) e;
    ssize_t node_id;
    int *rule_id;
    int rule_num;
    int depth;
};

STAILQ_HEAD(hs_queue_head, hs_queue_entry);

struct hs_runtime {
    struct shadow_range shadow_rngs[DIM_MAX];
    int64_t *shadow_pnts[DIM_MAX];
    struct hsn_pool node_pool;
    struct hs_queue_head wqh;
    const struct partition *p_pa;
    struct hs_tree *trees;
    int cur;
};


static int f_hs_init(struct hs_runtime *p_hs_rt, const struct partition *p_pa);
static void f_hs_term(struct hs_runtime *p_hs_rt);

static int f_hs_trigger(struct hs_runtime *p_hs_rt);
static int f_hs_process(struct hs_runtime *p_hs_rt);
static int f_hs_gather(struct hs_runtime *p_hs_rt);

static int f_hs_dim_decision(struct hs_runtime *p_hs_rt,
        const struct hs_queue_entry *p_wqe);
static uint32_t f_hs_pnt_decision(const struct shadow_range *p_shadow_rng);
static int f_hs_spawn(struct hs_runtime *p_hs_rt, struct hs_queue_entry *p_wqe,
        int split_dim, int is_inplace);

static int f_space_is_fully_covered(uint32_t (*left)[2], uint32_t (*right)[2]);


int hs_build(void *built_result, const struct partition *p_pa)
{
    int ret;
    struct hs_runtime hs_rt;
    struct hs_result *p_hs_result;

    if (!built_result || !p_pa || !p_pa->subsets || p_pa->subset_num <= 0 ||
        p_pa->subset_num > PART_MAX || p_pa->rule_num <= 1) {
        return -EINVAL;
    }

    /* Init */
    ret = f_hs_init(&hs_rt, p_pa);
    if (ret) {
        return ret;
    }

    /* Build hypersplit tree for each subset */
    for (hs_rt.cur = 0; hs_rt.cur < p_pa->subset_num; hs_rt.cur++) {

        /* trigger entry enqueue */
        ret = f_hs_trigger(&hs_rt);
        if (ret) {
            goto err;
        }

        /* hypersplit building */
        ret = f_hs_process(&hs_rt);
        if (ret) {
            goto err;
        }

        /* write subset result */
        ret = f_hs_gather(&hs_rt);
        if (ret) {
            goto err;
        }
    }

    /* Write final result */
    p_hs_result = malloc(sizeof(*p_hs_result));
    if (!p_hs_result) {
        ret = -ENOMEM;
        goto err;
    }

    p_hs_result->trees = hs_rt.trees;
    hs_rt.trees = NULL;
    p_hs_result->tree_num = p_pa->subset_num;
    p_hs_result->def_rule = p_pa->subsets[0].def_rule;
    *(typeof(p_hs_result) *)built_result = p_hs_result;

    /* Term */
    f_hs_term(&hs_rt);

    return 0;

err:
    while (--hs_rt.cur >= 0) {
        free(hs_rt.trees[hs_rt.cur].p_root);
    }

    f_hs_term(&hs_rt);

    return ret;
}

int hs_search(const struct trace *p_t, const void *built_result)
{
    int i, j, pri;
    const struct hs_result *p_hs_result;

    register uint32_t id, offset;
    register const struct packet *p_pkt;
    register const struct hs_node *p_node, *p_root;

    if (!p_t || !p_t->pkts || !built_result) {
        return -EINVAL;
    }

    p_hs_result = *(typeof(p_hs_result) *)built_result;
    if (!p_hs_result || !p_hs_result->trees) {
        return -EINVAL;
    }

    /* For each packet */
    offset = p_hs_result->def_rule + 1;
    for (i = 0; i < p_t->pkt_num; i++) {

        /* For each tree */
        pri = p_hs_result->def_rule, p_pkt = &p_t->pkts[i];
        for (j = 0; j < p_hs_result->tree_num; j++) {

            /* For each node */
            id = offset, p_root = p_hs_result->trees[j].p_root;
            do {
                p_node = p_root + id - offset;
                id = p_pkt->dims[p_node->dim] <= p_node->thresh ?
                    p_node->lchild : p_node->rchild;
            } while (id >= offset);

            if (id < pri) {
                pri = id;
            }
        }

        if (pri != p_t->pkts[i].match_rule) {
            fprintf(stderr, "packet %d match %d, but should match %d\n",
                    i, pri, p_t->pkts[i].match_rule);
            return -EFAULT;
        }
    }

    return 0;
}

void hs_destroy(void *built_result)
{
    int i;
    struct hs_result *p_hs_result;

    if (!built_result) {
        return;
    }

    p_hs_result = *(typeof(p_hs_result) *)built_result;
    if (!p_hs_result || !p_hs_result->trees) {
        return;
    }

    for (i = 0; i < p_hs_result->tree_num; i++) {
        free(p_hs_result->trees[i].p_root);
    }

    free(p_hs_result->trees);
    free(p_hs_result);

    return;
}

static int f_hs_init(struct hs_runtime *p_hs_rt, const struct partition *p_pa)
{
    int i, null_flag = 0;
    struct hs_tree *trees;
    int64_t **shadow_pnts;
    struct shadow_range *shadow_rngs;

    shadow_pnts = p_hs_rt->shadow_pnts;
    shadow_rngs = p_hs_rt->shadow_rngs;
    for (i = 0; i < DIM_MAX; i++) {
        shadow_pnts[i] = malloc((p_pa->rule_num << 1) *
                sizeof(*shadow_pnts[i]));
        shadow_rngs[i].pnts = malloc((p_pa->rule_num << 2) *
                sizeof(*shadow_rngs[i].pnts));
        shadow_rngs[i].cnts = malloc((p_pa->rule_num << 1) *
                sizeof(*shadow_rngs[i].cnts));
        if (!shadow_pnts[i] || !shadow_rngs[i].pnts || !shadow_rngs[i].cnts) {
            null_flag = 1;
        }
    }

    trees = calloc(p_pa->subset_num, sizeof(*trees));
    if (null_flag || !trees) {
        free(trees);

        for (i = 0; i < DIM_MAX; i++) {
            free(shadow_rngs[i].cnts);
            free(shadow_rngs[i].pnts);
            free(shadow_pnts[i]);
        }

        return -ENOMEM;
    }

    MPOOL_INIT(&p_hs_rt->node_pool, p2roundup(p_pa->rule_num) << 1);
    STAILQ_INIT(&p_hs_rt->wqh);
    p_hs_rt->p_pa = p_pa;
    p_hs_rt->trees = trees;

    return 0;
}

static void f_hs_term(struct hs_runtime *p_hs_rt)
{
    int i;
    struct hs_queue_head *p_wqh = &p_hs_rt->wqh;
    int64_t **shadow_pnts = p_hs_rt->shadow_pnts;
    struct shadow_range *shadow_rngs = p_hs_rt->shadow_rngs;

    while (!STAILQ_EMPTY(p_wqh)) {
        struct hs_queue_entry *p_wqe = STAILQ_FIRST(p_wqh);
        STAILQ_REMOVE_HEAD(p_wqh, e);
        free(p_wqe->rule_id);
        free(p_wqe);
    }

    MPOOL_TERM(&p_hs_rt->node_pool);
    free(p_hs_rt->trees);

    for (i = 0; i < DIM_MAX; i++) {
        free(shadow_rngs[i].cnts);
        free(shadow_rngs[i].pnts);
        free(shadow_pnts[i]);
    }

    return;
}

static int f_hs_trigger(struct hs_runtime *p_hs_rt)
{
    ssize_t node_id;
    struct hs_tree *p_tree;
    const struct rule_set *p_rs;
    static uint32_t space[DIM_MAX][2] = {
        {0, UINT32_MAX}, {0, UINT32_MAX},
        {0, UINT16_MAX}, {0, UINT16_MAX},
        {0, UINT8_MAX}
    };

    assert(p_hs_rt && p_hs_rt->trees);
    assert(p_hs_rt->p_pa->subsets[p_hs_rt->cur].rules);
    assert(p_hs_rt->p_pa->subsets[p_hs_rt->cur].rule_num > 1);

    MPOOL_RESET(&p_hs_rt->node_pool);
    node_id = MPOOL_MALLOC(hsn_pool, &p_hs_rt->node_pool);
    if (node_id == -1) {
        return -ENOMEM;
    }

    p_tree = &p_hs_rt->trees[p_hs_rt->cur];
    p_rs = &p_hs_rt->p_pa->subsets[p_hs_rt->cur];

    /* There is no need to build trees: only the tree root */
    if (f_space_is_fully_covered(space, p_rs->rules[0].dims)) {
        struct hs_node *p_root = MPOOL_ADDR(&p_hs_rt->node_pool, node_id);
        p_root->thresh = UINT32_MAX;
        p_root->dim = DIM_SIP;
        p_root->lchild = p_rs->rules[0].pri;
        p_tree->inode_num = p_tree->enode_num = p_tree->depth_max = 1;
        p_tree->depth_avg = 1.0;

    /* The tree root needs split */
    } else {
        int i, *rule_id = malloc(p_rs->rule_num * sizeof(*rule_id));
        struct hs_queue_entry *p_wqe = malloc(sizeof(*p_wqe));
        if (!rule_id || !p_wqe) {
            free(p_wqe);
            free(rule_id);
            return -ENOMEM;
        }

        for (i = 0; i < p_rs->rule_num; i++) {
            rule_id[i] = i;
        }
        memcpy(p_wqe->space, space, sizeof(space));
        p_wqe->node_id = node_id;
        p_wqe->rule_id = rule_id;
        p_wqe->rule_num = p_rs->rule_num;
        p_wqe->depth = 1;
        p_tree->inode_num++;
        STAILQ_INSERT_HEAD(&p_hs_rt->wqh, p_wqe, e);
    }

    return 0;
}

static int f_hs_process(struct hs_runtime *p_hs_rt)
{
    struct hs_queue_head *p_wqh;
    struct hs_queue_entry *p_wqe;

    /* The loop processes all internal nodes */
    p_wqh = &p_hs_rt->wqh;
    while (!STAILQ_EMPTY(p_wqh)) {
        int split_dim;
        struct hs_node *p_node;
        uint32_t split_pnt, orig_end, *split_rng;

        p_wqe = STAILQ_FIRST(p_wqh);
        STAILQ_REMOVE_HEAD(p_wqh, e);

        /* choose split dimension */
        split_dim = f_hs_dim_decision(p_hs_rt, p_wqe);
        if (split_dim == DIM_INV) {
            goto err;
        }

        /* choose split point */
        assert(split_dim > DIM_INV && split_dim < DIM_MAX);
        split_pnt = f_hs_pnt_decision(&p_hs_rt->shadow_rngs[split_dim]);

        p_node = MPOOL_ADDR(&p_hs_rt->node_pool, p_wqe->node_id);
        p_node->dim = split_dim;
        p_node->thresh = split_pnt;

        /* process left child: require a new wqe */
        split_rng = p_wqe->space[split_dim];
        orig_end = split_rng[1], split_rng[1] = split_pnt;
        if (f_hs_spawn(p_hs_rt, p_wqe, split_dim, 0)) {
            goto err;
        }

        /* process right child: reuse current wqe */
        split_rng[1] = orig_end, split_rng[0] = split_pnt + 1;
        if (f_hs_spawn(p_hs_rt, p_wqe, split_dim, 1)) {
            goto err;
        }
    }

    return 0;

err:
    free(p_wqe->rule_id);
    free(p_wqe);

    return -ENOMEM;
}

static int f_hs_gather(struct hs_runtime *p_hs_rt)
{
    struct hs_node *p_root;
    struct hs_tree *p_tree;
    struct hsn_pool *p_node_pool;

    p_node_pool = &p_hs_rt->node_pool;
    p_root = realloc(MPOOL_BASE(p_node_pool),
            MPOOL_COUNT(p_node_pool) * sizeof(*p_root));
    if (!p_root) {
        return -ENOMEM;
    }

    MPOOL_BASE(p_node_pool) = NULL;
    p_tree = &p_hs_rt->trees[p_hs_rt->cur];
    p_tree->p_root = p_root;
    p_tree->depth_avg /= p_tree->enode_num;
    assert(p_tree->inode_num == MPOOL_COUNT(p_node_pool));
    assert(p_tree->enode_num == p_tree->inode_num + 1);

    return 0;
}

static int f_hs_dim_decision(struct hs_runtime *p_hs_rt,
        const struct hs_queue_entry *p_wqe)
{
    int i, dim, pnt_num;
    int64_t **shadow_pnts;
    struct shadow_range *shadow_rngs;
    const struct rule *rules;
    /* float measure, measure_min = FLT_MAX; */
    long measure, measure_min = LONG_MAX;

    assert(p_wqe && p_wqe->rule_id && p_wqe->rule_num > 1);

    shadow_pnts = p_hs_rt->shadow_pnts;
    shadow_rngs = p_hs_rt->shadow_rngs;
    rules = p_hs_rt->p_pa->subsets[p_hs_rt->cur].rules;

    for (dim = DIM_INV, i = 0; i < DIM_MAX; i++) {
        if (shadow_rules(&shadow_rngs[i], shadow_pnts[i], p_wqe->space[i],
            p_wqe->rule_id, p_wqe->rule_num, rules, i)) {
            return DIM_INV;
        }

        pnt_num = shadow_rngs[i].pnt_num;
        if (pnt_num <= 2) { /* no more range */
            continue;
        }

        /* the former is original measure, and the latter is adapted to rfg */
        /* measure = shadow_rngs[i].total / (float)(pnt_num >> 1); */
        measure = shadow_rngs[i].total - (pnt_num >> 1);
        if (measure < measure_min) { /* the less, the better */
            measure_min = measure;
            dim = i;
        }
    }

    return dim;
}

static uint32_t f_hs_pnt_decision(const struct shadow_range *p_shadow_rng)
{
    int i, measure, measure_max, rng_num_max;

    assert(p_shadow_rng && p_shadow_rng->pnts && p_shadow_rng->cnts);

    measure = p_shadow_rng->cnts[0];
    measure_max = p_shadow_rng->total >> 1; /* binary cut */
    rng_num_max = (p_shadow_rng->pnt_num >> 1) - 1;
    assert(rng_num_max > 0);

    for (i = 1; i < rng_num_max && measure < measure_max; i++) {
        measure += p_shadow_rng->cnts[i];
    }

    return p_shadow_rng->pnts[(i << 1) - 1];
}

static int f_hs_spawn(struct hs_runtime *p_hs_rt, struct hs_queue_entry *p_wqe,
        int split_dim, int is_inplace)
{
    struct hs_node *p_node;
    struct hs_queue_entry *p_new_wqe;
    register int i, rid, new_rule_num, *new_rule_id;

    struct hs_tree *p_tree = &p_hs_rt->trees[p_hs_rt->cur];
    const struct rule_set *p_rs = &p_hs_rt->p_pa->subsets[p_hs_rt->cur];
    register const uint32_t *split_rng = p_wqe->space[split_dim];

    /* Get all intersected rules */
    if (is_inplace) {
        new_rule_id = p_wqe->rule_id;
    } else {
        new_rule_id = malloc(p_wqe->rule_num * sizeof(*new_rule_id));
        if (!new_rule_id) {
            return -ENOMEM;
        }
    }

    for (new_rule_num = i = 0; i < p_wqe->rule_num; i++) {
        rid = p_wqe->rule_id[i];
        if (p_rs->rules[rid].dims[split_dim][0] <= split_rng[1] &&
            p_rs->rules[rid].dims[split_dim][1] >= split_rng[0]) {
            new_rule_id[new_rule_num++] = rid;
        }
    }

    /* External node */
    rid = new_rule_id[0];
    if (f_space_is_fully_covered(p_wqe->space, p_rs->rules[rid].dims)) {
        p_tree->enode_num++;
        p_tree->depth_avg += p_wqe->depth;
        if (p_wqe->depth > p_tree->depth_max) {
            p_tree->depth_max = p_wqe->depth;
        }

        p_node = MPOOL_ADDR(&p_hs_rt->node_pool, p_wqe->node_id);
        free(new_rule_id);
        if (is_inplace) {
            free(p_wqe);
            p_node->rchild = p_rs->rules[rid].pri;
        } else {
            p_node->lchild = p_rs->rules[rid].pri;
        }

    /* Internal node */
    } else {
        uint32_t offset = p_rs->def_rule + 1;
        ssize_t node_id = MPOOL_MALLOC(hsn_pool, &p_hs_rt->node_pool);
        if (node_id == -1) {
            goto err;
        }

        p_node = MPOOL_ADDR(&p_hs_rt->node_pool, p_wqe->node_id);
        if (is_inplace) {
            p_new_wqe = p_wqe;
            p_node->rchild = node_id + offset;
        } else {
            p_new_wqe = malloc(sizeof(*p_new_wqe));
            if (!p_new_wqe) {
                goto err;
            }
            p_node->lchild = node_id + offset;
            memcpy(p_new_wqe->space, p_wqe->space, sizeof(p_new_wqe->space));
            p_new_wqe->rule_id = new_rule_id;
        }
        p_new_wqe->node_id = node_id;
        p_new_wqe->rule_num = new_rule_num;
        p_new_wqe->depth = p_wqe->depth + 1;
        p_tree->inode_num++;
        STAILQ_INSERT_HEAD(&p_hs_rt->wqh, p_new_wqe, e);
    }

    return 0;

err:
    if (!is_inplace) {
        free(new_rule_id);
    }

    return -ENOMEM;
}

static int f_space_is_fully_covered(uint32_t (*left)[2], uint32_t (*right)[2])
{
    int i;

    assert(left && right);

    for (i = 0; i < DIM_MAX; i++) {
        /* left is fully covered by right */
        if (left[i][0] < right[i][0] || left[i][1] > right[i][1]) {
            return 0;
        }
    }

    return 1;
}

