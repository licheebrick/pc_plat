/*
 *     Filename: rule_trace.c
 *  Description: Source file for rule and trace operations
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *               Chang Chen (ck-cc@hotmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common/impl.h"
#include "common/point_range.h"
#include "common/rule_trace.h"


int load_rules(struct rule_set *p_rs, const char *s_rf)
{
    FILE *fp_rule;
    struct rule *rules;

    uint32_t src_ip_0, src_ip_1, src_ip_2, src_ip_3, src_ip_mask;
    uint32_t dst_ip_0, dst_ip_1, dst_ip_2, dst_ip_3, dst_ip_mask;
    int ret, i = 0;

    if (!p_rs || !s_rf) {
        return -EINVAL;
    }

    fprintf(stderr, "Loading rules from %s\n", s_rf);

    fp_rule = fopen(s_rf, "r");
    if (!fp_rule) {
        fprintf(stderr, "Cannot open file %s", s_rf);
        return -errno;
    }

    rules = calloc(RULE_MAX, sizeof(*rules));
    if (!rules) {
        perror("Cannot allocate memory for rules");
        fclose(fp_rule);
        return -ENOMEM;
    }

    /* scan rule file */
    while (!feof(fp_rule)) {
        if (i >= RULE_MAX) {
            fprintf(stderr, "Too many rules\n");
            ret = -ENOTSUP;
            goto err;
        }

        if (fscanf(fp_rule, WUSTL_RULE_FMT_SCN,
            &src_ip_0, &src_ip_1, &src_ip_2, &src_ip_3, &src_ip_mask,
            &dst_ip_0, &dst_ip_1, &dst_ip_2, &dst_ip_3, &dst_ip_mask,
            &rules[i].dims[DIM_SPORT][0], &rules[i].dims[DIM_SPORT][1],
            &rules[i].dims[DIM_DPORT][0], &rules[i].dims[DIM_DPORT][1],
            &rules[i].dims[DIM_PROTO][0], &rules[i].dims[DIM_PROTO][1]) != 16) {
            fprintf(stderr, "Illegal rule format\n");
            ret = -ENOTSUP;
            goto err;
        }

        /* src ip */
        src_ip_0 = (src_ip_0 << 24) | (src_ip_1 << 16) |
            (src_ip_2 << 8) | src_ip_3;
        src_ip_mask = (uint32_t)(~((1ULL << (32 - src_ip_mask)) - 1));
        rules[i].dims[DIM_SIP][0] = src_ip_0 & src_ip_mask;
        rules[i].dims[DIM_SIP][1] = src_ip_0 | (~src_ip_mask);

        /* dst ip */
        dst_ip_0 = (dst_ip_0 << 24) | (dst_ip_1 << 16) |
            (dst_ip_2 << 8) | dst_ip_3;
        dst_ip_mask = (uint32_t)(~((1ULL << (32 - dst_ip_mask)) - 1));
        rules[i].dims[DIM_DIP][0] = dst_ip_0 & dst_ip_mask;
        rules[i].dims[DIM_DIP][1] = dst_ip_0 | (~dst_ip_mask);

        /* proto */
        if (rules[i].dims[DIM_PROTO][1] == 0xff) {
            rules[i].dims[DIM_PROTO][1] = rules[i].dims[DIM_PROTO][0];

        } else if (!rules[i].dims[DIM_PROTO][1]) {
            rules[i].dims[DIM_PROTO][0] = 0;
            rules[i].dims[DIM_PROTO][1] = 0xff;
        }

        rules[i].pri = i;
        i++;
    }

    p_rs->rules = rules;
    p_rs->rule_num = i;
    p_rs->def_rule = i - 1;

    fclose(fp_rule);
    fprintf(stderr, "%d rules loaded\n", i);

    return 0;

err:
    free(rules);
    fclose(fp_rule);

    return ret;
}

void unload_rules(struct rule_set *p_rs)
{
    if (!p_rs) {
        return;
    }

    free(p_rs->rules);

    return;
}

int load_trace(struct trace *p_t, const char *s_tf)
{
    FILE *fp_trace;
    struct packet *pkts;
    int ret, i = 0;

    if (!p_t || !s_tf) {
        return -EINVAL;
    }

    fprintf(stderr, "Loading trace from %s\n", s_tf);

    fp_trace = fopen(s_tf, "r");
    if (!fp_trace) {
        fprintf(stderr, "Cannot open file %s", s_tf);
        return -errno;
    }

    pkts = calloc(PKT_MAX, sizeof(*pkts));
    if (!pkts) {
        perror("Cannot allocate memory for packets");
        fclose(fp_trace);
        return -ENOMEM;
    }

    /* scan trace file */
    while (!feof(fp_trace)) {
        if (i >= PKT_MAX) {
            fprintf(stderr, "Too many packets\n");
            ret = -ENOTSUP;
            goto err;
        }

        if (fscanf(fp_trace, WUSTL_PKT_FMT_SCN,
            &pkts[i].dims[DIM_SIP], &pkts[i].dims[DIM_DIP],
            &pkts[i].dims[DIM_SPORT], &pkts[i].dims[DIM_DPORT],
            &pkts[i].dims[DIM_PROTO], &pkts[i].match_rule) != 6) {
            fprintf(stderr, "Illegal packet format\n");
            ret = -ENOTSUP;
            goto err;
        }

        pkts[i].match_rule--;
        i++;
    }

    p_t->pkts = pkts;
    p_t->pkt_num = i;

    fclose(fp_trace);
    fprintf(stderr, "%d packets loaded\n", i);

    return 0;

err:
    free(pkts);
    fclose(fp_trace);

    return ret;
}

void unload_trace(struct trace *p_t)
{
    if (!p_t) {
        return;
    }

    free(p_t->pkts);

    return;
}

int load_partition(struct partition *p_pa, const char *s_pf)
{
    FILE *fp_part;
    struct rule_set *subsets;
    struct rule *rules;

    uint32_t part_idx, rule_num;
    int ret, i = 0;

    if (!p_pa || !s_pf) {
        return -EINVAL;
    }

    fprintf(stderr, "Loading partition from %s\n", s_pf);

    fp_part = fopen(s_pf, "r");
    if (!fp_part) {
        fprintf(stderr, "Cannot open file %s", s_pf);
        return -errno;
    }

    subsets = calloc(PART_MAX, sizeof(*subsets));
    if (!subsets) {
        perror("Cannot allocate memory for subsets");
        fclose(fp_part);
        return -ENOMEM;
    }

    p_pa->rule_num = p_pa->subset_num = 0;

    while (!feof(fp_part)) {
        if (p_pa->subset_num >= PART_MAX) {
            fprintf(stderr, "Too many partitions\n");
            ret = -ENOTSUP;
            goto err;
        }

        if (fscanf(fp_part, PART_HEAD_FMT_SCN, &part_idx, &rule_num) != 2) {
            fprintf(stderr, "Illegal partition header format\n");
            ret = -ENOTSUP;
            goto err;
        }

        rules = calloc(rule_num, sizeof(*rules));
        if (!rules) {
            perror("Cannot allocate memory for rules");
            ret = -ENOMEM;
            goto err;
        }

        for (i = 0; i < rule_num; i++) {
            if (fscanf(fp_part, PART_RULE_FMT_SCN,
                &rules[i].dims[DIM_SIP][0], &rules[i].dims[DIM_SIP][1],
                &rules[i].dims[DIM_DIP][0], &rules[i].dims[DIM_DIP][1],
                &rules[i].dims[DIM_SPORT][0], &rules[i].dims[DIM_SPORT][1],
                &rules[i].dims[DIM_DPORT][0], &rules[i].dims[DIM_DPORT][1],
                &rules[i].dims[DIM_PROTO][0], &rules[i].dims[DIM_PROTO][1],
                &rules[i].pri) != 11) {
                fprintf(stderr, "Illegal partition rule format\n");
                free(rules);
                ret = -ENOTSUP;
                goto err;
            }
        }

        subsets[part_idx].rules = rules;
        subsets[part_idx].rule_num = rule_num;
        subsets[part_idx].def_rule = rules[i - 1].pri;

        p_pa->rule_num += rule_num;
        p_pa->subset_num++;
    }

    p_pa->subsets = subsets;
    p_pa->rule_num -= p_pa->subset_num - 1;

    fclose(fp_part);
    fprintf(stderr, "%d subsets and %d rules loaded\n",
            p_pa->subset_num, p_pa->rule_num);

    return 0;

err:
    while (--p_pa->subset_num >= 0) {
        unload_rules(&subsets[p_pa->subset_num]);
    };

    free(subsets);
    fclose(fp_part);

    return ret;
}

void unload_partition(struct partition *p_pa)
{
    int subset_num;
    struct rule_set *subsets;

    if (!p_pa || !p_pa->subsets) {
        return;
    }

    subset_num = p_pa->subset_num;
    subsets = p_pa->subsets;

    while (--subset_num >= 0) {
        unload_rules(&subsets[subset_num]);
    };

    free(subsets);

    return;
}

void dump_partition(const char *s_pf, const struct partition *p_pa)
{
    int i, j;
    FILE *fp_part;

    if (!s_pf || !p_pa || !p_pa->subsets) {
        return;
    }

    fprintf(stderr, "Dumping partition to %s\n", s_pf);

    fp_part = fopen(s_pf, "w+");
    if (!fp_part) {
        fprintf(stderr, "Cannot open file %s", s_pf);
        fp_part = stdout;
    }

    for (i = 0; i < p_pa->subset_num; i++) {
        fprintf(fp_part, PART_HEAD_FMT_PRI, i, p_pa->subsets[i].rule_num);

        for (j = 0; j < p_pa->subsets[i].rule_num; j++) {
            fprintf(fp_part, PART_RULE_FMT_PRI,
                p_pa->subsets[i].rules[j].dims[DIM_SIP][0],
                p_pa->subsets[i].rules[j].dims[DIM_SIP][1],
                p_pa->subsets[i].rules[j].dims[DIM_DIP][0],
                p_pa->subsets[i].rules[j].dims[DIM_DIP][1],
                p_pa->subsets[i].rules[j].dims[DIM_SPORT][0],
                p_pa->subsets[i].rules[j].dims[DIM_SPORT][1],
                p_pa->subsets[i].rules[j].dims[DIM_DPORT][0],
                p_pa->subsets[i].rules[j].dims[DIM_DPORT][1],
                p_pa->subsets[i].rules[j].dims[DIM_PROTO][0],
                p_pa->subsets[i].rules[j].dims[DIM_PROTO][1],
                p_pa->subsets[i].rules[j].pri);
        }
    }

    if (fp_part != stdout) {
        fclose(fp_part);
    }

    return;
}

int revert_partition(struct rule_set *p_rs, const struct partition *p_pa)
{
    struct rule *rules;
    struct rule_set *p_irs;
    int i, j, subset_num, rule_num;

    if (!p_rs || !p_pa || !p_pa->subsets) {
        return -EINVAL;
    }

    rules = calloc(p_pa->rule_num, sizeof(*rules));
    if (!rules) {
        perror("Cannot allocate memory for rules");
        return -ENOMEM;
    }

    for (subset_num = p_pa->subset_num, i = 0; i < subset_num; i++) {
        p_irs = p_pa->subsets + i;

        for (rule_num = p_irs->rule_num, j = 0; j < rule_num; j++) {
            rules[p_irs->rules[j].pri] = p_irs->rules[j];
        }
    }

    p_rs->rules = rules;
    p_rs->rule_num = p_pa->rule_num;
    p_rs->def_rule = p_pa->subsets[0].def_rule;

    return 0;
}

int split_range_rule(struct rule_vector *p_vector, const struct rule *p_rule)
{
    struct range rng;
    struct rule *p_new_rule;
    int d, ret, curs[DIM_MAX];
    struct prefix_vector prefixes[DIM_MAX];
    static const unsigned int bits[DIM_MAX] = {32, 32, 16, 16, 8};

    if (!p_vector || !p_rule) {
        return -EINVAL;
    }

    /* range2prefix on each dimension INDEPENDENTLY */
    memset(&rng, 0, sizeof(rng));
    memset(&curs, 0, sizeof(curs));

    for (ret = d = 0; d < DIM_MAX; d++) {
        rng.begin.u32 = p_rule->dims[d][0];
        rng.end.u32 = p_rule->dims[d][1];
        VECTOR_INIT(&prefixes[d]);

        ret = range2prefix(&prefixes[d], &rng, bits[d]);
        if (ret) {
            while (--d >= 0) {
                VECTOR_TERM(&prefixes[d]);
            }
            return ret;
        }
    }

    /* CROSS PRODUCT all dimensions */
    while (curs[DIM_SIP] < VECTOR_LEN(&prefixes[DIM_SIP])) {
        /* generate one rule */
        if (VECTOR_FULL(p_vector) && VECTOR_EXTEND(rule_vector,
            p_vector, VECTOR_LEN(p_vector) + 1)) {
            ret = -ENOMEM;
            break;
        }
        p_new_rule = VECTOR_ADDR(p_vector, VECTOR_LEN(p_vector));
        p_new_rule->pri = p_rule->pri;
        for (d = 0; d < DIM_MAX; d++) {
            prefix2range(&rng, VECTOR_ADDR(&prefixes[d], curs[d]), bits[d]);
            p_new_rule->dims[d][0] = rng.begin.u32;
            p_new_rule->dims[d][1] = rng.end.u32;
        }
        VECTOR_LEN(p_vector)++;

        /* calculate the carry from the last dimension */
        d = DIM_PROTO, curs[d]++;
        while (curs[d] == VECTOR_LEN(&prefixes[d]) && d > DIM_SIP) {
            curs[d] = 0, curs[--d]++;
        }
    }

    for (d = 0; d < DIM_MAX; d++) {
        VECTOR_TERM(&prefixes[d]);
    }

    return ret;
}

int shadow_rules(struct shadow_range *srngs, int64_t *spnts,
        const uint32_t dim_rng[2], const int *rule_id, int rule_num,
        const struct rule *rules, int dim)
{
    uint32_t *pnts, begin, end;
    int *cnts, i, last, cur_cnt, total, pnt_num, spnt_num;

    if (!srngs || !srngs->pnts || !dim_rng || dim_rng[0] > dim_rng[1] ||
        !rule_id || !rule_num || !rules || dim <= DIM_INV || dim >= DIM_MAX) {
        return -EINVAL;
    }

    spnt_num = rule_num << 1;
    /* step 1: project and sort */
    for (i = 0; i < spnt_num; i++) {
        begin = rules[rule_id[i >> 1]].dims[dim][0];
        spnts[i] = begin < dim_rng[0] ? dim_rng[0] : begin;
        spnts[i] <<= 1;

        end = rules[rule_id[i >> 1]].dims[dim][1];
        spnts[++i] = end > dim_rng[1] ? dim_rng[1] : end;
        spnts[i] = (spnts[i] << 1) + 1;
    }

    QSORT(int64, spnts, spnt_num);

    /* step 2: de-duplicated and output */
    pnts = srngs->pnts;
    cnts = srngs->cnts;
    cur_cnt = total = 0;

    for (pnt_num = last = 0, i = 1; i < spnt_num; i++) {
        if (spnts[last] == spnts[i]) {
            continue;
        }

        if (spnts[last] & 1) { /* last is end */
            if (cnts) {
                cur_cnt -= i - last;
            }

            if (spnts[i] & 1) { /* cur is end */
                if (cnts) {
                    total += cur_cnt;
                    cnts[pnt_num >> 1] = cur_cnt;
                }

                pnts[pnt_num] = (spnts[last] >> 1) + 1;
                pnts[pnt_num + 1] = spnts[i] >> 1;
                pnt_num += 2;

            } else if (spnts[last] + 1 != spnts[i]) { /* cur is begin */
                if (cnts) {
                    total += cur_cnt;
                    cnts[pnt_num >> 1] = cur_cnt;
                }

                pnts[pnt_num] = (spnts[last] >> 1) + 1;
                pnts[pnt_num + 1] = (spnts[i] >> 1) - 1;
                pnt_num += 2;
            }

        } else { /* last is begin */
            if (cnts) {
                cur_cnt += i - last;
                total += cur_cnt;
                cnts[pnt_num >> 1] = cur_cnt;
            }

            pnts[pnt_num] = spnts[last] >> 1;
            pnts[pnt_num + 1] = spnts[i] >> 1;

            if (!(spnts[i] & 1)) { /* cur is begin */
                pnts[pnt_num + 1]--;
            }

            pnt_num += 2;
        }

        last = i;
    }

    srngs->pnt_num  = pnt_num;
    srngs->total = total;

    return 0;
}

