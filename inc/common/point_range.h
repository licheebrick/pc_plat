/*
 *     Filename: point_range.h
 *  Description: Header file for point and range operations
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __POINT_RANGE_H__
#define __POINT_RANGE_H__

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>
#include "common/buffer.h"


/* TODO: This version only supports little endian */
union point {
    struct { uint64_t low, high; } u128;
    uint64_t u64;
    uint32_t u32;
    uint16_t u16;
    uint8_t u8;
};

struct range {
    union point begin;
    union point end;
};

struct prefix {
    union point value;
    int prefix_len;
};

VECTOR(prefix_vector, struct prefix);


static inline int point_is_zero(union point p)
{
    return !(p.u128.high | p.u128.low);
}

static inline int point_is_equal(union point left, union point right)
{
    return !((left.u128.high ^ right.u128.high)
            | (left.u128.low ^ right.u128.low));
}

static inline int point_is_less(union point left, union point right)
{
    return left.u128.high < right.u128.high
        || (left.u128.high == right.u128.high
                && left.u128.low < right.u128.low);
}

static inline int point_is_less_equal(union point left, union point right)
{
    return left.u128.high < right.u128.high
        || (left.u128.high == right.u128.high
                && left.u128.low <= right.u128.low);
}

static inline int point_is_greater(union point left, union point right)
{
    return left.u128.high > right.u128.high
        || (left.u128.high == right.u128.high
                && left.u128.low > right.u128.low);
}

static inline int point_is_greater_equal(union point left, union point right)
{
    return left.u128.high > right.u128.high
        || (left.u128.high == right.u128.high
                && left.u128.low >= right.u128.low);
}

static inline void point_not(union point *p_out, union point p)
{
    assert(p_out);

    p_out->u128.high = ~p.u128.high;
    p_out->u128.low = ~p.u128.low;

    return;
}

static inline void point_and(union point *p_out, union point p1, union point p2)
{
    assert(p_out);

    p_out->u128.high = p1.u128.high & p2.u128.high;
    p_out->u128.low = p1.u128.low & p2.u128.low;

    return;
}

static inline void point_or(union point *p_out, union point p1, union point p2)
{
    assert(p_out);

    p_out->u128.high = p1.u128.high | p2.u128.high;
    p_out->u128.low = p1.u128.low | p2.u128.low;

    return;
}

static inline void point_xor(union point *p_out, union point p1, union point p2)
{
    assert(p_out);

    p_out->u128.high = p1.u128.high ^ p2.u128.high;
    p_out->u128.low = p1.u128.low ^ p2.u128.low;

    return;
}

static inline void point_xnor(union point *p_out, union point p1, union point p2)
{
    assert(p_out);

    p_out->u128.high = ~(p1.u128.high ^ p2.u128.high);
    p_out->u128.low = ~(p1.u128.low ^ p2.u128.low);

    return;
}

static inline void point_increase(union point *p_pnt)
{
    assert(p_pnt);

    if (++p_pnt->u128.low == 0) {
        p_pnt->u128.high++;
    }

    return;
}

static inline void point_decrease(union point *p_pnt)
{
    assert(p_pnt);

    if (p_pnt->u128.low-- == 0) {
        p_pnt->u128.high--;
    }

    return;
}

static inline void point_set_bit(union point *p_pnt, unsigned int bit)
{
    assert(p_pnt && bit < 128);

    if (bit < 64) {
        p_pnt->u128.low |= 1ULL << bit;
    } else {
        p_pnt->u128.high |= 1ULL << (bit - 64);
    }

    return;
}

static inline void point_clear_bit(union point *p_pnt, unsigned int bit)
{
    assert(p_pnt && bit < 128);

    if (bit < 64) {
        p_pnt->u128.low &= ~(1ULL << bit);
    } else {
        p_pnt->u128.high &= ~(1ULL << (bit - 64));
    }

    return;
}

static inline int point_compare(const void *p_left, const void *p_right)
{
    union point *p_pt_left = (typeof(p_pt_left))p_left;
    union point *p_pt_right = (typeof(p_pt_left))p_right;

    assert(p_left && p_right);

    if (point_is_greater(*p_pt_left, *p_pt_right)) {
        return 1;
    } else if (point_is_less(*p_pt_left, *p_pt_right)) {
        return -1;
    } else {
        return 0;
    }
}

static inline void point_print(const union point *p_pnt)
{
    if (p_pnt) {
        fprintf(stdout, "Point: %016"PRIx64"%016"PRIx64"\n",
                p_pnt->u128.high, p_pnt->u128.low);
    } else {
        fprintf(stdout, "Point: NULL\n");
    }

    return;
}

void gen_prefix_mask(union point *p_out, unsigned int bits,
        unsigned int mask_len);
void gen_suffix_mask(union point *p_out, unsigned int mask_len);

int prefix2range(struct range *p_range, const struct prefix *p_prefix,
        unsigned int bits);
int range2prefix(struct prefix_vector *p_vector, const struct range *p_range,
        unsigned int bits);

#endif /* __POINT_RANGE_H__ */

