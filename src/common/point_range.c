/*
 *     Filename: point_range.c
 *  Description: Source file for point and range operations
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include <errno.h>
#include <limits.h>
#include "common/impl.h"
#include "common/point_range.h"


void gen_prefix_mask(union point *p_out, unsigned int bits,
        unsigned int mask_len)
{
    if (!p_out || bits > 128 || mask_len > bits) {
        return;
    }

    if (!mask_len) {
        p_out->u128.high = 0;
        p_out->u128.low = 0;

    } else if (mask_len <= 64) {
        if (bits < 64) {
            p_out->u128.high = 0;
            p_out->u128.low = ~((1ULL << (bits - mask_len)) - 1)
                & ((1ULL << bits) - 1);

        } else if (bits == 64) {
            p_out->u128.high = 0;
            p_out->u128.low = ~((1ULL << (64 - mask_len)) - 1);

        } else {
            p_out->u128.high = ~((1ULL << (64 - mask_len)) - 1);
            p_out->u128.low = 0;
        }

    } else {
        p_out->u128.high = UINT64_MAX;
        p_out->u128.low = ~((1ULL << (128 - mask_len)) - 1);
    }

    return;
}

void gen_suffix_mask(union point *p_out, unsigned int mask_len)
{
    if (!p_out || mask_len > 128) {
        return;
    }

    if (mask_len < 64) {
        p_out->u128.high = 0;
        p_out->u128.low = (1ULL << mask_len) - 1;

    } else if (mask_len == 64) {
        p_out->u128.high = 0;
        p_out->u128.low = UINT64_MAX;

    } else if (mask_len < 128) {
        p_out->u128.high = (1ULL << (mask_len - 64)) - 1;
        p_out->u128.low = UINT64_MAX;

    } else {
        p_out->u128.high = UINT64_MAX;
        p_out->u128.low = UINT64_MAX;
    }

    return;
}

int prefix2range(struct range *p_range, const struct prefix *p_prefix,
        unsigned int bits)
{
    union point pnt;

    if (!p_range || !p_prefix || bits > 128 || bits < p_prefix->prefix_len) {
        return -EINVAL;
    }

    gen_prefix_mask(&pnt, bits, p_prefix->prefix_len);
    point_and(&p_range->begin, p_prefix->value, pnt);

    gen_suffix_mask(&pnt, bits - p_prefix->prefix_len);
    point_or(&p_range->end, p_prefix->value, pnt);

    return 0;
}

int range2prefix(struct prefix_vector *p_vector, const struct range *p_range,
        unsigned int bits)
{
    int i;
    struct prefix *p_prefix;
    union point begin, mask, and, or;

    if (!p_vector || !p_range || bits > 128) {
        return -EINVAL;
    }

    begin = p_range->begin;
    while (point_is_less_equal(begin, p_range->end)) {
        for (i = 1; i <= bits; i++) {
            gen_suffix_mask(&mask, i);
            point_and(&and, begin, mask);
            point_or(&or, begin, mask);
            if (!point_is_zero(and) || point_is_greater(or, p_range->end)) {
                break;
            }
        }

        if (VECTOR_FULL(p_vector) && VECTOR_EXTEND(prefix_vector,
            p_vector, VECTOR_LEN(p_vector) + 1)) {
            return -ENOMEM;
        }
        p_prefix = VECTOR_ADDR(p_vector, VECTOR_LEN(p_vector));
        p_prefix->value = begin;
        p_prefix->prefix_len = bits - i + 1;
        VECTOR_LEN(p_vector)++;

        gen_suffix_mask(&mask, i - 1);
        point_or(&begin, begin, mask);
        point_increase(&begin);
        if (point_is_zero(begin)) {
            break;
        }
    }

    return 0;
}

