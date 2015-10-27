#include "common/sort.h"

#if !SORT_MACRO
enum {
    SORT_UNIT64,
    SORT_UNIT32,
    SORT_UNIT8
};

#define SORT_UNIT(size) ({ \
        const typeof(size) __size = (size); \
        (__size & (sizeof(uint64_t) - 1) ? (__size & (sizeof(uint32_t) - 1) ? \
        SORT_UNIT8 : SORT_UNIT32) : SORT_UNIT64);})

#define SORT_UNIT_NUM(size) ({ \
        const typeof(size) __size = (size); \
        (__size & (sizeof(uint64_t) - 1) ? (__size & (sizeof(uint32_t) - 1) ? \
        __size : __size >> 2) : __size >> 3);})

#define SORT_COPY(a, b, unit, unit_num) \
    do { \
        long __i = (unit_num); \
        switch (unit) { \
        case SORT_UNIT64: { \
            uint64_t *pa = (typeof(pa))(a); \
            uint64_t *pb = (typeof(pa))(b); \
            do { \
                *pa++ = *pb++; \
            } while (--__i > 0); \
            break; \
        } \
        case SORT_UNIT32: { \
            uint32_t *pa = (typeof(pa))(a); \
            uint32_t *pb = (typeof(pa))(b); \
            do { \
                *pa++ = *pb++; \
            } while (--__i > 0); \
            break; \
        } \
        case SORT_UNIT8: { \
            uint8_t *pa = (typeof(pa))(a); \
            uint8_t *pb = (typeof(pa))(b); \
            do { \
                *pa++ = *pb++; \
            } while (--__i > 0); \
            break; \
        } \
        } \
    } while (0)

#define SORT_SWAP(a, b, unit, unit_num) \
    do { \
        union { uint64_t u64; uint32_t u32; uint8_t u8; } __tmp; \
        long __i = (unit_num); \
        switch (unit) { \
        case SORT_UNIT64: { \
            uint64_t *pa = (typeof(pa))(a); \
            uint64_t *pb = (typeof(pa))(b); \
            do { \
                __tmp.u64 = *pa; \
                *pa++ = *pb; \
                *pb++ = __tmp.u64; \
            } while (--__i > 0); \
            break; \
        } \
        case SORT_UNIT32: { \
            uint32_t *pa = (typeof(pa))(a); \
            uint32_t *pb = (typeof(pa))(b); \
            do { \
                __tmp.u32 = *pa; \
                *pa++ = *pb; \
                *pb++ = __tmp.u32; \
            } while (--__i > 0); \
            break; \
        } \
        case SORT_UNIT8: { \
            uint8_t *pa = (typeof(pa))(a); \
            uint8_t *pb = (typeof(pa))(b); \
            do { \
                __tmp.u8 = *pa; \
                *pa++ = *pb; \
                *pb++ = __tmp.u8; \
            } while (--__i > 0); \
            break; \
        } \
        } \
    } while (0)

static inline void *medium3(void *a, void *b, void *c, sort_cmp_t cmp)
{
    return cmp(a, b) < 0 ? (cmp(b, c) < 0 ? b : (cmp(a, c) < 0 ? c : a))
        : (cmp(b, c) > 0 ? b : (cmp(a, c) < 0 ? a : c));
}

long binary_search(const void *key, const void *base, size_t num, size_t size,
        sort_cmp_t cmp)
{
    size_t start = 0, end = num;

    while (start < end) {
        size_t mid = start + ((end - start) >> 1);
        long result = cmp(key, (uint8_t *)base + mid * size);
        if (result < 0) {
            end = mid;
        } else if (result > 0) {
            start = mid + 1;
        } else {
            return mid;
        }
    }

    return -1;
}

void insert_sort(void *base, size_t num, size_t size, sort_cmp_t cmp)
{
    uint8_t *sorted, *cur, *prev, *base_u8 = base;
    const long unit = SORT_UNIT(size), unit_num = SORT_UNIT_NUM(size);

    for (sorted = base_u8 + size; --num > 0; sorted += size) {
        if (cmp(cur = sorted, base_u8) < 0) {
            while (cur > base_u8) {
                prev = cur - size;
                SORT_SWAP(prev, cur, unit, unit_num);
                cur = prev;
            }
        } else {
            while (cmp(prev = cur - size, cur) > 0) {
                SORT_SWAP(prev, cur, unit, unit_num);
                cur = prev;
            }
        }
    }
}

void quick_sort(void *base, size_t num, size_t size, sort_cmp_t cmp)
{
    long result, swapped = 0;
    const long unit = SORT_UNIT(size), unit_num = SORT_UNIT_NUM(size);
    uint8_t *l_begin, *l_end, *r_begin, *r_end, *end, *base_u8 = base;

loop:
    /* switch to insert_sort */
    if (num < 7) {
        goto fast;
    }

    { /* pivot selection */
        uint8_t *begin = base_u8;
        uint8_t *medium = base_u8 + (num >> 1) * size;
        end = base_u8 + (num - 1) * size;
        if (num > 40) {
            size_t seg = (num >> 3) * size;
            begin = medium3(begin, begin + seg, begin + (seg << 1), cmp);
            medium = medium3(medium - seg, medium, medium + seg, cmp);
            end = medium3(end - (seg << 1), end - seg, end, cmp);
        }
        medium = medium3(begin, medium, end, cmp);
        SORT_SWAP(base_u8, medium, unit, unit_num);
    }

    /* partition */
    l_begin = l_end = base_u8 + size;
    r_begin = r_end = base_u8 + (num - 1) * size;
    while (1) {
        while (l_end <= r_begin && (result = cmp(l_end, base_u8)) <= 0) {
            if (!result) {
                SORT_SWAP(l_begin, l_end, unit, unit_num);
                l_begin += size;
                swapped = 1;
            }
            l_end += size;
        }
        while (l_end <= r_begin && (result = cmp(r_begin, base_u8)) >= 0) {
            if (!result) {
                SORT_SWAP(r_begin, r_end, unit, unit_num);
                r_end -= size;
                swapped = 1;
            }
            r_begin -= size;
        }
        if (l_end > r_begin) {
            break;
        }
        SORT_SWAP(l_end, r_begin, unit, unit_num);
        l_end += size;
        r_begin -= size;
        swapped = 1;
    }
    if (!swapped) {
        goto fast;
    }
    if ((result = MIN(l_begin - base_u8, l_end - l_begin))) {
        SORT_SWAP(base_u8, l_end - result, unit, result / size * unit_num);
    }
    end = base_u8 + num * size;
    if ((result = MIN(r_end - r_begin, end - r_end - size))) {
        SORT_SWAP(l_end, end - result, unit, result / size * unit_num);
    }

    /* sort left part */
    if ((result = l_end - l_begin) > size) {
        quick_sort(base_u8, result / size, size, cmp);
    }

    /* sort right part */
    if ((result = r_end - r_begin) > size) {
        base_u8 = end - result;
        num = result / size;
        goto loop;
    }

    return;

fast:
    insert_sort(base_u8, num, size, cmp);
    return;
}

long merge_sort(void *base, void *buf, size_t num, size_t size, sort_cmp_t cmp)
{
    size_t i, step;
    uint8_t *bases[2], *src = base;
    const long unit = SORT_UNIT(size), unit_num = SORT_UNIT_NUM(size);

    /* first pass: insert_sort */
    for (i = 0, step = size << 3; i < num; i += 8, src += step) {
        insert_sort(src, i + 8 < num ? 8 : num - i, size, cmp);
    }
    if (num <= 8) {
        return 0;
    }

    /* pairwise merge */
    bases[0] = base;
    if (!(bases[1] = buf ? buf : malloc(num * size))) {
        return -ENOMEM;
    }
    for (step = 8, i = 0; step < num; step <<= 1, i ^= 1) {
        size_t j, mlen = step << 1;
        uint8_t *dst = bases[i ^ 1];
        for (j = 0, src = bases[i]; j < num; j += mlen) {
            size_t mindex = j * size;
            uint8_t *l_end, *r_end, *p = dst + mindex;
            uint8_t *l = src + mindex, *r = l + step * size;
            if (j + step > num) {
                l_end = src;
                r_end = src + num * size;
            } else {
                l_end = r;
                r_end = j + mlen > num ? src + num * size : l + mlen * size;
            }
            while (l < l_end && r < r_end) {
                if (cmp(l, r) < 0) {
                    SORT_COPY(p, l, unit, unit_num);
                    l += size;
                } else {
                    SORT_COPY(p, r, unit, unit_num);
                    r += size;
                }
                p += size;
            }
            while (l < l_end) {
                SORT_COPY(p, l, unit, unit_num);
                p += size, l += size;
            }
            while (r < r_end) {
                SORT_COPY(p, r, unit, unit_num);
                p += size, r += size;
            }
        }
    }

    /* cleanup */
    if (i) {
        memcpy(base, bases[1], num * size);
    }
    if (!buf) {
        free(bases[1]);
    }

    return 0;
}

#endif /* !SORT_MACRO */

