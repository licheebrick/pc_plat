#ifndef __SORT_H__
#define __SORT_H__

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include "common/utils.h"

#define SORT_MACRO 1

#if SORT_MACRO
#define BSEARCH_PROTOTYPE(scope, name, type_t) \
    scope long name##_BSEARCH(const type_t *key, const type_t *base, \
            size_t num);

#define BSEARCH_GENERATE(scope, name, type_t, cmp) \
    scope long name##_BSEARCH(const type_t *key, const type_t *base, \
            size_t num) \
    { \
        size_t start = 0, end = num; \
        while (start < end) { \
            size_t mid = start + ((end - start) >> 1); \
            long result = cmp(key, base + mid); \
            if (result < 0) { \
                end = mid; \
            } else if (result > 0) { \
                start = mid + 1; \
            } else { \
                return mid; \
            } \
        } \
        return -1; \
    }

#define ISORT_PROTOTYPE(scope, name, type_t) \
    scope void name##_ISORT(type_t *base, size_t num);

#define ISORT_GENERATE(scope, name, type_t, cmp) \
    scope void name##_ISORT(type_t *base, size_t num) \
    { \
        type_t tmp, *sorted, *cur, *prev; \
        for (sorted = base + 1; --num > 0; sorted++) { \
            tmp = *sorted; \
            if (cmp(cur = sorted, base) < 0) { \
                while (cur > base) { \
                    prev = cur - 1; \
                    *cur = *prev; \
                    cur = prev; \
                } \
            } else { \
                while (cmp(prev = cur - 1, &tmp) > 0) { \
                    *cur = *prev; \
                    cur = prev; \
                } \
            } \
            *cur = tmp; \
        } \
    }

#define QSORT_PROTOTYPE(scope, name, type_t) \
    scope type_t *name##_MEDIUM3(type_t *a, type_t *b, type_t *c); \
    scope void name##_QSORT(type_t *base, size_t num); \

#define QSORT_GENERATE(scope, name, type_t, cmp) \
    scope type_t *name##_MEDIUM3(type_t *a, type_t *b, type_t *c) \
    { \
        return cmp(a, b) < 0 ? (cmp(b, c) < 0 ? b : (cmp(a, c) < 0 ? c : a)) \
            : (cmp(b, c) > 0 ? b : (cmp(a, c) < 0 ? a : c)); \
    } \
    \
    scope void name##_QSORT(type_t *base, size_t num) \
    { \
        long result, swapped = 0; \
        type_t *l_begin, *l_end, *r_begin, *r_end, *end; \
    loop: \
        if (num < 7) { \
            goto fast; \
        } \
        { \
            type_t *begin = base; \
            type_t *medium = base + (num >> 1); \
            end = base + num - 1; \
            if (num > 40) { \
                size_t seg = num >> 3; \
                begin = name##_MEDIUM3(begin, begin + seg, begin + (seg << 1));\
                medium = name##_MEDIUM3(medium - seg, medium, medium + seg); \
                end = name##_MEDIUM3(end - (seg << 1), end - seg, end); \
            } \
            medium = name##_MEDIUM3(begin, medium, end); \
            SWAP(*base, *medium); \
        } \
        l_begin = l_end = base + 1; \
        r_begin = r_end = base + num - 1; \
        while (1) { \
            while (l_end <= r_begin && (result = cmp(l_end, base)) <= 0) { \
                if (!result) { \
                    SWAP(*l_begin, *l_end); \
                    l_begin++; \
                    swapped = 1; \
                } \
                l_end++; \
            } \
            while (l_end <= r_begin && (result = cmp(r_begin, base)) >= 0) { \
                if (!result) { \
                    SWAP(*r_begin, *r_end); \
                    r_end--; \
                    swapped = 1; \
                } \
                r_begin--; \
            } \
            if (l_end > r_begin) { \
                break; \
            } \
            SWAP(*l_end, *r_begin); \
            l_end++, r_begin--; \
            swapped = 1; \
        } \
        if (!swapped) { \
            goto fast; \
        } \
        if ((result = MIN(l_begin - base, l_end - l_begin))) { \
            long __i = result; \
            type_t *__pa = base, *__pb = l_end - result; \
            do { \
                SWAP(*__pa, *__pb); \
                __pa++, __pb++; \
            } while (--__i > 0); \
        } \
        end = base + num; \
        if ((result = MIN(r_end - r_begin, end - r_end - 1))) { \
            long __i = result; \
            type_t *__pa = l_end, *__pb = end - result; \
            do { \
                SWAP(*__pa, *__pb); \
                __pa++, __pb++; \
            } while (--__i > 0); \
        } \
        if ((result = l_end - l_begin) > 1) { \
            name##_QSORT(base, result); \
        } \
        if ((result = r_end - r_begin) > 1) { \
            base = end - result; \
            num = result; \
            goto loop; \
        } \
        return; \
    fast: \
        name##_ISORT(base, num); \
        return; \
    }

#define MSORT_PROTOTYPE(scope, name, type_t) \
    scope long name##_MSORT(type_t *base, type_t *buf, size_t num);

#define MSORT_GENERATE(scope, name, type_t, cmp) \
    scope long name##_MSORT(type_t *base, type_t *buf, size_t num) \
    { \
        size_t i, step; \
        type_t *bases[2], *src = base; \
        for (i = 0; i < num; i += 8) { \
            name##_ISORT(src + i, i + 8 < num ? 8 : num - i); \
        } \
        if (num <= 8) { \
            return 0; \
        } \
        bases[0] = base; \
        if (!(bases[1] = buf ? buf : malloc(num * sizeof(*buf)))) { \
            return -ENOMEM; \
        } \
        for (step = 8, i = 0; step < num; step <<= 1, i ^= 1) { \
            size_t j, mlen = step << 1; \
            type_t *dst = bases[i ^ 1]; \
            for (j = 0, src = bases[i]; j < num; j += mlen) { \
                type_t *l_end, *r_end, *p = dst + j; \
                type_t *l = src + j, *r = l + step; \
                if (j + step > num) { \
                    l_end = src; \
                    r_end = src + num; \
                } else { \
                    l_end = r; \
                    r_end = j + mlen > num ? src + num : l + mlen; \
                } \
                while (l < l_end && r < r_end) { \
                    if (cmp(l, r) < 0) { \
                        *p++ = *l++; \
                    } else { \
                        *p++ = *r++; \
                    } \
                } \
                while (l < l_end) { \
                    *p++ = *l++; \
                } \
                while (r < r_end) { \
                    *p++ = *r++; \
                } \
            } \
        } \
        if (i) { \
            memcpy(base, bases[1], num * sizeof(*base)); \
        } \
        if (!buf) { \
            free(bases[1]); \
        } \
        return 0; \
    }

#define BSEARCH(name, key, base, num) name##_BSEARCH(key, base, num)
#define ISORT(name, base, num) name##_ISORT(base, num)
#define QSORT(name, base, num) name##_QSORT(base, num)
#define MSORT(name, base, buf, num) name##_MSORT(base, buf, num)

#else
typedef long (*sort_cmp_t)(const void *, const void *);

long binary_search(const void *key, const void *base, size_t num, size_t size,
        sort_cmp_t cmp);

void insert_sort(void *base, size_t num, size_t size, sort_cmp_t cmp);
void quick_sort(void *base, size_t num, size_t size, sort_cmp_t cmp);
long merge_sort(void *base, void *buf, size_t num, size_t size, sort_cmp_t cmp);

#endif /* SORT_MACRO */

#endif /* __SORT_H__ */

