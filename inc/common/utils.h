#ifndef __UTILS_H__
#define __UTILS_H__

#include <stddef.h>
#include <stdint.h>

#define MIN(a, b) ({ \
        const typeof(a) __a = (a); \
        const typeof(b) __b = (b); \
        __a < __b ? __a : __b;})

#define MAX(a, b) ({ \
        const typeof(a) __a = (a); \
        const typeof(b) __b = (b); \
        __a > __b ? __a : __b;})

#define SWAP(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

#define ALIGN(size, align) ({ \
        const typeof(align) __align = (align); \
        ((size) + (__align - 1)) & ~(__align - 1);})

#define ROUNDUP(x, y) ({ \
        const typeof(y) __y = (y); \
        (((x) + (__y - 1)) / __y) * __y;})

#define ROUNDDOWN(x, y) ({ \
        const typeof(x) __x = (x); \
        __x - (__x % (y));})

#define POWEROF2(x) ({ \
        const typeof(x) __x = (x); \
        ((__x - 1) & __x) == 0;})

static inline uint64_t p2roundup(uint64_t n)
{
    if (!POWEROF2(n)) {
        n--;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        n |= n >> 32;
        n++;
    }
    return n;
}

static inline unsigned int popcount(uint32_t x)
{
#define INIT1(X) \
    ((((X) & (1 << 0)) != 0) + (((X) & (1 << 1)) != 0) + \
     (((X) & (1 << 2)) != 0) + (((X) & (1 << 3)) != 0) + \
     (((X) & (1 << 4)) != 0) + (((X) & (1 << 5)) != 0) + \
     (((X) & (1 << 6)) != 0) + (((X) & (1 << 7)) != 0))
#define INIT2(X)   INIT1(X),  INIT1((X) +  1)
#define INIT4(X)   INIT2(X),  INIT2((X) +  2)
#define INIT8(X)   INIT4(X),  INIT4((X) +  4)
#define INIT16(X)  INIT8(X),  INIT8((X) +  8)
#define INIT32(X) INIT16(X), INIT16((X) + 16)
#define INIT64(X) INIT32(X), INIT32((X) + 32)

    static const uint8_t popcount8[256] = {
        INIT64(0), INIT64(64), INIT64(128), INIT64(192)
    };

    return (popcount8[x & 0xff] + popcount8[(x >> 8) & 0xff] +
            popcount8[(x >> 16) & 0xff] + popcount8[x >> 24]);
}

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define CONTAINER_OF(ptr, type, member) ({ \
        const typeof(((type *)0)->member) *__mptr = (ptr); \
        (type *)((char *)__mptr - offsetof(type, member));})

#define SIZE_OF_SHIFT(n) (1ULL << (n))
#define MASK_OF_SHIFT(n) (SIZE_OF_SHIFT(n) - 1)

char **argv_split(const char *str, int *argcp);
void argv_free(char **argv);

#endif /* __UTILS_H__ */

