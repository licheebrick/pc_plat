/*
 *     Filename: buffer.h
 *  Description: Header file for vector buffer and ring buffer
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __BUFFER_H__
#define __BUFFER_H__

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "common/utils.h"

#define VECTOR(name, type_t) \
    struct name { \
        size_t size; \
        size_t len; \
        type_t *buf; \
    }

#define VECTOR_INITIALIZER(v) {0, 0, NULL}

#define VECTOR_SIZE(v) ((v)->size)
#define VECTOR_LEN(v) ((v)->len)
#define VECTOR_BASE(v) ((v)->buf)

#define VECTOR_EMPTY(v) (!(v)->len)
#define VECTOR_FULL(v) ({ \
        const typeof(v) __v = (v); \
        __v->len == __v->size;})
#define VECTOR_EQUAL(left, right) ({ \
        const typeof(left) __left = (left); \
        const typeof(right) __right = (right); \
        __left->len == __right->len && \
        !memcmp(__left->buf, __right->buf, __left->len);})

#define VECTOR_FIRST(v) 0
#define VECTOR_LAST(v) ((v)->len - 1)
#define VECTOR_ADDR(v, i) ((v)->buf + (i))
#define VECTOR_ELEMENT(v, i) ((v)->buf[(i)])

#define VECTOR_INIT(v) \
    do { \
        const typeof(v) __v = (v); \
        __v->size = __v->len = 0; \
        __v->buf = NULL; \
    } while (0)

#define VECTOR_TERM(v) \
    do { \
        free((v)->buf); \
    } while (0)

#define VECTOR_CLEAR(v) \
    do { \
        (v)->len = 0; \
    } while (0)

#define VECTOR_RESET(v) \
    do { \
        const typeof(v) __v = (v); \
        free(__v->buf); \
        __v->size = __v->len = 0; \
        __v->buf = NULL; \
    } while (0)

#define VECTOR_PROTOTYPE(scope, name, type_t) \
    scope int name##_VECTOR_EXTEND(struct name *v, size_t size); \
    scope int name##_VECTOR_PUSH(struct name *v, type_t elm); \
    scope int name##_VECTOR_PUSHN(struct name *v, type_t *elm, size_t n); \
    scope int name##_VECTOR_POP(struct name *v, type_t *elm); \
    scope int name##_VECTOR_COPY(struct name *dst, struct name *src);

#define VECTOR_GENERATE(scope, name, type_t) \
    scope int name##_VECTOR_EXTEND(struct name *v, size_t size) \
    { \
        size = (typeof(size))p2roundup(size); \
        if (VECTOR_SIZE(v) < size) { \
            type_t *n_buf = realloc(VECTOR_BASE(v), size * sizeof(*n_buf)); \
            if (!n_buf) { \
                return -ENOMEM; \
            } \
            VECTOR_SIZE(v) = size; \
            VECTOR_BASE(v) = n_buf; \
        } \
        return 0; \
    } \
    \
    scope int name##_VECTOR_PUSH(struct name *v, type_t elm) \
    { \
        if (VECTOR_FULL(v) && name##_VECTOR_EXTEND(v, VECTOR_LEN(v) + 1)) { \
            return -ENOMEM; \
        } \
        VECTOR_ELEMENT(v, VECTOR_LEN(v)) = elm; \
        VECTOR_LEN(v)++; \
        return 0; \
    } \
    \
    scope int name##_VECTOR_PUSHN(struct name *v, type_t *elm, size_t n) \
    { \
        if (VECTOR_SIZE(v) - VECTOR_LEN(v) < n && \
            name##_VECTOR_EXTEND(v, VECTOR_LEN(v) + n)) { \
            return -ENOMEM; \
        } \
        memcpy(VECTOR_ADDR(v, VECTOR_LEN(v)), elm, n * sizeof(*elm)); \
        VECTOR_LEN(v) += n; \
        return n; \
    } \
    \
    scope int name##_VECTOR_POP(struct name *v, type_t *elm) \
    { \
        if (VECTOR_EMPTY(v)) { \
            return -EOVERFLOW; \
        } \
        VECTOR_LEN(v)--; \
        if (elm) { \
            *elm = VECTOR_ELEMENT(v, VECTOR_LEN(v)); \
        } \
        return 0; \
    } \
    \
    scope int name##_VECTOR_INSERT(struct name *v, type_t *elm, size_t i, \
            size_t n) \
    { \
        if (i > VECTOR_LEN(v)) { \
            return -EINVAL; \
        } \
        if (VECTOR_SIZE(v) - VECTOR_LEN(v) < n && \
            name##_VECTOR_EXTEND(v, VECTOR_LEN(v) + n)) { \
            return -ENOMEM; \
        } \
        memmove(VECTOR_ADDR(v, i + n), VECTOR_ADDR(v, i), \
                (VECTOR_LEN(v) - i) * sizeof(*elm)); \
        memcpy(VECTOR_ADDR(v, i), elm, n * sizeof(*elm)); \
        VECTOR_LEN(v) += n; \
        return n; \
    } \
    \
    scope int name##_VECTOR_REMOVE(struct name *v, type_t *elm, size_t i, \
            size_t n) \
    { \
        if (i >= VECTOR_LEN(v)) { \
            return VECTOR_EMPTY(v) ? -EOVERFLOW : -EINVAL; \
        } \
        if (n > VECTOR_LEN(v) - i) { \
            n = VECTOR_LEN(v) - i; \
        } \
        if (elm) { \
            memcpy(elm, VECTOR_ADDR(v, i), n * sizeof(*elm)); \
        } \
        memmove(VECTOR_ADDR(v, i), VECTOR_ADDR(v, i + n), \
                (VECTOR_LEN(v) - i - n) * sizeof(*elm)); \
        VECTOR_LEN(v) -= n; \
        return n; \
    } \
    \
    scope int name##_VECTOR_COPY(struct name *dst, struct name *src) \
    { \
        if (VECTOR_SIZE(dst) < VECTOR_LEN(src) && \
            name##_VECTOR_EXTEND(dst, VECTOR_LEN(src))) { \
            return -ENOMEM; \
        } \
        memcpy(VECTOR_BASE(dst), VECTOR_BASE(src), \
                VECTOR_LEN(src) * sizeof(*VECTOR_BASE(dst))); \
        VECTOR_LEN(dst) = VECTOR_LEN(src); \
        return 0; \
    }

#define VECTOR_EXTEND(name, v, size) name##_VECTOR_EXTEND(v, size)
#define VECTOR_PUSH(name, v, elm) name##_VECTOR_PUSH(v, elm)
#define VECTOR_PUSHN(name, v, elm, n) name##_VECTOR_PUSHN(v, elm, n)
#define VECTOR_POP(name, v, elm) name##_VECTOR_POP(v, elm)
#define VECTOR_INSERT(name, v, elm, i, n) name##_VECTOR_INSERT(v, elm, i, n)
#define VECTOR_REMOVE(name, v, elm, i, n) name##_VECTOR_REMOVE(v, elm, i, n)
#define VECTOR_COPY(name, dst, src) name##_VECTOR_COPY(dst, src)


#define RING(name, type_t) \
    struct name { \
        size_t size; \
        size_t head; \
        size_t tail; \
        type_t *buf; \
    }

#define RING_SIZE(r) ((r)->size)
#define RING_BASE(r) ((r)->buf)

#define RING_EMPTY(r) ({ \
        const typeof(r) __r = (r); \
        __r->head == __r->tail;})
#define RING_FULL(r) ({ \
        const typeof(r) __r = (r); \
        __r->head - __r->size == __r->tail;})

#define RING_USED(r) ({ \
        const typeof(r) __r = (r); \
        __r->head - __r->tail;})
#define RING_AVAIL(r) ({ \
        const typeof(r) __r = (r); \
        __r->size - __r->head + __r->tail;})

#define RING_HEAD(r) ({ \
        const typeof(r) __r = (r); \
        __r->head & (__r->size - 1);})
#define RING_TAIL(r) ({ \
        const typeof(r) __r = (r); \
        __r->tail & (__r->size - 1);})
#define RING_ADDR(r, i) ((r)->buf + (i))
#define RING_ELEMENT(r, i) ((r)->buf[(i)])

#define RING_INIT(r, s, b) \
    do { \
        const typeof(r) __r = (r); \
        __r->size = (s); \
        __r->head = __r->tail = 0; \
        __r->buf = (b); \
    } while (0)

#define RING_CLEAR(r) \
    do { \
        const typeof(r) __r = (r); \
        __r->head = __r->tail = 0; \
    } while (0)

#define RING_PROTOTYPE(scope, name, type_t) \
    scope int name##_RING_PUT(struct name *r, type_t elm); \
    scope int name##_RING_PUTN(struct name *r, type_t *elm, size_t n); \
    scope int name##_RING_GET(struct name *r, type_t *elm); \
    scope int name##_RING_GETN(struct name *r, type_t *elm, size_t n); \
    scope int name##_RING_READ(struct name *r, int fd); \
    scope int name##_RING_WRITE(struct name *r, int fd);

#define RING_GENERATE(scope, name, type_t) \
    scope int name##_RING_PUT(struct name *r, type_t elm) \
    { \
        if (RING_FULL(r)) { \
            return -EOVERFLOW; \
        } \
        RING_ELEMENT(r, RING_HEAD(r)) = elm; \
        r->head++; \
        return 0; \
    } \
    \
    scope int name##_RING_PUTN(struct name *r, type_t *elm, size_t n) \
    { \
        size_t cnt = RING_AVAIL(r); \
        if (n > cnt) { \
            n = cnt; \
        } \
        /* memory barrier */ \
        cnt = RING_SIZE(r) - RING_HEAD(r); \
        if (cnt > n) { \
            cnt = n; \
        } \
        memcpy(RING_ADDR(r, RING_HEAD(r)), elm, cnt * sizeof(*elm)); \
        memcpy(RING_BASE(r), elm + cnt, (n - cnt) * sizeof(*elm)); \
        /* write memory barrier */ \
        r->head += n; \
        return n; \
    } \
    \
    scope int name##_RING_GET(struct name *r, type_t *elm) \
    { \
        if (RING_EMPTY(r)) { \
            return -EOVERFLOW; \
        } \
        *elm = RING_ELEMENT(r, RING_TAIL(r)); \
        r->tail++; \
        return 0; \
    } \
    \
    scope int name##_RING_GETN(struct name *r, type_t *elm, size_t n) \
    { \
        size_t cnt = RING_USED(r); \
        if (n > cnt) { \
            n = cnt; \
        } \
        /* read memory barrier */ \
        cnt = RING_SIZE(r) - RING_TAIL(r); \
        if (cnt > n) { \
            cnt = n; \
        } \
        memcpy(elm, RING_ADDR(r, RING_TAIL(r)), cnt * sizeof(*elm)); \
        memcpy(elm + cnt, RING_BASE(r), (n - cnt) * sizeof(*elm)); \
        /* memory barrier */ \
        r->tail += n; \
        return n; \
    } \
    \
    scope int name##_RING_READ(struct name *r, int fd) \
    { \
        while (!RING_FULL(r)) { \
            size_t avail = RING_AVAIL(r); \
            size_t frag = RING_SIZE(r) - RING_HEAD(r); \
            ssize_t n = read(fd, RING_ADDR(r, RING_HEAD(r)), \
                    avail < frag ? avail : frag); \
            if (n <= 0) { \
                return !n ? EOF : -errno; \
            } \
            r->head += n; \
        } \
        return 0; \
    } \
    \
    scope int name##_RING_WRITE(struct name *r, int fd) \
    { \
        while (!RING_EMPTY(r)) { \
            size_t used = RING_USED(r); \
            size_t frag = RING_SIZE(r) - RING_TAIL(r); \
            ssize_t n = write(fd, RING_ADDR(r, RING_TAIL(r)), \
                    used < frag ? used : frag); \
            if (n <= 0) { \
                return -errno; \
            } \
            r->tail += n; \
        } \
        return 0; \
    }

#define RING_PUT(name, r, elm) name##_RING_PUT(r, elm)
#define RING_PUTN(name, r, elm, n) name##_RING_PUTN(r, elm, n)
#define RING_GET(name, r, elm) name##_RING_GET(r, elm)
#define RING_GETN(name, r, elm, n) name##_RING_GETN(r, elm, n)

/* type_t must be uint8_t for these functions */
#define RING_READ(name, r, fd) name##_RING_READ(r, fd)
#define RING_WRITE(name, r, fd) name##_RING_WRITE(r, fd)

#endif /* __BUFFER_H__ */

