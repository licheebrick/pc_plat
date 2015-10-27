/*
 *     Filename: mpool.h
 *  Description: Header file for fixed-size memory pool
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __MPOOL_H__
#define __MPOOL_H__

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#define MPOOL(name, type_t) \
    struct name { \
        size_t step; \
        size_t size; \
        size_t num; \
        ssize_t flist; \
        union { ssize_t next; type_t elm; } *chunk; \
    }

#define MPOOL_INITIALIZER(mp, s) {(s), 0, 0, -1, NULL}

#define MPOOL_SIZE(mp) ((mp)->size)
#define MPOOL_COUNT(mp) ((mp)->num)
#define MPOOL_BASE(mp) ((mp)->chunk)

#define MPOOL_ADDR(mp, i) ((typeof((mp)->chunk->elm) *)((mp)->chunk + (i)))
#define MPOOL_ELEMENT(mp, i) ((mp)->chunk[(i)].elm)

#define MPOOL_INIT(mp, s) \
    do { \
        const typeof(mp) __mp = (mp); \
        __mp->step = (s); \
        __mp->size = __mp->num = 0; \
        __mp->flist = -1; \
        __mp->chunk = NULL; \
    } while (0)

#define MPOOL_TERM(mp) \
    do { \
        free((mp)->chunk); \
    } while (0)

#define MPOOL_CLEAR(mp) \
    do { \
        const typeof(mp) __mp = (mp); \
        __mp->num = 0; \
        __mp->flist = -1; \
    } while (0)

#define MPOOL_RESET(mp) \
    do { \
        const typeof(mp) __mp = (mp); \
        free(__mp->chunk); \
        __mp->size = __mp->num = 0; \
        __mp->flist = -1; \
        __mp->chunk = NULL; \
    } while (0)

#define MPOOL_PROTOTYPE(scope, name) \
    scope int name##_MPOOL_EXTEND(struct name *mp); \
    scope ssize_t name##_MPOOL_MALLOC(struct name *mp); \
    scope ssize_t name##_MPOOL_CALLOC(struct name *mp); \
    scope void name##_MPOOL_FREE(struct name *mp, ssize_t i);

#define MPOOL_GENERATE(scope, name) \
    scope int name##_MPOOL_EXTEND(struct name *mp) \
    { \
        size_t n_size = MPOOL_SIZE(mp) + mp->step; \
        typeof(mp->chunk) n_chunk = realloc(MPOOL_BASE(mp), \
                n_size * sizeof(*n_chunk)); \
        if (!n_chunk) { \
            return -ENOMEM; \
        } \
        MPOOL_SIZE(mp) = n_size; \
        MPOOL_BASE(mp) = n_chunk; \
        return 0; \
    } \
    \
    scope ssize_t name##_MPOOL_MALLOC(struct name *mp) \
    { \
        ssize_t i; \
        if (mp->flist != -1) { \
            i = mp->flist; \
            mp->flist = mp->chunk[i].next; \
            MPOOL_COUNT(mp)++; \
        } else if (MPOOL_COUNT(mp) < MPOOL_SIZE(mp) || \
            !name##_MPOOL_EXTEND(mp)) { \
            i = MPOOL_COUNT(mp)++; \
        } else { \
            i = -1; \
        } \
        return i; \
    } \
    \
    scope ssize_t name##_MPOOL_CALLOC(struct name *mp) \
    { \
        const ssize_t i = name##_MPOOL_MALLOC(mp); \
        if (i != -1) { \
            memset(mp->chunk + i, 0, sizeof(*mp->chunk)); \
        } \
        return i; \
    } \
    \
    scope void name##_MPOOL_FREE(struct name *mp, ssize_t i) \
    { \
        mp->chunk[i].next = mp->flist; \
        mp->flist = i; \
        MPOOL_COUNT(mp)--; \
    }

#define MPOOL_EXTEND(name, mp) name##_MPOOL_EXTEND(mp)
#define MPOOL_MALLOC(name, mp) name##_MPOOL_MALLOC(mp)
#define MPOOL_CALLOC(name, mp) name##_MPOOL_CALLOC(mp)
#define MPOOL_FREE(name, mp, i) name##_MPOOL_FREE(mp, i)


#define CMPOOL(name, type_t) \
    struct name { \
        size_t chunk_size; \
        size_t chunk_num; \
        size_t last_unused; \
        size_t flist_num; \
        union { void *next; type_t elm; } *flist, *last_chunk, **chunks; \
    }

#define CMPOOL_INITIALIZER(mp, s) {(s), 0, 0, 0, NULL, NULL, NULL}

#define CMPOOL_SIZE(mp) ({ \
        const typeof(mp) __mp = (mp); \
        __mp->chunk_num * __mp->chunk_size;})
#define CMPOOL_COUNT(mp) ({ \
        const typeof(mp) __mp = (mp); \
        __mp->chunk_num * __mp->chunk_size - \
        __mp->last_unused - __mp->flist_num;})
#define CMPOOL_BASE(mp) ((mp)->chunks)

#define CMPOOL_INIT(mp, s) \
    do { \
        const typeof(mp) __mp = (mp); \
        __mp->chunk_size = (s); \
        __mp->chunk_num = __mp->last_unused = __mp->flist_num = 0; \
        __mp->flist = __mp->last_chunk = NULL; \
        __mp->chunks = NULL; \
    } while (0)

#define CMPOOL_TERM(mp) \
    do { \
        const typeof(mp) __mp = (mp); \
        typeof(__mp->chunks) cur = __mp->chunks + __mp->chunk_num; \
        while (cur > __mp->chunks) { \
            free(*--cur); \
        } \
        free(__mp->chunks); \
    } while (0)

#define CMPOOL_RESET(mp) \
    do { \
        const typeof(mp) __mp = (mp); \
        typeof(__mp->chunks) cur = __mp->chunks + __mp->chunk_num; \
        while (cur > __mp->chunks) { \
            free(*--cur); \
        } \
        free(__mp->chunks); \
        __mp->chunk_num = __mp->last_unused = __mp->flist_num = 0; \
        __mp->flist = __mp->last_chunk = NULL; \
        __mp->chunks = NULL; \
    } while (0)

#define CMPOOL_PROTOTYPE(scope, name) \
    scope int name##_CMPOOL_EXTEND(struct name *mp); \
    scope void *name##_CMPOOL_MALLOC(struct name *mp); \
    scope void *name##_CMPOOL_CALLOC(struct name *mp); \
    scope void name##_CMPOOL_FREE(struct name *mp, void *p);

#define CMPOOL_GENERATE(scope, name) \
    scope int name##_CMPOOL_EXTEND(struct name *mp) \
    { \
        size_t n_chunk_num; \
        typeof(mp->chunks) n_chunks; \
        typeof(mp->last_chunk) n_last_chunk; \
        n_last_chunk = malloc(mp->chunk_size * sizeof(*n_last_chunk)); \
        if (!n_last_chunk) { \
            return -ENOMEM; \
        } \
        n_chunk_num = mp->chunk_num + 1; \
        n_chunks = realloc(CMPOOL_BASE(mp), n_chunk_num * sizeof(*n_chunks)); \
        if (!n_chunks) { \
            free(n_last_chunk); \
            return -ENOMEM; \
        } \
        CMPOOL_BASE(mp) = n_chunks; \
        CMPOOL_BASE(mp)[mp->chunk_num] = mp->last_chunk = n_last_chunk; \
        mp->chunk_num = n_chunk_num; \
        mp->last_unused = mp->chunk_size; \
        return 0; \
    } \
    \
    scope void *name##_CMPOOL_MALLOC(struct name *mp) \
    { \
        typeof(mp->flist) p; \
        if (mp->flist_num) { \
            p = mp->flist; \
            mp->flist = mp->flist->next; \
            mp->flist_num--; \
        } else if (mp->last_unused || !name##_CMPOOL_EXTEND(mp)) { \
            p = mp->last_chunk + mp->chunk_size - mp->last_unused; \
            mp->last_unused--; \
        } else { \
            p = NULL; \
        } \
        return p; \
    } \
    \
    scope void *name##_CMPOOL_CALLOC(struct name *mp) \
    { \
        const typeof(mp->flist) p = name##_CMPOOL_MALLOC(mp); \
        if (p) { \
            memset(p, 0, sizeof(*p)); \
        } \
        return p; \
    } \
    \
    scope void name##_CMPOOL_FREE(struct name *mp, void *p) \
    { \
        const typeof(mp->flist) __p = p; \
        __p->next = mp->flist; \
        mp->flist = __p; \
        mp->flist_num++; \
    }

#define CMPOOL_EXTEND(name, mp) name##_CMPOOL_EXTEND(mp)
#define CMPOOL_MALLOC(name, mp) name##_CMPOOL_MALLOC(mp)
#define CMPOOL_CALLOC(name, mp) name##_CMPOOL_CALLOC(mp)
#define CMPOOL_FREE(name, mp, p) name##_CMPOOL_FREE(mp, p)


struct gmpool {
    size_t slot_size;
    size_t step;
    size_t size;
    size_t num;
    ssize_t flist;
    void *chunk;
};

static inline size_t gmpool_size(struct gmpool *mp)
{
    return mp->size;
}

static inline size_t gmpool_count(struct gmpool *mp)
{
    return mp->num;
}

static inline void *gmpool_addr(struct gmpool *mp, size_t i)
{
    return (void *)((size_t)mp->chunk + i * mp->slot_size);
}

void gmpool_init(struct gmpool *mp, size_t step, size_t slot_size);
void gmpool_term(struct gmpool *mp);
void gmpool_clear(struct gmpool *mp);
void gmpool_reset(struct gmpool *mp);

int gmpool_extend(struct gmpool *mp);
ssize_t gmpool_malloc(struct gmpool *mp);
ssize_t gmpool_calloc(struct gmpool *mp);
void gmpool_free(struct gmpool *mp, ssize_t i);


struct gcmpool {
    size_t slot_size;
    size_t chunk_size;
    size_t chunk_num;
    size_t last_unused;
    size_t flist_num;
    void *flist, *last_chunk, **chunks;
};

static inline size_t gcmpool_size(struct gcmpool *mp)
{
    return mp->chunk_num * mp->chunk_size;
}

static inline size_t gcmpool_count(struct gcmpool *mp)
{
    return mp->chunk_num * mp->chunk_size - mp->last_unused - mp->flist_num;
}

void gcmpool_init(struct gcmpool *mp, size_t step, size_t slot_size);
void gcmpool_term(struct gcmpool *mp);
void gcmpool_reset(struct gcmpool *mp);

int gcmpool_extend(struct gcmpool *mp);
void *gcmpool_malloc(struct gcmpool *mp);
void *gcmpool_calloc(struct gcmpool *mp);
void gcmpool_free(struct gcmpool *mp, void *p);

#endif /* __MPOOL_H__ */

