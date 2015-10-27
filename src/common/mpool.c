/*
 *     Filename: mpool.c
 *  Description: Source file for fixed-size memory pool
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include "common/utils.h"
#include "common/mpool.h"

void gmpool_init(struct gmpool *mp, size_t step, size_t slot_size)
{
    mp->slot_size = slot_size < sizeof(size_t) ? sizeof(size_t) :
        ALIGN(slot_size, sizeof(size_t));
    mp->step = step;
    mp->size = mp->num = 0;
    mp->flist = -1;
    mp->chunk = NULL;
}

void gmpool_term(struct gmpool *mp)
{
    free(mp->chunk);
}

void gmpool_clear(struct gmpool *mp)
{
    mp->num = 0;
    mp->flist = -1;
}

void gmpool_reset(struct gmpool *mp)
{
    free(mp->chunk);
    mp->size = mp->num = 0;
    mp->flist = -1;
    mp->chunk = NULL;
}

int gmpool_extend(struct gmpool *mp)
{
    size_t n_size = mp->size + mp->step;
    void *n_chunk = realloc(mp->chunk, n_size * mp->slot_size);

    if (!n_chunk) {
        return -ENOMEM;
    }

    mp->size = n_size;
    mp->chunk = n_chunk;

    return 0;
}

ssize_t gmpool_malloc(struct gmpool *mp)
{
    ssize_t i;

    if (mp->flist != -1) {
        i = mp->flist;
        mp->flist = *(ssize_t *)gmpool_addr(mp, i);
        mp->num++;

    } else if (mp->num < mp->size || !gmpool_extend(mp)) {
        i = mp->num++;

    } else {
        i = -1;
    }

    return i;
}

ssize_t gmpool_calloc(struct gmpool *mp)
{
    const ssize_t i = gmpool_malloc(mp);

    if (i != -1) {
        memset(gmpool_addr(mp, i), 0, mp->slot_size);
    }

    return i;
}

void gmpool_free(struct gmpool *mp, ssize_t i)
{
    *(ssize_t *)gmpool_addr(mp, i) = mp->flist;
    mp->flist = i;
    mp->num--;
}

void gcmpool_init(struct gcmpool *mp, size_t step, size_t slot_size)
{
    mp->slot_size = slot_size < sizeof(size_t) ? sizeof(size_t) :
        ALIGN(slot_size, sizeof(size_t));
    mp->chunk_size = step;
    mp->chunk_num = mp->last_unused = mp->flist_num = 0;
    mp->flist = mp->last_chunk = NULL;
    mp->chunks = NULL;
}

void gcmpool_term(struct gcmpool *mp)
{
    void **cur = mp->chunks + mp->chunk_num;

    while (cur > mp->chunks) {
        free(*--cur);
    }

    free(mp->chunks);
}

void gcmpool_reset(struct gcmpool *mp)
{
    void **cur = mp->chunks + mp->chunk_num;

    while (cur > mp->chunks) {
        free(*--cur);
    }

    free(mp->chunks);

    mp->chunk_num = mp->last_unused = mp->flist_num = 0;
    mp->flist = mp->last_chunk = NULL;
    mp->chunks = NULL;
}

int gcmpool_extend(struct gcmpool *mp)
{
    size_t n_chunk_num;
    void **n_chunks;
    void *n_last_chunk = malloc(mp->chunk_size * mp->slot_size);

    if (!n_last_chunk) {
        return -ENOMEM;
    }

    n_chunk_num = mp->chunk_num + 1;
    n_chunks = realloc(mp->chunks, n_chunk_num * sizeof(*n_chunks));
    if (!n_chunks) {
        free(n_last_chunk);
        return -ENOMEM;
    }

    mp->chunks = n_chunks;
    mp->chunks[mp->chunk_num] = mp->last_chunk = n_last_chunk;
    mp->chunk_num = n_chunk_num;
    mp->last_unused = mp->chunk_size;

    return 0;
}

void *gcmpool_malloc(struct gcmpool *mp)
{
    void *p;

    if (mp->flist_num) {
        p = mp->flist;
        mp->flist = *(void **)mp->flist;
        mp->flist_num--;

    } else if (mp->last_unused || !gcmpool_extend(mp)) {
        p = (void *)((size_t)mp->last_chunk +
                (mp->chunk_size - mp->last_unused) * mp->slot_size);
        mp->last_unused--;

    } else {
        p = NULL;
    }

    return p;
}

void *gcmpool_calloc(struct gcmpool *mp)
{
    void *p = gcmpool_malloc(mp);

    if (p) {
        memset(p, 0, mp->slot_size);
    }

    return p;
}

void gcmpool_free(struct gcmpool *mp, void *p)
{
    *(void **)p = mp->flist;
    mp->flist = p;
    mp->flist_num++;
}

