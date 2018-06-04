#include "mb_memory_pool.h"

char * memory_pool_malloc(struct memory_pool * pool, uint32_t len){
    if(pool->idx + len > pool->length){
        return NULL;
    } else {
        uint32_t tmp = pool->idx;
        pool->idx += len;
        return &(pool->data[pool->idx]);
    }
}

void memory_pool_free(struct memory_pool * pool, uint32_t len){
    pool->idx -= len;
}