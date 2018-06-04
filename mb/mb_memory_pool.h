#ifndef __mb_memory_pool__h
#define __mb_memory_pool__h

#include <stdint.h>

struct memory_pool{
    char * data;
    uint32_t idx;
    uint32_t length; // max length of this memory pool
};

char * memory_pool_malloc(struct memory_pool * pool, uint32_t len);

void memory_pool_free(struct mem_pool * pool, uint32_t len);
#endif
