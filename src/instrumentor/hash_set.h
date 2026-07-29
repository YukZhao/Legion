#ifndef HASH_SET_H
#define HASH_SET_H

#include <stdint.h>

typedef struct hash_code_t
{
    uint32_t key;
    uint32_t count;
    uint32_t hash_code_raw;
    struct hash_code_t* next;
}hash_code;

typedef struct
{
    hash_code** nodes;
    uint32_t size;
    uint32_t capacity;
} hash_set;

hash_set* create_hash_set();
uint32_t hash(uint32_t key);
void insert(hash_set* set, uint32_t key);
int contains(hash_set* set, uint32_t key);
void free_hash_set(hash_set* set);
uint32_t** hashset_to_array(hash_set* set);

#endif