#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_set.h"

#define INITIAL_CAPACITY 16
#define GROWTH_FACTOR 0.75

hash_set* create_hash_set() {
   // printf("tesing!\n");
    hash_set* set = (hash_set*) malloc(sizeof(hash_set));
    set->nodes = (hash_code**) calloc(INITIAL_CAPACITY, sizeof(hash_code*));
    set->size = 0;
    set-> capacity = INITIAL_CAPACITY;
    return set;
}

uint32_t hash(uint32_t key) {
    uint32_t hash_key = key;
    hash_key ^= hash_key >> 16;
    hash_key *= 0x85ebca6b;
    hash_key ^= hash_key >> 13;
    hash_key *= 0xc2b2ae35;
    hash_key ^= hash_key >> 16;
    return hash_key;
}

void insert(hash_set* set, uint32_t key) {
    uint32_t code = hash(key);
    uint32_t index = code & (set->capacity - 1);

   // printf("index: %u\n", index);
    hash_code* current = set->nodes[index];
    while (current != NULL)
    {
        if (current->key == key)
        {
            ++current->count;
            return;
        }
        current = current->next;
        
    }
    
    hash_code* node = (hash_code*) malloc(sizeof(hash_code));
    node->key = key;
    node->hash_code_raw = code;
    node->count = 1;
    node->next = set->nodes[index];
    set->nodes[index] = node;

    ++set->size;
   // printf("size: %d\n", set->size);

    if (set->size >= set->capacity * GROWTH_FACTOR)
    {
        int new_capacity = set->capacity << 1;
        //printf("new capacity: %d\n", new_capacity);
        hash_code** new_codes =  (hash_code**) calloc(new_capacity, sizeof(hash_code*));
        for (int i = 0; i < set->capacity; i++)
        {
            hash_code* current = set->nodes[i];
            while (current != NULL)
            {
                hash_code* next = current->next;
                
                int new_index = (current->hash_code_raw & set->capacity) | i;
                if (new_codes[new_index] != NULL) {
                    current->next = new_codes[new_index];
                } else {
                    current->next = NULL;
                }
                new_codes[new_index] = current;
                current = next;
            }
        }
        free(set->nodes);
        set->nodes = new_codes;
        set->capacity = new_capacity;
    }
    
}

int contains(hash_set* set, uint32_t key) {
    int index = hash(key) & (set->capacity - 1);
    hash_code* node = set->nodes[index];
    while (node != NULL && node->key != key)
    {
        node = node->next;
    }
    if (node == NULL)
    {
        return 0;
    } else {
        return 1;
    }
}

void free_hash_set(hash_set* set) {
    for (int i = 0; i < set->capacity; i++)
    {
        hash_code* node = set->nodes[i];
        while (node != NULL)
        {
            hash_code* next = node->next;
            free(node);
            node = next;
        }
        
    }
    free(set->nodes);
    free(set);
}

uint32_t** hashset_to_array(hash_set* set){
    uint32_t** array =  (uint32_t**) calloc(2,sizeof(uint32_t*));
    array[0] = (uint32_t*) calloc(set->size, sizeof(uint32_t));
    array[1] = (uint32_t*) calloc(set->size, sizeof(uint32_t));
    int index = 0;
    for (int i = 0; i < set->capacity; i++)
    {
        hash_code* node = set->nodes[i];
        while (node != NULL)
        {
            array[0][index] = node->key;
            array[1][index] = node->count;
            ++index;
            node = node->next;
        }
        
    }
    return array;
    
}

/*
int main() {
    hash_set* set = create_hash_set();
    for (uint32_t i = 0; i < 1000000; i++)
    {
        insert(set, i);
    }
    for (uint32_t i = 0; i < 1000; i=i+2)
    {
        insert(set, i);
    }
    
    uint32_t** array = hashset_to_array(set);
    uint32_t count = 0;
    for (int i = 0; i < set->size; i++)
    {
        printf("key: %u, count: %u\n", array[0][i], array[1][i]);
        count += array[1][i];
    }
    printf("Size: %u, Count: %u\n", set->size, count);
    free_hash_set(set);
}
*/