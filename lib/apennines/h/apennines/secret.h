#ifndef APENNINES_T2_CRYPTO_SECRET_H
#define APENNINES_T2_CRYPTO_SECRET_H


#include "apennines/types.h"

typedef struct secret_block {
    void *ptr;
    u64 size;
    struct secret_block *next;
} secret_block;

typedef struct {
    secret_block *head;
    u64 total_size;
} secret_scope;

unsigned long secret_alloc(void **out, u64 size);
unsigned long secret_free(void *ptr, u64 size);
unsigned long secret_scope_create(secret_scope *out);
unsigned long secret_scope_alloc(void **out, secret_scope *scope, u64 size);
unsigned long secret_scope_destroy(secret_scope *scope);

#endif /* APENNINES_T2_CRYPTO_SECRET_H */
