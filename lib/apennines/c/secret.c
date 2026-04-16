#include "apennines/secret.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    #include <sys/mman.h>
#endif

/* ---- Platform-specific secure zero ---- */

static void secure_zero(void *ptr, u64 size) {
#ifdef _WIN32
    SecureZeroMemory(ptr, (SIZE_T)size);
#elif defined(__STDC_LIB_EXT1__) || defined(__STDC_WANT_LIB_EXT1__)
    memset_s(ptr, (size_t)size, 0, (size_t)size);
#else
    /*
     * Use a volatile function pointer to memset so the compiler cannot
     * optimise the call away. This is the standard portable idiom for
     * guaranteed zeroing when explicit_bzero is unavailable.
     */
    typedef void *(*memset_fn)(void *, int, size_t);
    static volatile memset_fn vol_memset = memset;
    vol_memset(ptr, 0, (size_t)size);
#endif
}

/* ---- Platform-specific lock/unlock ---- */

static int lock_memory(void *ptr, u64 size) {
#ifdef _WIN32
    return VirtualLock(ptr, (SIZE_T)size) ? 0 : -1;
#else
    return mlock(ptr, (size_t)size);
#endif
}

static int unlock_memory(void *ptr, u64 size) {
#ifdef _WIN32
    return VirtualUnlock(ptr, (SIZE_T)size) ? 0 : -1;
#else
    return munlock(ptr, (size_t)size);
#endif
}

/* ---- secret_alloc ---- */

unsigned long secret_alloc(void **out, u64 size) {
    void *ptr;

    if (!out) return 1;
    if (size == 0) return 2;

    ptr = malloc((size_t)size);
    if (!ptr) return 3;

    if (lock_memory(ptr, size) != 0) {
        free(ptr);
        return 4;
    }

    *out = ptr;
    return 0;
}

/* ---- secret_free ---- */

unsigned long secret_free(void *ptr, u64 size) {
    if (!ptr) return 1;
    if (size == 0) return 2;

    secure_zero(ptr, size);
    unlock_memory(ptr, size);
    free(ptr);
    return 0;
}

/* ---- secret_scope_create ---- */

unsigned long secret_scope_create(secret_scope *out) {
    if (!out) return 1;

    out->head = NULL;
    out->total_size = 0;
    return 0;
}

/* ---- secret_scope_alloc ---- */

unsigned long secret_scope_alloc(void **out, secret_scope *scope, u64 size) {
    void *ptr;
    secret_block *block;

    if (!out) return 1;
    if (!scope) return 2;
    if (size == 0) return 3;

    ptr = malloc((size_t)size);
    if (!ptr) return 4;

    if (lock_memory(ptr, size) != 0) {
        free(ptr);
        return 5;
    }

    block = (secret_block *)malloc(sizeof(secret_block));
    if (!block) {
        secure_zero(ptr, size);
        unlock_memory(ptr, size);
        free(ptr);
        return 6;
    }

    block->ptr = ptr;
    block->size = size;
    block->next = scope->head;
    scope->head = block;
    scope->total_size += size;

    *out = ptr;
    return 0;
}

/* ---- secret_scope_destroy ---- */

unsigned long secret_scope_destroy(secret_scope *scope) {
    secret_block *cur;
    secret_block *next;

    if (!scope) return 1;

    cur = scope->head;
    while (cur) {
        next = cur->next;
        secure_zero(cur->ptr, cur->size);
        unlock_memory(cur->ptr, cur->size);
        free(cur->ptr);
        free(cur);
        cur = next;
    }

    scope->head = NULL;
    scope->total_size = 0;
    return 0;
}
