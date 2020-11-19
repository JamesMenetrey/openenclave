// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/result.h>

#include <openenclave/internal/elf.h> // elf64_sym_t, elf64_phdr_t

/* NOTE: MUSL uses these restrictions in their implementation, which we
 * can keep for simplicity, but doesn't seem to be documented as a
 * de facto part of ELF loading anywhere */
// #define AUX_CNT 32
#define DYN_CNT 32

/* Defined in accordance with openenclave/include/corelibc/bits/types.h */
// typedef uint64_t oe_ino_t;
// typedef uint64_t oe_dev_t;

/* Defined in accordance with openenclave/include/corelibc/limits.h */
#define NAME_MAX 255

/* The entries in the .hash table always have a size of 32 bits. */
/* TODO: Move all new definitions to internal/elf.h */
typedef uint32_t elf_symndx_t;

#define DT_GNU_HASH 0x6ffffef5
#define DT_VERSYM 0x6ffffff0

#define STB_GNU_UNIQUE 10

#define STT_COMMON 5
#define STT_TLS 6

#define OK_TYPES \
    (1 << STT_NOTYPE | 1 << STT_OBJECT | 1 << STT_FUNC | 1 << STT_COMMON)
#define OK_BINDS (1 << STB_GLOBAL | 1 << STB_WEAK | 1 << STB_GNU_UNIQUE)

typedef struct _tls_module
{
    struct _tls_module* next;
    void* image;
    size_t len, size, align, offset;
} tls_module_t;

typedef struct _libc
{
    int can_do_threads;
    int threaded;
    int secure;
    volatile int threads_minus_1;
    size_t* auxv;
    tls_module_t* tls_head;
    size_t tls_size, tls_align, tls_cnt;
    size_t page_size;
    // struct __locale_struct global_locale;
} libc_t;

#ifndef PAGE_SIZE
#define PAGE_SIZE libc.page_size
#endif

// extern hidden libc_t __libc;
extern libc_t __libc;
#define libc __libc

typedef struct _td_index
{
    size_t args[2];
    struct _td_index* next;
} td_index_t;

typedef struct _dso
{
    char* name;
    unsigned char* base;
    size_t* dynv;
    struct _dso *next, *prev;

    elf64_phdr_t* phdr;
    int phnum;
    size_t phentsize;
    elf64_sym_t* syms;
    elf_symndx_t* hashtab;
    uint32_t* ghashtab;
    int16_t* versym;
    char* strings;
    struct _dso* syms_next;
    // struct _dso *lazy_next;
    // size_t *lazy, lazy_cnt;
    unsigned char* map; // TODO: Unused until map_library (~= image.segments)
    size_t map_len;     // TODO: Unused until map_library (~= image.segments)
    // oe_dev_t dev;
    // oe_ino_t ino;
    char relocated;
    char constructed;
    // char kernel_mapped;
    // struct _dso **deps;
    struct _dso* needed_by;
    char* rpath_orig; // Set by decode_dyn, but no use for it in OE yet
    // char *rpath;
    tls_module_t tls; // TODO: Unused until TLS fixup
    size_t tls_id;    // TODO: Unused until TLS fixup
    // size_t relro_start, relro_end;
    uintptr_t* new_dtv;     // TODO: Unused until TLS fixup
    unsigned char* new_tls; // TODO: Unused until TLS fixup
    // volatile int new_dtv_idx, new_tls_idx;
    // struct td_index* td_index;
    // struct _dso* fini_next;
    char* shortname;
    // struct fdpic_loadmap *loadmap;
    // struct funcdesc {
    // 	void *addr;
    // 	size_t *got;
    // } *funcdescs;
    size_t* got;
    char buf[]; // Null-terminated buffer that name/shortname points to
} dso_t;

typedef struct _symdef
{
    elf64_sym_t* sym;
    dso_t* dso;
} symdef_t;

typedef struct _oe_dso_load_state
{
    dso_t* head;
    dso_t* tail;
} oe_dso_load_state_t;

oe_result_t oe_load_enclave_dso(
    const char* name,
    oe_dso_load_state_t* load_state,
    dso_t* needed_by,
    dso_t** dso);

void oe_unload_enclave_dso(oe_dso_load_state_t* load_state);

oe_result_t oe_load_deps(oe_dso_load_state_t* load_state, dso_t* p);
