// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dynlink.h"
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <openenclave/internal/bits/fcntl.h>
#include <openenclave/internal/raise.h>
#include <stddef.h> //offsetof
#include <string.h>
#include <unistd.h> // for close()

#include <sys/stat.h>

/* TODO: Not Windows compatible, need to fix:
 * - path handling using strrchr
 * - use of pread, open, close
 * - use of linux specific protection flags (e.g. PROT_READ etc.)
 */
#if defined(_MSC_VER)
#include <Windows.h>
struct __stat64 statbuf;
#define _fstat64 fstat
#define S_ISREG(ST_MODE) (ST_MODE & _S_IFREG)
#else
#include <sys/mman.h>
#include <unistd.h>
struct stat statbuf;
#endif

#define MUSL_PATHNAME_MAX_LENGTH (2 * NAME_MAX + 2)

/* Return value of `mmap' in case of an error.  */
// #define MAP_FAILED ((void*)-1)

#define MAXP2(a, b) (-(-(a) & -(b)))
// #define ALIGN(x,y) ((x)+(y)-1 & -(y))

/* TODO: 3rdparty/musl/musl/arch/x86_64/bits/stdint.h defines:
 *    typedef uint32_t uint_fast32_t;
 * but the compiler detects uint_fast32_t as unsigned long instead.
 * Explicitly re-typing this to uint32_t as originally intended. */
typedef uint32_t uint_fast32_t;

/* TODO: Consider how to simplify this */
// static struct builtin_tls {
// 	char c;
// 	struct pthread pt;
// 	void *space[16];
// } builtin_tls[1];
// #define MIN_TLS_ALIGN offsetof(struct builtin_tls, pt)
#define MIN_TLS_ALIGN 8

// static size_t tls_cnt, tls_offset, tls_align = MIN_TLS_ALIGN;

// static tls_module_t *tls_tail;

/* TODO: Can we drop this? */
// libc_t __libc;

#define laddr(p, v) (void*)((p)->base + (v))
// #define laddr_pg(p, v) laddr(p, v)
// #define fpaddr(p, v) ((void (*)())laddr(p, v))

/* Unmodified helpers from dynlink.c */
static void decode_vec(size_t* v, size_t* a, size_t cnt)
{
    size_t i;
    for (i = 0; i < cnt; i++)
        a[i] = 0;
    for (; v[0]; v += 2)
        if (v[0] - 1 < cnt - 1)
        {
            a[0] |= 1UL << v[0];
            a[v[0]] = v[1];
        }
}

static int search_vec(size_t* v, size_t* r, size_t key)
{
    for (; v[0] != key; v += 2)
        if (!v[0])
            return 0;
    *r = v[1];
    return 1;
}

static uint32_t gnu_hash(const char* s0)
{
    const unsigned char* s = (void*)s0;
    uint_fast32_t h = 5381;
    for (; *s; s++)
        h += h * 32 + *s;
    return h;
}

static uint32_t sysv_hash(const char* s0)
{
    const unsigned char* s = (void*)s0;
    uint_fast32_t h = 0;
    while (*s)
    {
        h = 16 * h + *s++;
        h ^= h >> 24 & 0xf0;
    }
    return h & 0xfffffff;
}
/* End unmodified code from dynlink.c */

/* ELF Helper functions ======> */
/* These are lightly modified, usually removing unused compiler def codepaths
 * and replacing libc types for OE specific equivalents. (e.g. dso_t) */

static void decode_dyn(dso_t* p)
{
    /* TODO: Uncomment once they are populated as part of map_library */
    size_t dyn[DYN_CNT];
    // decode_vec(p->dynv, dyn, DYN_CNT);
    p->syms = laddr(p, dyn[DT_SYMTAB]);
    p->strings = laddr(p, dyn[DT_STRTAB]);
    if (dyn[0] & (1 << DT_HASH))
        p->hashtab = laddr(p, dyn[DT_HASH]);
    if (dyn[0] & (1 << DT_RPATH))
        p->rpath_orig = p->strings + dyn[DT_RPATH];
    if (dyn[0] & (1 << DT_RUNPATH))
        p->rpath_orig = p->strings + dyn[DT_RUNPATH];
    if (dyn[0] & (1 << DT_PLTGOT))
        p->got = laddr(p, dyn[DT_PLTGOT]);
    // if (search_vec(p->dynv, dyn, DT_GNU_HASH))
    // 	p->ghashtab = laddr(p, *dyn);
    // if (search_vec(p->dynv, dyn, DT_VERSYM))
    // 	p->versym = laddr(p, *dyn);
}

static elf64_sym_t* gnu_lookup(
    uint32_t h1,
    uint32_t* hashtab,
    dso_t* dso,
    const char* s)
{
    uint32_t nbuckets = hashtab[0];
    uint32_t* buckets = hashtab + 4 + hashtab[2] * (sizeof(size_t) / 4);
    uint32_t i = buckets[h1 % nbuckets];

    if (!i)
        return 0;

    uint32_t* hashval = buckets + nbuckets + (i - hashtab[1]);

    for (h1 |= 1;; i++)
    {
        uint32_t h2 = *hashval++;
        if ((h1 == (h2 | 1)) && (!dso->versym || dso->versym[i] >= 0) &&
            !strcmp(s, dso->strings + dso->syms[i].st_name))
            return dso->syms + i;
        if (h2 & 1)
            break;
    }

    return 0;
}

static elf64_sym_t* gnu_lookup_filtered(
    uint32_t h1,
    uint32_t* hashtab,
    dso_t* dso,
    const char* s,
    uint32_t fofs,
    size_t fmask)
{
    const size_t* bloomwords = (const void*)(hashtab + 4);
    size_t f = bloomwords[fofs & (hashtab[2] - 1)];
    if (!(f & fmask))
        return 0;

    f >>= (h1 >> hashtab[3]) % (8 * sizeof f);
    if (!(f & 1))
        return 0;

    return gnu_lookup(h1, hashtab, dso, s);
}

static elf64_sym_t* sysv_lookup(const char* s, uint32_t h, dso_t* dso)
{
    size_t i;
    elf64_sym_t* syms = dso->syms;
    elf_symndx_t* hashtab = dso->hashtab;
    char* strings = dso->strings;
    for (i = hashtab[2 + h % hashtab[0]]; i; i = hashtab[2 + hashtab[0] + i])
    {
        if ((!dso->versym || dso->versym[i] >= 0) &&
            (!strcmp(s, strings + syms[i].st_name)))
            return syms + i;
    }
    return 0;
}

static symdef_t find_sym(dso_t* dso, const char* s, int need_def)
{
    uint32_t h = 0, gh = gnu_hash(s), gho = gh / (8 * sizeof(size_t)), *ght;
    size_t ghm = 1ul << gh % (8 * sizeof(size_t));
    symdef_t def = {0};
    for (; dso; dso = dso->syms_next)
    {
        elf64_sym_t* sym;
        if ((ght = dso->ghashtab))
        {
            sym = gnu_lookup_filtered(gh, ght, dso, s, gho, ghm);
        }
        else
        {
            if (!h)
                h = sysv_hash(s);
            sym = sysv_lookup(s, h, dso);
        }
        if (!sym)
            continue;
        if (!sym->st_shndx)
            if (need_def || (sym->st_info & 0xf) == STT_TLS)
                // NOTE: Don't need to handle MIPS and ARCH_SYM_REJECT_UND(sym)
                continue;
        if (!sym->st_value)
            if ((sym->st_info & 0xf) != STT_TLS)
                continue;
        if (!(1 << (sym->st_info & 0xf) & OK_TYPES))
            continue;
        if (!(1 << (sym->st_info >> 4) & OK_BINDS))
            continue;
        def.sym = sym;
        def.dso = dso;
        break;
    }
    return def;
}

/* <====== END ELF Helper Functions */

static void unmap_library(dso_t* dso)
{
    /* TODO: This probably has parity with _unload_elf_image in terms of
     * cleaning up the members of a dso_t. */
    OE_UNUSED(dso);
    // 	if (dso->loadmap) {
    // 		size_t i;
    // 		for (i=0; i<dso->loadmap->nsegs; i++) {
    // 			if (!dso->loadmap->segs[i].p_memsz)
    // 				continue;
    // 			munmap((void *)dso->loadmap->segs[i].addr,
    // 				dso->loadmap->segs[i].p_memsz);
    // 		}
    // 		free(dso->loadmap);
    // 	} else if (dso->map && dso->map_len) {
    // 		munmap(dso->map, dso->map_len);
    // 	}
}

/* PROTO: This is the equivalent of the enclave _read_elf_header through
 * _stage_image_segments that caches the relevant ELF pointers on the DSO
 * object and loads the segments into memory */
static oe_result_t map_library(int fd, dso_t* dso)
{
    oe_result_t result = OE_OK;

    /* TODO: Determine why MUSL uses this buffer sizing with extra 896 bytes */
    elf64_ehdr_t buf[(896 + sizeof(elf64_ehdr_t)) / sizeof(elf64_ehdr_t)];
    void* allocated_buf = 0;
    size_t phsize;
    size_t addr_min = OE_SIZE_MAX, addr_max = 0;
    // size_t map_len;
    // size_t this_min, this_max;
    size_t nsegs = 0;
    off_t off_start;
    elf64_ehdr_t* eh;
    elf64_phdr_t *ph, *ph0;
    unsigned prot;
    // unsigned char *map = MAP_FAILED;
    unsigned char* base = NULL;
    size_t dyn = 0;
    size_t tls_image = 0;

    /* Read the ELF header [_read_elf_header replacement] */
    ssize_t l = read(fd, buf, sizeof(buf));
    eh = buf;

    if (l < 0)
        OE_RAISE(OE_READ_FAILED);
    if ((size_t)l < sizeof(*eh))
        OE_RAISE(OE_INVALID_IMAGE);

    /* Fail if not PIE or shared object. MUSL accepts ET_EXEC, but not OE */
    if (eh->e_type != ET_DYN)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not a PIE or shared object", NULL);

    /* OE specifically fails if not Intel X86 64-bit */
    if (eh->e_machine != EM_X86_64)
        OE_RAISE_MSG(
            OE_INVALID_IMAGE, "ELF image is not Intel X86 64-bit", NULL);

    /* Read the program headers [_initialize_image_segments replacement,
     * including call to elf64_get_program_header] */

    phsize = eh->e_phentsize * eh->e_phnum;
    if (phsize > sizeof buf - sizeof *eh)
    {
        allocated_buf = malloc(phsize);
        if (!allocated_buf)
            OE_RAISE(OE_OUT_OF_MEMORY);
        l = pread(fd, allocated_buf, phsize, (off_t)eh->e_phoff);
        if (l < 0 || (size_t)l != phsize)
            OE_RAISE(OE_READ_FAILED);
        ph = ph0 = allocated_buf;
    }
    else if (eh->e_phoff + phsize > (size_t)l)
    {
        l = pread(fd, buf + 1, phsize, (off_t)eh->e_phoff);
        if (l < 0 || (size_t)l != phsize)
            OE_RAISE(OE_READ_FAILED);
        ph = ph0 = (void*)(buf + 1);
    }
    else
    {
        ph = ph0 = (void*)((char*)buf + eh->e_phoff);
    }

    /* Read the program load segments */
    for (size_t i = eh->e_phnum; i;
         i--, ph = (void*)((char*)ph + eh->e_phentsize))
    {
        if (ph->p_type == PT_DYNAMIC)
        {
            dyn = ph->p_vaddr;
        }
        else if (ph->p_type == PT_TLS)
        {
            tls_image = ph->p_vaddr;
            dso->tls.align = ph->p_align;
            dso->tls.len = ph->p_filesz;
            dso->tls.size = ph->p_memsz;
        }
        if (ph->p_type != PT_LOAD)
            continue;
        nsegs++;
        if (ph->p_vaddr < addr_min)
        {
            addr_min = ph->p_vaddr;
            off_start = (off_t)ph->p_offset;
            /* TODO: OE indirects this with _make_secinfo_flags for
             * _add_segment_pages to consume */
            prot =
                (((ph->p_flags & PF_R) ? PROT_READ : 0) |
                 ((ph->p_flags & PF_W) ? PROT_WRITE : 0) |
                 ((ph->p_flags & PF_X) ? PROT_EXEC : 0));
        }
        if (ph->p_vaddr + ph->p_memsz > addr_max)
        {
            addr_max = ph->p_vaddr + ph->p_memsz;
        }
    }

    if (!dyn)
        OE_RAISE_MSG(OE_INVALID_IMAGE, "No PT_DYNAMIC segment found.", NULL);

    /* [_stage_image_segments replacement] */
    /* MUSL has a clever way of page-aligning the target address range */
    // addr_max += PAGE_SIZE - 1;
    // addr_max &= -PAGE_SIZE;
    // addr_min &= -PAGE_SIZE;
    // off_start &= -PAGE_SIZE;
    // map_len = addr_max - addr_min + off_start;

    // /* The first time, we map too much, possibly even more than
    //  * the length of the file. This is okay because we will not
    //  * use the invalid part; we just need to reserve the right
    //  * amount of virtual address space to map over later. */
    // map =
    //     DL_NOMMU_SUPPORT
    //         ? mmap(
    //               (void*)addr_min,
    //               map_len,
    //               PROT_READ | PROT_WRITE | PROT_EXEC,
    //               MAP_PRIVATE | MAP_ANONYMOUS,
    //               -1,
    //               0)
    //         : mmap((void*)addr_min, map_len, prot, MAP_PRIVATE, fd,
    //         off_start);
    // if (map == MAP_FAILED)
    //     goto error;
    // dso->map = map; // this would be equivalent to our image->segments
    // dso->map_len = map_len;
    // /* If the loaded file is not relocatable and the requested address is
    //  * not available, then the load operation must fail. */
    // if (eh->e_type != ET_DYN && addr_min && map != (void*)addr_min)
    // {
    //     errno = EBUSY;
    //     goto error;
    // }
    // base = map - addr_min;
    // dso->phdr = 0;
    // dso->phnum = 0;
    // for (ph = ph0, i = eh->e_phnum; i;
    //      i--, ph = (void*)((char*)ph + eh->e_phentsize))
    // {
    //     if (ph->p_type != PT_LOAD)
    //         continue;
    //
    //     /* Check if the programs headers are in this load segment, and
    //      * if so, record the address for use by dl_iterate_phdr. */
    //     if (!dso->phdr && eh->e_phoff >= ph->p_offset &&
    //         eh->e_phoff + phsize <= ph->p_offset + ph->p_filesz)
    //     {
    //         dso->phdr =
    //             (void*)(base + ph->p_vaddr + (eh->e_phoff - ph->p_offset));
    //         dso->phnum = eh->e_phnum;
    //         dso->phentsize = eh->e_phentsize;
    //     }
    //     this_min = ph->p_vaddr & -PAGE_SIZE;
    //     this_max = ph->p_vaddr + ph->p_memsz + PAGE_SIZE - 1 & -PAGE_SIZE;
    //     off_start = ph->p_offset & -PAGE_SIZE;
    //     prot =
    //         (((ph->p_flags & PF_R) ? PROT_READ : 0) |
    //          ((ph->p_flags & PF_W) ? PROT_WRITE : 0) |
    //          ((ph->p_flags & PF_X) ? PROT_EXEC : 0));
    //     /* Reuse the existing mapping for the lowest-address LOAD */
    //     if ((ph->p_vaddr & -PAGE_SIZE) != addr_min || DL_NOMMU_SUPPORT)
    //         if (mmap_fixed(
    //                 base + this_min,
    //                 this_max - this_min,
    //                 prot,
    //                 MAP_PRIVATE | MAP_FIXED,
    //                 fd,
    //                 off_start) == MAP_FAILED)
    //             goto error;
    //     if (ph->p_memsz > ph->p_filesz && (ph->p_flags & PF_W))
    //     {
    //         size_t brk = (size_t)base + ph->p_vaddr + ph->p_filesz;
    //         size_t pgbrk = brk + PAGE_SIZE - 1 & -PAGE_SIZE;
    //         memset((void*)brk, 0, pgbrk - brk & PAGE_SIZE - 1);
    //         if (pgbrk - (size_t)base < this_max &&
    //             mmap_fixed(
    //                 (void*)pgbrk,
    //                 (size_t)base + this_max - pgbrk,
    //                 prot,
    //                 MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
    //                 -1,
    //                 0) == MAP_FAILED)
    //             goto error;
    //     }
    // }
    // for (i = 0; ((size_t*)(base + dyn))[i]; i += 2)
    //     if (((size_t*)(base + dyn))[i] == DT_TEXTREL)
    //     {
    //         if (mprotect(map, map_len, PROT_READ | PROT_WRITE | PROT_EXEC) &&
    //             errno != ENOSYS)
    //             goto error;
    //         break;
    //     }

    /*
     * ====== TODO: Additional actions OE expects:
     */
    /* _read_elf_headers */
    /* Save entry point address needed to be set in the TCS for enclave app */
    // image->entry_rva = eh->e_entry;

    /* _read_elf_sections is completely elided */

    /* _initialize_image_segments */
    /* Calculate the full size of the image (rounded up to the page size) */
    // image->image_size = oe_round_up_to_page_size(hi - lo); // addr_max -
    // addr_min

    // /* Allocate the in-memory image for program segments on a page boundary
    // */ image->image_base = (char*)oe_memalign(OE_PAGE_SIZE,
    // image->image_size); if (!image->image_base)
    // {
    //     OE_RAISE(OE_OUT_OF_MEMORY);
    // }

    // /* Zero initialize the in-memory image */
    // memset(image->image_base, 0, image->image_size);

    /* _stage_image_segments */
    // /* Cache the segment properties for enclave page add */
    // segment->memsz = ph->p_memsz;
    // segment->vaddr = ph->p_vaddr;
    // segment->flags = ph->p_flags;
    /*
     * ====== END TODO
     */

    // done_mapping:
    dso->base = base;
    dso->dynv = laddr(dso, dyn);
    if (dso->tls.size)
        dso->tls.image = laddr(dso, tls_image);
    result = OE_OK;

done:
    if (result != OE_OK)
        unmap_library(dso);
    free(allocated_buf);
    return result;
}

/* PROTO: OE version of load_library function from
 * 3rdparty/musl/musl/ldso/dynlink.c */
oe_result_t oe_load_enclave_dso(
    const char* name,
    oe_dso_load_state_t* load_state,
    dso_t* needed_by,
    dso_t** dso)
{
    oe_result_t result = OE_UNEXPECTED;

    char pathname_buffer[MUSL_PATHNAME_MAX_LENGTH];
    char* pathname = NULL;
    int required_pathname_length = 0;
    const char* shortname = NULL;
    dso_t *p, temp_dso = {0};
    int fd = -1;
    size_t dso_alloc_size = 0;

    if (!name || !*name || !load_state)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check if the name provided is a pathed name, which is
     * usually provided for the primary dso */
    if (strchr(name, '/'))
    {
        /* Enforce OE max path length for _load_elf_image */
        if (strlen(name) > OE_INT32_MAX)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "Enclave path is not null-terminated or exceeds OE_INT32_MAX");

        pathname = (char*)name;
        shortname = strrchr(name, '/') + 1;
    }
    else
    {
        /* Limitation for consistency with MUSL libc loading */
        if (strlen(name) > NAME_MAX)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "Library name is not null-terminated or exceeds NAME_MAX");
        shortname = name;
    }

    /* Search for the name to see if it's already loaded */
    if (load_state->head)
    {
        for (p = load_state->head->next; p; p = p->next)
        {
            if (p->shortname && !strcmp(p->shortname, shortname))
            {
                if (dso)
                    *dso = p;
                result = OE_OK;
                goto done;
            }
        }
    }

    if (!pathname)
    {
        if (!load_state->head)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "No primary enclave has been loaded. Cannot resolve path for "
                "enclave dependencies");
        int root_path_length =
            (int)(strrchr(load_state->head->name, '/') - load_state->head->name);
        required_pathname_length = snprintf(
            pathname_buffer,
            sizeof(pathname_buffer),
            "%.*s/%s",
            root_path_length,
            load_state->head->name,
            shortname);
        if (required_pathname_length <= 0)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (required_pathname_length < (int64_t)sizeof(pathname_buffer))
            pathname = pathname_buffer;
        else
        {
            size_t buffer_size = (size_t)required_pathname_length + 1;
            pathname = (char*)malloc(buffer_size);
            if (!pathname)
                OE_RAISE(OE_OUT_OF_MEMORY);
            required_pathname_length = snprintf(
                pathname,
                buffer_size,
                "%.*s/%s",
                root_path_length,
                load_state->head->name,
                shortname);
        }
    }

    fd = open(pathname, O_RDONLY);
    if (fd < 0 || fstat(fd, &statbuf) != 0 || !S_ISREG(statbuf.st_mode))
        OE_RAISE(OE_INVALID_PARAMETER);

    result = map_library(fd, &temp_dso);
    close(fd);
    OE_CHECK(result);

    decode_dyn(&temp_dso);

    /* Allocate storage for the new DSO. Note OE does not account for
     * dynamic loading scenarios where a reservation for all pre-existing
     * threads to obtain copies of the new TLS plus an extended DTV capable of
     * storing an additional slot for the newly-loaded DSO. */
    dso_alloc_size = sizeof *p + strlen(pathname) + 1;
    p = calloc(1, dso_alloc_size);
    if (!p)
    {
        unmap_library(&temp_dso);
        OE_RAISE(OE_OUT_OF_MEMORY);
    }
    memcpy(p, &temp_dso, sizeof temp_dso);
    p->needed_by = needed_by;
    p->name = p->buf;
    strcpy(p->name, pathname);
    p->shortname = strrchr(p->name, '/') + 1;

    /* TODO: Fix up handling of TLS */
    //         if (p->tls.image)
    //         {
    //             p->tls_id = ++tls_cnt;
    //             tls_align = MAXP2(tls_align, p->tls.align);
    // #ifdef TLS_ABOVE_TP
    //             p->tls.offset =
    //                 tls_offset +
    //                 ((tls_align - 1) & -(tls_offset +
    //                 (uintptr_t)p->tls.image));
    //             tls_offset += p->tls.size;
    // #else
    //             tls_offset += p->tls.size + p->tls.align - 1;
    //             tls_offset -=
    //                 (tls_offset + (uintptr_t)p->tls.image) & (p->tls.align -
    //                 1);
    //             p->tls.offset = tls_offset;
    // #endif
    //             p->new_dtv =
    //                 (void*)(-sizeof(size_t) & (uintptr_t)(p->name +
    //                 strlen(p->name) + sizeof(size_t)));
    //             p->new_tls = (void*)(p->new_dtv + n_th * (tls_cnt + 1));
    //             if (tls_tail)
    //                 tls_tail->next = &p->tls;
    //             else
    //                 libc.tls_head = &p->tls;
    //             tls_tail = &p->tls;
    //         }

    if (!load_state->head)
        load_state->head = load_state->tail = p;
    else
    {
        load_state->tail->next = p;
        p->prev = load_state->tail;
        load_state->tail = p;
    }

    if (dso)
        *dso = p;
    result = OE_OK;

done:
    if (required_pathname_length >= (int64_t)sizeof(pathname_buffer))
        free(pathname);

    return result;
}

oe_result_t oe_load_deps(oe_dso_load_state_t* load_state, dso_t* p)
{
    oe_result_t result = OE_UNEXPECTED;
    for (; p; p = p->next)
    {
        OE_UNUSED(load_state);
        // TODO: enable after map_library is enabled
        // for (size_t i = 0; p->dynv[i]; i += 2)
        // {
        //     if (p->dynv[i] != DT_NEEDED)
        //         continue;
        //     OE_CHECK(oe_load_enclave_dso(
        //         p->strings + p->dynv[i + 1], load_state, p, NULL));
        // }
    }
    result = OE_OK;

    // done:
    return result;
}

void oe_unload_enclave_dso(oe_dso_load_state_t* load_state)
{
    if (load_state)
    {
        dso_t* next = NULL;
        for (dso_t* p = load_state->head; p; p = next)
        {
            next = p->next;
            unmap_library(p);
            free(p);
        }
    }
}