// In-process libFuzzer harness for libelfmaster's ELF loader (target: elf-open-object).
//
// elf_open_object() takes a *path* and mmaps it, so we stage the fuzz input to a real file
// and drive the loader over it. Unlike the original harness (which fed a random *string* as the
// path — so it almost never opened a real ELF and exercised ~none of the parser), this actually
// parses the mutated bytes and then walks the reconstructed section/segment/symbol tables to
// drive the forensic reconstruction code paths.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

extern "C" {
#include "libelfmaster.h"
}

// libelfmaster's forensic reconstruction allocates section/symbol structures it does not fully free
// on partial-parse error paths; disable leak detection so those reports don't swamp the memory-safety
// (OOB/UAF) findings. ASan + UBSan otherwise remain on and halting. (Set here rather than via the
// Mayhemfile env, which Mayhem owns.)
extern "C" const char *__asan_default_options(void) { return "detect_leaks=0"; }

// Persistent scratch file, created once and reused across iterations.
static int g_fd = -1;
static char g_path[64];

static void ensure_file(void) {
    if (g_fd != -1)
        return;
    snprintf(g_path, sizeof(g_path), "/tmp/elfobj_fuzz_%d", (int)getpid());
    g_fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (g_fd == -1) {
        perror("open scratch");
        _exit(1);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ensure_file();

    if (ftruncate(g_fd, 0) != 0)
        return 0;
    if (lseek(g_fd, 0, SEEK_SET) != 0)
        return 0;
    for (size_t off = 0; off < size;) {
        ssize_t n = write(g_fd, data + off, size - off);
        if (n <= 0)
            return 0;
        off += (size_t)n;
    }
    fsync(g_fd);

    elfobj_t obj;
    elf_error_t err;

    // ELF_LOAD_F_FORENSICS exercises the maximum amount of parsing/reconstruction; avoid the
    // MODIFY/ULEXEC/MAP_WRITE flags which mutate or execute the mapping.
    if (elf_open_object(g_path, &obj, ELF_LOAD_F_FORENSICS, &err) == false)
        return 0;

    // Walk the parsed structures to drive the accessors/iterators.
    struct elf_section section;
    elf_section_iterator_t s_iter;
    elf_section_iterator_init(&obj, &s_iter);
    while (elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
    }

    struct elf_segment segment;
    elf_segment_iterator_t p_iter;
    elf_segment_iterator_init(&obj, &p_iter);
    while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
    }

    struct elf_symbol symbol;
    elf_symtab_iterator_t sym_iter;
    elf_symtab_iterator_init(&obj, &sym_iter);
    while (elf_symtab_iterator_next(&sym_iter, &symbol) == ELF_ITER_OK) {
    }

    elf_dynsym_iterator_t dsym_iter;
    elf_dynsym_iterator_init(&obj, &dsym_iter);
    while (elf_dynsym_iterator_next(&dsym_iter, &symbol) == ELF_ITER_OK) {
    }

    elf_close_object(&obj);
    return 0;
}
