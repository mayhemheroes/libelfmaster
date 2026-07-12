/*
 * In-process libFuzzer harness for the `stripx` section-header stripping logic (target: stripx).
 *
 * Upstream ships `utils/stripx.c` as a standalone file-input CLI: it mmap()s an ELF file and,
 * trusting the on-file e_shoff / e_shnum / sh_link fields, walks the section-header table zeroing
 * out string/symbol tables. As a raw, uninstrumented file CLI it records zero Mayhem coverage, so
 * per the porting policy it is converted to an in-process libFuzzer harness that runs the IDENTICAL
 * stripping loops over a writable heap copy of the input. The bounds-trusting logic (and any
 * out-of-bounds access it commits on a crafted header) is preserved verbatim from stripx.c.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *mem, *p;
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;
    Elf64_Ehdr *ehdr64;
    Elf64_Shdr *shdr64;
    int i, j;
    char *StringTable, *SymStrTable;
    uint16_t e_mach;

    /*
     * The CLI relies on a real mmap of at least one ELF header; require that much so the harness
     * itself never over-reads its own buffer. Everything past this point mirrors stripx.c main().
     */
    if (size < sizeof(Elf64_Ehdr))
        return 0;

    mem = malloc(size);
    if (mem == NULL)
        return 0;
    memcpy(mem, data, size);

    if (mem[0] != 0x7f && strcmp((char *)&mem[1], "ELF")) {
        free(mem);
        return 0;
    }

    ehdr = (Elf32_Ehdr *)mem;
    e_mach = ehdr->e_machine;
    switch (e_mach) {
    case EM_X86_64:
        ehdr64 = (Elf64_Ehdr *)mem;
        shdr64 = (Elf64_Shdr *)&mem[ehdr64->e_shoff];

        for (i = 0; i < ehdr64->e_shnum; i++) {
            if (shdr64[i].sh_type == SHT_SYMTAB) {
                SymStrTable = (char *)&mem[shdr64[shdr64[i].sh_link].sh_offset];
                for (p = (uint8_t *)SymStrTable, j = 0; j < shdr64[shdr64[i].sh_link].sh_size; j++, p++)
                    *p = 0x00;
            }
        }

        for (i = 0, StringTable = (char *)&mem[shdr64[ehdr64->e_shstrndx].sh_offset], p = (uint8_t *)StringTable;
             i < shdr64[ehdr64->e_shstrndx].sh_size; i++, p++)
            *p = 0x00;

        for (p = &mem[ehdr64->e_shoff], i = 0; i < ehdr64->e_shentsize * ehdr64->e_shnum; i++, p++)
            *p = 0x00;

        ehdr64->e_shstrndx = 0;
        ehdr64->e_shnum = 0;
        ehdr64->e_shoff = 0;
        break;
    case EM_386:
        ehdr = (Elf32_Ehdr *)mem;
        shdr = (Elf32_Shdr *)&mem[ehdr->e_shoff];

        for (i = 0; i < ehdr->e_shnum; i++) {
            if (shdr[i].sh_type == SHT_SYMTAB) {
                SymStrTable = (char *)&mem[shdr[shdr[i].sh_link].sh_offset];
                for (p = (uint8_t *)SymStrTable, j = 0; j < shdr[shdr[i].sh_link].sh_size; j++, p++)
                    *p = 0x00;
            }
        }

        for (i = 0, StringTable = (char *)&mem[shdr[ehdr->e_shstrndx].sh_offset], p = (uint8_t *)StringTable;
             i < shdr[ehdr->e_shstrndx].sh_size; i++, p++)
            *p = 0x00;

        for (p = &mem[ehdr->e_shoff], i = 0; i < ehdr->e_shentsize * ehdr->e_shnum; i++, p++)
            *p = 0x00;

        ehdr->e_shstrndx = 0;
        ehdr->e_shnum = 0;
        ehdr->e_shoff = 0;
        break;
    default:
        free(mem);
        return 0;
    }

    free(mem);
    return 0;
}
