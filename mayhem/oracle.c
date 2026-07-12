/*
 * Behavioral / known-answer oracle for libelfmaster (authored — upstream ships no usable test
 * suite: regressions/ contains only an empty literally-named "*.c" file and a Makefile referencing
 * a parse_elfmaster.c that does not exist).
 *
 * It parses a fixture ELF built by mayhem/build.sh (mayhem/oracle_fixture.c, compiled -no-pie with a
 * known symbol `helper_symbol` and `main`) and prints the OBSERVED properties. mayhem/test.sh owns
 * the expected known answers and diffs them, so a libelfmaster neutered to a no-op (the sabotage
 * check) produces no/incorrect output and fails the oracle.
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "libelfmaster.h"

int main(int argc, char **argv)
{
    elfobj_t obj;
    elf_error_t err;
    struct elf_section section;
    struct elf_symbol symbol;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <elf>\n", argv[0]);
        return 2;
    }

    if (elf_open_object(argv[1], &obj, ELF_LOAD_F_FORENSICS, &err) == false) {
        fprintf(stderr, "elf_open_object failed: %s\n", elf_error_msg(&err));
        return 1;
    }

    printf("OPEN=1\n");
    printf("CLASS=%d\n", elf_class(&obj) == elfclass64 ? 64 : 32);
    printf("ARCH=%d\n", (int)elf_arch(&obj));
    printf("MACHINE=%u\n", (unsigned)elf_machine(&obj));
    printf("ENTRY=0x%" PRIx64 "\n", elf_entry_point(&obj));
    printf("SEC_TEXT=%d\n", elf_section_by_name(&obj, ".text", &section) ? 1 : 0);
    printf("SEC_SYMTAB=%d\n", elf_section_by_name(&obj, ".symtab", &section) ? 1 : 0);
    printf("SYM_MAIN=%d\n", elf_symbol_by_name(&obj, "main", &symbol) ? 1 : 0);
    printf("SYM_HELPER=%d\n", elf_symbol_by_name(&obj, "helper_symbol", &symbol) ? 1 : 0);

    elf_close_object(&obj);
    return 0;
}
