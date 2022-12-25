#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "libelfmaster.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString(1000);
    uint64_t flags = provider.ConsumeIntegral<uint64_t>();
    elfobj_t elfobj;
    elf_error_t elf_error;

    elf_open_object(str.c_str(), &elfobj, flags, &elf_error);

    return 0;
}
