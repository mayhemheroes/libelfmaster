#!/usr/bin/env bash
#
# mayhem/build.sh — build libelfmaster's fuzz harnesses (+ standalone reproducers) and the authored
# behavioral oracle. Runs inside the commit image as `mayhem` in /mayhem.
#
# Targets (names preserved from the fork's Mayhem run history):
#   elf-open-object  — libFuzzer harness driving elf_open_object() + the section/segment/symbol
#                       iterators over the mutated bytes (reworked from the old path-string harness).
#   stripx           — the utils/stripx.c section-header stripping logic, converted from an
#                       uninstrumented raw file CLI to an in-process libFuzzer harness (same code path).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

INC="$SRC/include"
LIBSRC=( "$SRC/src/internal.c" "$SRC/src/libelfmaster.c" )
COMMON="-D_GNU_SOURCE -I$INC"

# 1) Build the library ITSELF with the sanitizers + DWARF so the fuzzed code is instrumented.
mkdir -p /tmp/objs
san_objs=()
for src in "${LIBSRC[@]}"; do
    obj="/tmp/objs/$(basename "${src%.c}").san.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fPIC $COMMON -c "$src" -o "$obj"
    san_objs+=( "$obj" )
done
ar rcs /tmp/libelfmaster_san.a "${san_objs[@]}"

# 2) Harnesses — each linked twice: the libFuzzer binary and a standalone run-once reproducer.
#    elf-open-object is C++; compile the standalone driver as a C object so its LLVMFuzzerTestOneInput
#    reference keeps C linkage.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $COMMON \
    "$SRC/mayhem/fuzz_elf_open_object.cpp" /tmp/libelfmaster_san.a \
    -o /mayhem/fuzz_elf_open_object
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $COMMON \
    "$SRC/mayhem/fuzz_elf_open_object.cpp" /tmp/standalone_main.o /tmp/libelfmaster_san.a \
    -o /mayhem/fuzz_elf_open_object-standalone

# stripx harness is self-contained C (replicates stripx.c over a heap buffer) — no libelfmaster link.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    "$SRC/mayhem/fuzz_stripx.c" -o /mayhem/fuzz_stripx
$CC $SANITIZER_FLAGS $DEBUG_FLAGS \
    "$SRC/mayhem/fuzz_stripx.c" /tmp/standalone_main.o -o /mayhem/fuzz_stripx-standalone

# 3) Test suite (authored oracle) — a SEPARATE clean build with the project's normal flags (no
#    sanitizers), so test.sh only RUNS it. Build the library normally, the fixture ELF, and the oracle.
NORMAL_CFLAGS="-O0 -g -fPIC -D_GNU_SOURCE -I$INC"
norm_objs=()
for src in "${LIBSRC[@]}"; do
    obj="/tmp/objs/$(basename "${src%.c}").norm.o"
    $CC $NORMAL_CFLAGS $COVERAGE_FLAGS -c "$src" -o "$obj"
    norm_objs+=( "$obj" )
done
ar rcs /tmp/libelfmaster_norm.a "${norm_objs[@]}"

$CC $NORMAL_CFLAGS $COVERAGE_FLAGS "$SRC/mayhem/oracle.c" /tmp/libelfmaster_norm.a \
    -o /mayhem/oracle
# Known fixture: a -no-pie EXEC ELF with the stable symbols the oracle asserts.
$CC -no-pie -O0 "$SRC/mayhem/oracle_fixture.c" -o /mayhem/oracle_fixture

echo "build.sh: OK — targets: fuzz_elf_open_object, fuzz_stripx (+ standalones); oracle + fixture"
