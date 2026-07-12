#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the authored libelfmaster behavioral oracle built by mayhem/build.sh.
#
# Upstream ships NO usable functional suite (regressions/ holds only an empty literally-named "*.c"
# and a Makefile referencing a non-existent parse_elfmaster.c), so this is an AUTHORED known-answer
# oracle (tests_found=0). It parses a fixture ELF with libelfmaster and asserts KNOWN properties
# (class, arch/machine, presence of .text/.symtab, the fixture's `main`/`helper_symbol` symbols, a
# non-zero entry point). The expected values live HERE, not in the program, so a libelfmaster neutered
# to a no-op (the sabotage check) yields no/incorrect output and FAILS.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

ORACLE=/mayhem/oracle
FIXTURE=/mayhem/oracle_fixture

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ] || [ ! -f "$FIXTURE" ]; then
  echo "test.sh: oracle or fixture missing — build.sh bug" >&2
  emit_ctrf "libelfmaster-kat" 0 1
  exit 1
fi

OUT="$("$ORACLE" "$FIXTURE" 2>/dev/null || true)"
echo "--- oracle output ---"; echo "$OUT"; echo "---------------------"

passed=0; failed=0
check() { # check <name> <expected-line>
  if echo "$OUT" | grep -qx "$2"; then
    echo "PASS $1"; passed=$((passed+1))
  else
    echo "FAIL $1 (expected '$2')"; failed=$((failed+1))
  fi
}

check "open"        "OPEN=1"
check "class64"     "CLASS=64"
check "arch_x64"    "ARCH=1"
check "machine_x86_64" "MACHINE=62"
check "section_text"   "SEC_TEXT=1"
check "section_symtab" "SEC_SYMTAB=1"
check "symbol_main"    "SYM_MAIN=1"
check "symbol_helper"  "SYM_HELPER=1"

# Entry point must be present and non-zero for a -no-pie EXEC.
if echo "$OUT" | grep -qE '^ENTRY=0x[0-9a-f]+$' && ! echo "$OUT" | grep -qx 'ENTRY=0x0'; then
  echo "PASS entry_nonzero"; passed=$((passed+1))
else
  echo "FAIL entry_nonzero"; failed=$((failed+1))
fi

emit_ctrf "libelfmaster-kat" "$passed" "$failed"
