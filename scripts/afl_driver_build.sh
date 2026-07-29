#!/bin/bash

configure_fts_afl_compiler() {
    if [[ -z "${LEGION_FTS_AFL_CC:-}" && -x /clang+llvm/bin/clang ]]; then
        export CC=/clang+llvm/bin/clang
    else
        export CC="${LEGION_FTS_AFL_CC:-clang}"
    fi

    if [[ -z "${LEGION_FTS_AFL_CXX:-}" && -x /clang+llvm/bin/clang++ ]]; then
        export CXX=/clang+llvm/bin/clang++
    else
        export CXX="${LEGION_FTS_AFL_CXX:-clang++}"
    fi

    export LD="${LEGION_FTS_AFL_LD:-$CC}"
    if [[ -d /clang+llvm/lib ]]; then
        export LD_LIBRARY_PATH="/clang+llvm/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi
}

build_fts_afl_driver_engine() {
    local engine_lib="${1:-libFuzzingEngine-afl.a}"
    local script_dir
    local legion_root
    local afl_src
    local libfuzzer_src
    local afl_rt
    local afl_driver

    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    legion_root="$(cd "$script_dir/.." && pwd)"

    afl_src="${LEGION_FTS_AFL_SRC:-${AFL_SRC:-${AFL_BIN:-${TOOLS_ROOT:-/FuzzingTools}/AFL}}}"
    if [[ ! -f "$afl_src/llvm_mode/afl-llvm-rt.o.c" && -f "${TOOLS_ROOT:-/FuzzingTools}/AFL/llvm_mode/afl-llvm-rt.o.c" ]]; then
        afl_src="${TOOLS_ROOT:-/FuzzingTools}/AFL"
    fi

    libfuzzer_src="${LEGION_LIBFUZZER_SRC:-${LIBFUZZER_SRC:-$legion_root/Fuzzer}}"
    if [[ ! -f "$libfuzzer_src/afl/afl_driver.cpp" && -f "$legion_root/.cache/compiler-rt-11.1.0.src/lib/fuzzer/afl/afl_driver.cpp" ]]; then
        libfuzzer_src="$legion_root/.cache/compiler-rt-11.1.0.src/lib/fuzzer"
    fi

    afl_rt="$afl_src/llvm_mode/afl-llvm-rt.o.c"
    afl_driver="$libfuzzer_src/afl/afl_driver.cpp"

    if [[ ! -f "$afl_rt" ]]; then
        echo "[LEGION]missing AFL runtime source: $afl_rt" >&2
        exit 1
    fi
    if [[ ! -f "$afl_driver" ]]; then
        echo "[LEGION]missing FTS afl_driver.cpp: $afl_driver" >&2
        exit 1
    fi

    rm -f .legion_afl_llvm_rt.o .legion_afl_driver.o "$engine_lib"
    "$CC" $CFLAGS -c -w "$afl_rt" -o .legion_afl_llvm_rt.o
    "$CXX" $CXXFLAGS -std=c++11 -O2 -c "$afl_driver" -I"$libfuzzer_src" -o .legion_afl_driver.o
    ar rc "$engine_lib" .legion_afl_driver.o .legion_afl_llvm_rt.o
    ranlib "$engine_lib" 2>/dev/null || true

    export EXTRALIBS="$PWD/$engine_lib"
    export LEGION_USE_EXTERNAL_FUZZING_ENGINE=1
    echo "[LEGION]using FTS AFL driver engine: $EXTRALIBS"
}
