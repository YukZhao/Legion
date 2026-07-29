#!/bin/bash
set -euo pipefail

TOOLS_ROOT="${TOOLS_ROOT:-/FuzzingTools}"
if [[ ! -d "$TOOLS_ROOT" && -d /home/threedean/FuzzingTools ]]; then
    TOOLS_ROOT=/home/threedean/FuzzingTools
fi

export AFLPP_BIN="${AFLPP_BIN:-$TOOLS_ROOT/AFLplusplus}"
MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"
AFLPP_LLVM_LIBDIR="${AFLPP_LLVM_LIBDIR:-/clang+llvm/lib}"
AFLPP_MODE="${LEGION_AFLPP_MODE:-clang-simple}"
SYSTEM_BIN_PREFIX="${LEGION_SYSTEM_BIN_PREFIX:-/usr/bin:/bin:/clang+llvm/bin}"
CMIN_TARGET="${LEGION_CMIN_TARGET:-./build/aflapp}"

ensure_aflpp_compilers() {
    [[ -x "$AFLPP_BIN/afl-cc" && -x "$AFLPP_BIN/afl-fuzz" ]]
}

ensure_aflpp_llvm_passes() {
    [[ -f "$AFLPP_BIN/afl-llvm-pass.so" &&
       -f "$AFLPP_BIN/split-switches-pass.so" &&
       -f "$AFLPP_BIN/compare-transform-pass.so" &&
       -f "$AFLPP_BIN/split-compares-pass.so" ]]
}

bootstrap_aflpp_llvm_mode() {
    echo "[LEGION]bootstrapping AFL++ llvm_mode artifacts"
    local wrapper_dir="$AFLPP_BIN/.legion-bootstrap-bin"
    mkdir -p "$wrapper_dir"
    cat > "$wrapper_dir/clangxx-libcxx" <<'EOF'
#!/bin/sh
exec /clang+llvm/bin/clang++ -stdlib=libc++ "$@"
EOF
    chmod +x "$wrapper_dir/clangxx-libcxx"
    (
        cd "$AFLPP_BIN"
        export LD_LIBRARY_PATH="$AFLPP_LLVM_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        make -f GNUmakefile.llvm \
            LLVM_STDCXX=c++17 \
            REAL_CXX="$wrapper_dir/clangxx-libcxx" \
            -j"${JOBS:-$(nproc)}" || true
    )
}

has_regular_files() {
    find "$1" -maxdepth 1 -type f -print -quit | grep -q .
}

copy_seed_dir() {
    src=$1
    dst=$2
    mkdir -p "$dst"
    if [[ -d "$src" ]]; then
        find "$src" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | \
            xargs -0 -r cp -n --target-directory="$dst" 2>/dev/null || true
    fi
}

clear_directory() {
    mkdir -p "$1"
    find "$1" -mindepth 1 -maxdepth 1 -print0 | xargs -0 -r rm -rf
}

copy_queue_files() {
    dst=$1
    shift
    for dir in "$@"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | \
                xargs -0 -r cp --target-directory="$dst"
        fi
    done
}

sync_seed_dir_into_afl_peer_queue() {
    local source=$1
    local output_root=$2
    local peer_dir="$output_root/legion_sync"
    local queue_dir="$peer_dir/queue"
    local seen_file="$peer_dir/.seen_sha1"
    local next_file="$peer_dir/.next_id"
    local next_id=0
    local file checksum dst

    [[ -d "$source" && -d "$output_root" ]] || return 0
    mkdir -p "$queue_dir"
    touch "$seen_file"
    if [[ -f "$next_file" ]]; then
        read -r next_id < "$next_file" || next_id=0
    fi

    while IFS= read -r -d '' file; do
        checksum=$(sha1sum "$file" | awk '{print $1}')
        if grep -qx "$checksum" "$seen_file"; then
            continue
        fi
        dst=$(printf "%s/id:%06d" "$queue_dir" "$next_id")
        cp "$file" "$dst"
        echo "$checksum" >> "$seen_file"
        next_id=$((next_id + 1))
    done < <(find "$source" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0)

    echo "$next_id" > "$next_file"
}

filter_non_crashing_inputs() {
    src_dir=$1
    dst_dir=$2
    mkdir -p "$dst_dir"
    if [[ ! -d "$src_dir" ]]; then
        return 0
    fi
    while IFS= read -r -d '' seed; do
        if timeout 5 "$CMIN_TARGET" "$seed" >/dev/null 2>&1; then
            cp -p "$seed" "$dst_dir"/
        fi
    done < <(find "$src_dir" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0)
}

prepare_aflpp_build_env() {
    if ! ensure_aflpp_compilers; then
        echo "[LEGION]AFL++ compiler wrappers are unavailable under $AFLPP_BIN" >&2
        exit 1
    fi
    unset AFL_SRC || true
    export AFL_PATH="$AFLPP_BIN"
    export AFL_IGNORE_UNKNOWN_ENVS=1
    export AFL_USE_UBSAN=1
    export AFL_USE_ASAN=1
    # Keep AFL++'s own instrumentation and sanitizers, but do not pull in
    # libFuzzer's main/runtime on the AFL++ build path.
    export FSANITIZE_FUZZER_FLAGS="-fno-omit-frame-pointer -g"
    export CFLAGS="$FSANITIZE_FUZZER_FLAGS"
    export CXXFLAGS="$FSANITIZE_FUZZER_FLAGS"
    export EXTRALIBS=""

    if [[ "$AFLPP_MODE" == "llvm-fast" ]]; then
        if ! ensure_aflpp_llvm_passes; then
            bootstrap_aflpp_llvm_mode
        fi
        if ! ensure_aflpp_llvm_passes; then
            echo "[LEGION]AFL++ llvm_mode artifacts are still missing under $AFLPP_BIN" >&2
            exit 1
        fi
        export CC="$AFLPP_BIN/afl-clang-fast"
        export CXX="$AFLPP_BIN/afl-clang-fast++"
        export LD="$AFLPP_BIN/afl-clang-fast"
        export LD_LIBRARY_PATH="$AFLPP_LLVM_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    elif [[ "$AFLPP_MODE" == "clang-simple" ]]; then
        # llvm_mode crashes on jhead in this container; the simple clang mode
        # still gives AFL++-compatible instrumentation and is stable here.
        export PATH="$SYSTEM_BIN_PREFIX:$PATH"
        export CC="$AFLPP_BIN/afl-clang"
        export CXX="$AFLPP_BIN/afl-clang++"
        export LD="$AFLPP_BIN/afl-clang"
    else
        echo "[LEGION]unsupported AFL++ mode: $AFLPP_MODE" >&2
        exit 1
    fi
}

build() {
    ARCHIVE=$(basename "$2")

    prepare_aflpp_build_env

    rm -rf code_aflpp
    mkdir -p build code_aflpp
    cp "$2" code_aflpp/"$ARCHIVE"
    pushd code_aflpp >/dev/null || exit

    if [[ "$1" == "-zip" ]]; then
        unzip "$ARCHIVE"
    elif [[ "$1" == "-gz" ]]; then
        tar -xvf "$ARCHIVE"
    else
        echo "[LEGION]unknown compress format"
        exit 1
    fi

    rm "$ARCHIVE"

    SRC=$(find . -mindepth 1 -maxdepth 1 -type d | sort | head -n 1 | sed 's#^\./##')
    if [[ -z "$SRC" ]]; then
        echo "[LEGION]failed to locate extracted source directory" >&2
        exit 1
    fi

    pushd "$SRC" >/dev/null || exit
    ./fuzzbuild
    popd >/dev/null || exit
    popd >/dev/null || exit

    cp -p code_aflpp/"$SRC"/app build/aflppapp
}

run() {
    sync_interval="${LEGION_MONITOR_SYNC_INTERVAL:-60}"
    terminate_requested=0
    time=$1
    threads=$2
    outfolder=$3
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    unset AFL_SRC || true
    export AFL_PATH="$AFLPP_BIN"
    export AFL_IGNORE_UNKNOWN_ENVS=1
    export LD_LIBRARY_PATH="$AFLPP_LLVM_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    flush_output() {
        clear_directory "$outfolder"
        copy_queue_files "$outfolder" run_aflpp/output/fuzzer*/queue
    }

    handle_term() {
        terminate_requested=1
        echo "[LEGION]AFL++ received termination request, flushing current queue snapshot"
    }

    trap handle_term TERM INT
    rm -rf run_aflpp
    mkdir -p run_aflpp/input run_aflpp/output
    copy_seed_dir "${LEGION_INITIAL_DIR:-initial}" run_aflpp/input
    if ! has_regular_files run_aflpp/input; then
        echo "[LEGION]no initial seeds available for AFL++, skip this round"
        rm -rf "$outfolder"
        mkdir -p "$outfolder"
        return 0
    fi
    pushd run_aflpp >/dev/null || exit

    dict=""
    if [[ "${4:-}" == "-d" ]]; then
        dict="-x ../dict.dict"
    fi

    echo "[LEGION]$dict"
    timeout --foreground "$time" "$AFLPP_BIN/afl-fuzz" -m none -i input -o output -M fuzzer0 $dict -- ../build/aflppapp @@ &

    i=1
    while [[ "$i" -lt "$threads" ]]; do
        timeout --foreground "$time" "$AFLPP_BIN/afl-fuzz" -m none -i input -o output -S fuzzer$i $dict -- ../build/aflppapp @@ &
        i=$((i + 1))
    done

    popd >/dev/null || exit

    echo "[LEGION]sleep $time seconds before fuzzing round finish"

    i=0
    counter=0

    rm -rf "$outfolder"
    mkdir -p "$outfolder"
    while [[ "$i" -lt "$time" ]]; do
        if [[ "$terminate_requested" -ne 0 ]]; then
            break
        fi
        echo "[LEGION-fuzzer]running AFL++ background, $i/$time seconds passed"
        sleep 60
        i=$((i + 60))
        counter=$((counter + 60))
        if [[ "$counter" -ge "$sync_interval" ]]; then
            echo "[LEGION]copying files periodically to speed up the process"
            flush_output
            counter=0
        fi
    done

    echo "[LEGION]$threads instances of AFLPlusPlus run finished in $time seconds"

    sleep 2
    flush_output
}

next_aflpp_worker_index() {
    local output_dir=$1
    local next=1
    local dir base suffix
    for dir in "$output_dir"/fuzzer*; do
        [[ -d "$dir" ]] || continue
        base=$(basename "$dir")
        suffix=${base#fuzzer}
        if [[ "$suffix" =~ ^[0-9]+$ ]] && (( suffix >= next )); then
            next=$((suffix + 1))
        fi
    done
    echo "$next"
}

append() {
    local time=$1
    local threads=$2
    local outfolder=$3
    local dict=""
    local terminate_requested=0
    local pids=()
    local i=0
    local next_index=1

    if [[ ! -d run_aflpp/output ]]; then
        echo "[LEGION]AFL++ append requested without an active run directory, fallback to fresh run"
        run "$@"
        return 0
    fi

    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    unset AFL_SRC || true
    export AFL_PATH="$AFLPP_BIN"
    export AFL_IGNORE_UNKNOWN_ENVS=1
    export LD_LIBRARY_PATH="$AFLPP_LLVM_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    if [[ "${4:-}" == "-d" ]]; then
        dict="-x ../dict.dict"
    fi

    handle_term() {
        terminate_requested=1
        echo "[LEGION]AFL++ append workers received termination request"
    }

    trap handle_term TERM INT
    pushd run_aflpp >/dev/null || exit
    copy_seed_dir "${LEGION_INITIAL_DIR:-../initial}" input
    if [[ -n "${LEGION_APPEND_WORKER_INDEX:-}" ]]; then
        next_index="$LEGION_APPEND_WORKER_INDEX"
    else
        next_index=$(next_aflpp_worker_index output)
    fi

    while [[ "$i" -lt "$threads" ]]; do
        timeout --foreground "$time" "$AFLPP_BIN/afl-fuzz" -m none -i input -o output -S "fuzzer$next_index" $dict -- ../build/aflppapp @@ &
        pids+=("$!")
        next_index=$((next_index + 1))
        i=$((i + 1))
    done

    while [[ "$terminate_requested" -eq 0 ]]; do
        sleep 5
        live=0
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                live=1
                break
            fi
        done
        if [[ "$live" -eq 0 ]]; then
            break
        fi
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    popd >/dev/null || exit
    echo "[LEGION]AFL++ append finished after adding $threads slave workers"
}

update_seed() {
    source=$1
    sync_seed_dir_into_afl_peer_queue "$source" run_aflpp/output
}

minimize() {
    export AFL_SKIP_BIN_CHECK=1
    unset AFL_SRC || true
    export AFL_PATH="$AFLPP_BIN"
    export AFL_IGNORE_UNKNOWN_ENVS=1
    export LD_LIBRARY_PATH="$AFLPP_LLVM_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    in_dir=$1
    out_dir=$2
    shift 2
    filtered_in="${out_dir}.legion-filtered-inputs"
    rm -rf "$filtered_in"
    if [[ ! -x "$CMIN_TARGET" ]]; then
        echo "[LEGION]warning: cmin target $CMIN_TARGET is unavailable, keep original corpus"
        mkdir -p "$out_dir"
        copy_seed_dir "$in_dir" "$out_dir"
        export AFL_SKIP_BIN_CHECK=
        return 0
    fi
    echo "[LEGION]AFL++ cmin target: $CMIN_TARGET"
    filter_non_crashing_inputs "$in_dir" "$filtered_in"
    if ! has_regular_files "$filtered_in"; then
        echo "[LEGION]no non-crashing seeds available for AFL++ minimization, keep original corpus"
        mkdir -p "$out_dir"
        copy_seed_dir "$in_dir" "$out_dir"
        rm -rf "$filtered_in"
        export AFL_SKIP_BIN_CHECK=
        return 0
    fi
    if [[ -x "$AFLPP_BIN/afl-cmin" ]]; then
        time "$AFLPP_BIN/afl-cmin" "$@" -m none -i "$filtered_in" -o "$out_dir" -- "$CMIN_TARGET" @@
    else
        echo "[LEGION]warning: $AFLPP_BIN/afl-cmin is not executable, invoking via sh"
        time sh "$AFLPP_BIN/afl-cmin" "$@" -m none -i "$filtered_in" -o "$out_dir" -- "$CMIN_TARGET" @@
    fi
    rm -rf "$filtered_in"
    export AFL_SKIP_BIN_CHECK=
}

usage() {
    echo "[LEGION]USAGE: AFLPP.sh build -zip|-gz <file> or AFLPP.sh run|append <time> <threads> <output folder> [-d]"
}

if [[ "$#" -lt 1 ]]; then
    usage
    exit 1
fi

if [[ "$1" == "build" ]]; then
    echo "[LEGION]AFL++ build"
    build "${@:2}"
elif [[ "$1" == "run" ]]; then
    echo "[LEGION]AFL++ running"
    run "${@:2}"
elif [[ "$1" == "append" ]]; then
    echo "[LEGION]AFL++ appending workers"
    append "${@:2}"
elif [[ "$1" == "update" ]]; then
    echo "[LEGION]AFL++ updating seeds"
    update_seed "${@:2}"
elif [[ "$1" == "minimize" ]]; then
    echo "[LEGION]AFL++ minimizing seeds"
    minimize "${@:2}"
else
    usage
    exit 1
fi
