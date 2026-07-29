#!/bin/bash
set -euo pipefail

TOOLS_ROOT="${TOOLS_ROOT:-/FuzzingTools}"
if [[ ! -d "$TOOLS_ROOT" && -d /home/threedean/FuzzingTools ]]; then
    TOOLS_ROOT=/home/threedean/FuzzingTools
fi

export HONGG_BIN="${HONGG_BIN:-$TOOLS_ROOT/honggfuzz}"
MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"

prepare_hongg_wrappers() {
    local wrapper_dir="$PWD/.hongg-wrapper-bin"
    mkdir -p "$wrapper_dir"
    ln -sf "$HONGG_BIN/hfuzz_cc/hfuzz-cc" "$wrapper_dir/hfuzz-clang"
    ln -sf "$HONGG_BIN/hfuzz_cc/hfuzz-cc" "$wrapper_dir/hfuzz-clang++"
    printf '%s\n' "$wrapper_dir"
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
            xargs -0 -r cp --target-directory="$dst"
    fi
}

clear_directory() {
    mkdir -p "$1"
    find "$1" -mindepth 1 -maxdepth 1 -print0 | xargs -0 -r rm -rf
}

copy_output_files() {
    src=$1
    dst=$2
    if [[ -d "$src" ]]; then
        find "$src" -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | \
            xargs -0 -r cp --target-directory="$dst"
    fi
}

build() {
    ARCHIVE=$(basename "$2")

    rm -rf code_hongg
    mkdir -p build code_hongg
    cp "$2" code_hongg/"$ARCHIVE"
    pushd code_hongg >/dev/null || exit

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

    wrapper_dir=$(prepare_hongg_wrappers)
    export PATH="$wrapper_dir:$PATH"
    export CC="hfuzz-clang"
    export CXX="hfuzz-clang++"
    export LD="hfuzz-clang"

    export FSANITIZE_FUZZER_FLAGS="-fno-omit-frame-pointer -g -fsanitize=address,undefined"
    export CFLAGS="$FSANITIZE_FUZZER_FLAGS"
    export CXXFLAGS="$FSANITIZE_FUZZER_FLAGS"
    export EXTRALIBS=""

    pushd "$SRC" >/dev/null || exit
    ./fuzzbuild
    popd >/dev/null || exit
    popd >/dev/null || exit

    cp -p code_hongg/"$SRC"/app build/honggapp
}

run() {
    time=$1
    threads=$2
    outfolder=$3
    sync_interval="${LEGION_MONITOR_SYNC_INTERVAL:-60}"
    terminate_requested=0

    flush_output() {
        clear_directory "$outfolder"
        copy_output_files run_hongg/output "$outfolder"
    }

    handle_term() {
        terminate_requested=1
        echo "[LEGION]HonggFuzz received termination request, flushing current corpus snapshot"
    }

    trap handle_term TERM INT
    rm -rf run_hongg
    mkdir -p run_hongg/input run_hongg/output
    copy_seed_dir initial run_hongg/input
    if ! has_regular_files run_hongg/input; then
        echo "[LEGION]no initial seeds available for HonggFuzz, skip this round"
        rm -rf "$outfolder"
        mkdir -p "$outfolder"
        return 0
    fi

    pushd run_hongg >/dev/null || exit

    dict=""
    if [[ "${4:-}" == "-d" ]]; then
        dict="-w ../dict.dict"
        echo "[LEGION]we use a dictionary from $dict!"
    fi

    timeout "$time" "$HONGG_BIN/honggfuzz" \
        --threads "$threads" \
        -i input \
        --output output \
        $dict \
        -- ../build/honggapp ___FILE___ &
    child_pid=$!

    popd >/dev/null || exit

    i=0
    counter=0

    rm -rf "$outfolder"
    mkdir -p "$outfolder"
    while [[ "$i" -lt "$time" ]]; do
        if [[ "$terminate_requested" -ne 0 ]]; then
            break
        fi
        echo "[LEGION-fuzzer]running HonggFuzz background, $i/$time seconds passed"
        sleep 60
        i=$((i + 60))
        counter=$((counter + 60))
        if [[ "$counter" -ge "$sync_interval" ]]; then
            echo "[LEGION]copying files periodically to speed up the process"
            flush_output
            counter=0
        fi
    done

    echo "[LEGION]HonggFuzz run finished in $time seconds with $threads threads"

    wait "$child_pid" 2>/dev/null || true
    sleep 2
    flush_output
}

update_seeds() {
    sourcedir=$1
    if [[ -d run_hongg/output ]]; then
        find "$sourcedir" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | \
            xargs -0 -r cp --target-directory=run_hongg/output
    fi
}

usage() {
    echo "[LEGION]USAGE: HONGG.sh build -zip|-gz <file> or HONGG.sh run <time> <threads> <output folder> [-d]"
}

if [[ "$#" -lt 1 ]]; then
    usage
    exit 1
fi

if [[ "$1" == "build" ]]; then
    echo "[LEGION]HONGGFUZZ build"
    build "${@:2}"
elif [[ "$1" == "run" ]]; then
    echo "[LEGION]HONGGFUZZ running"
    run "${@:2}"
elif [[ "$1" == "update" ]]; then
    echo "[LEGION]HONGGFUZZ updating seeds"
    update_seeds "${@:2}"
else
    usage
    exit 1
fi
