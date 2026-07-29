#!/bin/bash
set -euo pipefail

TOOLS_ROOT="${TOOLS_ROOT:-/FuzzingTools}"
if [[ ! -d "$TOOLS_ROOT" && -d /home/threedean/FuzzingTools ]]; then
    TOOLS_ROOT=/home/threedean/FuzzingTools
fi

export ANGORA_BIN="${ANGORA_BIN:-$TOOLS_ROOT/Angora}"
MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"

export_angora_rust_env() {
    export CARGO_HOME="${ANGORA_CARGO_HOME:-$ANGORA_BIN/.cargo}"
    export RUSTUP_HOME="${ANGORA_RUSTUP_HOME:-$ANGORA_BIN/.rustup}"
    export PATH="$CARGO_HOME/bin:$PATH"
}

normalize_angora_scripts() {
    find "$ANGORA_BIN" \
        -maxdepth 2 \
        -type f \
        \( -name 'angora_*' -o -name '*.sh' -o -name '*.py' \) \
        -exec perl -pi -e 's/\r$//' {} +
    find "$ANGORA_BIN" \
        -maxdepth 2 \
        -type f \
        \( -name 'angora_*' -o -name '*.sh' -o -name '*.py' \) \
        -exec chmod +x {} +
}

ensure_rust_toolchain() {
    export_angora_rust_env
    if command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1 &&
       cargo --version >/dev/null 2>&1 && rustc --version >/dev/null 2>&1; then
        return 0
    fi

    echo "[LEGION]bootstrapping isolated Rust toolchain for Angora"
    mkdir -p "$ANGORA_BIN/build"
    (
        cd "$ANGORA_BIN/build"
        local rustup_init=./rustup-init
        if [[ -f /FuzzingTools/preload/rustup-init ]]; then
            cp /FuzzingTools/preload/rustup-init "$rustup_init"
        elif [[ ! -f "$rustup_init" ]]; then
            curl -fL --retry 5 --retry-delay 3 --connect-timeout 20 --max-time 300 \
                -o "$rustup_init" \
                https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
        fi
        chmod +x "$rustup_init"
        export RUSTUP_PERMIT_COPY_RENAME=1
        "$rustup_init" -y --no-modify-path --default-toolchain stable --profile minimal
    )

    command -v cargo >/dev/null 2>&1 && command -v rustc >/dev/null 2>&1 &&
        cargo --version >/dev/null 2>&1 && rustc --version >/dev/null 2>&1
}

bootstrap_angora_rust_artifacts() {
    echo "[LEGION]bootstrapping Angora Rust runtime artifacts"
    ensure_rust_toolchain
    normalize_angora_scripts
    (
        cd "$ANGORA_BIN"
        cargo build --release
        mkdir -p bin/lib
        cp -f target/release/fuzzer bin/fuzzer
        cp -f target/release/libruntime.a target/release/libruntime_fast.a bin/lib/
    )
}

ensure_angora_compilers() {
    if [[ -x "$ANGORA_BIN/bin/angora-clang" && -x "$ANGORA_BIN/bin/angora-clang++" ]]; then
        return 0
    fi

    bootstrap_angora_llvm_mode

    [[ -x "$ANGORA_BIN/bin/angora-clang" && -x "$ANGORA_BIN/bin/angora-clang++" ]]
}

ensure_angora_runtime_libs() {
    if [[ -f "$ANGORA_BIN/bin/lib/libruntime_fast.a" && -f "$ANGORA_BIN/bin/lib/libruntime.a" ]]; then
        normalize_angora_scripts
        return 0
    fi

    bootstrap_angora_rust_artifacts

    [[ -f "$ANGORA_BIN/bin/lib/libruntime_fast.a" && -f "$ANGORA_BIN/bin/lib/libruntime.a" ]]
}

bootstrap_angora_llvm_mode() {
    echo "[LEGION]bootstrapping Angora llvm_mode toolchain"
    mkdir -p "$ANGORA_BIN/bin"
    mkdir -p "$ANGORA_BIN/llvm_mode/build"
    find "$ANGORA_BIN/llvm_mode/dfsan_rt" \
        -path '*/scripts/*' \
        -type f \( -name '*.py' -o -name '*.sh' \) \
        -exec perl -pi -e 's/\r$//' {} +
    find "$ANGORA_BIN/llvm_mode/dfsan_rt" \
        -path '*/scripts/*' \
        -type f \( -name '*.py' -o -name '*.sh' \) \
        -exec chmod +x {} +
    (
        cd "$ANGORA_BIN/llvm_mode/build"
        CC="${CC:-/clang+llvm/bin/clang}" \
        CXX="${CXX:-/clang+llvm/bin/clang++}" \
        cmake -DCMAKE_INSTALL_PREFIX="$ANGORA_BIN/bin" -DCMAKE_BUILD_TYPE=Release ..
        make -j"${JOBS:-$(nproc)}" install
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
            xargs -0 -r cp --target-directory="$dst"
    fi
}

clear_directory() {
    mkdir -p "$1"
    find "$1" -mindepth 1 -maxdepth 1 -print0 | xargs -0 -r rm -rf
}

copy_queue_files() {
    outfolder=$1
    shift
    for dir in "$@"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | \
                xargs -0 -r cp --target-directory="$outfolder"
        fi
    done
}

angora_queue_dirs() {
    local dirs=()
    if [[ -d run_angora/output/queue ]]; then
        dirs+=(run_angora/output/queue)
    fi
    for dir in run_angora/output/fuzzer*/queue; do
        if [[ -d "$dir" ]]; then
            dirs+=("$dir")
        fi
    done
    printf '%s\n' "${dirs[@]}"
}

unpack_variant() {
    mode_dir=$1
    archive_path=$2
    archive_name=$(basename "$archive_path")

    mkdir -p "$mode_dir"
    cp "$archive_path" "$mode_dir/$archive_name"
    pushd "$mode_dir" >/dev/null || exit
    if [[ "$compress_format" == "-zip" ]]; then
        unzip "$archive_name"
    elif [[ "$compress_format" == "-gz" ]]; then
        tar -xvf "$archive_name"
    else
        echo "[LEGION]unknown compress format"
        exit 1
    fi
    rm "$archive_name"
    popd >/dev/null || exit
}

detect_src_dir() {
    local mode_dir=$1
    find "$mode_dir" -mindepth 1 -maxdepth 1 -type d | sort | head -n 1 | xargs -r basename
}

build() {
    compress_format=$1
    archive_path=$2

    if ! ensure_angora_compilers; then
        echo "[LEGION]Angora compiler wrappers are unavailable under $ANGORA_BIN/bin" >&2
        exit 1
    fi
    if ! ensure_angora_runtime_libs; then
        echo "[LEGION]Angora runtime libraries are missing under $ANGORA_BIN/bin/lib" >&2
        echo "[LEGION]need at least libruntime_fast.a and libruntime.a; this environment still lacks the Rust-built runtime artifacts" >&2
        exit 1
    fi

    rm -rf code_angora_fast code_angora_taint
    mkdir -p build

    export CC="$ANGORA_BIN/bin/angora-clang"
    export CXX="$ANGORA_BIN/bin/angora-clang++"
    export LD="$ANGORA_BIN/bin/angora-clang"
    export EXTRALIBS=""

    unpack_variant code_angora_fast "$archive_path"
    SRC=$(detect_src_dir code_angora_fast)
    if [[ -z "$SRC" ]]; then
        echo "[LEGION]failed to locate extracted source directory" >&2
        exit 1
    fi
    pushd "code_angora_fast/$SRC" >/dev/null || exit
    unset USE_TRACK
    export USE_FAST=1
    ./fuzzbuild
    popd >/dev/null || exit
    cp -p "code_angora_fast/$SRC"/app build/angoraapp.fast
    cp -p "code_angora_fast/$SRC"/app build/angoraapp

    unpack_variant code_angora_taint "$archive_path"
    pushd "code_angora_taint/$SRC" >/dev/null || exit
    unset USE_FAST
    export USE_TRACK=1
    ./fuzzbuild
    popd >/dev/null || exit
    cp -p "code_angora_taint/$SRC"/app build/angoraapp.taint
}

run() {
    time=$1
    threads=$2
    outfolder=$3
    sync_interval="${LEGION_MONITOR_SYNC_INTERVAL:-60}"
    terminate_requested=0

    flush_output() {
        clear_directory "$outfolder"
        mapfile -t queue_dirs < <(angora_queue_dirs)
        copy_queue_files "$outfolder" "${queue_dirs[@]}"
    }

    handle_term() {
        terminate_requested=1
        echo "[LEGION]Angora received termination request, flushing current queue snapshot"
    }

    trap handle_term TERM INT
    rm -rf run_angora
    mkdir -p run_angora/input
    copy_seed_dir initial run_angora/input
    if ! has_regular_files run_angora/input; then
        echo "[LEGION]no initial seeds available for Angora, skip this round"
        rm -rf "$outfolder"
        mkdir -p "$outfolder"
        return 0
    fi

    pushd run_angora >/dev/null || exit

    dict=""
    if [[ "${4:-}" == "-d" ]]; then
        dict="-x ../dict.dict"
    fi

    echo "[LEGION]$dict"

    timeout "$time" "$ANGORA_BIN/angora_fuzzer" \
        -i input \
        -o output \
        $dict \
        -t ../build/angoraapp.taint \
        -- ../build/angoraapp.fast @@ &

    i=1
    while [[ "$i" -lt "$threads" ]]; do
        timeout "$time" "$ANGORA_BIN/angora_fuzzer" \
            -i input \
            -o output \
            $dict \
            -t ../build/angoraapp.taint \
            -- ../build/angoraapp.fast @@ &
        i=$((i + 1))
    done

    popd >/dev/null || exit

    i=0
    counter=0

    rm -rf "$outfolder"
    mkdir -p "$outfolder"
    while [[ "$i" -lt "$time" ]]; do
        if [[ "$terminate_requested" -ne 0 ]]; then
            break
        fi
        echo "[LEGION-fuzzer]running Angora background, $i/$time seconds passed"
        sleep 60
        i=$((i + 60))
        counter=$((counter + 60))
        if [[ "$counter" -ge "$sync_interval" ]]; then
            echo "[LEGION]copying files periodically to speed up the process"
            flush_output
            counter=0
        fi
    done

    echo "[LEGION]$threads instances of Angora run finished in $time seconds"

    sleep 2
    flush_output
}

append() {
    local time=$1
    local threads=$2
    local outfolder=$3
    local dict=""
    local terminate_requested=0
    local pids=()
    local i=0

    if [[ ! -d run_angora/output ]]; then
        echo "[LEGION]Angora append requested without an active run directory, fallback to fresh run"
        run "$@"
        return 0
    fi

    if [[ "${4:-}" == "-d" ]]; then
        dict="-x ../dict.dict"
    fi

    handle_term() {
        terminate_requested=1
        echo "[LEGION]Angora append workers received termination request"
    }

    trap handle_term TERM INT
    pushd run_angora >/dev/null || exit
    copy_seed_dir ../initial input

    while [[ "$i" -lt "$threads" ]]; do
        timeout "$time" "$ANGORA_BIN/angora_fuzzer" \
            -i input \
            -o output \
            $dict \
            -t ../build/angoraapp.taint \
            -- ../build/angoraapp.fast @@ &
        pids+=("$!")
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
    echo "[LEGION]Angora append finished after adding $threads worker processes"
}

update_seed() {
    source=$1
    mapfile -t queue_dirs < <(angora_queue_dirs)
    for dir in "${queue_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$source" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | \
                xargs -0 -r cp --target-directory="$dir"
        fi
    done
}

minimize() {
    if [[ ! -x "$ANGORA_BIN/angora_cmin" ]]; then
        echo "[LEGION]Angora minimizer is unavailable at $ANGORA_BIN/angora_cmin" >&2
        return 1
    fi
    export ANGORA_SKIP_BIN_CHECK=1
    in_dir=$1
    out_dir=$2
    time "$ANGORA_BIN/angora_cmin" -i "$in_dir" -o "$out_dir" -- ./build/angoraapp.fast @@
    export ANGORA_SKIP_BIN_CHECK=
}

usage() {
    echo "[LEGION]USAGE: Angora.sh build -zip|-gz <file> or Angora.sh run|append <time> <threads> <output folder> [-d]"
}

if [[ "$#" -lt 1 ]]; then
    usage
    exit 1
fi

if [[ "$1" == "build" ]]; then
    echo "[LEGION]Angora build"
    build "${@:2}"
elif [[ "$1" == "run" ]]; then
    echo "[LEGION]Angora running"
    run "${@:2}"
elif [[ "$1" == "append" ]]; then
    echo "[LEGION]Angora appending workers"
    append "${@:2}"
elif [[ "$1" == "update" ]]; then
    echo "[LEGION]Angora updating seeds"
    update_seed "${@:2}"
elif [[ "$1" == "minimize" ]]; then
    echo "[LEGION]Angora minimizing seeds"
    minimize "${@:2}"
else
    usage
    exit 1
fi
