#!/bin/bash

TOOLS_ROOT="${TOOLS_ROOT:-/FuzzingTools}"
if [[ ! -d "$TOOLS_ROOT" && -d /home/threedean/FuzzingTools ]]; then
    TOOLS_ROOT=/home/threedean/FuzzingTools
fi

export AFL_BIN="${AFL_BIN:-$TOOLS_ROOT/AFL}"
export AFLPP_BIN="${AFLPP_BIN:-$TOOLS_ROOT/AFLplusplus}"
export QSYM_BIN="${QSYM_BIN:-$TOOLS_ROOT/QSYM}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEGION_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"
LEGION_AFL_TIMEOUT="${LEGION_AFL_TIMEOUT:-1000+}"

for candidate in \
    "$QSYM_BIN" \
    "$TOOLS_ROOT/QSYM-real" \
    "$LEGION_ROOT/.cache/qsym-sslab-gatech" \
    "/data/yukaizhao/Legion/.cache/qsym-sslab-gatech"; do
    if [[ -f "$candidate/setup.py" && -f "$candidate/bin/run_qsym_afl.py" ]]; then
        export QSYM_BIN="$candidate"
        break
    fi
done

has_regular_files() {
    find "$1" -maxdepth 1 -type f -print -quit | grep -q .
}

copy_seed_dir() {
    src=$1
    dst=$2
    mkdir -p "$dst"
    [[ -d "$src" ]] || return 0
    find "$src" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | \
        xargs -0 -r cp -n --target-directory="$dst" 2>/dev/null || true
}

copy_queues() {
    outfolder=$1
    shift
    for dir in "$@"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | xargs -0 -r cp --target-directory="$outfolder"
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

clear_directory() {
    mkdir -p "$1"
    find "$1" -mindepth 1 -maxdepth 1 -print0 | xargs -0 -r rm -rf
}

terminate_pids() {
    local -a pids=("$@")
    local pid

    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 2

    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}

cleanup_run_dir() {
    local dir=$1
    local attempts=0

    while [[ -e "$dir" && "$attempts" -lt 5 ]]; do
        rm -rf "$dir" 2>/dev/null || true
        if [[ ! -e "$dir" ]]; then
            break
        fi
        sleep 2
        attempts=$((attempts + 1))
    done
}

wait_for_file() {
    target=$1
    timeout_seconds=$2
    waited=0
    while [[ ! -f "$target" && "$waited" -lt "$timeout_seconds" ]]; do
        sleep 2
        waited=$((waited + 2))
    done
    [[ -f "$target" ]]
}

build() {

    ARCHIVE=$(basename "$2")
    SRC=${ARCHIVE%%.*}

    rm -rf code_qsym/"$SRC"
    mkdir -p code_qsym
    cp "$2" code_qsym/"$ARCHIVE"
    pushd code_qsym || exit

    if [[ "$1" == "-zip" ]]; then
        unzip "$ARCHIVE"
    elif [[ "$1" == "-gz" ]]; then
        tar -xvf "$ARCHIVE"
    else
        echo "[LEGION]unknown compress format"
        exit 1
    fi

    rm "$ARCHIVE"

    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    export CC="gcc"
    export CXX="g++"

    export CFLAGS="-O2 -fno-omit-frame-pointer"
    export CXXFLAGS="-O2 -fno-omit-frame-pointer -std=c++11"

    export EXTRALIBS=""

    pushd "$SRC" || exit
    ./fuzzbuild
    popd || exit
    popd || exit
    cp -p code_qsym/"$SRC"/app build/qsymapp

}

run(){
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    export QSYM_PIN_INJECTION="${QSYM_PIN_INJECTION:-child}"
    time=$1
    threads=$2
    outfolder=$3
    sync_interval="${LEGION_MONITOR_SYNC_INTERVAL:-60}"
    terminate_requested=0
    pids=()

    flush_output() {
        clear_directory "$outfolder"
        copy_queues "$outfolder" run_qsym/output/afl-master/queue run_qsym/output/afl-slave*/queue run_qsym/output/qsym*/queue
    }

    handle_term() {
        terminate_requested=1
        echo "[LEGION]QSYM received termination request, flushing current queue snapshot"
    }

    trap handle_term TERM INT
    cleanup_run_dir run_qsym
    mkdir run_qsym
    mkdir run_qsym/input
    mkdir run_qsym/output
    # get initial seeds, if any, to in
    copy_seed_dir "${LEGION_INITIAL_DIR:-initial}" run_qsym/input
    if ! has_regular_files run_qsym/input; then
        echo "[LEGION]no initial seeds available for QSYM, skip this round"
        rm -rf "$outfolder"
        mkdir -p "$outfolder"
        return 0
    fi
    pushd run_qsym || exit

    afl_runner="$AFL_BIN/afl-fuzz"
    afl_target="../build/aflapp"
    if [[ ! -x "$afl_runner" && -x "$AFLPP_BIN/afl-fuzz" ]]; then
        afl_runner="$AFLPP_BIN/afl-fuzz"
    fi
    if [[ ! -x "$afl_target" && -x ../build/aflppapp ]]; then
        echo "[LEGION]build/aflapp missing, fallback to AFL++ master with build/aflppapp"
        afl_target="../build/aflppapp"
    fi
    if [[ ! -x "$afl_target" ]]; then
        echo "[LEGION]build/aflapp or build/aflppapp is required for QSYM hybrid fuzzing"
        exit 1
    fi

    if [[ ! -x ../build/qsymapp ]]; then
        echo "[LEGION]build/qsymapp is required for QSYM hybrid fuzzing"
        exit 1
    fi

    if [[ ! -f "$QSYM_BIN/setup.py" ]]; then
        echo "[LEGION]real QSYM source tree not found at $QSYM_BIN"
        exit 1
    fi

    if [ "$4" == "-d" ]; then
        dict="-x ../dict.dict"
    fi

    echo "[LEGION]$dict"

    # AutoFZ QSYM model: one AFL master plus one QSYM symbolic executor.
    # Additional resource units are AFL slaves only; QSYM itself is not duplicated.
    timeout --foreground "$time" "$afl_runner" -m none -t "$LEGION_AFL_TIMEOUT" -i input -o output -M afl-master $dict -- "$afl_target" &
    pids+=("$!")
    stats_file="output/afl-master/fuzzer_stats"
    wait_budget=$time
    if [ "$wait_budget" -gt 30 ]; then
        wait_budget=30
    fi
    if wait_for_file "$stats_file" "$wait_budget"; then
        timeout --foreground "$time" env PYTHONPATH="$QSYM_BIN:${PYTHONPATH:-}" \
            python2 "$QSYM_BIN/bin/run_qsym_afl.py" \
            -a afl-master -o output -n qsym -b "$afl_target" -- ../build/qsymapp @@ &
        pids+=("$!")
    else
        echo "[LEGION]warning: afl-master did not create fuzzer_stats in time, skip QSYM symbolic executor"
    fi

    i=0
    extra_slaves=0
    if [ "$threads" -gt 2 ]; then
        extra_slaves=$((threads - 2))
    fi
    while [ "$i" -lt "$extra_slaves" ]; do
        slave="afl-slave$((i + 1))"
        timeout --foreground "$time" "$afl_runner" -m none -t "$LEGION_AFL_TIMEOUT" -i input -o output -S "$slave" $dict -- "$afl_target" &
        pids+=("$!")
        i=$((i + 1))
    done

    popd || exit

    echo "[LEGION]sleep $time seconds before fuzzing round finish"

    i=0
    counter=0

    rm -rf "$outfolder"
    mkdir -p "$outfolder"
    while [ "$i" -lt "$time" ] 
        do
        if [ "$terminate_requested" -ne 0 ]; then
            break
        fi
        echo "[LEGION-fuzzer]running QSYM background, $i/$time seconds passed"
        sleep 60
        i=$((i + 60))
        counter=$((counter + 60))
        if [ "$counter" -ge "$sync_interval" ]; then
            echo "[LEGION]copying files periodically to speed up the process"
            flush_output
            counter=0
        fi
    done

    echo "[LEGION]AutoFZ-style QSYM run finished in $time seconds with $threads logical resource units"

    terminate_pids "${pids[@]}"

    sleep 2
    flush_output
}

next_qsym_slave_index() {
    local output_dir=$1
    local next=0
    local dir base suffix
    for dir in "$output_dir"/afl-slave*; do
        [[ -d "$dir" ]] || continue
        base=$(basename "$dir")
        suffix=${base#afl-slave}
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
    local terminate_requested=0
    local pids=()
    local i=0
    local next_index=0

    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    export QSYM_PIN_INJECTION="${QSYM_PIN_INJECTION:-child}"

    local waited=0
    local wait_limit="${LEGION_APPEND_WAIT_SECONDS:-30}"
    while [[ ! -d run_qsym/output && "$waited" -lt "$wait_limit" ]]; do
        sleep 1
        waited=$((waited + 1))
    done

    if [[ ! -d run_qsym/output ]]; then
        echo "[LEGION]QSYM append requested without an active run directory, fallback to fresh run"
        run "$@"
        return 0
    fi

    handle_term() {
        terminate_requested=1
        echo "[LEGION]QSYM append workers received termination request"
    }

    trap handle_term TERM INT
    pushd run_qsym >/dev/null || exit
    copy_seed_dir "${LEGION_INITIAL_DIR:-../initial}" input

    afl_runner="$AFL_BIN/afl-fuzz"
    afl_target="../build/aflapp"
    if [[ ! -x "$afl_runner" && -x "$AFLPP_BIN/afl-fuzz" ]]; then
        afl_runner="$AFLPP_BIN/afl-fuzz"
    fi
    if [[ ! -x "$afl_target" && -x ../build/aflppapp ]]; then
        afl_target="../build/aflppapp"
    fi

    if [[ "${4:-}" == "-d" ]]; then
        dict="-x ../dict.dict"
    fi

    next_index=$(next_qsym_slave_index output)
    if [[ -n "${LEGION_APPEND_WORKER_INDEX:-}" ]]; then
        next_index="$LEGION_APPEND_WORKER_INDEX"
    fi
    while [[ "$i" -lt "$threads" ]]; do
        slave="afl-slave$next_index"
        timeout --foreground "$time" "$afl_runner" -m none -t "$LEGION_AFL_TIMEOUT" -i input -o output -S "$slave" $dict -- "$afl_target" &
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

    terminate_pids "${pids[@]}"
    popd >/dev/null || exit
    echo "[LEGION]QSYM append finished after adding $threads AFL slave workers"
}

update_seed() {
    source=$1
    sync_seed_dir_into_afl_peer_queue "$source" run_qsym/output
}

minimize() {
    in_dir=$1
    out_dir=$2
    AFL.sh minimize "$in_dir" "$out_dir"
}

usage(){
    echo "[LEGION]USAGE: QSYM.sh build -zip|-gz <file> or QSYM.sh run|append <time> <threads> <output folder> [-d]"
}

if [[ "$#" -lt 1 ]]; then
    usage
    exit 1
fi

if [[ "$1" == "build" ]]; then
    echo "[LEGION]QSYM build"
    build "${@:2}"
elif [[ "$1" == "run" ]]; then
    echo "[LEGION]QSYM running"
    run "${@:2}"
elif [[ "$1" == "append" ]]; then
    echo "[LEGION]QSYM appending workers"
    append "${@:2}"
elif [[ "$1" == "update" ]]; then
    echo "[LEGION]QSYM updating seeds"
    update_seed "${@:2}"
elif [[ "$1" == "minimize" ]]; then
    echo "[LEGION]QSYM minimizing seeds"
    minimize "${@:2}"
else
    usage
    exit 1
fi
