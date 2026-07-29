#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/afl_driver_build.sh"

TOOLS_ROOT="${TOOLS_ROOT:-/FuzzingTools}"
if [[ ! -d "$TOOLS_ROOT" && -d /home/threedean/FuzzingTools ]]; then
    TOOLS_ROOT=/home/threedean/FuzzingTools
fi

export FAIRFUZZ_BIN="${FAIRFUZZ_BIN:-$TOOLS_ROOT/FairFuzz}"
MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"
LEGION_AFL_FUZZ_BUILD="${LEGION_AFL_FUZZ_BUILD:-asan}"
LEGION_AFL_TIMEOUT="${LEGION_AFL_TIMEOUT:-1000+}"

use_noasan_fuzz_build() {
    if [[ "${LEGION_AFL_NO_ASAN:-0}" == "1" || "${LEGION_AFL_FAST_BUILD:-0}" == "1" ]]; then
        return 0
    fi

    case "$LEGION_AFL_FUZZ_BUILD" in
        noasan|no-asan|NOASAN|NO-ASAN|fast|FAST|autofz|AUTOFZ|none|NONE)
            return 0
            ;;
    esac

    return 1
}

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

clear_directory() {
    mkdir -p "$1"
    find "$1" -mindepth 1 -maxdepth 1 -print0 | xargs -0 -r rm -rf
}

terminate_pids() {
    local -a pids=("$@")
    local pid

    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    sleep 2

    for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
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
        [[ ! -e "$dir" ]] && return 0
        sleep 1
        attempts=$((attempts + 1))
    done

    if [[ -e "$dir" ]]; then
        echo "[LEGION]warning: failed to fully remove $dir before FairFuzz run"
        return 1
    fi
    return 0
}

copy_queue_files() {
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

build() {

    ARCHIVE=$(basename "$2")
    SRC=${ARCHIVE%%.*}

    rm -rf code_fairfuzz/"$SRC"
    mkdir code_fairfuzz
    cp "$2" code_fairfuzz/"$ARCHIVE"
    pushd code_fairfuzz || exit

    if [[ "$1" == "-zip" ]]; then
        unzip "$ARCHIVE"
    elif [[ "$1" == "-gz" ]]; then
        tar -xvf "$ARCHIVE"
    else
        echo "[LEGION]unknown compress format"
        exit 1
    fi

    rm "$ARCHIVE"

    configure_fts_afl_compiler

    unset AFL_LLVM_LAF_ALL AFL_USE_UBSAN AFL_USE_ASAN AFL_USE_MSAN

    if use_noasan_fuzz_build; then
        echo "[LEGION]building FairFuzz fuzzing target with AutoFZ justafl flags"
        export FSANITIZE_FUZZER_FLAGS="-O2 -fno-omit-frame-pointer -Wno-unused-command-line-argument -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
    else
        echo "[LEGION]building FairFuzz fuzzing target with AutoFZ aflasan flags"
        export FSANITIZE_FUZZER_FLAGS="-O2 -fno-omit-frame-pointer -Wno-unused-command-line-argument -fsanitize=address -fsanitize-address-use-after-scope -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
    fi

    export CFLAGS="$FSANITIZE_FUZZER_FLAGS"
    export CXXFLAGS="$FSANITIZE_FUZZER_FLAGS -std=c++11"
    export CPPFLAGS="${CPPFLAGS:-"-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"}"

	pushd "$SRC" || exit
    build_fts_afl_driver_engine libFuzzingEngine-afl.a
	./fuzzbuild
	popd || exit
	popd || exit
	cp -p code_fairfuzz/"$SRC"/app build/fairfuzzapp
    if use_noasan_fuzz_build; then
        cp -p build/fairfuzzapp build/fairfuzzapp_noasan
    else
        cp -p build/fairfuzzapp build/fairfuzzapp_asan
    fi

}

run(){
    #sudo $FAIRFUZZ_BIN/afl-system-config
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1
    time=$1
    threads=$2
    outfolder=$3
    sync_interval="${LEGION_MONITOR_SYNC_INTERVAL:-60}"
    terminate_requested=0
    pids=()

    flush_output() {
        clear_directory "$outfolder"
        copy_queue_files "$outfolder" run_fairfuzz/output/fuzzer*/queue
    }

    handle_term() {
        terminate_requested=1
        echo "[LEGION]FairFuzz received termination request, flushing current queue snapshot"
    }

    trap handle_term TERM INT
    cleanup_run_dir run_fairfuzz || return 1
    mkdir -p run_fairfuzz/input run_fairfuzz/output
    #get initial seeds, if any, to in
    copy_seed_dir "${LEGION_INITIAL_DIR:-initial}" run_fairfuzz/input
    if ! has_regular_files run_fairfuzz/input; then
        echo "[LEGION]no initial seeds available for FairFuzz, skip this round"
        rm -rf "$outfolder"
        mkdir -p "$outfolder"
        return 0
    fi
    pushd run_fairfuzz || exit

    #echo $1
    #echo $2

    if [ "$4" == "-d" ]; then
        dict="-x ../dict.dict"
    fi

    echo "[LEGION]$dict"

    # start the main fuzzing thread
    # screen -dmS fairfuzz-main timeout --foreground "$time" $FAIRFUZZ_BIN/afl-fuzz -i input -o output -M fuzzer0 $dict -- ../build/fairfuzzapp
    timeout --foreground "$time" $FAIRFUZZ_BIN/afl-fuzz -m none -t "$LEGION_AFL_TIMEOUT" -i input -o output -M fuzzer0 $dict -- ../build/fairfuzzapp &
    pids+=("$!")

    # start other ones
    #nohup bash -c '\
    i=1
    while [ "$i" -lt "$threads" ]
           do 
        #screen -dmS fairfuzz-"$i" timeout --foreground "$time" $FAIRFUZZ_BIN/afl-fuzz -i input -o output -S fuzzer$i $dict -- ../build/fairfuzzapp
        timeout --foreground "$time" $FAIRFUZZ_BIN/afl-fuzz -m none -t "$LEGION_AFL_TIMEOUT" -i input -o output -S fuzzer$i $dict -- ../build/fairfuzzapp &
        pids+=("$!")
    i=$((i + 1))
    done

    # channel output of a sceen to current terminal without blocking it

    popd || exit

    echo "[LEGION]sleep $time seconds before fuzzing round finish"

    #sleep "$time"
    i=0
    counter=0

    rm -rf "$outfolder"
    mkdir -p "$outfolder"
    while [ "$i" -lt "$time" ] 
        do
        if [ "$terminate_requested" -ne 0 ]; then
            break
        fi
        echo "[LEGION-fuzzer]running FairFuzz background, $i/$time seconds passed"
        sleep 60
        i=$((i + 60))
        counter=$((counter + 60))
        if [ "$counter" -ge "$sync_interval" ]; then
            echo "[LEGION]copying files preodically to speed up the process"
            flush_output
            counter=0
        fi
    done

    echo "[LEGION]$threads instances of FairFuzz run finished in $time seconds"

    #find run_fairfuzz/output/fuzzer0/queue -type f -name '*' -print0 | xargs -0 cp --target-directory="$outfolder"
        

    terminate_pids "${pids[@]}"
    sleep 2
    flush_output
}

next_fairfuzz_worker_index() {
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

    local waited=0
    local wait_limit="${LEGION_APPEND_WAIT_SECONDS:-30}"
    while [[ ! -d run_fairfuzz/output && "$waited" -lt "$wait_limit" ]]; do
        sleep 1
        waited=$((waited + 1))
    done

    if [[ ! -d run_fairfuzz/output ]]; then
        echo "[LEGION]FairFuzz append requested without an active run directory, fallback to fresh run"
        run "$@"
        return 0
    fi

    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_SKIP_CPUFREQ=1

    if [[ "${4:-}" == "-d" ]]; then
        dict="-x ../dict.dict"
    fi

    handle_term() {
        terminate_requested=1
        echo "[LEGION]FairFuzz append workers received termination request"
    }

    trap handle_term TERM INT
    pushd run_fairfuzz >/dev/null || exit
    copy_seed_dir "${LEGION_INITIAL_DIR:-../initial}" input
    if [[ -n "${LEGION_APPEND_WORKER_INDEX:-}" ]]; then
        next_index="$LEGION_APPEND_WORKER_INDEX"
    else
        next_index=$(next_fairfuzz_worker_index output)
    fi

    while [[ "$i" -lt "$threads" ]]; do
        timeout --foreground "$time" "$FAIRFUZZ_BIN/afl-fuzz" -m none -t "$LEGION_AFL_TIMEOUT" -i input -o output -S "fuzzer$next_index" $dict -- ../build/fairfuzzapp &
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

    if [[ "$terminate_requested" -ne 0 ]]; then
        terminate_pids "${pids[@]}"
    else
        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    fi
    popd >/dev/null || exit
    echo "[LEGION]FairFuzz append finished after adding $threads slave workers"
}

update_seed() {
    source=$1
    sync_seed_dir_into_afl_peer_queue "$source" run_fairfuzz/output
}

# we use FairFuzz for potential seed minimization
minimize() {
    # this is used since the minimization seem to crash or timeout when evaluating real tools
    export AFL_SKIP_BIN_CHECK=1
    in_dir=$1
    out_dir=$2
    #command="$FAIRFUZZ_BIN/afl-cmin -i $in_dir -o $out_dir -- ./build/fairfuzzapp"
    #echo $command
    time $FAIRFUZZ_BIN/afl-cmin -i "$in_dir" -o "$out_dir" -- ./build/fairfuzzapp
    export AFL_SKIP_BIN_CHECK=
}


usage(){
    #prog="$(basename "$0")"
    #log-error "$prog No options given, don't know what to do\n"
    echo "[LEGION]USAGE: FairFuzz.sh build -zip|-gz <file> or FairFuzz.sh run|append <time> <threads> <output folder> [-d]"
}

if [[ "$#" -lt 1 ]]; then
    usage
    exit 1
fi

if [[ "$1" == "build" ]]; then
    echo "[LEGION]FairFuzz build"
    build "${@:2}"
elif [[ "$1" == "run" ]]; then
    echo "[LEGION]FairFuzz running"
    run "${@:2}"
elif [[ "$1" == "append" ]]; then
    echo "[LEGION]FairFuzz appending workers"
    append "${@:2}"
elif [[ "$1" == "update" ]]; then
    echo "[LEGION]FairFuzz updating seeds"
    update_seed "${@:2}"
elif [[ "$1" == "minimize" ]]; then
    echo "[LEGION]FairFuzz minimizing seeds"
    minimize "${@:2}"
else
    usage
    exit 1
fi
