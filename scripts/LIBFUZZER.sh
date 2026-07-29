#!/bin/bash
set -euo pipefail

MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"

DEFAULT_LIBFUZZER_CC="clang"
DEFAULT_LIBFUZZER_CXX="clang++"
if command -v clang-12 >/dev/null 2>&1 && command -v clang++-12 >/dev/null 2>&1; then
	DEFAULT_LIBFUZZER_CC="clang-12"
	DEFAULT_LIBFUZZER_CXX="clang++-12"
elif command -v clang-8 >/dev/null 2>&1 && command -v clang++-8 >/dev/null 2>&1; then
	DEFAULT_LIBFUZZER_CC="clang-8"
	DEFAULT_LIBFUZZER_CXX="clang++-8"
fi

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

copy_output_files() {
	src=$1
	dst=$2
	find "$src" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | xargs -0 -r cp --target-directory="$dst"
}

sync_seed_dir_into_libfuzzer_sync_queue() {
	local source=$1
	local sync_root=run_lib/output/autofz
	local queue_dir="$sync_root/queue"
	local seen_file=run_lib/output/.legion_autofz_seen_sha1
	local next_file=run_lib/output/.legion_autofz_next_id
	local next_id=0
	local file checksum dst

	[[ -d "$source" ]] || return 0
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

	rm -rf code_lib/$SRC
	mkdir code_lib
	cp "$2" code_lib/"$ARCHIVE"
	pushd code_lib || exit

	if [[ "$1" == "-zip" ]]; then
		unzip "$ARCHIVE"
	elif [[ "$1" == "-gz" ]]; then
		tar -xvf "$ARCHIVE"
	else
		echo "[LEGION]unknown compress format"
		exit 1
	fi

	rm "$ARCHIVE"

	export CC="${LEGION_LIBFUZZER_CC:-$DEFAULT_LIBFUZZER_CC}"
	export CXX="${LEGION_LIBFUZZER_CXX:-$DEFAULT_LIBFUZZER_CXX}"
	export LD="${LEGION_LIBFUZZER_LD:-$CC}"

	# Build libraries with AutoFZ's libFuzzer sanitizer flags. We keep
	# Legion's compiler selection, and add the libFuzzer main only in the
	# final app link step.
	export FSANITIZE_FUZZER_FLAGS="-O2 -fno-omit-frame-pointer -gline-tables-only -fsanitize=address,fuzzer-no-link -fsanitize-address-use-after-scope"
	export CFLAGS=$FSANITIZE_FUZZER_FLAGS
	export CXXFLAGS=$FSANITIZE_FUZZER_FLAGS

	export EXTRALIBS="-fsanitize=fuzzer"

	pushd $SRC || exit
	./fuzzbuild
	popd || exit
	popd || exit
	cp -p code_lib/"$SRC"/app build/libapp
}

run() {
	time=$1
	threads=$2
	outfolder=$3
	dict=""
	sync_interval="${LEGION_MONITOR_SYNC_INTERVAL:-60}"
	terminate_requested=0

	flush_output() {
		clear_directory "$outfolder"
		copy_output_files run_lib/output/queue "$outfolder"
	}

	handle_term() {
		terminate_requested=1
		echo "[LEGION]LibFuzzer received termination request, flushing current corpus snapshot"
	}

	trap handle_term TERM INT
	rm -rf run_lib
	mkdir -p run_lib/input run_lib/output/queue run_lib/output/crashes run_lib/output/autofz/queue
	#get initial seeds, if any, to input
	copy_seed_dir "${LEGION_INITIAL_DIR:-initial}" run_lib/input
	if ! has_regular_files run_lib/input; then
		echo "[LEGION]no initial seeds available for LibFuzzer, skip this round"
		rm -rf "$outfolder"
		mkdir -p "$outfolder"
		return 0
	fi
	pushd run_lib || exit

	if [ "${4:-}" == "-d" ]; then
		dict="-dict=../dict.dict"
		echo "[LEGION]we use a dictionary from $dict!"
	fi

	
	#let's fxxking fuzz!
	timeout --foreground "$time" ../build/libapp -fork="$threads" -ignore_crashes=1 -artifact_prefix=./output/crashes/ $dict ./output/queue/ ./input/ ./output/autofz/ &
	child_pid=$!


	popd || exit

	i=0
	counter=0

	rm -rf "$outfolder"
	mkdir -p "$outfolder"
	while [ "$i" -lt "$time" ] 
		do
		if [ "$terminate_requested" -ne 0 ]; then
			break
		fi
		echo "[LEGION-fuzzer]running LibFuzzer background, $i/$time seconds passed"
		sleep 60
		i=$((i + 60))
		counter=$((counter + 60))
		if [ "$counter" -ge "$sync_interval" ]; then
			echo "[LEGION]copying files preodically to speed up the process"
			flush_output
			counter=0
		fi
	done


	echo "[LEGION]libfuzzer run finished in $time seconds with $threads threads"

	#cp -r run_lib/output/* "$outfolder"
	wait "$child_pid" 2>/dev/null || true
	sleep 2
	flush_output
}

append() {
	local time=$1
	local threads=$2
	local outfolder=$3
	local dict=""
	local terminate_requested=0
	local child_pid=

	local waited=0
	local wait_limit="${LEGION_APPEND_WAIT_SECONDS:-30}"
	while [[ ! -d run_lib/output/queue && "$waited" -lt "$wait_limit" ]]; do
		sleep 1
		waited=$((waited + 1))
	done

	if [[ ! -d run_lib/output/queue ]]; then
		echo "[LEGION]LibFuzzer append requested without an active run directory, fallback to fresh run"
		run "$@"
		return 0
	fi

	handle_term() {
		terminate_requested=1
		echo "[LEGION]LibFuzzer append workers received termination request"
	}

	trap handle_term TERM INT
	pushd run_lib || exit
	mkdir -p input output/queue output/crashes output/autofz/queue
	copy_seed_dir "${LEGION_INITIAL_DIR:-../initial}" input

	if [ "${4:-}" == "-d" ]; then
		dict="-dict=../dict.dict"
		echo "[LEGION]we use a dictionary from $dict!"
	fi

	timeout --foreground "$time" ../build/libapp -fork="$threads" -ignore_crashes=1 -artifact_prefix=./output/crashes/ $dict ./output/queue/ ./input/ ./output/autofz/ &
	child_pid=$!

	while [ "$terminate_requested" -eq 0 ]; do
		sleep 5
		if ! kill -0 "$child_pid" 2>/dev/null; then
			break
		fi
	done

	wait "$child_pid" 2>/dev/null || true
	popd || exit
	echo "[LEGION]LibFuzzer append finished after adding $threads worker processes"
}

update_seed() {
	source=$1
	sync_seed_dir_into_libfuzzer_sync_queue "$source"
}

usage(){
	#prog="$(basename "$0")"
	#log-error "$prog No options given, don't know what to do\n"
	echo "[LEGION]USAGE: LIBFUZZER.sh build -zip|-gz <file> or LIBFUZZER.sh run|append <time> <threads> <output folder> [-d]"
}

if [[ "$#" -lt 1 ]]; then
	usage
	exit 1
fi


if [[ "$1" == "build" ]]; then
	echo "[LEGION]LibFuzzer build"
	build "${@:2}"
elif [[ "$1" == "run" ]]; then
	echo "[LEGION]LibFuzzer running"
	run "${@:2}"
elif [[ "$1" == "append" ]]; then
	echo "[LEGION]LibFuzzer appending workers"
	append "${@:2}"
elif [[ "$1" == "update" ]]; then
	echo "[LEGION]LibFuzzer updating seeds"
	update_seed "${@:2}"
else
	usage
	exit 1
fi
