#!/bin/bash

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

TOOLS_ROOT="${TOOLS_ROOT:-/FuzzingTools}"
if [[ ! -d "$TOOLS_ROOT" && -d /home/threedean/FuzzingTools ]]; then
	TOOLS_ROOT=/home/threedean/FuzzingTools
fi

export RADAMSA_BIN="${RADAMSA_BIN:-$TOOLS_ROOT/radamsa/bin/radamsa}"
export RADAMSA_SHL="${RADAMSA_SHL:-$SCRIPT_DIR/run_radamsa.sh}"
export AFLPP_SH="${AFLPP_SH:-$SCRIPT_DIR/AFLPP.sh}"
MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"

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

build() {
	echo "[LEGION]for radamsa we do not need to build a binary"
}

run(){
	time=$1
	threads=$2
	outfolder=$3
	sync_interval="${LEGION_MONITOR_SYNC_INTERVAL:-60}"
	terminate_requested=0
	shift 3
	do_cmin=0
	while [[ "$#" -gt 0 ]]; do
		case "$1" in
			--cmin)
				do_cmin=1
				;;
			-d)
				;;
		esac
		shift
	done

	flush_output() {
		mkdir -p "$outfolder"
		if has_regular_files run_radamsa/output; then
			copy_output_files run_radamsa/output "$outfolder"
		fi
	}

	handle_term() {
		terminate_requested=1
		echo "[LEGION]Radamsa received termination request, flushing current output snapshot"
	}

	trap handle_term TERM INT
	rm -rf run_radamsa
	mkdir run_radamsa
	mkdir run_radamsa/input
	mkdir run_radamsa/output
	#get initial seeds, if any, to in
	copy_seed_dir "${LEGION_INITIAL_DIR:-initial}" run_radamsa/input
	if ! has_regular_files run_radamsa/input; then
		echo "[LEGION]no initial seeds available for Radamsa, skip this round"
		rm -rf "$outfolder"
		mkdir -p "$outfolder"
		return 0
	fi
	cp "$RADAMSA_SHL" ./run_radamsa/run_radamsa.sh
	chmod +x ./run_radamsa/run_radamsa.sh
	pushd run_radamsa || exit
	pushd output || exit

	i=0
	pids=()
	while [ $i -lt "$threads" ] 
		do
			i=$((i + 1))
			timeout --foreground "$time" ../run_radamsa.sh "$i" ../input "$RADAMSA_BIN" &
			pids+=("$!")
	done

	popd || exit
	popd || exit

	elapsed=0
	counter=0
	poll_interval=5
	last_report=-60

	rm -rf "$outfolder"
	mkdir -p "$outfolder"
	while true
		do
		if [ "$terminate_requested" -ne 0 ]; then
			echo "[LEGION]Radamsa stop requested after $elapsed seconds"
			break
		fi
		live_pids=()
		for pid in "${pids[@]}"; do
			if kill -0 "$pid" 2>/dev/null; then
				live_pids+=("$pid")
			fi
		done
		pids=("${live_pids[@]}")

		if [ "${#pids[@]}" -eq 0 ]; then
			echo "[LEGION]Radamsa workers finished early after $elapsed seconds"
			break
		fi

		if [ "$elapsed" -ge "$time" ]; then
			echo "[LEGION]Radamsa reached the time budget of $time seconds"
			break
		fi

		if [ $((elapsed - last_report)) -ge 60 ] || [ "$elapsed" -eq 0 ]; then
			echo "[LEGION-fuzzer]running Radamsa background, $elapsed/$time seconds passed"
			last_report=$elapsed
		fi

		sleep "$poll_interval"
		elapsed=$((elapsed + poll_interval))
		counter=$((counter + poll_interval))
		if [ "$counter" -ge "$sync_interval" ]; then
			echo "[LEGION]copying files preodically to speed up the process"
			flush_output
			clear_directory run_radamsa/output
			counter=0
		fi
	done

	for pid in "${pids[@]}"; do
		wait "$pid" 2>/dev/null
	done

	echo "[LEGION]$threads instances of radamsa run finished after $elapsed seconds (budget $time seconds)"

	sleep 2
	flush_output
	if [[ "$do_cmin" -eq 1 ]] && has_regular_files "$outfolder"; then
		tmp_cmin_dir="${outfolder}_cmin_tmp"
		echo "[LEGION]minimize Radamsa output under $outfolder"
		rm -rf "$tmp_cmin_dir"
		mkdir -p "$tmp_cmin_dir"
		if "$AFLPP_SH" minimize "$outfolder" "$tmp_cmin_dir" -t 1000+; then
			clear_directory "$outfolder"
			copy_output_files "$tmp_cmin_dir" "$outfolder"
		else
			echo "[LEGION]warning: Radamsa cmin failed, keep original output under $outfolder"
		fi
		rm -rf "$tmp_cmin_dir"
	fi
	#cp -r run_radamsa/output/* "$outfolder"
}

append() {
	local time=$1
	local threads=$2
	local outfolder=$3
	local terminate_requested=0
	local pids=()
	local i=0

	if [[ ! -d run_radamsa/output ]]; then
		echo "[LEGION]Radamsa append requested without an active run directory, fallback to fresh run"
		run "$@"
		return 0
	fi

	handle_term() {
		terminate_requested=1
		echo "[LEGION]Radamsa append workers received termination request"
	}

	trap handle_term TERM INT
	copy_seed_dir "${LEGION_INITIAL_DIR:-initial}" run_radamsa/input
		if [[ ! -f run_radamsa/run_radamsa.sh ]]; then
			cp "$RADAMSA_SHL" ./run_radamsa/run_radamsa.sh
			chmod +x ./run_radamsa/run_radamsa.sh
		fi

	pushd run_radamsa/output >/dev/null || exit
	while [ "$i" -lt "$threads" ]
		do
		i=$((i + 1))
		timeout --foreground "$time" ../run_radamsa.sh "append${BASHPID}_$i" ../input "$RADAMSA_BIN" &
		pids+=("$!")
	done

	while [ "$terminate_requested" -eq 0 ]; do
		sleep 5
		live=0
		for pid in "${pids[@]}"; do
			if kill -0 "$pid" 2>/dev/null; then
				live=1
				break
			fi
		done
		if [ "$live" -eq 0 ]; then
			break
		fi
	done

	for pid in "${pids[@]}"; do
		wait "$pid" 2>/dev/null || true
	done
	popd >/dev/null || exit
	echo "[LEGION]Radamsa append finished after adding $threads worker processes"
}

update_seed() {
	source=$1
	find "$source" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | xargs -0 -r cp --target-directory=run_radamsa/input
	#cp "$source"/* run_radamsa/input
}


usage(){
	#prog="$(basename "$0")"
	#log-error "$prog No options given, don't know what to do\n"
	echo "[LEGION]USAGE: RADAMSA.sh build -zip|-gz <file> or RADAMSA.sh run|append <time> <threads> <output folder> [-d] [--cmin]"
}

if [[ "$#" -lt 1 ]]; then
	usage
	exit 1
fi

if [[ "$1" == "build" ]]; then
	#echo "[LEGION]AFL++ build"
	build "${@:2}"
elif [[ "$1" == "run" ]]; then
	echo "[LEGION]radamsa running"
	run "${@:2}"
elif [[ "$1" == "append" ]]; then
	echo "[LEGION]radamsa appending workers"
	append "${@:2}"
elif [[ "$1" == "update" ]]; then
	echo "[LEGION]radamsa updating seeds"
	update_seed "${@:2}"
else
	usage
	exit 1
fi
