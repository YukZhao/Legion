#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LOCAL_LEGION_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

DEFAULT_LEGION_PATH="$LOCAL_LEGION_ROOT"
DEFAULT_INSTRUMENT_BIN="$LOCAL_LEGION_ROOT/bin"

if [[ ! -d "$DEFAULT_INSTRUMENT_BIN" ]]; then
	TOOLS_ROOT="${TOOLS_ROOT:-/FuzzingTools}"
	if [[ ! -d "$TOOLS_ROOT" && -d /home/threedean/FuzzingTools ]]; then
		TOOLS_ROOT=/home/threedean/FuzzingTools
	fi
	DEFAULT_LEGION_PATH="$TOOLS_ROOT/Legion"
	DEFAULT_INSTRUMENT_BIN="$DEFAULT_LEGION_PATH/bin"
fi

export INSTRUMENT_BIN="${INSTRUMENT_BIN:-$DEFAULT_INSTRUMENT_BIN/}"
export LEGION_PATH="${LEGION_PATH:-$DEFAULT_LEGION_PATH}"

DEFAULT_INSTRUMENT_CC="clang"
DEFAULT_INSTRUMENT_CXX="clang++"
if command -v clang-12 >/dev/null 2>&1 && command -v clang++-12 >/dev/null 2>&1; then
	DEFAULT_INSTRUMENT_CC="clang-12"
	DEFAULT_INSTRUMENT_CXX="clang++-12"
elif command -v clang-8 >/dev/null 2>&1 && command -v clang++-8 >/dev/null 2>&1; then
	DEFAULT_INSTRUMENT_CC="clang-8"
	DEFAULT_INSTRUMENT_CXX="clang++-8"
fi

build() {

	ARCHIVE=$(basename "$2")
	SRC=${ARCHIVE%%.*}

	mkdir build
	rm -rf code_instrument/"$SRC"
	mkdir code_instrument
	cp "$2" code_instrument/"$ARCHIVE"
	pushd code_instrument || exit

	if [[ "$1" == "-zip" ]]; then
		unzip "$ARCHIVE"
	elif [[ "$1" == "-gz" ]]; then
		tar -xvf "$ARCHIVE"
	else
		echo "[LEGION]unknown compress format"
		exit 1
	fi

	rm "$ARCHIVE"

	export CC="${LEGION_INSTRUMENT_CC:-$DEFAULT_INSTRUMENT_CC}"
	export CXX="${LEGION_INSTRUMENT_CXX:-$DEFAULT_INSTRUMENT_CXX}"
	export LD="${LEGION_INSTRUMENT_LD:-$CC}"

	# we add fuzzer fsanitizer options for persistent fuzzing  $INSTRUMENT_BIN/trace.o
	export FSANITIZE_FUZZER_FLAGS="-fno-omit-frame-pointer -g -fsanitize-coverage=trace-pc-guard"
	export CFLAGS="$FSANITIZE_FUZZER_FLAGS"
	export CXXFLAGS="$FSANITIZE_FUZZER_FLAGS"

	#export EXTRALIBS="-L$INSTRUMENT_BIN $INSTRUMENT_BIN/entry.o $INSTRUMENT_BIN/trace.o"
	export EXTRALIBS="-L. -linstrumentor"

	pushd "$SRC" || exit
	cp $INSTRUMENT_BIN/libinstrumentor.a ./

	sed -i '/^[[:space:]]*make[[:space:]]/ s/^\([[:space:]]*\)make[[:space:]]/\1bear make /' ./fuzzbuild
	./fuzzbuild

	if [[ "${3:-}" == "--call-graph" ]]; then
		analyze
	fi

	popd || exit
	popd || exit
	cp -p code_instrument/$SRC/app build/instrumentapp

}

run(){
    folder_path=$1
	report_path=$2

	time ./build/instrumentapp "$folder_path" "$report_path"

	echo "[LEGION] finishe evaluating for this round!" 
}

analyze() {
	echo "[LEGION]generate call graph"
	cp $LEGION_PATH/doxygen.config ./
	doxygen doxygen.config
	pushd html || exit
	file=$(
		find . -type f \
			\( -name "target*_cgraph.dot" \
			-o -name "*privkey*_cgraph.dot" \
			-o -name "*fuzz*_*_cgraph.dot" \
			-o -name "*driver*_cgraph.dot" \) \
			| head -n 1
	)
	if [[ -z "$file" ]]; then
		file=$(find . -type f -name "*_cgraph.dot" | head -n 1)
	fi
	if [[ -z "$file" ]]; then
		echo "[LEGION]failed to locate a call graph dot file" >&2
		exit 1
	fi
	cp "$file" ../../../build/cgraph.dot
	popd || exit
}

usage(){
	prog="$(basename "$0")"
	log-error "$prog No options given, don't know what to do\n"
}

[[ "$0" == 0 ]] && usage

if [[ "$1" == "build" ]]; then
	echo "[LEGION]AFL++ build"
	build "${@:2}"
elif [[ "$1" == "run" ]]; then
	echo "[LEGION]AFL++ running"
	run "${@:2}"
fi
