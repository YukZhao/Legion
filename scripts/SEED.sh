#!/bin/bash

MAX_SEED_BYTES="${LEGION_MAX_SEED_SIZE_BYTES:-1048576}"

has_regular_files() {
    find "$1" -maxdepth 1 -type f -print -quit | grep -q .
}

has_copyable_files() {
    find "$1" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print -quit | grep -q .
}

clear_directory() {
    mkdir -p "$1"
    find "$1" -mindepth 1 -maxdepth 1 -print0 | xargs -0 -r rm -rf
}

copy_regular_files() {
    src=$1
    dst=$2
    mkdir -p "$dst"
    find "$src" -maxdepth 1 -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | xargs -0 -r cp --target-directory="$dst"
}

if [ "$1" = "copy" ]; then
    temp_dir=$(mktemp -d)
    unzip -q "$2" -d "$temp_dir"
    if ! find "$temp_dir" -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print -quit | grep -q .; then
        echo "[LEGION]warning: no <= ${MAX_SEED_BYTES} byte seeds found in archive $2, keep existing files in $3"
        rm -rf "$temp_dir"
        exit 0
    fi
    clear_directory "$3"
    find "$temp_dir" -type f -size -"$((${MAX_SEED_BYTES} + 1))"c -print0 | xargs -0 -r cp --target-directory="$3"
    rm -rf "$temp_dir"
elif [ "$1" == "create" ]; then
    head /dev/urandom | head -c 16 > "$3"/seed
else
    source_dir="./$2"
    target_dir="./$3"
    if ! has_copyable_files "$source_dir"; then
        echo "[LEGION]warning: no seeds found in $source_dir, keep existing files in $target_dir"
        exit 0
    fi
    temp_dir=$(mktemp -d)
    copy_regular_files "$source_dir" "$temp_dir"
    clear_directory "$target_dir"
    copy_regular_files "$temp_dir" "$target_dir"
    rm -rf "$temp_dir"
fi
