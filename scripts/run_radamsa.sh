#!/bin/bash

shopt -s nullglob

count=0
id=$1
seeds=$2
bin=$3
PROB=5
MAXX=10000

for filename in "$seeds"/*; do
        rand=$(( RANDOM % 10 ))
        if (( rand < PROB )); then
                count=$((count + 1))
                name=$(basename "$filename")
                "$bin" "$filename" > "$name"-"$id"-"$count"

                if (( count >= MAXX )); then
                        sleep 600
                        exit 0
                fi
        fi
done

sleep 600
exit 0

		
