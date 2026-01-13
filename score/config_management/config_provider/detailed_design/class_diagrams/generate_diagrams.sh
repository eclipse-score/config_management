#!/bin/bash

set -euo pipefail

SOURCE_DIR="./"
OUTPUT_DIR="./generated"

BASE_DIR=$(git rev-parse --show-toplevel 2>/dev/null || realpath ../../../../../../..)

DEPTH=10

rm -rf "$OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

for file in "$SOURCE_DIR"*.puml; do

    filename=$(basename "$file")
    input_path=$(realpath "$file")
    output_path=$(realpath "$OUTPUT_DIR")/"$filename"

    python3.8 ../../../../tools/detailed_design_preprocess/preprocess.py \
    --input_puml "$input_path" \
    --output_puml "$output_path" \
    --base_dir "$BASE_DIR" \
    --depth "$DEPTH"

done

echo "Diagrams are generated."
