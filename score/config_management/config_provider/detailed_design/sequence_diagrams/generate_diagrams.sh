#!/bin/bash

set -euo pipefail

SOURCE_DIR="./"
PUML_OUTPUT_DIR="./generated/puml"
SVG_OUTPUT_DIR="./generated/svg"

BASE_DIR=$(git rev-parse --show-toplevel 2>/dev/null || realpath ../../../../../../..)

DEPTH=10

rm -rf "$PUML_OUTPUT_DIR"
rm -rf "$SVG_OUTPUT_DIR"

mkdir -p "$PUML_OUTPUT_DIR"
mkdir -p "$SVG_OUTPUT_DIR"

for file in "$SOURCE_DIR"*.puml; do

    filename=$(basename "$file")
    input_path=$(realpath "$file")
    puml_output_path=$(realpath "$PUML_OUTPUT_DIR")/"$filename"
    svg_output_path=$(realpath "$SVG_OUTPUT_DIR")/"$filename"

    # python3.8 ../../../../tools/detailed_design_preprocess/preprocess.py \
    # --input_puml "$input_path" \
    # --output_puml "$puml_output_path" \
    # --base_dir "$BASE_DIR" \
    # --depth "$DEPTH"

    plantuml -svg "$input_path" -o "$SVG_OUTPUT_DIR"
done

echo "Diagrams are generated."
