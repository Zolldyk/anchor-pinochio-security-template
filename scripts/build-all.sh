#!/bin/bash
set -e

echo "Building all Solana programs..."

for pattern in patterns/*/; do
  # Only build patterns that have actual program code (Cargo.toml exists in a program subdirectory)
  if [ -d "$pattern/programs" ] && find "$pattern/programs" -name "Cargo.toml" -type f | grep -q .; then
    echo "Building $(basename $pattern)..."
    cd "$pattern"
    anchor build || { echo "Failed to build $(basename $pattern)"; exit 1; }
    cd - > /dev/null
  else
    echo "Skipping $(basename $pattern) (no programs implemented yet)"
  fi
done

echo "All programs built successfully!"
