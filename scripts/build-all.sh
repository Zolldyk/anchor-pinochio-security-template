#!/bin/bash
set -e

echo "Building all Solana programs..."

for pattern in patterns/*/; do
  if [ -d "$pattern/programs" ]; then
    echo "Building $(basename $pattern)..."
    cd "$pattern"
    anchor build || { echo "Failed to build $(basename $pattern)"; exit 1; }
    cd - > /dev/null
  fi
done

echo "All programs built successfully!"
