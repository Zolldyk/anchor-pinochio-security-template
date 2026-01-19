#!/bin/bash
set -e

echo "Running verification checks..."

echo "1. Checking Rust formatting..."
cargo fmt --all -- --check

echo "2. Running Clippy..."
cargo clippy --all-targets -- -D warnings

echo "3. Building all programs..."
./scripts/build-all.sh

echo "4. Checking TypeScript compilation..."
tsc --noEmit

echo "5. Verifying no mainnet references in scripts..."
if grep -r "mainnet-beta" scripts/ 2>/dev/null; then
  echo "ERROR: Mainnet reference found in scripts"
  exit 1
fi

echo "6. Checking for TODO/FIXME in production code..."
if git grep -n "TODO\|FIXME" -- '*.rs' ':!*vulnerable*' | grep -v "^Binary"; then
  echo "WARNING: TODOs found in secure implementations"
fi

echo "All verification checks passed!"
