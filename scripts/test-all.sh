#!/bin/bash
set -e

echo "Running all tests..."

for pattern in patterns/*/; do
  # Only test patterns that have actual program code (Cargo.toml exists in a program subdirectory)
  if [ -d "$pattern/tests" ] && find "$pattern/programs" -name "Cargo.toml" -type f 2>/dev/null | grep -q .; then
    echo "Testing $(basename $pattern)..."
    cd "$pattern"
    # Let anchor manage its own local validator with pre-funded wallet
    anchor test || {
      echo "Tests failed for $(basename $pattern)"
      exit 1
    }
    cd - > /dev/null
  else
    echo "Skipping $(basename $pattern) (no programs implemented yet)"
  fi
done

echo "All tests passed!"
