#!/bin/bash
set -e

echo "Running all tests..."

# Start local validator in background
solana-test-validator > /dev/null 2>&1 &
VALIDATOR_PID=$!
sleep 5

# Ensure validator cleanup on exit
trap "kill $VALIDATOR_PID 2>/dev/null || true" EXIT

for pattern in patterns/*/; do
  if [ -d "$pattern/tests" ]; then
    echo "Testing $(basename $pattern)..."
    cd "$pattern"
    anchor test --skip-local-validator || {
      echo "Tests failed for $(basename $pattern)"
      exit 1
    }
    cd - > /dev/null
  fi
done

echo "All tests passed!"
