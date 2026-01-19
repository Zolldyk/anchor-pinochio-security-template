#!/bin/bash
set -e

# CRITICAL: Mainnet deployment prevention
CLUSTER=$(solana config get | grep "RPC URL" | awk '{print $3}')

if [[ "$CLUSTER" == *"mainnet"* ]]; then
    echo "CRITICAL ERROR: Attempting to deploy to MAINNET"
    echo "This repository contains INTENTIONALLY VULNERABLE CODE"
    echo "Mainnet deployment is PROHIBITED"
    exit 1
fi

echo "WARNING: This script deploys EDUCATIONAL programs with INTENTIONAL VULNERABILITIES"
echo "Target cluster: $CLUSTER"
read -p "Continue deployment to DEVNET? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
  echo "Deployment cancelled"
  exit 0
fi

echo "Deploying all programs to Devnet..."
solana config set --url devnet

for pattern in patterns/*/; do
  if [ -d "$pattern/programs" ]; then
    echo "Deploying $(basename $pattern)..."
    cd "$pattern"
    anchor deploy --provider.cluster devnet
    cd - > /dev/null
  fi
done

echo "All programs deployed to Devnet!"
echo "Remember: These programs contain INTENTIONAL VULNERABILITIES for educational purposes"
