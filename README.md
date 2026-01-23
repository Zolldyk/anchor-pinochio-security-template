# Anchor/Pinocchio Security Template

> **WARNING: EDUCATIONAL REPOSITORY** - This project contains **deliberately vulnerable** Solana programs for security education. These programs have intentional security flaws. **DO NOT deploy to mainnet or use in production.**

## Overview

A comprehensive educational resource for learning Solana smart contract security through hands-on vulnerability analysis. This repository provides a structured learning environment where developers can safely explore common security vulnerabilities, understand how exploits work, and learn defensive coding patterns—all without risking real assets.

Each of the six vulnerability patterns includes both a deliberately vulnerable implementation and a secure implementation side-by-side. This approach allows you to see exactly what makes code vulnerable and how to fix it.

### What You'll Learn

- **Missing Account Validation** - How missing owner/signer checks allow unauthorized access
- **Authority Check Failures** - How insufficient authority verification enables privilege escalation
- **Unsafe Arithmetic** - How unchecked integer overflow/underflow corrupts program state
- **CPI Re-entrancy** - How cross-program invocation can be manipulated for state exploitation
- **PDA Derivation Issues** - How incorrect PDA seeds or validation enables unauthorized access
- **SPL Token Validation** - How improper token account validation enables token theft

### Educational Approach

Each pattern follows a consistent structure:

1. **Vulnerable Program** - Demonstrates the security flaw with intentionally exploitable code
2. **Secure Program** - Shows the correct implementation with proper security checks
3. **Exploit Tests** - Proves the vulnerability works against the vulnerable program
4. **Security Tests** - Confirms the secure program correctly rejects attacks

Both Anchor and Pinocchio implementations are provided for all patterns, allowing you to learn security concepts across different Solana development frameworks.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Rust](https://www.rust-lang.org/tools/install) | 1.92.0 | Solana program development |
| [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) | 3.1.6 | Program deployment and interaction |
| [Anchor CLI](https://www.anchor-lang.com/docs/installation) | 0.32.1 | Smart contract framework and project management |
| [Node.js](https://nodejs.org/) | 24.13.0 | Test execution environment |
| npm | 11.7.0 | JavaScript dependency management (bundled with Node.js) |
| [Git](https://git-scm.com/downloads) | 2.52.0 | Source code management |

## Installation

Follow these steps in order: Rust → Solana → Anchor → Node.js

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Add required Rust toolchain components:

```bash
rustup component add rustfmt clippy
rustup target add bpf-unknown-unknown
```

Verify installation:

```bash
rustc --version
# Expected: rustc 1.92.0 or higher
```

### 2. Install Solana CLI

**macOS/Linux:**

```bash
sh -c "$(curl -sSfL https://release.solana.com/v3.1.6/install)"
```

Add to PATH (add to your shell profile):

```bash
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
```

Verify installation:

```bash
solana --version
# Expected: solana-cli 3.1.6
```

### 3. Install Anchor CLI

```bash
cargo install --git https://github.com/coral-xyz/anchor --tag v0.32.1 anchor-cli --locked
```

Verify installation:

```bash
anchor --version
# Expected: anchor-cli 0.32.1
```

### 4. Install Node.js

Using [nvm](https://github.com/nvm-sh/nvm) (recommended):

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
source ~/.bashrc  # or ~/.zshrc on macOS
nvm install 24.13.0
nvm use 24.13.0
```

Verify installation:

```bash
node --version
# Expected: v24.13.0

npm --version
# Expected: 11.7.0
```

### Platform-Specific Notes

**macOS:**
- Install Xcode Command Line Tools: `xcode-select --install`

**Linux (Ubuntu/Debian):**
- Install build essentials: `sudo apt-get install build-essential`

**WSL2:**
- Ensure you're running WSL2 (not WSL1): `wsl --set-default-version 2`
- Install inside WSL2, not Windows

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/anchor-pinochio-security-template.git
cd anchor-pinochio-security-template
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Build All Programs

```bash
./scripts/build-all.sh
```

### 4. Run a Single Pattern Test

```bash
npm run test:01
```

### 5. Run Full Test Suite

```bash
npm test
# or
./scripts/test-all.sh
```

**Expected Times:**
- Build (all programs): < 5 minutes
- Test suite (all patterns): < 2 minutes

## Vulnerability Patterns

| # | Pattern | Difficulty | Description |
|---|---------|------------|-------------|
| 01 | [Missing Account Validation](patterns/01-missing-validation/README.md) | Beginner | Missing owner/signer checks allow unauthorized access |
| 02 | [Authority Check Failures](patterns/02-authority-checks/README.md) | Beginner | Insufficient authority verification enables privilege escalation |
| 03 | [Unsafe Arithmetic](patterns/03-unsafe-arithmetic/README.md) | Intermediate | Unchecked integer overflow/underflow corrupts state |
| 04 | [CPI Re-entrancy](patterns/04-cpi-reentrancy/README.md) | Advanced | Cross-program invocation manipulation for state exploitation |
| 05 | [PDA Derivation Issues](patterns/05-pda-derivation/README.md) | Advanced | Incorrect PDA seeds or validation enables unauthorized access |
| 06 | [SPL Token Validation](patterns/06-token-validation/README.md) | Advanced | Improper token account validation enables theft |

For a recommended study order, see [LEARNING_PATH.md](LEARNING_PATH.md).

### Expected Output

When tests run successfully, you'll see output like:

```
Testing 01-missing-validation...
  Vulnerable Program
    ✗ should be exploitable without validation (demonstrates vulnerability)
  Secure Program
    ✓ should reject unauthorized access (demonstrates fix)
```

- `✗` prefix indicates a successful exploit demonstration (vulnerability confirmed)
- `✓` prefix indicates secure implementation correctly rejects attack

## Repository Structure

```
anchor-pinochio-security-template/
├── patterns/                       # Vulnerability pattern modules
│   ├── 01-missing-validation/      # Each pattern is self-contained
│   │   ├── programs/               # Anchor implementations
│   │   │   ├── vulnerable/         # Deliberately vulnerable code
│   │   │   └── secure/             # Fixed implementation
│   │   ├── pinocchio-programs/     # Pinocchio implementations
│   │   │   ├── vulnerable/
│   │   │   └── secure/
│   │   ├── tests/                  # Exploit demonstrations
│   │   ├── docs/                   # Pattern-specific documentation
│   │   └── README.md               # Pattern overview
│   ├── 02-authority-checks/
│   ├── 03-unsafe-arithmetic/
│   ├── 04-cpi-reentrancy/
│   ├── 05-pda-derivation/
│   └── 06-token-validation/
├── scripts/                        # Build and test automation
│   ├── build-all.sh                # Build all programs
│   ├── test-all.sh                 # Run all tests
│   ├── deploy-devnet.sh            # Deploy to devnet (educational only)
│   └── verify.sh                   # Run verification checks
├── docs/                           # Project documentation
└── README.md                       # This file
```

## Local Validator Testing

**Local validator is the PRIMARY testing method.** This ensures consistent, fast testing without network dependencies.

### Starting the Local Validator

```bash
solana-test-validator
```

### Running Tests with Local Validator

The test scripts automatically manage the local validator. Simply run:

```bash
npm test
```

Or for a specific pattern:

```bash
npm run test:01
```

### Manual Testing with Existing Validator

If you already have a validator running:

```bash
cd patterns/01-missing-validation
anchor test --skip-local-validator
```

### Test Output Interpretation

| Symbol | Meaning |
|--------|---------|
| `✗` | Exploit succeeded (vulnerability confirmed) |
| `✓` | Secure implementation blocked the attack |

Both outcomes are expected and educational:
- Vulnerable programs SHOULD be exploitable
- Secure programs SHOULD reject attacks

## Solana CLI Configuration

### Check Current Configuration

```bash
solana config get
```

Expected output for local development:

```
Config File: /Users/you/.config/solana/cli/config.yml
RPC URL: http://localhost:8899
WebSocket URL: ws://localhost:8900
Keypair Path: /Users/you/.config/solana/id.json
Commitment: confirmed
```

### Configure for Local Development

```bash
solana config set --url localhost
```

### Generate Test Keypair (Optional)

```bash
solana-keygen new --outfile ~/.config/solana/id.json --no-bip39-passphrase
```

### Devnet Configuration (Optional, Educational Only)

```bash
solana config set --url devnet
solana-keygen new --outfile ~/.config/solana/devnet-keypair.json --no-bip39-passphrase
solana airdrop 2 --url devnet
```

**Note:** Devnet deployment is optional. All patterns can be developed and tested entirely on local validator.

## Troubleshooting

### Devnet Unavailable

If Solana Devnet is experiencing issues:

1. **Use Local Validator (Recommended):**
   ```bash
   npm test  # Uses local validator by default
   ```

2. **Check Devnet Status:**
   ```bash
   solana cluster-version --url devnet
   ```

3. **Alternative Public RPC:**
   If default devnet RPC is slow, use alternatives:
   ```bash
   solana config set --url https://api.devnet.solana.com
   ```

4. **Local-Only Development:**
   All patterns can be developed and tested entirely on local validator.
   Devnet deployment is optional for educational purposes.

### RPC Rate Limits

If you encounter rate limit errors on devnet:

- Add 500ms delays between RPC-heavy operations
- Implement retry logic for network errors
- **Best solution:** Use local validator (no rate limits)

### Common Rust Issues

**PATH not set after installation:**
```bash
source $HOME/.cargo/env
# Add to ~/.bashrc or ~/.zshrc for persistence
```

**Wrong Rust version:**
```bash
rustup update
rustup default stable
```

### Common Solana CLI Issues

**Configuration not found:**
```bash
solana config set --url localhost
```

**Keypair not found:**
```bash
solana-keygen new
```

### Common Anchor Issues

**Build failures - missing BPF target:**
```bash
rustup target add bpf-unknown-unknown
```

**Anchor not found after installation:**
```bash
# Ensure Cargo bin is in PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

### Platform-Specific Issues

**macOS - Xcode Command Line Tools:**
```bash
xcode-select --install
```

**Linux - Missing build tools:**
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev
```

**WSL2 - Performance issues:**
- Ensure project files are in WSL filesystem (not /mnt/c/)
- Check WSL version: `wsl --list --verbose`

## npm Scripts Reference

| Script | Description |
|--------|-------------|
| `npm run build` | Build all programs |
| `npm test` | Run full test suite |
| `npm run test:01` | Test pattern 01 (Missing Validation) |
| `npm run test:02` | Test pattern 02 (Authority Checks) |
| `npm run test:03` | Test pattern 03 (Unsafe Arithmetic) |
| `npm run test:04` | Test pattern 04 (CPI Re-entrancy) |
| `npm run test:05` | Test pattern 05 (PDA Derivation) |
| `npm run test:06` | Test pattern 06 (Token Validation) |
| `npm run deploy` | Deploy to devnet (educational only) |
| `npm run verify` | Run verification checks |
| `npm run lint` | Run Clippy linter |
| `npm run format` | Format code with rustfmt |


### Built With

- [Anchor](https://www.anchor-lang.com/) - Solana smart contract framework
- [Pinocchio](https://github.com/febo/pinocchio) - Lightweight Solana program library
- [Solana](https://solana.com/) - High-performance blockchain

## License

MIT License - See [LICENSE](LICENSE)
