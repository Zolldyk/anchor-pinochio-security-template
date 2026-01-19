# Anchor/Pinocchio Security Template

> **EDUCATIONAL REPOSITORY**: This project contains deliberately vulnerable Solana programs for security education. DO NOT deploy to mainnet.

## Overview

A comprehensive educational resource for learning Solana smart contract security through hands-on vulnerability analysis. Each pattern demonstrates a common security vulnerability with both vulnerable and secure implementations.

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
├── patterns/                    # Vulnerability pattern modules
│   ├── 01-missing-validation/   # Each pattern is self-contained
│   │   ├── programs/vulnerable/ # Deliberately vulnerable code
│   │   ├── programs/secure/     # Fixed implementation
│   │   ├── tests/               # Exploit demonstrations
│   │   └── README.md            # Pattern-specific docs
│   ├── 02-arithmetic-overflow/
│   ├── 03-improper-signer/
│   ├── 04-account-confusion/
│   ├── 05-reinitialization/
│   └── 06-pda-validation/
├── scripts/                     # Build and test automation
│   ├── build-all.sh            # Build all programs
│   ├── test-all.sh             # Run all tests
│   ├── deploy-devnet.sh        # Deploy to devnet (educational only)
│   └── verify.sh               # Run verification checks
├── docs/                        # Project documentation
└── README.md                    # This file
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

| Script | Command | Description |
|--------|---------|-------------|
| `npm run build` | `./scripts/build-all.sh` | Build all programs |
| `npm test` | `./scripts/test-all.sh` | Run full test suite |
| `npm run test:01` | `cd patterns/01-* && anchor test` | Test pattern 01 |
| `npm run lint` | `cargo clippy --all-targets -- -D warnings` | Run linter |
| `npm run format` | `cargo fmt --all` | Format code |

## Learning Path

See [LEARNING_PATH.md](docs/LEARNING_PATH.md) for the recommended order to study vulnerability patterns.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT License - See [LICENSE](LICENSE)
