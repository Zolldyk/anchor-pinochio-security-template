# Deep Dive: CPI Re-entrancy in Solana Programs

> **Educational Resource** - This document provides comprehensive coverage of Cross-Program Invocation (CPI) re-entrancy vulnerabilities in Solana programs, including the Solana execution model, CPI mechanics, attack anatomy, real-world patterns, and defensive programming techniques.

## Table of Contents

1. [Solana Program Execution Model](#solana-program-execution-model)
   - [Runtime Architecture](#runtime-architecture)
   - [Account Model](#account-model)
   - [Transaction Processing](#transaction-processing)
   - [Execution Context](#execution-context)

2. [CPI Mechanics Deep-Dive](#cpi-mechanics-deep-dive)
   - [What is CPI?](#what-is-cpi)
   - [invoke() Function](#invoke-function)
   - [invoke_signed() Function](#invoke_signed-function)
   - [CPI Context and Account Passing](#cpi-context-and-account-passing)
   - [CPI Depth Limit](#cpi-depth-limit)
   - [Compute Budget Considerations](#compute-budget-considerations)

3. [Re-entrancy Vulnerability Anatomy](#re-entrancy-vulnerability-anatomy)
   - [The Classic Pattern](#the-classic-pattern)
   - [State Inconsistency Window](#state-inconsistency-window)
   - [Complete Attack Flow Analysis](#complete-attack-flow-analysis)
   - [Code-Level Vulnerability Analysis](#code-level-vulnerability-analysis)

4. [Real-World Case Studies](#real-world-case-studies)
   - [Solana Ecosystem Context](#solana-ecosystem-context)
   - [Ethereum Historical Context: The DAO](#ethereum-historical-context-the-dao)
   - [Cross-Chain Lessons](#cross-chain-lessons)

5. [Common Vulnerable Patterns in DeFi](#common-vulnerable-patterns-in-defi)
   - [Vault Withdrawals](#vault-withdrawals)
   - [Token Swaps with Callbacks](#token-swaps-with-callbacks)
   - [Lending Protocol Liquidations](#lending-protocol-liquidations)
   - [Flash Loan Callbacks](#flash-loan-callbacks)
   - [NFT Marketplace Callbacks](#nft-marketplace-callbacks)

6. [Defense Pattern Selection Guide](#defense-pattern-selection-guide)
   - [Decision Flowchart](#decision-flowchart)
   - [When to Use CEI (Checks-Effects-Interactions)](#when-to-use-cei-checks-effects-interactions)
   - [When to Add Re-entrancy Guards](#when-to-add-re-entrancy-guards)
   - [When to Use Account Locking](#when-to-use-account-locking)
   - [When to Use CPI Restrictions](#when-to-use-cpi-restrictions)
   - [Defense Combinations](#defense-combinations)

7. [Implementation Examples](#implementation-examples)
   - [Complete Secure Vault Implementation](#complete-secure-vault-implementation)
   - [Testing for Re-entrancy](#testing-for-re-entrancy)

8. [References](#references)

---

## Solana Program Execution Model

Understanding Solana's execution model is essential to grasp why and how re-entrancy vulnerabilities manifest differently than in Ethereum.

### Runtime Architecture

Solana's runtime executes programs in a unique environment:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Solana Runtime Architecture                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Transaction                                                                │
│   ┌──────────────────────────────────────────────────────────────────────┐  │
│   │  Instruction 1  │  Instruction 2  │  Instruction 3  │  ...           │  │
│   └──────────────────────────────────────────────────────────────────────┘  │
│          │                  │                  │                             │
│          ▼                  ▼                  ▼                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         Program Runtime                              │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│   │  │  Program A  │──│  Program B  │──│  Program C  │  (CPI chain)     │   │
│   │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│   │         │                │                │                          │   │
│   │         └────────────────┴────────────────┘                          │   │
│   │                         │                                            │   │
│   │                         ▼                                            │   │
│   │              ┌──────────────────────┐                                │   │
│   │              │   Account Data Store  │                                │   │
│   │              │  (Modified in place)  │                                │   │
│   │              └──────────────────────┘                                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Key Characteristics:                                                       │
│   • Programs are stateless (no storage within program)                      │
│   • All state lives in accounts                                             │
│   • Accounts are passed explicitly to each instruction                      │
│   • Programs can modify accounts they own                                   │
│   • CPI allows programs to invoke other programs                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Account Model

Unlike Ethereum's contract storage, Solana uses an account-based model:

| Aspect | Ethereum | Solana |
|--------|----------|--------|
| State location | Contract storage (mapped to contract address) | Account data (separate from program) |
| State ownership | Contract owns its storage | Accounts owned by programs |
| State access | Contract can always access its storage | Accounts must be passed to instruction |
| State isolation | Storage is contract-private | Accounts can be shared across programs |
| Modification rights | Only owning contract | Only owning program (via CPI) |

**Implications for Re-entrancy:**
- In Ethereum: Re-entrant call sees the same contract storage in inconsistent state
- In Solana: Re-entrant CPI receives the same account data in inconsistent state

### Transaction Processing

Solana transactions are processed atomically:

```rust
// Transaction structure (simplified)
Transaction {
    signatures: [...],
    message: Message {
        header: MessageHeader { ... },
        account_keys: [wallet, vault, program_a, program_b, ...],
        instructions: [
            Instruction { program_id: program_a, accounts: [0, 1], data: [...] },
            Instruction { program_id: program_b, accounts: [1, 2], data: [...] },
        ]
    }
}
```

**Key points:**
1. All accounts must be declared upfront in the transaction
2. Instructions execute sequentially within a transaction
3. CPIs can invoke additional instructions not in the original transaction
4. If any instruction fails, the entire transaction reverts

### Execution Context

During program execution, the runtime maintains an execution context:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Execution Context                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Call Stack (CPI Depth Limit: 4)                                           │
│   ┌───────────────────────────────────────────────────────────────────┐     │
│   │ Depth 0: Original instruction (User → Program A)                   │     │
│   │ Depth 1: CPI from Program A → Program B                           │     │
│   │ Depth 2: CPI from Program B → Program A (re-entry possible!)      │     │
│   │ Depth 3: CPI from Program A → Program B                           │     │
│   │ Depth 4: LIMIT REACHED - further CPI fails                        │     │
│   └───────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│   Account Access:                                                            │
│   • Each depth level can access accounts passed to it                       │
│   • Account modifications are visible to all depths immediately             │
│   • Re-entrant calls see current (possibly inconsistent) account state      │
│                                                                              │
│   Compute Budget:                                                            │
│   • Shared across entire call stack                                         │
│   • Default: ~200,000 compute units                                         │
│   • Can request up to 1,400,000 CU                                          │
│   • Deep CPI chains consume more compute                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## CPI Mechanics Deep-Dive

### What is CPI?

Cross-Program Invocation (CPI) allows one Solana program to invoke instructions on another program during execution. This is Solana's equivalent of Ethereum's external contract calls.

```rust
// CPI is how programs communicate on Solana
Program A ──CPI──> Program B ──CPI──> Program C
              │                   │
              │   Passes accounts │   Passes accounts
              │   and instruction │   and instruction
              │   data            │   data
              ▼                   ▼
```

### invoke() Function

The basic CPI function for invoking programs without PDA signing:

```rust
use anchor_lang::solana_program::program::invoke;

pub fn call_external_program(ctx: Context<CallExternal>) -> Result<()> {
    // Build the instruction to invoke
    let instruction = Instruction {
        program_id: ctx.accounts.external_program.key(),
        accounts: vec![
            AccountMeta::new(ctx.accounts.some_account.key(), false),      // writable, not signer
            AccountMeta::new_readonly(ctx.accounts.other_account.key(), true), // read-only, signer
        ],
        data: instruction_data,
    };

    // Invoke the external program
    // NOTE: This is where re-entrancy attacks can occur!
    invoke(
        &instruction,
        &[
            ctx.accounts.some_account.to_account_info(),
            ctx.accounts.other_account.to_account_info(),
        ],
    )?;

    // Code here executes AFTER the CPI returns
    // If attacker re-entered above, this may use stale data!
    Ok(())
}
```

**Parameters:**
- `instruction`: The instruction to execute on the target program
- `account_infos`: Account references to pass to the invoked program

### invoke_signed() Function

For CPIs that require PDA signing authority:

```rust
use anchor_lang::solana_program::program::invoke_signed;

pub fn call_with_pda_authority(ctx: Context<CallWithPda>) -> Result<()> {
    let seeds = &[
        b"vault",
        ctx.accounts.authority.key().as_ref(),
        &[ctx.accounts.vault.bump],
    ];
    let signer_seeds = &[&seeds[..]];

    let instruction = Instruction {
        program_id: ctx.accounts.token_program.key(),
        accounts: vec![
            AccountMeta::new(ctx.accounts.vault_token_account.key(), false),
            AccountMeta::new(ctx.accounts.user_token_account.key(), false),
            AccountMeta::new_readonly(ctx.accounts.vault_pda.key(), true), // PDA is signer
        ],
        data: transfer_instruction_data,
    };

    // The PDA signs this CPI
    invoke_signed(
        &instruction,
        &[
            ctx.accounts.vault_token_account.to_account_info(),
            ctx.accounts.user_token_account.to_account_info(),
            ctx.accounts.vault_pda.to_account_info(),
        ],
        signer_seeds,
    )?;

    Ok(())
}
```

### CPI Context and Account Passing

When making a CPI, accounts are passed by reference. Changes made by the invoked program are immediately visible:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CPI Account Passing                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Program A                          Program B                               │
│   ┌─────────────────────┐           ┌─────────────────────┐                 │
│   │                     │           │                     │                 │
│   │  vault.balance = X  │──CPI──────│  vault.balance = X  │                 │
│   │                     │           │  (same reference)   │                 │
│   │  // Later:          │◄──────────│                     │                 │
│   │  vault.balance = Y  │  returns  │  vault.balance = Y  │                 │
│   │  (sees B's changes) │           │  (modified)         │                 │
│   │                     │           │                     │                 │
│   └─────────────────────┘           └─────────────────────┘                 │
│                                                                              │
│   CRITICAL: Account data is shared memory!                                  │
│   • Changes made in Program B are visible in Program A immediately         │
│   • If Program B calls back to Program A, it sees the CURRENT state        │
│   • This is the foundation of re-entrancy attacks                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### CPI Depth Limit

Solana enforces a maximum CPI depth of 4 to prevent stack overflow and unbounded recursion:

```
Depth 0: User Tx → Program A (initial instruction)
Depth 1: Program A → Program B (CPI)
Depth 2: Program B → Program C (CPI)
Depth 3: Program C → Program D (CPI)
Depth 4: Program D → Program E (FAILS: CPI depth limit exceeded)
```

**Re-entrancy Attack Depth:**
```
Depth 0: User Tx → Vulnerable Vault (withdraw)
Depth 1: Vault → Attacker Program (callback)
Depth 2: Attacker → Vulnerable Vault (re-entry: withdraw again)
Depth 3: Vault → Attacker Program (callback again)
Depth 4: Attacker → Vulnerable Vault (FAILS: limit reached)
```

**Impact:** The depth limit provides partial mitigation - attackers can only re-enter a limited number of times. However:
- One successful re-entry may be enough to drain a vault
- The limit reduces but does not eliminate the vulnerability
- Never rely on depth limit as a security control

### Compute Budget Considerations

CPIs consume compute units from the transaction's shared budget:

```rust
// Requesting increased compute budget (client-side)
ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
```

**Default:** ~200,000 CU
**Maximum:** 1,400,000 CU

**Re-entrancy Impact:**
- Each CPI level adds overhead (~1,000-5,000 CU)
- Deep re-entrancy chains may hit compute limits
- However, efficient attacks complete in 1-2 re-entries
- Do not rely on compute limits for security

---

## Re-entrancy Vulnerability Anatomy

### The Classic Pattern

The fundamental vulnerable pattern follows this structure:

```rust
pub fn vulnerable_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // 1. READ: Get current state
    let balance = ctx.accounts.vault.balance;

    // 2. CHECK: Validate the operation
    require!(balance >= amount, ErrorCode::InsufficientBalance);

    // 3. INTERACT: Make external call (CPI)
    // ⚠️ VULNERABILITY: State not yet updated!
    invoke(&callback_ix, &accounts)?;  // Attacker can re-enter here

    // 4. EFFECT: Update state (TOO LATE!)
    ctx.accounts.vault.balance = balance - amount;

    Ok(())
}
```

**The vulnerability is the order of operations:**
- Read → Check → **Interact** → Effect (vulnerable)
- Read → Check → Effect → **Interact** (secure - CEI pattern)

### State Inconsistency Window

The "window" during which state is inconsistent:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     State Inconsistency Window                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   Time ───────────────────────────────────────────────────────────────►     │
│                                                                              │
│   ┌─────────┐  ┌─────────┐  ┌───────────────────────┐  ┌─────────────┐     │
│   │  Read   │  │  Check  │  │   CPI (DANGER ZONE)   │  │   Update    │     │
│   │ balance │  │ balance │  │                       │  │   balance   │     │
│   │ = 1000  │  │ >= 100  │  │  External program     │  │   = 900     │     │
│   └─────────┘  └─────────┘  │  can call back here   │  └─────────────┘     │
│        │            │       │                       │         │             │
│        │            │       │  ┌─────────────────┐  │         │             │
│        │            │       │  │ ATTACK WINDOW:  │  │         │             │
│        │            │       │  │ balance STILL   │  │         │             │
│        │            │       │  │ shows 1000!     │  │         │             │
│        │            │       │  └─────────────────┘  │         │             │
│        │            │       │                       │         │             │
│        └────────────┴───────┴───────────────────────┴─────────┘             │
│                              │                                               │
│                              │ During this time, the actual balance          │
│                              │ is 1000 but should logically be 900           │
│                              │ after the withdrawal is "committed"           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Complete Attack Flow Analysis

Let's trace through a complete attack:

**Initial State:**
- Vault balance: 1000 tokens
- Attacker deposit: 1000 tokens (owns the vault balance)
- Withdrawal amount: 500 tokens

**Attack Execution:**

```
Step 1: Attacker calls withdraw(500)
┌──────────────────────────────────────────────────────────────────────┐
│ Vulnerable Program (Depth 0)                                          │
│ • Read balance: 1000                                                 │
│ • Check: 1000 >= 500 ✓                                               │
│ • Making CPI to attacker's callback...                               │
└──────────────────────────────────────────────────────────────────────┘
                         │
                         ▼
Step 2: Attacker's callback receives control
┌──────────────────────────────────────────────────────────────────────┐
│ Attacker Program (Depth 1)                                           │
│ • Received callback                                                  │
│ • Checking: Can I re-enter the vault?                                │
│ • YES - making CPI back to vulnerable program's withdraw             │
└──────────────────────────────────────────────────────────────────────┘
                         │
                         ▼
Step 3: Re-entrant withdrawal
┌──────────────────────────────────────────────────────────────────────┐
│ Vulnerable Program (Depth 2) - RE-ENTRY                              │
│ • Read balance: 1000 (NOT YET UPDATED!)                              │
│ • Check: 1000 >= 500 ✓ (passes again!)                               │
│ • Making CPI to attacker's callback...                               │
└──────────────────────────────────────────────────────────────────────┘
                         │
                         ▼
Step 4: Attacker's callback (second time)
┌──────────────────────────────────────────────────────────────────────┐
│ Attacker Program (Depth 3)                                           │
│ • Attack state shows already re-entered                              │
│ • Stopping to avoid infinite loop / depth limit                      │
│ • Returning normally                                                 │
└──────────────────────────────────────────────────────────────────────┘
                         │
                         ▼
Step 5: Inner withdrawal completes
┌──────────────────────────────────────────────────────────────────────┐
│ Vulnerable Program (Depth 2)                                         │
│ • CPI returned                                                       │
│ • Updating balance: 1000 - 500 = 500                                 │
│ • Done                                                               │
└──────────────────────────────────────────────────────────────────────┘
                         │
                         ▼
Step 6: Outer withdrawal completes
┌──────────────────────────────────────────────────────────────────────┐
│ Vulnerable Program (Depth 0)                                         │
│ • CPI returned                                                       │
│ • Updating balance: 1000 - 500 = 500 (USING STALE VALUE!)            │
│ • Done                                                               │
└──────────────────────────────────────────────────────────────────────┘

RESULT:
• Attacker withdrew 500 tokens twice = 1000 tokens total
• Vault balance: 500 (should be 0)
• Attacker received 1000 tokens but vault lost only 500 in tracking
• If vault held real tokens: tokens are drained, tracking is wrong
```

### Code-Level Vulnerability Analysis

**Vulnerable Program (annotated):**

```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ┌─────────────────────────────────────────────────────────────────┐
    // │ VULNERABILITY POINT 1: Reading state into local variables       │
    // │ These local variables become "snapshots" of state at this time  │
    // └─────────────────────────────────────────────────────────────────┘
    let current_balance = ctx.accounts.vault.balance;       // snapshot: 1000
    let current_user_amount = ctx.accounts.user_deposit.amount;

    // ┌─────────────────────────────────────────────────────────────────┐
    // │ VULNERABILITY POINT 2: Checking against snapshots               │
    // │ The check uses the snapshot, not live state                     │
    // └─────────────────────────────────────────────────────────────────┘
    require!(current_balance >= amount, ErrorCode::InsufficientBalance);
    require!(current_user_amount >= amount, ErrorCode::InsufficientUserBalance);

    // ┌─────────────────────────────────────────────────────────────────┐
    // │ VULNERABILITY POINT 3: CPI before state update                  │
    // │ External program can now re-enter, and will see:                │
    // │ - vault.balance = 1000 (not yet decremented)                    │
    // │ - The same checks will pass again!                              │
    // └─────────────────────────────────────────────────────────────────┘
    let callback_ix = /* ... build callback instruction ... */;
    invoke(&callback_ix, &accounts)?;  // <-- RE-ENTRY HAPPENS HERE

    // ┌─────────────────────────────────────────────────────────────────┐
    // │ VULNERABILITY POINT 4: Updating state using snapshots           │
    // │ Using current_balance (1000) not the account's current value    │
    // │ If re-entry occurred, account balance was already modified      │
    // │ but we're overwriting with: 1000 - 500 = 500                    │
    // └─────────────────────────────────────────────────────────────────┘
    ctx.accounts.vault.balance = current_balance
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientBalance)?;

    ctx.accounts.user_deposit.amount = current_user_amount
        .checked_sub(amount)
        .ok_or(ErrorCode::InsufficientUserBalance)?;

    Ok(())
}
```

**The Fix (Secure Pattern):**

```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let user_deposit = &mut ctx.accounts.user_deposit;

    // SECURITY: Check re-entrancy guard first
    require!(!vault.reentrancy_guard, ErrorCode::ReentrancyDetected);

    // SECURITY: Set guard immediately
    vault.reentrancy_guard = true;

    // CHECKS: Validate state
    require!(vault.balance >= amount, ErrorCode::InsufficientBalance);
    require!(user_deposit.amount >= amount, ErrorCode::InsufficientUserBalance);

    // EFFECTS: Update state BEFORE CPI
    vault.balance = vault.balance.checked_sub(amount)?;
    user_deposit.amount = user_deposit.amount.checked_sub(amount)?;

    // INTERACTIONS: CPI after state is consistent
    let callback_ix = /* ... */;
    invoke(&callback_ix, &accounts)?;
    // Even if re-entry occurs, state is already updated!

    // Clear guard
    ctx.accounts.vault.reentrancy_guard = false;

    Ok(())
}
```

---

## Real-World Case Studies

### Solana Ecosystem Context

While Solana has not experienced a catastrophic public re-entrancy exploit equivalent to The DAO, the risk exists:

**Audit Findings:**
- Multiple DeFi protocols have had CPI-related vulnerabilities identified in audits
- Flash loan callback implementations frequently exhibit this pattern
- Cross-program token operations are common vulnerability points

**Why No Major Public Incidents (Yet):**
1. Solana DeFi is younger than Ethereum DeFi
2. CPI depth limit provides partial mitigation
3. Many protocols learned from Ethereum's history
4. Security auditing has become standard practice

**Note:** The absence of public incidents does not mean the vulnerability doesn't exist or isn't being exploited. Many exploits are not publicly disclosed or attributed to re-entrancy.

### Ethereum Historical Context: The DAO

The most famous re-entrancy attack in blockchain history provides essential context:

**The DAO Hack (June 2016):**
- **Protocol:** The DAO (Decentralized Autonomous Organization)
- **Funds Lost:** ~$60 million (3.6 million ETH)
- **Vulnerability:** Re-entrancy in the `splitDAO()` function

**Vulnerable Code Pattern:**

```solidity
// Simplified vulnerable Solidity code from The DAO
function withdraw(uint amount) public {
    // CHECK: balance
    require(balances[msg.sender] >= amount);

    // INTERACT: Send ETH (external call!)
    // ⚠️ The receiving contract can call back!
    msg.sender.call.value(amount)("");  // <-- RE-ENTRY HERE

    // EFFECT: Update balance (TOO LATE!)
    balances[msg.sender] -= amount;
}

// Attacker's contract
receive() external payable {
    if (dao.balances(address(this)) > 0) {
        dao.withdraw(amount);  // Re-enter before balance updated!
    }
}
```

**Attack Flow:**
1. Attacker deposits ETH into The DAO
2. Attacker calls `withdraw()`
3. The DAO sends ETH via `call.value()`
4. Attacker's `receive()` function is triggered
5. Attacker calls `withdraw()` again (re-entry)
6. Balance check passes (not yet decremented)
7. Repeat until depth limit or gas exhaustion
8. Balance is only decremented once at the end

**Outcome:**
- $60M drained from The DAO
- Ethereum hard forked to recover funds (creating ETH/ETC split)
- Led to widespread adoption of re-entrancy guards
- OpenZeppelin's `ReentrancyGuard` became standard

### Cross-Chain Lessons

| Lesson from Ethereum | Application to Solana |
|---------------------|----------------------|
| External calls before state updates are dangerous | CPIs before state updates are equally dangerous |
| Re-entrancy guards are essential | Boolean guards in accounts serve same purpose |
| Checks-Effects-Interactions pattern | Same pattern applies to Solana programs |
| Gas limits don't prevent exploitation | CPI depth limits don't prevent exploitation |
| Code audit is not optional | Security review of CPI flows is critical |

---

## Common Vulnerable Patterns in DeFi

### Vault Withdrawals

The most common vulnerable pattern in DeFi:

```rust
// VULNERABLE: Classic vault withdrawal
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &ctx.accounts.vault;

    // Check balance
    require!(vault.balance >= amount, ErrorCode::InsufficientBalance);

    // VULNERABILITY: Transfer tokens via CPI before updating vault state
    let transfer_ix = token_program::transfer(/* ... */);
    invoke(&transfer_ix, &accounts)?;  // Token program could have callbacks

    // Update after transfer (vulnerable!)
    ctx.accounts.vault.balance -= amount;
    Ok(())
}
```

**Attack Vector:** If the token transfer includes any callback mechanism (e.g., token extensions with transfer hooks), the callback can re-enter.

### Token Swaps with Callbacks

Automated Market Makers (AMMs) often use callbacks:

```rust
// VULNERABLE: Swap with callback
pub fn swap(ctx: Context<Swap>, amount_in: u64) -> Result<()> {
    let pool = &ctx.accounts.pool;

    // Calculate output
    let amount_out = calculate_output(pool, amount_in);

    // Check pool reserves
    require!(pool.reserve_out >= amount_out, ErrorCode::InsufficientLiquidity);

    // VULNERABILITY: Callback to user before updating reserves
    let callback_ix = /* notify user of swap */;
    invoke(&callback_ix, &accounts)?;  // User can re-enter

    // Update reserves (too late!)
    ctx.accounts.pool.reserve_in += amount_in;
    ctx.accounts.pool.reserve_out -= amount_out;
    Ok(())
}
```

### Lending Protocol Liquidations

Liquidation functions are high-value targets:

```rust
// VULNERABLE: Liquidation with callback
pub fn liquidate(ctx: Context<Liquidate>, debt_amount: u64) -> Result<()> {
    let position = &ctx.accounts.position;

    // Check if position is liquidatable
    require!(is_undercollateralized(position), ErrorCode::NotLiquidatable);

    // Calculate collateral to seize
    let collateral_amount = calculate_collateral(debt_amount);

    // VULNERABILITY: CPI to liquidator before updating position
    let seize_ix = /* transfer collateral to liquidator */;
    invoke(&seize_ix, &accounts)?;  // Liquidator can re-enter

    // Update position (too late!)
    ctx.accounts.position.debt -= debt_amount;
    ctx.accounts.position.collateral -= collateral_amount;
    Ok(())
}
```

### Flash Loan Callbacks

Flash loans are inherently callback-based:

```rust
// VULNERABLE: Flash loan implementation
pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
    let pool = &ctx.accounts.pool;

    // Record pre-loan state
    let balance_before = pool.balance;

    // Transfer tokens to borrower
    transfer_tokens(ctx, amount)?;

    // VULNERABILITY: Borrower callback - they WILL call external code
    let callback_ix = /* execute borrower's callback */;
    invoke(&callback_ix, &accounts)?;  // Borrower has full control here

    // Check repayment (vulnerable if callback can manipulate pool state)
    require!(pool.balance >= balance_before + fee, ErrorCode::NotRepaid);
    Ok(())
}

// SECURE: Flash loan with state protection
pub fn flash_loan_secure(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
    let pool = &mut ctx.accounts.pool;

    // SECURITY: Set loan active flag
    require!(!pool.loan_active, ErrorCode::ReentrancyDetected);
    pool.loan_active = true;

    // Record balance
    let balance_before = pool.balance;

    // Transfer and callback
    transfer_tokens(ctx, amount)?;
    invoke(&callback_ix, &accounts)?;

    // Clear flag and verify
    pool.loan_active = false;
    require!(pool.balance >= balance_before + fee, ErrorCode::NotRepaid);
    Ok(())
}
```

### NFT Marketplace Callbacks

NFT transfers often include receiver callbacks:

```rust
// VULNERABLE: NFT sale with callback
pub fn execute_sale(ctx: Context<ExecuteSale>, price: u64) -> Result<()> {
    let listing = &ctx.accounts.listing;

    // Validate sale
    require!(listing.price == price, ErrorCode::PriceMismatch);

    // VULNERABILITY: Transfer NFT (may have on_receive callback)
    let transfer_ix = nft_program::transfer(/* ... */);
    invoke(&transfer_ix, &accounts)?;  // Buyer's on_receive can re-enter

    // Mark as sold (too late!)
    ctx.accounts.listing.sold = true;

    // Transfer payment to seller
    transfer_sol(ctx, price)?;
    Ok(())
}
```

---

## Defense Pattern Selection Guide

### Decision Flowchart

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                   CPI Re-entrancy Defense Decision Guide                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │  Does your instruction make    │
                    │  any CPI calls?                │
                    └────────────────────────────────┘
                           │                │
                          NO               YES
                           │                │
                           ▼                ▼
              ┌────────────────┐   ┌────────────────────────────┐
              │ No re-entrancy │   │ ALWAYS apply CEI pattern:  │
              │ risk from CPI  │   │ Update state before CPI    │
              └────────────────┘   └────────────────────────────┘
                                               │
                                               ▼
                              ┌────────────────────────────────┐
                              │  Can the invoked program be    │
                              │  controlled by attackers?      │
                              └────────────────────────────────┘
                                     │                │
                                    YES              NO
                                     │                │
                                     ▼                ▼
                        ┌────────────────┐   ┌────────────────────────┐
                        │ HIGH RISK:     │   │ Can you allowlist the  │
                        │ Add re-entrancy│   │ invoked programs?      │
                        │ guard          │   └────────────────────────┘
                        └────────────────┘          │           │
                                                   YES         NO
                                                    │           │
                                                    ▼           ▼
                                      ┌──────────────────┐  ┌────────────────┐
                                      │ Implement CPI    │  │ Add re-entrancy│
                                      │ restrictions +   │  │ guard for      │
                                      │ CEI pattern      │  │ defense-in-    │
                                      └──────────────────┘  │ depth          │
                                                            └────────────────┘

    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  RULE OF THUMB:                                                          ║
    ║  If in doubt, add a re-entrancy guard. The cost (1 byte per account)    ║
    ║  is negligible compared to the risk of exploitation.                     ║
    ╚══════════════════════════════════════════════════════════════════════════╝
```

### When to Use CEI (Checks-Effects-Interactions)

**Always.** CEI is the baseline defense that should be applied to every function making CPIs.

```rust
pub fn any_function_with_cpi(ctx: Context<Op>, param: u64) -> Result<()> {
    // CHECKS: All validation
    require!(condition, Error);

    // EFFECTS: All state updates
    ctx.accounts.account.field = new_value;

    // INTERACTIONS: All external calls last
    invoke(&ix, &accounts)?;

    Ok(())
}
```

**Exceptions where CEI might be difficult:**
- Need to use CPI result to calculate state update → Use re-entrancy guard
- Complex multi-step operations → Use re-entrancy guard + account locking
- Flash loans (callback is in the middle by design) → Use re-entrancy guard

### When to Add Re-entrancy Guards

Add a re-entrancy guard when:

1. **The CPI target is user-controlled**
   ```rust
   // User passes in the callback program - MUST have guard
   pub callback_program: UncheckedAccount<'info>,
   ```

2. **CEI pattern is not feasible**
   ```rust
   // Need CPI result before state update
   let result = invoke_and_get_result(&ix)?;
   ctx.accounts.state.value = process_result(result);  // Can't move before CPI
   ```

3. **Multiple related operations could be interleaved**
   ```rust
   // Deposit and withdraw on same vault - guard prevents interleaving
   pub fn deposit() { ... }
   pub fn withdraw() { /* guard blocks re-entry from deposit callback */ }
   ```

4. **High-value operations**
   ```rust
   // Any operation involving significant value transfer
   // Add guard even if CEI is already applied (defense in depth)
   ```

### When to Use Account Locking

Use account locking for:

1. **Multi-transaction operations**
   ```rust
   // Two-phase commit pattern
   pub fn initiate_withdrawal() {
       vault.locked = true;
       vault.pending_withdrawal = amount;
   }

   pub fn complete_withdrawal() {
       require!(vault.locked, Error);
       // ... complete operation ...
       vault.locked = false;
   }
   ```

2. **Time-sensitive operations**
   ```rust
   vault.locked_until = clock.unix_timestamp + 3600;  // 1 hour lock
   ```

3. **Cross-program atomic operations**
   ```rust
   // Lock while coordinating with external protocol
   vault.locked = true;
   invoke(&external_protocol_ix)?;
   vault.locked = false;
   ```

### When to Use CPI Restrictions

Use CPI restrictions when:

1. **You know all valid callback targets**
   ```rust
   const ALLOWED_CALLBACKS: [&str; 2] = ["ProgramA", "ProgramB"];
   require!(ALLOWED_CALLBACKS.contains(&callback.key().to_string()), Error);
   ```

2. **Integrating with specific protocols**
   ```rust
   // Only allow calls to known DEX or lending protocols
   require!(
       callback.key() == RAYDIUM_PROGRAM_ID ||
       callback.key() == ORCA_PROGRAM_ID,
       Error
   );
   ```

3. **Building composable but controlled systems**
   ```rust
   // Governance can add/remove allowed programs
   require!(allowed_programs.contains(&callback.key()), Error);
   ```

### Defense Combinations

**Recommended combinations by use case:**

| Use Case | CEI | Re-entrancy Guard | Account Lock | CPI Restrict |
|----------|-----|-------------------|--------------|--------------|
| Simple withdrawal | ✓ | Optional | - | - |
| Vault with callbacks | ✓ | ✓ | - | - |
| Flash loan | ✓ | ✓ | - | - |
| Multi-tx operation | ✓ | ✓ | ✓ | - |
| Known integrations | ✓ | ✓ | - | ✓ |
| High-security vault | ✓ | ✓ | ✓ | ✓ |

---

## Implementation Examples

### Complete Secure Vault Implementation

```rust
use anchor_lang::prelude::*;

declare_id!("SecureVault111111111111111111111111111111111");

#[program]
pub mod secure_vault {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.reentrancy_guard = false;
        vault.bump = ctx.bumps.vault;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // SECURITY: Even deposits could be re-entrant in complex scenarios
        require!(!vault.reentrancy_guard, ErrorCode::ReentrancyDetected);
        vault.reentrancy_guard = true;

        // CHECKS
        require!(amount > 0, ErrorCode::InvalidAmount);
        require!(amount <= MAX_DEPOSIT, ErrorCode::ExceedsLimit);

        // EFFECTS
        vault.balance = vault.balance
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        // INTERACTIONS (if any)
        // ... CPI calls would go here ...

        vault.reentrancy_guard = false;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let user = &mut ctx.accounts.user_account;

        // SECURITY: Re-entrancy guard - FIRST CHECK
        require!(!vault.reentrancy_guard, ErrorCode::ReentrancyDetected);

        // SECURITY: Set guard immediately
        vault.reentrancy_guard = true;

        // CHECKS: All validation before any state changes
        require!(amount > 0, ErrorCode::InvalidAmount);
        require!(vault.balance >= amount, ErrorCode::InsufficientBalance);
        require!(user.balance >= amount, ErrorCode::InsufficientUserBalance);

        // EFFECTS: Update ALL state before CPI
        vault.balance = vault.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;
        user.balance = user.balance
            .checked_sub(amount)
            .ok_or(ErrorCode::Underflow)?;

        // INTERACTIONS: CPI after state is consistent
        if ctx.accounts.callback_program.key() != System::id() {
            // SECURITY: Optional - validate callback program
            // require!(is_allowed_callback(&ctx.accounts.callback_program), ErrorCode::InvalidCallback);

            let callback_ix = build_callback_instruction(
                ctx.accounts.callback_program.key(),
                amount,
            );

            invoke(
                &callback_ix,
                &[
                    ctx.accounts.vault.to_account_info(),
                    ctx.accounts.user_account.to_account_info(),
                ],
            )?;
        }

        // SECURITY: Clear guard after all operations
        let vault = &mut ctx.accounts.vault;
        vault.reentrancy_guard = false;

        emit!(WithdrawalEvent {
            user: ctx.accounts.authority.key(),
            amount,
            remaining_balance: vault.balance,
        });

        Ok(())
    }
}

// Constants
const MAX_DEPOSIT: u64 = 1_000_000_000_000; // 1 trillion lamports

// Account structures
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
    pub reentrancy_guard: bool,
    pub bump: u8,
}

#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

// Error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Re-entrancy detected")]
    ReentrancyDetected,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Amount exceeds limit")]
    ExceedsLimit,
    #[msg("Insufficient vault balance")]
    InsufficientBalance,
    #[msg("Insufficient user balance")]
    InsufficientUserBalance,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Arithmetic underflow")]
    Underflow,
    #[msg("Invalid callback program")]
    InvalidCallback,
}

// Events
#[event]
pub struct WithdrawalEvent {
    pub user: Pubkey,
    pub amount: u64,
    pub remaining_balance: u64,
}
```

### Testing for Re-entrancy

```typescript
import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";

describe("Re-entrancy Protection Tests", () => {
  // ... setup ...

  it("blocks re-entrant withdrawal attempts", async () => {
    // This test simulates what happens when an attacker tries to re-enter

    // Setup: Create vault with balance
    await program.methods.initialize().accounts({ /* ... */ }).rpc();
    await program.methods.deposit(new BN(1000)).accounts({ /* ... */ }).rpc();

    // Attempt: Try to withdraw with a malicious callback that would re-enter
    // The callback program should attempt to call withdraw again

    // Expected: ReentrancyDetected error from the guard
    try {
      await program.methods
        .withdraw(new BN(500))
        .accounts({
          vault: vaultPda,
          userAccount: userAccountPda,
          authority: attacker.publicKey,
          callbackProgram: maliciousCallbackProgram,
        })
        .signers([attacker])
        .rpc();

      // If we reach here, the re-entrancy guard failed
      expect.fail("Should have thrown ReentrancyDetected");
    } catch (error) {
      // Verify the error is the re-entrancy guard, not some other failure
      expect(error.message).to.include("ReentrancyDetected");
    }
  });

  it("allows legitimate sequential withdrawals", async () => {
    // Verify that the guard doesn't break normal operations
    await program.methods.deposit(new BN(1000)).accounts({ /* ... */ }).rpc();

    // First withdrawal
    await program.methods.withdraw(new BN(300)).accounts({ /* ... */ }).rpc();

    // Second withdrawal (should work - guard was cleared)
    await program.methods.withdraw(new BN(300)).accounts({ /* ... */ }).rpc();

    // Verify final balance
    const vault = await program.account.vault.fetch(vaultPda);
    expect(vault.balance.toNumber()).to.equal(400);
  });

  it("maintains consistency under CEI pattern", async () => {
    // Verify that state is updated before CPI

    const initialBalance = (await program.account.vault.fetch(vaultPda)).balance;
    const withdrawAmount = new BN(100);

    // The callback will check if vault balance is already decremented
    // If CEI is implemented correctly, it should see the updated balance
    await program.methods
      .withdraw(withdrawAmount)
      .accounts({
        callbackProgram: balanceCheckingCallbackProgram,
        // ... other accounts
      })
      .rpc();

    // If the callback didn't throw, CEI is working correctly
  });
});
```

---

## References

### Official Solana Documentation
- [Solana Program Model](https://solana.com/docs/core/programs)
- [Cross-Program Invocations](https://solana.com/docs/core/cpi)
- [Solana Runtime](https://solana.com/docs/core/runtime)
- [Compute Budget](https://solana.com/docs/core/fees)

### Anchor Framework
- [Anchor Book - CPIs](https://www.anchor-lang.com/docs/cross-program-invocations)
- [Anchor Security Considerations](https://book.anchor-lang.com/anchor_references/security_considerations.html)

### Security Research
- [Sealevel Attacks Repository](https://github.com/coral-xyz/sealevel-attacks) - Solana vulnerability patterns
- [Neodyme Blog](https://blog.neodyme.io) - Solana security research
- [OtterSec Blog](https://osec.io/blog) - Solana audit findings

### Ethereum Historical Context
- [The DAO Hack Analysis](https://blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability)
- [OpenZeppelin ReentrancyGuard](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard)
- [Solidity by Example - Re-entrancy](https://solidity-by-example.org/hacks/re-entrancy/)

### Related Patterns in This Repository
- [Pattern 04: CPI Re-entrancy](/patterns/04-cpi-reentrancy/README.md) - Hands-on examples
- [Pattern 01: Missing Validation](/patterns/01-missing-validation/README.md) - Input validation
- [Pattern 02: Authority Checks](/patterns/02-authority-checks/README.md) - Access control
- [Pattern 03: Unsafe Arithmetic](/patterns/03-unsafe-arithmetic/README.md) - Safe arithmetic

---

*This document is part of the Solana Security Patterns educational repository.*
