# Deep Dive: Unsafe Arithmetic in Solana Programs

> **Educational Resource** - This document provides comprehensive coverage of arithmetic vulnerabilities in Solana programs, including Rust's arithmetic behavior, common vulnerable patterns, and defensive programming techniques.

## Table of Contents

1. [Rust Arithmetic Behavior](#rust-arithmetic-behavior)
   - [Debug vs Release Mode](#debug-vs-release-mode)
   - [Overflow-Checks Cargo Profile](#overflow-checks-cargo-profile)
   - [Solana's Release Mode Compilation](#solanas-release-mode-compilation)
   - [Code Examples: Debug vs Release](#code-examples-debug-vs-release)
   - [Wraparound Behavior Diagram](#wraparound-behavior-diagram)

2. [Arithmetic Methods Comparison](#arithmetic-methods-comparison)
   - [Comparison Table](#comparison-table)
   - [wrapping_* Methods](#wrapping_-methods)
   - [checked_* Methods](#checked_-methods)
   - [saturating_* Methods](#saturating_-methods)
   - [overflowing_* Methods](#overflowing_-methods)
   - [Decision Flowchart](#decision-flowchart)

3. [Common Vulnerable Patterns](#common-vulnerable-patterns)
   - [Reward Calculations](#reward-calculations)
   - [Fee Subtraction](#fee-subtraction)
   - [Balance Transfers](#balance-transfers)
   - [Limit Counters](#limit-counters)

4. [Real-World Incidents](#real-world-incidents)
   - [Solana Ecosystem](#solana-ecosystem)
   - [Ethereum Context: batchOverflow](#ethereum-context-batchoverflow)
   - [Lessons Learned](#lessons-learned)

5. [Framework Assistance](#framework-assistance)
   - [Anchor's Role in Arithmetic Safety](#anchors-role-in-arithmetic-safety)
   - [Pinocchio Comparison](#pinocchio-comparison)
   - [Framework-Agnostic Truths](#framework-agnostic-truths)
   - [Arithmetic Safety Checklist](#arithmetic-safety-checklist)

6. [References](#references)

---

## Rust Arithmetic Behavior

### Debug vs Release Mode

Rust's standard arithmetic operators (`+`, `-`, `*`) behave differently depending on the compilation mode:

| Mode | Behavior on Overflow/Underflow | Default Profile |
|------|-------------------------------|-----------------|
| **Debug** | Panic (program terminates) | `cargo build` |
| **Release** | Silent wraparound | `cargo build --release` |

This inconsistency is a common source of vulnerabilities. Code that works perfectly in debug mode (panicking on overflow) silently wraps in release mode, potentially allowing attackers to exploit integer boundaries.

### Overflow-Checks Cargo Profile

Rust provides the `overflow-checks` profile setting to control this behavior:

```toml
# Cargo.toml
[profile.release]
overflow-checks = true  # Panic on overflow even in release mode
```

When `overflow-checks = true`:
- Standard operators will panic on overflow in release mode
- Provides safety similar to debug mode
- Small performance cost (~2-5% depending on arithmetic intensity)

**Important:** Even with `overflow-checks = true`, explicit `wrapping_*` methods will still wrap silently - this setting only affects standard operators.

### Solana's Release Mode Compilation

Solana programs are **always compiled in release mode** for deployment:

```bash
# Solana build command (used by Anchor)
cargo build-sbf  # Builds in release mode by default
```

**Security Implications:**

1. **Default behavior is dangerous**: Without `overflow-checks = true`, arithmetic silently wraps
2. **Testing may miss vulnerabilities**: If you test with `cargo test` (debug mode), overflow panics but production code wraps
3. **Explicit safety required**: Must use `checked_*` methods or enable `overflow-checks`

**Recommendation for Solana Projects:**

```toml
[profile.release]
overflow-checks = true  # Enable overflow checking
lto = "fat"             # Link-time optimization (standard for Solana)
codegen-units = 1       # Single codegen unit (standard for Solana)
```

### Code Examples: Debug vs Release

```rust
// Example: Standard addition behavior
fn demonstrate_modes() {
    let a: u64 = u64::MAX;
    let b: u64 = 1;

    // In DEBUG mode: PANIC! "attempt to add with overflow"
    // In RELEASE mode (default): Returns 0 (wrapped)
    // In RELEASE mode (overflow-checks=true): PANIC!
    let result = a + b;
}

// Example: Why this matters in Solana
pub fn process_deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // User has deposited near u64::MAX already
    // Attacker deposits 1 more

    // DANGEROUS: In release mode, this wraps to near-zero!
    ctx.accounts.vault.total_deposits += amount;

    // Now attacker can withdraw as if vault had tiny balance
    Ok(())
}
```

### Wraparound Behavior Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        u64 Number Line with Wraparound                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   0                                                           u64::MAX       │
│   │                                                               │          │
│   ▼                                                               ▼          │
│   ├───────────────────────────────────────────────────────────────┤          │
│   │                                                               │          │
│   │         Normal arithmetic stays within bounds                 │          │
│   │                                                               │          │
│   └───────────────────────────────────────────────────────────────┘          │
│                                                                              │
│   OVERFLOW WRAPAROUND:                                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  u64::MAX + 1 = 0                                                   │   │
│   │                                                                     │   │
│   │  u64::MAX ────────┐                                                 │   │
│   │                   │  +1                                             │   │
│   │                   ▼                                                 │   │
│   │  0 ◄──────────────┘ (wraps around)                                  │   │
│   │                                                                     │   │
│   │  Example: 18446744073709551615 + 1 = 0                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   UNDERFLOW WRAPAROUND:                                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  0 - 1 = u64::MAX                                                   │   │
│   │                                                                     │   │
│   │  0 ────────────────┐                                                │   │
│   │                    │  -1                                            │   │
│   │                    ▼                                                │   │
│   │  u64::MAX ◄────────┘ (wraps around)                                 │   │
│   │                                                                     │   │
│   │  Example: 0 - 1 = 18446744073709551615                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   MULTIPLICATION OVERFLOW:                                                   │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  Large numbers multiply to wrap multiple times                      │   │
│   │                                                                     │   │
│   │  Example: 10^19 * 2 = 1553255926290448384 (not 2×10^19)             │   │
│   │                                                                     │   │
│   │  The result is: (10^19 * 2) mod (2^64)                              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Arithmetic Methods Comparison

### Comparison Table

| Method Family | Return Type | On Overflow/Underflow | Performance | Use Case |
|--------------|-------------|----------------------|-------------|----------|
| `+`, `-`, `*` | `T` | Panic (debug) / Wrap (release) | Fastest | **Never use in Solana without overflow-checks** |
| `wrapping_add/sub/mul` | `T` | Always wraps silently | Fast | **Only for demonstrating vulnerabilities** |
| `checked_add/sub/mul` | `Option<T>` | Returns `None` | Slightly slower | **Recommended for most operations** |
| `saturating_add/sub/mul` | `T` | Clamps to MIN/MAX | Fast | Non-critical counters, metrics |
| `overflowing_add/sub/mul` | `(T, bool)` | Returns value + overflow flag | Fast | When you need both result and detection |

### wrapping_* Methods

**Behavior:** Always perform wraparound arithmetic, regardless of compilation mode.

```rust
// wrapping_add: Addition with wraparound
let max = u64::MAX;  // 18446744073709551615
let result = max.wrapping_add(1);  // Returns 0

// wrapping_sub: Subtraction with wraparound
let zero = 0u64;
let result = zero.wrapping_sub(1);  // Returns u64::MAX

// wrapping_mul: Multiplication with wraparound
let large = u64::MAX / 2;
let result = large.wrapping_mul(3);  // Wraps around
```

**When to use:**
- **Never in production code** for financial calculations
- Only for educational demonstrations of vulnerabilities
- Cryptographic operations that require defined wraparound

### checked_* Methods

**Behavior:** Return `Option<T>` - `Some(result)` on success, `None` on overflow.

```rust
// checked_add: Safe addition
let max = u64::MAX;
match max.checked_add(1) {
    Some(result) => println!("Result: {}", result),
    None => return Err(ProgramError::ArithmeticOverflow),
}

// Idiomatic Anchor pattern with .ok_or()
let new_balance = current_balance
    .checked_add(deposit_amount)
    .ok_or(ErrorCode::ArithmeticOverflow)?;

// Multiple operations chained
let result = base_amount
    .checked_mul(multiplier)
    .and_then(|v| v.checked_add(bonus))
    .ok_or(ErrorCode::ArithmeticOverflow)?;
```

**When to use:**
- **Recommended for all financial calculations**
- Token balances, deposits, withdrawals
- Any operation where overflow indicates an error condition

### saturating_* Methods

**Behavior:** Clamp to MIN or MAX bounds instead of wrapping.

```rust
// saturating_add: Clamps to MAX
let max = u64::MAX;
let result = max.saturating_add(1);  // Returns u64::MAX (not 0)

// saturating_sub: Clamps to MIN (0 for unsigned)
let small = 5u64;
let result = small.saturating_sub(10);  // Returns 0 (not u64::MAX - 4)

// saturating_mul: Clamps to MAX
let large = u64::MAX / 2;
let result = large.saturating_mul(3);  // Returns u64::MAX
```

**When to use:**
- Non-critical counters and metrics
- Statistics that can tolerate clamping
- UI display values
- **Not recommended for financial calculations** (masks overflow condition)

### overflowing_* Methods

**Behavior:** Return a tuple `(result, overflow_flag)`.

```rust
// overflowing_add: Returns (wrapped_result, did_overflow)
let max = u64::MAX;
let (result, overflowed) = max.overflowing_add(1);
// result = 0, overflowed = true

if overflowed {
    return Err(ProgramError::ArithmeticOverflow);
}

// Useful when you need the wrapped value for logging/debugging
let (result, overflowed) = amount.overflowing_mul(rate);
if overflowed {
    msg!("Overflow detected! Wrapped result would be: {}", result);
    return Err(ErrorCode::CalculationOverflow);
}
```

**When to use:**
- When you need to log or inspect the wrapped value
- Complex calculations requiring overflow detection with result access
- Generally prefer `checked_*` for simpler code

### Decision Flowchart

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Which Arithmetic Method Should I Use?                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │  Is this a financial/security  │
                    │  critical calculation?         │
                    └────────────────────────────────┘
                           │                │
                          YES              NO
                           │                │
                           ▼                ▼
              ┌────────────────┐    ┌────────────────────────┐
              │  Use checked_* │    │  Is clamping behavior  │
              │  methods with  │    │  acceptable?           │
              │  error handling│    └────────────────────────┘
              └────────────────┘           │           │
                                          YES         NO
                                           │           │
                                           ▼           ▼
                              ┌──────────────────┐  ┌────────────────┐
                              │ Use saturating_* │  │ Use checked_*  │
                              │ (counters, stats)│  │ or overflowing_│
                              └──────────────────┘  └────────────────┘

    ╔══════════════════════════════════════════════════════════════════════╗
    ║  NEVER USE IN PRODUCTION:                                            ║
    ║  • Standard operators (+, -, *) without overflow-checks = true       ║
    ║  • wrapping_* methods for financial calculations                     ║
    ╚══════════════════════════════════════════════════════════════════════╝
```

---

## Common Vulnerable Patterns

### Reward Calculations

Reward calculations are particularly vulnerable because they often involve multiplication of user-controlled values with system rates.

**Vulnerable Pattern:**
```rust
// VULNERABILITY: Reward rate multiplication can overflow
pub fn calculate_rewards(
    ctx: Context<CalculateRewards>,
    staked_amount: u64,
) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // VULNERABILITY: No overflow protection
    // If staked_amount is large, this wraps to a small number
    let reward = staked_amount.wrapping_mul(vault.reward_rate);

    // VULNERABILITY: Adding wrapped (small) reward to balance
    vault.total_rewards = vault.total_rewards.wrapping_add(reward);

    Ok(())
}
```

**Attack Scenario:**
```
Initial state:
- reward_rate = 100 (100x multiplier)
- staked_amount = 184467440737095517 (carefully chosen)

Calculation:
- 184467440737095517 * 100 = overflow!
- Wrapped result: 184467440737095517 * 100 mod 2^64 = 1700
- User gets much less reward than entitled (denial of service)

OR with different values:
- staked_amount = u64::MAX / 50
- Result wraps to a value that benefits attacker
```

**Secure Pattern:**
```rust
// SECURITY: Safe reward calculation
pub fn calculate_rewards(
    ctx: Context<CalculateRewards>,
    staked_amount: u64,
) -> Result<()> {
    let vault = &mut ctx.accounts.vault;

    // SECURITY: Validate input bounds
    require!(
        staked_amount <= MAX_STAKE_AMOUNT,
        ErrorCode::ExceedsMaxStake
    );

    // SECURITY: Use checked multiplication
    let reward = staked_amount
        .checked_mul(vault.reward_rate)
        .ok_or(ErrorCode::RewardCalculationOverflow)?;

    // SECURITY: Use checked addition
    vault.total_rewards = vault.total_rewards
        .checked_add(reward)
        .ok_or(ErrorCode::RewardCalculationOverflow)?;

    Ok(())
}
```

### Fee Subtraction

Fee calculations are vulnerable to underflow when subtracting fees from amounts.

**Vulnerable Pattern:**
```rust
// VULNERABILITY: Fee subtraction can underflow
pub fn transfer_with_fee(
    ctx: Context<Transfer>,
    amount: u64,
) -> Result<()> {
    let fee = calculate_fee(amount);  // e.g., 1% fee

    // VULNERABILITY: What if fee > amount due to rounding or manipulation?
    let net_amount = amount.wrapping_sub(fee);

    // VULNERABILITY: net_amount could be massive (wrapped)
    // User receives way more than they should
    transfer_tokens(ctx, net_amount)?;

    Ok(())
}
```

**Attack Scenario:**
```
If fee calculation has rounding issues:
- amount = 50 lamports
- fee = calculate_fee(50) = 51 lamports (due to minimum fee)

Calculation:
- 50 - 51 = underflow!
- Wrapped result: u64::MAX (18446744073709551615)
- Transfer attempts to send massive amount
```

**Secure Pattern:**
```rust
// SECURITY: Safe fee subtraction
pub fn transfer_with_fee(
    ctx: Context<Transfer>,
    amount: u64,
) -> Result<()> {
    let fee = calculate_fee(amount);

    // SECURITY: Explicit validation that fee doesn't exceed amount
    require!(
        fee <= amount,
        ErrorCode::FeeExceedsAmount
    );

    // SECURITY: Use checked subtraction
    let net_amount = amount
        .checked_sub(fee)
        .ok_or(ErrorCode::FeeCalculationUnderflow)?;

    transfer_tokens(ctx, net_amount)?;

    Ok(())
}
```

### Balance Transfers

Balance transfers are a classic overflow/underflow target.

**Vulnerable Pattern:**
```rust
// VULNERABILITY: Unchecked balance updates
pub fn transfer(
    ctx: Context<Transfer>,
    amount: u64,
) -> Result<()> {
    let from = &mut ctx.accounts.from_account;
    let to = &mut ctx.accounts.to_account;

    // VULNERABILITY: No check that from.balance >= amount
    // VULNERABILITY: Underflow wraps to massive balance
    from.balance = from.balance.wrapping_sub(amount);

    // VULNERABILITY: Overflow could wrap recipient's balance to small value
    to.balance = to.balance.wrapping_add(amount);

    Ok(())
}
```

**Attack Scenario:**
```
Attacker's balance: 100 tokens
Victim's balance: 0 tokens
Transfer amount: 200 tokens

Without protection:
- Attacker balance: 100 - 200 = underflow = u64::MAX - 99
- Attacker now has massive balance!

Or overflow attack:
- Victim balance near u64::MAX
- Small deposit wraps to tiny balance
- Victim loses funds
```

**Secure Pattern:**
```rust
// SECURITY: Fully protected balance transfer
pub fn transfer(
    ctx: Context<Transfer>,
    amount: u64,
) -> Result<()> {
    let from = &mut ctx.accounts.from_account;
    let to = &mut ctx.accounts.to_account;

    // SECURITY: Validate sufficient balance
    require!(
        from.balance >= amount,
        ErrorCode::InsufficientBalance
    );

    // SECURITY: Use checked arithmetic for both operations
    from.balance = from.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::BalanceUnderflow)?;

    to.balance = to.balance
        .checked_add(amount)
        .ok_or(ErrorCode::BalanceOverflow)?;

    Ok(())
}
```

### Limit Counters

Counters used for rate limiting or quotas can be manipulated through overflow.

**Vulnerable Pattern:**
```rust
// VULNERABILITY: Counter overflow bypasses limits
pub fn increment_usage(
    ctx: Context<Usage>,
    operations: u64,
) -> Result<()> {
    let user = &mut ctx.accounts.user;

    // VULNERABILITY: Counter can wrap, resetting limits
    user.operations_count = user.operations_count.wrapping_add(operations);

    // This check passes after overflow wraps the counter!
    require!(
        user.operations_count <= MAX_DAILY_OPERATIONS,
        ErrorCode::RateLimitExceeded
    );

    Ok(())
}
```

**Attack Scenario:**
```
Rate limit: 1000 operations per day
Current count: 999

Attacker requests: u64::MAX - 998 operations
After wrapping: 999 + (u64::MAX - 998) = 0 (wrapped)

Now attacker's counter is reset to 0!
They can continue making unlimited operations.
```

**Secure Pattern:**
```rust
// SECURITY: Protected counter increment
pub fn increment_usage(
    ctx: Context<Usage>,
    operations: u64,
) -> Result<()> {
    let user = &mut ctx.accounts.user;

    // SECURITY: Calculate new count with checked arithmetic
    let new_count = user.operations_count
        .checked_add(operations)
        .ok_or(ErrorCode::CounterOverflow)?;

    // SECURITY: Validate against limit BEFORE updating
    require!(
        new_count <= MAX_DAILY_OPERATIONS,
        ErrorCode::RateLimitExceeded
    );

    user.operations_count = new_count;

    Ok(())
}
```

---

## Real-World Incidents

### Solana Ecosystem

While many Solana exploits involve different vulnerability classes (e.g., missing signer checks, incorrect PDA derivation), arithmetic vulnerabilities have been identified in audits:

**Audit Findings (General Patterns):**
- Multiple DeFi protocols identified with unchecked arithmetic in reward calculations
- LP token calculations without overflow protection
- Fee distributions vulnerable to precision loss and overflow

**Note:** Specific incident details are often not publicly disclosed for responsible disclosure reasons. The patterns documented above are based on common audit findings and theoretical attack vectors.

### Ethereum Context: batchOverflow

The **batchOverflow** vulnerability (CVE-2018-10299) affected multiple ERC-20 tokens in April 2018:

**Vulnerability:**
```solidity
// Vulnerable Solidity code (simplified)
function batchTransfer(address[] _receivers, uint256 _value) public {
    uint256 amount = _receivers.length * _value;  // OVERFLOW HERE
    require(balances[msg.sender] >= amount);

    balances[msg.sender] -= amount;
    for (uint i = 0; i < _receivers.length; i++) {
        balances[_receivers[i]] += _value;
    }
}
```

**Attack:**
- `_receivers.length = 2`
- `_value = 2^255` (very large number)
- `amount = 2 * 2^255 = 0` (overflow!)
- Balance check passes (sender has >= 0)
- Recipients each receive `2^255` tokens

**Impact:**
- Billions of dollars worth of tokens at risk
- Multiple exchanges suspended trading
- Demonstrated the critical importance of safe arithmetic

### Lessons Learned

1. **Always use safe arithmetic functions** - Never trust standard operators in financial code
2. **Defense in depth** - Combine input validation with checked arithmetic
3. **Test with boundary values** - Include u64::MAX, 0, and near-boundary values in tests
4. **Audit multiplication first** - Multiplication overflows are easier to trigger than addition
5. **Consider all code paths** - Underflow in error paths can be just as dangerous
6. **Enable overflow-checks** - Extra safety layer at minimal performance cost

---

## Framework Assistance

A common misconception among Solana developers is that using a framework like Anchor automatically provides arithmetic safety. This section clarifies exactly what frameworks provide versus what developers must implement themselves.

### Anchor's Role in Arithmetic Safety

Anchor is a popular Solana development framework that provides significant developer experience improvements. However, it's crucial to understand that **Anchor does NOT provide built-in arithmetic safety**.

#### What Anchor Provides

| Feature | Purpose | Example |
|---------|---------|---------|
| `#[error_code]` | Define custom error enums with auto-generated codes | `ArithmeticOverflow = 6000` |
| `require!()` | Concise input validation macro | `require!(amount <= MAX, ErrorCode::...)` |
| Error integration | `ErrorCode` works with `?` operator | `.ok_or(ErrorCode::ArithmeticOverflow)?` |
| `constraint` | Account-level pre-validation | `#[account(constraint = balance > 0)]` |

#### What Anchor Does NOT Provide

| Missing Feature | Reality |
|-----------------|---------|
| Safe arithmetic methods | **Rust stdlib** provides `checked_*`, `saturating_*`, etc. |
| Automatic overflow detection | You must manually call safe arithmetic methods |
| Numeric limit definitions | You must define constants like `MAX_DEPOSIT` |
| Input range validation logic | You must write the validation code |
| Compile-time arithmetic safety | All protections are runtime checks |

#### Anchor Error Handling Example

```rust
use anchor_lang::prelude::*;

// ANCHOR: Declarative error code definition
#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,
    #[msg("Deposit amount exceeds maximum allowed")]
    ExceedsMaxDeposit,
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
}

// YOUR CODE: Define safe limits (not provided by Anchor)
const MAX_DEPOSIT: u64 = 1_000_000_000;

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // ANCHOR: require!() macro for validation
    require!(amount <= MAX_DEPOSIT, ErrorCode::ExceedsMaxDeposit);

    // RUST STDLIB: checked_add() - NOT an Anchor feature
    // RUST STDLIB: .ok_or() - standard Option method
    // ANCHOR: ErrorCode integrates with Anchor's error system
    ctx.accounts.vault.balance = ctx.accounts.vault.balance
        .checked_add(amount)
        .ok_or(ErrorCode::ArithmeticOverflow)?;

    Ok(())
}
```

### Pinocchio Comparison

Pinocchio is a lightweight alternative to Anchor that provides minimal abstractions. For arithmetic safety, the comparison is straightforward: **neither framework provides built-in protection**.

#### Side-by-Side Error Handling

**Anchor:**
```rust
#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,
    #[msg("Insufficient balance")]
    InsufficientBalance,
}

// ~10 lines for error definition
```

**Pinocchio:**
```rust
#[derive(Debug)]
pub enum SecureError {
    ArithmeticOverflow,
    InsufficientBalance,
}

impl From<SecureError> for ProgramError {
    fn from(e: SecureError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// ~15-20 lines for error definition + conversion
```

#### Side-by-Side Input Validation

**Anchor:**
```rust
// Single line with require! macro
require!(amount <= MAX_DEPOSIT, ErrorCode::ExceedsMaxDeposit);
```

**Pinocchio:**
```rust
// Explicit if statement
if amount > MAX_DEPOSIT {
    return Err(SecureError::ExceedsMaxDeposit.into());
}
```

#### Side-by-Side Safe Arithmetic

**Anchor:**
```rust
let new_balance = balance
    .checked_add(amount)
    .ok_or(ErrorCode::ArithmeticOverflow)?;
```

**Pinocchio:**
```rust
let new_balance = balance
    .checked_add(amount)
    .ok_or(SecureError::ArithmeticOverflow)?;
```

**Key Observation:** The safe arithmetic code is nearly identical—both use Rust's `checked_add()` from the standard library. The only difference is the error type.

### Framework-Agnostic Truths

Regardless of which framework you use (or if you use no framework at all), these truths apply:

1. **Safe arithmetic comes from Rust, not frameworks**
   - `checked_add()`, `checked_sub()`, `checked_mul()` are std library methods
   - These work identically in Anchor, Pinocchio, or raw Solana programs

2. **You must explicitly call safe methods**
   - No framework wraps standard operators (`+`, `-`, `*`) with safety checks
   - Every arithmetic operation that could overflow needs manual protection

3. **Input validation is always your responsibility**
   - Frameworks provide syntax sugar (`require!` vs `if`) but not the logic
   - You must determine what values are acceptable

4. **Testing is framework-independent**
   - Boundary value testing (0, MAX, overflow points) applies universally
   - Both frameworks can have vulnerable OR secure implementations

#### LOC Comparison for Equivalent Safety

| Component | Anchor | Pinocchio | Difference |
|-----------|--------|-----------|------------|
| Error enum definition | ~10 | ~20 | Anchor is more concise |
| Single validation check | 1 | 3 | Anchor macro reduces boilerplate |
| Safe arithmetic operation | 3 | 3 | Identical (both use Rust stdlib) |
| Total for secure deposit fn | ~15 | ~25 | ~40% less code with Anchor |

**Conclusion:** Anchor reduces boilerplate for error handling and validation, but the core arithmetic safety code is identical because it comes from Rust's standard library, not the framework.

### Arithmetic Safety Checklist

Use this framework-agnostic checklist for any Solana program:

#### Pre-Implementation
- [ ] Define error types for: overflow, underflow, exceeds limit, insufficient balance
- [ ] Define named constants for all numeric limits
- [ ] Document the maximum expected values for all numeric fields
- [ ] Identify every arithmetic operation in the instruction

#### Implementation
- [ ] Validate all inputs against defined limits BEFORE arithmetic
- [ ] Use `checked_add()` for every addition operation
- [ ] Use `checked_sub()` for every subtraction (with prior balance validation)
- [ ] Use `checked_mul()` for every multiplication
- [ ] Use `checked_div()` for every division (also check for divide-by-zero)
- [ ] Handle `None` results with appropriate error types
- [ ] Add `// SECURITY:` comments explaining each protection

#### Post-Implementation Verification
- [ ] Test with `amount = 0`
- [ ] Test with `amount = 1`
- [ ] Test with `amount = MAX_LIMIT`
- [ ] Test with `amount = MAX_LIMIT + 1`
- [ ] Test with `amount = u64::MAX`
- [ ] Test with `balance = 0` and various withdrawal amounts
- [ ] Test with `balance = u64::MAX - 1` and deposit of `2`
- [ ] Verify all error codes are returned correctly
- [ ] Review: "If an attacker controls this input, what's the worst case?"

---

## References

### Official Documentation
- [Rust Book: Integer Overflow](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Rust std::primitive - Arithmetic Methods](https://doc.rust-lang.org/std/primitive.u64.html)
- [Solana Documentation: Developing Programs](https://docs.solana.com/developing/on-chain-programs/developing-rust)

### Security Resources
- [Solana Security Best Practices](https://github.com/coral-xyz/sealevel-attacks)
- [Anchor Book: Security Considerations](https://www.anchor-lang.com/docs/security-considerations)
- [OWASP Integer Overflow](https://owasp.org/www-community/vulnerabilities/Integer_overflow)

### Related Patterns in This Repository
- [Pattern 03: Unsafe Arithmetic](/patterns/03-unsafe-arithmetic/README.md) - Hands-on examples
- [Anchor Framework Features for Arithmetic Safety](/patterns/03-unsafe-arithmetic/README.md#anchor-framework-features-for-arithmetic-safety) - Anchor-specific guidance
- [Token Manipulation Tests](/patterns/03-unsafe-arithmetic/tests/token-manipulation.ts) - SPL Token specific scenarios

<!-- TODO: Add cross-reference to Epic 7 (SPL Token Security) when implemented -->

---

*This document is part of the Solana Security Patterns educational repository.*
