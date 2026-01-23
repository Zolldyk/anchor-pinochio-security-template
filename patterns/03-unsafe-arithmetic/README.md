# Pattern 03: Unsafe Arithmetic

> ## Common Misconception: "Rust Prevents Overflow"
>
> **Myth:** "Rust's safety guarantees mean I don't need to worry about integer overflow."
>
> **Reality:** Rust's overflow behavior depends on compilation mode AND the arithmetic method used:
>
> | Scenario | Standard `+`, `-`, `*` | `wrapping_*` methods |
> |----------|------------------------|---------------------|
> | Debug mode | ✅ Panics | ⚠️ Wraps silently |
> | Release mode (default) | ⚠️ Wraps silently | ⚠️ Wraps silently |
> | Release + `overflow-checks = true` | ✅ Panics | ⚠️ Wraps silently |
>
> **Why this matters for Solana:**
> - Solana programs are **always compiled in release mode**
> - Even with `overflow-checks = true` in `Cargo.toml`, explicit `wrapping_*` methods **always wrap**
> - The vulnerable programs in this pattern use `wrapping_*` to demonstrate what happens in programs without proper protection
> - **Always use `checked_*` methods** for financial calculations - they return `None` on overflow instead of wrapping
>
> **This project's configuration:** The workspace has `overflow-checks = true`, which makes standard operators safe. However, the vulnerable programs explicitly use `wrapping_add()`, `wrapping_sub()`, and `wrapping_mul()` to demonstrate the vulnerability pattern that occurs in unprotected code.

## Vulnerability Description

Integer overflow and underflow vulnerabilities occur when arithmetic operations produce results that exceed the maximum or minimum representable values for a data type. In Solana programs compiled in **release mode**, arithmetic operations wrap silently instead of panicking, creating dangerous security vulnerabilities.

**Key Insight:** Solana programs compile in release mode where `overflow-checks` is disabled by default. This means:
- `balance + deposit` that exceeds `u64::MAX` wraps to a small value
- `balance - withdrawal` that goes below 0 wraps to a huge value (near `u64::MAX`)
- `balance * rate` that exceeds `u64::MAX` wraps to an incorrect value

## Attack Scenario

### Overflow Exploit
1. Attacker deposits a large amount close to `u64::MAX` (e.g., `u64::MAX - 10`)
2. Attacker deposits a small additional amount (e.g., `20`)
3. Balance wraps: `(u64::MAX - 10) + 20 = 9` (silently!)
4. Attacker now has nearly zero balance despite depositing a massive amount

### Underflow Exploit
1. User has small balance (e.g., `100`)
2. Attacker calls withdraw with amount larger than balance (e.g., `200`)
3. Balance wraps: `100 - 200 = u64::MAX - 99` (massive value!)
4. Attacker now has near-maximum balance from a small deposit

### Multiplication Overflow
1. User has large balance (e.g., `2^40`)
2. Calculate rewards with large rate (e.g., `2^30`)
3. Multiplication wraps: `2^40 * 2^30 = 2^70` exceeds `u64::MAX` and wraps
4. User receives incorrect (potentially much less or more) rewards

## Vulnerable Implementation

### Anchor Vulnerable Program
**File:** `programs/vulnerable/src/lib.rs`

```rust
// VULNERABILITY: Uses wrapping arithmetic - will wrap on overflow!
user_balance.balance = user_balance.balance.wrapping_add(amount_to_add);

// VULNERABILITY: Uses wrapping subtraction - will wrap on underflow!
user_balance.balance = user_balance.balance.wrapping_sub(amount_to_subtract);

// VULNERABILITY: Uses wrapping multiplication - will wrap on overflow!
let reward_amount = user_balance.balance.wrapping_mul(reward_rate);
```

### Pinocchio Vulnerable Program
**File:** `pinocchio-programs/pinocchio-vulnerable/src/lib.rs`

Same vulnerability pattern - Pinocchio programs exhibit identical overflow/underflow behavior when using `wrapping_*` methods.

## Secure Implementation

### Anchor Secure Program
**File:** `programs/secure/src/lib.rs`

```rust
// SECURITY: Validate deposit amount against maximum limit
require!(amount_to_add <= MAX_DEPOSIT, ErrorCode::ExceedsMaxDeposit);

// SECURITY: Use checked_add() - returns None on overflow
user_balance.balance = user_balance.balance
    .checked_add(amount_to_add)
    .ok_or(ErrorCode::ArithmeticOverflow)?;

// SECURITY: Validate sufficient balance before subtraction
require!(user_balance.balance >= amount_to_subtract, ErrorCode::InsufficientBalance);

// SECURITY: Use checked_sub() for defense in depth
user_balance.balance = user_balance.balance
    .checked_sub(amount_to_subtract)
    .ok_or(ErrorCode::ArithmeticUnderflow)?;

// SECURITY: Validate reward rate against maximum
require!(reward_rate <= MAX_REWARD_RATE, ErrorCode::ExceedsMaxRewardRate);

// SECURITY: Use checked_mul() - returns None on overflow
let reward_amount = user_balance.balance
    .checked_mul(reward_rate)
    .ok_or(ErrorCode::ArithmeticOverflow)?;
```

### Pinocchio Secure Program
**File:** `pinocchio-programs/pinocchio-secure/src/lib.rs`

```rust
// SECURITY: Validate deposit amount against maximum limit
if amount_to_add > MAX_DEPOSIT {
    return Err(SecureError::ExceedsMaxDeposit.into());
}

// SECURITY: Use checked_add() for balance update
user_balance.balance = user_balance
    .balance
    .checked_add(amount_to_add)
    .ok_or(SecureError::ArithmeticOverflow)?;

// SECURITY: Validate sufficient balance before subtraction
if user_balance.balance < amount_to_subtract {
    return Err(SecureError::InsufficientBalance.into());
}

// SECURITY: Use checked_sub() for defense in depth
user_balance.balance = user_balance
    .balance
    .checked_sub(amount_to_subtract)
    .ok_or(SecureError::ArithmeticUnderflow)?;
```

## Anchor vs Pinocchio Comparison

### Arithmetic Safety Approaches

| Feature | Anchor | Pinocchio |
|---------|--------|-----------|
| Safe arithmetic | `checked_add().ok_or(ErrorCode::...)` | `checked_add().ok_or(SecureError::...)` |
| Error definition | `#[error_code]` enum macro | Custom enum + `impl From<SecureError> for ProgramError` |
| Input validation | `require!(amount <= MAX, ErrorCode::...)` | `if amount > MAX { return Err(...) }` |
| Error propagation | `ErrorCode::ArithmeticOverflow` | `SecureError::ArithmeticOverflow.into()` |

### Code Complexity Comparison

| Metric | Anchor | Pinocchio |
|--------|--------|-----------|
| Error enum definition | ~10 lines (macro) | ~20 lines (manual + impl) |
| Validation check | 1 line (require!) | 3 lines (if + return) |
| Account serialization | Automatic | Manual (~50 lines per struct) |
| Total secure LOC | ~330 lines | ~450 lines |
| Cognitive load | Lower (declarative) | Higher (imperative) |

### Error Message Quality

| Framework | Error Code | Error Message |
|-----------|------------|---------------|
| Anchor | `6000` | "Arithmetic overflow detected" |
| Anchor | `6001` | "Arithmetic underflow detected" |
| Anchor | `6002` | "Insufficient balance for withdrawal" |
| Pinocchio | `Custom(0)` | (Must decode error code manually) |
| Pinocchio | `Custom(1)` | (Must decode error code manually) |
| Pinocchio | `Custom(2)` | (Must decode error code manually) |

### Testing Approach Differences

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Instruction calls | IDL-based type-safe methods | Manual Buffer encoding |
| Account fetching | `program.account.userBalance.fetch()` | Raw `connection.getAccountInfo()` + decode |
| Error handling | Automatic error parsing | Manual error code interpretation |
| Test complexity | Lower | Higher |

## When to Choose Each Framework

### Choose Anchor When:
- Rapid development is priority
- Team has mixed experience levels
- Complex admin/permission systems
- Want automatic error messages
- Need IDL generation for clients

### Choose Pinocchio When:
- Performance-critical (lower CU usage)
- Full control over serialization
- Minimal runtime overhead needed
- Team has strong Rust experience
- Already have custom client code

## Anchor Framework Features for Arithmetic Safety

> **Key Insight:** Anchor helps you handle arithmetic errors elegantly, but does NOT perform safe arithmetic for you. Safe arithmetic comes from Rust's standard library, not Anchor.

### What Anchor Gives You

Anchor provides features that make error handling and validation more ergonomic, but these are **error handling helpers, not arithmetic safety features**.

#### 1. `#[error_code]` Enum for Custom Errors

```rust
// Anchor's declarative error definition
#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,        // 6000
    #[msg("Arithmetic underflow detected")]
    ArithmeticUnderflow,       // 6001
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,       // 6002
    #[msg("Deposit exceeds maximum allowed")]
    ExceedsMaxDeposit,         // 6003
}
```

**What it does:** Generates error codes (starting at 6000) with human-readable messages. The `#[msg()]` attribute creates client-friendly error descriptions.

**What it does NOT do:** Detect arithmetic issues—you must still check for them manually.

#### 2. `require!()` Macro for Input Validation

```rust
// SECURITY: Validate input before arithmetic operations
require!(amount <= MAX_DEPOSIT, ErrorCode::ExceedsMaxDeposit);
require!(user_balance.balance >= amount, ErrorCode::InsufficientBalance);
```

**What it does:** Concise validation syntax that returns an error if the condition is false. Reduces boilerplate compared to manual if/return statements.

**What it does NOT do:** Validate arithmetic results—it validates inputs BEFORE operations, not the operations themselves.

#### 3. `.ok_or()` Pattern for Error Conversion

```rust
// SECURITY: Convert checked arithmetic Option to Anchor Result
let new_balance = current_balance
    .checked_add(amount)
    .ok_or(ErrorCode::ArithmeticOverflow)?;
```

**What it does:** Converts `Option<T>` (from `checked_*` methods) to `Result<T, Error>`, allowing use of the `?` operator for clean error propagation.

**What it does NOT do:** This is a Rust standard library method, not an Anchor feature. Anchor's contribution is the `ErrorCode` type that integrates with its error system.

#### 4. `constraint` Attribute for Account-Level Validation

```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        constraint = user_balance.balance < MAX_BALANCE @ ErrorCode::BalanceAtMaximum
    )]
    pub user_balance: Account<'info, UserBalance>,
}
```

**What it does:** Validates account state at instruction entry, before any logic runs. Rejects transactions early if constraints fail.

**What it does NOT do:** Protect against overflow during the instruction—constraints validate the starting state, not the computation.

### What You Must Do Yourself

| Responsibility | Source | What You Must Write |
|---------------|--------|---------------------|
| Safe arithmetic methods | **Rust stdlib** | `checked_add()`, `checked_sub()`, `checked_mul()` |
| Overflow/underflow detection | **Rust stdlib** | Handle `None` from `checked_*` methods |
| Numeric limit constants | **Your code** | `const MAX_DEPOSIT: u64 = 1_000_000_000;` |
| Input range validation | **Your code** | `require!(amount <= MAX, ...)` |
| Pre-subtraction balance checks | **Your code** | `require!(balance >= amount, ...)` |

### Common Misconception

> ⚠️ **"Anchor makes my arithmetic safe"** — This is FALSE.
>
> Anchor provides excellent error handling infrastructure, but:
> - `checked_add()`, `checked_sub()`, `checked_mul()` are **Rust standard library** methods
> - Anchor has **no automatic overflow detection**
> - You must **manually call** safe arithmetic methods
> - You must **manually define** numeric limits
>
> Both Anchor and Pinocchio programs are equally vulnerable to arithmetic issues if developers don't use safe methods.

### Complete Example: All Features Working Together

```rust
use anchor_lang::prelude::*;

// ANCHOR FEATURE: Declarative error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,
    #[msg("Deposit exceeds maximum allowed (1B lamports)")]
    ExceedsMaxDeposit,
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
}

// YOUR RESPONSIBILITY: Define safe limits
const MAX_DEPOSIT: u64 = 1_000_000_000; // 1B lamports

pub fn safe_deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // ANCHOR FEATURE: require!() for input validation
    require!(amount <= MAX_DEPOSIT, ErrorCode::ExceedsMaxDeposit);

    // RUST STDLIB: checked_add() for safe arithmetic
    // ANCHOR FEATURE: .ok_or() integrates with error system
    ctx.accounts.user_balance.balance = ctx.accounts.user_balance.balance
        .checked_add(amount)
        .ok_or(ErrorCode::ArithmeticOverflow)?;

    Ok(())
}

pub fn safe_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ANCHOR FEATURE: require!() for pre-subtraction validation
    require!(
        ctx.accounts.user_balance.balance >= amount,
        ErrorCode::InsufficientBalance
    );

    // RUST STDLIB: checked_sub() with ANCHOR error integration
    ctx.accounts.user_balance.balance = ctx.accounts.user_balance.balance
        .checked_sub(amount)
        .ok_or(ErrorCode::ArithmeticOverflow)?;

    Ok(())
}
```

### Anchor vs Pinocchio: Arithmetic Safety Comparison

| Aspect | Anchor | Pinocchio |
|--------|--------|-----------|
| Safe arithmetic source | Rust stdlib | Rust stdlib |
| Error definition | `#[error_code]` macro (10 LOC) | Manual enum + `impl From` (20 LOC) |
| Input validation | `require!(cond, err)` (1 line) | `if !cond { return Err(...) }` (3 lines) |
| Error conversion | `.ok_or(ErrorCode::...)` | `.ok_or(Error::...)` |
| Arithmetic protection | **None built-in** | **None built-in** |

**The Bottom Line:** Core arithmetic safety is framework-agnostic. Whether you use Anchor or Pinocchio, you must:
1. Use `checked_*` methods from Rust's standard library
2. Handle the `None` case appropriately
3. Define and enforce numeric limits

### Arithmetic Safety Checklist for Anchor Developers

Use this checklist when implementing arithmetic operations:

**Pre-Implementation:**
- [ ] Define error codes in `#[error_code]` enum for all arithmetic failures
- [ ] Define constants for all numeric limits (`MAX_DEPOSIT`, `MAX_RATE`, etc.)
- [ ] Identify all arithmetic operations in your instruction

**Implementation:**
- [ ] Use `require!()` to validate inputs BEFORE arithmetic
- [ ] Use `checked_add()` for all additions
- [ ] Use `checked_sub()` for all subtractions (with prior balance check)
- [ ] Use `checked_mul()` for all multiplications
- [ ] Convert `Option` results with `.ok_or(ErrorCode::...)?`
- [ ] Add `// SECURITY:` comments explaining each protection

**Post-Implementation:**
- [ ] Write tests with boundary values (`u64::MAX`, `0`, limits ± 1)
- [ ] Test that overflow/underflow returns expected error codes
- [ ] Verify error messages are clear and actionable
- [ ] Review with "what if an attacker controls this input?" mindset

## Running Tests

```bash
# Navigate to pattern directory
cd patterns/03-unsafe-arithmetic

# Run all tests (Anchor + Pinocchio comparison)
anchor test

# Run only exploit demo tests
npx ts-mocha -p ./tsconfig.json -t 1000000 tests/exploit-demo.ts

# Run only framework comparison tests
npx ts-mocha -p ./tsconfig.json -t 1000000 tests/pinocchio-comparison.ts
```

## Key Takeaways

1. **Always use checked arithmetic** - `checked_add()`, `checked_sub()`, `checked_mul()` return `None` on overflow/underflow instead of wrapping silently.

2. **Add input validation** - Define constants like `MAX_DEPOSIT` and `MAX_REWARD_RATE` to prevent attackers from crafting overflow-inducing values.

3. **Validate before subtracting** - Always check `balance >= withdrawal` before any subtraction to prevent underflow attacks.

4. **Consider saturating arithmetic** - For non-critical counters, `saturating_add()` caps at MAX instead of wrapping, which may be acceptable for some use cases.

5. **Framework doesn't determine security** - Both Anchor and Pinocchio can be secure OR vulnerable. Security comes from developer discipline, not framework choice.

## File Structure

```
patterns/03-unsafe-arithmetic/
├── programs/
│   ├── vulnerable/           # Anchor vulnerable (wrapping_*)
│   │   └── src/lib.rs
│   ├── secure/               # Anchor secure (checked_*)
│   │   └── src/lib.rs
│   ├── token-vulnerable/     # Token vault with unsafe arithmetic
│   │   ├── Cargo.toml
│   │   ├── src/lib.rs
│   │   └── token-vulnerable-keypair.json
│   └── token-secure/         # Token vault with safe arithmetic
│       ├── Cargo.toml
│       ├── src/lib.rs
│       └── token-secure-keypair.json
├── pinocchio-programs/       # Pinocchio implementations
│   ├── pinocchio-vulnerable/
│   │   ├── Cargo.toml
│   │   ├── src/lib.rs
│   │   └── pinocchio-vulnerable-keypair.json
│   └── pinocchio-secure/
│       ├── Cargo.toml
│       ├── src/lib.rs
│       └── pinocchio-secure-keypair.json
├── tests/
│   ├── exploit-demo.ts       # Anchor exploit demonstrations
│   ├── pinocchio-comparison.ts  # Framework comparison tests
│   └── token-manipulation.ts # Token vault arithmetic tests
├── Anchor.toml
└── README.md

deep-dive/
└── unsafe-arithmetic.md      # Comprehensive educational deep-dive
```

## Deep Dive

For comprehensive educational content on arithmetic vulnerabilities, including:
- Rust debug vs release mode behavior
- Comparison of all arithmetic method families (`wrapping_*`, `checked_*`, `saturating_*`, `overflowing_*`)
- Common vulnerable patterns with code examples
- Real-world incident references
- Decision flowcharts for method selection
- Framework assistance analysis (Anchor vs Pinocchio)

**See: [Deep Dive: Unsafe Arithmetic](/deep-dive/unsafe-arithmetic.md)**

For detailed framework comparison content, see the [Framework Assistance](/deep-dive/unsafe-arithmetic.md#framework-assistance) section.

## Token Manipulation Example

This pattern includes a realistic token vault scenario demonstrating arithmetic vulnerabilities with actual SPL Token operations.

### Token Vulnerable Program
**File:** `programs/token-vulnerable/src/lib.rs`

Demonstrates a token vault that tracks deposits and withdrawals using `wrapping_*` arithmetic:
- `total_deposited` uses `wrapping_add()` - can overflow to near-zero
- `total_withdrawn` uses `wrapping_add()` - can overflow
- Available balance calculation uses `wrapping_sub()` - can underflow

### Token Secure Program
**File:** `programs/token-secure/src/lib.rs`

Implements secure token vault with:
- `checked_add()` for deposit tracking with overflow detection
- `checked_sub()` for available balance calculation
- `MAX_TOKEN_DEPOSIT` limit for defense in depth
- Balance validation before withdrawal operations

### Token Manipulation Tests
**File:** `tests/token-manipulation.ts`

Tests demonstrating:
- How tracked balances can diverge from actual token holdings
- Secure program rejecting overflow/underflow scenarios
- Proper token amount validation with SPL Token integration

```bash
# Run token manipulation tests
npx ts-mocha -p ./tsconfig.json -t 1000000 tests/token-manipulation.ts
```

<!-- TODO: Add cross-reference to Epic 7 (SPL Token Security) when implemented -->

## Related Patterns

- [Pattern 01: Missing Validation](../01-missing-validation/) - Input validation fundamentals
- [Pattern 02: Authority Checks](../02-authority-checks/) - Access control patterns

## References

- [Rust Overflow Behavior](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow)
- [Solana Security Best Practices](https://docs.solana.com/developing/on-chain-programs/developing-rust#program-security)
- [Anchor Error Handling](https://www.anchor-lang.com/docs/errors)
- [OWASP Integer Overflow](https://owasp.org/www-community/vulnerabilities/Integer_overflow)
