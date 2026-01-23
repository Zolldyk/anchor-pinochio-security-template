# Solana Account Ownership Model

## Overview

Understanding Solana's account ownership model is fundamental to implementing secure authority checks. Unlike traditional web applications where users authenticate via passwords or tokens, Solana uses **cryptographic signatures** and **account ownership** to establish authority.

This section explains how account ownership works, the distinction between different types of authority, and why understanding these concepts is critical for preventing privilege escalation vulnerabilities.

## Account Ownership Fundamentals

Every account on Solana has an **owner program**. Only the owner program can modify the account's data or deduct lamports from it. This creates a clear chain of authority:

```
Account Data
    │
    ├── lamports (balance)
    ├── data (arbitrary bytes)
    ├── owner (program that can modify this account)
    └── executable (is this account a program?)
```

### Key Ownership Rules

| Rule | Description |
|------|-------------|
| Only owner can modify data | A program can only write to accounts it owns |
| Only owner can deduct lamports | Lamports can only be removed by the owner program |
| Anyone can add lamports | Any account can receive SOL |
| System Program owns wallets | User wallets are owned by the System Program |
| Programs own derived accounts | PDAs and data accounts are owned by the creating program |

## Program Ownership vs User Ownership

There's an important distinction between two types of "ownership":

### 1. Program Ownership (On-Chain)

**Program ownership** refers to which program has write access to an account. This is enforced by the Solana runtime.

```
┌─────────────────────────────────────────────────────────────┐
│                      Solana Runtime                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────┐         ┌─────────────────────────┐      │
│   │   System    │ owns    │    User Wallet          │      │
│   │   Program   │────────▶│    (e.g., Alice)        │      │
│   └─────────────┘         │    Balance: 10 SOL      │      │
│                           └─────────────────────────┘      │
│                                                             │
│   ┌─────────────┐         ┌─────────────────────────┐      │
│   │  Your DeFi  │ owns    │    AdminConfig PDA      │      │
│   │   Program   │────────▶│    super_admin: Alice   │      │
│   └─────────────┘         │    fee_basis_points: 100│      │
│                           └─────────────────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Key insight:** The System Program owns user wallets, but your program owns the data accounts (PDAs) that store application state.

### 2. Application Authority (Logical Ownership)

**Application authority** refers to which user pubkey is stored in your program's data as having permission to perform certain actions. This is enforced by your program logic.

```rust
// SECURITY: This struct stores WHO has authority, not program ownership
pub struct AdminConfig {
    pub super_admin: Pubkey,           // Application authority - who can pause?
    pub admin_list: [Pubkey; 3],       // Application authority - who can modify fees?
    pub fee_basis_points: u16,
    pub paused: bool,
    pub bump: u8,
}
```

**Key insight:** Program ownership (which program can write) is different from application authority (which user can authorize actions).

## Account Ownership Relationships Diagram

The following diagram shows how ownership and authority relationships work in Pattern 02:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PATTERN 02 ARCHITECTURE                         │
└─────────────────────────────────────────────────────────────────────────┘

     PROGRAM OWNERSHIP                    APPLICATION AUTHORITY
     (Enforced by runtime)                (Enforced by program logic)

┌─────────────────────┐              ┌─────────────────────────────────┐
│   System Program    │              │        Authority Hierarchy       │
│   ───────────────   │              │        ──────────────────        │
│                     │              │                                   │
│  ┌───────────────┐  │              │     super_admin (Pubkey)         │
│  │ super_admin   │  │              │            │                      │
│  │ wallet        │──┼──────────────┼────────────┤ Can: pause, add/    │
│  └───────────────┘  │              │            │      remove admins  │
│                     │              │            ▼                      │
│  ┌───────────────┐  │              │     admin_list[0..n]             │
│  │ admin         │  │              │            │                      │
│  │ wallet        │──┼──────────────┼────────────┤ Can: modify fees,   │
│  └───────────────┘  │              │            │      create managers│
│                     │              │            ▼                      │
│  ┌───────────────┐  │              │     managers                      │
│  │ attacker      │  │              │            │                      │
│  │ wallet        │──┼───── X ──────┼────────────┤ Has: no authority   │
│  └───────────────┘  │  (blocked)   │            │      in admin_list  │
│                     │              │                                   │
└─────────────────────┘              └─────────────────────────────────┘

┌─────────────────────┐              ┌─────────────────────────────────┐
│  Authority Checks   │              │        AdminConfig PDA           │
│      Program        │              │        ──────────────            │
│   ───────────────   │              │                                   │
│                     │   owns       │  seeds: ["admin_config"]         │
│                     │──────────────│  super_admin: <pubkey>           │
│                     │              │  admin_list: [<pubkey>, ...]     │
│                     │              │  admin_count: 2                   │
│                     │   owns       │  fee_basis_points: 100           │
│                     │──────────────│  paused: false                   │
│                     │              │  bump: 255                        │
│                     │              └─────────────────────────────────┘
│                     │
│                     │   owns       ┌─────────────────────────────────┐
│                     │──────────────│       ManagerAccount PDA         │
│                     │              │       ─────────────────          │
│                     │              │  seeds: ["manager", mgr.key]     │
│                     │              │  authority: <admin pubkey>       │
│                     │              │  manager: <manager pubkey>       │
│                     │              │  can_modify_fees: true           │
│                     │              │  can_pause: false                │
│                     │              └─────────────────────────────────┘
└─────────────────────┘
```

**Text description for accessibility:** The diagram shows two parallel concepts. On the left, the System Program owns all user wallets (super_admin, admin, attacker). On the right, the Authority Checks Program owns the AdminConfig PDA and ManagerAccount PDAs. Application authority flows from super_admin (highest) to admin_list members to managers. An attacker's wallet exists but has no authority in the admin_list, so their actions are blocked by program logic.

## AccountInfo vs Signer: The Critical Distinction

The most common authority check mistake is using `AccountInfo` (or `UncheckedAccount`) when `Signer` is required.

### AccountInfo (UncheckedAccount)

`AccountInfo` provides raw access to an account's data. It performs **no verification** that the account owner has authorized this transaction.

```rust
// VULNERABILITY: Using AccountInfo for authority account
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    // VULNERABILITY: Anyone can pass any pubkey here!
    // No signature required - attacker can impersonate super_admin
    /// CHECK: Intentionally unchecked to demonstrate vulnerability
    pub caller: UncheckedAccount<'info>,

    /// CHECK: Just provides a pubkey
    pub new_admin: UncheckedAccount<'info>,
}
```

**Attack scenario:**
1. Attacker creates a transaction
2. Sets `caller` to the legitimate super_admin's pubkey (no signature needed)
3. Sets `new_admin` to their own pubkey
4. Transaction succeeds - attacker is now an admin

### Signer

`Signer` enforces that the account has **cryptographically signed** the transaction. This proves the caller owns the private key.

```rust
// SECURITY: Using Signer for authority account
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Validates caller is the super_admin stored in admin_config
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    // SECURITY: Signer type enforces cryptographic signature verification
    // The transaction MUST be signed by this account's private key
    pub caller: Signer<'info>,

    /// CHECK: Just provides a pubkey
    pub new_admin: UncheckedAccount<'info>,
}
```

**Security guarantees:**
1. Transaction must be signed by `caller`'s private key
2. Constraint verifies `caller.key() == admin_config.super_admin`
3. Both conditions must be true, or transaction fails

### Comparison Table

| Aspect | AccountInfo / UncheckedAccount | Signer |
|--------|-------------------------------|--------|
| Signature required | No | Yes |
| Can impersonate | Yes - anyone can pass any pubkey | No - must own private key |
| Use case | Read-only accounts, PDAs | Authority accounts |
| Security level | None | Cryptographic |

## Account-Level vs Instruction-Level Authority

Authority validation happens at two distinct levels:

### Account-Level Authority (Constraints)

Account-level checks happen **before** your instruction logic runs. They are declared in the `#[derive(Accounts)]` struct.

```rust
#[derive(Accounts)]
pub struct UpdateFee<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Account-level authority check
        // This runs BEFORE update_fee instruction body
        constraint = is_admin(
            &admin_config.admin_list,
            admin_config.admin_count,
            caller.key
        ) @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub caller: Signer<'info>,
}
```

**Advantages:**
- Fails fast - invalid transactions rejected before any processing
- Clear declaration of requirements
- Anchor generates helpful error messages

### Instruction-Level Authority (Runtime Checks)

Instruction-level checks happen **inside** your instruction logic. Use these for complex validation that can't be expressed as constraints.

```rust
pub fn remove_admin(ctx: Context<RemoveAdmin>) -> Result<()> {
    let admin_config = &mut ctx.accounts.admin_config;
    let admin_to_remove = ctx.accounts.admin_to_remove.key();

    // SECURITY: Instruction-level authority check
    // Prevent removing super_admin from admin_list (would cause lockout)
    if admin_to_remove == admin_config.super_admin {
        return Err(ErrorCode::CannotRemoveSuperAdmin.into());
    }

    // ... rest of removal logic
    Ok(())
}
```

**Use for:**
- Complex conditional logic
- Checks that depend on computed values
- Multi-step validation

### When to Use Each Level

| Check Type | Use Account-Level | Use Instruction-Level |
|------------|-------------------|----------------------|
| Is caller a signer? | `pub caller: Signer<'info>` | Never |
| Is caller in admin_list? | `constraint = is_admin(...)` | Rarely |
| Is caller super_admin? | `constraint = caller.key() == ...` | Rarely |
| Can't remove super_admin? | No | `if x == super_admin { return Err }` |
| Sufficient balance? | `constraint = balance >= amount` | Either |
| Complex business logic? | No | Yes |

## Code Examples from Pattern 02

### Vulnerable Pattern: No Authority Checks

From `vulnerable_authority_checks` program:

```rust
// VULNERABILITY: No signer check, no authority validation
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    // VULNERABILITY: UncheckedAccount allows anyone to pass any pubkey
    /// CHECK: Intentionally unchecked to demonstrate vulnerability
    pub caller: UncheckedAccount<'info>,

    /// CHECK: Just provides a pubkey
    pub new_admin: UncheckedAccount<'info>,
}

pub fn add_admin(ctx: Context<AddAdmin>) -> Result<()> {
    let admin_config = &mut ctx.accounts.admin_config;

    // VULNERABILITY: No check that caller is super_admin
    // VULNERABILITY: No signer verification
    // Anyone can add anyone as admin!

    let new_admin_key = ctx.accounts.new_admin.key();
    let index = admin_config.admin_count as usize;
    admin_config.admin_list[index] = new_admin_key;
    admin_config.admin_count += 1;

    Ok(())
}
```

### Secure Pattern: Proper Authority Checks

From `secure_authority_checks` program:

```rust
// SECURITY: Signer + constraint + PDA seeds
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Only super_admin can add admins
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    // SECURITY: Signer enforces cryptographic signature verification
    pub caller: Signer<'info>,

    /// CHECK: Just provides a pubkey
    pub new_admin: UncheckedAccount<'info>,
}

pub fn add_admin(ctx: Context<AddAdmin>) -> Result<()> {
    let admin_config = &mut ctx.accounts.admin_config;

    // SECURITY: Authority validation already done by constraint
    // Only super_admin reaches this point

    if admin_config.admin_count as usize >= MAX_ADMINS {
        return Err(ErrorCode::AdminListFull.into());
    }

    let new_admin_key = ctx.accounts.new_admin.key();
    let index = admin_config.admin_count as usize;
    admin_config.admin_list[index] = new_admin_key;
    admin_config.admin_count += 1;

    Ok(())
}
```

## Key Takeaways

1. **Program ownership** (runtime-enforced) is different from **application authority** (program-enforced)

2. **Always use `Signer<'info>`** for accounts that must authorize an action - never use `AccountInfo` or `UncheckedAccount` for authority

3. **Use constraints** to validate authority relationships at the account level before your instruction runs

4. **Account-level checks** (constraints) should be preferred over instruction-level checks when possible

5. **Both levels of authority** must work together - `Signer` proves identity, constraints prove authorization

## Next Section

Continue to [Common Mistakes](./common-mistakes.md) to learn about the specific authority check failures that lead to privilege escalation vulnerabilities.
