# Pattern 02: Authority Checks

## Vulnerability Description

**Authority check vulnerabilities** occur when Solana programs fail to properly validate that the caller is authorized to perform a privileged operation. This can happen due to:

1. **Missing signer verification** - Using `AccountInfo`/`UncheckedAccount` instead of `Signer`
2. **Missing authority validation** - No `constraint` checking caller against stored authority
3. **Missing relationship validation** - No `has_one` or equivalent constraint
4. **Missing authority chain validation** - Not verifying delegated permissions back to root

These vulnerabilities lead to **privilege escalation attacks** where unauthorized users can:
- Add themselves as administrators
- Modify protocol fees or configurations
- Pause/unpause the protocol
- Create accounts with elevated permissions
- Steal funds from protocol-controlled accounts

## Attack Scenario

### Scenario: Admin Privilege Escalation

The vulnerable program allows anyone to add themselves as an admin without authorization:

```
1. Attacker observes the admin_config PDA address
2. Attacker creates transaction calling add_admin:
   - caller = attacker's pubkey (NOT required to sign)
   - new_admin = attacker's pubkey
3. Transaction succeeds because:
   - No signer check on caller
   - No constraint validating caller == super_admin
4. Attacker is now in admin_list with full privileges
5. Attacker can modify fees, pause protocol, etc.
```

**Impact:** Complete protocol takeover with single transaction

### Scenario: Fee Manipulation Attack

```
1. Attacker monitors mempool for high-value user transaction
2. Attacker front-runs with update_fee(10000) (100% fee)
3. User's transaction executes, paying 100% fee
4. Attacker back-runs with update_fee(100) to hide attack
```

**Impact:** Theft of user funds through fee manipulation

## Vulnerable Implementation

**Location:** [`programs/vulnerable/src/lib.rs`](./programs/vulnerable/src/lib.rs)

The vulnerable program demonstrates multiple authority check failures:

```rust
// VULNERABILITY: caller is UncheckedAccount, not Signer
// Anyone can pass any pubkey without proving ownership
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    // VULNERABILITY: No signer verification
    /// CHECK: Intentionally unchecked to demonstrate vulnerability.
    pub caller: UncheckedAccount<'info>,

    /// CHECK: Just provides a pubkey to add.
    pub new_admin: UncheckedAccount<'info>,
}

pub fn add_admin(ctx: Context<AddAdmin>) -> Result<()> {
    // VULNERABILITY: No check that caller is super_admin
    // VULNERABILITY: Anyone can add anyone as admin
    let new_admin_key = ctx.accounts.new_admin.key();
    let index = admin_config.admin_count as usize;
    admin_config.admin_list[index] = new_admin_key;
    admin_config.admin_count += 1;
    Ok(())
}
```

**Key vulnerabilities:**
- `caller` is `UncheckedAccount` instead of `Signer`
- No `constraint` validating `caller.key() == admin_config.super_admin`
- No PDA `seeds` constraint on `admin_config` (allows substitution)

## Secure Implementation

**Location:** [`programs/secure/src/lib.rs`](./programs/secure/src/lib.rs)

The secure program demonstrates proper authority validation:

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

    /// CHECK: Just provides a pubkey to add.
    pub new_admin: UncheckedAccount<'info>,
}
```

**Security measures:**
1. `Signer<'info>` - Enforces cryptographic signature verification
2. `constraint` - Validates caller against stored `super_admin`
3. `seeds` + `bump` - Prevents account substitution attacks
4. Custom error - Clear error message for unauthorized access

### Helper Function for Admin List Checks

```rust
/// SECURITY: Reusable authority validation helper
pub fn is_admin(admin_list: &[Pubkey; MAX_ADMINS], admin_count: u8, key: &Pubkey) -> bool {
    let count = admin_count as usize;
    admin_list.iter().take(count).any(|admin| admin == key)
}

// Usage in constraint:
constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key)
    @ ErrorCode::NotAdmin
```

## Running Tests

```bash
cd patterns/02-authority-checks
anchor test
```

### Expected Test Output

```
Authority Checks Pattern
  VULNERABLE Program
    ⚠️ EXPLOIT SUCCESSFUL: Non-super_admin added admin
    ⚠️ EXPLOIT SUCCESSFUL: Non-admin modified fees
    ⚠️ EXPLOIT SUCCESSFUL: Non-super_admin paused protocol
    ⚠️ EXPLOIT SUCCESSFUL: Non-admin created manager

  SECURE Program
    ✓ SECURITY VERIFIED: Non-super_admin blocked from adding admin
    ✓ SECURITY VERIFIED: Non-admin blocked from fee modification
    ✓ SECURITY VERIFIED: Non-super_admin blocked from pausing
    ✓ SECURITY VERIFIED: Non-admin blocked from creating manager
    ✓ SECURITY VERIFIED: Fake admin_config rejected - PDA seeds enforced

  Authorized Operations
    ✓ SUCCESS: Super_admin added admin successfully
    ✓ SUCCESS: Admin updated fees successfully
    ✓ SUCCESS: Super_admin paused protocol successfully
    ✓ SUCCESS: Admin created manager successfully
```

## Key Takeaways

1. **Always use `Signer<'info>`** for accounts that must authorize an action
   - Never use `AccountInfo` or `UncheckedAccount` for authority accounts
   - `Signer` enforces cryptographic signature verification

2. **Add constraint checks** validating caller against stored authority
   - For super_admin: `constraint = caller.key() == admin_config.super_admin`
   - For admin_list: `constraint = is_admin(&admin_list, count, caller.key)`

3. **Use PDA seeds constraints** to prevent account substitution
   - Always include `seeds = [...]` and `bump` on PDA accounts
   - Without seeds, attackers can substitute fake accounts

4. **Validate authority at every level** of the authority chain
   - When creating managers, verify the creating admin is in admin_list
   - Don't trust intermediate authorities without verification

5. **Use helper functions** for consistent validation
   - `is_admin()` helper ensures the same logic everywhere
   - Reduces risk of typos in repeated constraints

## Deep-Dive Documentation

For comprehensive documentation on authority check patterns, see the deep-dive section:

| Document | Description |
|----------|-------------|
| [Index](../../deep-dive/02-authority-checks/index.md) | Overview and table of contents |
| [Ownership Model](../../deep-dive/02-authority-checks/ownership-model.md) | Solana's account ownership model |
| [Common Mistakes](../../deep-dive/02-authority-checks/common-mistakes.md) | Authority check failures with examples |
| [Real-World Examples](../../deep-dive/02-authority-checks/real-world-examples.md) | Historical exploits and case studies |
| [Web Comparison](../../deep-dive/02-authority-checks/web-comparison.md) | RBAC/ACL mapping to Solana |
| [Decision Tree](../../deep-dive/02-authority-checks/decision-tree.md) | Systematic approach to authority design |
| [Common Patterns](../../deep-dive/02-authority-checks/common-patterns.md) | Reusable authority patterns |

## Pinocchio Framework Comparison

This pattern includes Pinocchio implementations to demonstrate authority check patterns in both frameworks.

### Directory Structure

```
patterns/02-authority-checks/
├── programs/                         # Anchor programs
│   ├── vulnerable/                   # Vulnerable Anchor implementation
│   └── secure/                       # Secure Anchor implementation
├── pinocchio-programs/               # Pinocchio programs
│   ├── pinocchio-vulnerable/         # Vulnerable Pinocchio implementation
│   └── pinocchio-secure/             # Secure Pinocchio implementation
└── tests/
    ├── exploit-demo.ts               # Anchor program tests
    └── pinocchio-comparison.ts       # Pinocchio framework comparison tests
```

### Authority Validation: Anchor vs Pinocchio

| Security Feature | Anchor | Pinocchio |
|-----------------|--------|-----------|
| Signer validation | `Signer<'info>` type | `is_signer()` method |
| Super admin constraint | `constraint = caller.key() == admin` | Manual pubkey comparison |
| Admin list membership | Custom constraint function | `is_admin()` helper function |
| Account ownership | `seeds = [...]`, `bump` | `owned_by(program_id)` method |
| Error handling | `#[error_code]` enum | `ProgramError::Custom(u32)` |
| Instruction routing | `#[program]` macro | Manual match on discriminator |

### Pinocchio Vulnerable Implementation

**Location:** [`pinocchio-programs/pinocchio-vulnerable/src/lib.rs`](./pinocchio-programs/pinocchio-vulnerable/src/lib.rs)

```rust
// VULNERABILITY: No is_signer() check on caller
// VULNERABILITY: No super_admin comparison
fn add_admin(accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, _caller, new_admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // VULNERABILITY: Anyone can add themselves as admin
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    let index = admin_config.admin_count as usize;
    admin_config.admin_list[index] = Address::new_from_array(*new_admin.address().as_array());
    admin_config.admin_count += 1;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    Ok(())
}
```

### Pinocchio Secure Implementation

**Location:** [`pinocchio-programs/pinocchio-secure/src/lib.rs`](./pinocchio-programs/pinocchio-secure/src/lib.rs)

```rust
// SECURITY: Manual is_signer() + super_admin comparison
fn add_admin(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, caller, new_admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify caller is a signer
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify caller is super_admin
    if admin_config.super_admin.as_ref() != caller.address().as_ref() {
        return Err(SecureError::NotSuperAdmin.into());
    }

    // Now safe to add admin
    let index = admin_config.admin_count as usize;
    admin_config.admin_list[index] = Address::new_from_array(*new_admin.address().as_array());
    admin_config.admin_count += 1;

    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    Ok(())
}

// SECURITY: Reusable authority validation helper
pub fn is_admin(admin_list: &[Address; MAX_ADMINS], admin_count: u8, key: &Address) -> bool {
    let count = admin_count as usize;
    admin_list.iter().take(count).any(|admin| admin.as_ref() == key.as_ref())
}
```

### Running Pinocchio Tests

```bash
cd patterns/02-authority-checks
anchor test
```

The test suite includes both Anchor and Pinocchio comparison tests demonstrating identical vulnerabilities and security measures in both frameworks.

### Key Pinocchio Differences for Authority Checks

1. **No automatic signer enforcement** - Must call `is_signer()` explicitly
2. **No declarative constraints** - All validation is imperative code
3. **Manual serialization** - Must handle account data parsing
4. **Smaller binary size** - No Anchor discriminator overhead (saves 8 bytes per account)
5. **Single-byte discriminators** - Manual instruction routing with 1-byte discriminators vs Anchor's 8-byte sighash

### When to Use Each Framework

| Use Anchor When | Use Pinocchio When |
|-----------------|-------------------|
| Complex admin hierarchies | Performance-critical code |
| Team projects with multiple developers | Minimal compute unit usage |
| Rapid prototyping | Full control over serialization |
| Need for IDL/TypeScript types | Binary size optimization |
| Declarative security constraints | Explicit, auditable security code |

## Related Patterns

| Pattern | Relationship |
|---------|-------------|
| Pattern 01: Missing Account Validation | Account existence and ownership (complements authority) |
| Pattern 03: Integer Overflow (Coming Soon) | Arithmetic safety (separate concern) |
| Pattern 04: Reentrancy (Coming Soon) | Cross-program invocation safety (separate concern) |

## References

### Anchor Documentation
- [Account Constraints](https://www.anchor-lang.com/docs/account-constraints) - Official Anchor constraint documentation
- [Security Considerations](https://www.anchor-lang.com/docs/security) - Anchor security best practices

### Solana Documentation
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security) - Official security guidelines
- [Account Model](https://docs.solana.com/developing/programming-model/accounts) - Understanding account ownership

### Security Research
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks) - Common Solana vulnerability patterns
- [Cashio Post-Mortem](https://blog.cashio.app/post-mortem/) - Real-world authority check failure
- [Wormhole Incident Analysis](https://wormholecrypto.medium.com/) - Signature verification bypass

## Authority Hierarchy Reference

This pattern implements a three-tier authority hierarchy:

```
super_admin (highest privilege)
    ├── Can pause/unpause protocol
    ├── Can add/remove admins
    │
    └── admin_list members
            ├── Can modify fees
            ├── Can create managers
            │
            └── managers
                    └── Limited delegated permissions
```

| Level | Example Operations | Validation |
|-------|-------------------|------------|
| Super Admin | pause, add_admin, remove_admin | `caller.key() == super_admin` |
| Admin | update_fee, create_manager | `is_admin(&admin_list, count, caller.key)` |
| Manager | delegated operations | Permission flags + chain validation |
