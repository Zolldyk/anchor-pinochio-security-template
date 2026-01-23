# Common Authority Check Mistakes

## Overview

Authority check failures follow predictable patterns. This section documents the four most common mistakes that lead to privilege escalation vulnerabilities, with code examples from Pattern 02 demonstrating both vulnerable and secure implementations.

Understanding these mistakes is essential for:
- **Developers**: Avoid introducing vulnerabilities in new code
- **Code Reviewers**: Identify authority check gaps during review
- **Security Auditors**: Know what patterns to look for during audits

## Mistake Matrix

| # | Mistake | Impact | Fix |
|---|---------|--------|-----|
| 1 | Using `AccountInfo` instead of `Signer` | Anyone can impersonate any authority | Use `Signer<'info>` |
| 2 | Missing `has_one` constraint | Relationship validation bypassed | Add `has_one` or custom `constraint` |
| 3 | Checking signer but not relationship | Signed by wrong authority | Validate against stored authority |
| 4 | Missing authority chain validation | Delegated permissions bypassed | Validate entire authority chain |

## Mistake 1: Using AccountInfo Instead of Signer

### The Vulnerability

Using `AccountInfo` (or `UncheckedAccount`) for an account that should authorize an action allows anyone to pass any pubkey without proving ownership.

### Why It Happens

- Developer assumes the account will be validated elsewhere
- Copy-paste from examples that don't require signatures
- Misunderstanding of Anchor's account types

### Vulnerable Code

From `vulnerable_authority_checks/src/lib.rs`:

```rust
// VULNERABILITY: caller is UncheckedAccount, not Signer
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    // VULNERABILITY: This is UncheckedAccount, not Signer!
    // Anyone can pass any pubkey here without proving ownership.
    /// CHECK: This account is intentionally unchecked to demonstrate the vulnerability.
    pub caller: UncheckedAccount<'info>,

    /// CHECK: This account just provides a pubkey to add.
    pub new_admin: UncheckedAccount<'info>,
}
```

### Attack Scenario

```typescript
// Attacker's transaction - no signature from super_admin required!
await vulnerableProgram.methods
  .addAdmin()
  .accounts({
    adminConfig: vulnerableAdminConfigPda,
    caller: attackerKeypair.publicKey, // Not required to sign!
    newAdmin: attackerKeypair.publicKey,
  })
  .rpc(); // No signers array needed for caller

// Result: Attacker is now an admin
```

### Secure Code

From `secure_authority_checks/src/lib.rs`:

```rust
// SECURITY: caller is Signer - enforces cryptographic signature verification
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Only super_admin can add new admins
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    // SECURITY: Signer type enforces cryptographic signature verification.
    // The caller must prove they own the private key by signing the transaction.
    pub caller: Signer<'info>,

    /// CHECK: This account just provides a pubkey to add.
    pub new_admin: UncheckedAccount<'info>,
}
```

### Security Impact

| Aspect | Vulnerable | Secure |
|--------|------------|--------|
| Signature required | No | Yes |
| Can impersonate | Any pubkey | None |
| Attack cost | 1 transaction | Impossible |
| Exploit difficulty | Trivial | N/A |

### Detection Checklist

- [ ] Is the account marked as `Signer<'info>`?
- [ ] If using `UncheckedAccount`, is there a valid reason (e.g., it's only for reading data)?
- [ ] Are all accounts that authorize actions using `Signer`?

---

## Mistake 2: Missing has_one Constraint

### The Vulnerability

Even with a `Signer`, if there's no validation that the signer matches a stored authority field, any signer can perform the action.

### Why It Happens

- Developer adds `Signer` but forgets to validate against stored authority
- Assumption that being a signer is sufficient
- Not understanding that `Signer` only proves identity, not authorization

### Vulnerable Code

```rust
// VULNERABILITY: Signer exists but no has_one or constraint validation
#[derive(Accounts)]
pub struct UpdateUserData<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,

    // This IS a Signer, but there's no check that it matches user_account.authority
    pub authority: Signer<'info>,
}

// user_account.authority could be Alice
// But Bob can sign and modify Alice's data!
```

### Secure Code Using has_one

```rust
// SECURITY: has_one constraint validates relationship
#[derive(Accounts)]
pub struct UpdateUserData<'info> {
    #[account(
        mut,
        // SECURITY: has_one checks user_account.authority == authority.key()
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub user_account: Account<'info, UserAccount>,

    // SECURITY: Combined with has_one, this ensures:
    // 1. Transaction is signed by 'authority' account
    // 2. user_account.authority field matches this signer
    pub authority: Signer<'info>,
}
```

### Secure Code Using Custom Constraint

For more complex validations (like array membership), use custom constraints:

```rust
// SECURITY: Custom constraint for array membership check
#[derive(Accounts)]
pub struct UpdateFee<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Custom constraint validates caller is in admin_list
        constraint = is_admin(
            &admin_config.admin_list,
            admin_config.admin_count,
            caller.key
        ) @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    // SECURITY: Signer enforces caller owns the private key.
    pub caller: Signer<'info>,
}

/// Helper function for consistent admin membership validation
pub fn is_admin(admin_list: &[Pubkey; MAX_ADMINS], admin_count: u8, key: &Pubkey) -> bool {
    let count = admin_count as usize;
    admin_list.iter().take(count).any(|admin| admin == key)
}
```

### has_one vs constraint Comparison

| Aspect | has_one | constraint |
|--------|---------|------------|
| Use case | Simple field match | Complex validation |
| Syntax | `has_one = field_name` | `constraint = expression` |
| Error handling | Default or custom | Custom required |
| Array membership | Not supported | Use helper function |

### Detection Checklist

- [ ] For each `Signer`, is there a `has_one` or `constraint` that validates against stored authority?
- [ ] If the authority is stored in an array, is there a helper function checking membership?
- [ ] Is the constraint using the correct error code?

---

## Mistake 3: Checking Signer But Not Owner/Relationship

### The Vulnerability

A transaction might be signed, but by the wrong authority. For example, checking that someone signed, but not checking that they're the specific authority for this particular account or operation.

### Why It Happens

- Multiple authority levels (super_admin vs admin)
- Copy-paste of constraints without updating for the specific operation
- Assuming any valid signer is authorized for any action

### Vulnerable Code

```rust
// VULNERABILITY: Checks is_admin but operation requires super_admin
#[derive(Accounts)]
pub struct PauseProtocol<'info> {
    #[account(
        mut,
        // VULNERABILITY: Using is_admin check for super_admin-only operation
        constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key)
            @ ErrorCode::NotAdmin  // Wrong check!
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub caller: Signer<'info>,
}
// Problem: Any admin can pause, but only super_admin should be able to
```

### Secure Code

From `secure_authority_checks/src/lib.rs`:

```rust
// SECURITY: Correctly checks for super_admin authority
#[derive(Accounts)]
pub struct PauseProtocol<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: pause_protocol is super_admin-only, enforced by constraint
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    // SECURITY: Signer type enforces cryptographic signature verification.
    pub caller: Signer<'info>,
}
```

### Authority Level Matrix

| Operation | Required Authority | Constraint |
|-----------|-------------------|------------|
| Add/remove admin | super_admin | `caller.key() == admin_config.super_admin` |
| Pause/unpause | super_admin | `caller.key() == admin_config.super_admin` |
| Update fees | admin_list member | `is_admin(&admin_list, count, caller.key)` |
| Create manager | admin_list member | `is_admin(&admin_list, count, caller.key)` |

### Detection Checklist

- [ ] For each privileged operation, what authority level is required?
- [ ] Does the constraint check for the correct authority level?
- [ ] Are super_admin-only operations protected with super_admin checks (not just admin)?

---

## Mistake 4: Missing Authority Chain Validation

### The Vulnerability

In hierarchical authority systems, attackers can create fake intermediate entities that appear valid but weren't created by legitimate authorities.

### Why It Happens

- Only validating the immediate actor, not how they got their authority
- Missing validation of the authority who delegated permissions
- Assuming PDAs are always created correctly

### Vulnerable Code

```rust
// VULNERABILITY: admin not validated against admin_list
#[derive(Accounts)]
pub struct CreateManager<'info> {
    // admin_config is loaded but never used for validation
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        init,
        payer = payer,
        space = ManagerAccount::ACCOUNT_SIZE,
        seeds = [b"manager", manager.key().as_ref()],
        bump
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    // VULNERABILITY: Not a Signer, not validated against admin_list
    /// CHECK: Intentionally unchecked to demonstrate vulnerability.
    pub admin: UncheckedAccount<'info>,

    /// CHECK: This account just provides a pubkey for the manager role.
    pub manager: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}
```

**Attack:**
1. Attacker passes their own pubkey as `admin`
2. Creates manager with `can_modify_fees = true`, `can_pause = true`
3. Attacker now has a "legitimate" manager account with elevated permissions

### Secure Code

From `secure_authority_checks/src/lib.rs`:

```rust
// SECURITY: Full authority chain validation
#[derive(Accounts)]
pub struct CreateManager<'info> {
    #[account(
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: admin validated against admin_list
        constraint = is_admin(
            &admin_config.admin_list,
            admin_config.admin_count,
            admin.key
        ) @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        init,
        payer = payer,
        space = ManagerAccount::ACCOUNT_SIZE,
        seeds = [b"manager", manager.key().as_ref()],
        bump
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    // SECURITY: Signer type enforces signature verification.
    // SECURITY: Admin is validated against admin_list via constraint above.
    pub admin: Signer<'info>,

    /// CHECK: This account just provides a pubkey for the manager role.
    pub manager: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}
```

### Authority Chain Visualization

```
                    VULNERABLE                         SECURE
              ──────────────────────            ──────────────────────

              ┌─────────────────────┐           ┌─────────────────────┐
              │   admin_config      │           │   admin_config      │
              │   (not validated)   │           │   (seeds verified)  │
              └─────────────────────┘           └─────────────────────┘
                        │                                 │
                        │ No check                        │ constraint:
                        ▼                                 │ is_admin()
              ┌─────────────────────┐                     ▼
              │   "admin" account   │           ┌─────────────────────┐
              │   (any pubkey!)     │           │   admin: Signer     │
              └─────────────────────┘           │   (validated)       │
                        │                       └─────────────────────┘
                        │                                 │
                        ▼                                 ▼
              ┌─────────────────────┐           ┌─────────────────────┐
              │   manager_account   │           │   manager_account   │
              │   (attacker has     │           │   (legitimate)      │
              │    full perms!)     │           └─────────────────────┘
              └─────────────────────┘
```

**Text description for accessibility:** The vulnerable path shows admin_config loaded but not validated, then any pubkey can be passed as admin, resulting in an attacker-controlled manager. The secure path shows admin_config with seeds verification, admin must be a Signer validated against admin_list, resulting in only legitimate managers being created.

### Detection Checklist

- [ ] When creating delegated accounts (managers, agents, etc.), is the delegating authority validated?
- [ ] Is the authority chain validated back to a root authority (super_admin)?
- [ ] Are all intermediate authorities verified against their parent's authority list?

---

## Common Mistake Patterns Summary

### Pattern: Missing Signer

```rust
// VULNERABLE
pub caller: UncheckedAccount<'info>,

// SECURE
pub caller: Signer<'info>,
```

### Pattern: Missing Constraint

```rust
// VULNERABLE
#[account(mut)]
pub admin_config: Account<'info, AdminConfig>,

// SECURE
#[account(
    mut,
    constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
)]
pub admin_config: Account<'info, AdminConfig>,
```

### Pattern: Missing Seeds

```rust
// VULNERABLE - allows account substitution
#[account(mut)]
pub admin_config: Account<'info, AdminConfig>,

// SECURE - enforces correct PDA
#[account(
    mut,
    seeds = [b"admin_config"],
    bump = admin_config.bump
)]
pub admin_config: Account<'info, AdminConfig>,
```

### Pattern: Wrong Authority Level

```rust
// VULNERABLE - admin check for super_admin operation
constraint = is_admin(...) @ ErrorCode::NotAdmin

// SECURE - super_admin check for super_admin operation
constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
```

## Code Review Checklist

When reviewing code for authority check vulnerabilities:

1. **For each instruction:**
   - [ ] What authority level is required?
   - [ ] Is that authority level correctly validated?

2. **For each account that authorizes:**
   - [ ] Is it a `Signer<'info>`?
   - [ ] Is there a `has_one` or `constraint` validating the relationship?

3. **For PDAs:**
   - [ ] Are seeds constraints present?
   - [ ] Is the bump validated?

4. **For hierarchical authority:**
   - [ ] Is the full authority chain validated?
   - [ ] Can attackers create fake intermediate authorities?

## Next Section

Continue to [Real-World Examples](./real-world-examples.md) to learn about actual Solana exploits caused by authority check failures.
