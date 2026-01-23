# Common Authority Patterns

## Overview

This section documents reusable authority patterns you can implement in your Solana programs. Each pattern includes a complete code example, security considerations, and references to the Pattern 02 implementation.

## Pattern Categories

| Pattern | Use Case | Complexity |
|---------|----------|------------|
| [Admin Lists](#pattern-1-admin-lists) | Multiple admins with equal privileges | Medium |
| [Hierarchical Ownership](#pattern-2-hierarchical-ownership) | Tiered authority levels | High |
| [Delegated Authority](#pattern-3-delegated-authority) | Permission delegation to subordinates | High |
| [PDA Authority](#pattern-4-pda-authority) | Program-controlled accounts | Medium |

---

## Pattern 1: Admin Lists

### Description

The Admin Lists pattern maintains an array of authorized administrators who share equal privileges for certain operations. This is useful when:

- Multiple team members need admin access
- You want to avoid single points of failure
- Operations need any-admin-can-approve semantics

### Implementation

**Account Structure:**

```rust
pub const MAX_ADMINS: usize = 3;

/// Admin configuration with list-based authorization
#[account]
pub struct AdminConfig {
    /// The highest-privilege administrator
    pub super_admin: Pubkey,

    /// Fixed-size array of authorized administrators
    /// SECURITY: Using fixed array for predictable account sizing
    pub admin_list: [Pubkey; MAX_ADMINS],

    /// Number of active administrators (valid entries are 0..admin_count)
    pub admin_count: u8,

    /// Protocol settings that admins can modify
    pub fee_basis_points: u16,

    /// PDA bump seed
    pub bump: u8,
}

impl AdminConfig {
    pub const ACCOUNT_SIZE: usize = 8 + 32 + 96 + 1 + 2 + 1; // 140 bytes
}
```

**Helper Function:**

```rust
/// SECURITY: Reusable authority validation helper
/// Checks if a pubkey is in the admin_list
pub fn is_admin(admin_list: &[Pubkey; MAX_ADMINS], admin_count: u8, key: &Pubkey) -> bool {
    // SECURITY: Only check valid entries (0..admin_count)
    // This prevents reading uninitialized array slots
    let count = admin_count as usize;
    admin_list.iter().take(count).any(|admin| admin == key)
}
```

**Account Context:**

```rust
/// SECURITY: Admin-only operation using is_admin helper
#[derive(Accounts)]
pub struct AdminOperation<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Constraint validates caller is in admin_list
        constraint = is_admin(
            &admin_config.admin_list,
            admin_config.admin_count,
            caller.key
        ) @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    // SECURITY: Signer enforces cryptographic signature verification
    pub caller: Signer<'info>,
}
```

### Security Considerations

| Consideration | Implementation |
|---------------|----------------|
| Array bounds | Use `admin_count` to limit iteration |
| Initialization | Initialize `admin_list` with `Pubkey::default()` |
| Max admins | Use constant `MAX_ADMINS` for consistent sizing |
| Super admin in list | Include super_admin at index 0 for dual privileges |
| Removal safety | Don't allow removing super_admin from list |

### Pattern 02 Reference

This pattern is implemented in `secure_authority_checks`:
- `AdminConfig` struct: `patterns/02-authority-checks/programs/secure/src/lib.rs:530-566`
- `is_admin` helper: `patterns/02-authority-checks/programs/secure/src/lib.rs:76-81`
- Usage in `UpdateFee`: `patterns/02-authority-checks/programs/secure/src/lib.rs:696-712`

---

## Pattern 2: Hierarchical Ownership

### Description

The Hierarchical Ownership pattern implements tiered authority levels where higher levels have more privileges. This is the standard model for most protocols:

```
super_admin (highest privilege)
    │
    ├── Can: pause, add/remove admins, all admin operations
    │
    └── admin_list members
            │
            ├── Can: modify fees, create managers
            │
            └── managers
                    │
                    └── Can: limited delegated permissions
```

### Implementation

**Account Structures:**

```rust
/// Top-level configuration with authority hierarchy
#[account]
pub struct AdminConfig {
    /// Highest privilege - can do everything
    pub super_admin: Pubkey,

    /// Second tier - can do most things
    pub admin_list: [Pubkey; MAX_ADMINS],
    pub admin_count: u8,

    /// Protocol state
    pub fee_basis_points: u16,
    pub paused: bool,
    pub bump: u8,
}

/// Third tier - limited delegated permissions
#[account]
pub struct ManagerAccount {
    /// The admin who created this manager (for chain validation)
    pub authority: Pubkey,

    /// The manager's identity
    pub manager: Pubkey,

    /// Specific permissions granted
    pub can_modify_fees: bool,
    pub can_pause: bool,

    /// Can be deactivated by admins
    pub is_active: bool,

    pub bump: u8,
}
```

**Super Admin Only Context:**

```rust
/// SECURITY: Operations requiring highest privilege
#[derive(Accounts)]
pub struct SuperAdminOnly<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Only super_admin can perform this action
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub caller: Signer<'info>,
}
```

**Admin or Higher Context:**

```rust
/// SECURITY: Operations any admin (including super_admin) can perform
#[derive(Accounts)]
pub struct AdminOrHigher<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: super_admin is admin_list[0], so this catches both
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

**Manager with Permission Context:**

```rust
/// SECURITY: Operations managers can perform (with specific permission)
#[derive(Accounts)]
pub struct ManagerWithPermission<'info> {
    #[account(
        seeds = [b"admin_config"],
        bump = admin_config.bump,
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        seeds = [b"manager", manager_account.manager.as_ref()],
        bump = manager_account.bump,
        // SECURITY: Validate authority chain - manager's authority must be admin
        constraint = is_admin(
            &admin_config.admin_list,
            admin_config.admin_count,
            &manager_account.authority
        ) @ ErrorCode::InvalidAuthorityChain,
        // SECURITY: Manager must be active
        constraint = manager_account.is_active @ ErrorCode::ManagerNotActive,
        // SECURITY: Must have specific permission
        constraint = manager_account.can_modify_fees @ ErrorCode::InsufficientPermission
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    // SECURITY: Caller must be the manager
    #[account(
        constraint = caller.key() == manager_account.manager @ ErrorCode::NotManager
    )]
    pub caller: Signer<'info>,
}
```

### Security Considerations

| Level | Considerations |
|-------|---------------|
| Super Admin | Should never be removable from admin_list; Consider multi-sig for production |
| Admin | Can be added/removed by super_admin; Include super_admin in list at initialization |
| Manager | Validate authority chain back to admin; Can be deactivated without deletion |

### Pattern 02 Reference

This pattern is the core of Pattern 02:
- Full hierarchy: `patterns/02-authority-checks/programs/secure/src/lib.rs`
- `PauseProtocol` (super_admin): Line 722-738
- `UpdateFee` (admin): Line 696-712
- `CreateManager` (admin creates): Line 787-826

---

## Pattern 3: Delegated Authority

### Description

The Delegated Authority pattern allows higher-level authorities to grant specific permissions to lower-level accounts. Unlike hierarchical ownership where each level has fixed permissions, delegated authority allows granular permission assignment.

### Implementation

**Permission Flags in Manager Account:**

```rust
/// Manager with delegated permissions
#[account]
pub struct ManagerAccount {
    /// Who delegated authority to this manager
    pub authority: Pubkey,

    /// The manager's identity
    pub manager: Pubkey,

    /// Delegated permissions (granular)
    pub can_modify_fees: bool,
    pub can_pause: bool,
    pub can_create_sub_managers: bool,
    pub can_view_reports: bool,

    /// Status
    pub is_active: bool,
    pub bump: u8,
}
```

**Creating Manager with Specific Permissions:**

```rust
pub fn create_manager(
    ctx: Context<CreateManager>,
    can_modify_fees: bool,
    can_pause: bool,
) -> Result<()> {
    let manager_account = &mut ctx.accounts.manager_account;

    // SECURITY: Authority chain validated in context constraints

    // Set the delegating authority
    manager_account.authority = ctx.accounts.admin.key();
    manager_account.manager = ctx.accounts.manager.key();

    // SECURITY: Permissions explicitly set by creating admin
    // Admin cannot grant permissions they don't have (if implemented)
    manager_account.can_modify_fees = can_modify_fees;
    manager_account.can_pause = can_pause;

    manager_account.is_active = true;
    manager_account.bump = ctx.bumps.manager_account;

    msg!(
        "Manager created with permissions: fees={}, pause={}",
        can_modify_fees,
        can_pause
    );

    Ok(())
}
```

**Permission-Gated Operation:**

```rust
#[derive(Accounts)]
pub struct DelegatedFeeUpdate<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        seeds = [b"manager", manager_account.manager.as_ref()],
        bump = manager_account.bump,
        // SECURITY: Must have specific permission
        constraint = manager_account.can_modify_fees @ ErrorCode::NoFeePermission,
        constraint = manager_account.is_active @ ErrorCode::ManagerNotActive
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    #[account(
        constraint = caller.key() == manager_account.manager @ ErrorCode::NotManager
    )]
    pub caller: Signer<'info>,
}

pub fn delegated_fee_update(ctx: Context<DelegatedFeeUpdate>, new_fee: u16) -> Result<()> {
    // SECURITY: Permission already validated in constraints
    ctx.accounts.admin_config.fee_basis_points = new_fee;
    msg!("Fee updated by manager to {} basis points", new_fee);
    Ok(())
}
```

### Permission Inheritance Pattern

For more complex systems, you might want permissions to cascade:

```rust
/// Check if authority can grant a permission
pub fn can_grant_permission(
    admin_config: &AdminConfig,
    granter: &Pubkey,
    permission: Permission,
) -> bool {
    // SECURITY: Only super_admin can grant pause permission
    if permission == Permission::Pause {
        return *granter == admin_config.super_admin;
    }

    // SECURITY: Any admin can grant other permissions
    is_admin(&admin_config.admin_list, admin_config.admin_count, granter)
}
```

### Security Considerations

| Consideration | Implementation |
|---------------|----------------|
| Permission explosion | Limit permission types with enum |
| Delegation depth | Validate full chain, limit depth |
| Permission escalation | Grantees can't grant more than they have |
| Revocation | Support deactivation and permission modification |
| Audit trail | Log who granted what permissions |

### Pattern 02 Reference

Delegated authority is shown in `CreateManager`:
- Manager creation: `patterns/02-authority-checks/programs/secure/src/lib.rs:374-407`
- Permission validation: `patterns/02-authority-checks/programs/secure/src/lib.rs:787-826`

---

## Pattern 4: PDA Authority

### Description

The PDA Authority pattern uses Program Derived Addresses as authorities for token accounts, vaults, and other resources. The program itself controls these accounts, and users trigger actions through program instructions.

### Implementation

**Vault Configuration with PDA Authority:**

```rust
/// Vault configuration where PDA is the authority
#[account]
pub struct VaultConfig {
    /// User who can trigger withdrawals
    pub authorized_user: Pubkey,

    /// Token mint this vault holds
    pub token_mint: Pubkey,

    /// Maximum withdrawal per transaction
    pub max_withdrawal: u64,

    /// PDA bump for signing
    pub bump: u8,
}

impl VaultConfig {
    /// Derive the vault PDA
    pub fn derive_vault_pda(config_key: &Pubkey, program_id: &Pubkey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"vault", config_key.as_ref()],
            program_id,
        )
    }
}
```

**Vault Account Context:**

```rust
#[derive(Accounts)]
pub struct WithdrawFromVault<'info> {
    /// Vault configuration
    #[account(
        seeds = [b"vault_config", authorized_user.key().as_ref()],
        bump = vault_config.bump,
        // SECURITY: Only authorized user can trigger withdrawal
        has_one = authorized_user @ ErrorCode::Unauthorized
    )]
    pub vault_config: Account<'info, VaultConfig>,

    /// The vault token account (owned by vault_pda)
    #[account(
        mut,
        constraint = vault.owner == vault_pda.key() @ ErrorCode::InvalidVaultOwner
    )]
    pub vault: Account<'info, TokenAccount>,

    /// The vault PDA (authority for vault token account)
    /// CHECK: PDA derived from vault_config
    #[account(
        seeds = [b"vault", vault_config.key().as_ref()],
        bump
    )]
    pub vault_pda: UncheckedAccount<'info>,

    /// Destination for withdrawn tokens
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,

    /// User triggering the withdrawal
    pub authorized_user: Signer<'info>,

    pub token_program: Program<'info, Token>,
}
```

**PDA Signing for CPI:**

```rust
pub fn withdraw_from_vault(ctx: Context<WithdrawFromVault>, amount: u64) -> Result<()> {
    let vault_config = &ctx.accounts.vault_config;

    // SECURITY: Enforce withdrawal limits
    require!(
        amount <= vault_config.max_withdrawal,
        ErrorCode::ExceedsWithdrawalLimit
    );

    // SECURITY: Construct PDA signer seeds
    let config_key = vault_config.key();
    let seeds = &[
        b"vault",
        config_key.as_ref(),
        &[ctx.bumps.vault_pda],
    ];
    let signer_seeds = &[&seeds[..]];

    // SECURITY: Transfer using PDA as authority
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.vault_pda.to_account_info(),
            },
            signer_seeds,
        ),
        amount,
    )?;

    msg!("Withdrawn {} tokens from vault", amount);
    Ok(())
}
```

### PDA Authority Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     PDA AUTHORITY FLOW                          │
└─────────────────────────────────────────────────────────────────┘

  1. User triggers instruction
     ┌──────────────┐
     │  User Wallet │ ──signs──▶ Transaction
     │   (Signer)   │
     └──────────────┘
              │
              │ calls
              ▼
  2. Program validates user authority
     ┌──────────────┐
     │  Your        │
     │  Program     │ ──checks──▶ vault_config.authorized_user == user
     └──────────────┘
              │
              │ if valid
              ▼
  3. Program signs CPI with PDA seeds
     ┌──────────────┐
     │  Vault PDA   │ ──"signs"──▶ Token Transfer
     │  (Authority) │     via invoke_signed
     └──────────────┘
              │
              │ transfers from
              ▼
  4. Token account executes transfer
     ┌──────────────┐     ┌──────────────┐
     │  Vault       │ ──▶ │ Destination  │
     │  Token Acct  │     │ Token Acct   │
     └──────────────┘     └──────────────┘
```

**Text description:** User signs a transaction calling your program. Program validates user is authorized via vault_config. Program constructs PDA seeds and uses invoke_signed to make the PDA "sign" the token transfer CPI. Token program transfers tokens from vault to destination.

### Security Considerations

| Consideration | Implementation |
|---------------|----------------|
| PDA seed uniqueness | Include config account key in seeds |
| Bump validation | Store and verify bump in config |
| User authorization | Validate user against config before CPI |
| Rate limiting | Consider time-based or amount limits |
| Re-initialization | Prevent config modification after vault funded |

### Pattern 02 Reference

While Pattern 02 doesn't use token vaults, the PDA derivation pattern is used for `admin_config` and `manager_account`:
- PDA seeds: `patterns/02-authority-checks/programs/secure/src/lib.rs:636-642`
- Bump storage and validation: Throughout secure program

---

## Combining Patterns

Real-world programs often combine multiple patterns:

```rust
/// Example: DeFi protocol combining all patterns
pub struct ProtocolConfig {
    // Pattern 2: Hierarchical Ownership
    pub super_admin: Pubkey,
    pub admin_list: [Pubkey; MAX_ADMINS],
    pub admin_count: u8,

    // Pattern 4: PDA Authority
    pub treasury_bump: u8,  // PDA for protocol treasury

    // Protocol state
    pub paused: bool,
    pub fee_basis_points: u16,
    pub bump: u8,
}

pub struct OperatorAccount {
    // Pattern 3: Delegated Authority
    pub authority: Pubkey,          // Admin who created this
    pub operator: Pubkey,           // The operator
    pub can_execute_trades: bool,   // Specific permission
    pub max_trade_size: u64,        // Permission limit
    pub is_active: bool,
    pub bump: u8,
}

/// Combined context using multiple patterns
#[derive(Accounts)]
pub struct ExecuteTrade<'info> {
    // Pattern 1 & 2: Admin list validation
    #[account(
        seeds = [b"protocol_config"],
        bump = protocol_config.bump,
        constraint = !protocol_config.paused @ ErrorCode::ProtocolPaused
    )]
    pub protocol_config: Account<'info, ProtocolConfig>,

    // Pattern 3: Delegated authority with permission check
    #[account(
        seeds = [b"operator", operator_account.operator.as_ref()],
        bump = operator_account.bump,
        constraint = is_admin(&protocol_config.admin_list, protocol_config.admin_count, &operator_account.authority)
            @ ErrorCode::InvalidAuthorityChain,
        constraint = operator_account.is_active @ ErrorCode::OperatorNotActive,
        constraint = operator_account.can_execute_trades @ ErrorCode::NoTradePermission
    )]
    pub operator_account: Account<'info, OperatorAccount>,

    // Pattern 4: PDA-controlled treasury
    #[account(
        mut,
        seeds = [b"treasury", protocol_config.key().as_ref()],
        bump = protocol_config.treasury_bump
    )]
    pub treasury: Account<'info, TokenAccount>,

    /// CHECK: Treasury PDA for signing
    #[account(
        seeds = [b"treasury_auth", protocol_config.key().as_ref()],
        bump
    )]
    pub treasury_authority: UncheckedAccount<'info>,

    // Operator must sign
    #[account(
        constraint = caller.key() == operator_account.operator @ ErrorCode::NotOperator
    )]
    pub caller: Signer<'info>,

    pub token_program: Program<'info, Token>,
}
```

---

## Security Checklist for All Patterns

Use this checklist when implementing any authority pattern:

### Account Types
- [ ] All authority accounts use `Signer<'info>`
- [ ] PDAs use proper `seeds` and `bump` constraints
- [ ] Read-only accounts don't accidentally have `mut`

### Constraints
- [ ] Every privileged operation has appropriate constraint
- [ ] Constraints use descriptive custom errors
- [ ] Helper functions are tested independently

### Authority Chain
- [ ] Can trace authority back to root (super_admin or program)
- [ ] Intermediate authorities are validated
- [ ] Deactivated/removed authorities are rejected

### Edge Cases
- [ ] Cannot remove last super_admin
- [ ] Cannot escalate own permissions
- [ ] Paused state blocks appropriate operations
- [ ] Re-initialization attacks prevented

### Testing
- [ ] Test authorized operations succeed
- [ ] Test unauthorized operations fail with correct errors
- [ ] Test edge cases (empty lists, max capacity, etc.)

---

## Summary

| Pattern | Best For | Key Validation |
|---------|----------|----------------|
| Admin Lists | Multi-admin protocols | `is_admin()` helper + Signer |
| Hierarchical | Tiered permissions | Level-specific constraints |
| Delegated | Granular permissions | Permission flags + chain validation |
| PDA Authority | Program-controlled accounts | `invoke_signed` with seeds |

All patterns should combine:
1. **Signer** type for identity verification
2. **Constraints** for authorization validation
3. **PDA seeds** for account integrity
4. **Custom errors** for clear failure messages

## Related Documentation

- [Ownership Model](./ownership-model.md) - Fundamental concepts
- [Common Mistakes](./common-mistakes.md) - What to avoid
- [Decision Tree](./decision-tree.md) - Choosing the right pattern
