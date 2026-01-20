//! # Vulnerable Authority Checks Program
//!
//! This program demonstrates **INSECURE** authority check patterns in Solana.
//! It is designed for educational purposes to show how privilege escalation
//! vulnerabilities occur when proper authority validation is missing.
//!
//! ## Learning Objectives
//!
//! After studying this code, you will understand:
//! 1. Why signer verification is critical for authority checks
//! 2. How missing authority validation enables privilege escalation
//! 3. The difference between `AccountInfo` and `Signer` in Anchor
//! 4. Why authority chains must be validated at each level
//!
//! ## Authority Hierarchy (Intended)
//!
//! ```text
//! super_admin (highest privilege)
//!     │
//!     ├── Can pause/unpause protocol
//!     ├── Can add/remove admins
//!     │
//!     └── admin_list members
//!             │
//!             ├── Can modify fees
//!             ├── Can create managers
//!             │
//!             └── managers
//!                     │
//!                     └── Limited delegated permissions
//! ```
//!
//! ## CRITICAL WARNING
//!
//! **DO NOT USE THIS CODE IN PRODUCTION!**
//!
//! This program intentionally contains security vulnerabilities for
//! educational demonstration. Each vulnerability is marked with
//! `// VULNERABILITY:` comments explaining the security flaw.
//!
//! See the companion `secure-authority-checks` program for the correct
//! implementation with proper authority validation.

use anchor_lang::prelude::*;

// Program ID - generated from vulnerable-keypair.json
declare_id!("hZ1d6UbD6akV9gW8JrCHrtVrD889bW3aLQFaesgm9eh");

/// Maximum number of administrators allowed in the admin_list.
/// Using a fixed-size array for predictable account sizing.
pub const MAX_ADMINS: usize = 3;

// =============================================================================
// PROGRAM ENTRY POINT
// =============================================================================

/// The vulnerable authority checks program module.
///
/// This program demonstrates common authority validation mistakes that
/// lead to privilege escalation vulnerabilities in Solana programs.
#[program]
pub mod vulnerable_authority_checks {
    use super::*;

    // =========================================================================
    // INSTRUCTION: initialize_config
    // =========================================================================

    /// Initializes the admin configuration with a super_admin.
    ///
    /// This is the only secure instruction in this program - it properly
    /// validates that the super_admin is a signer and initializes the
    /// configuration correctly.
    ///
    /// # Security
    ///
    /// This instruction is SAFE because:
    /// - The `super_admin` is a `Signer`, ensuring cryptographic verification
    /// - The PDA is derived deterministically, preventing account substitution
    /// - Initial state is set correctly with super_admin in admin_list
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The PDA account to initialize (created by this ix)
    /// - `super_admin`: The signer who becomes the super administrator
    /// - `system_program`: Required for account creation
    pub fn initialize_config(ctx: Context<InitializeConfig>) -> Result<()> {
        // Get mutable reference to the admin config account
        let admin_config = &mut ctx.accounts.admin_config;

        // SECURITY: super_admin is a Signer, so we know this is authentic
        admin_config.super_admin = ctx.accounts.super_admin.key();

        // Initialize the admin list with super_admin as the first admin
        // This ensures super_admin has both super_admin AND admin privileges
        admin_config.admin_list = [Pubkey::default(); MAX_ADMINS];
        admin_config.admin_list[0] = ctx.accounts.super_admin.key();
        admin_config.admin_count = 1;

        // Set default fee to 1% (100 basis points)
        admin_config.fee_basis_points = 100;

        // Protocol starts in active (unpaused) state
        admin_config.paused = false;

        // Store the bump seed for future PDA derivations
        admin_config.bump = ctx.bumps.admin_config;

        // Log the initialization for on-chain transparency
        msg!("Admin config initialized with super_admin: {}", admin_config.super_admin);

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: add_admin (VULNERABLE)
    // =========================================================================

    /// Adds a new administrator to the admin_list.
    ///
    /// # VULNERABILITIES
    ///
    /// This instruction is **CRITICALLY INSECURE** because:
    ///
    /// 1. **No signer verification**: The `caller` is `AccountInfo`, not `Signer`.
    ///    Anyone can pass any pubkey as the caller without proving ownership.
    ///
    /// 2. **No authority validation**: There's no check that `caller` equals
    ///    `admin_config.super_admin`. Any account can claim to be authorized.
    ///
    /// 3. **Privilege escalation**: An attacker can add their own pubkey to
    ///    the admin_list, gaining administrative privileges.
    ///
    /// # Attack Scenario
    ///
    /// ```text
    /// Attacker creates transaction:
    ///   - caller = attacker's pubkey (not signed)
    ///   - new_admin = attacker's pubkey
    ///   - Result: Attacker is now an admin!
    /// ```
    pub fn add_admin(ctx: Context<AddAdmin>) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;

        // VULNERABILITY: No check that caller is super_admin
        // A secure implementation would verify:
        //   require!(caller.key() == admin_config.super_admin, ErrorCode::NotSuperAdmin);

        // VULNERABILITY: No signer verification on caller
        // The caller account is AccountInfo, not Signer, so anyone can
        // pass any pubkey here without proving they own the private key

        // Check if admin list is full (this check is present but doesn't help security)
        if admin_config.admin_count as usize >= MAX_ADMINS {
            return Err(ErrorCode::AdminListFull.into());
        }

        // VULNERABILITY: Anyone can add themselves as admin
        // This adds the new_admin to the list without any authorization check
        let new_admin_key = ctx.accounts.new_admin.key();
        let index = admin_config.admin_count as usize;
        admin_config.admin_list[index] = new_admin_key;
        admin_config.admin_count += 1;

        // Log the addition (attackers love leaving traces)
        msg!("Admin added: {}", new_admin_key);

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: update_fee (VULNERABLE)
    // =========================================================================

    /// Updates the protocol fee configuration.
    ///
    /// # VULNERABILITIES
    ///
    /// This instruction is **INSECURE** because:
    ///
    /// 1. **No signer verification**: The `caller` is not required to sign.
    ///
    /// 2. **No admin_list validation**: There's no check that `caller` is in
    ///    the `admin_config.admin_list` array.
    ///
    /// 3. **Economic attack**: Anyone can set arbitrary fees, potentially
    ///    setting fees to 100% (10000 basis points) to steal all funds.
    ///
    /// # Attack Scenario
    ///
    /// ```text
    /// Attacker creates transaction:
    ///   - caller = any pubkey (not signed)
    ///   - new_fee = 10000 (100% fee - steals everything)
    ///   - Result: Protocol now takes 100% of all transactions!
    /// ```
    pub fn update_fee(ctx: Context<UpdateFee>, new_fee: u16) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;

        // VULNERABILITY: No check that caller is in admin_list
        // A secure implementation would verify:
        //   require!(is_admin(&admin_config.admin_list, caller.key()), ErrorCode::NotAdmin);

        // VULNERABILITY: No signer verification
        // The transaction doesn't require the caller to sign, so anyone
        // can impersonate any admin by passing their pubkey

        // VULNERABILITY: Any user can modify protocol fees
        // This allows attackers to set fees to 0 (no revenue) or
        // 10000 basis points (100%, stealing all funds)
        admin_config.fee_basis_points = new_fee;

        // Log the fee update
        msg!("Fee updated to {} basis points", new_fee);

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: pause_protocol (VULNERABLE)
    // =========================================================================

    /// Pauses the protocol, preventing all operations.
    ///
    /// # VULNERABILITIES
    ///
    /// This instruction is **INSECURE** because:
    ///
    /// 1. **No super_admin check**: Anyone can pause the protocol, not just
    ///    the super_admin who should have exclusive pause authority.
    ///
    /// 2. **No signer verification**: No signature required from any authority.
    ///
    /// 3. **Denial of Service**: An attacker can permanently pause the protocol,
    ///    preventing all legitimate operations.
    ///
    /// # Attack Scenario
    ///
    /// ```text
    /// Attacker creates transaction:
    ///   - caller = any pubkey (not signed)
    ///   - Result: Protocol is paused, all operations blocked!
    /// ```
    pub fn pause_protocol(ctx: Context<PauseProtocol>) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;

        // VULNERABILITY: No check that caller is super_admin
        // Only super_admin should be able to pause the protocol, but
        // this instruction performs no authorization check at all

        // VULNERABILITY: pause_protocol is super_admin-only but unprotected
        // This is a critical security function that can disable the entire
        // protocol, yet anyone can call it
        admin_config.paused = true;

        // Log the pause action
        msg!("Protocol paused");

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: create_manager (VULNERABLE)
    // =========================================================================

    /// Creates a new manager account with delegated permissions.
    ///
    /// # VULNERABILITIES
    ///
    /// This instruction is **INSECURE** because:
    ///
    /// 1. **No admin validation**: The `admin` account is not verified against
    ///    the `admin_config.admin_list`.
    ///
    /// 2. **No signer verification**: The `admin` is not required to sign.
    ///
    /// 3. **Permission escalation**: Anyone can create manager accounts with
    ///    arbitrary permissions, potentially granting themselves pause access.
    ///
    /// # Attack Scenario
    ///
    /// ```text
    /// Attacker creates transaction:
    ///   - admin = any pubkey (not signed, not validated)
    ///   - manager = attacker's pubkey
    ///   - can_modify_fees = true
    ///   - can_pause = true
    ///   - Result: Attacker has a manager account with full permissions!
    /// ```
    pub fn create_manager(
        ctx: Context<CreateManager>,
        can_modify_fees: bool,
        can_pause: bool,
    ) -> Result<()> {
        let manager_account = &mut ctx.accounts.manager_account;

        // VULNERABILITY: admin not validated against admin_list
        // The admin_config is loaded but never checked against the admin
        // A secure implementation would verify:
        //   require!(is_admin(&admin_config.admin_list, admin.key()), ErrorCode::NotAdmin);

        // VULNERABILITY: Any user can create managers
        // Since there's no validation, anyone can create manager accounts
        // and assign themselves arbitrary permissions

        // Set the authority to the (unvalidated) admin
        manager_account.authority = ctx.accounts.admin.key();

        // Set the manager to the provided pubkey
        manager_account.manager = ctx.accounts.manager.key();

        // Assign permissions (attacker can give themselves any permissions)
        manager_account.can_modify_fees = can_modify_fees;
        manager_account.can_pause = can_pause;

        // Manager starts active
        manager_account.is_active = true;

        // Store bump for PDA derivation
        manager_account.bump = ctx.bumps.manager_account;

        // Log the manager creation
        msg!(
            "Manager created: {} with authority: {}",
            manager_account.manager,
            manager_account.authority
        );

        Ok(())
    }
}

// =============================================================================
// ACCOUNT STRUCTURES
// =============================================================================

/// Global administrator configuration account.
///
/// This account stores the protocol's administrative hierarchy, including
/// the super_admin, admin list, and critical protocol settings like fees
/// and pause state.
///
/// ## Authority Levels (Intended)
///
/// | Field | Authority Level | Who Can Modify |
/// |-------|----------------|----------------|
/// | `super_admin` | Highest | Only at init |
/// | `admin_list` | High | super_admin only |
/// | `fee_basis_points` | Medium | admin_list members |
/// | `paused` | Highest | super_admin only |
///
/// ## Account Size Calculation
///
/// | Field | Size (bytes) |
/// |-------|--------------|
/// | Discriminator | 8 |
/// | super_admin | 32 |
/// | admin_list | 96 (3 * 32) |
/// | admin_count | 1 |
/// | fee_basis_points | 2 |
/// | paused | 1 |
/// | bump | 1 |
/// | **Total** | **141** |
#[account]
pub struct AdminConfig {
    /// The highest-privilege administrator who can:
    /// - Add/remove other admins
    /// - Pause/unpause the protocol
    /// - Perform any admin action
    pub super_admin: Pubkey,

    /// Fixed-size array of authorized administrators.
    /// These accounts can modify fees and create managers.
    /// Using fixed array instead of Vec for predictable account sizing.
    pub admin_list: [Pubkey; MAX_ADMINS],

    /// Number of active administrators in the admin_list.
    /// Valid entries are admin_list[0..admin_count].
    pub admin_count: u8,

    /// Protocol fee in basis points (1/100th of a percent).
    /// 100 = 1%, 500 = 5%, 10000 = 100%
    /// Only admins should be able to modify this.
    pub fee_basis_points: u16,

    /// Emergency pause flag.
    /// When true, all protocol operations should be blocked.
    /// Only super_admin should be able to modify this.
    pub paused: bool,

    /// PDA bump seed for account derivation.
    /// Used to reconstruct the PDA address off-chain.
    pub bump: u8,
}

impl AdminConfig {
    /// Account size including Anchor discriminator.
    /// 8 (discriminator) + 32 + 96 + 1 + 2 + 1 + 1 = 141 bytes
    pub const ACCOUNT_SIZE: usize = 8 + 32 + 96 + 1 + 2 + 1 + 1;
}

/// Manager account with delegated administrative permissions.
///
/// Managers are created by admins and can have limited permissions
/// delegated to them. This allows for granular access control.
///
/// ## Permission Flags
///
/// | Flag | Permission |
/// |------|-----------|
/// | `can_modify_fees` | Can update protocol fees |
/// | `can_pause` | Can pause the protocol |
///
/// ## Account Size Calculation
///
/// | Field | Size (bytes) |
/// |-------|--------------|
/// | Discriminator | 8 |
/// | authority | 32 |
/// | manager | 32 |
/// | can_modify_fees | 1 |
/// | can_pause | 1 |
/// | is_active | 1 |
/// | bump | 1 |
/// | **Total** | **76** |
#[account]
pub struct ManagerAccount {
    /// The admin who created this manager.
    /// Used to track the authority chain.
    pub authority: Pubkey,

    /// The manager's public key.
    /// This is the account that holds the manager role.
    pub manager: Pubkey,

    /// Permission to modify protocol fees.
    /// If true, this manager can call fee update instructions.
    pub can_modify_fees: bool,

    /// Permission to pause the protocol.
    /// If true, this manager can pause operations.
    pub can_pause: bool,

    /// Whether this manager account is currently active.
    /// Inactive managers cannot use their permissions.
    pub is_active: bool,

    /// PDA bump seed for account derivation.
    pub bump: u8,
}

impl ManagerAccount {
    /// Account size including Anchor discriminator.
    /// 8 + 32 + 32 + 1 + 1 + 1 + 1 = 76 bytes
    pub const ACCOUNT_SIZE: usize = 8 + 32 + 32 + 1 + 1 + 1 + 1;
}

// =============================================================================
// ACCOUNT VALIDATION CONTEXTS
// =============================================================================

/// Accounts for the initialize_config instruction.
///
/// This is the only account context with proper validation in this
/// vulnerable program, serving as an example of correct implementation.
#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    /// The admin config PDA to be created.
    /// Seeds: ["admin_config"]
    /// Space: AdminConfig::ACCOUNT_SIZE
    #[account(
        init,
        payer = super_admin,
        space = AdminConfig::ACCOUNT_SIZE,
        seeds = [b"admin_config"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The super administrator who will own this config.
    /// SECURITY: This is a Signer, ensuring proper authorization.
    #[account(mut)]
    pub super_admin: Signer<'info>,

    /// System program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts for the add_admin instruction.
///
/// ## SECURITY FLAWS
///
/// This context demonstrates multiple security anti-patterns:
///
/// 1. `caller` is `UncheckedAccount` instead of `Signer`
///    - No signature verification
///    - Anyone can pass any pubkey
///
/// 2. No `has_one` constraint linking to `admin_config.super_admin`
///    - No validation that caller is authorized
///
/// 3. No custom constraint checking authority
///    - Missing: `#[account(constraint = caller.key() == admin_config.super_admin)]`
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    /// The admin config to modify.
    /// Note: mut allows modification but provides no authorization.
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to add an admin.
    /// VULNERABILITY: This is UncheckedAccount, not Signer!
    /// Anyone can pass any pubkey here without proving ownership.
    /// CHECK: This account is intentionally unchecked to demonstrate the vulnerability.
    pub caller: UncheckedAccount<'info>,

    /// The new admin to add to the admin_list.
    /// CHECK: This account just provides a pubkey to add.
    pub new_admin: UncheckedAccount<'info>,
}

/// Accounts for the update_fee instruction.
///
/// ## SECURITY FLAWS
///
/// 1. `caller` is not a `Signer` - no signature required
/// 2. No validation that `caller` is in `admin_config.admin_list`
/// 3. No constraint preventing unauthorized fee modification
#[derive(Accounts)]
pub struct UpdateFee<'info> {
    /// The admin config containing fee settings.
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to update fees.
    /// VULNERABILITY: Not a Signer, no admin_list validation.
    /// CHECK: Intentionally unchecked to demonstrate vulnerability.
    pub caller: UncheckedAccount<'info>,
}

/// Accounts for the pause_protocol instruction.
///
/// ## SECURITY FLAWS
///
/// 1. `caller` is not a `Signer`
/// 2. No check that `caller` is `admin_config.super_admin`
/// 3. Critical security function completely unprotected
#[derive(Accounts)]
pub struct PauseProtocol<'info> {
    /// The admin config containing pause state.
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to pause.
    /// VULNERABILITY: No signer check, no super_admin check.
    /// CHECK: Intentionally unchecked to demonstrate vulnerability.
    pub caller: UncheckedAccount<'info>,
}

/// Accounts for the create_manager instruction.
///
/// ## SECURITY FLAWS
///
/// 1. `admin` is not a `Signer`
/// 2. `admin` is not validated against `admin_config.admin_list`
/// 3. `admin_config` is loaded but never used for validation
/// 4. Anyone can create managers with arbitrary permissions
#[derive(Accounts)]
pub struct CreateManager<'info> {
    /// The admin config (loaded but NOT used for validation).
    /// In a secure implementation, we would check that admin
    /// is in admin_config.admin_list.
    pub admin_config: Account<'info, AdminConfig>,

    /// The manager account PDA to create.
    /// Seeds: ["manager", manager.key]
    #[account(
        init,
        payer = payer,
        space = ManagerAccount::ACCOUNT_SIZE,
        seeds = [b"manager", manager.key().as_ref()],
        bump
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    /// The admin creating this manager.
    /// VULNERABILITY: Not a Signer, not validated against admin_list.
    /// CHECK: Intentionally unchecked to demonstrate vulnerability.
    pub admin: UncheckedAccount<'info>,

    /// The user who will become a manager.
    /// CHECK: This account just provides a pubkey for the manager role.
    pub manager: UncheckedAccount<'info>,

    /// Account paying for manager account creation.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// System program for account creation.
    pub system_program: Program<'info, System>,
}

// =============================================================================
// ERROR CODES
// =============================================================================

/// Custom error codes for authority-related failures.
///
/// These errors are defined for completeness but are NOT USED in the
/// vulnerable implementation. The secure version uses these errors
/// to reject unauthorized operations.
///
/// In a secure program, these errors would be returned when:
/// - An unauthorized user attempts privileged operations
/// - Authority chain validation fails
/// - Permission requirements are not met
#[error_code]
pub enum ErrorCode {
    /// The caller is not authorized to perform this action.
    /// Generic authorization failure for any permission check.
    #[msg("Not authorized to perform this action")]
    Unauthorized,

    /// The caller is not the super_admin.
    /// Returned when a super_admin-only operation is attempted
    /// by someone other than the super_admin.
    #[msg("Only super_admin can perform this action")]
    NotSuperAdmin,

    /// The caller is not in the admin_list.
    /// Returned when an admin-only operation is attempted
    /// by someone not in the admin_list array.
    #[msg("Only admins can perform this action")]
    NotAdmin,

    /// The admin_list has reached maximum capacity.
    /// No more admins can be added until one is removed.
    #[msg("Admin list is full - maximum admins reached")]
    AdminListFull,

    /// The protocol is currently paused.
    /// Operations cannot proceed until unpaused by super_admin.
    #[msg("Protocol is paused - operations are disabled")]
    ProtocolPaused,
}
