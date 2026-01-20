//! # Secure Authority Checks Program
//!
//! This program demonstrates **SECURE** authority check patterns in Solana.
//! It is designed for educational purposes to show how to properly implement
//! authority validation to prevent privilege escalation vulnerabilities.
//!
//! ## Learning Objectives
//!
//! After studying this code, you will understand:
//! 1. How to use `Signer<'info>` to enforce cryptographic signature verification
//! 2. How to use `constraint` expressions to validate authority relationships
//! 3. The difference between account-level and instruction-level authority
//! 4. How to implement multi-tier authority hierarchies securely
//!
//! ## Authority Hierarchy (Enforced)
//!
//! ```text
//! super_admin (highest privilege)
//!     |
//!     +-- Can pause/unpause protocol (ENFORCED: super_admin-only constraint)
//!     +-- Can add/remove admins (ENFORCED: super_admin-only constraint)
//!     |
//!     +-- admin_list members
//!             |
//!             +-- Can modify fees (ENFORCED: admin_list membership check)
//!             +-- Can create managers (ENFORCED: admin_list membership check)
//!             |
//!             +-- managers
//!                     |
//!                     +-- Limited delegated permissions
//! ```
//!
//! ## SECURITY PATTERNS DEMONSTRATED
//!
//! This program uses Anchor's constraint system to enforce authority:
//!
//! 1. **`Signer<'info>`**: Enforces cryptographic signature verification
//! 2. **`constraint = ... @ ErrorCode`**: Validates authority relationships
//! 3. **Helper functions**: `is_admin()` for reusable validation logic
//!
//! Compare this to the vulnerable `vulnerable-authority-checks` program
//! to see exactly what security measures were missing.

use anchor_lang::prelude::*;

// Program ID - generated from secure-keypair.json
declare_id!("7EjQ3phjWPknKc5ASAdcA91ikNXhNapNvbMRStxJ3R7f");

/// Maximum number of administrators allowed in the admin_list.
/// Using a fixed-size array for predictable account sizing.
pub const MAX_ADMINS: usize = 3;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Checks if a given pubkey is in the admin_list.
///
/// # SECURITY: Reusable Authority Validation
///
/// This helper function provides a consistent way to check admin membership
/// across multiple instructions. Using a helper function ensures:
/// 1. Consistent validation logic everywhere
/// 2. No risk of typos in repeated constraint expressions
/// 3. Easy auditing of authority checks
///
/// # Arguments
///
/// * `admin_list` - The fixed-size array of admin pubkeys
/// * `admin_count` - The number of valid entries in admin_list
/// * `key` - The pubkey to check for membership
///
/// # Returns
///
/// `true` if the key is found in admin_list[0..admin_count], `false` otherwise
pub fn is_admin(admin_list: &[Pubkey; MAX_ADMINS], admin_count: u8, key: &Pubkey) -> bool {
    // SECURITY: Only check valid entries (0..admin_count)
    // This prevents reading uninitialized array slots
    let count = admin_count as usize;
    admin_list.iter().take(count).any(|admin| admin == key)
}

// =============================================================================
// ERROR CODES
// =============================================================================

/// Custom error codes for authority-related failures.
///
/// These errors are actively used in constraint expressions to provide
/// meaningful error messages when authorization checks fail.
///
/// ## Educational Value
///
/// Each error clearly indicates what authorization requirement was violated,
/// helping developers and users understand why a transaction was rejected.
#[error_code]
pub enum ErrorCode {
    /// The caller is not authorized to perform this action.
    /// Generic authorization failure for any permission check.
    #[msg("Not authorized to perform this action")]
    Unauthorized,

    /// The caller is not the super_admin.
    /// Returned when a super_admin-only operation is attempted
    /// by someone other than the super_admin.
    ///
    /// SECURITY: This error is used in constraints like:
    /// `constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin`
    #[msg("Only super_admin can perform this action")]
    NotSuperAdmin,

    /// The caller is not in the admin_list.
    /// Returned when an admin-only operation is attempted
    /// by someone not in the admin_list array.
    ///
    /// SECURITY: This error is used with the is_admin() helper:
    /// `constraint = is_admin(...) @ ErrorCode::NotAdmin`
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

    /// Cannot remove super_admin from the admin_list.
    /// The super_admin must always remain in the admin list.
    #[msg("Cannot remove super_admin from admin list")]
    CannotRemoveSuperAdmin,

    /// The manager account is not active.
    /// Deactivated managers cannot perform delegated operations.
    #[msg("Manager account is deactivated")]
    ManagerNotActive,

    /// The admin to remove was not found in the admin_list.
    /// Cannot remove an admin that doesn't exist.
    #[msg("Admin not found in admin list")]
    AdminNotFound,
}

// =============================================================================
// PROGRAM ENTRY POINT
// =============================================================================

/// The secure authority checks program module.
///
/// This program demonstrates proper authority validation patterns that
/// prevent privilege escalation vulnerabilities in Solana programs.
#[program]
pub mod secure_authority_checks {
    use super::*;

    // =========================================================================
    // INSTRUCTION: initialize_config
    // =========================================================================

    /// Initializes the admin configuration with a super_admin.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: The `super_admin` is a `Signer`, ensuring cryptographic verification
    /// - SECURITY: The PDA is derived deterministically, preventing account substitution
    /// - SECURITY: Initial state is set correctly with super_admin in admin_list
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
        // The Signer type in Anchor enforces that the transaction was signed
        // by the private key corresponding to this public key
        admin_config.super_admin = ctx.accounts.super_admin.key();

        // Initialize the admin list with super_admin as the first admin
        // SECURITY: This ensures super_admin has both super_admin AND admin privileges
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
    // INSTRUCTION: add_admin (SECURE)
    // =========================================================================

    /// Adds a new administrator to the admin_list.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: `caller` is `Signer<'info>` - enforces cryptographic signature verification
    /// - SECURITY: Constraint validates `caller.key() == admin_config.super_admin`
    /// - SECURITY: Only the super_admin can add new admins
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The admin config PDA (must be initialized)
    /// - `caller`: Must be super_admin AND must sign the transaction
    /// - `new_admin`: The pubkey to add to admin_list
    pub fn add_admin(ctx: Context<AddAdmin>) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;

        // SECURITY: Authority validation is done in the Accounts struct via constraint
        // The constraint `caller.key() == admin_config.super_admin` ensures
        // only the super_admin can reach this point

        // Check if admin list is full
        if admin_config.admin_count as usize >= MAX_ADMINS {
            return Err(ErrorCode::AdminListFull.into());
        }

        // SECURITY: Only super_admin can add admins (enforced by constraint)
        let new_admin_key = ctx.accounts.new_admin.key();
        let index = admin_config.admin_count as usize;
        admin_config.admin_list[index] = new_admin_key;
        admin_config.admin_count += 1;

        msg!("Admin added by super_admin: {}", new_admin_key);

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: update_fee (SECURE)
    // =========================================================================

    /// Updates the protocol fee configuration.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: `caller` is `Signer<'info>` - enforces caller owns the private key
    /// - SECURITY: Constraint uses `is_admin()` to verify caller is in admin_list
    /// - SECURITY: Only admin_list members can modify fees
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The admin config PDA containing fee settings
    /// - `caller`: Must be in admin_list AND must sign the transaction
    pub fn update_fee(ctx: Context<UpdateFee>, new_fee: u16) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;

        // SECURITY: Authority validation is done in the Accounts struct via constraint
        // The constraint `is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key)`
        // ensures only admin_list members can reach this point

        // SECURITY: Only admins can modify protocol fees
        admin_config.fee_basis_points = new_fee;

        msg!("Fee updated to {} basis points by admin", new_fee);

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: pause_protocol (SECURE)
    // =========================================================================

    /// Pauses the protocol, preventing all operations.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: `caller` is `Signer<'info>` - enforces signature verification
    /// - SECURITY: Constraint validates `caller.key() == admin_config.super_admin`
    /// - SECURITY: Only super_admin can pause - this is a critical security function
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The admin config PDA containing pause state
    /// - `caller`: Must be super_admin AND must sign the transaction
    pub fn pause_protocol(ctx: Context<PauseProtocol>) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;

        // SECURITY: pause_protocol is super_admin-only, enforced by constraint
        // Pausing is a critical operation that could affect all users,
        // so it requires the highest level of authorization
        admin_config.paused = true;

        msg!("Protocol paused by super_admin");

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: unpause_protocol (SECURE)
    // =========================================================================

    /// Unpauses the protocol, allowing operations to resume.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: `caller` is `Signer<'info>` - enforces signature verification
    /// - SECURITY: Constraint validates `caller.key() == admin_config.super_admin`
    /// - SECURITY: Only super_admin can unpause - mirrors pause_protocol security
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The admin config PDA containing pause state
    /// - `caller`: Must be super_admin AND must sign the transaction
    pub fn unpause_protocol(ctx: Context<UnpauseProtocol>) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;

        // SECURITY: unpause requires super_admin authority
        // Only the same authority that can pause should be able to unpause
        admin_config.paused = false;

        msg!("Protocol unpaused by super_admin");

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: create_manager (SECURE)
    // =========================================================================

    /// Creates a new manager account with delegated permissions.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: `admin` is `Signer<'info>` - enforces signature verification
    /// - SECURITY: Constraint uses `is_admin()` to validate admin against admin_list
    /// - SECURITY: Custom constraint achieves same validation as has_one would
    ///
    /// ## Note on has_one vs constraint
    ///
    /// The `has_one` constraint is typically used for simple field matching:
    /// ```rust,ignore
    /// #[account(has_one = authority)]
    /// pub user_account: Account<'info, UserAccount>,
    /// pub authority: Signer<'info>,
    /// ```
    ///
    /// For complex checks like array membership, we use custom constraints instead:
    /// ```rust,ignore
    /// #[account(constraint = is_admin(...) @ ErrorCode::NotAdmin)]
    /// ```
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The admin config PDA for authority validation
    /// - `manager_account`: The manager PDA to create
    /// - `admin`: Must be in admin_list AND must sign the transaction
    /// - `manager`: The user who will become a manager
    /// - `payer`: Account paying for manager account creation
    /// - `system_program`: Required for account creation
    pub fn create_manager(
        ctx: Context<CreateManager>,
        can_modify_fees: bool,
        can_pause: bool,
    ) -> Result<()> {
        let manager_account = &mut ctx.accounts.manager_account;

        // SECURITY: admin validated against admin_list via constraint
        // The constraint ensures only authorized admins can create managers

        // Set the authority to the validated admin
        manager_account.authority = ctx.accounts.admin.key();

        // Set the manager to the provided pubkey
        manager_account.manager = ctx.accounts.manager.key();

        // Assign permissions (only an authorized admin can grant these)
        manager_account.can_modify_fees = can_modify_fees;
        manager_account.can_pause = can_pause;

        // Manager starts active
        manager_account.is_active = true;

        // Store bump for PDA derivation
        manager_account.bump = ctx.bumps.manager_account;

        msg!(
            "Manager created: {} with authority: {} (validated admin)",
            manager_account.manager,
            manager_account.authority
        );

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: remove_admin (SECURE - Enhancement)
    // =========================================================================

    /// Removes an administrator from the admin_list.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: `caller` is `Signer<'info>` - enforces signature verification
    /// - SECURITY: Constraint validates `caller.key() == admin_config.super_admin`
    /// - SECURITY: Only super_admin can remove admins
    /// - SECURITY: Cannot remove super_admin from list (prevents lockout)
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The admin config PDA (must be initialized)
    /// - `caller`: Must be super_admin AND must sign the transaction
    /// - `admin_to_remove`: The pubkey to remove from admin_list
    pub fn remove_admin(ctx: Context<RemoveAdmin>) -> Result<()> {
        let admin_config = &mut ctx.accounts.admin_config;
        let admin_to_remove = ctx.accounts.admin_to_remove.key();

        // SECURITY: Only super_admin can remove admins (enforced by constraint)

        // SECURITY: Prevent removing super_admin from admin_list
        // This prevents the super_admin from accidentally locking themselves out
        if admin_to_remove == admin_config.super_admin {
            return Err(ErrorCode::CannotRemoveSuperAdmin.into());
        }

        // Find the admin in the list
        let count = admin_config.admin_count as usize;
        let mut found_index: Option<usize> = None;

        for i in 0..count {
            if admin_config.admin_list[i] == admin_to_remove {
                found_index = Some(i);
                break;
            }
        }

        // Return error if admin not found
        let index = found_index.ok_or(ErrorCode::AdminNotFound)?;

        // Remove admin by shifting remaining entries left
        // SECURITY: This maintains array integrity without leaving gaps
        for i in index..count - 1 {
            admin_config.admin_list[i] = admin_config.admin_list[i + 1];
        }

        // Clear the last slot and decrement count
        admin_config.admin_list[count - 1] = Pubkey::default();
        admin_config.admin_count -= 1;

        msg!("Admin removed by super_admin: {}", admin_to_remove);

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: deactivate_manager (SECURE)
    // =========================================================================

    /// Deactivates a manager account, revoking their permissions.
    ///
    /// # Security
    ///
    /// This instruction is SECURE because:
    /// - SECURITY: `caller` is `Signer<'info>` - enforces signature verification
    /// - SECURITY: Constraint uses `is_admin()` to validate caller against admin_list
    /// - SECURITY: Only admins can deactivate managers
    ///
    /// # Accounts
    ///
    /// - `admin_config`: The admin config PDA for authority validation
    /// - `manager_account`: The manager account to deactivate
    /// - `caller`: Must be in admin_list AND must sign the transaction
    pub fn deactivate_manager(ctx: Context<DeactivateManager>) -> Result<()> {
        let manager_account = &mut ctx.accounts.manager_account;

        // SECURITY: Only admins can deactivate managers (enforced by constraint)
        manager_account.is_active = false;

        msg!("Manager deactivated: {}", manager_account.manager);

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
/// ## Authority Levels (Enforced in Secure Version)
///
/// | Field | Authority Level | Who Can Modify | Enforcement |
/// |-------|----------------|----------------|-------------|
/// | `super_admin` | Highest | Only at init | N/A |
/// | `admin_list` | High | super_admin only | `constraint` |
/// | `fee_basis_points` | Medium | admin_list members | `is_admin()` |
/// | `paused` | Highest | super_admin only | `constraint` |
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
    /// SECURITY: Only admins can modify this (enforced by constraint).
    pub fee_basis_points: u16,

    /// Emergency pause flag.
    /// When true, all protocol operations should be blocked.
    /// SECURITY: Only super_admin can modify this (enforced by constraint).
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
    /// SECURITY: Used to track the authority chain.
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
    /// SECURITY: Inactive managers cannot use their permissions.
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
// ACCOUNT VALIDATION CONTEXTS (SECURE)
// =============================================================================

/// Accounts for the initialize_config instruction.
///
/// This context properly validates that the super_admin signs the transaction.
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
    /// SECURITY: Signer type enforces cryptographic signature verification.
    /// The super_admin must sign this transaction to prove they own the private key.
    #[account(mut)]
    pub super_admin: Signer<'info>,

    /// System program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts for the add_admin instruction.
///
/// ## SECURITY IMPLEMENTATION
///
/// This context demonstrates proper authority validation:
///
/// 1. SECURITY: `caller` is `Signer<'info>` - enforces signature verification
/// 2. SECURITY: `constraint` validates caller equals super_admin
/// 3. SECURITY: Transaction will fail with NotSuperAdmin if unauthorized
#[derive(Accounts)]
pub struct AddAdmin<'info> {
    /// The admin config to modify.
    /// SECURITY: Seeds constraint ensures we're modifying the correct PDA.
    /// SECURITY: constraint validates caller is the super_admin.
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Only super_admin can add new admins
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to add an admin.
    /// SECURITY: Signer type enforces cryptographic signature verification.
    /// The caller must prove they own the private key by signing the transaction.
    pub caller: Signer<'info>,

    /// The new admin to add to the admin_list.
    /// CHECK: This account just provides a pubkey to add.
    pub new_admin: UncheckedAccount<'info>,
}

/// Accounts for the update_fee instruction.
///
/// ## SECURITY IMPLEMENTATION
///
/// 1. SECURITY: `caller` is `Signer<'info>` - enforces caller owns the private key
/// 2. SECURITY: `constraint` uses is_admin() to check admin_list membership
/// 3. SECURITY: Only admin_list members can modify fees
#[derive(Accounts)]
pub struct UpdateFee<'info> {
    /// The admin config containing fee settings.
    /// SECURITY: Seeds constraint ensures we're modifying the correct PDA.
    /// SECURITY: Custom constraint validates caller is in admin_list.
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Only admin_list members can modify fees
        constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key) @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to update fees.
    /// SECURITY: Signer enforces caller owns the private key.
    pub caller: Signer<'info>,
}

/// Accounts for the pause_protocol instruction.
///
/// ## SECURITY IMPLEMENTATION
///
/// 1. SECURITY: `caller` is `Signer<'info>` - enforces signature verification
/// 2. SECURITY: `constraint` validates caller equals super_admin
/// 3. SECURITY: Pause is a critical function requiring highest authority
#[derive(Accounts)]
pub struct PauseProtocol<'info> {
    /// The admin config containing pause state.
    /// SECURITY: Seeds constraint ensures we're modifying the correct PDA.
    /// SECURITY: constraint validates caller is the super_admin.
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: pause_protocol is super_admin-only, enforced by constraint
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to pause.
    /// SECURITY: Signer type enforces cryptographic signature verification.
    pub caller: Signer<'info>,
}

/// Accounts for the unpause_protocol instruction.
///
/// ## SECURITY IMPLEMENTATION
///
/// Mirrors PauseProtocol - same super_admin-only requirement.
#[derive(Accounts)]
pub struct UnpauseProtocol<'info> {
    /// The admin config containing pause state.
    /// SECURITY: Seeds constraint ensures we're modifying the correct PDA.
    /// SECURITY: constraint validates caller is the super_admin.
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: unpause requires super_admin authority
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to unpause.
    /// SECURITY: Signer type enforces cryptographic signature verification.
    pub caller: Signer<'info>,
}

/// Accounts for the create_manager instruction.
///
/// ## SECURITY IMPLEMENTATION
///
/// 1. SECURITY: `admin` is `Signer<'info>` - enforces signature verification
/// 2. SECURITY: `constraint` uses is_admin() to validate admin against admin_list
/// 3. SECURITY: Custom constraint achieves same validation as has_one would
///
/// ## Note on has_one vs constraint
///
/// The `has_one` constraint checks if an account field matches another account's key:
/// ```rust,ignore
/// // has_one checks: user_account.authority == authority.key()
/// #[account(has_one = authority)]
/// pub user_account: Account<'info, UserAccount>,
/// pub authority: Signer<'info>,
/// ```
///
/// For admin_list membership checks, we use custom constraints instead:
/// ```rust,ignore
/// // Custom constraint checks array membership
/// #[account(constraint = is_admin(...) @ ErrorCode::NotAdmin)]
/// ```
#[derive(Accounts)]
pub struct CreateManager<'info> {
    /// The admin config for authority validation.
    /// SECURITY: Seeds constraint ensures we're using the correct PDA.
    /// SECURITY: Custom constraint validates admin is in admin_list.
    #[account(
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: admin validated against admin_list
        constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, admin.key) @ ErrorCode::NotAdmin
    )]
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
    /// SECURITY: Signer type enforces signature verification.
    /// SECURITY: Admin is validated against admin_list via constraint above.
    pub admin: Signer<'info>,

    /// The user who will become a manager.
    /// CHECK: This account just provides a pubkey for the manager role.
    pub manager: UncheckedAccount<'info>,

    /// Account paying for manager account creation.
    #[account(mut)]
    pub payer: Signer<'info>,

    /// System program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts for the remove_admin instruction.
///
/// ## SECURITY IMPLEMENTATION
///
/// 1. SECURITY: `caller` is `Signer<'info>` - enforces signature verification
/// 2. SECURITY: `constraint` validates caller equals super_admin
/// 3. SECURITY: Only super_admin can remove admins
#[derive(Accounts)]
pub struct RemoveAdmin<'info> {
    /// The admin config to modify.
    /// SECURITY: Seeds constraint ensures we're modifying the correct PDA.
    /// SECURITY: constraint validates caller is the super_admin.
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Only super_admin can remove admins
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The caller attempting to remove an admin.
    /// SECURITY: Signer type enforces cryptographic signature verification.
    pub caller: Signer<'info>,

    /// The admin to remove from the admin_list.
    /// CHECK: This account just provides a pubkey to remove.
    pub admin_to_remove: UncheckedAccount<'info>,
}

/// Accounts for the deactivate_manager instruction.
///
/// ## SECURITY IMPLEMENTATION
///
/// 1. SECURITY: `caller` is `Signer<'info>` - enforces signature verification
/// 2. SECURITY: `constraint` uses is_admin() to check admin_list membership
/// 3. SECURITY: Only admins can deactivate managers
#[derive(Accounts)]
pub struct DeactivateManager<'info> {
    /// The admin config for authority validation.
    /// SECURITY: Seeds constraint ensures we're using the correct PDA.
    /// SECURITY: Custom constraint validates caller is in admin_list.
    #[account(
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Only admins can deactivate managers
        constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key) @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// The manager account to deactivate.
    /// SECURITY: Seeds constraint ensures we're modifying the correct manager PDA.
    #[account(
        mut,
        seeds = [b"manager", manager_account.manager.as_ref()],
        bump = manager_account.bump
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    /// The caller attempting to deactivate the manager.
    /// SECURITY: Signer type enforces cryptographic signature verification.
    pub caller: Signer<'info>,
}
