//! # Secure Missing Validation Program
//!
//! ✅ **This program demonstrates PROPER account validation in Solana programs.**
//!
//! This program shows the correct way to implement account validation using Anchor's
//! built-in constraints. Compare this with the vulnerable version to understand
//! how proper validation prevents unauthorized access.
//!
//! ## Security Features Demonstrated
//! - Signer validation using `Signer<'info>` type
//! - Ownership validation using `has_one = authority` constraint
//! - State validation using `constraint = user_account.is_initialized`
//!
//! ## Learning Objectives
//! After studying this code, you should understand:
//! 1. How `Signer<'info>` enforces signature verification
//! 2. How `has_one` validates account ownership
//! 3. How constraints prevent unauthorized state modifications
//!
//! **This program is safe for production use (as a reference pattern).**

use anchor_lang::prelude::*;

// Program ID generated from keypair
declare_id!("78x68Ufm5nCVRUpyzdKd1VjZk7gFeNNFVryqT48mE1kL");

// =============================================================================
// CONSTANTS
// =============================================================================

/// Anchor discriminator size (8 bytes for account type identification)
/// // SECURITY: Discriminator prevents account type confusion attacks
pub const DISCRIMINATOR_SIZE: usize = 8;

/// Total size of UserAccount:
/// - Discriminator: 8 bytes
/// - authority (Pubkey): 32 bytes
/// - balance (u64): 8 bytes
/// - is_initialized (bool): 1 byte
/// - bump (u8): 1 byte
///
/// Total: 50 bytes
pub const ACCOUNT_SIZE: usize = DISCRIMINATOR_SIZE + 32 + 8 + 1 + 1;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// User account storing balance and ownership information.
///
/// This account stores:
/// - The authority (owner) who has exclusive modification rights
/// - A balance value that can only be modified by the authority
/// - Initialization flag to prevent re-initialization attacks
/// - PDA bump seed for account derivation
///
/// // SECURITY: Structure is identical to vulnerable version for comparison,
/// // but validation is enforced in the account structs below.
#[account]
pub struct UserAccount {
    /// The public key of the user who owns this account.
    /// // SECURITY: This field is validated via `has_one = authority` constraint
    /// // to ensure only the true owner can modify account state.
    pub authority: Pubkey,

    /// Balance value that can be modified by instructions.
    /// In a real program, this might represent tokens, points, or other values.
    pub balance: u64,

    /// Flag indicating whether the account has been initialized.
    /// // SECURITY: Validated via `constraint = user_account.is_initialized`
    /// // to prevent operations on uninitialized accounts.
    pub is_initialized: bool,

    /// PDA bump seed if this account is derived as a PDA.
    /// Stored to avoid recalculating on subsequent calls.
    pub bump: u8,
}

// =============================================================================
// ERROR CODES
// =============================================================================

/// Custom error codes for the secure program.
///
/// // SECURITY: Unlike the vulnerable version, these errors ARE ACTIVELY USED
/// // to reject unauthorized operations and provide meaningful error messages.
#[error_code]
pub enum ErrorCode {
    /// Returned when a signer is not authorized to perform the operation.
    /// // SECURITY: Triggered when `has_one = authority` constraint fails,
    /// // indicating the signer doesn't match the account's authority.
    #[msg("Unauthorized: Signer is not the account authority")]
    Unauthorized,

    /// Returned when attempting to initialize an already initialized account.
    /// // SECURITY: Prevents re-initialization attacks that could reset account state.
    #[msg("Account has already been initialized")]
    AlreadyInitialized,
}

// =============================================================================
// PROGRAM INSTRUCTIONS
// =============================================================================

#[program]
pub mod secure_missing_validation {
    use super::*;

    /// Initializes a new user account with the caller as the authority.
    ///
    /// // SECURITY: This instruction is safe because:
    /// // - `init` constraint ensures account doesn't already exist
    /// // - `authority` must be a Signer (verified by Anchor)
    /// // - PDA derivation with authority seed ensures uniqueness per user
    /// // - System program validates rent and space requirements
    ///
    /// # Arguments
    /// * `ctx` - The context containing all account references
    ///
    /// # Returns
    /// * `Result<()>` - Success or error
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // SECURITY: Get the user account from context
        let user_account = &mut ctx.accounts.user_account;

        // SECURITY: Set authority to the verified signer's pubkey
        // This establishes who owns the account - only this key can modify it
        user_account.authority = ctx.accounts.authority.key();

        // SECURITY: Initialize balance to zero
        user_account.balance = 0;

        // SECURITY: Mark as initialized to enable is_initialized constraint checks
        user_account.is_initialized = true;

        // SECURITY: Store the bump seed for future PDA derivation verification
        user_account.bump = ctx.bumps.user_account;

        msg!("✓ SECURITY: Account initialized for authority: {}", user_account.authority);
        msg!("✓ SECURITY: Initial balance: {}", user_account.balance);

        Ok(())
    }

    /// Updates the balance of a user account.
    ///
    /// // SECURITY: This instruction is PROPERLY SECURED with these validations:
    /// // - `authority: Signer<'info>` - Ensures authority signed the transaction
    /// // - `has_one = authority` - Verifies user_account.authority matches signer
    /// // - `constraint = user_account.is_initialized` - Ensures account is valid
    ///
    /// Compare with vulnerable version which lacks ALL of these checks!
    ///
    /// # Arguments
    /// * `ctx` - The context containing validated account references
    /// * `new_balance` - The new balance to set
    ///
    /// # Returns
    /// * `Result<()>` - Success if authorized, error if validation fails
    pub fn update_balance(ctx: Context<UpdateBalance>, new_balance: u64) -> Result<()> {
        // SECURITY: At this point, Anchor has already validated:
        // 1. ctx.accounts.authority is a signer (must have signed transaction)
        // 2. ctx.accounts.user_account.authority == ctx.accounts.authority.key()
        // 3. ctx.accounts.user_account.is_initialized == true
        //
        // If any validation failed, we wouldn't reach this code - Anchor returns
        // ConstraintHasOne, ConstraintRaw, or SignatureVerificationFailed errors.

        let user_account = &mut ctx.accounts.user_account;

        // Store old balance for logging
        let old_balance = user_account.balance;

        // SECURITY: Safe to set balance - all authorization checks passed
        user_account.balance = new_balance;

        msg!("✓ SECURITY VERIFIED: Balance updated from {} to {}", old_balance, new_balance);
        msg!("✓ SECURITY VERIFIED: Authorized by: {}", ctx.accounts.authority.key());

        Ok(())
    }
}

// =============================================================================
// ACCOUNT VALIDATION STRUCTS
// =============================================================================

/// Accounts required for the initialize instruction.
///
/// // SECURITY: This struct properly validates all accounts:
/// // - `init` constraint ensures fresh account creation
/// // - `authority` must be a Signer (signature verified)
/// // - PDA seeds ensure account uniqueness per authority
/// // - System program is type-checked by Anchor
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The user account to be created and initialized.
    /// // SECURITY: Uses PDA derivation with authority pubkey as seed
    /// // This ensures each authority can only have one account.
    #[account(
        init,
        payer = authority,
        space = ACCOUNT_SIZE,
        seeds = [b"user_account", authority.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,

    /// The authority who will own this account.
    /// // SECURITY: `Signer<'info>` type enforces signature verification.
    /// // Must be a signer AND will pay for account creation.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The Solana system program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts required for the update_balance instruction.
///
/// ✅ **SECURE**: This struct demonstrates PROPER validation!
///
/// // SECURITY: Compare with vulnerable version that LACKS these protections:
/// //
/// // | Security Check          | Vulnerable | Secure (this) |
/// // |-------------------------|------------|---------------|
/// // | Signer verification     | ❌ No      | ✅ Yes        |
/// // | has_one authority       | ❌ No      | ✅ Yes        |
/// // | is_initialized check    | ❌ No      | ✅ Yes        |
/// // | Authority type          | AccountInfo| Signer        |
#[derive(Accounts)]
pub struct UpdateBalance<'info> {
    /// The user account to modify.
    ///
    /// // SECURITY: Multiple constraints ensure authorization:
    /// // - `mut` allows modification (standard)
    /// // - `has_one = authority` verifies user_account.authority == authority.key()
    /// // - `constraint = user_account.is_initialized` ensures account is valid
    /// // - `@ ErrorCode::Unauthorized` provides meaningful error on failure
    ///
    /// // VULNERABLE VERSION COMPARISON:
    /// // Vulnerable: `#[account(mut)]` - NO ownership validation!
    /// // Secure: Full constraint chain below
    #[account(
        mut,
        has_one = authority,
        constraint = user_account.is_initialized @ ErrorCode::Unauthorized
    )]
    pub user_account: Account<'info, UserAccount>,

    /// The authority for this operation.
    ///
    /// // SECURITY: `Signer<'info>` type is CRITICAL!
    /// // - Anchor automatically verifies this account signed the transaction
    /// // - Combined with `has_one = authority`, this proves ownership
    ///
    /// // VULNERABLE VERSION COMPARISON:
    /// // Vulnerable: `pub authority: AccountInfo<'info>` - NO signature check!
    /// // Secure: `pub authority: Signer<'info>` - ENFORCED signature check
    pub authority: Signer<'info>,
}
