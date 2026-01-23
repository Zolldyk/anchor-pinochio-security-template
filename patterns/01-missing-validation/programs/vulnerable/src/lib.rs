#![allow(unexpected_cfgs)]

//! # Vulnerable Missing Validation Program
//!
//! ⚠️ **WARNING: This program contains INTENTIONAL security vulnerabilities for educational purposes.**
//!
//! This program demonstrates the critical importance of account validation in Solana programs.
//! It deliberately omits signer and ownership checks to show how attackers can exploit
//! programs that fail to properly validate accounts.
//!
//! ## Vulnerabilities Demonstrated
//! - Missing signer validation on authority account
//! - Missing ownership validation (no `has_one` constraint)
//! - Authority field not checked against transaction signer
//!
//! ## Learning Objectives
//! After studying this code, you should understand:
//! 1. Why every instruction must verify the signer
//! 2. Why account ownership must be validated
//! 3. How attackers exploit missing validation
//!
//! **DO NOT deploy this program to mainnet or use in production.**

use anchor_lang::prelude::*;

// Program ID generated from keypair
declare_id!("Bkh2Wph3fz5iNNcUFy585rRjrRPniCpKs7T3DZZVYeYb");

// =============================================================================
// CONSTANTS
// =============================================================================

/// Anchor discriminator size (8 bytes for account type identification)
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
/// - The authority (owner) who should have exclusive modification rights
/// - A balance value that can be modified
/// - Initialization flag to prevent re-initialization attacks
/// - PDA bump seed for account derivation
#[account]
pub struct UserAccount {
    /// The public key of the user who owns this account.
    /// This field SHOULD be checked on every modification, but the vulnerable
    /// program deliberately skips this check.
    pub authority: Pubkey,

    /// Balance value that can be modified by instructions.
    /// In a real program, this might represent tokens, points, or other values.
    pub balance: u64,

    /// Flag indicating whether the account has been initialized.
    /// Prevents re-initialization attacks when properly validated.
    pub is_initialized: bool,

    /// PDA bump seed if this account is derived as a PDA.
    /// Stored to avoid recalculating on subsequent calls.
    pub bump: u8,
}

// =============================================================================
// ERROR CODES
// =============================================================================

/// Custom error codes for the vulnerable program.
///
/// Note: These errors are defined for documentation purposes but are NOT USED
/// in the vulnerable implementation. The secure version will use these errors
/// to reject unauthorized operations.
#[error_code]
pub enum ErrorCode {
    /// Returned when a signer is not authorized to perform the operation.
    /// The vulnerable program does NOT check this - any account is accepted.
    #[msg("Unauthorized: Signer is not the account authority")]
    Unauthorized,

    /// Returned when attempting to initialize an already initialized account.
    /// Prevents re-initialization attacks that could reset account state.
    #[msg("Account has already been initialized")]
    AlreadyInitialized,
}

// =============================================================================
// PROGRAM INSTRUCTIONS
// =============================================================================

#[program]
pub mod vulnerable_missing_validation {
    use super::*;

    /// Initializes a new user account with the caller as the authority.
    ///
    /// # Security Note
    /// // SECURITY: This instruction is safe because:
    /// // - Account creation enforces uniqueness (can't overwrite existing)
    /// // - Authority is set to the verified signer
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

        // SECURITY: Set authority to the signer's pubkey
        // This establishes who owns the account
        user_account.authority = ctx.accounts.authority.key();

        // SECURITY: Initialize balance to zero
        user_account.balance = 0;

        // SECURITY: Mark as initialized to prevent re-initialization
        user_account.is_initialized = true;

        // SECURITY: Store the bump seed for future PDA derivation
        user_account.bump = ctx.bumps.user_account;

        msg!("Account initialized for authority: {}", user_account.authority);
        msg!("Initial balance: {}", user_account.balance);

        Ok(())
    }

    /// Updates the balance of a user account.
    ///
    /// # ⚠️ VULNERABILITY WARNING
    /// This instruction is INTENTIONALLY VULNERABLE and demonstrates what happens
    /// when proper validation is omitted:
    ///
    /// // VULNERABILITY: No signer validation - anyone can call this
    /// // VULNERABILITY: No owner validation - any account accepted
    /// // VULNERABILITY: Authority field not checked against signer
    ///
    /// An attacker can call this instruction with:
    /// - Any account as "authority" (doesn't need to sign)
    /// - Any user_account (doesn't verify ownership)
    /// And successfully modify the balance without authorization.
    ///
    /// # Arguments
    /// * `ctx` - The context containing account references (NOT validated!)
    /// * `new_balance` - The new balance to set (directly applied without checks)
    ///
    /// # Returns
    /// * `Result<()>` - Always succeeds (no validation to fail)
    pub fn update_balance(ctx: Context<UpdateBalance>, new_balance: u64) -> Result<()> {
        // VULNERABILITY: No signer validation - anyone can call this
        // In a secure program, we would verify: ctx.accounts.authority.is_signer

        // VULNERABILITY: No owner validation - any account accepted
        // In a secure program, we would have: has_one = authority constraint

        // VULNERABILITY: Authority field not checked against signer
        // In a secure program, we would verify:
        // require!(user_account.authority == ctx.accounts.authority.key(), Unauthorized)

        let user_account = &mut ctx.accounts.user_account;

        // Store old balance for logging
        let old_balance = user_account.balance;

        // Directly set the new balance without any authorization checks
        user_account.balance = new_balance;

        msg!("Balance updated from {} to {}", old_balance, new_balance);
        msg!(
            "⚠️ WARNING: No authorization check performed! Authority account: {}",
            ctx.accounts.authority.key()
        );

        Ok(())
    }
}

// =============================================================================
// ACCOUNT VALIDATION STRUCTS
// =============================================================================

/// Accounts required for the initialize instruction.
///
/// // SECURITY: This struct properly validates accounts:
/// // - user_account is created fresh (init) so can't be re-used
/// // - authority must be a signer (verified by Anchor)
/// // - system_program is validated by Anchor
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The user account to be created and initialized.
    /// Uses PDA derivation with authority pubkey as seed for uniqueness.
    #[account(
        init,
        payer = authority,
        space = ACCOUNT_SIZE,
        seeds = [b"user_account", authority.key().as_ref()],
        bump
    )]
    pub user_account: Account<'info, UserAccount>,

    /// The authority who will own this account.
    /// Must be a signer and will pay for account creation.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// The Solana system program for account creation.
    pub system_program: Program<'info, System>,
}

/// Accounts required for the update_balance instruction.
///
/// ⚠️ **VULNERABILITY WARNING**: This struct demonstrates missing validation!
///
/// // VULNERABILITY: Missing constraints that should be present:
/// // - NO `has_one = authority` - doesn't verify account ownership
/// // - authority is AccountInfo, NOT Signer - doesn't verify signature
/// // - NO `constraint = user_account.is_initialized` - could modify uninitialized
///
/// Compare with what a SECURE version would have:
/// ```rust,ignore
/// #[account(mut, has_one = authority)]
/// pub user_account: Account<'info, UserAccount>,
/// pub authority: Signer<'info>,  // Note: Signer, not AccountInfo
/// ```
#[derive(Accounts)]
pub struct UpdateBalance<'info> {
    /// The user account to modify.
    /// // VULNERABILITY: No `has_one = authority` constraint
    /// Any user_account can be passed, regardless of who owns it.
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,

    /// The supposed authority for this operation.
    /// // VULNERABILITY: This is AccountInfo, not Signer!
    /// This means the account doesn't need to sign the transaction.
    /// Anyone can pass any pubkey here without proving ownership.
    ///
    /// CHECK: Intentionally unchecked for vulnerability demonstration.
    /// In production, this MUST be a Signer type with has_one constraint.
    pub authority: AccountInfo<'info>,
}
