#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

// Program ID from generated keypair
declare_id!("AjgRX5jTbb96u5knHCmPhco94FX5UUk325kZSzX5fngt");

// PDA Derivation Secure Program
//
// This program demonstrates secure PDA patterns:
// - Always re-derive PDAs using seeds constraints
// - Enforce canonical bump seeds
// - Use has_one constraints for relationship validation
// - Proper seed component validation
//
// EDUCATIONAL PURPOSE - Demonstrates security best practices

// ============================================================================
// CONSTANTS
// ============================================================================

/// Seed prefix for treasury PDA
pub const TREASURY_SEED: &[u8] = b"treasury";

/// Seed prefix for user deposit PDA
pub const USER_DEPOSIT_SEED: &[u8] = b"user_deposit";

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

/// Treasury account - holds program funds
/// PDA seeds: ["treasury", authority]
///
/// SECURITY: Bump is stored to enable efficient re-derivation during
/// subsequent operations. The canonical bump (highest valid bump) is
/// always used, as enforced by Anchor's bump constraint.
#[account]
#[derive(InitSpace)]
pub struct Treasury {
    /// Treasury admin who can manage funds
    /// SECURITY: Used as seed component for deterministic PDA derivation
    pub authority: Pubkey,
    /// Total balance held in treasury (tracked internally)
    pub balance: u64,
    /// PDA bump seed - always canonical (highest valid)
    /// SECURITY: Stored for efficient re-derivation, validated on every access
    pub bump: u8,
}

/// User deposit account - tracks individual deposits
/// PDA seeds: ["user_deposit", treasury, owner]
///
/// SECURITY: Hierarchical PDA structure ensures:
/// - Each deposit is uniquely tied to a specific treasury
/// - Each deposit is uniquely tied to a specific user
/// - Cannot be forged or substituted
#[account]
#[derive(InitSpace)]
pub struct UserDeposit {
    /// Depositor's pubkey
    /// SECURITY: Used as seed component, validated via seeds constraint
    pub owner: Pubkey,
    /// Associated treasury account
    /// SECURITY: Used as seed component, creating hierarchical relationship
    pub treasury: Pubkey,
    /// Deposited amount
    pub amount: u64,
    /// PDA bump seed - always canonical
    /// SECURITY: Validated on every access via bump constraint
    pub bump: u8,
}

// ============================================================================
// PROGRAM MODULE
// ============================================================================

#[program]
pub mod secure_pda_derivation {
    use super::*;

    /// Initialize a new treasury account
    ///
    /// SECURITY: Uses Anchor's seeds and bump constraints for secure derivation
    /// - PDA is deterministically derived from authority pubkey
    /// - Only canonical bump is accepted
    /// - Account ownership verified by Anchor's Account type
    pub fn initialize_treasury(ctx: Context<InitializeTreasury>) -> Result<()> {
        let treasury = &mut ctx.accounts.treasury;

        treasury.authority = ctx.accounts.authority.key();
        treasury.balance = 0;
        // SECURITY: Store the canonical bump from Anchor's derivation
        // This bump is guaranteed to be the highest valid bump (canonical)
        treasury.bump = ctx.bumps.treasury;

        msg!(
            "Treasury initialized: authority={}, canonical_bump={}",
            treasury.authority,
            treasury.bump
        );

        Ok(())
    }

    /// Create a user deposit account linked to a treasury
    ///
    /// SECURITY: Proper hierarchical PDA derivation
    /// - Treasury must be a valid Treasury account (type checked)
    /// - User deposit PDA includes treasury in seeds (hierarchical)
    /// - Canonical bump enforced by Anchor
    pub fn create_user_deposit(ctx: Context<CreateUserDeposit>) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;

        user_deposit.owner = ctx.accounts.owner.key();
        // SECURITY: Treasury is type-checked, ensuring it's a valid Treasury account
        user_deposit.treasury = ctx.accounts.treasury.key();
        user_deposit.amount = 0;
        // SECURITY: Store canonical bump from Anchor's derivation
        user_deposit.bump = ctx.bumps.user_deposit;

        msg!(
            "User deposit created: owner={}, treasury={}, bump={}",
            user_deposit.owner,
            user_deposit.treasury,
            user_deposit.bump
        );

        Ok(())
    }

    /// Deposit funds into user's deposit account
    ///
    /// SECURITY: Full PDA validation on every access
    /// - seeds constraint re-derives PDA to verify authenticity
    /// - has_one ensures user_deposit.treasury matches treasury account
    /// - has_one ensures user_deposit.owner matches depositor
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;
        let treasury = &mut ctx.accounts.treasury;

        // SECURITY: Anchor has already validated:
        // 1. user_deposit PDA derivation via seeds constraint
        // 2. user_deposit.treasury == treasury.key() via has_one
        // 3. user_deposit.owner == depositor.key() via has_one

        // Transfer lamports from depositor to treasury
        let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.depositor.key(),
            &treasury.key(),
            amount,
        );

        anchor_lang::solana_program::program::invoke(
            &transfer_ix,
            &[
                ctx.accounts.depositor.to_account_info(),
                treasury.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        // Update balances
        user_deposit.amount =
            user_deposit.amount.checked_add(amount).ok_or(PdaError::ArithmeticOverflow)?;
        treasury.balance =
            treasury.balance.checked_add(amount).ok_or(PdaError::ArithmeticOverflow)?;

        msg!("Deposited {} lamports securely", amount);

        Ok(())
    }

    /// Withdraw funds from user's deposit account
    ///
    /// SECURITY: Comprehensive validation before any fund movement
    /// - seeds constraint re-derives and validates both PDAs
    /// - bump = stored_bump ensures canonical bump is used
    /// - has_one validates all account relationships
    /// - Only the deposit owner can withdraw
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;
        let treasury = &mut ctx.accounts.treasury;

        // SECURITY: Anchor has already validated:
        // 1. user_deposit PDA is correctly derived (seeds constraint)
        // 2. treasury PDA is correctly derived (seeds constraint)
        // 3. user_deposit.owner == withdrawer.key() (has_one)
        // 4. user_deposit.treasury == treasury.key() (has_one)
        // 5. treasury.authority matches (has_one on treasury seeds)
        // 6. Canonical bumps are used (bump = account.bump)

        require!(user_deposit.amount >= amount, PdaError::InsufficientBalance);

        // Update balances before transfer (checks-effects-interactions pattern)
        user_deposit.amount =
            user_deposit.amount.checked_sub(amount).ok_or(PdaError::ArithmeticOverflow)?;
        treasury.balance =
            treasury.balance.checked_sub(amount).ok_or(PdaError::ArithmeticOverflow)?;

        // SECURITY: Transfer lamports directly from PDA
        // Note: PDAs with data cannot use system_instruction::transfer
        // Instead, we directly manipulate lamports
        let treasury_info = treasury.to_account_info();
        let withdrawer_info = ctx.accounts.withdrawer.to_account_info();

        **treasury_info.try_borrow_mut_lamports()? =
            treasury_info.lamports().checked_sub(amount).ok_or(PdaError::InsufficientBalance)?;
        **withdrawer_info.try_borrow_mut_lamports()? =
            withdrawer_info.lamports().checked_add(amount).ok_or(PdaError::ArithmeticOverflow)?;

        msg!("Withdrew {} lamports securely", amount);

        Ok(())
    }
}

// ============================================================================
// ACCOUNT CONTEXTS
// ============================================================================

/// SECURITY: Initialize treasury with proper PDA constraints
/// - seeds: Deterministically derives PDA from authority
/// - bump: Anchor finds and enforces canonical bump
#[derive(Accounts)]
pub struct InitializeTreasury<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Treasury::INIT_SPACE,
        // SECURITY: Deterministic derivation ensures unique treasury per authority
        seeds = [TREASURY_SEED, authority.key().as_ref()],
        // SECURITY: Anchor finds canonical bump automatically
        bump
    )]
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// SECURITY: Create user deposit with hierarchical PDA
/// - Treasury is type-checked as Account<Treasury>
/// - Seeds include treasury key for proper hierarchy
#[derive(Accounts)]
pub struct CreateUserDeposit<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + UserDeposit::INIT_SPACE,
        // SECURITY: Hierarchical seeds create unique deposit per treasury+owner combo
        seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), owner.key().as_ref()],
        // SECURITY: Canonical bump enforced
        bump
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    /// SECURITY: Type-checked as Account<Treasury>, ensuring valid treasury
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// SECURITY: Deposit with full validation
/// - seeds constraint re-validates PDA on every call
/// - has_one validates treasury and owner relationships
/// - bump = stored bump ensures canonical bump
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        // SECURITY: Re-derive PDA to verify account authenticity
        seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), depositor.key().as_ref()],
        // SECURITY: Validate stored bump matches canonical
        bump = user_deposit.bump,
        // SECURITY: Verify relationships via has_one
        has_one = treasury,
        has_one = owner @ PdaError::UnauthorizedAccess
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    /// SECURITY: Type-checked and used in seeds derivation
    #[account(mut)]
    pub treasury: Account<'info, Treasury>,

    /// The depositor must be the owner of the user_deposit account
    #[account(
        mut,
        // SECURITY: Depositor must match user_deposit.owner
        constraint = depositor.key() == user_deposit.owner @ PdaError::UnauthorizedAccess
    )]
    pub depositor: Signer<'info>,

    /// Owner is checked via has_one, must match user_deposit.owner
    /// CHECK: Validated through has_one constraint on user_deposit
    pub owner: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

/// SECURITY: Withdraw with comprehensive validation
/// - All PDAs re-validated via seeds constraints
/// - All relationships validated via has_one
/// - Canonical bumps enforced via bump = stored_bump
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        // SECURITY: Full PDA re-derivation
        seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), withdrawer.key().as_ref()],
        // SECURITY: Enforce canonical bump
        bump = user_deposit.bump,
        // SECURITY: Validate relationships
        has_one = treasury,
        has_one = owner @ PdaError::UnauthorizedAccess
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    #[account(
        mut,
        // SECURITY: Re-derive treasury PDA to verify authenticity
        seeds = [TREASURY_SEED, treasury.authority.as_ref()],
        // SECURITY: Enforce canonical bump
        bump = treasury.bump
    )]
    pub treasury: Account<'info, Treasury>,

    /// The withdrawer must be the owner of the user_deposit
    #[account(
        mut,
        // SECURITY: Only owner can withdraw
        constraint = withdrawer.key() == user_deposit.owner @ PdaError::UnauthorizedAccess
    )]
    pub withdrawer: Signer<'info>,

    /// CHECK: Validated through has_one constraint
    pub owner: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// ERROR CODES
// ============================================================================

#[error_code]
pub enum PdaError {
    #[msg("Invalid PDA derivation: Address does not match expected seeds")]
    InvalidPdaDerivation,

    #[msg("Non-canonical bump: Only canonical (highest valid) bump accepted")]
    NonCanonicalBump,

    #[msg("Seed mismatch: Provided seeds do not match account derivation")]
    SeedMismatch,

    #[msg("Unauthorized: Caller is not authorized for this operation")]
    UnauthorizedAccess,

    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,

    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
