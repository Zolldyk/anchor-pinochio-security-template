//! Secure CPI Re-entrancy Program
//!
//! This program demonstrates the CORRECT pattern for handling CPI calls that
//! protects against re-entrancy attacks using two defensive strategies:
//!
//! 1. **Checks-Effects-Interactions Pattern**: Update state BEFORE making CPI calls
//! 2. **Re-entrancy Guard**: Boolean flag that prevents recursive calls
//!
//! ✅ SAFE FOR PRODUCTION USE (pattern demonstration)
//!
//! Security Flow:
//! 1. Check re-entrancy guard (reject if already in progress)
//! 2. Set re-entrancy guard
//! 3. Update state (effects) - balance is decremented FIRST
//! 4. Make CPI (interactions) - external program can't exploit old state
//! 5. Clear re-entrancy guard

use anchor_lang::prelude::*;

declare_id!("DmLeYUrsmp4D8PPFYzqoeoVxicmHcDNoFUt3KbJGtQ8K");

#[program]
pub mod secure_cpi_reentrancy {
    use super::*;

    /// Initialize a new vault with the given authority
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.withdrawals_pending = 0;
        // SECURITY: Initialize re-entrancy guard to false
        vault.reentrancy_guard = false;
        vault.bump = ctx.bumps.vault;

        msg!("// SECURITY: Vault initialized with re-entrancy protection");
        msg!("// SECURITY: Authority: {}", vault.authority);
        Ok(())
    }

    /// Deposit funds into the vault
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let user_deposit = &mut ctx.accounts.user_deposit;

        // Update vault balance
        vault.balance = vault.balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;

        // Update user deposit tracking
        user_deposit.owner = ctx.accounts.depositor.key();
        user_deposit.amount =
            user_deposit.amount.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        user_deposit.bump = ctx.bumps.user_deposit;

        msg!("// SECURITY: Deposited {} to vault. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// SECURE: Withdraw funds with re-entrancy protection
    ///
    /// This instruction demonstrates the secure pattern:
    /// 1. CHECKS: Verify re-entrancy guard is not set
    /// 2. Set re-entrancy guard
    /// 3. EFFECTS: Update state BEFORE CPI
    /// 4. INTERACTIONS: Make CPI to external program
    /// 5. Clear re-entrancy guard
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let user_deposit = &mut ctx.accounts.user_deposit;

        // SECURITY: Step 1 - Check re-entrancy guard FIRST
        // This blocks any attempt to re-enter while a withdrawal is in progress
        require!(!vault.reentrancy_guard, ErrorCode::ReentrancyDetected);

        msg!("// SECURITY: Re-entrancy guard check passed");

        // SECURITY: Step 2 - Set re-entrancy guard IMMEDIATELY
        vault.reentrancy_guard = true;

        msg!("// SECURITY: Re-entrancy guard SET - withdrawal in progress");

        // SECURITY: Step 3 - Perform balance checks
        require!(vault.balance >= amount, ErrorCode::InsufficientBalance);
        require!(user_deposit.amount >= amount, ErrorCode::InsufficientUserBalance);

        msg!("// SECURITY: Balance checks passed. Current balance: {}", vault.balance);

        // SECURITY: Step 4 - Update state BEFORE CPI (Effects before Interactions)
        // This is the KEY defense: even if an attacker re-enters, they'll see
        // the UPDATED balance, not the old one
        vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::InsufficientBalance)?;

        user_deposit.amount =
            user_deposit.amount.checked_sub(amount).ok_or(ErrorCode::InsufficientUserBalance)?;

        msg!("// SECURITY: State updated BEFORE CPI. New balance: {}", vault.balance);

        // SECURITY: Step 5 - Make CPI AFTER state is updated (Interactions)
        // Even if the external program tries to re-enter, it will be blocked
        // by the re-entrancy guard, AND the balance is already decremented
        let callback_ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.callback_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.vault.key(), false),
                AccountMeta::new(ctx.accounts.user_deposit.key(), false),
                AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
                AccountMeta::new_readonly(ctx.accounts.secure_program.key(), false),
                AccountMeta::new(ctx.accounts.attack_state.key(), false),
            ],
            data: build_callback_data(amount),
        };

        msg!("// SECURITY: Making CPI with state already updated");

        anchor_lang::solana_program::program::invoke(
            &callback_ix,
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.user_deposit.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.secure_program.to_account_info(),
                ctx.accounts.attack_state.to_account_info(),
            ],
        )?;

        msg!("// SECURITY: CPI completed, clearing re-entrancy guard");

        // SECURITY: Step 6 - Clear re-entrancy guard after CPI completes
        // Need to reload the account to clear the guard
        let vault = &mut ctx.accounts.vault;
        vault.reentrancy_guard = false;

        msg!("// SECURITY: Re-entrancy guard CLEARED - withdrawal complete");
        msg!("// SECURITY: Final balance: {}", vault.balance);

        Ok(())
    }

    /// Callback target for testing - demonstrates guard prevents re-entry
    pub fn callback_target(_ctx: Context<CallbackTarget>, _amount: u64) -> Result<()> {
        msg!("// SECURITY: Callback received in secure program");
        msg!("// SECURITY: Re-entrancy guard would block any attempt to call withdraw again");
        Ok(())
    }
}

/// Build instruction data for callback with amount
fn build_callback_data(amount: u64) -> Vec<u8> {
    // Anchor discriminator for "receive_callback" + amount
    let mut data = Vec::with_capacity(16);
    // Discriminator: first 8 bytes of SHA256("global:receive_callback")
    data.extend_from_slice(&[0x2a, 0x55, 0x18, 0x6e, 0x79, 0x94, 0x3e, 0x65]);
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

// ============================================================================
// Account Structures
// ============================================================================

/// Anchor discriminator size constant
pub const DISCRIMINATOR_SIZE: usize = 8;

/// Vault account size (secure): 8 + 32 + 8 + 8 + 1 + 1 = 58 bytes
/// Includes reentrancy_guard boolean for protection
pub const VAULT_SIZE: usize = DISCRIMINATOR_SIZE + 32 + 8 + 8 + 1 + 1;

/// UserDeposit account size: 8 + 32 + 8 + 1 = 49 bytes
pub const USER_DEPOSIT_SIZE: usize = DISCRIMINATOR_SIZE + 32 + 8 + 1;

/// Seed for vault PDA
pub const VAULT_SEED: &[u8] = b"vault";

/// Seed for user deposit PDA
pub const USER_SEED: &[u8] = b"user_deposit";

/// Vault account with re-entrancy protection
#[account]
pub struct Vault {
    /// Vault owner/authority (32 bytes)
    pub authority: Pubkey,
    /// Total vault balance (8 bytes)
    pub balance: u64,
    /// Tracks withdrawals in progress (8 bytes)
    pub withdrawals_pending: u64,
    /// SECURITY: Re-entrancy guard flag (1 byte)
    /// When true, blocks any new withdrawal attempts
    pub reentrancy_guard: bool,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

/// User deposit tracking account
#[account]
pub struct UserDeposit {
    /// Depositor's public key (32 bytes)
    pub owner: Pubkey,
    /// Amount deposited by this user (8 bytes)
    pub amount: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

// ============================================================================
// Instruction Contexts
// ============================================================================

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(
        init,
        payer = authority,
        space = VAULT_SIZE,
        seeds = [VAULT_SEED, authority.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, vault.authority.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init_if_needed,
        payer = depositor,
        space = USER_DEPOSIT_SIZE,
        seeds = [USER_SEED, vault.key().as_ref(), depositor.key().as_ref()],
        bump
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, vault.authority.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [USER_SEED, vault.key().as_ref(), authority.key().as_ref()],
        bump = user_deposit.bump,
        constraint = user_deposit.owner == authority.key() @ ErrorCode::Unauthorized
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    pub authority: Signer<'info>,

    /// CHECK: External callback program - allowed for testing
    /// SECURITY: Even if malicious, re-entrancy guard protects us
    pub callback_program: UncheckedAccount<'info>,

    /// CHECK: This program's ID for CPI context
    pub secure_program: UncheckedAccount<'info>,

    /// CHECK: Attack state account for testing
    #[account(mut)]
    pub attack_state: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct CallbackTarget<'info> {
    #[account(
        mut,
        seeds = [VAULT_SEED, vault.authority.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    pub authority: Signer<'info>,
}

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Re-entrancy detected: Operation already in progress")]
    ReentrancyDetected = 6005,

    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow = 6001,

    #[msg("Insufficient vault balance for withdrawal")]
    InsufficientBalance = 6002,

    #[msg("Insufficient user balance for withdrawal")]
    InsufficientUserBalance = 6003,

    #[msg("Unauthorized: caller is not the vault authority")]
    Unauthorized = 6000,

    #[msg("Withdrawal in progress: Complete current withdrawal first")]
    WithdrawalInProgress = 6006,
}
