#![allow(unexpected_cfgs)]

//! Vulnerable CPI Re-entrancy Program
//!
//! This program demonstrates a DANGEROUS pattern where state is updated AFTER a CPI call,
//! allowing malicious programs to exploit re-entrancy vulnerabilities.
//!
//! ⚠️  EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION ⚠️
//!
//! The vulnerability: During withdrawal, the program makes a CPI to an external callback
//! program BEFORE updating its internal state. This allows the external program to
//! re-enter and withdraw again before the balance is decremented.

use anchor_lang::prelude::*;

declare_id!("DW5PRzSRWd1oAS8mDiV915GNh1hvpWrs7dxehpdnkD6b");

#[program]
pub mod vulnerable_cpi_reentrancy {
    use super::*;

    /// Initialize a new vault with the given authority
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.balance = 0;
        vault.withdrawals_pending = 0;
        vault.bump = ctx.bumps.vault;

        msg!("Vault initialized with authority: {}", vault.authority);
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

        msg!("Deposited {} to vault. New balance: {}", amount, vault.balance);
        Ok(())
    }

    /// VULNERABLE: Withdraw funds with callback to external program
    ///
    /// This instruction demonstrates the re-entrancy vulnerability:
    /// 1. Reads current balance BEFORE CPI
    /// 2. Makes CPI to external program
    /// 3. Updates state AFTER CPI (too late!)
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // VULNERABILITY: Read state BEFORE CPI
        // An attacker can exploit this because the balance check uses pre-CPI state
        let current_balance = ctx.accounts.vault.balance;
        let current_user_amount = ctx.accounts.user_deposit.amount;

        msg!("// VULNERABILITY: Reading balance BEFORE CPI: {}", current_balance);

        // VULNERABILITY: Check balance against pre-CPI state
        require!(current_balance >= amount, ErrorCode::InsufficientBalance);
        require!(current_user_amount >= amount, ErrorCode::InsufficientUserBalance);

        msg!("// VULNERABILITY: Balance check passed, making CPI to callback program");

        // VULNERABILITY: Make CPI BEFORE updating state
        // The external program can re-enter this function and withdraw again!
        let callback_ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.callback_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.vault.key(), false),
                AccountMeta::new(ctx.accounts.user_deposit.key(), false),
                AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
                AccountMeta::new_readonly(ctx.accounts.vulnerable_program.key(), false),
                AccountMeta::new(ctx.accounts.attack_state.key(), false),
            ],
            data: build_callback_data(amount),
        };

        anchor_lang::solana_program::program::invoke(
            &callback_ix,
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.user_deposit.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.vulnerable_program.to_account_info(),
                ctx.accounts.attack_state.to_account_info(),
            ],
        )?;

        msg!("// VULNERABILITY: CPI returned, NOW updating state (too late!)");

        // VULNERABILITY: Update state AFTER CPI - attacker already re-entered!
        // At this point, if the attacker re-entered, they've already withdrawn
        // using the old balance value. This update is using stale data.
        ctx.accounts.vault.balance =
            current_balance.checked_sub(amount).ok_or(ErrorCode::InsufficientBalance)?;

        ctx.accounts.user_deposit.amount =
            current_user_amount.checked_sub(amount).ok_or(ErrorCode::InsufficientUserBalance)?;

        msg!(
            "// VULNERABILITY: State updated AFTER CPI. New balance: {}",
            ctx.accounts.vault.balance
        );

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

/// Vault account size: 8 + 32 + 8 + 8 + 1 = 57 bytes
pub const VAULT_SIZE: usize = DISCRIMINATOR_SIZE + 32 + 8 + 8 + 1;

/// UserDeposit account size: 8 + 32 + 8 + 1 = 49 bytes
pub const USER_DEPOSIT_SIZE: usize = DISCRIMINATOR_SIZE + 32 + 8 + 1;

/// Seed for vault PDA
pub const VAULT_SEED: &[u8] = b"vault";

/// Seed for user deposit PDA
pub const USER_SEED: &[u8] = b"user_deposit";

/// Vault account storing total balance and authority
#[account]
pub struct Vault {
    /// Vault owner/authority (32 bytes)
    pub authority: Pubkey,
    /// Total vault balance - RE-ENTRANCY VULNERABILITY TARGET (8 bytes)
    pub balance: u64,
    /// Tracks withdrawals in progress (8 bytes)
    pub withdrawals_pending: u64,
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

    /// CHECK: External callback program - intentionally unchecked for vulnerability demo
    /// VULNERABILITY: We allow ANY program to be passed here as the callback target
    pub callback_program: UncheckedAccount<'info>,

    /// CHECK: This program's ID for CPI context
    pub vulnerable_program: UncheckedAccount<'info>,

    /// CHECK: Attack state account for re-entrancy tracking
    #[account(mut)]
    pub attack_state: UncheckedAccount<'info>,
}

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow = 6001,

    #[msg("Insufficient vault balance for withdrawal")]
    InsufficientBalance = 6002,

    #[msg("Insufficient user balance for withdrawal")]
    InsufficientUserBalance = 6003,

    #[msg("Unauthorized: caller is not the vault authority")]
    Unauthorized = 6000,
}
