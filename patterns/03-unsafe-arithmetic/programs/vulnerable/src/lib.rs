#![allow(unexpected_cfgs)]

// ============================================================================
// VULNERABLE UNSAFE ARITHMETIC - EDUCATIONAL DEMONSTRATION ONLY
// ============================================================================
// WARNING: This program intentionally contains arithmetic vulnerabilities to
// demonstrate how integer overflow/underflow attacks work in Solana programs.
// DO NOT use wrapping arithmetic in production code - always use checked_* methods.
// ============================================================================

use anchor_lang::prelude::*;

declare_id!("7H6Q6tavPU58GpJfdsHvXUD9G75gF3okF8SoF7QxNaS4");

// ============================================================================
// CONSTANTS
// ============================================================================

/// Anchor discriminator size (8 bytes)
pub const DISCRIMINATOR_SIZE: usize = 8;

/// VaultState account size: 8 + 32 + 8 + 8 + 8 + 1 = 65 bytes
pub const VAULT_STATE_SIZE: usize = DISCRIMINATOR_SIZE + 32 + 8 + 8 + 8 + 1;

/// UserBalance account size: 8 + 32 + 8 + 8 + 8 + 1 = 65 bytes
pub const USER_BALANCE_SIZE: usize = DISCRIMINATOR_SIZE + 32 + 8 + 8 + 8 + 1;

/// Seed for vault PDA
pub const VAULT_SEED: &[u8] = b"vault";

/// Seed for user balance PDA
pub const USER_SEED: &[u8] = b"user";

// ============================================================================
// PROGRAM MODULE
// ============================================================================

#[program]
pub mod vulnerable_unsafe_arithmetic {
    use super::*;

    /// Initialize the vault with the given authority
    /// This instruction is secure - same implementation as secure program
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        let vault = &mut ctx.accounts.vault_state;
        vault.authority = ctx.accounts.authority.key();
        vault.total_deposits = 0;
        vault.user_count = 0;
        vault.total_rewards = 0;
        vault.bump = ctx.bumps.vault_state;

        msg!("Vault initialized with authority: {}", vault.authority);
        Ok(())
    }

    /// Create a user balance account
    /// This instruction is secure - same implementation as secure program
    pub fn create_user(ctx: Context<CreateUser>) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;
        user_balance.owner = ctx.accounts.owner.key();
        user_balance.balance = 0;
        user_balance.deposits = 0;
        user_balance.withdrawals = 0;
        user_balance.bump = ctx.bumps.user_balance;

        let vault = &mut ctx.accounts.vault_state;
        vault.user_count += 1;

        msg!("User created: {}", user_balance.owner);
        Ok(())
    }

    /// Deposit funds into user balance
    ///
    /// VULNERABILITY: This instruction uses wrapping arithmetic that silently overflows!
    /// In production code without overflow-checks, standard +/-/* operators behave this way.
    /// Here we use wrapping_* methods explicitly to demonstrate the vulnerability.
    pub fn deposit(ctx: Context<Deposit>, amount_to_add: u64) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;
        let vault = &mut ctx.accounts.vault_state;

        msg!("Before deposit - User balance: {}, Amount: {}", user_balance.balance, amount_to_add);

        // VULNERABILITY: Uses wrapping addition - will wrap on overflow!
        // If balance = u64::MAX - 10 and amount_to_add = 20, result = 9 (wraparound)
        // This allows an attacker to reduce their balance to a small value
        // while appearing to have deposited a large amount.
        user_balance.balance = user_balance.balance.wrapping_add(amount_to_add);

        // VULNERABILITY: No maximum deposit limit check
        // An attacker can deposit any amount, including values designed to cause overflow
        user_balance.deposits = user_balance.deposits.wrapping_add(amount_to_add);

        // VULNERABILITY: Vault total also vulnerable to overflow
        vault.total_deposits = vault.total_deposits.wrapping_add(amount_to_add);

        msg!("After deposit - User balance: {}", user_balance.balance);
        Ok(())
    }

    /// Withdraw funds from user balance
    ///
    /// VULNERABILITY: This instruction uses wrapping arithmetic that silently underflows!
    /// In production code without overflow-checks, underflow wraps to u64::MAX.
    pub fn withdraw(ctx: Context<Withdraw>, amount_to_subtract: u64) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;

        msg!(
            "Before withdraw - User balance: {}, Amount: {}",
            user_balance.balance,
            amount_to_subtract
        );

        // VULNERABILITY: Uses wrapping subtraction - will wrap on underflow!
        // If balance = 10 and amount_to_subtract = 20, result = u64::MAX - 9 (huge value!)
        // This allows an attacker to gain a massive balance from a small deposit
        user_balance.balance = user_balance.balance.wrapping_sub(amount_to_subtract);

        // VULNERABILITY: No check that balance >= withdrawal amount
        // The subtraction above will silently underflow and wrap around
        user_balance.withdrawals = user_balance.withdrawals.wrapping_add(amount_to_subtract);

        msg!("After withdraw - User balance: {}", user_balance.balance);
        Ok(())
    }

    /// Calculate rewards based on balance and rate
    ///
    /// VULNERABILITY: This instruction uses wrapping multiplication that silently overflows!
    pub fn calculate_rewards(ctx: Context<CalculateRewards>, reward_rate: u64) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;
        let vault = &mut ctx.accounts.vault_state;

        msg!("Calculating rewards - Balance: {}, Rate: {}", user_balance.balance, reward_rate);

        // VULNERABILITY: Uses wrapping multiplication - will wrap on overflow!
        // If balance = 2^32 and reward_rate = 2^33, result wraps to incorrect value
        // This can result in attackers receiving far more or less rewards than expected
        let reward_amount = user_balance.balance.wrapping_mul(reward_rate);

        // VULNERABILITY: No check for multiplication overflow before adding
        vault.total_rewards = vault.total_rewards.wrapping_add(reward_amount);

        // VULNERABILITY: Adding wrapping reward to balance
        user_balance.balance = user_balance.balance.wrapping_add(reward_amount);

        msg!("Reward calculated: {}, New balance: {}", reward_amount, user_balance.balance);
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================
// These accounts store u64 values that are targets for overflow/underflow attacks.
// In production, all arithmetic on these fields should use checked_* methods.

/// Vault state account - tracks global vault information
#[account]
pub struct VaultState {
    /// Authority who controls the vault (32 bytes)
    pub authority: Pubkey,
    /// Total SOL deposited across all users (8 bytes) - ARITHMETIC VULNERABILITY TARGET
    pub total_deposits: u64,
    /// Number of users registered (8 bytes)
    pub user_count: u64,
    /// Accumulated rewards distributed (8 bytes) - ARITHMETIC VULNERABILITY TARGET
    pub total_rewards: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

/// User balance account - tracks individual user's balance
#[account]
pub struct UserBalance {
    /// User who owns this balance (32 bytes)
    pub owner: Pubkey,
    /// User's current balance (8 bytes) - ARITHMETIC VULNERABILITY TARGET
    pub balance: u64,
    /// Total deposits made by user (8 bytes)
    pub deposits: u64,
    /// Total withdrawals made by user (8 bytes)
    pub withdrawals: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

// ============================================================================
// INSTRUCTION CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = VAULT_STATE_SIZE,
        seeds = [VAULT_SEED],
        bump
    )]
    pub vault_state: Account<'info, VaultState>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateUser<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [VAULT_SEED],
        bump = vault_state.bump
    )]
    pub vault_state: Account<'info, VaultState>,

    #[account(
        init,
        payer = owner,
        space = USER_BALANCE_SIZE,
        seeds = [USER_SEED, owner.key().as_ref()],
        bump
    )]
    pub user_balance: Account<'info, UserBalance>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [VAULT_SEED],
        bump = vault_state.bump
    )]
    pub vault_state: Account<'info, VaultState>,

    #[account(
        mut,
        seeds = [USER_SEED, owner.key().as_ref()],
        bump = user_balance.bump,
        constraint = user_balance.owner == owner.key()
    )]
    pub user_balance: Account<'info, UserBalance>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [USER_SEED, owner.key().as_ref()],
        bump = user_balance.bump,
        constraint = user_balance.owner == owner.key()
    )]
    pub user_balance: Account<'info, UserBalance>,
}

#[derive(Accounts)]
pub struct CalculateRewards<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [VAULT_SEED],
        bump = vault_state.bump
    )]
    pub vault_state: Account<'info, VaultState>,

    #[account(
        mut,
        seeds = [USER_SEED, user_balance.owner.as_ref()],
        bump = user_balance.bump
    )]
    pub user_balance: Account<'info, UserBalance>,
}
