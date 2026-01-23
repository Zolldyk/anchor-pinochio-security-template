#![allow(unexpected_cfgs)]

//! # Vulnerable Token Validation Pattern
//!
//! This program demonstrates common SPL Token integration vulnerabilities that
//! can lead to token theft, unauthorized minting, and account substitution attacks.
//!
//! ## Learning Objectives
//!
//! After studying this pattern, you will understand:
//! 1. Why token account mint validation is critical
//! 2. How missing owner validation enables fund redirection
//! 3. Why authority checks prevent unauthorized minting
//! 4. Common token account substitution attack vectors
//!
//! ## Vulnerabilities Demonstrated
//!
//! | Vulnerability | Impact | Instruction |
//! |---------------|--------|-------------|
//! | Missing mint validation | Deposit worthless tokens, withdraw valuable ones | `deposit` |
//! | Missing owner validation | Redirect withdrawals to attacker accounts | `withdraw` |
//! | Missing authority check | Unlimited unauthorized token minting | `mint_reward` |
//!
//! ## WARNING
//!
//! **DO NOT use this code in production.** This program intentionally contains
//! security vulnerabilities for educational purposes only.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, MintTo, Token, TokenAccount, Transfer};

// Program ID generated from keypair
declare_id!("7BuzUJe5wBqrsmnM6VDjKTM4S3TWwDtm2rHPPWYRb9px");

// ============================================================================
// Constants
// ============================================================================

/// Vault account space: discriminator (8) + authority (32) + mint (32) +
/// vault_token_account (32) + total_deposits (8) + bump (1) = 113 bytes
const VAULT_SPACE: usize = 8 + 32 + 32 + 32 + 8 + 1;

/// UserDeposit account space: discriminator (8) + user (32) + vault (32) +
/// amount (8) + bump (1) = 81 bytes
const USER_DEPOSIT_SPACE: usize = 8 + 32 + 32 + 8 + 1;

/// Seed prefix for vault PDA derivation
const VAULT_SEED: &[u8] = b"vault";

/// Seed prefix for user deposit PDA derivation
const USER_DEPOSIT_SEED: &[u8] = b"user_deposit";

// ============================================================================
// Program Entry Point
// ============================================================================

#[program]
pub mod vulnerable_token_validation {
    use super::*;

    /// Initializes a new token vault that accepts deposits.
    ///
    /// Creates a vault PDA that tracks the accepted mint and stores the
    /// vault's token account address. The initializer becomes the vault authority.
    ///
    /// # Arguments
    /// * `ctx` - Context containing vault accounts
    ///
    /// # Returns
    /// * `Ok(())` on successful initialization
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        // Store vault configuration
        let vault = &mut ctx.accounts.vault;
        vault.authority = ctx.accounts.authority.key();
        vault.mint = ctx.accounts.mint.key();
        vault.vault_token_account = ctx.accounts.vault_token_account.key();
        vault.total_deposits = 0;
        vault.bump = ctx.bumps.vault;

        msg!("Vault initialized for mint: {}", vault.mint);
        msg!("Vault authority: {}", vault.authority);

        Ok(())
    }

    /// Deposits tokens into the vault.
    ///
    /// # VULNERABILITY: No Mint Validation
    ///
    /// This function accepts ANY token account without verifying that its mint
    /// matches the vault's expected mint. An attacker can:
    ///
    /// 1. Create a worthless token mint
    /// 2. Mint tokens to their token account
    /// 3. Deposit the worthless tokens (accepted because no mint check)
    /// 4. Withdraw valuable tokens from the vault
    ///
    /// The vulnerable code trusts that `user_token_account.mint == vault.mint`
    /// without actually checking it.
    ///
    /// # Arguments
    /// * `ctx` - Context containing deposit accounts
    /// * `amount` - Amount of tokens to deposit
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // VULNERABILITY: No mint validation - accepts any token account!
        // The user_token_account.mint is never checked against vault.mint
        // This allows depositing tokens from a different (worthless) mint

        // Initialize or update user deposit record
        let user_deposit = &mut ctx.accounts.user_deposit;
        if user_deposit.user == Pubkey::default() {
            // First deposit - initialize the record
            user_deposit.user = ctx.accounts.user.key();
            user_deposit.vault = ctx.accounts.vault.key();
            user_deposit.amount = 0;
            user_deposit.bump = ctx.bumps.user_deposit;
        }

        // VULNERABILITY: No mint validation - accepts any token account!
        // An attacker can deposit worthless tokens from a different mint
        // and later withdraw valuable tokens from the vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // Update deposit tracking (credits attacker with deposit amount)
        user_deposit.amount =
            user_deposit.amount.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;

        // Update vault total
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits =
            vault.total_deposits.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;

        msg!("Deposited {} tokens (mint validation: NONE)", amount);

        Ok(())
    }

    /// Withdraws tokens from the vault.
    ///
    /// # VULNERABILITY: No Owner Validation
    ///
    /// This function accepts ANY destination token account without verifying
    /// that its owner matches the withdrawer. An attacker can:
    ///
    /// 1. Wait for a victim to initiate a withdrawal
    /// 2. Front-run by substituting the destination with their own token account
    /// 3. Receive the victim's tokens in their account
    ///
    /// Or in a simpler attack:
    /// 1. Attacker calls withdraw with their own destination account
    /// 2. Even though they have a deposit record, they redirect to wrong owner
    ///
    /// The vulnerable code trusts that the destination belongs to the withdrawer.
    ///
    /// # Arguments
    /// * `ctx` - Context containing withdrawal accounts
    /// * `amount` - Amount of tokens to withdraw
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;

        // Check user has sufficient deposit balance
        require!(user_deposit.amount >= amount, VulnerableError::InsufficientBalance);

        // VULNERABILITY: No owner validation on destination!
        // The destination_token_account.owner is never checked against user.key()
        // This allows redirecting withdrawals to any token account

        // Build PDA signer seeds for vault authority
        let vault = &ctx.accounts.vault;
        let vault_bump = vault.bump;
        let seeds = &[VAULT_SEED, vault.mint.as_ref(), &[vault_bump]];
        let signer_seeds = &[&seeds[..]];

        // VULNERABILITY: No owner validation - sends to any destination!
        // Attacker can provide their own token account as destination
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.destination_token_account.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        token::transfer(cpi_ctx, amount)?;

        // Update deposit tracking
        user_deposit.amount =
            user_deposit.amount.checked_sub(amount).ok_or(ProgramError::ArithmeticOverflow)?;

        // Update vault total
        let vault = &mut ctx.accounts.vault;
        vault.total_deposits =
            vault.total_deposits.checked_sub(amount).ok_or(ProgramError::ArithmeticOverflow)?;

        msg!("Withdrew {} tokens (owner validation: NONE)", amount);

        Ok(())
    }

    /// Mints reward tokens to a user.
    ///
    /// # VULNERABILITY: No Authority Check
    ///
    /// This function allows ANYONE to mint tokens because it doesn't verify
    /// that the caller is the mint authority. An attacker can:
    ///
    /// 1. Call mint_reward with any amount
    /// 2. Mint unlimited tokens to their account
    /// 3. Drain the vault by exchanging inflated tokens
    ///
    /// The vulnerable code passes the vault as mint authority but doesn't
    /// verify the caller has permission to trigger minting.
    ///
    /// # Arguments
    /// * `ctx` - Context containing mint accounts
    /// * `amount` - Amount of tokens to mint
    pub fn mint_reward(ctx: Context<MintReward>, amount: u64) -> Result<()> {
        // VULNERABILITY: No authority check - anyone can mint!
        // There's no validation that the caller (anyone) is authorized
        // to trigger minting operations

        // Build PDA signer seeds for mint authority
        let vault = &ctx.accounts.vault;
        let vault_bump = vault.bump;
        let seeds = &[VAULT_SEED, vault.mint.as_ref(), &[vault_bump]];
        let signer_seeds = &[&seeds[..]];

        // VULNERABILITY: No authority check - allows unauthorized minting!
        // Any user can call this and mint tokens to themselves
        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.destination_token_account.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer_seeds,
        );
        token::mint_to(cpi_ctx, amount)?;

        msg!("Minted {} reward tokens (authority check: NONE)", amount);

        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

/// Vault account storing token vault configuration.
///
/// The vault is a PDA that holds configuration for a token deposit system.
/// It tracks the accepted mint, vault token account, and total deposits.
#[account]
pub struct Vault {
    /// Authority who can manage the vault (32 bytes)
    pub authority: Pubkey,
    /// The SPL Token mint this vault accepts (32 bytes)
    pub mint: Pubkey,
    /// Token account holding vault funds (32 bytes)
    pub vault_token_account: Pubkey,
    /// Total tokens deposited across all users (8 bytes)
    pub total_deposits: u64,
    /// PDA bump seed for signing (1 byte)
    pub bump: u8,
}

/// User deposit record tracking individual user deposits.
///
/// Each user has a PDA tracking their deposit amount in a specific vault.
/// This enables per-user withdrawal limits and balance tracking.
#[account]
pub struct UserDeposit {
    /// User who made the deposit (32 bytes)
    pub user: Pubkey,
    /// Vault this deposit belongs to (32 bytes)
    pub vault: Pubkey,
    /// Amount currently deposited (8 bytes)
    pub amount: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

// ============================================================================
// Instruction Contexts
// ============================================================================

/// Accounts required for vault initialization.
#[derive(Accounts)]
pub struct InitializeVault<'info> {
    /// Vault PDA to initialize - seeds: ["vault", mint]
    #[account(
        init,
        payer = authority,
        space = VAULT_SPACE,
        seeds = [VAULT_SEED, mint.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,

    /// The token mint this vault will accept
    pub mint: Account<'info, Mint>,

    /// Token account owned by vault PDA to hold deposited tokens
    #[account(
        mut,
        constraint = vault_token_account.mint == mint.key(),
        constraint = vault_token_account.owner == vault.key()
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// Authority initializing and managing the vault
    #[account(mut)]
    pub authority: Signer<'info>,

    /// System program for account creation
    pub system_program: Program<'info, System>,

    /// Token program for token operations
    pub token_program: Program<'info, Token>,
}

/// Accounts required for deposit operation.
///
/// # Security Analysis
///
/// This context is VULNERABLE because it does not validate that
/// `user_token_account.mint == vault.mint`. An attacker can pass
/// a token account from a different mint.
#[derive(Accounts)]
pub struct Deposit<'info> {
    /// Vault receiving the deposit
    #[account(
        mut,
        seeds = [VAULT_SEED, vault.mint.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    /// User's deposit record PDA - seeds: ["user_deposit", vault, user]
    #[account(
        init_if_needed,
        payer = user,
        space = USER_DEPOSIT_SPACE,
        seeds = [USER_DEPOSIT_SEED, vault.key().as_ref(), user.key().as_ref()],
        bump
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    // VULNERABILITY: No mint constraint on user_token_account!
    // Should have: constraint = user_token_account.mint == vault.mint
    /// User's token account to transfer from (VULNERABLE: no mint check)
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,

    /// Vault's token account to receive tokens
    #[account(
        mut,
        constraint = vault_token_account.key() == vault.vault_token_account
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// User making the deposit
    #[account(mut)]
    pub user: Signer<'info>,

    /// System program for PDA creation
    pub system_program: Program<'info, System>,

    /// Token program for transfer
    pub token_program: Program<'info, Token>,
}

/// Accounts required for withdrawal operation.
///
/// # Security Analysis
///
/// This context is VULNERABLE because it does not validate that
/// `destination_token_account.owner == user.key()`. An attacker can
/// redirect withdrawals to their own token account.
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// Vault to withdraw from
    #[account(
        mut,
        seeds = [VAULT_SEED, vault.mint.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    /// User's deposit record
    #[account(
        mut,
        seeds = [USER_DEPOSIT_SEED, vault.key().as_ref(), user.key().as_ref()],
        bump = user_deposit.bump,
        constraint = user_deposit.user == user.key()
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    /// Vault's token account to transfer from
    #[account(
        mut,
        constraint = vault_token_account.key() == vault.vault_token_account
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    // VULNERABILITY: No owner constraint on destination_token_account!
    // Should have: constraint = destination_token_account.owner == user.key()
    /// Destination token account (VULNERABLE: no owner check)
    #[account(mut)]
    pub destination_token_account: Account<'info, TokenAccount>,

    /// User requesting withdrawal
    pub user: Signer<'info>,

    /// Token program for transfer
    pub token_program: Program<'info, Token>,
}

/// Accounts required for minting rewards.
///
/// # Security Analysis
///
/// This context is VULNERABLE because it does not validate that
/// the caller is authorized to mint tokens. Anyone can call this
/// instruction and mint unlimited tokens.
#[derive(Accounts)]
pub struct MintReward<'info> {
    /// Vault that serves as mint authority
    #[account(
        seeds = [VAULT_SEED, vault.mint.as_ref()],
        bump = vault.bump
    )]
    pub vault: Account<'info, Vault>,

    /// Mint to create tokens from
    #[account(
        mut,
        constraint = mint.key() == vault.mint
    )]
    pub mint: Account<'info, Mint>,

    /// Token account to receive minted tokens
    #[account(
        mut,
        constraint = destination_token_account.mint == mint.key()
    )]
    pub destination_token_account: Account<'info, TokenAccount>,

    // VULNERABILITY: No authority validation!
    // Should require: authority == vault.authority AND be a Signer
    // Anyone can call this instruction without permission
    /// Caller (VULNERABLE: no authority check)
    pub anyone: Signer<'info>,

    /// Token program for minting
    pub token_program: Program<'info, Token>,
}

// ============================================================================
// Error Codes
// ============================================================================

/// Custom error codes for the vulnerable program.
///
/// Note: A secure implementation would have more comprehensive error types
/// for validation failures. This minimal set exists only for basic operation.
#[error_code]
pub enum VulnerableError {
    /// User doesn't have enough deposited tokens to withdraw
    #[msg("Insufficient deposit balance for withdrawal")]
    InsufficientBalance,
}
