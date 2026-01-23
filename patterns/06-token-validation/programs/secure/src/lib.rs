#![allow(unexpected_cfgs)]

//! # Secure Token Validation Pattern
//!
//! This program demonstrates secure SPL Token integration with proper validation
//! of token accounts, mint addresses, owners, and authorities.
//!
//! ## Learning Objectives
//!
//! After studying this pattern, you will understand:
//! 1. How to validate token account mints using Anchor constraints
//! 2. How to verify token account ownership for fund protection
//! 3. How to implement proper authority checks for privileged operations
//! 4. Best practices for SPL Token CPI calls
//!
//! ## Security Features Implemented
//!
//! | Security Check | Purpose | Constraint Used |
//! |----------------|---------|-----------------|
//! | Mint validation | Ensure correct token type | `constraint = token.mint == vault.mint` |
//! | Owner validation | Prevent fund redirection | `constraint = token.owner == user.key()` |
//! | Authority check | Restrict privileged operations | `has_one = authority` + `Signer` |
//!
//! ## Comparison with Vulnerable Version
//!
//! Each instruction in this program has a counterpart in the vulnerable version.
//! Compare the account constraints to understand what validations are missing
//! in the vulnerable implementation.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, MintTo, Token, TokenAccount, Transfer};

// Program ID generated from keypair
declare_id!("9EaBSBiZ2AHzL8Q5p9SqrC8Xgw2uExJMQzQttbA7vy4H");

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
pub mod secure_token_validation {
    use super::*;

    /// Initializes a new token vault with proper security configuration.
    ///
    /// Creates a vault PDA that tracks the accepted mint and stores the
    /// vault's token account address. The initializer becomes the vault authority
    /// and is the only one who can trigger minting operations.
    ///
    /// # Security Features
    /// - Vault PDA ensures deterministic, unforgeable address
    /// - Authority stored for future privileged operation validation
    /// - Mint address locked at initialization
    ///
    /// # Arguments
    /// * `ctx` - Context containing vault accounts
    ///
    /// # Returns
    /// * `Ok(())` on successful initialization
    pub fn initialize_vault(ctx: Context<InitializeVault>) -> Result<()> {
        // SECURITY: Store vault configuration with authority for future checks
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

    /// Deposits tokens into the vault with full mint validation.
    ///
    /// # Security Features
    ///
    /// 1. **Mint Validation**: The `Deposit` context enforces that
    ///    `user_token_account.mint == vault.mint`. This prevents attackers
    ///    from depositing worthless tokens from a different mint.
    ///
    /// 2. **Owner Validation**: The user must own the source token account,
    ///    preventing unauthorized transfers from other users' accounts.
    ///
    /// ## Vulnerable vs Secure Comparison
    ///
    /// | Check | Vulnerable | Secure |
    /// |-------|------------|--------|
    /// | Mint validation | ❌ None | ✅ `constraint = user_token_account.mint == vault.mint` |
    /// | Token ownership | ✅ Signer | ✅ Signer |
    ///
    /// # Arguments
    /// * `ctx` - Context containing validated deposit accounts
    /// * `amount` - Amount of tokens to deposit
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        // Initialize or update user deposit record
        let user_deposit = &mut ctx.accounts.user_deposit;
        if user_deposit.user == Pubkey::default() {
            // First deposit - initialize the record
            user_deposit.user = ctx.accounts.user.key();
            user_deposit.vault = ctx.accounts.vault.key();
            user_deposit.amount = 0;
            user_deposit.bump = ctx.bumps.user_deposit;
        }

        // SECURITY: Mint validation enforced by account constraints
        // The user_token_account.mint == vault.mint check happens in Deposit context
        // This prevents depositing tokens from a different (worthless) mint
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // SECURITY: Safe arithmetic with checked operations
        user_deposit.amount =
            user_deposit.amount.checked_add(amount).ok_or(TokenSecureError::ArithmeticOverflow)?;

        let vault = &mut ctx.accounts.vault;
        vault.total_deposits =
            vault.total_deposits.checked_add(amount).ok_or(TokenSecureError::ArithmeticOverflow)?;

        msg!("SECURE: Deposited {} tokens (mint validated)", amount);

        Ok(())
    }

    /// Withdraws tokens from the vault with full owner validation.
    ///
    /// # Security Features
    ///
    /// 1. **Owner Validation**: The `Withdraw` context enforces that
    ///    `destination_token_account.owner == user.key()`. This prevents
    ///    attackers from redirecting withdrawals to their own accounts.
    ///
    /// 2. **Balance Check**: Ensures user has sufficient deposited balance.
    ///
    /// 3. **Mint Validation**: Destination must match vault mint, preventing
    ///    cross-mint confusion.
    ///
    /// ## Vulnerable vs Secure Comparison
    ///
    /// | Check | Vulnerable | Secure |
    /// |-------|------------|--------|
    /// | Owner validation | ❌ None | ✅ `constraint = destination.owner == user.key()` |
    /// | Mint validation | ❌ None | ✅ `constraint = destination.mint == vault.mint` |
    /// | Balance check | ✅ Yes | ✅ Yes |
    ///
    /// # Arguments
    /// * `ctx` - Context containing validated withdrawal accounts
    /// * `amount` - Amount of tokens to withdraw
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;

        // SECURITY: Check user has sufficient deposit balance
        require!(user_deposit.amount >= amount, TokenSecureError::InsufficientBalance);

        // SECURITY: Owner validation enforced by account constraints
        // The destination_token_account.owner == user.key() check happens in Withdraw context
        // This prevents redirecting withdrawals to attacker-controlled accounts

        // Build PDA signer seeds for vault authority
        let vault = &ctx.accounts.vault;
        let vault_bump = vault.bump;
        let seeds = &[VAULT_SEED, vault.mint.as_ref(), &[vault_bump]];
        let signer_seeds = &[&seeds[..]];

        // SECURITY: Transfer to validated destination only
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

        // SECURITY: Safe arithmetic with checked operations
        user_deposit.amount =
            user_deposit.amount.checked_sub(amount).ok_or(TokenSecureError::ArithmeticOverflow)?;

        let vault = &mut ctx.accounts.vault;
        vault.total_deposits =
            vault.total_deposits.checked_sub(amount).ok_or(TokenSecureError::ArithmeticOverflow)?;

        msg!("SECURE: Withdrew {} tokens (owner validated)", amount);

        Ok(())
    }

    /// Mints reward tokens with proper authority validation.
    ///
    /// # Security Features
    ///
    /// 1. **Authority Validation**: The `MintReward` context enforces that
    ///    the caller is the vault authority using `has_one = authority`.
    ///
    /// 2. **Signer Requirement**: The authority must sign the transaction,
    ///    preventing spoofed authority pubkeys.
    ///
    /// 3. **Mint Validation**: Destination must match vault mint.
    ///
    /// ## Vulnerable vs Secure Comparison
    ///
    /// | Check | Vulnerable | Secure |
    /// |-------|------------|--------|
    /// | Authority validation | ❌ None | ✅ `has_one = authority` |
    /// | Signer requirement | ❌ Any signer | ✅ Authority must sign |
    /// | Mint validation | ✅ Yes | ✅ Yes |
    ///
    /// # Arguments
    /// * `ctx` - Context containing validated mint accounts
    /// * `amount` - Amount of tokens to mint
    pub fn mint_reward(ctx: Context<MintReward>, amount: u64) -> Result<()> {
        // SECURITY: Authority validation enforced by has_one constraint
        // Only vault.authority can reach this point

        // Build PDA signer seeds for mint authority
        let vault = &ctx.accounts.vault;
        let vault_bump = vault.bump;
        let seeds = &[VAULT_SEED, vault.mint.as_ref(), &[vault_bump]];
        let signer_seeds = &[&seeds[..]];

        // SECURITY: Mint with verified authority
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

        msg!("SECURE: Minted {} reward tokens (authority verified)", amount);

        Ok(())
    }
}

// ============================================================================
// Account Structures
// ============================================================================

/// Vault account storing token vault configuration.
///
/// The vault is a PDA that holds configuration for a token deposit system.
/// It tracks the accepted mint, vault token account, total deposits, and
/// importantly the authority for privileged operations.
#[account]
pub struct Vault {
    /// Authority who can manage the vault and mint rewards (32 bytes)
    /// SECURITY: Used in has_one constraint for authority validation
    pub authority: Pubkey,
    /// The SPL Token mint this vault accepts (32 bytes)
    /// SECURITY: Used to validate all incoming deposits
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
///
/// # Security Features
/// - Vault is a PDA with deterministic derivation
/// - Authority is stored for future has_one validation
/// - Vault token account ownership verified at init time
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
    /// SECURITY: Verify ownership at initialization
    #[account(
        mut,
        constraint = vault_token_account.mint == mint.key() @ TokenSecureError::MintMismatch,
        constraint = vault_token_account.owner == vault.key() @ TokenSecureError::OwnerMismatch
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
/// # Security Features
///
/// 1. **Mint Validation**: `user_token_account.mint == vault.mint` ensures
///    only the correct token type can be deposited.
///
/// 2. **Ownership**: User must sign, proving ownership of source account.
///
/// ## Comparison with Vulnerable Version
///
/// The vulnerable version is missing the mint constraint, allowing attackers
/// to deposit tokens from any mint (including worthless ones they created).
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

    // SECURITY: Mint validation - only accept tokens from vault's mint
    // This is the key fix compared to the vulnerable version
    /// User's token account to transfer from (SECURE: mint validated)
    #[account(
        mut,
        constraint = user_token_account.mint == vault.mint @ TokenSecureError::MintMismatch
    )]
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
/// # Security Features
///
/// 1. **Owner Validation**: `destination_token_account.owner == user.key()`
///    ensures funds can only be withdrawn to the user's own account.
///
/// 2. **Mint Validation**: Destination must accept the vault's token type.
///
/// 3. **Balance Check**: Performed in instruction logic.
///
/// ## Comparison with Vulnerable Version
///
/// The vulnerable version is missing the owner constraint, allowing attackers
/// to redirect withdrawals to any token account they control.
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
        constraint = user_deposit.user == user.key() @ TokenSecureError::Unauthorized
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    /// Vault's token account to transfer from
    #[account(
        mut,
        constraint = vault_token_account.key() == vault.vault_token_account
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    // SECURITY: Owner validation - only allow withdrawal to user's own account
    // SECURITY: Mint validation - destination must accept vault's token
    // These are the key fixes compared to the vulnerable version
    /// Destination token account (SECURE: owner and mint validated)
    #[account(
        mut,
        constraint = destination_token_account.owner == user.key() @ TokenSecureError::OwnerMismatch,
        constraint = destination_token_account.mint == vault.mint @ TokenSecureError::MintMismatch
    )]
    pub destination_token_account: Account<'info, TokenAccount>,

    /// User requesting withdrawal
    pub user: Signer<'info>,

    /// Token program for transfer
    pub token_program: Program<'info, Token>,
}

/// Accounts required for minting rewards.
///
/// # Security Features
///
/// 1. **Authority Validation**: `has_one = authority` ensures only the
///    designated vault authority can mint rewards.
///
/// 2. **Signer Requirement**: Authority must sign the transaction.
///
/// 3. **Mint Validation**: Destination must accept the vault's token type.
///
/// ## Comparison with Vulnerable Version
///
/// The vulnerable version has no authority check - anyone can call mint_reward
/// and create unlimited tokens. This version restricts minting to the authority.
#[derive(Accounts)]
pub struct MintReward<'info> {
    // SECURITY: has_one = authority ensures only vault.authority can mint
    // This is the key fix compared to the vulnerable version
    /// Vault that serves as mint authority (SECURE: authority validated)
    #[account(
        seeds = [VAULT_SEED, vault.mint.as_ref()],
        bump = vault.bump,
        has_one = authority @ TokenSecureError::Unauthorized
    )]
    pub vault: Account<'info, Vault>,

    /// Mint to create tokens from
    #[account(
        mut,
        constraint = mint.key() == vault.mint @ TokenSecureError::MintMismatch
    )]
    pub mint: Account<'info, Mint>,

    // SECURITY: Mint validation on destination
    /// Token account to receive minted tokens
    #[account(
        mut,
        constraint = destination_token_account.mint == mint.key() @ TokenSecureError::MintMismatch
    )]
    pub destination_token_account: Account<'info, TokenAccount>,

    // SECURITY: Authority must sign - prevents spoofed authority pubkeys
    /// Vault authority (SECURE: must be vault.authority and must sign)
    pub authority: Signer<'info>,

    /// Token program for minting
    pub token_program: Program<'info, Token>,
}

// ============================================================================
// Error Codes
// ============================================================================

/// Custom error codes for the secure token validation program.
///
/// These errors provide clear feedback when security validations fail,
/// helping developers understand why their transactions were rejected.
#[error_code]
pub enum TokenSecureError {
    /// Token account mint doesn't match vault's expected mint
    /// Triggered when: user tries to deposit tokens from wrong mint
    #[msg("Token account mint does not match vault mint")]
    MintMismatch,

    /// Token account owner doesn't match expected owner
    /// Triggered when: withdrawal destination isn't owned by withdrawer
    #[msg("Token account owner mismatch")]
    OwnerMismatch,

    /// Caller is not authorized for this operation
    /// Triggered when: non-authority tries to mint rewards
    #[msg("Not authorized to perform this action")]
    Unauthorized,

    /// User doesn't have enough deposited tokens to withdraw
    /// Triggered when: withdrawal amount exceeds deposit balance
    #[msg("Insufficient deposit balance for withdrawal")]
    InsufficientBalance,

    /// Arithmetic operation would overflow or underflow
    /// Triggered when: deposit/withdrawal causes numeric overflow
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}
