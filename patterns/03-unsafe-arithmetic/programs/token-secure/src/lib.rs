#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

// Program ID from generated keypair
declare_id!("5BPg6JQc92Uey4F9KYqu9aCXvRjeETCeX1Qw6VYDkpva");

/// Vault seed for PDA derivation
pub const TOKEN_VAULT_SEED: &[u8] = b"token_vault";

/// Maximum single token deposit: 1 billion tokens with 9 decimals
///
/// Rationale: For SPL tokens with 9 decimals (SOL equivalent):
/// - 1 token = 10^9 base units
/// - MAX_TOKEN_DEPOSIT = 10^9 tokens × 10^9 = 10^18 base units
/// - This allows deposits up to 1 billion tokens in a single transaction
/// - Provides defense in depth against overflow attacks
/// - Value chosen to be large enough for real use while staying well under u64::MAX (~1.8×10^19)
///
/// SECURITY: Defense in depth - limits input even when using checked arithmetic
pub const MAX_TOKEN_DEPOSIT: u64 = 1_000_000_000_000_000_000;

/// TokenVaultState account size
/// Discriminator: 8 bytes
/// mint: 32 bytes
/// vault_token_account: 32 bytes
/// authority: 32 bytes
/// total_deposited: 8 bytes
/// total_withdrawn: 8 bytes
/// bump: 1 byte
/// Total: 121 bytes
pub const TOKEN_VAULT_STATE_SIZE: usize = 8 + 32 + 32 + 32 + 8 + 8 + 1;

/// Custom error codes for the secure token vault
#[error_code]
pub enum TokenVaultError {
    /// Arithmetic overflow detected during token deposit tracking
    #[msg("Token arithmetic overflow: deposit would exceed maximum trackable amount")]
    TokenArithmeticOverflow,

    /// Arithmetic underflow detected during token withdrawal tracking
    #[msg("Token arithmetic underflow: withdrawal calculation underflowed")]
    TokenArithmeticUnderflow,

    /// Attempted to withdraw more tokens than available balance
    #[msg("Insufficient tokens: withdrawal amount exceeds available balance")]
    InsufficientTokens,

    /// Single deposit exceeds maximum allowed amount
    #[msg("Deposit exceeds maximum: single deposit cannot exceed MAX_TOKEN_DEPOSIT")]
    ExceedsMaxTokenDeposit,
}

/// Token vault state account tracking deposits and withdrawals
///
/// # Security
/// This secure implementation uses checked arithmetic for all balance tracking
/// operations and validates inputs against maximum limits.
#[account]
pub struct TokenVaultState {
    /// Token mint address
    pub mint: Pubkey,
    /// Vault's token account (holds actual tokens)
    pub vault_token_account: Pubkey,
    /// Vault authority (PDA that signs for token transfers)
    pub authority: Pubkey,
    /// Total tokens deposited (SECURITY: uses checked arithmetic)
    pub total_deposited: u64,
    /// Total tokens withdrawn (SECURITY: uses checked arithmetic)
    pub total_withdrawn: u64,
    /// PDA bump seed
    pub bump: u8,
}

impl TokenVaultState {
    /// Calculate available balance with checked arithmetic
    ///
    /// # Security
    /// Uses checked_sub to ensure underflow is detected and reported
    pub fn available_balance(&self) -> Result<u64> {
        // SECURITY: Use checked_sub to prevent underflow
        self.total_deposited
            .checked_sub(self.total_withdrawn)
            .ok_or_else(|| error!(TokenVaultError::TokenArithmeticUnderflow))
    }
}

#[program]
pub mod token_secure_unsafe_arithmetic {
    use super::*;

    /// Initialize a new token vault
    ///
    /// Creates a vault state account that tracks token deposits and withdrawals.
    /// The vault uses a PDA as authority for the token account.
    pub fn initialize_token_vault(ctx: Context<InitializeTokenVault>) -> Result<()> {
        let vault_state = &mut ctx.accounts.vault_state;

        vault_state.mint = ctx.accounts.mint.key();
        vault_state.vault_token_account = ctx.accounts.vault_token_account.key();
        vault_state.authority = ctx.accounts.vault_authority.key();
        vault_state.total_deposited = 0;
        vault_state.total_withdrawn = 0;
        vault_state.bump = ctx.bumps.vault_state;

        msg!("Secure token vault initialized for mint: {}", vault_state.mint);
        msg!("Vault token account: {}", vault_state.vault_token_account);

        Ok(())
    }

    /// Deposit tokens into the vault
    ///
    /// # Security
    /// - SECURITY: Validates deposit against MAX_TOKEN_DEPOSIT limit
    /// - SECURITY: Uses checked_add() to detect overflow
    /// - SECURITY: Fails transaction if arithmetic would overflow
    ///
    /// This prevents attackers from manipulating the tracked balance
    /// through arithmetic overflow.
    pub fn deposit_tokens(ctx: Context<DepositTokens>, amount: u64) -> Result<()> {
        let vault_state = &mut ctx.accounts.vault_state;

        // SECURITY: Validate deposit amount against maximum limit
        // Defense in depth: even if checked_add would succeed, we limit single deposits
        require!(amount <= MAX_TOKEN_DEPOSIT, TokenVaultError::ExceedsMaxTokenDeposit);

        // SECURITY: Use checked_add to detect overflow BEFORE modifying state
        let new_total_deposited = vault_state
            .total_deposited
            .checked_add(amount)
            .ok_or(TokenVaultError::TokenArithmeticOverflow)?;

        // Only perform token transfer after all validations pass
        let cpi_accounts = Transfer {
            from: ctx.accounts.depositor_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.depositor.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // SECURITY: Update state only after successful transfer
        let old_total = vault_state.total_deposited;
        vault_state.total_deposited = new_total_deposited;

        msg!("SECURE DEPOSIT:");
        msg!("  Amount deposited: {}", amount);
        msg!("  Previous total_deposited: {}", old_total);
        msg!("  New total_deposited: {}", vault_state.total_deposited);

        Ok(())
    }

    /// Withdraw tokens from the vault
    ///
    /// # Security
    /// - SECURITY: Validates available balance >= withdrawal amount
    /// - SECURITY: Uses checked arithmetic for all calculations
    /// - SECURITY: Fails transaction if balance would underflow
    ///
    /// This prevents attackers from withdrawing more than deposited
    /// through arithmetic manipulation.
    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>, amount: u64) -> Result<()> {
        let vault_state = &mut ctx.accounts.vault_state;

        // SECURITY: Calculate available balance with checked arithmetic
        let available = vault_state.available_balance()?;

        msg!("SECURE WITHDRAWAL:");
        msg!("  Requested amount: {}", amount);
        msg!("  Tracked total_deposited: {}", vault_state.total_deposited);
        msg!("  Tracked total_withdrawn: {}", vault_state.total_withdrawn);
        msg!("  Calculated available balance: {}", available);

        // SECURITY: Validate sufficient balance BEFORE any state changes
        require!(amount <= available, TokenVaultError::InsufficientTokens);

        // SECURITY: Calculate new total_withdrawn with checked arithmetic
        let new_total_withdrawn = vault_state
            .total_withdrawn
            .checked_add(amount)
            .ok_or(TokenVaultError::TokenArithmeticOverflow)?;

        // Transfer tokens from vault to withdrawer
        // The vault PDA signs for this transfer
        let vault_bump = vault_state.bump;
        let mint_key = vault_state.mint;
        let signer_seeds: &[&[&[u8]]] = &[&[TOKEN_VAULT_SEED, mint_key.as_ref(), &[vault_bump]]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.withdrawer_token_account.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer_seeds);
        token::transfer(cpi_ctx, amount)?;

        // SECURITY: Update state only after successful transfer
        let old_withdrawn = vault_state.total_withdrawn;
        vault_state.total_withdrawn = new_total_withdrawn;

        msg!("  Previous total_withdrawn: {}", old_withdrawn);
        msg!("  New total_withdrawn: {}", vault_state.total_withdrawn);

        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeTokenVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The token mint for this vault
    pub mint: Account<'info, Mint>,

    /// The vault state account (PDA)
    #[account(
        init,
        payer = payer,
        space = TOKEN_VAULT_STATE_SIZE,
        seeds = [TOKEN_VAULT_SEED, mint.key().as_ref()],
        bump,
    )]
    pub vault_state: Account<'info, TokenVaultState>,

    /// The vault's token account that will hold deposited tokens
    /// This should be initialized separately and owned by vault_authority
    #[account(
        constraint = vault_token_account.mint == mint.key(),
        constraint = vault_token_account.owner == vault_authority.key(),
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// The vault authority PDA that owns the vault token account
    /// CHECK: This is a PDA that will be used as token account authority
    #[account(
        seeds = [TOKEN_VAULT_SEED, mint.key().as_ref()],
        bump,
    )]
    pub vault_authority: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DepositTokens<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [TOKEN_VAULT_SEED, mint.key().as_ref()],
        bump = vault_state.bump,
    )]
    pub vault_state: Account<'info, TokenVaultState>,

    /// Depositor's token account (source of tokens)
    #[account(
        mut,
        constraint = depositor_token_account.mint == mint.key(),
        constraint = depositor_token_account.owner == depositor.key(),
    )]
    pub depositor_token_account: Account<'info, TokenAccount>,

    /// Vault's token account (destination for tokens)
    #[account(
        mut,
        constraint = vault_token_account.key() == vault_state.vault_token_account,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    #[account(mut)]
    pub withdrawer: Signer<'info>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [TOKEN_VAULT_SEED, mint.key().as_ref()],
        bump = vault_state.bump,
    )]
    pub vault_state: Account<'info, TokenVaultState>,

    /// Vault's token account (source of tokens)
    #[account(
        mut,
        constraint = vault_token_account.key() == vault_state.vault_token_account,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    /// Withdrawer's token account (destination for tokens)
    #[account(
        mut,
        constraint = withdrawer_token_account.mint == mint.key(),
        constraint = withdrawer_token_account.owner == withdrawer.key(),
    )]
    pub withdrawer_token_account: Account<'info, TokenAccount>,

    /// The vault authority PDA that signs for token transfers
    /// CHECK: This is the PDA authority for the vault token account
    #[account(
        seeds = [TOKEN_VAULT_SEED, mint.key().as_ref()],
        bump = vault_state.bump,
    )]
    pub vault_authority: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
}
