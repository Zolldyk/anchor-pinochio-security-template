#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

// Program ID from generated keypair
declare_id!("5j5GEqUp7L76EvzNjVYN1d6f1Vs287b2anJRtEbrmUoH");

/// Vault seed for PDA derivation
pub const TOKEN_VAULT_SEED: &[u8] = b"token_vault";

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

/// Token vault state account tracking deposits and withdrawals
///
/// # Vulnerability
/// This program demonstrates arithmetic vulnerabilities in token tracking.
/// The `total_deposited` and `total_withdrawn` fields use `wrapping_*` methods
/// which can overflow/underflow silently, allowing manipulation of tracked balances.
#[account]
pub struct TokenVaultState {
    /// Token mint address
    pub mint: Pubkey,
    /// Vault's token account (holds actual tokens)
    pub vault_token_account: Pubkey,
    /// Vault authority (PDA that signs for token transfers)
    pub authority: Pubkey,
    /// Total tokens deposited (VULNERABILITY: uses wrapping arithmetic)
    pub total_deposited: u64,
    /// Total tokens withdrawn (VULNERABILITY: uses wrapping arithmetic)
    pub total_withdrawn: u64,
    /// PDA bump seed
    pub bump: u8,
}

#[program]
pub mod token_vulnerable_unsafe_arithmetic {
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

        msg!("Token vault initialized for mint: {}", vault_state.mint);
        msg!("Vault token account: {}", vault_state.vault_token_account);

        Ok(())
    }

    /// Deposit tokens into the vault
    ///
    /// # Vulnerability
    /// - VULNERABILITY: Uses `wrapping_add()` for `total_deposited` tracking
    /// - VULNERABILITY: No maximum deposit limit
    ///
    /// An attacker can deposit a carefully chosen amount that causes the
    /// `total_deposited` counter to wrap around to a small value, making
    /// the tracked balance inconsistent with actual token holdings.
    pub fn deposit_tokens(ctx: Context<DepositTokens>, amount: u64) -> Result<()> {
        let vault_state = &mut ctx.accounts.vault_state;

        // Transfer tokens from depositor to vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.depositor_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.depositor.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // VULNERABILITY: Uses wrapping_add() - can overflow and wrap to small value
        // If total_deposited is near u64::MAX, adding more will wrap around to near 0
        // This makes the tracked balance inconsistent with actual token balance
        let old_total = vault_state.total_deposited;
        vault_state.total_deposited = vault_state.total_deposited.wrapping_add(amount);

        msg!("VULNERABLE DEPOSIT:");
        msg!("  Amount deposited: {}", amount);
        msg!("  Previous total_deposited: {}", old_total);
        msg!("  New total_deposited: {}", vault_state.total_deposited);

        // VULNERABILITY: No validation that tracking didn't overflow
        // In a real attack, total_deposited could wrap to a small number
        // while actual vault balance is much larger

        Ok(())
    }

    /// Withdraw tokens from the vault
    ///
    /// # Vulnerability
    /// - VULNERABILITY: Uses `wrapping_sub()` for balance calculation
    /// - VULNERABILITY: No validation that tracked balance >= withdrawal
    ///
    /// An attacker can withdraw more than the tracked balance allows because
    /// the subtraction wraps around instead of failing. Combined with the
    /// deposit overflow, this can drain funds.
    pub fn withdraw_tokens(ctx: Context<WithdrawTokens>, amount: u64) -> Result<()> {
        let vault_state = &mut ctx.accounts.vault_state;

        // VULNERABILITY: Calculate "available" balance with wrapping arithmetic
        // If total_withdrawn > total_deposited (shouldn't happen, but can via wrapping),
        // this produces a huge "available" balance
        let available = vault_state.total_deposited.wrapping_sub(vault_state.total_withdrawn);

        msg!("VULNERABLE WITHDRAWAL:");
        msg!("  Requested amount: {}", amount);
        msg!("  Tracked total_deposited: {}", vault_state.total_deposited);
        msg!("  Tracked total_withdrawn: {}", vault_state.total_withdrawn);
        msg!("  Calculated available (wrapping): {}", available);

        // VULNERABILITY: No proper validation - just check if amount <= available
        // But 'available' was calculated with wrapping, so this check is unreliable
        // Note: We still need SOME check or the token transfer will fail,
        // but the wrapping arithmetic makes this check potentially misleading

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

        // VULNERABILITY: Uses wrapping_add() for total_withdrawn - can overflow
        let old_withdrawn = vault_state.total_withdrawn;
        vault_state.total_withdrawn = vault_state.total_withdrawn.wrapping_add(amount);

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
