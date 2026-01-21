use anchor_lang::prelude::*;

// Program ID from generated keypair
declare_id!("4bEDU5VynGAFuZ1MXF1HU4oNLDv5XaDyBZwDARYszCwm");

/// PDA Derivation Vulnerable Program
///
/// This program demonstrates common PDA-related vulnerabilities:
/// - Accepting user-provided PDAs without re-derivation
/// - Not validating canonical bump seeds
/// - Missing seed validation allowing unauthorized access
///
/// EDUCATIONAL PURPOSE ONLY - DO NOT USE IN PRODUCTION

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
#[account]
#[derive(InitSpace)]
pub struct Treasury {
    /// Treasury admin who can manage funds
    pub authority: Pubkey,
    /// Total balance held in treasury (tracked internally, not actual lamports)
    pub balance: u64,
    /// PDA bump seed (stored but not validated in vulnerable version)
    pub bump: u8,
}

/// User deposit account - tracks individual deposits
/// PDA seeds: ["user_deposit", treasury, owner]
#[account]
#[derive(InitSpace)]
pub struct UserDeposit {
    /// Depositor's pubkey
    pub owner: Pubkey,
    /// Associated treasury account
    pub treasury: Pubkey,
    /// Deposited amount
    pub amount: u64,
    /// PDA bump seed (stored but not validated in vulnerable version)
    pub bump: u8,
}

// ============================================================================
// PROGRAM MODULE
// ============================================================================

#[program]
pub mod vulnerable_pda_derivation {
    use super::*;

    /// Initialize a new treasury account
    ///
    /// VULNERABILITY: Accepts user-provided bump without re-deriving to verify
    /// it matches the canonical bump. An attacker could potentially pass a
    /// non-canonical bump, though Anchor's init constraint still derives.
    pub fn initialize_treasury(ctx: Context<InitializeTreasury>, bump: u8) -> Result<()> {
        let treasury = &mut ctx.accounts.treasury;

        treasury.authority = ctx.accounts.authority.key();
        treasury.balance = 0;
        // VULNERABILITY: Storing user-provided bump without validation
        // In a secure version, we would use the bump from Anchor's derivation
        treasury.bump = bump;

        msg!("Treasury initialized: authority={}, bump={}", treasury.authority, treasury.bump);

        Ok(())
    }

    /// Create a user deposit account linked to a treasury
    ///
    /// VULNERABILITY: Does not verify the treasury PDA derivation matches expected seeds.
    /// An attacker could pass a fake treasury account.
    pub fn create_user_deposit(ctx: Context<CreateUserDeposit>, bump: u8) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;

        user_deposit.owner = ctx.accounts.owner.key();
        // VULNERABILITY: Accepts any treasury account without verifying it's a valid PDA
        user_deposit.treasury = ctx.accounts.treasury.key();
        user_deposit.amount = 0;
        // VULNERABILITY: Storing user-provided bump without validation
        user_deposit.bump = bump;

        msg!(
            "User deposit created: owner={}, treasury={}",
            user_deposit.owner,
            user_deposit.treasury
        );

        Ok(())
    }

    /// Deposit funds into user's deposit account
    ///
    /// VULNERABILITY: Does not validate that user_deposit PDA is derived from
    /// correct seeds. Attacker could substitute a different account.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;
        let treasury = &mut ctx.accounts.treasury;

        // VULNERABILITY: No validation that user_deposit.treasury == treasury.key()
        // VULNERABILITY: No PDA seeds validation

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
        user_deposit.amount = user_deposit.amount.checked_add(amount).unwrap();
        treasury.balance = treasury.balance.checked_add(amount).unwrap();

        msg!("Deposited {} lamports", amount);

        Ok(())
    }

    /// Withdraw funds from user's deposit account
    ///
    /// VULNERABILITY: Accepts any account without proper PDA validation
    /// VULNERABILITY: Does not verify canonical bump seed
    /// VULNERABILITY: Missing authority check on treasury
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let user_deposit = &mut ctx.accounts.user_deposit;
        let treasury = &mut ctx.accounts.treasury;

        // VULNERABILITY: No validation that caller owns this deposit
        // VULNERABILITY: No PDA re-derivation to verify account authenticity
        // VULNERABILITY: No check that user_deposit.treasury matches treasury.key()

        require!(user_deposit.amount >= amount, PdaError::InsufficientBalance);

        // Update balances before transfer (good practice, but doesn't fix vulnerabilities)
        user_deposit.amount = user_deposit.amount.checked_sub(amount).unwrap();
        treasury.balance = treasury.balance.checked_sub(amount).unwrap();

        // Transfer lamports from treasury to withdrawer
        // VULNERABILITY: Using stored bump without validating it's canonical
        // Note: PDAs with data cannot use system_instruction::transfer
        let treasury_info = treasury.to_account_info();
        let withdrawer_info = ctx.accounts.withdrawer.to_account_info();

        **treasury_info.try_borrow_mut_lamports()? =
            treasury_info.lamports().checked_sub(amount).unwrap();
        **withdrawer_info.try_borrow_mut_lamports()? =
            withdrawer_info.lamports().checked_add(amount).unwrap();

        msg!("Withdrew {} lamports", amount);

        Ok(())
    }
}

// ============================================================================
// ACCOUNT CONTEXTS
// ============================================================================

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct InitializeTreasury<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Treasury::INIT_SPACE,
        // VULNERABILITY: While Anchor derives the PDA, we accept user's bump parameter
        // and store it without verifying it matches Anchor's canonical derivation
        seeds = [TREASURY_SEED, authority.key().as_ref()],
        bump
    )]
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct CreateUserDeposit<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + UserDeposit::INIT_SPACE,
        seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), owner.key().as_ref()],
        bump
    )]
    pub user_deposit: Account<'info, UserDeposit>,

    /// VULNERABILITY: Treasury is accepted as AccountInfo, no type checking
    /// An attacker could pass any account here
    /// CHECK: Intentionally vulnerable - no validation performed
    pub treasury: AccountInfo<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user_deposit: Account<'info, UserDeposit>,

    /// VULNERABILITY: No has_one constraint to verify relationship
    /// VULNERABILITY: No seeds constraint to verify PDA derivation
    #[account(mut)]
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// VULNERABILITY: No seeds constraint to re-derive and validate PDA
    /// VULNERABILITY: No has_one constraint to verify owner
    #[account(mut)]
    pub user_deposit: Account<'info, UserDeposit>,

    /// VULNERABILITY: No validation that this is the correct treasury for user_deposit
    /// VULNERABILITY: No seeds constraint to verify canonical bump
    #[account(mut)]
    pub treasury: Account<'info, Treasury>,

    #[account(mut)]
    pub withdrawer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ============================================================================
// ERROR CODES
// ============================================================================

#[error_code]
pub enum PdaError {
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,
}
