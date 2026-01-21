use anchor_lang::prelude::*;

declare_id!("9tncVxSh8pPnfwrzStTwnmaNd9Zi8PoQZugTBtqUV1ji");

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

/// Maximum single deposit amount: 1000 SOL in lamports
///
/// Rationale: 1 SOL = 1,000,000,000 lamports (10^9), so:
/// - MAX_DEPOSIT = 1,000 SOL × 10^9 = 10^12 lamports = 1,000,000,000,000
/// - This is a reasonable single-deposit limit for most DeFi applications
/// - Prevents overflow attacks by limiting deposit size
/// - Even MAX_DEPOSIT × MAX_REWARD_RATE = 10^16 fits safely in u64 (max ~1.8×10^19)
///
/// SECURITY: Limits input to prevent crafted overflow-inducing values
pub const MAX_DEPOSIT: u64 = 1_000_000_000_000;

/// Maximum reward rate multiplier: 10,000 basis points = 100x max
///
/// Rationale: Using basis points where 100 = 1x multiplier:
/// - 1 basis point = 0.01x multiplier
/// - 100 basis points = 1x multiplier (balance doubles)
/// - 10,000 basis points = 100x multiplier (maximum allowed)
/// - This provides fine-grained control (0.01x increments) up to 100x
///
/// SECURITY: Prevents multiplication overflow in reward calculations
/// Combined with MAX_DEPOSIT, worst case: 10^12 × 10^4 = 10^16 (safe for u64)
pub const MAX_REWARD_RATE: u64 = 10_000;

// ============================================================================
// PROGRAM MODULE
// ============================================================================

#[program]
pub mod secure_unsafe_arithmetic {
    use super::*;

    /// Initialize the vault with the given authority
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
    pub fn create_user(ctx: Context<CreateUser>) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;
        user_balance.owner = ctx.accounts.owner.key();
        user_balance.balance = 0;
        user_balance.deposits = 0;
        user_balance.withdrawals = 0;
        user_balance.bump = ctx.bumps.user_balance;

        let vault = &mut ctx.accounts.vault_state;
        // SECURITY: Use checked_add for user count increment
        vault.user_count = vault.user_count.checked_add(1).ok_or(ErrorCode::ArithmeticOverflow)?;

        msg!("User created: {}", user_balance.owner);
        Ok(())
    }

    /// Deposit funds into user balance
    ///
    /// SECURITY: This instruction uses checked arithmetic to prevent overflow attacks.
    /// All arithmetic operations return errors instead of wrapping silently.
    pub fn deposit(ctx: Context<Deposit>, amount_to_add: u64) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;
        let vault = &mut ctx.accounts.vault_state;

        msg!("Before deposit - User balance: {}, Amount: {}", user_balance.balance, amount_to_add);

        // SECURITY: Validate deposit amount against maximum limit
        // This prevents attackers from crafting overflow-inducing deposits
        require!(amount_to_add <= MAX_DEPOSIT, ErrorCode::ExceedsMaxDeposit);

        // SECURITY: Use checked_add() for balance update - returns None on overflow
        // If overflow would occur, we return an error instead of wrapping
        user_balance.balance =
            user_balance.balance.checked_add(amount_to_add).ok_or(ErrorCode::ArithmeticOverflow)?;

        // SECURITY: Use checked_add() for deposit tracking
        user_balance.deposits = user_balance
            .deposits
            .checked_add(amount_to_add)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        // SECURITY: Use checked_add() for vault total tracking
        vault.total_deposits =
            vault.total_deposits.checked_add(amount_to_add).ok_or(ErrorCode::ArithmeticOverflow)?;

        msg!("After deposit - User balance: {}", user_balance.balance);
        Ok(())
    }

    /// Withdraw funds from user balance
    ///
    /// SECURITY: This instruction validates sufficient balance and uses checked
    /// arithmetic to prevent underflow attacks.
    pub fn withdraw(ctx: Context<Withdraw>, amount_to_subtract: u64) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;

        msg!(
            "Before withdraw - User balance: {}, Amount: {}",
            user_balance.balance,
            amount_to_subtract
        );

        // SECURITY: First validate sufficient balance before any arithmetic
        // This is the primary defense against underflow attacks
        require!(user_balance.balance >= amount_to_subtract, ErrorCode::InsufficientBalance);

        // SECURITY: Use checked_sub() for defense in depth
        // Even after the require check, we use safe arithmetic as a second layer
        user_balance.balance = user_balance
            .balance
            .checked_sub(amount_to_subtract)
            .ok_or(ErrorCode::ArithmeticUnderflow)?;

        // SECURITY: Use checked_add() for withdrawal tracking
        user_balance.withdrawals = user_balance
            .withdrawals
            .checked_add(amount_to_subtract)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        msg!("After withdraw - User balance: {}", user_balance.balance);
        Ok(())
    }

    /// Calculate rewards based on balance and rate
    ///
    /// SECURITY: This instruction validates reward rate and uses checked
    /// multiplication to prevent overflow attacks.
    pub fn calculate_rewards(ctx: Context<CalculateRewards>, reward_rate: u64) -> Result<()> {
        let user_balance = &mut ctx.accounts.user_balance;
        let vault = &mut ctx.accounts.vault_state;

        msg!("Calculating rewards - Balance: {}, Rate: {}", user_balance.balance, reward_rate);

        // SECURITY: Validate reward rate against maximum
        // This prevents attackers from using extreme rates to cause overflow
        require!(reward_rate <= MAX_REWARD_RATE, ErrorCode::ExceedsMaxRewardRate);

        // SECURITY: Use checked_mul() for reward calculation - returns None on overflow
        // This prevents multiplication overflow attacks
        let reward_amount =
            user_balance.balance.checked_mul(reward_rate).ok_or(ErrorCode::ArithmeticOverflow)?;

        // SECURITY: Use checked_add() for vault reward tracking
        vault.total_rewards =
            vault.total_rewards.checked_add(reward_amount).ok_or(ErrorCode::ArithmeticOverflow)?;

        // SECURITY: Use checked_add() for adding reward to balance
        user_balance.balance =
            user_balance.balance.checked_add(reward_amount).ok_or(ErrorCode::ArithmeticOverflow)?;

        msg!("Reward calculated: {}, New balance: {}", reward_amount, user_balance.balance);
        Ok(())
    }
}

// ============================================================================
// ACCOUNT STRUCTURES
// ============================================================================

/// Vault state account - tracks global vault information
/// SECURITY: All numeric fields use safe arithmetic operations
#[account]
pub struct VaultState {
    /// Authority who controls the vault (32 bytes)
    pub authority: Pubkey,
    /// Total SOL deposited across all users (8 bytes)
    pub total_deposits: u64,
    /// Number of users registered (8 bytes)
    pub user_count: u64,
    /// Accumulated rewards distributed (8 bytes)
    pub total_rewards: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

/// User balance account - tracks individual user's balance
/// SECURITY: All balance operations use checked arithmetic
#[account]
pub struct UserBalance {
    /// User who owns this balance (32 bytes)
    pub owner: Pubkey,
    /// User's current balance (8 bytes)
    pub balance: u64,
    /// Total deposits made by user (8 bytes)
    pub deposits: u64,
    /// Total withdrawals made by user (8 bytes)
    pub withdrawals: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

// ============================================================================
// ERROR CODES
// ============================================================================

#[error_code]
pub enum ErrorCode {
    /// Arithmetic operation would overflow
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,

    /// Arithmetic operation would underflow
    #[msg("Arithmetic underflow detected")]
    ArithmeticUnderflow,

    /// Insufficient balance for withdrawal
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,

    /// Deposit amount exceeds maximum allowed
    #[msg("Deposit amount exceeds maximum allowed")]
    ExceedsMaxDeposit,

    /// Reward rate exceeds maximum allowed
    #[msg("Reward rate exceeds maximum allowed")]
    ExceedsMaxRewardRate,
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
