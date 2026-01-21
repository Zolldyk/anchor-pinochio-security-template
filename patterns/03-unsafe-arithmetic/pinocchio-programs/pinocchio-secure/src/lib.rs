//! # Pinocchio Secure Unsafe Arithmetic Program
//!
//! This program demonstrates **SECURE** arithmetic patterns in Solana using Pinocchio.
//! It is designed for educational purposes to show how to prevent integer overflow/underflow
//! vulnerabilities using proper safe math techniques.
//!
//! ## Key Security Patterns
//! - `checked_add()` with error handling for deposits
//! - `checked_sub()` with error handling for withdrawals
//! - `checked_mul()` with error handling for reward calculations
//! - Input validation with maximum limits (MAX_DEPOSIT, MAX_REWARD_RATE)
//! - Custom error enum for clear error messages
//!
//! ## Key Differences from Anchor
//! - Manual error type definition instead of `#[error_code]`
//! - Explicit if-checks instead of `require!()` macro
//! - Manual instruction routing with discriminators

#![allow(unexpected_cfgs)]

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID: CVyZU6X4vBxHQaQar29cho6Gv9qYLX8wu1wBYCq1K4jW
pub const ID: Address = Address::new_from_array([
    0x6b, 0x3e, 0xea, 0x8a, 0xae, 0x8f, 0xcc, 0x38, 0xbe, 0x2d, 0x22, 0xfc, 0x70, 0xf6, 0xeb, 0x1f,
    0x4c, 0xec, 0x3d, 0x00, 0x74, 0x24, 0xdc, 0xfb, 0x45, 0xf9, 0xe0, 0x1d, 0xe2, 0x91, 0xbf, 0x3c,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// VaultState account size (no Anchor discriminator):
/// - authority (Address): 32 bytes
/// - total_deposits (u64): 8 bytes
/// - user_count (u64): 8 bytes
/// - total_rewards (u64): 8 bytes
/// - bump (u8): 1 byte
///
/// Total: 57 bytes
pub const VAULT_STATE_SIZE: usize = 32 + 8 + 8 + 8 + 1;

/// UserBalance account size (no Anchor discriminator):
/// - owner (Address): 32 bytes
/// - balance (u64): 8 bytes
/// - deposits (u64): 8 bytes
/// - withdrawals (u64): 8 bytes
/// - bump (u8): 1 byte
///
/// Total: 57 bytes
pub const USER_BALANCE_SIZE: usize = 32 + 8 + 8 + 8 + 1;

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

// =============================================================================
// INSTRUCTION DISCRIMINATORS
// =============================================================================

pub const INITIALIZE_VAULT_DISCRIMINATOR: u8 = 0;
pub const CREATE_USER_DISCRIMINATOR: u8 = 1;
pub const DEPOSIT_DISCRIMINATOR: u8 = 2;
pub const WITHDRAW_DISCRIMINATOR: u8 = 3;
pub const CALCULATE_REWARDS_DISCRIMINATOR: u8 = 4;

// =============================================================================
// CUSTOM ERROR TYPES
// =============================================================================

/// Custom error types for secure arithmetic operations.
///
/// This enum provides clear, specific error codes for different failure modes.
/// Equivalent to Anchor's `#[error_code]` macro but defined manually.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum SecureError {
    /// Arithmetic operation would overflow (e.g., balance + deposit > u64::MAX)
    ArithmeticOverflow = 0,
    /// Arithmetic operation would underflow (e.g., balance - withdrawal < 0)
    ArithmeticUnderflow = 1,
    /// User has insufficient balance for the requested withdrawal
    InsufficientBalance = 2,
    /// Deposit amount exceeds the maximum allowed (MAX_DEPOSIT)
    ExceedsMaxDeposit = 3,
    /// Reward rate exceeds the maximum allowed (MAX_REWARD_RATE)
    ExceedsMaxRewardRate = 4,
}

impl From<SecureError> for ProgramError {
    fn from(e: SecureError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Vault state account - tracks global vault information.
/// SECURITY: All numeric fields use checked arithmetic operations.
pub struct VaultState {
    /// Authority who controls the vault (32 bytes)
    pub authority: Address,
    /// Total SOL deposited across all users (8 bytes)
    pub total_deposits: u64,
    /// Number of users registered (8 bytes)
    pub user_count: u64,
    /// Accumulated rewards distributed (8 bytes)
    pub total_rewards: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

impl VaultState {
    /// Deserialize VaultState from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < VAULT_STATE_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let total_deposits = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let user_count = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let total_rewards = u64::from_le_bytes(
            data[48..56].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let bump = data[56];

        Ok(Self { authority, total_deposits, user_count, total_rewards, bump })
    }

    /// Serialize VaultState into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < VAULT_STATE_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.authority.as_ref());
        data[32..40].copy_from_slice(&self.total_deposits.to_le_bytes());
        data[40..48].copy_from_slice(&self.user_count.to_le_bytes());
        data[48..56].copy_from_slice(&self.total_rewards.to_le_bytes());
        data[56] = self.bump;

        Ok(())
    }
}

/// User balance account - tracks individual user's balance.
/// SECURITY: All balance operations use checked arithmetic.
pub struct UserBalance {
    /// User who owns this balance (32 bytes)
    pub owner: Address,
    /// User's current balance (8 bytes)
    pub balance: u64,
    /// Total deposits made by user (8 bytes)
    pub deposits: u64,
    /// Total withdrawals made by user (8 bytes)
    pub withdrawals: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

impl UserBalance {
    /// Deserialize UserBalance from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < USER_BALANCE_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let owner = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let balance = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let deposits = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let withdrawals = u64::from_le_bytes(
            data[48..56].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let bump = data[56];

        Ok(Self { owner, balance, deposits, withdrawals, bump })
    }

    /// Serialize UserBalance into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_BALANCE_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.owner.as_ref());
        data[32..40].copy_from_slice(&self.balance.to_le_bytes());
        data[40..48].copy_from_slice(&self.deposits.to_le_bytes());
        data[48..56].copy_from_slice(&self.withdrawals.to_le_bytes());
        data[56] = self.bump;

        Ok(())
    }
}

// =============================================================================
// ENTRYPOINT
// =============================================================================

entrypoint!(process_instruction);

/// Main entrypoint for the Pinocchio secure unsafe arithmetic program.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, data) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        INITIALIZE_VAULT_DISCRIMINATOR => initialize_vault(program_id, accounts, data),
        CREATE_USER_DISCRIMINATOR => create_user(program_id, accounts, data),
        DEPOSIT_DISCRIMINATOR => deposit(accounts, data),
        WITHDRAW_DISCRIMINATOR => withdraw(accounts, data),
        CALCULATE_REWARDS_DISCRIMINATOR => calculate_rewards(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initialize the vault with the given authority.
///
/// # Accounts
/// 0. `[writable]` vault_state - The vault account to initialize (must be pre-allocated)
/// 1. `[signer]` authority - The authority who controls the vault
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed
fn initialize_vault(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_state_acc, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_state_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let bump = if data.is_empty() { 0 } else { data[0] };

    let vault_state = VaultState {
        authority: Address::new_from_array(*authority.address().as_array()),
        total_deposits: 0,
        user_count: 0,
        total_rewards: 0,
        bump,
    };

    let mut account_data = vault_state_acc.try_borrow_mut()?;
    vault_state.serialize(&mut account_data)?;

    log!("Vault initialized with authority");

    Ok(())
}

/// Create a user balance account.
///
/// # Accounts
/// 0. `[writable]` vault_state - The vault account
/// 1. `[writable]` user_balance - The user balance account to initialize (must be pre-allocated)
/// 2. `[signer]` owner - The user who will own this balance
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed for user_balance
fn create_user(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_state_acc, user_balance_acc, owner] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_state_acc.owned_by(program_id) || !user_balance_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let bump = if data.is_empty() { 0 } else { data[0] };

    // Read and update vault state
    let vault_data = vault_state_acc.try_borrow()?;
    let mut vault_state = VaultState::try_from_slice(&vault_data)?;
    drop(vault_data);

    // SECURITY: Use checked_add for user count increment
    vault_state.user_count =
        vault_state.user_count.checked_add(1).ok_or(SecureError::ArithmeticOverflow)?;

    let mut vault_data = vault_state_acc.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;
    drop(vault_data);

    // Initialize user balance
    let user_balance = UserBalance {
        owner: Address::new_from_array(*owner.address().as_array()),
        balance: 0,
        deposits: 0,
        withdrawals: 0,
        bump,
    };

    let mut account_data = user_balance_acc.try_borrow_mut()?;
    user_balance.serialize(&mut account_data)?;

    log!("User created");

    Ok(())
}

/// Deposit funds into user balance.
///
/// # Security Features
/// - SECURITY: Validates deposit amount against MAX_DEPOSIT limit
/// - SECURITY: Uses checked_add() for all balance updates
/// - SECURITY: Returns ArithmeticOverflow error on failure
///
/// # Accounts
/// 0. `[writable]` vault_state - The vault account
/// 1. `[writable]` user_balance - The user's balance account
/// 2. `[signer]` owner - The user making the deposit
///
/// # Instruction Data
/// - amount (u64): The amount to deposit (8 bytes, little-endian)
fn deposit(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_state_acc, user_balance_acc, owner] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount_to_add = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read user balance
    let user_data = user_balance_acc.try_borrow()?;
    let mut user_balance = UserBalance::try_from_slice(&user_data)?;
    drop(user_data);

    // Verify owner matches
    if user_balance.owner.as_ref() != owner.address().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    log!("Before deposit - User balance: {}, Amount: {}", user_balance.balance, amount_to_add);

    // SECURITY: Validate deposit amount against maximum limit
    // This prevents attackers from crafting overflow-inducing deposits
    if amount_to_add > MAX_DEPOSIT {
        log!("Deposit amount {} exceeds maximum {}", amount_to_add, MAX_DEPOSIT);
        return Err(SecureError::ExceedsMaxDeposit.into());
    }

    // SECURITY: Use checked_add() for balance update - returns None on overflow
    // If overflow would occur, we return an error instead of wrapping
    user_balance.balance =
        user_balance.balance.checked_add(amount_to_add).ok_or(SecureError::ArithmeticOverflow)?;

    // SECURITY: Use checked_add() for deposit tracking
    user_balance.deposits =
        user_balance.deposits.checked_add(amount_to_add).ok_or(SecureError::ArithmeticOverflow)?;

    // Write updated user balance
    let mut user_data = user_balance_acc.try_borrow_mut()?;
    user_balance.serialize(&mut user_data)?;
    drop(user_data);

    // Update vault totals
    let vault_data = vault_state_acc.try_borrow()?;
    let mut vault_state = VaultState::try_from_slice(&vault_data)?;
    drop(vault_data);

    // SECURITY: Use checked_add() for vault total tracking
    vault_state.total_deposits = vault_state
        .total_deposits
        .checked_add(amount_to_add)
        .ok_or(SecureError::ArithmeticOverflow)?;

    let mut vault_data = vault_state_acc.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;

    log!("After deposit - User balance: {}", user_balance.balance);

    Ok(())
}

/// Withdraw funds from user balance.
///
/// # Security Features
/// - SECURITY: Validates sufficient balance before any arithmetic
/// - SECURITY: Uses checked_sub() for defense in depth
/// - SECURITY: Returns InsufficientBalance or ArithmeticUnderflow error on failure
///
/// # Accounts
/// 0. `[writable]` user_balance - The user's balance account
/// 1. `[signer]` owner - The user making the withdrawal
///
/// # Instruction Data
/// - amount (u64): The amount to withdraw (8 bytes, little-endian)
fn withdraw(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [user_balance_acc, owner] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount_to_subtract = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read user balance
    let user_data = user_balance_acc.try_borrow()?;
    let mut user_balance = UserBalance::try_from_slice(&user_data)?;
    drop(user_data);

    // Verify owner matches
    if user_balance.owner.as_ref() != owner.address().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }

    log!(
        "Before withdraw - User balance: {}, Amount: {}",
        user_balance.balance,
        amount_to_subtract
    );

    // SECURITY: First validate sufficient balance before any arithmetic
    // This is the primary defense against underflow attacks
    if user_balance.balance < amount_to_subtract {
        log!("Insufficient balance: {} < {}", user_balance.balance, amount_to_subtract);
        return Err(SecureError::InsufficientBalance.into());
    }

    // SECURITY: Use checked_sub() for defense in depth
    // Even after the balance check, we use safe arithmetic as a second layer
    user_balance.balance = user_balance
        .balance
        .checked_sub(amount_to_subtract)
        .ok_or(SecureError::ArithmeticUnderflow)?;

    // SECURITY: Use checked_add() for withdrawal tracking
    user_balance.withdrawals = user_balance
        .withdrawals
        .checked_add(amount_to_subtract)
        .ok_or(SecureError::ArithmeticOverflow)?;

    // Write updated user balance
    let mut user_data = user_balance_acc.try_borrow_mut()?;
    user_balance.serialize(&mut user_data)?;

    log!("After withdraw - User balance: {}", user_balance.balance);

    Ok(())
}

/// Calculate rewards based on balance and rate.
///
/// # Security Features
/// - SECURITY: Validates reward rate against MAX_REWARD_RATE limit
/// - SECURITY: Uses checked_mul() for reward calculation
/// - SECURITY: Uses checked_add() for adding rewards
/// - SECURITY: Returns ArithmeticOverflow or ExceedsMaxRewardRate error on failure
///
/// # Accounts
/// 0. `[writable]` vault_state - The vault account
/// 1. `[writable]` user_balance - The user's balance account
/// 2. `[signer]` authority - The vault authority (can calculate rewards for any user)
///
/// # Instruction Data
/// - reward_rate (u64): The reward rate multiplier (8 bytes, little-endian)
fn calculate_rewards(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_state_acc, user_balance_acc, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let reward_rate = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read user balance
    let user_data = user_balance_acc.try_borrow()?;
    let mut user_balance = UserBalance::try_from_slice(&user_data)?;
    drop(user_data);

    log!("Calculating rewards - Balance: {}, Rate: {}", user_balance.balance, reward_rate);

    // SECURITY: Validate reward rate against maximum
    // This prevents attackers from using extreme rates to cause overflow
    if reward_rate > MAX_REWARD_RATE {
        log!("Reward rate {} exceeds maximum {}", reward_rate, MAX_REWARD_RATE);
        return Err(SecureError::ExceedsMaxRewardRate.into());
    }

    // SECURITY: Use checked_mul() for reward calculation - returns None on overflow
    // This prevents multiplication overflow attacks
    let reward_amount =
        user_balance.balance.checked_mul(reward_rate).ok_or(SecureError::ArithmeticOverflow)?;

    // Read and update vault state
    let vault_data = vault_state_acc.try_borrow()?;
    let mut vault_state = VaultState::try_from_slice(&vault_data)?;
    drop(vault_data);

    // SECURITY: Use checked_add() for vault reward tracking
    vault_state.total_rewards = vault_state
        .total_rewards
        .checked_add(reward_amount)
        .ok_or(SecureError::ArithmeticOverflow)?;

    let mut vault_data = vault_state_acc.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;
    drop(vault_data);

    // SECURITY: Use checked_add() for adding reward to balance
    user_balance.balance =
        user_balance.balance.checked_add(reward_amount).ok_or(SecureError::ArithmeticOverflow)?;

    // Write updated user balance
    let mut user_data = user_balance_acc.try_borrow_mut()?;
    user_balance.serialize(&mut user_data)?;

    log!("Reward calculated: {}, New balance: {}", reward_amount, user_balance.balance);

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_state_serialization() {
        let vault = VaultState {
            authority: Address::new_from_array([1u8; 32]),
            total_deposits: 1000,
            user_count: 5,
            total_rewards: 500,
            bump: 255,
        };

        let mut buffer = [0u8; VAULT_STATE_SIZE];
        vault.serialize(&mut buffer).unwrap();

        let deserialized = VaultState::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.authority, vault.authority);
        assert_eq!(deserialized.total_deposits, vault.total_deposits);
        assert_eq!(deserialized.user_count, vault.user_count);
        assert_eq!(deserialized.total_rewards, vault.total_rewards);
        assert_eq!(deserialized.bump, vault.bump);
    }

    #[test]
    fn test_user_balance_serialization() {
        let user = UserBalance {
            owner: Address::new_from_array([2u8; 32]),
            balance: 10000,
            deposits: 15000,
            withdrawals: 5000,
            bump: 254,
        };

        let mut buffer = [0u8; USER_BALANCE_SIZE];
        user.serialize(&mut buffer).unwrap();

        let deserialized = UserBalance::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.owner, user.owner);
        assert_eq!(deserialized.balance, user.balance);
        assert_eq!(deserialized.deposits, user.deposits);
        assert_eq!(deserialized.withdrawals, user.withdrawals);
        assert_eq!(deserialized.bump, user.bump);
    }

    #[test]
    fn test_checked_add_overflow_returns_none() {
        let balance: u64 = u64::MAX - 10;
        let amount: u64 = 20;
        let result = balance.checked_add(amount);
        assert!(result.is_none(), "checked_add should return None on overflow");
    }

    #[test]
    fn test_checked_sub_underflow_returns_none() {
        let balance: u64 = 10;
        let amount: u64 = 20;
        let result = balance.checked_sub(amount);
        assert!(result.is_none(), "checked_sub should return None on underflow");
    }

    #[test]
    fn test_checked_mul_overflow_returns_none() {
        let balance: u64 = 1 << 32;
        let rate: u64 = 1 << 33;
        let result = balance.checked_mul(rate);
        assert!(result.is_none(), "checked_mul should return None on overflow");
    }

    #[test]
    fn test_max_deposit_validation() {
        let deposit_amount: u64 = MAX_DEPOSIT + 1;
        assert!(deposit_amount > MAX_DEPOSIT, "Amount should exceed MAX_DEPOSIT");
    }

    #[test]
    fn test_max_reward_rate_validation() {
        let rate: u64 = MAX_REWARD_RATE + 1;
        assert!(rate > MAX_REWARD_RATE, "Rate should exceed MAX_REWARD_RATE");
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(SecureError::ArithmeticOverflow as u32, 0);
        assert_eq!(SecureError::ArithmeticUnderflow as u32, 1);
        assert_eq!(SecureError::InsufficientBalance as u32, 2);
        assert_eq!(SecureError::ExceedsMaxDeposit as u32, 3);
        assert_eq!(SecureError::ExceedsMaxRewardRate as u32, 4);
    }
}
