//! # Pinocchio Vulnerable Unsafe Arithmetic Program
//!
//! This program demonstrates **INSECURE** arithmetic patterns in Solana using Pinocchio.
//! It is designed for educational purposes to show how integer overflow/underflow
//! vulnerabilities occur when proper safe math is not used.
//!
//! ## Key Differences from Anchor
//! - No `#[error_code]` macro - must define custom error types manually
//! - No `require!()` macro - must write explicit if-checks
//! - No automatic discriminators - must handle instruction routing manually
//!
//! ## Vulnerabilities Demonstrated
//! - `wrapping_add()` for silent overflow in deposits
//! - `wrapping_sub()` for silent underflow in withdrawals
//! - `wrapping_mul()` for silent overflow in reward calculations
//!
//! **DO NOT USE THIS CODE IN PRODUCTION!**

#![allow(unexpected_cfgs)]

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID: 4R677cX6tV6G5YeWMw1ndtPpDzvD4zrdz6HbNYWF9oQi
pub const ID: Address = Address::new_from_array([
    0x3b, 0x4a, 0x1b, 0x42, 0x70, 0x9b, 0x6e, 0x86, 0x85, 0xa1, 0x74, 0xd4, 0xa3, 0x99, 0x81, 0xed,
    0x78, 0x6f, 0xde, 0xd0, 0x7c, 0xee, 0xcb, 0x18, 0x3f, 0xbe, 0x49, 0x60, 0x46, 0x48, 0x76, 0x06,
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

// =============================================================================
// INSTRUCTION DISCRIMINATORS
// =============================================================================

pub const INITIALIZE_VAULT_DISCRIMINATOR: u8 = 0;
pub const CREATE_USER_DISCRIMINATOR: u8 = 1;
pub const DEPOSIT_DISCRIMINATOR: u8 = 2;
pub const WITHDRAW_DISCRIMINATOR: u8 = 3;
pub const CALCULATE_REWARDS_DISCRIMINATOR: u8 = 4;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Vault state account - tracks global vault information.
///
/// This struct is identical to the Anchor version but uses manual serialization.
/// In Pinocchio, there's no Anchor discriminator (8 bytes saved).
pub struct VaultState {
    /// Authority who controls the vault (32 bytes)
    pub authority: Address,
    /// Total SOL deposited across all users (8 bytes) - ARITHMETIC VULNERABILITY TARGET
    pub total_deposits: u64,
    /// Number of users registered (8 bytes)
    pub user_count: u64,
    /// Accumulated rewards distributed (8 bytes) - ARITHMETIC VULNERABILITY TARGET
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

        // Parse authority (32 bytes at offset 0)
        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse total_deposits (8 bytes at offset 32)
        let total_deposits = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse user_count (8 bytes at offset 40)
        let user_count = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse total_rewards (8 bytes at offset 48)
        let total_rewards = u64::from_le_bytes(
            data[48..56].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse bump (1 byte at offset 56)
        let bump = data[56];

        Ok(Self { authority, total_deposits, user_count, total_rewards, bump })
    }

    /// Serialize VaultState into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < VAULT_STATE_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write authority (32 bytes at offset 0)
        data[0..32].copy_from_slice(self.authority.as_ref());

        // Write total_deposits (8 bytes at offset 32)
        data[32..40].copy_from_slice(&self.total_deposits.to_le_bytes());

        // Write user_count (8 bytes at offset 40)
        data[40..48].copy_from_slice(&self.user_count.to_le_bytes());

        // Write total_rewards (8 bytes at offset 48)
        data[48..56].copy_from_slice(&self.total_rewards.to_le_bytes());

        // Write bump (1 byte at offset 56)
        data[56] = self.bump;

        Ok(())
    }
}

/// User balance account - tracks individual user's balance.
pub struct UserBalance {
    /// User who owns this balance (32 bytes)
    pub owner: Address,
    /// User's current balance (8 bytes) - ARITHMETIC VULNERABILITY TARGET
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

        // Parse owner (32 bytes at offset 0)
        let owner = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse balance (8 bytes at offset 32)
        let balance = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse deposits (8 bytes at offset 40)
        let deposits = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse withdrawals (8 bytes at offset 48)
        let withdrawals = u64::from_le_bytes(
            data[48..56].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse bump (1 byte at offset 56)
        let bump = data[56];

        Ok(Self { owner, balance, deposits, withdrawals, bump })
    }

    /// Serialize UserBalance into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_BALANCE_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write owner (32 bytes at offset 0)
        data[0..32].copy_from_slice(self.owner.as_ref());

        // Write balance (8 bytes at offset 32)
        data[32..40].copy_from_slice(&self.balance.to_le_bytes());

        // Write deposits (8 bytes at offset 40)
        data[40..48].copy_from_slice(&self.deposits.to_le_bytes());

        // Write withdrawals (8 bytes at offset 48)
        data[48..56].copy_from_slice(&self.withdrawals.to_le_bytes());

        // Write bump (1 byte at offset 56)
        data[56] = self.bump;

        Ok(())
    }
}

// =============================================================================
// ENTRYPOINT
// =============================================================================

entrypoint!(process_instruction);

/// Main entrypoint for the Pinocchio vulnerable unsafe arithmetic program.
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
/// This instruction is SECURE - same implementation as secure program.
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

    // Verify authority is a signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify vault account is owned by this program
    if !vault_state_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Parse bump from instruction data
    let bump = if data.is_empty() { 0 } else { data[0] };

    // Initialize vault state
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
/// This instruction is SECURE - same implementation as secure program.
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

    // Verify owner is a signer
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify accounts are owned by this program
    if !vault_state_acc.owned_by(program_id) || !user_balance_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Parse bump from instruction data
    let bump = if data.is_empty() { 0 } else { data[0] };

    // Read and update vault state
    let vault_data = vault_state_acc.try_borrow()?;
    let mut vault_state = VaultState::try_from_slice(&vault_data)?;
    drop(vault_data);

    vault_state.user_count += 1;

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
/// # VULNERABILITIES
///
/// This instruction is **CRITICALLY INSECURE** because:
///
/// // VULNERABILITY: Uses wrapping_add() - will wrap on overflow!
/// // VULNERABILITY: No maximum deposit limit check
///
/// An attacker can deposit a large amount that causes the balance to overflow
/// and wrap around to a small value, or craft deposits to reach a specific target value.
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

    // Verify owner is a signer
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse amount from instruction data
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

    // VULNERABILITY: Uses wrapping addition - will wrap on overflow!
    // If balance = u64::MAX - 10 and amount_to_add = 20, result = 9 (wraparound)
    // This allows an attacker to reduce their balance to a small value
    // while appearing to have deposited a large amount.
    user_balance.balance = user_balance.balance.wrapping_add(amount_to_add);

    // VULNERABILITY: No maximum deposit limit check
    // An attacker can deposit any amount, including values designed to cause overflow
    user_balance.deposits = user_balance.deposits.wrapping_add(amount_to_add);

    // Write updated user balance
    let mut user_data = user_balance_acc.try_borrow_mut()?;
    user_balance.serialize(&mut user_data)?;
    drop(user_data);

    // Update vault totals
    let vault_data = vault_state_acc.try_borrow()?;
    let mut vault_state = VaultState::try_from_slice(&vault_data)?;
    drop(vault_data);

    // VULNERABILITY: Vault total also vulnerable to overflow
    vault_state.total_deposits = vault_state.total_deposits.wrapping_add(amount_to_add);

    let mut vault_data = vault_state_acc.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;

    log!("After deposit - User balance: {}", user_balance.balance);

    Ok(())
}

/// Withdraw funds from user balance.
///
/// # VULNERABILITIES
///
/// This instruction is **CRITICALLY INSECURE** because:
///
/// // VULNERABILITY: Uses wrapping_sub() - will wrap on underflow!
/// // VULNERABILITY: No check that balance >= withdrawal amount
///
/// An attacker can withdraw more than their balance, causing the balance to underflow
/// and wrap around to a huge value (close to u64::MAX).
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

    // Verify owner is a signer
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse amount from instruction data
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

    // VULNERABILITY: Uses wrapping subtraction - will wrap on underflow!
    // If balance = 10 and amount_to_subtract = 20, result = u64::MAX - 9 (huge value!)
    // This allows an attacker to gain a massive balance from a small deposit
    user_balance.balance = user_balance.balance.wrapping_sub(amount_to_subtract);

    // VULNERABILITY: No check that balance >= withdrawal amount
    // The subtraction above will silently underflow and wrap around
    user_balance.withdrawals = user_balance.withdrawals.wrapping_add(amount_to_subtract);

    // Write updated user balance
    let mut user_data = user_balance_acc.try_borrow_mut()?;
    user_balance.serialize(&mut user_data)?;

    log!("After withdraw - User balance: {}", user_balance.balance);

    Ok(())
}

/// Calculate rewards based on balance and rate.
///
/// # VULNERABILITIES
///
/// This instruction is **CRITICALLY INSECURE** because:
///
/// // VULNERABILITY: Uses wrapping_mul() - will wrap on overflow!
/// // VULNERABILITY: No check for multiplication overflow
/// // VULNERABILITY: No maximum reward rate limit
///
/// An attacker can use extreme reward rates that cause multiplication overflow,
/// resulting in incorrect (and exploitable) reward amounts.
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

    // Verify authority is a signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse reward_rate from instruction data
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

    // VULNERABILITY: Uses wrapping multiplication - will wrap on overflow!
    // If balance = 2^32 and reward_rate = 2^33, result wraps to incorrect value
    // This can result in attackers receiving far more or less rewards than expected
    let reward_amount = user_balance.balance.wrapping_mul(reward_rate);

    // Read and update vault state
    let vault_data = vault_state_acc.try_borrow()?;
    let mut vault_state = VaultState::try_from_slice(&vault_data)?;
    drop(vault_data);

    // VULNERABILITY: No check for multiplication overflow before adding
    vault_state.total_rewards = vault_state.total_rewards.wrapping_add(reward_amount);

    let mut vault_data = vault_state_acc.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;
    drop(vault_data);

    // VULNERABILITY: Adding wrapping reward to balance
    user_balance.balance = user_balance.balance.wrapping_add(reward_amount);

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
    fn test_wrapping_add_overflow() {
        // Demonstrate wrapping_add vulnerability
        let balance: u64 = u64::MAX - 10;
        let amount: u64 = 20;
        let result = balance.wrapping_add(amount);
        // u64::MAX - 10 + 20 = u64::MAX + 10 wraps to 9
        assert_eq!(result, 9);
    }

    #[test]
    fn test_wrapping_sub_underflow() {
        // Demonstrate wrapping_sub vulnerability
        let balance: u64 = 10;
        let amount: u64 = 20;
        let result = balance.wrapping_sub(amount);
        // 10 - 20 = -10 wraps to u64::MAX - 9
        assert_eq!(result, u64::MAX - 9);
    }

    #[test]
    fn test_wrapping_mul_overflow() {
        // Demonstrate wrapping_mul vulnerability
        let balance: u64 = 1 << 32; // 2^32
        let rate: u64 = 1 << 33; // 2^33
        let result = balance.wrapping_mul(rate);
        // 2^32 * 2^33 = 2^65 wraps to 0 (since 2^65 mod 2^64 = 0)
        assert_eq!(result, 0);
    }
}
