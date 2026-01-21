//! # Pinocchio Vulnerable CPI Re-entrancy Program
//!
//! This program demonstrates a DANGEROUS pattern where state is updated AFTER a CPI call,
//! allowing malicious programs to exploit re-entrancy vulnerabilities.
//!
//! ## Key Differences from Anchor Version
//! - No `#[error_code]` macro - must define custom error types manually
//! - No `require!()` macro - must write explicit if-checks
//! - No `CpiContext` - uses manual `invoke()` with `InstructionView`
//! - No automatic discriminators - must handle instruction routing manually
//! - Manual serialization/deserialization of account data
//!
//! ## Vulnerability Pattern
//! The vulnerability: During withdrawal, the program makes a CPI to an external callback
//! program BEFORE updating its internal state. This allows the external program to
//! re-enter and withdraw again before the balance is decremented.
//!
//! **DO NOT USE THIS CODE IN PRODUCTION!**

#![allow(unexpected_cfgs)]

use pinocchio::{
    cpi::invoke,
    entrypoint,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID: ANpcyVKyc3Vz2U9aPwjLzsHvwzzuimiG5DThsPz6Qgsa
pub const ID: Address = Address::new_from_array([
    0x8b, 0x50, 0x39, 0x44, 0xbd, 0x2c, 0x9f, 0xda, 0x63, 0x63, 0x32, 0xcb, 0xd8, 0xa8, 0xdf, 0x0b,
    0xa1, 0x41, 0x26, 0xba, 0x38, 0xad, 0xcf, 0xa0, 0xe8, 0x54, 0x61, 0xfa, 0xc6, 0xb7, 0x59, 0xf9,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Vault account size (no Anchor discriminator):
/// - authority (Address): 32 bytes
/// - balance (u64): 8 bytes
/// - withdrawals_pending (u64): 8 bytes
/// - bump (u8): 1 byte
///
/// Total: 49 bytes
pub const VAULT_SIZE: usize = 32 + 8 + 8 + 1;

/// UserDeposit account size (no Anchor discriminator):
/// - owner (Address): 32 bytes
/// - amount (u64): 8 bytes
/// - bump (u8): 1 byte
///
/// Total: 41 bytes
pub const USER_DEPOSIT_SIZE: usize = 32 + 8 + 1;

/// Seed for vault PDA
pub const VAULT_SEED: &[u8] = b"vault";

/// Seed for user deposit PDA
pub const USER_SEED: &[u8] = b"user_deposit";

// =============================================================================
// INSTRUCTION DISCRIMINATORS
// =============================================================================

pub const INITIALIZE_VAULT_DISCRIMINATOR: u8 = 0;
pub const DEPOSIT_DISCRIMINATOR: u8 = 1;
pub const WITHDRAW_DISCRIMINATOR: u8 = 2;
pub const CALLBACK_TARGET_DISCRIMINATOR: u8 = 3;

// =============================================================================
// CUSTOM ERRORS
// =============================================================================

/// Custom error codes for the vulnerable vault program.
/// Note: In Pinocchio, we don't have Anchor's #[error_code] macro.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum VulnerableError {
    /// Arithmetic overflow detected
    ArithmeticOverflow = 6001,
    /// Insufficient vault balance for withdrawal
    InsufficientBalance = 6002,
    /// Insufficient user balance for withdrawal
    InsufficientUserBalance = 6003,
    /// Unauthorized: caller is not the vault authority
    Unauthorized = 6000,
}

impl From<VulnerableError> for ProgramError {
    fn from(e: VulnerableError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Vault account - NO re-entrancy guard (vulnerable version)
///
/// This struct mirrors the Anchor Vault but uses manual serialization.
/// In Pinocchio, there's no Anchor discriminator (8 bytes saved).
pub struct Vault {
    /// Vault owner/authority (32 bytes)
    pub authority: Address,
    /// Total vault balance - RE-ENTRANCY VULNERABILITY TARGET (8 bytes)
    pub balance: u64,
    /// Tracks withdrawals in progress (8 bytes)
    pub withdrawals_pending: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

impl Vault {
    /// Deserialize Vault from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        // Parse authority (32 bytes at offset 0)
        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse balance (8 bytes at offset 32)
        let balance = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse withdrawals_pending (8 bytes at offset 40)
        let withdrawals_pending = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse bump (1 byte at offset 48)
        let bump = data[48];

        Ok(Self { authority, balance, withdrawals_pending, bump })
    }

    /// Serialize Vault into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write authority (32 bytes at offset 0)
        data[0..32].copy_from_slice(self.authority.as_ref());

        // Write balance (8 bytes at offset 32)
        data[32..40].copy_from_slice(&self.balance.to_le_bytes());

        // Write withdrawals_pending (8 bytes at offset 40)
        data[40..48].copy_from_slice(&self.withdrawals_pending.to_le_bytes());

        // Write bump (1 byte at offset 48)
        data[48] = self.bump;

        Ok(())
    }
}

/// User deposit tracking account
pub struct UserDeposit {
    /// Depositor's public key (32 bytes)
    pub owner: Address,
    /// Amount deposited by this user (8 bytes)
    pub amount: u64,
    /// PDA bump seed (1 byte)
    pub bump: u8,
}

impl UserDeposit {
    /// Deserialize UserDeposit from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        // Parse owner (32 bytes at offset 0)
        let owner = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse amount (8 bytes at offset 32)
        let amount = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse bump (1 byte at offset 40)
        let bump = data[40];

        Ok(Self { owner, amount, bump })
    }

    /// Serialize UserDeposit into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write owner (32 bytes at offset 0)
        data[0..32].copy_from_slice(self.owner.as_ref());

        // Write amount (8 bytes at offset 32)
        data[32..40].copy_from_slice(&self.amount.to_le_bytes());

        // Write bump (1 byte at offset 40)
        data[40] = self.bump;

        Ok(())
    }
}

// =============================================================================
// ENTRYPOINT
// =============================================================================

entrypoint!(process_instruction);

/// Main entrypoint for the Pinocchio vulnerable CPI re-entrancy program.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, data) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        INITIALIZE_VAULT_DISCRIMINATOR => initialize_vault(program_id, accounts, data),
        DEPOSIT_DISCRIMINATOR => deposit(program_id, accounts, data),
        WITHDRAW_DISCRIMINATOR => withdraw(accounts, data),
        CALLBACK_TARGET_DISCRIMINATOR => callback_target(data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initialize a new vault with the given authority.
///
/// # Accounts
/// 0. `[writable]` vault - The vault account (must be pre-allocated)
/// 1. `[signer]` authority - The authority who controls the vault
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed
fn initialize_vault(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acc, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify vault account is owned by this program
    if !vault_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Parse bump from instruction data
    let bump = if data.is_empty() { 0 } else { data[0] };

    // Initialize vault state
    let vault = Vault {
        authority: Address::new_from_array(*authority.address().as_array()),
        balance: 0,
        withdrawals_pending: 0,
        bump,
    };

    let mut account_data = vault_acc.try_borrow_mut()?;
    vault.serialize(&mut account_data)?;

    log!("Vault initialized");

    Ok(())
}

/// Deposit funds into the vault.
///
/// # Accounts
/// 0. `[writable]` vault - The vault account
/// 1. `[writable]` user_deposit - The user deposit account (must be pre-allocated)
/// 2. `[signer]` depositor - The user making the deposit
///
/// # Instruction Data
/// - amount (u64): The amount to deposit (8 bytes, little-endian)
/// - bump (u8): The user deposit PDA bump seed (optional)
fn deposit(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acc, user_deposit_acc, depositor] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify depositor is a signer
    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify accounts are owned by this program
    if !vault_acc.owned_by(program_id) || !user_deposit_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Parse amount from instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Parse optional bump
    let bump = if data.len() > 8 { data[8] } else { 0 };

    // Read and update vault state
    let vault_data = vault_acc.try_borrow()?;
    let mut vault = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    vault.balance = vault.balance.checked_add(amount).ok_or(VulnerableError::ArithmeticOverflow)?;

    let mut vault_data = vault_acc.try_borrow_mut()?;
    vault.serialize(&mut vault_data)?;
    drop(vault_data);

    // Read user deposit (check if already initialized)
    let user_data = user_deposit_acc.try_borrow()?;
    let is_initialized = user_data.len() >= USER_DEPOSIT_SIZE && user_data[0..32] != [0u8; 32];

    let mut user_deposit = if is_initialized {
        UserDeposit::try_from_slice(&user_data)?
    } else {
        UserDeposit {
            owner: Address::new_from_array(*depositor.address().as_array()),
            amount: 0,
            bump,
        }
    };
    drop(user_data);

    // Update user deposit
    user_deposit.owner = Address::new_from_array(*depositor.address().as_array());
    user_deposit.amount =
        user_deposit.amount.checked_add(amount).ok_or(VulnerableError::ArithmeticOverflow)?;
    if bump != 0 {
        user_deposit.bump = bump;
    }

    let mut user_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut user_data)?;

    log!("Deposited {} to vault. New balance: {}", amount, vault.balance);

    Ok(())
}

/// VULNERABLE: Withdraw funds with callback to external program.
///
/// This instruction demonstrates the re-entrancy vulnerability:
/// 1. Reads current balance BEFORE CPI
/// 2. Makes CPI to external program
/// 3. Updates state AFTER CPI (too late!)
///
/// # Accounts
/// 0. `[writable]` vault - The vault account
/// 1. `[writable]` user_deposit - The user's deposit account
/// 2. `[signer]` authority - The withdrawal authority
/// 3. `[]` callback_program - External program to receive callback
/// 4. `[]` vulnerable_program - This program's ID (for CPI context)
/// 5. `[writable]` attack_state - Attack state account for re-entrancy tracking
///
/// # Instruction Data
/// - amount (u64): The amount to withdraw (8 bytes, little-endian)
fn withdraw(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acc, user_deposit_acc, authority, callback_program, vulnerable_program, attack_state] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is a signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse amount from instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // VULNERABILITY: Read state BEFORE CPI
    // An attacker can exploit this because the balance check uses pre-CPI state
    let vault_data = vault_acc.try_borrow()?;
    let vault = Vault::try_from_slice(&vault_data)?;
    let current_balance = vault.balance;
    drop(vault_data);

    let user_data = user_deposit_acc.try_borrow()?;
    let user_deposit = UserDeposit::try_from_slice(&user_data)?;
    let current_user_amount = user_deposit.amount;
    drop(user_data);

    log!("// VULNERABILITY: Reading balance BEFORE CPI: {}", current_balance);

    // VULNERABILITY: Check balance against pre-CPI state
    if current_balance < amount {
        return Err(VulnerableError::InsufficientBalance.into());
    }
    if current_user_amount < amount {
        return Err(VulnerableError::InsufficientUserBalance.into());
    }

    // Verify user owns this deposit
    if user_deposit.owner.as_ref() != authority.address().as_ref() {
        return Err(VulnerableError::Unauthorized.into());
    }

    log!("// VULNERABILITY: Balance check passed, making CPI to callback program");

    // VULNERABILITY: Make CPI BEFORE updating state
    // The external program can re-enter this function and withdraw again!

    // Build callback instruction data: discriminator (1 byte) + amount (8 bytes)
    let mut callback_data = [0u8; 9];
    callback_data[0] = 0; // receive_callback discriminator for attacker program
    callback_data[1..9].copy_from_slice(&amount.to_le_bytes());

    // Build instruction accounts using InstructionAccount
    let ix_accounts = [
        InstructionAccount::writable(vault_acc.address()),
        InstructionAccount::writable(user_deposit_acc.address()),
        InstructionAccount::readonly_signer(authority.address()),
        InstructionAccount::readonly(vulnerable_program.address()),
        InstructionAccount::writable(attack_state.address()),
        InstructionAccount::readonly(callback_program.address()),
    ];

    let callback_ix = InstructionView {
        program_id: callback_program.address(),
        accounts: &ix_accounts,
        data: &callback_data,
    };

    // VULNERABILITY: Invoke CPI - state not yet updated!
    invoke::<6>(
        &callback_ix,
        &[
            vault_acc,
            user_deposit_acc,
            authority,
            vulnerable_program,
            attack_state,
            callback_program,
        ],
    )?;

    log!("// VULNERABILITY: CPI returned, NOW updating state (too late!)");

    // VULNERABILITY: Update state AFTER CPI - attacker already re-entered!
    // At this point, if the attacker re-entered, they've already withdrawn
    // using the old balance value. This update is using stale data.
    let vault_data = vault_acc.try_borrow()?;
    let mut vault = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    vault.balance =
        current_balance.checked_sub(amount).ok_or(VulnerableError::InsufficientBalance)?;

    let mut vault_data = vault_acc.try_borrow_mut()?;
    vault.serialize(&mut vault_data)?;
    drop(vault_data);

    // Update user deposit
    let user_data = user_deposit_acc.try_borrow()?;
    let mut user_deposit = UserDeposit::try_from_slice(&user_data)?;
    drop(user_data);

    user_deposit.amount =
        current_user_amount.checked_sub(amount).ok_or(VulnerableError::InsufficientUserBalance)?;

    let mut user_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut user_data)?;

    log!("// VULNERABILITY: State updated AFTER CPI. New balance: {}", vault.balance);

    Ok(())
}

/// Callback target instruction for CPI entry point.
/// This is called by external programs and can be used to demonstrate callbacks.
///
/// # Instruction Data
/// - amount (u64): The callback amount (8 bytes, little-endian)
fn callback_target(data: &[u8]) -> ProgramResult {
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    log!("// VULNERABILITY: Callback received with amount: {}", amount);

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_serialization() {
        let vault = Vault {
            authority: Address::new_from_array([1u8; 32]),
            balance: 1000,
            withdrawals_pending: 0,
            bump: 255,
        };

        let mut buffer = [0u8; VAULT_SIZE];
        vault.serialize(&mut buffer).unwrap();

        let deserialized = Vault::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.authority, vault.authority);
        assert_eq!(deserialized.balance, vault.balance);
        assert_eq!(deserialized.withdrawals_pending, vault.withdrawals_pending);
        assert_eq!(deserialized.bump, vault.bump);
    }

    #[test]
    fn test_user_deposit_serialization() {
        let user =
            UserDeposit { owner: Address::new_from_array([2u8; 32]), amount: 500, bump: 254 };

        let mut buffer = [0u8; USER_DEPOSIT_SIZE];
        user.serialize(&mut buffer).unwrap();

        let deserialized = UserDeposit::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.owner, user.owner);
        assert_eq!(deserialized.amount, user.amount);
        assert_eq!(deserialized.bump, user.bump);
    }
}
