//! # Pinocchio Secure CPI Re-entrancy Program
//!
//! This program demonstrates the CORRECT pattern for handling CPI calls that
//! protects against re-entrancy attacks using two defensive strategies:
//!
//! 1. **Checks-Effects-Interactions Pattern**: Update state BEFORE making CPI calls
//! 2. **Re-entrancy Guard**: Boolean flag that prevents recursive calls
//!
//! This is safe for production use (pattern demonstration).

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

/// Program ID: Du8vRGWEyC5bjXDnjVNHK3JZdHUhmJqu4bbt4tWwrPQD
pub const ID: Address = Address::new_from_array([
    0xbf, 0xa7, 0x66, 0xc8, 0xa7, 0x22, 0x1e, 0x06, 0x87, 0x54, 0xa6, 0x12, 0x17, 0x27, 0xa5, 0xa9,
    0xf0, 0x95, 0x95, 0x2b, 0x10, 0x05, 0xe4, 0x03, 0xa3, 0x29, 0x8c, 0xa9, 0x6a, 0xdf, 0x41, 0xc2,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Vault account size (secure version with re-entrancy guard)
pub const VAULT_SIZE: usize = 32 + 8 + 8 + 1 + 1; // 50 bytes

/// UserDeposit account size
pub const USER_DEPOSIT_SIZE: usize = 32 + 8 + 1; // 41 bytes

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

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum SecureError {
    Unauthorized = 6000,
    ArithmeticOverflow = 6001,
    InsufficientBalance = 6002,
    InsufficientUserBalance = 6003,
    ReentrancyDetected = 6005,
}

impl From<SecureError> for ProgramError {
    fn from(e: SecureError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Vault account WITH re-entrancy guard (secure version)
pub struct Vault {
    pub authority: Address,
    pub balance: u64,
    pub withdrawals_pending: u64,
    pub reentrancy_guard: bool,
    pub bump: u8,
}

impl Vault {
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let balance = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let withdrawals_pending = u64::from_le_bytes(
            data[40..48].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let reentrancy_guard = data[48] != 0;
        let bump = data[49];

        Ok(Self { authority, balance, withdrawals_pending, reentrancy_guard, bump })
    }

    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.authority.as_ref());
        data[32..40].copy_from_slice(&self.balance.to_le_bytes());
        data[40..48].copy_from_slice(&self.withdrawals_pending.to_le_bytes());
        data[48] = if self.reentrancy_guard { 1 } else { 0 };
        data[49] = self.bump;

        Ok(())
    }
}

/// User deposit tracking account
pub struct UserDeposit {
    pub owner: Address,
    pub amount: u64,
    pub bump: u8,
}

impl UserDeposit {
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let owner = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let amount = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let bump = data[40];

        Ok(Self { owner, amount, bump })
    }

    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.owner.as_ref());
        data[32..40].copy_from_slice(&self.amount.to_le_bytes());
        data[40] = self.bump;

        Ok(())
    }
}

// =============================================================================
// ENTRYPOINT
// =============================================================================

entrypoint!(process_instruction);

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
        CALLBACK_TARGET_DISCRIMINATOR => callback_target(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

fn initialize_vault(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acc, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let bump = if data.is_empty() { 0 } else { data[0] };

    let vault = Vault {
        authority: Address::new_from_array(*authority.address().as_array()),
        balance: 0,
        withdrawals_pending: 0,
        reentrancy_guard: false,
        bump,
    };

    let mut account_data = vault_acc.try_borrow_mut()?;
    vault.serialize(&mut account_data)?;

    log!("// SECURITY: Vault initialized with re-entrancy protection");

    Ok(())
}

fn deposit(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acc, user_deposit_acc, depositor] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !vault_acc.owned_by(program_id) || !user_deposit_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    let bump = if data.len() > 8 { data[8] } else { 0 };

    let vault_data = vault_acc.try_borrow()?;
    let mut vault = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    vault.balance = vault.balance.checked_add(amount).ok_or(SecureError::ArithmeticOverflow)?;

    let mut vault_data = vault_acc.try_borrow_mut()?;
    vault.serialize(&mut vault_data)?;
    drop(vault_data);

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

    user_deposit.owner = Address::new_from_array(*depositor.address().as_array());
    user_deposit.amount =
        user_deposit.amount.checked_add(amount).ok_or(SecureError::ArithmeticOverflow)?;
    if bump != 0 {
        user_deposit.bump = bump;
    }

    let mut user_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut user_data)?;

    log!("// SECURITY: Deposited {} to vault. New balance: {}", amount, vault.balance);

    Ok(())
}

/// SECURE: Withdraw funds with re-entrancy protection.
fn withdraw(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acc, user_deposit_acc, authority, callback_program, secure_program, attack_state] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    let vault_data = vault_acc.try_borrow()?;
    let mut vault = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    // SECURITY: Step 1 - Check re-entrancy guard FIRST
    if vault.reentrancy_guard {
        log!("// SECURITY: Re-entrancy detected! Blocking re-entry attempt.");
        return Err(SecureError::ReentrancyDetected.into());
    }

    log!("// SECURITY: Re-entrancy guard check passed");

    // SECURITY: Step 2 - Set re-entrancy guard IMMEDIATELY
    vault.reentrancy_guard = true;

    log!("// SECURITY: Re-entrancy guard SET");

    // SECURITY: Step 3 - Perform balance checks
    if vault.balance < amount {
        vault.reentrancy_guard = false;
        let mut vault_data = vault_acc.try_borrow_mut()?;
        vault.serialize(&mut vault_data)?;
        return Err(SecureError::InsufficientBalance.into());
    }

    let user_data = user_deposit_acc.try_borrow()?;
    let mut user_deposit = UserDeposit::try_from_slice(&user_data)?;
    drop(user_data);

    if user_deposit.amount < amount {
        vault.reentrancy_guard = false;
        let mut vault_data = vault_acc.try_borrow_mut()?;
        vault.serialize(&mut vault_data)?;
        return Err(SecureError::InsufficientUserBalance.into());
    }

    if user_deposit.owner.as_ref() != authority.address().as_ref() {
        vault.reentrancy_guard = false;
        let mut vault_data = vault_acc.try_borrow_mut()?;
        vault.serialize(&mut vault_data)?;
        return Err(SecureError::Unauthorized.into());
    }

    log!("// SECURITY: Balance checks passed. Current balance: {}", vault.balance);

    // SECURITY: Step 4 - Update state BEFORE CPI (Effects before Interactions)
    vault.balance = vault.balance.checked_sub(amount).ok_or(SecureError::InsufficientBalance)?;
    user_deposit.amount =
        user_deposit.amount.checked_sub(amount).ok_or(SecureError::InsufficientUserBalance)?;

    let mut vault_data = vault_acc.try_borrow_mut()?;
    vault.serialize(&mut vault_data)?;
    drop(vault_data);

    let mut user_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut user_data)?;
    drop(user_data);

    log!("// SECURITY: State updated BEFORE CPI. New balance: {}", vault.balance);

    // SECURITY: Step 5 - Make CPI AFTER state is updated
    let mut callback_data = [0u8; 9];
    callback_data[0] = 0;
    callback_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let ix_accounts = [
        InstructionAccount::writable(vault_acc.address()),
        InstructionAccount::writable(user_deposit_acc.address()),
        InstructionAccount::readonly_signer(authority.address()),
        InstructionAccount::readonly(secure_program.address()),
        InstructionAccount::writable(attack_state.address()),
        InstructionAccount::readonly(callback_program.address()),
    ];

    let callback_ix = InstructionView {
        program_id: callback_program.address(),
        accounts: &ix_accounts,
        data: &callback_data,
    };

    log!("// SECURITY: Making CPI with state already updated");

    invoke::<6>(
        &callback_ix,
        &[vault_acc, user_deposit_acc, authority, secure_program, attack_state, callback_program],
    )?;

    log!("// SECURITY: CPI completed, clearing re-entrancy guard");

    // SECURITY: Step 6 - Clear re-entrancy guard after CPI completes
    let vault_data = vault_acc.try_borrow()?;
    let mut vault = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    vault.reentrancy_guard = false;

    let mut vault_data = vault_acc.try_borrow_mut()?;
    vault.serialize(&mut vault_data)?;

    log!("// SECURITY: Re-entrancy guard CLEARED - withdrawal complete");

    Ok(())
}

fn callback_target(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault_acc, _authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    let vault_data = vault_acc.try_borrow()?;
    let vault = Vault::try_from_slice(&vault_data)?;

    log!("// SECURITY: Callback received, guard is: {}", vault.reentrancy_guard);
    log!("// SECURITY: Amount: {}", amount);

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
            reentrancy_guard: false,
            bump: 255,
        };

        let mut buffer = [0u8; VAULT_SIZE];
        vault.serialize(&mut buffer).unwrap();

        let deserialized = Vault::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.authority, vault.authority);
        assert_eq!(deserialized.balance, vault.balance);
        assert_eq!(deserialized.reentrancy_guard, vault.reentrancy_guard);
    }

    #[test]
    fn test_secure_error_codes() {
        assert_eq!(SecureError::Unauthorized as u32, 6000);
        assert_eq!(SecureError::ReentrancyDetected as u32, 6005);
    }
}
