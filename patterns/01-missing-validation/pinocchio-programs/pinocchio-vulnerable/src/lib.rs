//! # Pinocchio Vulnerable Missing Validation Program
//!
//! ⚠️ **WARNING: This program contains INTENTIONAL security vulnerabilities for educational purposes.**
//!
//! This is the Pinocchio equivalent of the Anchor vulnerable program, demonstrating
//! how missing validation vulnerabilities manifest in a lower-level Solana framework.
//!
//! ## Key Differences from Anchor
//! - No declarative account constraints (`#[account(mut, has_one = authority)]`)
//! - No type-based signer enforcement (`Signer<'info>`)
//! - All validation must be done explicitly (and is deliberately omitted here)
//!
//! ## Vulnerabilities Demonstrated
//! - Missing signer validation on authority account
//! - Missing ownership validation (authority not checked)
//! - No verification that signer matches stored authority
//!
//! **DO NOT deploy this program to mainnet or use in production.**

#![allow(unexpected_cfgs)]

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID generated from keypair: FTu4tEsgTb1WJPdvxHYFULT7ocvfDpjSsBcFJu6VqYpR
pub const ID: Address = Address::new_from_array([
    0xd6, 0xe7, 0x97, 0x1d, 0xdd, 0x87, 0xb8, 0x9d, 0x7e, 0x82, 0x28, 0x1b, 0x6e, 0xef, 0xb4, 0x26,
    0x50, 0xcd, 0x80, 0x2c, 0x5f, 0xc3, 0x0f, 0x57, 0xb1, 0xf3, 0x7f, 0xe4, 0xfc, 0xfa, 0xde, 0xfa,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Size of UserAccount in bytes (no Anchor discriminator):
/// - authority (Address): 32 bytes
/// - balance (u64): 8 bytes
/// - is_initialized (bool): 1 byte
/// - bump (u8): 1 byte
///
/// Total: 42 bytes
pub const USER_ACCOUNT_SIZE: usize = 32 + 8 + 1 + 1;

/// Seed prefix for user account PDA derivation
pub const USER_ACCOUNT_SEED: &[u8] = b"user_account";

/// Instruction discriminator for initialize
pub const INITIALIZE_DISCRIMINATOR: u8 = 0;

/// Instruction discriminator for update_balance
pub const UPDATE_BALANCE_DISCRIMINATOR: u8 = 1;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// User account storing balance and ownership information.
///
/// This struct is identical to the Anchor version but uses manual serialization.
/// In Pinocchio, there's no Anchor discriminator (8 bytes saved).
pub struct UserAccount {
    /// The public key of the user who owns this account.
    /// This field SHOULD be checked on every modification, but the vulnerable
    /// program deliberately skips this check.
    pub authority: Address,

    /// Balance value that can be modified by instructions.
    pub balance: u64,

    /// Flag indicating whether the account has been initialized.
    pub is_initialized: bool,

    /// PDA bump seed for account derivation.
    pub bump: u8,
}

impl UserAccount {
    /// Deserialize UserAccount from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < USER_ACCOUNT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        // Parse authority (32 bytes)
        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse balance (8 bytes, little-endian)
        let balance = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse is_initialized (1 byte)
        let is_initialized = data[40] != 0;

        // Parse bump (1 byte)
        let bump = data[41];

        Ok(Self { authority, balance, is_initialized, bump })
    }

    /// Serialize UserAccount into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_ACCOUNT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write authority (32 bytes)
        data[0..32].copy_from_slice(self.authority.as_ref());

        // Write balance (8 bytes, little-endian)
        data[32..40].copy_from_slice(&self.balance.to_le_bytes());

        // Write is_initialized (1 byte)
        data[40] = self.is_initialized as u8;

        // Write bump (1 byte)
        data[41] = self.bump;

        Ok(())
    }
}

// =============================================================================
// ENTRYPOINT
// =============================================================================

entrypoint!(process_instruction);

/// Main entrypoint for the Pinocchio program.
///
/// Unlike Anchor's `#[program]` macro, Pinocchio requires manual instruction routing.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    // Parse instruction discriminator (first byte)
    let (discriminator, data) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        INITIALIZE_DISCRIMINATOR => initialize(program_id, accounts, data),
        UPDATE_BALANCE_DISCRIMINATOR => update_balance(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initializes a user account by writing initial data.
///
/// Note: In this simplified version, the account must be pre-created by the test harness.
/// This focuses the demonstration on the validation vulnerability rather than account creation.
///
/// # Accounts
/// 0. `[writable]` user_account - The account to initialize (must be pre-allocated)
/// 1. `[signer]` authority - The user who will own this account
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed (1 byte)
///
/// # Security Note
/// // SECURITY: This instruction is safe because:
/// // - Authority must sign (verified here)
/// // - Sets up account ownership correctly
fn initialize(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Account parsing
    let [user_account, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify authority is a signer (required for initialization)
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !user_account.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Parse bump from instruction data
    let bump = if data.is_empty() { 0 } else { data[0] };

    // Initialize account data
    let user_data = UserAccount {
        authority: Address::new_from_array(*authority.address().as_array()),
        balance: 0,
        is_initialized: true,
        bump,
    };

    // Write data to the account
    let mut account_data = user_account.try_borrow_mut()?;
    user_data.serialize(&mut account_data)?;

    log!("Account initialized for authority");
    log!("Initial balance: 0");

    Ok(())
}

/// Updates the balance of a user account.
///
/// # ⚠️ VULNERABILITY WARNING
/// This instruction is INTENTIONALLY VULNERABLE and demonstrates what happens
/// when proper validation is omitted in Pinocchio programs.
///
/// # Accounts
/// 0. `[writable]` user_account - The account to modify
/// 1. `[]` authority - The supposed authority (NOT validated!)
///
/// # Instruction Data
/// - new_balance (u64): The new balance to set (8 bytes, little-endian)
///
/// # Vulnerabilities
/// // VULNERABILITY: No signer validation - authority doesn't need to sign
/// // VULNERABILITY: No ownership validation - authority not checked against stored value
/// // VULNERABILITY: Account owner not verified as this program
fn update_balance(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Account parsing
    let [user_account, _authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse new_balance from instruction data (u64 = 8 bytes)
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_balance = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // VULNERABILITY: No signer validation - anyone can call this
    // In a secure program, we would verify: authority.is_signer()

    // VULNERABILITY: No owner validation - any account accepted
    // In a secure program, we would verify: user_account.owned_by(program_id)

    // VULNERABILITY: Authority field not checked against signer
    // In a secure program, we would verify:
    // user_data.authority == *authority.address()

    // Read current data
    let account_data = user_account.try_borrow()?;
    let mut user_data = UserAccount::try_from_slice(&account_data)?;
    let old_balance = user_data.balance;
    drop(account_data);

    // Directly set the new balance without any authorization checks
    user_data.balance = new_balance;

    // Write updated data
    let mut account_data = user_account.try_borrow_mut()?;
    user_data.serialize(&mut account_data)?;

    log!("Balance updated from {} to {}", old_balance, new_balance);
    log!("WARNING: No authorization check performed!");

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_account_serialization() {
        let account = UserAccount {
            authority: Address::new_from_array([1u8; 32]),
            balance: 12345,
            is_initialized: true,
            bump: 255,
        };

        let mut buffer = [0u8; USER_ACCOUNT_SIZE];
        account.serialize(&mut buffer).unwrap();

        let deserialized = UserAccount::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.authority, account.authority);
        assert_eq!(deserialized.balance, account.balance);
        assert_eq!(deserialized.is_initialized, account.is_initialized);
        assert_eq!(deserialized.bump, account.bump);
    }
}
