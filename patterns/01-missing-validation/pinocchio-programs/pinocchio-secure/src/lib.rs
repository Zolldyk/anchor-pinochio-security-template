//! # Pinocchio Secure Missing Validation Program
//!
//! **This program demonstrates PROPER account validation in Pinocchio.**
//!
//! This is the Pinocchio equivalent of the Anchor secure program, showing how
//! to implement proper validation manually when using a lower-level framework.
//!
//! ## Key Differences from Anchor
//! - No declarative constraints - all validation is explicit code
//! - No type-based signer enforcement - must check `is_signer()` manually
//! - No `has_one` constraint - must compare pubkeys explicitly
//!
//! ## Security Features Demonstrated
//! - Manual signer verification using `is_signer()` method
//! - Manual ownership validation comparing stored authority to signer
//! - Account ownership check using `owned_by()` method
//! - Initialization state check before operations
//!
//! **This program is safe for production use (as a reference pattern).**

#![allow(unexpected_cfgs)]

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID generated from keypair: ENZfh7vCvh9qvbKNQgWDvThLcmaR95qAfzuourgUCMqq
pub const ID: Address = Address::new_from_array([
    0xc6, 0xae, 0x10, 0x57, 0xc3, 0x53, 0xca, 0x9c, 0x6d, 0x8f, 0x94, 0xde, 0xd5, 0xdc, 0xf9, 0xc5,
    0x7a, 0xa8, 0x37, 0x51, 0x0f, 0x34, 0x9d, 0x85, 0x2b, 0x60, 0xb1, 0xcd, 0x05, 0xb2, 0xeb, 0xe8,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Size of UserAccount in bytes (no Anchor discriminator):
/// - authority (Address): 32 bytes
/// - balance (u64): 8 bytes
/// - is_initialized (bool): 1 byte
/// - bump (u8): 1 byte
/// Total: 42 bytes
pub const USER_ACCOUNT_SIZE: usize = 32 + 8 + 1 + 1;

/// Seed prefix for user account PDA derivation
pub const USER_ACCOUNT_SEED: &[u8] = b"user_account";

/// Instruction discriminator for initialize
pub const INITIALIZE_DISCRIMINATOR: u8 = 0;

/// Instruction discriminator for update_balance
pub const UPDATE_BALANCE_DISCRIMINATOR: u8 = 1;

// =============================================================================
// ERROR CODES
// =============================================================================

/// Custom error codes for the secure program.
///
/// // SECURITY: Unlike the vulnerable version, these errors ARE ACTIVELY USED
/// // to reject unauthorized operations and provide meaningful error messages.
#[repr(u32)]
pub enum SecureError {
    /// Returned when a signer is not authorized to perform the operation.
    /// // SECURITY: Triggered when signer doesn't match account's authority.
    Unauthorized = 0x1000,

    /// Returned when attempting to operate on an uninitialized account.
    /// // SECURITY: Prevents operations on accounts that haven't been set up.
    NotInitialized = 0x1001,
}

impl From<SecureError> for ProgramError {
    fn from(e: SecureError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// User account storing balance and ownership information.
///
/// This struct is identical to the vulnerable version.
/// // SECURITY: Structure is the same - the difference is in how validation
/// // is performed in the instruction handlers.
pub struct UserAccount {
    /// The public key of the user who owns this account.
    /// // SECURITY: This field is validated in update_balance to ensure
    /// // only the true owner can modify account state.
    pub authority: Address,

    /// Balance value that can be modified by instructions.
    pub balance: u64,

    /// Flag indicating whether the account has been initialized.
    /// // SECURITY: Validated to prevent operations on uninitialized accounts.
    pub is_initialized: bool,

    /// PDA bump seed if this account is derived as a PDA.
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
        UPDATE_BALANCE_DISCRIMINATOR => update_balance(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initializes a user account by writing initial data.
///
/// Note: In this simplified version, the account must be pre-created by the test harness.
///
/// # Accounts
/// 0. `[writable]` user_account - The account to initialize (must be pre-allocated)
/// 1. `[signer]` authority - The user who will own this account
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed (1 byte)
///
/// # Security Validations
/// // SECURITY: Authority must be a signer (signature verification)
/// // SECURITY: Account must be owned by this program (ownership check)
fn initialize(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Account parsing
    let [user_account, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify authority is a signer (required for initialization)
    // This is equivalent to Anchor's Signer<'info> type enforcement
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    // This prevents initializing accounts that belong to other programs
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

    log!("SECURITY VERIFIED: Account initialized for authority");
    log!("SECURITY VERIFIED: Initial balance: 0");

    Ok(())
}

/// Updates the balance of a user account with FULL SECURITY VALIDATION.
///
/// # ✅ SECURITY FEATURES
/// This instruction demonstrates PROPER validation in Pinocchio:
///
/// # Accounts
/// 0. `[writable]` user_account - The account to modify
/// 1. `[signer]` authority - MUST be signer AND match stored authority
///
/// # Instruction Data
/// - new_balance (u64): The new balance to set (8 bytes, little-endian)
///
/// # Security Validations
/// // SECURITY: Authority must be a signer (signature verification)
/// // SECURITY: Account must be owned by this program (ownership check)
/// // SECURITY: Account must be initialized (state validation)
/// // SECURITY: Signer must match stored authority (authorization check)
fn update_balance(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Account parsing
    let [user_account, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ==========================================================================
    // SECURITY CHECK 1: Verify authority is a signer
    // ==========================================================================
    // SECURITY: This is equivalent to Anchor's Signer<'info> type.
    // Without this check, anyone could pass any pubkey without proving ownership.
    //
    // VULNERABLE VERSION COMPARISON:
    // Vulnerable: Uses AccountInfo (no signer check)
    // Secure: Explicitly verifies is_signer()
    if !authority.is_signer() {
        log!("SECURITY REJECTION: Authority must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ==========================================================================
    // SECURITY CHECK 2: Verify account is owned by this program
    // ==========================================================================
    // SECURITY: Ensures we're only modifying accounts that belong to this program.
    // Without this, an attacker could pass an account from a different program.
    //
    // VULNERABLE VERSION COMPARISON:
    // Vulnerable: No owner check - any account accepted
    // Secure: Explicitly verifies owned_by(program_id)
    if !user_account.owned_by(program_id) {
        log!("SECURITY REJECTION: Account not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // Read current data
    let account_data = user_account.try_borrow()?;
    let mut user_data = UserAccount::try_from_slice(&account_data)?;
    drop(account_data);

    // ==========================================================================
    // SECURITY CHECK 3: Verify account is initialized
    // ==========================================================================
    // SECURITY: Prevents operations on uninitialized or corrupted accounts.
    //
    // VULNERABLE VERSION COMPARISON:
    // Vulnerable: No initialization check
    // Secure: Explicitly verifies is_initialized flag
    if !user_data.is_initialized {
        log!("SECURITY REJECTION: Account not initialized");
        return Err(SecureError::NotInitialized.into());
    }

    // ==========================================================================
    // SECURITY CHECK 4: Verify signer matches stored authority
    // ==========================================================================
    // SECURITY: This is equivalent to Anchor's `has_one = authority` constraint.
    // Ensures only the account owner can modify their balance.
    //
    // VULNERABLE VERSION COMPARISON:
    // Vulnerable: Authority not checked against stored value
    // Secure: Explicitly compares user_data.authority with signer's address
    if user_data.authority.as_ref() != authority.address().as_ref() {
        log!("SECURITY REJECTION: Signer does not match account authority");
        return Err(SecureError::Unauthorized.into());
    }

    // Parse new_balance from instruction data (u64 = 8 bytes)
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_balance = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Store old balance for logging
    let old_balance = user_data.balance;

    // SECURITY: Safe to set balance - all authorization checks passed
    user_data.balance = new_balance;

    // Write updated data
    let mut account_data = user_account.try_borrow_mut()?;
    user_data.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Balance updated from {} to {}", old_balance, new_balance);
    log!("SECURITY VERIFIED: Authorized by verified signer");

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

    #[test]
    fn test_error_conversion() {
        let err: ProgramError = SecureError::Unauthorized.into();
        assert!(matches!(err, ProgramError::Custom(0x1000)));

        let err: ProgramError = SecureError::NotInitialized.into();
        assert!(matches!(err, ProgramError::Custom(0x1001)));
    }
}
