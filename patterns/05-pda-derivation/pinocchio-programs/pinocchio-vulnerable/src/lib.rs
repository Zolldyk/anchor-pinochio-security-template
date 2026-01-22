//! # Pinocchio Vulnerable PDA Derivation Program
//!
//! **WARNING: This program contains INTENTIONAL security vulnerabilities for educational purposes.**
//!
//! This is the Pinocchio equivalent of the Anchor vulnerable PDA derivation program,
//! demonstrating how PDA-related vulnerabilities manifest in a lower-level Solana framework.
//!
//! ## Key Differences from Anchor
//! - No declarative `seeds` constraint for automatic PDA derivation
//! - No `bump` constraint for canonical bump verification
//! - No `has_one` constraint for relationship validation
//! - All validation must be done explicitly (and is deliberately omitted here)
//!
//! ## Vulnerabilities Demonstrated
//! - **Missing PDA Re-derivation:** Accepts any account without verifying it was derived
//!   from the expected seeds
//! - **User-Provided Bump Acceptance:** Stores bumps from instruction data without
//!   verifying they are canonical (highest valid bump)
//! - **Missing Relationship Validation:** Does not verify `user_deposit.treasury`
//!   matches the provided treasury account
//!
//! ## PDA Seeds Reference
//! - Treasury: `["treasury", authority_pubkey]`
//! - UserDeposit: `["user_deposit", treasury_pubkey, owner_pubkey]`
//!
//! **DO NOT deploy this program to mainnet or use in production.**

#![allow(unexpected_cfgs)]

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID for the vulnerable PDA derivation program.
/// Unique identifier distinguishing this from the secure version.
pub const ID: Address = Address::new_from_array([
    0x05, 0xda, 0xde, 0x51, 0x70, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Size of Treasury account in bytes (no Anchor discriminator):
/// - authority (Address): 32 bytes
/// - balance (u64): 8 bytes
/// - bump (u8): 1 byte
///
/// Total: 41 bytes
pub const TREASURY_SIZE: usize = 32 + 8 + 1;

/// Size of UserDeposit account in bytes (no Anchor discriminator):
/// - owner (Address): 32 bytes
/// - treasury (Address): 32 bytes
/// - amount (u64): 8 bytes
/// - bump (u8): 1 byte
///
/// Total: 73 bytes
pub const USER_DEPOSIT_SIZE: usize = 32 + 32 + 8 + 1;

/// Seed prefix for treasury PDA derivation
pub const TREASURY_SEED: &[u8] = b"treasury";

/// Seed prefix for user deposit PDA derivation
pub const USER_DEPOSIT_SEED: &[u8] = b"user_deposit";

/// Instruction discriminator for initialize_treasury
pub const INITIALIZE_TREASURY_DISCRIMINATOR: u8 = 0;

/// Instruction discriminator for create_user_deposit
pub const CREATE_USER_DEPOSIT_DISCRIMINATOR: u8 = 1;

/// Instruction discriminator for deposit
pub const DEPOSIT_DISCRIMINATOR: u8 = 2;

/// Instruction discriminator for withdraw
pub const WITHDRAW_DISCRIMINATOR: u8 = 3;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Treasury account - holds program funds.
///
/// PDA seeds: `["treasury", authority]`
///
/// This struct stores the treasury authority, balance tracking, and bump seed.
/// In the vulnerable version, the bump is accepted from instruction data
/// without verifying it's the canonical (highest valid) bump.
pub struct Treasury {
    /// Treasury admin who can manage funds.
    /// Should be a seed component for PDA derivation.
    pub authority: Address,

    /// Total balance held in treasury (tracked internally, not actual lamports).
    pub balance: u64,

    /// PDA bump seed.
    /// VULNERABILITY: Stored from user input without canonical verification.
    pub bump: u8,
}

impl Treasury {
    /// Deserialize Treasury from raw account data bytes.
    ///
    /// Layout: [authority: 32][balance: 8][bump: 1] = 41 bytes
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < TREASURY_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        // Parse authority (32 bytes at offset 0)
        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse balance (8 bytes at offset 32, little-endian)
        let balance = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse bump (1 byte at offset 40)
        let bump = data[40];

        Ok(Self { authority, balance, bump })
    }

    /// Serialize Treasury into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < TREASURY_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write authority (32 bytes at offset 0)
        data[0..32].copy_from_slice(self.authority.as_ref());

        // Write balance (8 bytes at offset 32, little-endian)
        data[32..40].copy_from_slice(&self.balance.to_le_bytes());

        // Write bump (1 byte at offset 40)
        data[40] = self.bump;

        Ok(())
    }
}

/// UserDeposit account - tracks individual user deposits.
///
/// PDA seeds: `["user_deposit", treasury, owner]`
///
/// This struct creates a hierarchical relationship: each deposit is tied to
/// both a specific treasury and a specific user. In the vulnerable version,
/// this relationship is stored but never validated.
pub struct UserDeposit {
    /// Depositor's pubkey - should be a signer for withdrawals.
    pub owner: Address,

    /// Associated treasury account pubkey.
    /// VULNERABILITY: Stored but not validated against provided treasury.
    pub treasury: Address,

    /// Deposited amount (tracked internally).
    pub amount: u64,

    /// PDA bump seed.
    /// VULNERABILITY: Stored from user input without canonical verification.
    pub bump: u8,
}

impl UserDeposit {
    /// Deserialize UserDeposit from raw account data bytes.
    ///
    /// Layout: [owner: 32][treasury: 32][amount: 8][bump: 1] = 73 bytes
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        // Parse owner (32 bytes at offset 0)
        let owner = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse treasury (32 bytes at offset 32)
        let treasury = Address::new_from_array(
            data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse amount (8 bytes at offset 64, little-endian)
        let amount = u64::from_le_bytes(
            data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse bump (1 byte at offset 72)
        let bump = data[72];

        Ok(Self { owner, treasury, amount, bump })
    }

    /// Serialize UserDeposit into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write owner (32 bytes at offset 0)
        data[0..32].copy_from_slice(self.owner.as_ref());

        // Write treasury (32 bytes at offset 32)
        data[32..64].copy_from_slice(self.treasury.as_ref());

        // Write amount (8 bytes at offset 64, little-endian)
        data[64..72].copy_from_slice(&self.amount.to_le_bytes());

        // Write bump (1 byte at offset 72)
        data[72] = self.bump;

        Ok(())
    }
}

// =============================================================================
// ENTRYPOINT
// =============================================================================

entrypoint!(process_instruction);

/// Main entrypoint for the Pinocchio program.
///
/// Unlike Anchor's `#[program]` macro, Pinocchio requires manual instruction routing
/// based on a discriminator byte.
///
/// | Discriminator | Instruction |
/// |---------------|-------------|
/// | 0 | initialize_treasury |
/// | 1 | create_user_deposit |
/// | 2 | deposit |
/// | 3 | withdraw |
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    // Parse instruction discriminator (first byte)
    let (discriminator, data) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        INITIALIZE_TREASURY_DISCRIMINATOR => initialize_treasury(program_id, accounts, data),
        CREATE_USER_DEPOSIT_DISCRIMINATOR => create_user_deposit(program_id, accounts, data),
        DEPOSIT_DISCRIMINATOR => deposit(accounts, data),
        WITHDRAW_DISCRIMINATOR => withdraw(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initialize a new treasury account.
///
/// # Accounts
/// 0. `[writable]` treasury - The treasury PDA account (must be pre-allocated)
/// 1. `[signer]` authority - The treasury authority who will manage funds
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed (1 byte)
///
/// # Vulnerabilities
/// // VULNERABILITY: Accepts user-provided bump without re-deriving to verify
/// // it matches the canonical bump. An attacker could store a non-canonical
/// // bump, potentially enabling bump seed manipulation attacks.
///
/// ## Anchor Comparison
/// In Anchor's secure version:
/// ```ignore
/// #[account(
///     init,
///     seeds = [b"treasury", authority.key().as_ref()],
///     bump  // Anchor derives and uses canonical bump automatically
/// )]
/// ```
fn initialize_treasury(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // Account parsing
    let [treasury_acc, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Basic signer validation (this is safe in initialize)
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Basic ownership check (account should be owned by this program)
    if !treasury_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Parse bump from instruction data
    // VULNERABILITY: Accepting user-provided bump without validation
    // A secure implementation would derive the canonical bump using
    // find_program_address() and compare/use that value instead.
    let bump = if data.is_empty() { 0 } else { data[0] };

    // Initialize treasury data
    let treasury = Treasury {
        authority: Address::new_from_array(*authority.address().as_array()),
        balance: 0,
        // VULNERABILITY: Storing user-provided bump without verifying it's canonical
        // In Anchor secure version: treasury.bump = ctx.bumps.treasury
        bump,
    };

    // Write data to the account
    let mut account_data = treasury_acc.try_borrow_mut()?;
    treasury.serialize(&mut account_data)?;

    log!("Treasury initialized: authority provided bump={}", bump);
    log!("WARNING: Bump not verified as canonical!");

    Ok(())
}

/// Create a user deposit account linked to a treasury.
///
/// # Accounts
/// 0. `[writable]` user_deposit - The user deposit PDA account (must be pre-allocated)
/// 1. `[]` treasury - The treasury account to link to
/// 2. `[signer]` owner - The depositor who will own this deposit account
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed (1 byte)
///
/// # Vulnerabilities
/// // VULNERABILITY: Does not verify the treasury account is a valid PDA.
/// // VULNERABILITY: Does not verify treasury is derived from expected seeds.
/// // VULNERABILITY: Accepts any account as treasury without type checking.
///
/// ## Anchor Comparison
/// Vulnerable Anchor version uses `AccountInfo` for treasury:
/// ```ignore
/// /// CHECK: Intentionally vulnerable - no validation performed
/// pub treasury: AccountInfo<'info>,
/// ```
/// Secure Anchor version uses typed account:
/// ```ignore
/// pub treasury: Account<'info, Treasury>,
/// ```
fn create_user_deposit(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    // Account parsing
    let [user_deposit_acc, treasury_acc, owner] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Basic signer validation
    if !owner.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Basic ownership check for user_deposit
    if !user_deposit_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // VULNERABILITY: No validation that treasury_acc is:
    // 1. Owned by this program
    // 2. A valid Treasury account (correct size, initialized)
    // 3. Derived from expected seeds ["treasury", some_authority]
    //
    // An attacker could pass ANY account as treasury, including:
    // - An account from a different program
    // - A fake treasury with manipulated authority
    // - A non-PDA account

    // Parse bump from instruction data
    let bump = if data.is_empty() { 0 } else { data[0] };

    // Initialize user deposit data
    let user_deposit = UserDeposit {
        owner: Address::new_from_array(*owner.address().as_array()),
        // VULNERABILITY: Storing treasury address without validation
        // A secure version would verify treasury is a valid PDA
        treasury: Address::new_from_array(*treasury_acc.address().as_array()),
        amount: 0,
        // VULNERABILITY: Storing user-provided bump without verification
        bump,
    };

    // Write data to the account
    let mut account_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut account_data)?;

    log!("User deposit created for owner");
    log!("WARNING: Treasury not validated as genuine PDA!");

    Ok(())
}

/// Deposit funds into a user's deposit account.
///
/// # Accounts
/// 0. `[writable]` user_deposit - The user deposit account
/// 1. `[writable]` treasury - The treasury account to receive funds
/// 2. `[signer]` depositor - The user making the deposit
/// 3. `[]` system_program - System program for transfers
///
/// # Instruction Data
/// - amount (u64): Amount to deposit in lamports (8 bytes, little-endian)
///
/// # Vulnerabilities
/// // VULNERABILITY: No validation that user_deposit.treasury == treasury.key()
/// // VULNERABILITY: No PDA re-derivation to verify accounts are genuine
/// // VULNERABILITY: Missing relationship validation between accounts
///
/// ## Anchor Comparison
/// Secure Anchor version:
/// ```ignore
/// #[account(
///     mut,
///     seeds = [b"user_deposit", treasury.key(), depositor.key()],
///     bump = user_deposit.bump,
///     has_one = treasury,  // Validates relationship
///     has_one = owner,
/// )]
/// pub user_deposit: Account<'info, UserDeposit>,
/// ```
fn deposit(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Account parsing
    let [user_deposit_acc, treasury_acc, depositor, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Basic signer validation for depositor
    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: No PDA re-derivation for user_deposit
    // Should verify: user_deposit_acc.address() == derive_user_deposit_pda(treasury, owner)

    // VULNERABILITY: No PDA re-derivation for treasury
    // Should verify: treasury_acc.address() == derive_treasury_pda(authority)

    // VULNERABILITY: No relationship validation
    // Should verify: user_deposit.treasury == treasury_acc.address()

    // VULNERABILITY: No ownership check
    // Should verify: user_deposit_acc.owned_by(program_id)

    // Parse amount from instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read and update user deposit
    let user_deposit_data = user_deposit_acc.try_borrow()?;
    let mut user_deposit = UserDeposit::try_from_slice(&user_deposit_data)?;
    drop(user_deposit_data);

    // Read and update treasury
    let treasury_data = treasury_acc.try_borrow()?;
    let mut treasury = Treasury::try_from_slice(&treasury_data)?;
    drop(treasury_data);

    // Update balances
    user_deposit.amount =
        user_deposit.amount.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
    treasury.balance =
        treasury.balance.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;

    // Write updated data
    let mut user_deposit_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut user_deposit_data)?;
    drop(user_deposit_data);

    let mut treasury_data = treasury_acc.try_borrow_mut()?;
    treasury.serialize(&mut treasury_data)?;

    // Note: Actual lamport transfer would require CPI to system program
    // For this educational example, we only track internal balances

    log!("Deposited {} lamports", amount);
    log!("WARNING: No PDA or relationship validation performed!");

    Ok(())
}

/// Withdraw funds from a user's deposit account.
///
/// # Accounts
/// 0. `[writable]` user_deposit - The user deposit account
/// 1. `[writable]` treasury - The treasury account to withdraw from
/// 2. `[signer]` withdrawer - The user requesting withdrawal
/// 3. `[]` system_program - System program
///
/// # Instruction Data
/// - amount (u64): Amount to withdraw in lamports (8 bytes, little-endian)
///
/// # Vulnerabilities
/// // VULNERABILITY: No signer validation against user_deposit.owner
/// // VULNERABILITY: No PDA re-derivation for user_deposit or treasury
/// // VULNERABILITY: No canonical bump verification
/// // VULNERABILITY: No relationship validation (user_deposit.treasury != treasury)
/// // VULNERABILITY: Any signer can withdraw from any deposit account
///
/// This is the MOST DANGEROUS instruction because it moves funds without
/// proper authorization checks.
///
/// ## Anchor Comparison
/// Secure Anchor version performs 6+ validations:
/// ```ignore
/// #[account(
///     mut,
///     seeds = [b"user_deposit", treasury.key(), withdrawer.key()],
///     bump = user_deposit.bump,      // Canonical bump check
///     has_one = treasury,            // Relationship validation
///     has_one = owner,               // Owner validation
/// )]
/// pub user_deposit: Account<'info, UserDeposit>,
///
/// #[account(
///     mut,
///     seeds = [b"treasury", treasury.authority.as_ref()],
///     bump = treasury.bump,          // Canonical bump check
/// )]
/// pub treasury: Account<'info, Treasury>,
/// ```
fn withdraw(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    // Account parsing
    let [user_deposit_acc, treasury_acc, withdrawer, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Basic signer check - but this is INSUFFICIENT for security
    if !withdrawer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // VULNERABILITY: No check that withdrawer == user_deposit.owner
    // Any signer can withdraw! This is the critical vulnerability.

    // VULNERABILITY: No PDA re-derivation for user_deposit
    // Cannot verify the account is derived from expected seeds

    // VULNERABILITY: No PDA re-derivation for treasury
    // Cannot verify the treasury is genuine

    // VULNERABILITY: No canonical bump verification
    // Stored bump might not be the canonical one

    // VULNERABILITY: No relationship validation
    // user_deposit.treasury might not match treasury_acc.address()

    // VULNERABILITY: No program ownership check
    // Accounts might belong to a different program

    // Parse amount from instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read account data
    let user_deposit_data = user_deposit_acc.try_borrow()?;
    let mut user_deposit = UserDeposit::try_from_slice(&user_deposit_data)?;
    drop(user_deposit_data);

    let treasury_data = treasury_acc.try_borrow()?;
    let mut treasury = Treasury::try_from_slice(&treasury_data)?;
    drop(treasury_data);

    // Check balance (at least this is done correctly)
    if user_deposit.amount < amount {
        log!("Insufficient balance: {} < {}", user_deposit.amount, amount);
        return Err(ProgramError::InsufficientFunds);
    }

    // Update balances
    user_deposit.amount =
        user_deposit.amount.checked_sub(amount).ok_or(ProgramError::ArithmeticOverflow)?;
    treasury.balance =
        treasury.balance.checked_sub(amount).ok_or(ProgramError::ArithmeticOverflow)?;

    // Write updated data
    let mut user_deposit_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut user_deposit_data)?;
    drop(user_deposit_data);

    let mut treasury_data = treasury_acc.try_borrow_mut()?;
    treasury.serialize(&mut treasury_data)?;

    // Note: Actual lamport transfer would manipulate lamports directly
    // or use CPI - simplified for educational purposes

    log!("Withdrew {} lamports", amount);
    log!("WARNING: No authorization check performed!");
    log!("CRITICAL: Any signer could have made this withdrawal!");

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Treasury serialization and deserialization roundtrip.
    #[test]
    fn test_treasury_serialization() {
        let treasury = Treasury {
            authority: Address::new_from_array([1u8; 32]),
            balance: 1_000_000_000,
            bump: 255,
        };

        let mut buffer = [0u8; TREASURY_SIZE];
        treasury.serialize(&mut buffer).unwrap();

        let deserialized = Treasury::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.authority, treasury.authority);
        assert_eq!(deserialized.balance, treasury.balance);
        assert_eq!(deserialized.bump, treasury.bump);
    }

    /// Test UserDeposit serialization and deserialization roundtrip.
    #[test]
    fn test_user_deposit_serialization() {
        let user_deposit = UserDeposit {
            owner: Address::new_from_array([2u8; 32]),
            treasury: Address::new_from_array([3u8; 32]),
            amount: 500_000_000,
            bump: 254,
        };

        let mut buffer = [0u8; USER_DEPOSIT_SIZE];
        user_deposit.serialize(&mut buffer).unwrap();

        let deserialized = UserDeposit::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.owner, user_deposit.owner);
        assert_eq!(deserialized.treasury, user_deposit.treasury);
        assert_eq!(deserialized.amount, user_deposit.amount);
        assert_eq!(deserialized.bump, user_deposit.bump);
    }

    /// Test Treasury deserialization with insufficient data.
    #[test]
    fn test_treasury_invalid_data_length() {
        let short_buffer = [0u8; 10]; // Less than TREASURY_SIZE
        let result = Treasury::try_from_slice(&short_buffer);
        assert!(result.is_err());
    }

    /// Test UserDeposit deserialization with insufficient data.
    #[test]
    fn test_user_deposit_invalid_data_length() {
        let short_buffer = [0u8; 50]; // Less than USER_DEPOSIT_SIZE
        let result = UserDeposit::try_from_slice(&short_buffer);
        assert!(result.is_err());
    }
}
