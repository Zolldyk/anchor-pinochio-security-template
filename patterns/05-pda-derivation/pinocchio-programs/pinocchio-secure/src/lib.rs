//! # Pinocchio Secure PDA Derivation Program
//!
//! **This program demonstrates PROPER PDA validation in Pinocchio.**
//!
//! This is the Pinocchio equivalent of the Anchor secure PDA derivation program,
//! showing how to implement all the security checks that Anchor provides declaratively.
//!
//! ## Framework Comparison: Anchor vs Pinocchio
//!
//! | Anchor Constraint | Pinocchio Equivalent |
//! |-------------------|---------------------|
//! | `seeds = [...]` | `find_program_address(&[...], program_id)` then compare |
//! | `bump = account.bump` | `if data.bump != expected_bump { return Err(...) }` |
//! | `has_one = treasury` | `if user_deposit.treasury != treasury.address() { return Err(...) }` |
//! | `has_one = owner` | `if user_deposit.owner != signer.address() { return Err(...) }` |
//! | `Account<'info, T>` | `account.owned_by(program_id)` + manual deserialization |
//! | `Signer<'info>` | `account.is_signer()` check |
//!
//! ## Trade-offs
//!
//! **Anchor Advantages:**
//! - Concise, declarative constraints
//! - Compile-time guarantees for account types
//! - Automatic PDA derivation and validation
//!
//! **Pinocchio Advantages:**
//! - Explicit control over all validation logic
//! - No macro magic - easier to audit
//! - Smaller binary size (no framework overhead)
//! - Educational value: understand what's happening
//!
//! ## Security Features Demonstrated
//! - Manual PDA re-derivation using `find_program_address()`
//! - Explicit canonical bump verification
//! - Manual relationship validation (treasury <-> user_deposit)
//! - Program ownership validation using `owned_by()`
//! - Signer validation using `is_signer()`
//!
//! **This program is safe for production use (as a reference pattern).**

#![allow(unexpected_cfgs)]

extern crate alloc;

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// Syscalls are only available on Solana runtime
#[cfg(target_os = "solana")]
use pinocchio::syscalls;

// =============================================================================
// PDA DERIVATION SYSCALL WRAPPER
// =============================================================================

/// Find a valid program derived address and its canonical bump seed.
///
/// This wraps the `sol_try_find_program_address` syscall to derive PDAs
/// on-chain. The syscall efficiently finds the canonical (highest valid)
/// bump seed that produces an off-curve address.
///
/// ## Anchor Comparison
/// This is equivalent to what Anchor does internally when you use:
/// ```ignore
/// #[account(seeds = [...], bump)]
/// ```
///
/// ## Implementation Note
/// On the Solana runtime (target_os = "solana"), this calls the efficient
/// syscall. In tests (not on Solana), it falls back to a simplified implementation.
#[cfg(target_os = "solana")]
#[inline]
fn find_program_address(seeds: &[&[u8]], program_id: &Address) -> (Address, u8) {
    let mut pda_bytes = core::mem::MaybeUninit::<[u8; 32]>::uninit();
    let mut bump_seed = u8::MAX;

    let result = unsafe {
        syscalls::sol_try_find_program_address(
            seeds as *const _ as *const u8,
            seeds.len() as u64,
            program_id as *const _ as *const u8,
            pda_bytes.as_mut_ptr() as *mut u8,
            &mut bump_seed as *mut u8,
        )
    };

    if result == 0 {
        (Address::new_from_array(unsafe { pda_bytes.assume_init() }), bump_seed)
    } else {
        panic!("Unable to find a viable program address bump seed")
    }
}

/// Test-only implementation of find_program_address.
///
/// This is a simplified implementation for unit tests that don't run on Solana.
/// It produces deterministic addresses for testing serialization/deserialization,
/// but does NOT perform actual cryptographic PDA derivation.
///
/// **WARNING:** This implementation is NOT secure and should ONLY be used in tests.
/// Real PDA derivation requires the Solana runtime syscall.
#[cfg(not(target_os = "solana"))]
#[inline]
fn find_program_address(seeds: &[&[u8]], program_id: &Address) -> (Address, u8) {
    use alloc::vec::Vec;

    // For non-Solana targets (tests), we create a deterministic but
    // not cryptographically correct address. This allows unit tests
    // to run without the Solana runtime.
    let mut hasher_input = Vec::new();
    for seed in seeds {
        hasher_input.extend_from_slice(seed);
    }
    hasher_input.extend_from_slice(program_id.as_ref());

    // Simple XOR hash for testing - NOT cryptographically secure
    let mut result = [0u8; 32];
    for (i, byte) in hasher_input.iter().enumerate() {
        result[i % 32] ^= byte;
        result[(i + 7) % 32] = result[(i + 7) % 32].wrapping_add(*byte);
    }

    // Return with a deterministic "canonical" bump of 255
    (Address::new_from_array(result), 255)
}

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID for the secure PDA derivation program.
/// Unique identifier distinguishing this from the vulnerable version.
pub const ID: Address = Address::new_from_array([
    0x5e, 0xc0, 0x0e, 0x52, 0x71, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x02,
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
// ERROR CODES
// =============================================================================

/// Custom error codes for PDA validation failures.
///
/// These provide meaningful error messages for security rejections,
/// making it easier to debug and understand why transactions fail.
///
/// ## Anchor Comparison
/// In Anchor, custom errors are defined with `#[error_code]`:
/// ```ignore
/// #[error_code]
/// pub enum PdaError {
///     #[msg("Invalid PDA derivation")]
///     InvalidPdaDerivation,
/// }
/// ```
#[repr(u32)]
pub enum SecureError {
    /// PDA derivation mismatch - provided account doesn't match expected PDA.
    /// // SECURITY: Triggered when account address != find_program_address() result
    InvalidPda = 0x1000,

    /// Non-canonical bump seed detected.
    /// // SECURITY: Triggered when stored bump != canonical bump from derivation
    InvalidBump = 0x1001,

    /// Treasury relationship validation failed (user_deposit.treasury != treasury).
    /// // SECURITY: Equivalent to Anchor's `has_one = treasury` constraint
    InvalidTreasury = 0x1002,

    /// Unauthorized access - signer doesn't match expected authority/owner.
    /// // SECURITY: Equivalent to Anchor's `has_one = owner` constraint
    Unauthorized = 0x1003,

    /// Account not initialized or invalid state.
    NotInitialized = 0x1004,

    /// Insufficient funds for withdrawal.
    InsufficientFunds = 0x1005,
}

impl From<SecureError> for ProgramError {
    fn from(e: SecureError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// =============================================================================
// PDA DERIVATION HELPERS
// =============================================================================

/// Derive the expected Treasury PDA and canonical bump.
///
/// Seeds: `["treasury", authority_pubkey]`
///
/// ## Anchor Comparison
/// This is equivalent to Anchor's seeds constraint:
/// ```ignore
/// #[account(
///     seeds = [TREASURY_SEED, authority.key().as_ref()],
///     bump
/// )]
/// ```
///
/// In Anchor, this derivation happens automatically. In Pinocchio,
/// we must call it explicitly and compare the result.
#[inline]
fn derive_treasury_pda(authority: &Address, program_id: &Address) -> (Address, u8) {
    find_program_address(&[TREASURY_SEED, authority.as_ref()], program_id)
}

/// Derive the expected UserDeposit PDA and canonical bump.
///
/// Seeds: `["user_deposit", treasury_pubkey, owner_pubkey]`
///
/// ## Anchor Comparison
/// This is equivalent to Anchor's seeds constraint:
/// ```ignore
/// #[account(
///     seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), owner.key().as_ref()],
///     bump
/// )]
/// ```
///
/// The hierarchical structure (treasury in seeds) ensures each deposit
/// is uniquely tied to both a treasury and an owner.
#[inline]
fn derive_user_deposit_pda(
    treasury: &Address,
    owner: &Address,
    program_id: &Address,
) -> (Address, u8) {
    find_program_address(&[USER_DEPOSIT_SEED, treasury.as_ref(), owner.as_ref()], program_id)
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Treasury account - holds program funds.
///
/// PDA seeds: `["treasury", authority]`
///
/// This struct is identical to the vulnerable version, but the difference
/// is in how validation is performed in instruction handlers.
pub struct Treasury {
    /// Treasury admin who can manage funds.
    /// // SECURITY: Used as seed component, validated via PDA re-derivation.
    pub authority: Address,

    /// Total balance held in treasury (tracked internally).
    pub balance: u64,

    /// PDA bump seed - always canonical (highest valid).
    /// // SECURITY: Validated against re-derived canonical bump on every access.
    pub bump: u8,
}

impl Treasury {
    /// Deserialize Treasury from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < TREASURY_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let balance = u64::from_le_bytes(
            data[32..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let bump = data[40];

        Ok(Self { authority, balance, bump })
    }

    /// Serialize Treasury into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < TREASURY_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.authority.as_ref());
        data[32..40].copy_from_slice(&self.balance.to_le_bytes());
        data[40] = self.bump;

        Ok(())
    }
}

/// UserDeposit account - tracks individual user deposits.
///
/// PDA seeds: `["user_deposit", treasury, owner]`
///
/// The hierarchical relationship ensures each deposit is uniquely tied
/// to a specific treasury and user combination.
pub struct UserDeposit {
    /// Depositor's pubkey.
    /// // SECURITY: Validated via has_one equivalent check.
    pub owner: Address,

    /// Associated treasury account pubkey.
    /// // SECURITY: Validated via has_one equivalent check.
    pub treasury: Address,

    /// Deposited amount (tracked internally).
    pub amount: u64,

    /// PDA bump seed - always canonical.
    /// // SECURITY: Validated against re-derived canonical bump.
    pub bump: u8,
}

impl UserDeposit {
    /// Deserialize UserDeposit from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let owner = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let treasury = Address::new_from_array(
            data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let amount = u64::from_le_bytes(
            data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let bump = data[72];

        Ok(Self { owner, treasury, amount, bump })
    }

    /// Serialize UserDeposit into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.owner.as_ref());
        data[32..64].copy_from_slice(self.treasury.as_ref());
        data[64..72].copy_from_slice(&self.amount.to_le_bytes());
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
    let (discriminator, data) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        INITIALIZE_TREASURY_DISCRIMINATOR => initialize_treasury(program_id, accounts, data),
        CREATE_USER_DEPOSIT_DISCRIMINATOR => create_user_deposit(program_id, accounts, data),
        DEPOSIT_DISCRIMINATOR => deposit(program_id, accounts, data),
        WITHDRAW_DISCRIMINATOR => withdraw(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initialize a new treasury account with SECURE validation.
///
/// # Accounts
/// 0. `[writable]` treasury - The treasury PDA account
/// 1. `[signer]` authority - The treasury authority
///
/// # Instruction Data
/// - (empty) - bump is derived, not accepted from user
///
/// # Security Validations
/// // SECURITY: Signer validation - authority must sign
/// // SECURITY: Program ownership - treasury owned by this program
/// // SECURITY: PDA derivation - verify treasury matches expected PDA
/// // SECURITY: Canonical bump - derive and store only canonical bump
///
/// ## Anchor Comparison
/// ```ignore
/// #[account(
///     init,
///     payer = authority,
///     seeds = [TREASURY_SEED, authority.key().as_ref()],
///     bump,  // Anchor derives canonical bump automatically
/// )]
/// pub treasury: Account<'info, Treasury>,
/// ```
fn initialize_treasury(
    program_id: &Address,
    accounts: &[AccountView],
    _data: &[u8],
) -> ProgramResult {
    let [treasury_acc, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ==========================================================================
    // SECURITY CHECK 1: Signer validation
    // Anchor equivalent: authority: Signer<'info>
    // ==========================================================================
    // SECURITY: Verify authority is a signer.
    // Without this, anyone could initialize a treasury with any authority.
    if !authority.is_signer() {
        log!("SECURITY REJECTION: Authority must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ==========================================================================
    // SECURITY CHECK 2: Program ownership validation
    // Anchor equivalent: Implicit via Account<'info, Treasury> type
    // ==========================================================================
    // SECURITY: Verify treasury account is owned by this program.
    // This ensures we're initializing a legitimate treasury account.
    if !treasury_acc.owned_by(program_id) {
        log!("SECURITY REJECTION: Treasury not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // ==========================================================================
    // SECURITY CHECK 3: PDA derivation and bump verification
    // Anchor equivalent: seeds = [...], bump (on init)
    // ==========================================================================
    // SECURITY: Derive the expected PDA and canonical bump.
    // This ensures the treasury account address is deterministically correct.
    let (expected_pda, canonical_bump) = derive_treasury_pda(authority.address(), program_id);

    // SECURITY: Verify the provided account matches the expected PDA.
    if treasury_acc.address() != &expected_pda {
        log!("SECURITY REJECTION: Treasury PDA mismatch");
        log!("  Expected: derived from authority");
        log!("  Got: different address");
        return Err(SecureError::InvalidPda.into());
    }

    // Initialize treasury with canonical bump (not user-provided!)
    let treasury = Treasury {
        authority: Address::new_from_array(*authority.address().as_array()),
        balance: 0,
        // SECURITY: Store the canonical bump from derivation
        // This is equivalent to Anchor's ctx.bumps.treasury
        bump: canonical_bump,
    };

    let mut account_data = treasury_acc.try_borrow_mut()?;
    treasury.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Treasury initialized");
    log!("  Authority: verified signer");
    log!("  PDA: verified derivation");
    log!("  Bump: {} (canonical)", canonical_bump);

    Ok(())
}

/// Create a user deposit account with SECURE validation.
///
/// # Accounts
/// 0. `[writable]` user_deposit - The user deposit PDA account
/// 1. `[]` treasury - The treasury account (must be valid PDA)
/// 2. `[signer]` owner - The depositor
///
/// # Instruction Data
/// - (empty) - bump is derived, not accepted from user
///
/// # Security Validations
/// // SECURITY: Signer validation - owner must sign
/// // SECURITY: Program ownership - both accounts owned by this program
/// // SECURITY: Treasury PDA verification - verify treasury is genuine
/// // SECURITY: User deposit PDA verification - verify correct derivation
/// // SECURITY: Canonical bumps for both accounts
///
/// ## Anchor Comparison
/// ```ignore
/// pub treasury: Account<'info, Treasury>,  // Type-checked
/// #[account(
///     init,
///     seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), owner.key().as_ref()],
///     bump,
/// )]
/// pub user_deposit: Account<'info, UserDeposit>,
/// ```
fn create_user_deposit(
    program_id: &Address,
    accounts: &[AccountView],
    _data: &[u8],
) -> ProgramResult {
    let [user_deposit_acc, treasury_acc, owner] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ==========================================================================
    // SECURITY CHECK 1: Signer validation
    // Anchor equivalent: owner: Signer<'info>
    // ==========================================================================
    if !owner.is_signer() {
        log!("SECURITY REJECTION: Owner must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ==========================================================================
    // SECURITY CHECK 2: Program ownership for user_deposit
    // Anchor equivalent: Account<'info, UserDeposit> type enforcement
    // ==========================================================================
    if !user_deposit_acc.owned_by(program_id) {
        log!("SECURITY REJECTION: UserDeposit not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // ==========================================================================
    // SECURITY CHECK 3: Program ownership for treasury
    // Anchor equivalent: Account<'info, Treasury> type enforcement
    // ==========================================================================
    // SECURITY: Verify treasury is owned by this program.
    // This prevents linking to a fake treasury from another program.
    if !treasury_acc.owned_by(program_id) {
        log!("SECURITY REJECTION: Treasury not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // ==========================================================================
    // SECURITY CHECK 4: Treasury PDA verification
    // Anchor equivalent: Implicit via Account<Treasury> type + seeds on init
    // ==========================================================================
    // SECURITY: Deserialize and verify treasury is a valid PDA.
    let treasury_data = treasury_acc.try_borrow()?;
    let treasury = Treasury::try_from_slice(&treasury_data)?;
    drop(treasury_data);

    let (expected_treasury_pda, expected_treasury_bump) =
        derive_treasury_pda(&treasury.authority, program_id);

    if treasury_acc.address() != &expected_treasury_pda {
        log!("SECURITY REJECTION: Treasury PDA mismatch");
        return Err(SecureError::InvalidPda.into());
    }

    if treasury.bump != expected_treasury_bump {
        log!("SECURITY REJECTION: Treasury non-canonical bump");
        return Err(SecureError::InvalidBump.into());
    }

    // ==========================================================================
    // SECURITY CHECK 5: UserDeposit PDA verification
    // Anchor equivalent: seeds = [...], bump on init
    // ==========================================================================
    let (expected_user_deposit_pda, canonical_bump) =
        derive_user_deposit_pda(treasury_acc.address(), owner.address(), program_id);

    if user_deposit_acc.address() != &expected_user_deposit_pda {
        log!("SECURITY REJECTION: UserDeposit PDA mismatch");
        return Err(SecureError::InvalidPda.into());
    }

    // Initialize user deposit with canonical bump
    let user_deposit = UserDeposit {
        owner: Address::new_from_array(*owner.address().as_array()),
        treasury: Address::new_from_array(*treasury_acc.address().as_array()),
        amount: 0,
        bump: canonical_bump,
    };

    let mut account_data = user_deposit_acc.try_borrow_mut()?;
    user_deposit.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: UserDeposit created");
    log!("  Owner: verified signer");
    log!("  Treasury: verified PDA");
    log!("  UserDeposit: verified PDA, bump={}", canonical_bump);

    Ok(())
}

/// Deposit funds with SECURE validation.
///
/// # Accounts
/// 0. `[writable]` user_deposit - The user deposit account
/// 1. `[writable]` treasury - The treasury account
/// 2. `[signer]` depositor - The user making the deposit
/// 3. `[]` system_program - System program
///
/// # Instruction Data
/// - amount (u64): Amount to deposit (8 bytes, little-endian)
///
/// # Security Validations
/// // SECURITY: Signer validation
/// // SECURITY: Program ownership for both accounts
/// // SECURITY: PDA re-derivation for user_deposit
/// // SECURITY: PDA re-derivation for treasury
/// // SECURITY: Canonical bump verification for both
/// // SECURITY: Relationship validation (user_deposit.treasury == treasury)
/// // SECURITY: Owner validation (depositor == user_deposit.owner)
///
/// ## Anchor Comparison
/// ```ignore
/// #[account(
///     mut,
///     seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), depositor.key().as_ref()],
///     bump = user_deposit.bump,    // Canonical bump check
///     has_one = treasury,          // Relationship validation
///     has_one = owner,             // Owner validation
/// )]
/// pub user_deposit: Account<'info, UserDeposit>,
/// ```
fn deposit(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [user_deposit_acc, treasury_acc, depositor, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ==========================================================================
    // SECURITY CHECK 1: Signer validation
    // Anchor equivalent: depositor: Signer<'info>
    // ==========================================================================
    if !depositor.is_signer() {
        log!("SECURITY REJECTION: Depositor must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ==========================================================================
    // SECURITY CHECK 2: Program ownership validation
    // Anchor equivalent: Account<'info, T> type enforcement
    // ==========================================================================
    if !user_deposit_acc.owned_by(program_id) {
        log!("SECURITY REJECTION: UserDeposit not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    if !treasury_acc.owned_by(program_id) {
        log!("SECURITY REJECTION: Treasury not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // Deserialize account data
    let user_deposit_data = user_deposit_acc.try_borrow()?;
    let mut user_deposit = UserDeposit::try_from_slice(&user_deposit_data)?;
    drop(user_deposit_data);

    let treasury_data = treasury_acc.try_borrow()?;
    let mut treasury = Treasury::try_from_slice(&treasury_data)?;
    drop(treasury_data);

    // ==========================================================================
    // SECURITY CHECK 3: UserDeposit PDA re-derivation
    // Anchor equivalent: seeds = [...], bump = user_deposit.bump
    // ==========================================================================
    let (expected_user_deposit_pda, expected_ud_bump) =
        derive_user_deposit_pda(treasury_acc.address(), depositor.address(), program_id);

    if user_deposit_acc.address() != &expected_user_deposit_pda {
        log!("SECURITY REJECTION: UserDeposit PDA mismatch");
        return Err(SecureError::InvalidPda.into());
    }

    if user_deposit.bump != expected_ud_bump {
        log!("SECURITY REJECTION: UserDeposit non-canonical bump");
        return Err(SecureError::InvalidBump.into());
    }

    // ==========================================================================
    // SECURITY CHECK 4: Treasury PDA re-derivation
    // Anchor equivalent: seeds = [...], bump = treasury.bump
    // ==========================================================================
    let (expected_treasury_pda, expected_t_bump) =
        derive_treasury_pda(&treasury.authority, program_id);

    if treasury_acc.address() != &expected_treasury_pda {
        log!("SECURITY REJECTION: Treasury PDA mismatch");
        return Err(SecureError::InvalidPda.into());
    }

    if treasury.bump != expected_t_bump {
        log!("SECURITY REJECTION: Treasury non-canonical bump");
        return Err(SecureError::InvalidBump.into());
    }

    // ==========================================================================
    // SECURITY CHECK 5: Relationship validation (has_one = treasury)
    // Anchor equivalent: has_one = treasury
    // ==========================================================================
    if &user_deposit.treasury != treasury_acc.address() {
        log!("SECURITY REJECTION: UserDeposit treasury mismatch");
        return Err(SecureError::InvalidTreasury.into());
    }

    // ==========================================================================
    // SECURITY CHECK 6: Owner validation (has_one = owner)
    // Anchor equivalent: has_one = owner (or depositor == user_deposit.owner)
    // ==========================================================================
    if &user_deposit.owner != depositor.address() {
        log!("SECURITY REJECTION: Depositor is not the owner");
        return Err(SecureError::Unauthorized.into());
    }

    // Parse amount from instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // All security checks passed - update balances
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

    log!("SECURITY VERIFIED: Deposit of {} approved", amount);
    log!("  PDA: both accounts verified");
    log!("  Bumps: both canonical");
    log!("  Relationships: verified");

    Ok(())
}

/// Withdraw funds with COMPREHENSIVE SECURITY VALIDATION.
///
/// This is the most security-critical instruction as it moves funds.
/// All 7 security checks must pass before any withdrawal occurs.
///
/// # Accounts
/// 0. `[writable]` user_deposit - The user deposit account
/// 1. `[writable]` treasury - The treasury account
/// 2. `[signer]` withdrawer - The user requesting withdrawal
/// 3. `[]` system_program - System program
///
/// # Instruction Data
/// - amount (u64): Amount to withdraw (8 bytes, little-endian)
///
/// # Security Validations (ALL REQUIRED)
/// 1. Signer validation - withdrawer must sign
/// 2. Program ownership - both accounts owned by this program
/// 3. UserDeposit PDA re-derivation - verify account is genuine
/// 4. Treasury PDA re-derivation - verify account is genuine
/// 5. Canonical bump verification - both accounts use canonical bumps
/// 6. Relationship validation - user_deposit.treasury == treasury
/// 7. Authority validation - withdrawer == user_deposit.owner
/// 8. Sufficient funds check
///
/// ## Anchor Comparison
/// This shows exactly what Anchor does behind the scenes with:
/// ```ignore
/// #[account(
///     mut,
///     seeds = [USER_DEPOSIT_SEED, treasury.key().as_ref(), withdrawer.key().as_ref()],
///     bump = user_deposit.bump,
///     has_one = treasury,
///     has_one = owner @ PdaError::UnauthorizedAccess,
/// )]
/// pub user_deposit: Account<'info, UserDeposit>,
///
/// #[account(
///     mut,
///     seeds = [TREASURY_SEED, treasury.authority.as_ref()],
///     bump = treasury.bump,
/// )]
/// pub treasury: Account<'info, Treasury>,
/// ```
fn withdraw(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [user_deposit_acc, treasury_acc, withdrawer, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // ==========================================================================
    // SECURITY CHECK 1: Signer validation
    // Anchor equivalent: withdrawer: Signer<'info>
    // ==========================================================================
    if !withdrawer.is_signer() {
        log!("SECURITY REJECTION: Withdrawer must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ==========================================================================
    // SECURITY CHECK 2: Program ownership validation
    // Anchor equivalent: Account<'info, T> type enforcement
    // ==========================================================================
    if !user_deposit_acc.owned_by(program_id) {
        log!("SECURITY REJECTION: UserDeposit not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    if !treasury_acc.owned_by(program_id) {
        log!("SECURITY REJECTION: Treasury not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // Deserialize account data
    let user_deposit_data = user_deposit_acc.try_borrow()?;
    let mut user_deposit = UserDeposit::try_from_slice(&user_deposit_data)?;
    drop(user_deposit_data);

    let treasury_data = treasury_acc.try_borrow()?;
    let mut treasury = Treasury::try_from_slice(&treasury_data)?;
    drop(treasury_data);

    // ==========================================================================
    // SECURITY CHECK 3: UserDeposit PDA re-derivation
    // Anchor equivalent: seeds = [USER_DEPOSIT_SEED, treasury.key(), withdrawer.key()]
    // ==========================================================================
    let (expected_user_deposit_pda, expected_ud_bump) =
        derive_user_deposit_pda(treasury_acc.address(), withdrawer.address(), program_id);

    if user_deposit_acc.address() != &expected_user_deposit_pda {
        log!("SECURITY REJECTION: UserDeposit PDA mismatch");
        log!("  This could indicate a fake user_deposit account");
        return Err(SecureError::InvalidPda.into());
    }

    // ==========================================================================
    // SECURITY CHECK 4: UserDeposit canonical bump verification
    // Anchor equivalent: bump = user_deposit.bump
    // ==========================================================================
    if user_deposit.bump != expected_ud_bump {
        log!("SECURITY REJECTION: UserDeposit non-canonical bump");
        log!("  Stored: {}, Expected: {}", user_deposit.bump, expected_ud_bump);
        return Err(SecureError::InvalidBump.into());
    }

    // ==========================================================================
    // SECURITY CHECK 5: Treasury PDA re-derivation
    // Anchor equivalent: seeds = [TREASURY_SEED, treasury.authority.as_ref()]
    // ==========================================================================
    let (expected_treasury_pda, expected_t_bump) =
        derive_treasury_pda(&treasury.authority, program_id);

    if treasury_acc.address() != &expected_treasury_pda {
        log!("SECURITY REJECTION: Treasury PDA mismatch");
        log!("  This could indicate a fake treasury account");
        return Err(SecureError::InvalidPda.into());
    }

    // ==========================================================================
    // SECURITY CHECK 6: Treasury canonical bump verification
    // Anchor equivalent: bump = treasury.bump
    // ==========================================================================
    if treasury.bump != expected_t_bump {
        log!("SECURITY REJECTION: Treasury non-canonical bump");
        log!("  Stored: {}, Expected: {}", treasury.bump, expected_t_bump);
        return Err(SecureError::InvalidBump.into());
    }

    // ==========================================================================
    // SECURITY CHECK 7: Relationship validation (has_one = treasury)
    // Anchor equivalent: has_one = treasury
    // ==========================================================================
    if &user_deposit.treasury != treasury_acc.address() {
        log!("SECURITY REJECTION: UserDeposit treasury mismatch");
        log!("  Stored treasury doesn't match provided treasury");
        return Err(SecureError::InvalidTreasury.into());
    }

    // ==========================================================================
    // SECURITY CHECK 8: Authority validation (has_one = owner)
    // Anchor equivalent: has_one = owner @ PdaError::UnauthorizedAccess
    // ==========================================================================
    if &user_deposit.owner != withdrawer.address() {
        log!("SECURITY REJECTION: Withdrawer is not the owner");
        log!("  Only the deposit owner can withdraw");
        return Err(SecureError::Unauthorized.into());
    }

    // Parse amount from instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // ==========================================================================
    // SECURITY CHECK 9: Sufficient funds
    // ==========================================================================
    if user_deposit.amount < amount {
        log!("SECURITY REJECTION: Insufficient funds");
        log!("  Available: {}, Requested: {}", user_deposit.amount, amount);
        return Err(SecureError::InsufficientFunds.into());
    }

    // All security checks passed - proceed with withdrawal
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

    log!("SECURITY VERIFIED: Withdrawal of {} approved", amount);
    log!("  All 9 security checks passed:");
    log!("  [1] Signer validation");
    log!("  [2] Program ownership");
    log!("  [3] UserDeposit PDA");
    log!("  [4] UserDeposit bump");
    log!("  [5] Treasury PDA");
    log!("  [6] Treasury bump");
    log!("  [7] Treasury relationship");
    log!("  [8] Owner authorization");
    log!("  [9] Sufficient funds");

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

    /// Test SecureError conversion to ProgramError.
    #[test]
    fn test_error_conversion() {
        let err: ProgramError = SecureError::InvalidPda.into();
        assert!(matches!(err, ProgramError::Custom(0x1000)));

        let err: ProgramError = SecureError::InvalidBump.into();
        assert!(matches!(err, ProgramError::Custom(0x1001)));

        let err: ProgramError = SecureError::InvalidTreasury.into();
        assert!(matches!(err, ProgramError::Custom(0x1002)));

        let err: ProgramError = SecureError::Unauthorized.into();
        assert!(matches!(err, ProgramError::Custom(0x1003)));

        let err: ProgramError = SecureError::NotInitialized.into();
        assert!(matches!(err, ProgramError::Custom(0x1004)));

        let err: ProgramError = SecureError::InsufficientFunds.into();
        assert!(matches!(err, ProgramError::Custom(0x1005)));
    }

    /// Test Treasury deserialization with insufficient data.
    #[test]
    fn test_treasury_invalid_data_length() {
        let short_buffer = [0u8; 10];
        let result = Treasury::try_from_slice(&short_buffer);
        assert!(result.is_err());
    }

    /// Test UserDeposit deserialization with insufficient data.
    #[test]
    fn test_user_deposit_invalid_data_length() {
        let short_buffer = [0u8; 50];
        let result = UserDeposit::try_from_slice(&short_buffer);
        assert!(result.is_err());
    }
}
