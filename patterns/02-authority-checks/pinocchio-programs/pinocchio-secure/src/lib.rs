//! # Pinocchio Secure Authority Checks Program
//!
//! This program demonstrates **SECURE** authority check patterns in Solana using Pinocchio.
//! It is designed for educational purposes to show how to properly implement
//! authority validation to prevent privilege escalation vulnerabilities.
//!
//! ## Security Patterns Demonstrated
//! - Manual is_signer() verification (Pinocchio equivalent of Anchor's `Signer<'info>`)
//! - Manual super_admin comparison (Pinocchio equivalent of Anchor's `constraint`)
//! - Manual is_admin() membership checks (Pinocchio equivalent of custom constraints)
//! - Manual owned_by() verification for account ownership
//!
//! ## Key Differences from Anchor
//! - No declarative account constraints - all checks are explicit code
//! - No type-based signer enforcement - must call is_signer() manually
//! - Error handling uses ProgramError or custom errors
//!
//! Compare this to the vulnerable `pinocchio-vulnerable-authority-checks` program
//! to see exactly what security measures were missing.

#![allow(unexpected_cfgs)]

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID: 3P6BDR7EK5DV7gWyVLSceYRbnUkywjDupYugSQre7eyp
pub const ID: Address = Address::new_from_array([
    0xa7, 0xc1, 0xcd, 0x5c, 0xb7, 0xb3, 0xa2, 0x30, 0xc9, 0xac, 0x2b, 0xc8, 0x67, 0x94, 0xc2, 0x6c,
    0x61, 0xd3, 0x8c, 0xc4, 0xd0, 0x6a, 0x60, 0xae, 0xb5, 0x83, 0x33, 0x0e, 0x93, 0x8f, 0x55, 0xc3,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum number of administrators allowed in the admin_list.
pub const MAX_ADMINS: usize = 3;

/// AdminConfig account size (no Anchor discriminator):
/// - super_admin (Address): 32 bytes
/// - admin_list ([Address; 3]): 96 bytes
/// - admin_count (u8): 1 byte
/// - fee_basis_points (u16): 2 bytes
/// - paused (bool): 1 byte
/// - bump (u8): 1 byte
/// Total: 133 bytes
pub const ADMIN_CONFIG_SIZE: usize = 32 + 96 + 1 + 2 + 1 + 1;

/// ManagerAccount size (no Anchor discriminator):
/// - authority (Address): 32 bytes
/// - manager (Address): 32 bytes
/// - can_modify_fees (bool): 1 byte
/// - can_pause (bool): 1 byte
/// - is_active (bool): 1 byte
/// - bump (u8): 1 byte
/// Total: 68 bytes
pub const MANAGER_ACCOUNT_SIZE: usize = 32 + 32 + 1 + 1 + 1 + 1;

/// Seed for admin_config PDA
pub const ADMIN_CONFIG_SEED: &[u8] = b"admin_config";

/// Seed for manager PDA
pub const MANAGER_SEED: &[u8] = b"manager";

// =============================================================================
// INSTRUCTION DISCRIMINATORS
// =============================================================================

pub const INITIALIZE_CONFIG_DISCRIMINATOR: u8 = 0;
pub const ADD_ADMIN_DISCRIMINATOR: u8 = 1;
pub const UPDATE_FEE_DISCRIMINATOR: u8 = 2;
pub const PAUSE_PROTOCOL_DISCRIMINATOR: u8 = 3;
pub const UNPAUSE_PROTOCOL_DISCRIMINATOR: u8 = 4;
pub const CREATE_MANAGER_DISCRIMINATOR: u8 = 5;
pub const REMOVE_ADMIN_DISCRIMINATOR: u8 = 6;
pub const DEACTIVATE_MANAGER_DISCRIMINATOR: u8 = 7;

// =============================================================================
// CUSTOM ERRORS
// =============================================================================

/// Custom error codes for authority-related failures.
/// These map to Anchor's ErrorCode enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SecureError {
    /// The caller is not authorized to perform this action.
    Unauthorized = 0,
    /// The caller is not the super_admin.
    NotSuperAdmin = 1,
    /// The caller is not in the admin_list.
    NotAdmin = 2,
    /// The admin_list has reached maximum capacity.
    AdminListFull = 3,
    /// The protocol is currently paused.
    ProtocolPaused = 4,
    /// Cannot remove super_admin from the admin_list.
    CannotRemoveSuperAdmin = 5,
    /// The manager account is not active.
    ManagerNotActive = 6,
    /// The admin to remove was not found in the admin_list.
    AdminNotFound = 7,
}

impl From<SecureError> for ProgramError {
    fn from(e: SecureError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Checks if a given address is in the admin_list.
///
/// # SECURITY: Reusable Authority Validation
///
/// This helper function provides a consistent way to check admin membership
/// across multiple instructions. Using a helper function ensures:
/// 1. Consistent validation logic everywhere
/// 2. No risk of typos in repeated constraint expressions
/// 3. Easy auditing of authority checks
///
/// # Arguments
///
/// * `admin_list` - The fixed-size array of admin addresses
/// * `admin_count` - The number of valid entries in admin_list
/// * `key` - The address to check for membership
///
/// # Returns
///
/// `true` if the key is found in admin_list[0..admin_count], `false` otherwise
pub fn is_admin(admin_list: &[Address; MAX_ADMINS], admin_count: u8, key: &Address) -> bool {
    // SECURITY: Only check valid entries (0..admin_count)
    // This prevents reading uninitialized array slots
    let count = admin_count as usize;
    admin_list.iter().take(count).any(|admin| admin.as_ref() == key.as_ref())
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Global administrator configuration account.
pub struct AdminConfig {
    /// The highest-privilege administrator
    pub super_admin: Address,
    /// Fixed-size array of authorized administrators
    pub admin_list: [Address; MAX_ADMINS],
    /// Number of active administrators in the admin_list
    pub admin_count: u8,
    /// Protocol fee in basis points (100 = 1%)
    pub fee_basis_points: u16,
    /// Emergency pause flag
    pub paused: bool,
    /// PDA bump seed
    pub bump: u8,
}

impl AdminConfig {
    /// Deserialize AdminConfig from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < ADMIN_CONFIG_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let super_admin = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let mut admin_list: [Address; MAX_ADMINS] = [
            Address::new_from_array([0u8; 32]),
            Address::new_from_array([0u8; 32]),
            Address::new_from_array([0u8; 32]),
        ];
        for i in 0..MAX_ADMINS {
            let start = 32 + (i * 32);
            let end = start + 32;
            admin_list[i] = Address::new_from_array(
                data[start..end].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
            );
        }

        let admin_count = data[128];
        let fee_basis_points = u16::from_le_bytes(
            data[129..131].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let paused = data[131] != 0;
        let bump = data[132];

        Ok(Self { super_admin, admin_list, admin_count, fee_basis_points, paused, bump })
    }

    /// Serialize AdminConfig into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < ADMIN_CONFIG_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.super_admin.as_ref());

        for i in 0..MAX_ADMINS {
            let start = 32 + (i * 32);
            let end = start + 32;
            data[start..end].copy_from_slice(self.admin_list[i].as_ref());
        }

        data[128] = self.admin_count;
        data[129..131].copy_from_slice(&self.fee_basis_points.to_le_bytes());
        data[131] = self.paused as u8;
        data[132] = self.bump;

        Ok(())
    }
}

/// Manager account with delegated administrative permissions.
pub struct ManagerAccount {
    /// The admin who created this manager
    pub authority: Address,
    /// The manager's public key
    pub manager: Address,
    /// Permission to modify protocol fees
    pub can_modify_fees: bool,
    /// Permission to pause the protocol
    pub can_pause: bool,
    /// Whether this manager account is currently active
    pub is_active: bool,
    /// PDA bump seed
    pub bump: u8,
}

impl ManagerAccount {
    /// Deserialize ManagerAccount from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < MANAGER_ACCOUNT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let manager = Address::new_from_array(
            data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let can_modify_fees = data[64] != 0;
        let can_pause = data[65] != 0;
        let is_active = data[66] != 0;
        let bump = data[67];

        Ok(Self { authority, manager, can_modify_fees, can_pause, is_active, bump })
    }

    /// Serialize ManagerAccount into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < MANAGER_ACCOUNT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.authority.as_ref());
        data[32..64].copy_from_slice(self.manager.as_ref());
        data[64] = self.can_modify_fees as u8;
        data[65] = self.can_pause as u8;
        data[66] = self.is_active as u8;
        data[67] = self.bump;

        Ok(())
    }
}

// =============================================================================
// ENTRYPOINT
// =============================================================================

entrypoint!(process_instruction);

/// Main entrypoint for the Pinocchio program.
pub fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, data) =
        instruction_data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        INITIALIZE_CONFIG_DISCRIMINATOR => initialize_config(program_id, accounts, data),
        ADD_ADMIN_DISCRIMINATOR => add_admin(program_id, accounts),
        UPDATE_FEE_DISCRIMINATOR => update_fee(program_id, accounts, data),
        PAUSE_PROTOCOL_DISCRIMINATOR => pause_protocol(program_id, accounts),
        UNPAUSE_PROTOCOL_DISCRIMINATOR => unpause_protocol(program_id, accounts),
        CREATE_MANAGER_DISCRIMINATOR => create_manager(program_id, accounts, data),
        REMOVE_ADMIN_DISCRIMINATOR => remove_admin(program_id, accounts),
        DEACTIVATE_MANAGER_DISCRIMINATOR => deactivate_manager(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initializes the admin configuration with a super_admin.
///
/// Note: Account must be pre-created by the test harness.
///
/// # Security
///
/// This instruction is SECURE because:
/// - SECURITY: The `super_admin` is verified as a signer
/// - SECURITY: Account ownership is verified
/// - SECURITY: Initial state is set correctly with super_admin in admin_list
fn initialize_config(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [admin_config_acc, super_admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify super_admin is a signer
    if !super_admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let bump = if data.is_empty() { 0 } else { data[0] };

    // Initialize account data
    let admin_config = AdminConfig {
        super_admin: Address::new_from_array(*super_admin.address().as_array()),
        admin_list: {
            let mut list: [Address; MAX_ADMINS] = [
                Address::new_from_array([0u8; 32]),
                Address::new_from_array([0u8; 32]),
                Address::new_from_array([0u8; 32]),
            ];
            list[0] = Address::new_from_array(*super_admin.address().as_array());
            list
        },
        admin_count: 1,
        fee_basis_points: 100,
        paused: false,
        bump,
    };

    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("Admin config initialized with super_admin");

    Ok(())
}

/// Adds a new administrator to the admin_list.
///
/// # Security
///
/// This instruction is SECURE because:
/// - SECURITY: Caller must be a signer (is_signer() check)
/// - SECURITY: Caller must match admin_config.super_admin
/// - SECURITY: Account ownership is verified
fn add_admin(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, caller, new_admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify caller is a signer (Pinocchio equivalent of Signer<'info>)
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify caller is super_admin (Pinocchio equivalent of constraint)
    if admin_config.super_admin.as_ref() != caller.address().as_ref() {
        log!("SECURITY REJECTION: Only super_admin can add admins");
        return Err(SecureError::NotSuperAdmin.into());
    }

    // Check if admin list is full
    if admin_config.admin_count as usize >= MAX_ADMINS {
        log!("Error: Admin list is full");
        return Err(SecureError::AdminListFull.into());
    }

    // SECURITY: Only super_admin can add admins (enforced above)
    let index = admin_config.admin_count as usize;
    admin_config.admin_list[index] = Address::new_from_array(*new_admin.address().as_array());
    admin_config.admin_count += 1;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Admin added by super_admin");

    Ok(())
}

/// Updates the protocol fee configuration.
///
/// # Security
///
/// This instruction is SECURE because:
/// - SECURITY: Caller must be a signer (is_signer() check)
/// - SECURITY: Caller must be in admin_list (is_admin() check)
/// - SECURITY: Account ownership is verified
fn update_fee(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [admin_config_acc, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse new_fee from instruction data
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_fee = u16::from_le_bytes(
        data[0..2].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // SECURITY: Verify caller is a signer
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify caller is in admin_list (is_admin helper)
    if !is_admin(&admin_config.admin_list, admin_config.admin_count, caller.address()) {
        log!("SECURITY REJECTION: Only admins can modify fees");
        return Err(SecureError::NotAdmin.into());
    }

    // SECURITY: Only admins can modify protocol fees
    admin_config.fee_basis_points = new_fee;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Fee updated to {} basis points by admin", new_fee);

    Ok(())
}

/// Pauses the protocol, preventing all operations.
///
/// # Security
///
/// This instruction is SECURE because:
/// - SECURITY: Caller must be a signer
/// - SECURITY: Caller must be super_admin
/// - SECURITY: Pause is a critical function requiring highest authority
fn pause_protocol(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify caller is a signer
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify caller is super_admin
    if admin_config.super_admin.as_ref() != caller.address().as_ref() {
        log!("SECURITY REJECTION: Only super_admin can pause protocol");
        return Err(SecureError::NotSuperAdmin.into());
    }

    // SECURITY: Only super_admin can pause
    admin_config.paused = true;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Protocol paused by super_admin");

    Ok(())
}

/// Unpauses the protocol, allowing operations to resume.
///
/// # Security
///
/// Same security requirements as pause_protocol.
fn unpause_protocol(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify caller is a signer
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify caller is super_admin
    if admin_config.super_admin.as_ref() != caller.address().as_ref() {
        log!("SECURITY REJECTION: Only super_admin can unpause protocol");
        return Err(SecureError::NotSuperAdmin.into());
    }

    admin_config.paused = false;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Protocol unpaused by super_admin");

    Ok(())
}

/// Creates a new manager account with delegated permissions.
///
/// Note: Account must be pre-created by the test harness.
///
/// # Security
///
/// This instruction is SECURE because:
/// - SECURITY: Admin must be a signer
/// - SECURITY: Admin must be in admin_list (is_admin() check)
/// - SECURITY: Account ownership is verified
fn create_manager(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [admin_config_acc, manager_account_acc, admin, manager] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse instruction data
    if data.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let can_modify_fees = data[0] != 0;
    let can_pause = data[1] != 0;
    let bump = data[2];

    // SECURITY: Verify admin is a signer
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify admin_config is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // SECURITY: Verify manager_account is owned by this program
    if !manager_account_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Read admin_config
    let account_data = admin_config_acc.try_borrow()?;
    let admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify admin is in admin_list
    if !is_admin(&admin_config.admin_list, admin_config.admin_count, admin.address()) {
        log!("SECURITY REJECTION: Only admins can create managers");
        return Err(SecureError::NotAdmin.into());
    }

    // Initialize manager data
    let manager_data = ManagerAccount {
        authority: Address::new_from_array(*admin.address().as_array()),
        manager: Address::new_from_array(*manager.address().as_array()),
        can_modify_fees,
        can_pause,
        is_active: true,
        bump,
    };

    let mut account_data = manager_account_acc.try_borrow_mut()?;
    manager_data.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Manager created by validated admin");

    Ok(())
}

/// Removes an administrator from the admin_list.
///
/// # Security
///
/// This instruction is SECURE because:
/// - SECURITY: Caller must be a signer
/// - SECURITY: Caller must be super_admin
/// - SECURITY: Cannot remove super_admin from list
fn remove_admin(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, caller, admin_to_remove] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify caller is a signer
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify account is owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify caller is super_admin
    if admin_config.super_admin.as_ref() != caller.address().as_ref() {
        log!("SECURITY REJECTION: Only super_admin can remove admins");
        return Err(SecureError::NotSuperAdmin.into());
    }

    // SECURITY: Prevent removing super_admin from admin_list
    if admin_to_remove.address().as_ref() == admin_config.super_admin.as_ref() {
        log!("SECURITY REJECTION: Cannot remove super_admin from admin list");
        return Err(SecureError::CannotRemoveSuperAdmin.into());
    }

    // Find the admin in the list
    let count = admin_config.admin_count as usize;
    let mut found_index: Option<usize> = None;

    for i in 0..count {
        if admin_config.admin_list[i].as_ref() == admin_to_remove.address().as_ref() {
            found_index = Some(i);
            break;
        }
    }

    // Return error if admin not found
    let index = match found_index {
        Some(i) => i,
        None => {
            log!("Error: Admin not found in admin list");
            return Err(SecureError::AdminNotFound.into());
        }
    };

    // Remove admin by shifting remaining entries left
    for i in index..count - 1 {
        admin_config.admin_list[i] =
            Address::new_from_array(*admin_config.admin_list[i + 1].as_array());
    }

    // Clear the last slot and decrement count
    admin_config.admin_list[count - 1] = Address::new_from_array([0u8; 32]);
    admin_config.admin_count -= 1;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Admin removed by super_admin");

    Ok(())
}

/// Deactivates a manager account, revoking their permissions.
///
/// # Security
///
/// This instruction is SECURE because:
/// - SECURITY: Caller must be a signer
/// - SECURITY: Caller must be in admin_list
fn deactivate_manager(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, manager_account_acc, caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify caller is a signer
    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify accounts are owned by this program
    if !admin_config_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    if !manager_account_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Read admin_config
    let account_data = admin_config_acc.try_borrow()?;
    let admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // SECURITY: Verify caller is in admin_list
    if !is_admin(&admin_config.admin_list, admin_config.admin_count, caller.address()) {
        log!("SECURITY REJECTION: Only admins can deactivate managers");
        return Err(SecureError::NotAdmin.into());
    }

    // Read and update manager account
    let account_data = manager_account_acc.try_borrow()?;
    let mut manager_data = ManagerAccount::try_from_slice(&account_data)?;
    drop(account_data);

    manager_data.is_active = false;

    let mut account_data = manager_account_acc.try_borrow_mut()?;
    manager_data.serialize(&mut account_data)?;

    log!("SECURITY VERIFIED: Manager deactivated by admin");

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_admin_helper() {
        let admin1 = Address::new_from_array([1u8; 32]);
        let admin2 = Address::new_from_array([2u8; 32]);
        let non_admin = Address::new_from_array([99u8; 32]);

        // Create admin_list with fresh Address instances
        let admin_list = [
            Address::new_from_array([1u8; 32]),
            Address::new_from_array([2u8; 32]),
            Address::new_from_array([0u8; 32]),
        ];
        let admin_count = 2;

        assert!(is_admin(&admin_list, admin_count, &admin1));
        assert!(is_admin(&admin_list, admin_count, &admin2));
        assert!(!is_admin(&admin_list, admin_count, &non_admin));

        // Test with a fresh admin1 for empty list test
        let admin1_check = Address::new_from_array([1u8; 32]);
        assert!(!is_admin(&admin_list, 0, &admin1_check)); // Empty list
    }

    #[test]
    fn test_admin_config_serialization() {
        let config = AdminConfig {
            super_admin: Address::new_from_array([1u8; 32]),
            admin_list: [
                Address::new_from_array([1u8; 32]),
                Address::new_from_array([0u8; 32]),
                Address::new_from_array([0u8; 32]),
            ],
            admin_count: 1,
            fee_basis_points: 100,
            paused: false,
            bump: 255,
        };

        let mut buffer = [0u8; ADMIN_CONFIG_SIZE];
        config.serialize(&mut buffer).unwrap();

        let deserialized = AdminConfig::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.super_admin, config.super_admin);
        assert_eq!(deserialized.admin_count, config.admin_count);
        assert_eq!(deserialized.fee_basis_points, config.fee_basis_points);
        assert_eq!(deserialized.paused, config.paused);
        assert_eq!(deserialized.bump, config.bump);
    }

    #[test]
    fn test_manager_account_serialization() {
        let manager = ManagerAccount {
            authority: Address::new_from_array([1u8; 32]),
            manager: Address::new_from_array([2u8; 32]),
            can_modify_fees: true,
            can_pause: false,
            is_active: true,
            bump: 254,
        };

        let mut buffer = [0u8; MANAGER_ACCOUNT_SIZE];
        manager.serialize(&mut buffer).unwrap();

        let deserialized = ManagerAccount::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.authority, manager.authority);
        assert_eq!(deserialized.manager, manager.manager);
        assert_eq!(deserialized.can_modify_fees, manager.can_modify_fees);
        assert_eq!(deserialized.can_pause, manager.can_pause);
        assert_eq!(deserialized.is_active, manager.is_active);
        assert_eq!(deserialized.bump, manager.bump);
    }
}
