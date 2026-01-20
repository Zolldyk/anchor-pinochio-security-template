//! # Pinocchio Vulnerable Authority Checks Program
//!
//! This program demonstrates **INSECURE** authority check patterns in Solana using Pinocchio.
//! It is designed for educational purposes to show how privilege escalation
//! vulnerabilities occur when proper authority validation is missing.
//!
//! ## Key Differences from Anchor
//! - No declarative account constraints (`#[account(constraint = ...)]`)
//! - No type-based signer enforcement (`Signer<'info>`)
//! - All validation must be done explicitly (and is deliberately omitted here)
//!
//! ## Vulnerabilities Demonstrated
//! - Missing is_signer() validation on caller accounts
//! - Missing super_admin comparison for admin operations
//! - Missing is_admin() membership validation for admin_list
//!
//! **DO NOT USE THIS CODE IN PRODUCTION!**

#![allow(unexpected_cfgs)]

use pinocchio::{entrypoint, error::ProgramError, AccountView, Address, ProgramResult};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID: E1VUgxWRMV2aPhMJuzz1f9mRDp7KoX5kBZu5oq1SyAqb
pub const ID: Address = Address::new_from_array([
    0xcf, 0x75, 0x97, 0x8f, 0xb1, 0x4f, 0x40, 0x5a, 0xf4, 0x10, 0x44, 0xd8, 0x1f, 0x49, 0x36, 0xc8,
    0x05, 0x05, 0xb4, 0xba, 0x11, 0x37, 0xdf, 0xa2, 0xf1, 0xd6, 0xc6, 0x5e, 0x66, 0x12, 0x94, 0xfa,
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

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Global administrator configuration account.
///
/// This struct is identical to the Anchor version but uses manual serialization.
/// In Pinocchio, there's no Anchor discriminator (8 bytes saved).
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

        // Parse super_admin (32 bytes)
        let super_admin = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse admin_list (96 bytes = 3 * 32)
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

        // Parse admin_count (1 byte at offset 128)
        let admin_count = data[128];

        // Parse fee_basis_points (2 bytes at offset 129)
        let fee_basis_points = u16::from_le_bytes(
            data[129..131].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        // Parse paused (1 byte at offset 131)
        let paused = data[131] != 0;

        // Parse bump (1 byte at offset 132)
        let bump = data[132];

        Ok(Self { super_admin, admin_list, admin_count, fee_basis_points, paused, bump })
    }

    /// Serialize AdminConfig into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < ADMIN_CONFIG_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        // Write super_admin (32 bytes)
        data[0..32].copy_from_slice(self.super_admin.as_ref());

        // Write admin_list (96 bytes)
        for i in 0..MAX_ADMINS {
            let start = 32 + (i * 32);
            let end = start + 32;
            data[start..end].copy_from_slice(self.admin_list[i].as_ref());
        }

        // Write admin_count (1 byte at offset 128)
        data[128] = self.admin_count;

        // Write fee_basis_points (2 bytes at offset 129)
        data[129..131].copy_from_slice(&self.fee_basis_points.to_le_bytes());

        // Write paused (1 byte at offset 131)
        data[131] = self.paused as u8;

        // Write bump (1 byte at offset 132)
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
        ADD_ADMIN_DISCRIMINATOR => add_admin(accounts),
        UPDATE_FEE_DISCRIMINATOR => update_fee(accounts, data),
        PAUSE_PROTOCOL_DISCRIMINATOR => pause_protocol(accounts),
        UNPAUSE_PROTOCOL_DISCRIMINATOR => unpause_protocol(accounts),
        CREATE_MANAGER_DISCRIMINATOR => create_manager(accounts, data),
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
/// This instruction is SAFE because:
/// - The `super_admin` is verified as a signer
/// - Account ownership is verified
///
/// # Accounts
/// 0. `[writable]` admin_config - The account to initialize (must be pre-allocated)
/// 1. `[signer]` super_admin - The signer who becomes the super administrator
///
/// # Instruction Data
/// - bump (u8): The PDA bump seed
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

    // Parse bump from instruction data
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
        fee_basis_points: 100, // Default 1% fee
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
/// # VULNERABILITIES
///
/// This instruction is **CRITICALLY INSECURE** because:
///
/// // VULNERABILITY: No is_signer() check on caller
/// // VULNERABILITY: No super_admin comparison
/// // VULNERABILITY: Anyone can add themselves as admin
///
/// # Accounts
/// 0. `[writable]` admin_config - The admin config to modify
/// 1. `[]` caller - The caller (NOT validated!)
/// 2. `[]` new_admin - The new admin to add
fn add_admin(accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, _caller, new_admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // VULNERABILITY: No is_signer() check on caller
    // A secure implementation would verify: caller.is_signer()

    // VULNERABILITY: No super_admin comparison
    // A secure implementation would verify:
    // admin_config.super_admin.as_ref() == caller.address().as_ref()

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // Check if admin list is full
    if admin_config.admin_count as usize >= MAX_ADMINS {
        log!("Admin list is full");
        return Err(ProgramError::InvalidArgument);
    }

    // VULNERABILITY: Anyone can add themselves as admin
    let index = admin_config.admin_count as usize;
    admin_config.admin_list[index] = Address::new_from_array(*new_admin.address().as_array());
    admin_config.admin_count += 1;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("Admin added (no authorization check performed!)");

    Ok(())
}

/// Updates the protocol fee configuration.
///
/// # VULNERABILITIES
///
/// This instruction is **INSECURE** because:
///
/// // VULNERABILITY: No is_signer() check on caller
/// // VULNERABILITY: No is_admin() membership check
/// // VULNERABILITY: Anyone can modify protocol fees
///
/// # Accounts
/// 0. `[writable]` admin_config - The admin config containing fee settings
/// 1. `[]` caller - The caller (NOT validated!)
///
/// # Instruction Data
/// - new_fee (u16): The new fee in basis points
fn update_fee(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [admin_config_acc, _caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse new_fee from instruction data
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let new_fee = u16::from_le_bytes(
        data[0..2].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // VULNERABILITY: No is_signer() check on caller
    // A secure implementation would verify: caller.is_signer()

    // VULNERABILITY: No is_admin() membership check
    // A secure implementation would verify:
    // is_admin(&admin_config.admin_list, admin_config.admin_count, caller.address())

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // VULNERABILITY: Any user can modify protocol fees
    admin_config.fee_basis_points = new_fee;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("Fee updated to {} basis points (no authorization check!)", new_fee);

    Ok(())
}

/// Pauses the protocol, preventing all operations.
///
/// # VULNERABILITIES
///
/// This instruction is **INSECURE** because:
///
/// // VULNERABILITY: No is_signer() check on caller
/// // VULNERABILITY: No super_admin comparison
/// // VULNERABILITY: Anyone can pause the protocol (DoS attack)
///
/// # Accounts
/// 0. `[writable]` admin_config - The admin config containing pause state
/// 1. `[]` caller - The caller (NOT validated!)
fn pause_protocol(accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, _caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // VULNERABILITY: No is_signer() check on caller
    // A secure implementation would verify: caller.is_signer()

    // VULNERABILITY: No super_admin comparison
    // A secure implementation would verify:
    // admin_config.super_admin.as_ref() == caller.address().as_ref()

    // Read current data
    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    // VULNERABILITY: Anyone can pause the protocol
    admin_config.paused = true;

    // Write updated data
    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("Protocol paused (no authorization check!)");

    Ok(())
}

/// Unpauses the protocol, allowing operations to resume.
///
/// # VULNERABILITIES
/// Same as pause_protocol - no authorization checks.
fn unpause_protocol(accounts: &[AccountView]) -> ProgramResult {
    let [admin_config_acc, _caller] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // VULNERABILITY: No authorization checks

    let account_data = admin_config_acc.try_borrow()?;
    let mut admin_config = AdminConfig::try_from_slice(&account_data)?;
    drop(account_data);

    admin_config.paused = false;

    let mut account_data = admin_config_acc.try_borrow_mut()?;
    admin_config.serialize(&mut account_data)?;

    log!("Protocol unpaused (no authorization check!)");

    Ok(())
}

/// Creates a new manager account with delegated permissions.
///
/// Note: Account must be pre-created by the test harness.
///
/// # VULNERABILITIES
///
/// This instruction is **INSECURE** because:
///
/// // VULNERABILITY: No is_signer() check on admin
/// // VULNERABILITY: No is_admin() membership check
/// // VULNERABILITY: Anyone can create managers with arbitrary permissions
///
/// # Accounts
/// 0. `[]` admin_config - The admin config (NOT used for validation!)
/// 1. `[writable]` manager_account - The manager account (must be pre-allocated)
/// 2. `[]` admin - The admin creating this manager (NOT validated!)
/// 3. `[]` manager - The user who will become a manager
///
/// # Instruction Data
/// - can_modify_fees (bool): 1 byte
/// - can_pause (bool): 1 byte
/// - bump (u8): 1 byte
fn create_manager(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [_admin_config_acc, manager_account_acc, admin, manager] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse instruction data
    if data.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let can_modify_fees = data[0] != 0;
    let can_pause = data[1] != 0;
    let bump = data[2];

    // VULNERABILITY: No is_signer() check on admin
    // A secure implementation would verify: admin.is_signer()

    // VULNERABILITY: No is_admin() membership check
    // A secure implementation would verify:
    // is_admin(&admin_config.admin_list, admin_config.admin_count, admin.address())

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

    log!("Manager created (no admin validation performed!)");

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
