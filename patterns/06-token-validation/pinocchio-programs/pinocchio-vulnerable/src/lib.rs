//! # Pinocchio Vulnerable Token Validation Program
//!
//! This program demonstrates common SPL Token integration vulnerabilities
//! in the Pinocchio framework. It serves as a comparison to the Anchor
//! vulnerable implementation to show how these vulnerabilities manifest
//! when validation must be done manually.
//!
//! ## Key Differences from Anchor
//!
//! | Aspect | Anchor | Pinocchio |
//! |--------|--------|-----------|
//! | Mint validation | `constraint = token.mint == vault.mint` | Must parse token account bytes manually |
//! | Owner validation | `constraint = token.owner == user.key()` | Must parse token account bytes manually |
//! | Authority check | `has_one = authority` + `Signer` | Must compare addresses explicitly |
//! | Token CPI | `token::transfer()`, `token::mint_to()` | Manual instruction data construction |
//! | Account parsing | Automatic via `Account<T>` | Manual byte slice parsing |
//!
//! ## Vulnerabilities Demonstrated
//!
//! | Vulnerability | Impact | Instruction |
//! |---------------|--------|-------------|
//! | Missing mint validation | Deposit worthless tokens, withdraw valuable ones | `deposit` |
//! | Missing owner validation | Redirect withdrawals to attacker accounts | `withdraw` |
//! | Missing authority check | Unlimited unauthorized token minting | `mint_reward` |
//!
//! ## WARNING
//!
//! **DO NOT use this code in production.** This program intentionally contains
//! security vulnerabilities for educational purposes only.

#![allow(unexpected_cfgs)]

use pinocchio::{
    cpi::{invoke, invoke_signed, Seed, Signer},
    entrypoint,
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use solana_program_log::log;

// =============================================================================
// PROGRAM ID
// =============================================================================

/// Program ID: 4dPjoc3tbiQjXMzxy1fS2ktuCPHcV6TMJdeVEonnNFVR
pub const ID: Address = Address::new_from_array([
    0x35, 0xe5, 0xae, 0x09, 0xaa, 0xe4, 0xde, 0x15, 0x29, 0x26, 0x35, 0x7c, 0x8e, 0x18, 0x88, 0x57,
    0xcc, 0x0d, 0x38, 0xa2, 0x5c, 0x00, 0xdc, 0xc6, 0x3f, 0xe4, 0xa1, 0xa0, 0x73, 0x49, 0x5a, 0xa0,
]);

/// SPL Token Program ID
pub const TOKEN_PROGRAM_ID: Address = Address::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Vault account size (no Anchor discriminator):
/// - authority: 32 bytes (offset 0)
/// - mint: 32 bytes (offset 32)
/// - vault_token_account: 32 bytes (offset 64)
/// - total_deposits: 8 bytes (offset 96)
/// - bump: 1 byte (offset 104)
///
/// Total: 105 bytes
pub const VAULT_SIZE: usize = 32 + 32 + 32 + 8 + 1;

/// UserDeposit account size (no Anchor discriminator):
/// - user: 32 bytes (offset 0)
/// - vault: 32 bytes (offset 32)
/// - amount: 8 bytes (offset 64)
/// - bump: 1 byte (offset 72)
///
/// Total: 73 bytes
pub const USER_DEPOSIT_SIZE: usize = 32 + 32 + 8 + 1;

/// Seed prefix for vault PDA derivation
pub const VAULT_SEED: &[u8] = b"vault";

/// Seed prefix for user deposit PDA derivation
pub const USER_DEPOSIT_SEED: &[u8] = b"user_deposit";

/// Instruction discriminators
pub const INITIALIZE_VAULT_DISCRIMINATOR: u8 = 0;
pub const DEPOSIT_DISCRIMINATOR: u8 = 1;
pub const WITHDRAW_DISCRIMINATOR: u8 = 2;
pub const MINT_REWARD_DISCRIMINATOR: u8 = 3;

// =============================================================================
// SPL TOKEN CPI HELPERS
// =============================================================================
//
// These helpers construct the raw instruction data for SPL Token operations.
// Unlike Anchor's `token::transfer()` and `token::mint_to()`, we must manually
// build the 9-byte instruction data and invoke the Token Program.

/// SPL Token Transfer instruction discriminator
const SPL_TRANSFER_DISCRIMINATOR: u8 = 3;

/// SPL Token MintTo instruction discriminator
const SPL_MINT_TO_DISCRIMINATOR: u8 = 7;

/// Parses the mint address from a token account's data.
///
/// ## Token Account Data Layout
/// ```text
/// Offset  Size  Field
/// 0       32    mint (Pubkey)
/// 32      32    owner (Pubkey)
/// 64      8     amount (u64)
/// ...
/// ```
pub fn parse_token_account_mint(token_account_data: &[u8]) -> Result<Address, ProgramError> {
    if token_account_data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }

    let mint_bytes: [u8; 32] =
        token_account_data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(Address::new_from_array(mint_bytes))
}

/// Parses the owner address from a token account's data.
pub fn parse_token_account_owner(token_account_data: &[u8]) -> Result<Address, ProgramError> {
    if token_account_data.len() < 64 {
        return Err(ProgramError::InvalidAccountData);
    }

    let owner_bytes: [u8; 32] =
        token_account_data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(Address::new_from_array(owner_bytes))
}

/// Invokes SPL Token Transfer instruction.
///
/// Builds the 9-byte instruction data: [3u8, amount: u64 LE]
pub fn spl_token_transfer(
    from: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    token_program: &AccountView,
    amount: u64,
) -> ProgramResult {
    // Build instruction data: [discriminator (1 byte), amount (8 bytes LE)]
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = SPL_TRANSFER_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    // Build account metas for CPI
    let accounts = [
        InstructionAccount::writable(from.address()),
        InstructionAccount::writable(to.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

    // Build instruction view
    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &instruction_data,
    };

    // Invoke the token program
    invoke::<3>(&instruction, &[from, to, authority])
}

/// Invokes SPL Token Transfer instruction with PDA signer.
pub fn spl_token_transfer_signed<const N: usize>(
    from: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    token_program: &AccountView,
    amount: u64,
    signer_seeds: &[Seed; N],
) -> ProgramResult {
    // Build instruction data: [discriminator (1 byte), amount (8 bytes LE)]
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = SPL_TRANSFER_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    // Build account metas for CPI
    let accounts = [
        InstructionAccount::writable(from.address()),
        InstructionAccount::writable(to.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

    // Build instruction view
    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &instruction_data,
    };

    // Build signer from seeds
    let signer = Signer::from(signer_seeds);

    // Invoke with signer seeds for PDA
    invoke_signed::<3>(&instruction, &[from, to, authority], &[signer])
}

/// Invokes SPL Token MintTo instruction with PDA signer.
///
/// Builds the 9-byte instruction data: [7u8, amount: u64 LE]
pub fn spl_token_mint_to_signed<const N: usize>(
    mint: &AccountView,
    destination: &AccountView,
    authority: &AccountView,
    token_program: &AccountView,
    amount: u64,
    signer_seeds: &[Seed; N],
) -> ProgramResult {
    // Build instruction data: [discriminator (1 byte), amount (8 bytes LE)]
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = SPL_MINT_TO_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    // Build account metas for CPI
    let accounts = [
        InstructionAccount::writable(mint.address()),
        InstructionAccount::writable(destination.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

    // Build instruction view
    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &instruction_data,
    };

    // Build signer from seeds
    let signer = Signer::from(signer_seeds);

    // Invoke with signer seeds for PDA
    invoke_signed::<3>(&instruction, &[mint, destination, authority], &[signer])
}

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Vault account storing token vault configuration.
pub struct Vault {
    /// Authority who can manage the vault (32 bytes)
    pub authority: Address,
    /// The SPL Token mint this vault accepts (32 bytes)
    pub mint: Address,
    /// Token account holding vault funds (32 bytes)
    pub vault_token_account: Address,
    /// Total tokens deposited across all users (8 bytes)
    pub total_deposits: u64,
    /// PDA bump seed for signing (1 byte)
    pub bump: u8,
}

impl Vault {
    /// Deserialize Vault from raw account data bytes.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let authority = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let mint = Address::new_from_array(
            data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let vault_token_account = Address::new_from_array(
            data[64..96].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let total_deposits = u64::from_le_bytes(
            data[96..104].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let bump = data[104];

        Ok(Self { authority, mint, vault_token_account, total_deposits, bump })
    }

    /// Serialize Vault into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < VAULT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.authority.as_ref());
        data[32..64].copy_from_slice(self.mint.as_ref());
        data[64..96].copy_from_slice(self.vault_token_account.as_ref());
        data[96..104].copy_from_slice(&self.total_deposits.to_le_bytes());
        data[104] = self.bump;

        Ok(())
    }
}

/// User deposit record tracking individual user deposits.
pub struct UserDeposit {
    /// User who made the deposit (32 bytes)
    pub user: Address,
    /// Vault this deposit belongs to (32 bytes)
    pub vault: Address,
    /// Amount currently deposited (8 bytes)
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

        let user = Address::new_from_array(
            data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let vault = Address::new_from_array(
            data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let amount = u64::from_le_bytes(
            data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );

        let bump = data[72];

        Ok(Self { user, vault, amount, bump })
    }

    /// Serialize UserDeposit into raw account data bytes.
    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < USER_DEPOSIT_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..32].copy_from_slice(self.user.as_ref());
        data[32..64].copy_from_slice(self.vault.as_ref());
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
        WITHDRAW_DISCRIMINATOR => withdraw(program_id, accounts, data),
        MINT_REWARD_DISCRIMINATOR => mint_reward(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

/// Initializes a new token vault that accepts deposits.
fn initialize_vault(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, mint, vault_token_account, authority, _system_program, _token_program] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify authority is signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify vault is owned by this program
    if !vault.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    // Parse bump from instruction data
    let bump = if data.is_empty() { 0 } else { data[0] };

    // Initialize vault data
    let vault_data = Vault {
        authority: Address::new_from_array(*authority.address().as_array()),
        mint: Address::new_from_array(*mint.address().as_array()),
        vault_token_account: Address::new_from_array(*vault_token_account.address().as_array()),
        total_deposits: 0,
        bump,
    };

    // Write data to the vault account
    let mut account_data = vault.try_borrow_mut()?;
    vault_data.serialize(&mut account_data)?;

    log!("Vault initialized for mint");
    log!("Vault authority set");

    Ok(())
}

/// Deposits tokens into the vault.
///
/// # VULNERABILITY: No Mint Validation
///
/// This function accepts ANY token account without verifying that its mint
/// matches the vault's expected mint.
fn deposit(_program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, user_deposit, user_token_account, vault_token_account, user, _system_program, token_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify user is signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data
    if data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    let user_deposit_bump = data[8];

    // VULNERABILITY: No mint validation - accepts any token account!
    // In a secure implementation, we would verify user_token_account.mint == vault.mint

    // Read current vault state
    let vault_data = vault.try_borrow()?;
    let mut vault_state = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    // Initialize or read user deposit
    let user_deposit_data = user_deposit.try_borrow()?;
    let mut user_deposit_state = if user_deposit_data[0..32] == [0u8; 32] {
        UserDeposit {
            user: Address::new_from_array(*user.address().as_array()),
            vault: Address::new_from_array(*vault.address().as_array()),
            amount: 0,
            bump: user_deposit_bump,
        }
    } else {
        UserDeposit::try_from_slice(&user_deposit_data)?
    };
    drop(user_deposit_data);

    // VULNERABILITY: No mint validation - accepts any token account!
    spl_token_transfer(user_token_account, vault_token_account, user, token_program, amount)?;

    // Update deposit tracking
    user_deposit_state.amount =
        user_deposit_state.amount.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;

    vault_state.total_deposits =
        vault_state.total_deposits.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;

    // Write updated states
    let mut vault_data = vault.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;
    drop(vault_data);

    let mut user_deposit_data = user_deposit.try_borrow_mut()?;
    user_deposit_state.serialize(&mut user_deposit_data)?;

    log!("Deposited tokens (mint validation: NONE)");

    Ok(())
}

/// Withdraws tokens from the vault.
///
/// # VULNERABILITY: No Owner Validation
///
/// This function accepts ANY destination token account without verifying
/// that its owner matches the withdrawer.
fn withdraw(_program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, user_deposit, vault_token_account, destination_token_account, user, token_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Verify user is signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read vault state
    let vault_data = vault.try_borrow()?;
    let mut vault_state = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    // Read user deposit state
    let user_deposit_data = user_deposit.try_borrow()?;
    let mut user_deposit_state = UserDeposit::try_from_slice(&user_deposit_data)?;
    drop(user_deposit_data);

    // Check user has sufficient deposit balance
    if user_deposit_state.amount < amount {
        log!("Insufficient balance for withdrawal");
        return Err(ProgramError::InsufficientFunds);
    }

    // VULNERABILITY: No owner validation on destination!
    // In a secure implementation, we would verify destination.owner == user

    // Build PDA signer seeds for vault authority
    let vault_bump = vault_state.bump;
    let bump_bytes = [vault_bump];
    let seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(vault_state.mint.as_ref()),
        Seed::from(&bump_bytes),
    ];

    // VULNERABILITY: No owner validation - sends to any destination!
    spl_token_transfer_signed(
        vault_token_account,
        destination_token_account,
        vault,
        token_program,
        amount,
        &seeds,
    )?;

    // Update deposit tracking
    user_deposit_state.amount =
        user_deposit_state.amount.checked_sub(amount).ok_or(ProgramError::ArithmeticOverflow)?;

    vault_state.total_deposits =
        vault_state.total_deposits.checked_sub(amount).ok_or(ProgramError::ArithmeticOverflow)?;

    // Write updated states
    let mut vault_data = vault.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;
    drop(vault_data);

    let mut user_deposit_data = user_deposit.try_borrow_mut()?;
    user_deposit_state.serialize(&mut user_deposit_data)?;

    log!("Withdrew tokens (owner validation: NONE)");

    Ok(())
}

/// Mints reward tokens to a user.
///
/// # VULNERABILITY: No Authority Check
///
/// This function allows ANYONE to mint tokens because it doesn't verify
/// that the caller is the mint authority.
fn mint_reward(_program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, mint, destination_token_account, _anyone, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // Parse instruction data
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // VULNERABILITY: No authority check - anyone can mint!
    // In a secure implementation, we would verify caller == vault.authority

    // Read vault state for PDA seeds
    let vault_data = vault.try_borrow()?;
    let vault_state = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    // Build PDA signer seeds for mint authority
    let vault_bump = vault_state.bump;
    let bump_bytes = [vault_bump];
    let seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(vault_state.mint.as_ref()),
        Seed::from(&bump_bytes),
    ];

    // VULNERABILITY: No authority check - allows unauthorized minting!
    spl_token_mint_to_signed(mint, destination_token_account, vault, token_program, amount, &seeds)?;

    log!("Minted reward tokens (authority check: NONE)");

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
            mint: Address::new_from_array([2u8; 32]),
            vault_token_account: Address::new_from_array([3u8; 32]),
            total_deposits: 1_000_000,
            bump: 255,
        };

        let mut buffer = [0u8; VAULT_SIZE];
        vault.serialize(&mut buffer).unwrap();

        let deserialized = Vault::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.authority, vault.authority);
        assert_eq!(deserialized.mint, vault.mint);
        assert_eq!(deserialized.vault_token_account, vault.vault_token_account);
        assert_eq!(deserialized.total_deposits, vault.total_deposits);
        assert_eq!(deserialized.bump, vault.bump);
    }

    #[test]
    fn test_user_deposit_serialization() {
        let user_deposit = UserDeposit {
            user: Address::new_from_array([1u8; 32]),
            vault: Address::new_from_array([2u8; 32]),
            amount: 500_000,
            bump: 254,
        };

        let mut buffer = [0u8; USER_DEPOSIT_SIZE];
        user_deposit.serialize(&mut buffer).unwrap();

        let deserialized = UserDeposit::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.user, user_deposit.user);
        assert_eq!(deserialized.vault, user_deposit.vault);
        assert_eq!(deserialized.amount, user_deposit.amount);
        assert_eq!(deserialized.bump, user_deposit.bump);
    }

    #[test]
    fn test_parse_token_account_mint() {
        let mut data = [0u8; 165];
        let expected_mint = [42u8; 32];
        data[0..32].copy_from_slice(&expected_mint);

        let mint = parse_token_account_mint(&data).unwrap();
        assert_eq!(mint, Address::new_from_array(expected_mint));
    }

    #[test]
    fn test_parse_token_account_owner() {
        let mut data = [0u8; 165];
        let expected_owner = [84u8; 32];
        data[32..64].copy_from_slice(&expected_owner);

        let owner = parse_token_account_owner(&data).unwrap();
        assert_eq!(owner, Address::new_from_array(expected_owner));
    }
}
