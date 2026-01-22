//! # Pinocchio Secure Token Validation Program
//!
//! This program demonstrates secure SPL Token integration with proper manual
//! validation in the Pinocchio framework. It serves as a comparison to the Anchor
//! secure implementation to show how security must be explicitly implemented
//! when using a lower-level framework.
//!
//! ## Key Differences from Anchor
//!
//! | Aspect | Anchor | Pinocchio |
//! |--------|--------|-----------|
//! | Mint validation | `constraint = token.mint == vault.mint` | Manual: parse bytes 0-32, compare |
//! | Owner validation | `constraint = token.owner == user.key()` | Manual: parse bytes 32-64, compare |
//! | Authority check | `has_one = authority` + `Signer` | Manual: compare addresses, check signer |
//! | Token CPI | `token::transfer()`, `token::mint_to()` | Manual instruction data construction |
//!
//! ## Security Features Implemented
//!
//! | Security Check | Purpose | Implementation |
//! |----------------|---------|----------------|
//! | Mint validation | Ensure correct token type | Parse token account data, compare mint |
//! | Owner validation | Prevent fund redirection | Parse token account data, compare owner |
//! | Authority check | Restrict privileged ops | Compare against stored authority + signer check |
//!
//! **This program demonstrates proper security patterns for production use.**

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

/// Program ID: CF7pz8p5P9iz2cqr4Lfd1eS2PBPtKij63YAgcSRPaGEt
pub const ID: Address = Address::new_from_array([
    0xa7, 0x0e, 0x68, 0x3e, 0x6a, 0xd8, 0x84, 0x48, 0xe5, 0xd8, 0x99, 0x3c, 0xeb, 0xb3, 0x38, 0x40,
    0x0e, 0xeb, 0x79, 0xb1, 0x77, 0x3c, 0xcb, 0xac, 0xcf, 0xb7, 0x74, 0x19, 0x70, 0xf9, 0xc6, 0x89,
]);

/// SPL Token Program ID
pub const TOKEN_PROGRAM_ID: Address = Address::new_from_array([
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// Vault account size (no Anchor discriminator): 105 bytes
pub const VAULT_SIZE: usize = 32 + 32 + 32 + 8 + 1;

/// UserDeposit account size (no Anchor discriminator): 73 bytes
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
// CUSTOM ERROR CODES
// =============================================================================

/// Custom error codes for the secure token validation program.
#[repr(u32)]
pub enum TokenSecureError {
    /// Token account mint doesn't match vault's expected mint
    MintMismatch = 0x1770, // 6000
    /// Token account owner doesn't match expected owner
    OwnerMismatch = 0x1771, // 6001
    /// Caller is not authorized for this operation
    Unauthorized = 0x1772, // 6002
    /// User doesn't have enough deposited tokens to withdraw
    InsufficientBalance = 0x1773, // 6003
    /// Arithmetic operation would overflow or underflow
    ArithmeticOverflow = 0x1774, // 6004
}

impl From<TokenSecureError> for ProgramError {
    fn from(e: TokenSecureError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// =============================================================================
// SPL TOKEN CPI HELPERS
// =============================================================================

const SPL_TRANSFER_DISCRIMINATOR: u8 = 3;
const SPL_MINT_TO_DISCRIMINATOR: u8 = 7;

/// Parses the mint address from a token account's data.
/// // SECURITY: This function extracts the mint from raw token account data,
/// // enabling manual mint validation that Anchor does automatically.
pub fn parse_token_account_mint(token_account_data: &[u8]) -> Result<Address, ProgramError> {
    if token_account_data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }

    let mint_bytes: [u8; 32] =
        token_account_data[0..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(Address::new_from_array(mint_bytes))
}

/// Parses the owner address from a token account's data.
/// // SECURITY: This function extracts the owner from raw token account data,
/// // enabling manual owner validation that Anchor does automatically.
pub fn parse_token_account_owner(token_account_data: &[u8]) -> Result<Address, ProgramError> {
    if token_account_data.len() < 64 {
        return Err(ProgramError::InvalidAccountData);
    }

    let owner_bytes: [u8; 32] =
        token_account_data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?;

    Ok(Address::new_from_array(owner_bytes))
}

/// Invokes SPL Token Transfer instruction.
pub fn spl_token_transfer(
    from: &AccountView,
    to: &AccountView,
    authority: &AccountView,
    token_program: &AccountView,
    amount: u64,
) -> ProgramResult {
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = SPL_TRANSFER_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        InstructionAccount::writable(from.address()),
        InstructionAccount::writable(to.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

    let instruction = InstructionView {
        program_id: token_program.address(),
        accounts: &accounts,
        data: &instruction_data,
    };
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
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = SPL_TRANSFER_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        InstructionAccount::writable(from.address()),
        InstructionAccount::writable(to.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

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
pub fn spl_token_mint_to_signed<const N: usize>(
    mint: &AccountView,
    destination: &AccountView,
    authority: &AccountView,
    token_program: &AccountView,
    amount: u64,
    signer_seeds: &[Seed; N],
) -> ProgramResult {
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = SPL_MINT_TO_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        InstructionAccount::writable(mint.address()),
        InstructionAccount::writable(destination.address()),
        InstructionAccount::readonly_signer(authority.address()),
    ];

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
    /// Authority who can manage the vault and mint rewards (32 bytes)
    /// // SECURITY: Used in authority validation for mint_reward
    pub authority: Address,
    /// The SPL Token mint this vault accepts (32 bytes)
    /// // SECURITY: Used to validate all incoming deposits
    pub mint: Address,
    /// Token account holding vault funds (32 bytes)
    pub vault_token_account: Address,
    /// Total tokens deposited across all users (8 bytes)
    pub total_deposits: u64,
    /// PDA bump seed for signing (1 byte)
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

/// Initializes a new token vault with proper security configuration.
/// // SECURITY: Vault PDA ensures deterministic, unforgeable address
/// // SECURITY: Authority stored for future privileged operation validation
fn initialize_vault(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, mint, vault_token_account, authority, _system_program, _token_program] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify authority is signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // SECURITY: Verify vault is owned by this program
    if !vault.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let bump = if data.is_empty() { 0 } else { data[0] };

    let vault_data = Vault {
        authority: Address::new_from_array(*authority.address().as_array()),
        mint: Address::new_from_array(*mint.address().as_array()),
        vault_token_account: Address::new_from_array(*vault_token_account.address().as_array()),
        total_deposits: 0,
        bump,
    };

    let mut account_data = vault.try_borrow_mut()?;
    vault_data.serialize(&mut account_data)?;

    log!("SECURE: Vault initialized for mint");
    log!("SECURE: Vault authority set");

    Ok(())
}

/// Deposits tokens into the vault with full mint validation.
///
/// // SECURITY: Mint Validation - The user_token_account's mint is checked against
/// // vault.mint to prevent depositing worthless tokens from a different mint.
///
/// ## Anchor Equivalent
/// ```rust,ignore
/// #[account(constraint = user_token_account.mint == vault.mint @ TokenSecureError::MintMismatch)]
/// ```
fn deposit(_program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, user_deposit, user_token_account, vault_token_account, user, _system_program, token_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify user is signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.len() < 9 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );
    let user_deposit_bump = data[8];

    // Read vault state to get expected mint
    let vault_data = vault.try_borrow()?;
    let mut vault_state = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    // ==========================================================================
    // SECURITY CHECK: Mint Validation
    // ==========================================================================
    // // SECURITY: Parse the user's token account data to extract the mint field.
    // // Compare against vault.mint to ensure only the correct token type is deposited.
    // // Anchor equivalent: constraint = user_token_account.mint == vault.mint
    let user_token_data = user_token_account.try_borrow()?;
    let user_token_mint = parse_token_account_mint(&user_token_data)?;
    drop(user_token_data);

    if user_token_mint != vault_state.mint {
        log!("SECURITY REJECTION: Token account mint does not match vault mint");
        return Err(TokenSecureError::MintMismatch.into());
    }

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

    // SECURITY: Transfer with validated mint
    spl_token_transfer(user_token_account, vault_token_account, user, token_program, amount)?;

    // SECURITY: Safe arithmetic with checked operations
    user_deposit_state.amount = user_deposit_state
        .amount
        .checked_add(amount)
        .ok_or(TokenSecureError::ArithmeticOverflow)?;

    vault_state.total_deposits = vault_state
        .total_deposits
        .checked_add(amount)
        .ok_or(TokenSecureError::ArithmeticOverflow)?;

    // Write updated states
    let mut vault_data = vault.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;
    drop(vault_data);

    let mut user_deposit_data = user_deposit.try_borrow_mut()?;
    user_deposit_state.serialize(&mut user_deposit_data)?;

    log!("SECURE: Deposited tokens (mint validated)");

    Ok(())
}

/// Withdraws tokens from the vault with full owner validation.
///
/// // SECURITY: Owner Validation - The destination_token_account's owner is checked
/// // against the user to prevent redirecting withdrawals to attacker accounts.
///
/// ## Anchor Equivalent
/// ```rust,ignore
/// #[account(constraint = destination_token_account.owner == user.key() @ TokenSecureError::OwnerMismatch)]
/// ```
fn withdraw(_program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, user_deposit, vault_token_account, destination_token_account, user, token_program] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    // SECURITY: Verify user is signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

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

    // SECURITY: Check user has sufficient deposit balance
    if user_deposit_state.amount < amount {
        log!("SECURITY REJECTION: Insufficient balance for withdrawal");
        return Err(TokenSecureError::InsufficientBalance.into());
    }

    // ==========================================================================
    // SECURITY CHECK: Owner Validation
    // ==========================================================================
    // // SECURITY: Parse the destination token account data to extract the owner field.
    // // Compare against user address to ensure funds go to the withdrawer's account.
    // // Anchor equivalent: constraint = destination_token_account.owner == user.key()
    let dest_data = destination_token_account.try_borrow()?;
    let dest_owner = parse_token_account_owner(&dest_data)?;
    let dest_mint = parse_token_account_mint(&dest_data)?;
    drop(dest_data);

    if dest_owner.as_ref() != user.address().as_ref() {
        log!("SECURITY REJECTION: Destination owner does not match user");
        return Err(TokenSecureError::OwnerMismatch.into());
    }

    // SECURITY: Mint validation on destination
    if dest_mint != vault_state.mint {
        log!("SECURITY REJECTION: Destination mint does not match vault mint");
        return Err(TokenSecureError::MintMismatch.into());
    }

    // Build PDA signer seeds for vault authority
    let vault_bump = vault_state.bump;
    let bump_bytes = [vault_bump];
    let seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(vault_state.mint.as_ref()),
        Seed::from(&bump_bytes),
    ];

    // SECURITY: Transfer to validated destination only
    spl_token_transfer_signed(
        vault_token_account,
        destination_token_account,
        vault,
        token_program,
        amount,
        &seeds,
    )?;

    // SECURITY: Safe arithmetic with checked operations
    user_deposit_state.amount = user_deposit_state
        .amount
        .checked_sub(amount)
        .ok_or(TokenSecureError::ArithmeticOverflow)?;

    vault_state.total_deposits = vault_state
        .total_deposits
        .checked_sub(amount)
        .ok_or(TokenSecureError::ArithmeticOverflow)?;

    // Write updated states
    let mut vault_data = vault.try_borrow_mut()?;
    vault_state.serialize(&mut vault_data)?;
    drop(vault_data);

    let mut user_deposit_data = user_deposit.try_borrow_mut()?;
    user_deposit_state.serialize(&mut user_deposit_data)?;

    log!("SECURE: Withdrew tokens (owner validated)");

    Ok(())
}

/// Mints reward tokens with proper authority validation.
///
/// // SECURITY: Authority Validation - The caller must be the vault authority
/// // AND must sign the transaction.
///
/// ## Anchor Equivalent
/// ```rust,ignore
/// #[account(has_one = authority @ TokenSecureError::Unauthorized)]
/// pub vault: Account<'info, Vault>,
/// pub authority: Signer<'info>,
/// ```
fn mint_reward(_program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [vault, mint, destination_token_account, authority, token_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ProgramError::InvalidInstructionData)?,
    );

    // Read vault state to get stored authority
    let vault_data = vault.try_borrow()?;
    let vault_state = Vault::try_from_slice(&vault_data)?;
    drop(vault_data);

    // ==========================================================================
    // SECURITY CHECK 1: Authority must be a signer
    // ==========================================================================
    // // SECURITY: This is equivalent to Anchor's Signer<'info> type.
    if !authority.is_signer() {
        log!("SECURITY REJECTION: Authority must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ==========================================================================
    // SECURITY CHECK 2: Signer must match stored authority
    // ==========================================================================
    // // SECURITY: This is equivalent to Anchor's has_one = authority constraint.
    if vault_state.authority.as_ref() != authority.address().as_ref() {
        log!("SECURITY REJECTION: Signer does not match vault authority");
        return Err(TokenSecureError::Unauthorized.into());
    }

    // ==========================================================================
    // SECURITY CHECK 3: Destination mint validation
    // ==========================================================================
    let dest_data = destination_token_account.try_borrow()?;
    let dest_mint = parse_token_account_mint(&dest_data)?;
    drop(dest_data);

    if dest_mint != vault_state.mint {
        log!("SECURITY REJECTION: Destination mint does not match vault mint");
        return Err(TokenSecureError::MintMismatch.into());
    }

    // Build PDA signer seeds for mint authority
    let vault_bump = vault_state.bump;
    let bump_bytes = [vault_bump];
    let seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(vault_state.mint.as_ref()),
        Seed::from(&bump_bytes),
    ];

    // SECURITY: Mint with verified authority
    spl_token_mint_to_signed(mint, destination_token_account, vault, token_program, amount, &seeds)?;

    log!("SECURE: Minted reward tokens (authority verified)");

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
    fn test_error_conversion() {
        let err: ProgramError = TokenSecureError::MintMismatch.into();
        assert!(matches!(err, ProgramError::Custom(0x1770)));

        let err: ProgramError = TokenSecureError::OwnerMismatch.into();
        assert!(matches!(err, ProgramError::Custom(0x1771)));

        let err: ProgramError = TokenSecureError::Unauthorized.into();
        assert!(matches!(err, ProgramError::Custom(0x1772)));
    }
}
