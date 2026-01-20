//! Minimal Pinocchio spike to verify compatibility with Anchor workspace

use pinocchio::{entrypoint, AccountView, Address, ProgramResult};

// Program ID constant (Pinocchio 0.10 uses Address instead of Pubkey)
pub const ID: Address = Address::new_from_array([
    0x53, 0x70, 0x69, 0x6b, 0x65, 0x50, 0x69, 0x6e, // SpikePinocchio...
    0x6f, 0x63, 0x63, 0x68, 0x69, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]);

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Address,
    _accounts: &[AccountView],
    _instruction_data: &[u8],
) -> ProgramResult {
    Ok(())
}
