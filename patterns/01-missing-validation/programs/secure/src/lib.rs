use anchor_lang::prelude::*;

// SECURITY: Placeholder program ID - will be replaced after first build
declare_id!("F1TPTovfsL5zGYWdD7xbPT9BFRhEWqpZuSK5Daif2Wd7");

#[program]
pub mod secure_missing_validation {
    use super::*;

    /// Placeholder instruction - will be replaced with secure implementation
    pub fn initialize(_ctx: Context<Initialize>) -> Result<()> {
        msg!("Secure program initialized");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
