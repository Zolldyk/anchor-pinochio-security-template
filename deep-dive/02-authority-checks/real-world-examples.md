# Real-World Authority Check Exploits

## Overview

Authority check vulnerabilities have caused some of the largest losses in Solana and blockchain history. This section documents real-world incidents, analyzes what went wrong, and extracts lessons for developers.

Learning from these incidents helps you:
- Understand the real-world impact of authority check failures
- Recognize similar patterns in your own code
- Appreciate why security audits focus heavily on authorization

## Incident Summary Table

| Incident | Date | Loss | Vulnerability Type | Root Cause |
|----------|------|------|-------------------|------------|
| Cashio | March 2022 | $52M | Missing signer validation | Unchecked collateral authority |
| Wormhole | February 2022 | $326M | Signature verification bypass | Deprecated function without validation |
| Slope Wallet | August 2022 | $4M+ | Private key exposure | Authority keys logged to third-party |

## Incident 1: Cashio (March 2022)

### Summary

Cashio was a decentralized stablecoin protocol on Solana. An attacker exploited a missing signer validation in the mint collateral function, allowing them to mint unlimited CASH tokens without depositing collateral.

**Loss:** ~$52 million

### The Vulnerability

The Cashio protocol allowed users to mint CASH stablecoins by depositing collateral. The vulnerability was in how the protocol validated the collateral being deposited.

**Simplified vulnerable pattern:**

```rust
// VULNERABILITY: Missing validation of collateral account authority
pub struct MintCash<'info> {
    #[account(mut)]
    pub crate_collateral_tokens: Account<'info, TokenAccount>,

    #[account(mut)]
    pub depositor_collateral: Account<'info, TokenAccount>,

    // VULNERABILITY: No validation that this account is a legitimate
    // collateral type approved by the protocol
    pub collateral_mint: Account<'info, Mint>,

    // VULNERABILITY: No constraint linking collateral to protocol config
    /// CHECK: Missing validation
    pub collateral_account: UncheckedAccount<'info>,
}
```

### Attack Flow

```
1. Attacker creates fake collateral account
   └── No validation that collateral is approved by protocol

2. Attacker calls mint_cash with fake collateral
   └── Protocol accepts any account that has correct structure

3. Attacker receives CASH tokens without real collateral
   └── Mints unlimited stablecoins

4. Attacker swaps CASH for real assets on DEXs
   └── Drains liquidity pools
```

### What Should Have Been Validated

```rust
// SECURITY: Proper collateral validation
pub struct MintCash<'info> {
    #[account(
        mut,
        // SECURITY: Verify crate belongs to this bank
        constraint = crate_collateral_tokens.owner == crate_token.key()
    )]
    pub crate_collateral_tokens: Account<'info, TokenAccount>,

    #[account(
        // SECURITY: Verify collateral mint is in approved list
        constraint = bank.is_approved_collateral(&collateral_mint.key())
            @ ErrorCode::InvalidCollateral
    )]
    pub collateral_mint: Account<'info, Mint>,

    #[account(
        // SECURITY: Verify collateral account authority
        has_one = authority @ ErrorCode::InvalidAuthority
    )]
    pub bank: Account<'info, Bank>,

    pub authority: Signer<'info>,
}
```

### Lessons Learned

| Lesson | Application to Pattern 02 |
|--------|--------------------------|
| Validate all account relationships | Use `has_one` and custom constraints |
| Don't trust account structure alone | Always check against protocol state |
| Whitelist approved entities | Admin_list pattern for authorized users |
| Authority chains must be complete | Validate back to root authority |

---

## Incident 2: Wormhole Bridge (February 2022)

### Summary

Wormhole is a cross-chain bridge connecting Solana to other blockchains. An attacker exploited a vulnerability in the signature verification system, bypassing guardian approval to mint 120,000 wrapped ETH (wETH) on Solana without locking real ETH on Ethereum.

**Loss:** ~$326 million (largest DeFi hack at the time)

### The Vulnerability

Wormhole used a deprecated Solana function (`load_current_index`) that didn't properly validate that the guardian set had actually signed the message.

**Simplified vulnerable pattern:**

```rust
// VULNERABILITY: Using deprecated function without proper validation
fn verify_signatures(
    accs: &VerifySignatures,
    data: VerifySignaturesData,
) -> Result<()> {
    // VULNERABILITY: load_current_index was deprecated and
    // didn't validate the instruction was actually executed
    let current_instruction = solana_program::sysvar::instructions::load_current_index(
        &accs.instruction_acc.try_borrow_data()?
    );

    // Attacker could bypass this check by crafting special transaction
    // that made it appear signatures were verified when they weren't
}
```

### Attack Flow

```
1. Attacker creates malicious Solana transaction
   └── Exploits deprecated sysvar instruction handling

2. Transaction bypasses guardian signature verification
   └── load_current_index doesn't validate actual execution

3. Wormhole contract believes message is signed by guardians
   └── Accepts fraudulent "transfer complete" message

4. Attacker mints 120,000 wETH on Solana
   └── Without locking real ETH on Ethereum

5. Attacker bridges/swaps wETH for real assets
   └── Drains protocol reserves
```

### What Should Have Been Done

```rust
// SECURITY: Proper signature verification
fn verify_signatures(
    accs: &VerifySignatures,
    data: VerifySignaturesData,
) -> Result<()> {
    // SECURITY: Use current, maintained function
    let instruction_sysvar = &accs.instruction_acc;

    // SECURITY: Explicitly verify the secp256k1 instruction exists
    // and was executed in this transaction
    let secp_ix = sysvar::instructions::get_instruction_relative(
        -1, // Previous instruction
        instruction_sysvar
    )?;

    // SECURITY: Verify it's the expected program
    if secp_ix.program_id != secp256k1_program::id() {
        return Err(ErrorCode::InvalidSignatureVerification.into());
    }

    // SECURITY: Verify signature data matches expected guardians
    verify_guardian_signatures(&secp_ix.data, &accs.guardian_set)?;

    Ok(())
}
```

### Lessons Learned

| Lesson | Application to Pattern 02 |
|--------|--------------------------|
| Don't use deprecated functions | Stay current with Solana/Anchor updates |
| Verify the verifier | Ensure verification actually happened |
| Defense in depth | Multiple validation layers |
| Signature != Authorization | Signatures must be tied to specific authority |

---

## Incident 3: Slope Wallet (August 2022)

### Summary

Slope was a popular Solana mobile wallet. The wallet inadvertently logged users' private keys to a centralized logging service (Sentry), exposing authority credentials to potential attackers.

**Loss:** ~$4 million+ across thousands of wallets

### The Vulnerability

This wasn't a smart contract vulnerability, but rather an operational security failure that exposed authority credentials.

**What happened:**

```javascript
// VULNERABILITY: Logging sensitive data
function importWallet(seedPhrase) {
    // VULNERABILITY: Seed phrase sent to third-party logging service
    logger.info("Wallet import", { seedPhrase: seedPhrase });

    // Even if logging is "secure", this violates principle of
    // never transmitting or storing raw private keys
}
```

### Why This Matters for Smart Contract Developers

Even if your smart contract is perfectly secure, authority can be compromised at other layers:

```
APPLICATION LAYER
    ├── Wallet software (compromised in Slope)
    ├── Browser extensions
    └── Key management systems

SMART CONTRACT LAYER
    ├── Authority validation (Pattern 02 focus)
    ├── Signer checks
    └── Constraint validation

INFRASTRUCTURE LAYER
    ├── RPC nodes
    ├── Validators
    └── Network security
```

### Lessons Learned

| Lesson | Application |
|--------|------------|
| Authority extends beyond contracts | Consider full system security |
| Private keys must never be logged | Audit dependencies for key handling |
| Multi-sig for high-value operations | Require multiple authorities |
| Key rotation capabilities | Design for authority key compromise |

---

## Pattern 02 Parallels

The vulnerabilities in these real-world incidents parallel the issues demonstrated in Pattern 02:

### Cashio ↔ Missing Authority Validation

| Cashio | Pattern 02 Vulnerable |
|--------|----------------------|
| Accepted any collateral account | Accepts any caller as admin |
| No whitelist validation | No admin_list check |
| Missing `has_one` constraint | Missing `constraint` on admin_config |

**Vulnerable Pattern 02 code:**

```rust
// VULNERABILITY: No validation that caller is super_admin
// Just like Cashio didn't validate collateral was approved
pub caller: UncheckedAccount<'info>,
```

### Wormhole ↔ Signature Verification Bypass

| Wormhole | Pattern 02 Vulnerable |
|----------|----------------------|
| Signature check bypassed | Signer check missing |
| Used deprecated validation | Used UncheckedAccount |
| Attacker impersonated guardians | Attacker impersonates super_admin |

**Vulnerable Pattern 02 code:**

```rust
// VULNERABILITY: No signer verification
// Just like Wormhole's signature verification was bypassed
/// CHECK: Intentionally unchecked to demonstrate vulnerability.
pub caller: UncheckedAccount<'info>,
```

### Slope ↔ Authority Chain Compromise

| Slope | Pattern 02 Concept |
|-------|-------------------|
| Private keys exposed | Authority credentials |
| Centralized logging | Single point of failure |
| All user wallets affected | All dependent operations affected |

**Pattern 02 secure mitigation:**

```rust
// SECURITY: Multiple authority levels provide defense in depth
// Even if one admin is compromised, super_admin functions are protected
constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
```

---

## Hypothetical Scenarios Based on Pattern 02

If Pattern 02's vulnerable program were deployed with real value:

### Scenario 1: Admin Privilege Escalation

**Attack:**
1. Attacker calls `add_admin` passing themselves as both `caller` and `new_admin`
2. No signature required, no super_admin check
3. Attacker is now an admin

**Impact:**
- Attacker can modify protocol fees (set to 100%)
- Attacker can create managers with full permissions
- All user transactions have fees stolen

### Scenario 2: Protocol Pause DoS

**Attack:**
1. Attacker calls `pause_protocol` with any pubkey as caller
2. Protocol is paused, blocking all operations
3. Legitimate super_admin cannot unpause (no unpause function in vulnerable version)

**Impact:**
- Complete protocol shutdown
- Users cannot access funds
- Reputational damage, potential permanent loss of user trust

### Scenario 3: Fee Manipulation

**Attack:**
1. Attacker monitors mempool for high-value transactions
2. Front-runs with `update_fee(10000)` (100% fee)
3. User's transaction executes with 100% fee
4. Attacker back-runs with `update_fee(100)` to hide attack

**Impact:**
- Individual users lose entire transaction amounts
- Difficult to detect without careful monitoring
- Ongoing extraction of value

---

## Prevention Strategies

Based on real-world incidents and Pattern 02 analysis:

### 1. Use Signer for All Authority Accounts

```rust
// ALWAYS
pub caller: Signer<'info>,

// NEVER for authority
pub caller: UncheckedAccount<'info>,
```

### 2. Validate Against Stored Authority

```rust
// ALWAYS
constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin

// NEVER
// (no constraint at all)
```

### 3. Use PDA Seeds Constraints

```rust
// ALWAYS
#[account(
    mut,
    seeds = [b"admin_config"],
    bump = admin_config.bump
)]
pub admin_config: Account<'info, AdminConfig>,

// NEVER
#[account(mut)]
pub admin_config: Account<'info, AdminConfig>,
```

### 4. Implement Authority Hierarchies

```rust
// Good: Clear authority levels
pub struct AdminConfig {
    pub super_admin: Pubkey,        // Highest level
    pub admin_list: [Pubkey; 3],    // Second level
    // Different operations require different levels
}
```

### 5. Audit All Validation Paths

Before deployment, verify:
- [ ] Every privileged instruction has authority checks
- [ ] All authority accounts are `Signer` types
- [ ] Constraints validate against correct authority level
- [ ] PDA seeds are enforced
- [ ] Error messages don't leak sensitive information

---

## Further Reading

### Public Security Reports

- [Cashio Post-Mortem](https://blog.cashio.app/post-mortem/) - Official incident analysis
- [Wormhole Incident Report](https://wormholecrypto.medium.com/) - Bridge security analysis
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security) - Official documentation

### Security Research

- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks) - Common Solana vulnerability patterns
- [Anchor Security Considerations](https://www.anchor-lang.com/docs/security) - Framework-specific guidance

## Next Section

Continue to [Web Authorization Comparison](./web-comparison.md) to understand how Solana authority patterns map to traditional RBAC and ACL concepts.
