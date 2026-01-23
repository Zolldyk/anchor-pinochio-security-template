# Learning Path

A guided progression through Solana security vulnerability patterns, from foundational concepts to advanced DeFi-specific attacks.

## Overview

This learning path is designed to build your understanding of Solana program security incrementally. Each pattern builds on concepts from previous ones, so we recommend following the order below.

**All patterns include both Anchor and Pinocchio implementations**, allowing you to compare how security concepts translate across frameworks. This dual-implementation approach helps you understand that security principles are framework-agnostic - the same vulnerabilities and defenses apply regardless of your development approach.

## Prerequisites

Before starting, you should be familiar with:
- Basic Rust programming (ownership, borrowing, error handling)
- Solana account model and PDAs
- Anchor framework fundamentals
- TypeScript for writing tests

## Study Progression

The patterns are organized into three levels with dependencies:

```
Level 1: Fundamentals (Start Here)
├── Pattern 01: Missing Validation (Beginner)
└── Pattern 02: Authority Checks (Beginner)
        │
        ▼
Level 2: Arithmetic & Data Safety
└── Pattern 03: Unsafe Arithmetic (Intermediate)
        │
        ▼
Level 3: Advanced Patterns
├── Pattern 04: CPI Re-entrancy (Advanced) ─ Requires 01-03
├── Pattern 05: PDA Derivation (Advanced) ─── Requires 01-02
└── Pattern 06: Token Validation (Advanced) ─ Requires 01-05
```

**Patterns 01-03** can be studied sequentially. **Patterns 04-06** build on earlier concepts and can be studied in any order after completing the prerequisites.

---

## Level 1: Fundamentals

### Pattern 01: Missing Validation

**Difficulty:** Beginner | **Time:** 1-2 hours

Learn the importance of validating all inputs and account constraints. This foundational pattern covers account ownership validation, signer verification, and data bounds checking.

**Path:** `patterns/01-missing-validation/`

#### Learning Objectives

After completing this pattern, you will:
- Understand why every instruction must verify account signers
- Learn how Solana's account ownership model affects security
- Know how to use Anchor constraints (`Signer<'info>`, `has_one`, `constraint`) to enforce validation
- Recognize the difference between vulnerable and secure implementation patterns

#### Prerequisites

- Basic Rust programming (structs, enums, error handling)
- Understanding of public key cryptography (signing, verification)
- Basic familiarity with Solana accounts

#### Key Takeaways

- **Always use `Signer<'info>`** for accounts that must authorize an action - never use `AccountInfo` for authority accounts
- **Add `has_one` constraints** to verify account ownership relationships
- **Trust no input** - assume every account passed could be malicious; validate everything
- Both signer AND owner validation are needed - signer alone doesn't prove account ownership

#### Self-Assessment Questions

1. What is the difference between `AccountInfo<'info>` and `Signer<'info>`? When would you use each?
2. If a program only uses `Signer<'info>` but omits `has_one = authority`, what attack is still possible?
3. Why does Solana's permissionless transaction model make input validation critical?

---

### Pattern 02: Authority Checks

**Difficulty:** Beginner | **Time:** 1-2 hours

Understand access control and privilege separation in Solana programs. Learn admin-only operations, owner checks for user data, and PDA authority patterns.

**Path:** `patterns/02-authority-checks/`

**Deep Dive:** [Authority Checks Documentation](deep-dive/02-authority-checks/)

#### Learning Objectives

After completing this pattern, you will:
- Understand access control and privilege separation concepts
- Implement multi-tier authority hierarchies (super_admin, admin, manager)
- Use PDA seeds constraints to prevent account substitution
- Apply reusable validation helper functions for consistent security

#### Prerequisites

- **Pattern 01** - Signer and ownership validation fundamentals
- Understanding of role-based access control concepts

#### Key Takeaways

- **Always use `Signer<'info>`** for accounts that authorize actions - `UncheckedAccount` allows impersonation
- **Add constraint checks** validating caller against stored authority fields
- **Use PDA seeds constraints** to prevent fake account substitution attacks
- **Create helper functions** like `is_admin()` for consistent validation across instructions

#### Self-Assessment Questions

1. Why is using `UncheckedAccount` for a caller account a critical vulnerability?
2. How does the `seeds` constraint on a PDA prevent account substitution attacks?
3. In a three-tier hierarchy (super_admin > admin > manager), what checks are needed when an admin creates a manager?

---

## Level 2: Arithmetic & Data Safety

### Pattern 03: Unsafe Arithmetic

**Difficulty:** Intermediate | **Time:** 2-3 hours

Master safe arithmetic in Solana programs. Understand integer overflow/underflow risks, Rust's arithmetic methods, and how to combine input validation with safe operations.

**Path:** `patterns/03-unsafe-arithmetic/`

**Deep Dive:** [Unsafe Arithmetic Deep Dive](deep-dive/unsafe-arithmetic.md)

#### Learning Objectives

After completing this pattern, you will:
- Understand Rust's debug vs release mode arithmetic behavior
- Know when to use `checked_*`, `wrapping_*`, and `saturating_*` methods
- Recognize how overflow/underflow can corrupt program state
- Implement defense-in-depth with input validation AND safe arithmetic

#### Prerequisites

- **Patterns 01-02** - Input validation fundamentals
- Understanding of Rust integer types (u64, i64, etc.)
- Knowledge of how Solana programs compile (release mode)

#### Key Takeaways

- **Always use `checked_*` methods** for financial calculations - they return `None` on overflow instead of wrapping silently
- **Rust's safety guarantees depend on compilation mode** - release mode wraps by default
- **Validate inputs BEFORE arithmetic** - define constants like `MAX_DEPOSIT` and check against them
- **Framework doesn't determine security** - both Anchor and Pinocchio require the same defensive patterns

#### Self-Assessment Questions

1. Why does `balance.wrapping_sub(withdrawal)` create a vulnerability even in "safe" Rust?
2. What is the difference between `checked_add()` and `saturating_add()`? When would you use each?
3. A user has balance=100 and attempts withdraw(200). Walk through what happens with `wrapping_sub` vs `checked_sub`.

---

## Level 3: Advanced Patterns

### Pattern 04: CPI Re-entrancy

**Difficulty:** Advanced | **Time:** 3-4 hours

Understand how Solana's Cross-Program Invocation (CPI) creates re-entrancy attack vectors. Learn the Checks-Effects-Interactions (CEI) pattern adapted for Solana and implement re-entrancy guards.

**Path:** `patterns/04-cpi-reentrancy/`

**Deep Dive:** [CPI Re-entrancy Deep Dive](deep-dive/cpi-reentrancy.md)

#### Learning Objectives

After completing this pattern, you will:
- Understand how CPI creates re-entrancy attack vectors in Solana
- Implement the Checks-Effects-Interactions (CEI) pattern for safe CPI ordering
- Add re-entrancy guards as defense-in-depth
- Compare Ethereum vs Solana re-entrancy differences
- Understand CPI depth limits and their security implications

#### Prerequisites

- **Patterns 01-03** - Account validation and safe arithmetic
- Understanding of CPI basics (`invoke`, `invoke_signed`)
- Familiarity with Solana's execution model

#### Key Takeaways

- **Always use Checks-Effects-Interactions (CEI)** - update all state BEFORE making any CPI calls
- **Add re-entrancy guards for critical operations** - a simple boolean flag provides defense-in-depth
- **CPI depth limit (4) is not sufficient protection** - one re-entry is enough to exploit most vulnerabilities
- **Think like an attacker** - for any CPI, ask "What if the invoked program calls back immediately?"

#### Self-Assessment Questions

1. A function reads balance, validates it, makes a CPI, then updates balance. What is the vulnerability window?
2. How does Solana's re-entrancy differ from Ethereum's? Why does the CPI depth limit not prevent attacks?
3. What are the two complementary defenses against CPI re-entrancy, and why should you use both?

---

### Pattern 05: PDA Derivation Issues

**Difficulty:** Advanced | **Time:** 3-4 hours

Understand how PDAs are derived and why proper validation is critical. Learn about canonical bumps, seed validation, and hierarchical PDA design patterns.

**Path:** `patterns/05-pda-derivation/`

#### Learning Objectives

After completing this pattern, you will:
- Understand how PDAs are derived and why the canonical bump matters
- Know why PDAs must be off-curve (no private key) for security
- Identify common PDA vulnerability patterns (missing validation, user-controlled seeds)
- Use Anchor's `seeds`, `bump`, and `has_one` constraints effectively
- Apply best practices for hierarchical PDA design

#### Prerequisites

- **Patterns 01-02** - Account validation and authority checks
- Understanding of PDA basics (`find_program_address`)
- Familiarity with Anchor constraint syntax

#### Key Takeaways

- **Always re-derive PDAs** on every access - use `seeds` constraint, not just on initialization
- **Enforce canonical bumps** - accept only the highest valid bump to prevent multiple "valid" accounts
- **Validate all relationships** - use `has_one` to ensure accounts are properly linked
- **Design seeds carefully** - include all relevant identifiers; order matters for derivation

#### Self-Assessment Questions

1. What is a canonical bump, and why does accepting non-canonical bumps create a vulnerability?
2. A program accepts `treasury: AccountInfo<'info>` without type checking. How can an attacker exploit this?
3. Why must you include the treasury PDA in user_deposit seeds to create a secure hierarchical relationship?

---

### Pattern 06: Token Validation

**Difficulty:** Advanced | **Time:** 3-4 hours

Learn critical SPL Token integration security. Understand token account structure, mint validation, owner validation, and authority checks for minting/burning operations.

**Path:** `patterns/06-token-validation/`

#### Learning Objectives

After completing this pattern, you will:
- Understand token account structure (mint, owner, authority fields)
- Know why mint validation prevents token substitution attacks
- Implement owner validation to prevent withdrawal redirection
- Require authority signatures for privileged minting/burning operations

#### Prerequisites

- **Patterns 01-05** - All previous patterns (this pattern synthesizes concepts)
- Understanding of SPL Token basics (token accounts, mints, authorities)
- Familiarity with token account data layout

#### Key Takeaways

- **Always validate token mint** - without mint validation, attackers deposit worthless tokens and withdraw valuable ones
- **Always validate token owner for withdrawals** - prevents attackers from redirecting funds to their accounts
- **Always require authority signature** - a pubkey alone can be passed by anyone; verify with `has_one` and `Signer`
- **Test the exploits** - if you can't demonstrate the vulnerability, you haven't proven it's fixed

#### Self-Assessment Questions

1. An attacker creates their own mint and deposits 1000 tokens. Without mint validation, what happens when they withdraw?
2. What is the owner bypass attack, and how does adding `constraint = token.owner == user.key()` prevent it?
3. Why is `has_one = authority` on a vault account not sufficient - why must authority also be `Signer<'info>`?

---

## Study Approach

For each pattern, we recommend:

1. **Read the README** - Understand the vulnerability concept and why it matters
2. **Study Vulnerable Code** - See exactly how the vulnerability manifests in code
3. **Study Secure Code** - Learn the proper mitigation techniques
4. **Run Tests** - Observe the vulnerability being exploited and blocked
5. **Compare Frameworks** - Study both Anchor and Pinocchio implementations
6. **Read Deep Dives** - For comprehensive understanding of complex patterns
7. **Try to Break It** - Modify tests to explore edge cases

### Framework Comparison Value

All patterns include implementations in both **Anchor** (declarative, high-level) and **Pinocchio** (explicit, low-level). This comparison helps you:

- Understand that security principles are framework-agnostic
- See how declarative constraints translate to explicit validation code
- Make informed framework choices based on your project needs
- Recognize vulnerabilities regardless of the codebase style you're auditing

## Testing Commands

```bash
# Run all tests for a pattern
cd patterns/<pattern-name>
anchor test

# Run specific test file
npx ts-mocha -p ./tsconfig.json -t 1000000 tests/<test-file>.ts

# Build all programs
anchor build

# Run with verbose output to see security logs
anchor test -- --nocapture
```

## Additional Resources

### Official Documentation

- [Solana Security Best Practices](https://solana.com/docs/programs#security) - Official security guidelines
- [Anchor Security Considerations](https://www.anchor-lang.com/docs/security) - Anchor-specific security
- [Solana Account Model](https://solana.com/docs/core/accounts) - Understanding accounts and ownership

### Security Research

- [Sealevel Attacks Repository](https://github.com/coral-xyz/sealevel-attacks) - Common Solana vulnerability patterns with examples
- [Neodyme Blog](https://blog.neodyme.io/) - Solana security research and audits
- [sec3 Security Scanner](https://www.sec3.dev/) - Automated security scanning for Solana programs

### Historical Context

- [The DAO Hack Analysis](https://blog.ethereum.org/2016/06/17/critical-update-re-dao-vulnerability) - Re-entrancy context from Ethereum
- [Solana Ecosystem Security Incidents](https://github.com/coral-xyz/sealevel-attacks#real-world-examples) - Real-world vulnerability examples

### Smart Contract Security

- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/) - General smart contract vulnerabilities
