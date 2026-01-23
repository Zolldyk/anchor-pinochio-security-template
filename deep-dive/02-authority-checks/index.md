# Authority Checks Pattern - Deep Dive

## Overview

This deep-dive documentation explores authority check vulnerabilities in Solana programs, one of the most critical security patterns to understand. Missing or improper authority validation leads to **privilege escalation attacks**, where unauthorized users can perform administrative actions, steal funds, or disrupt protocol operations.

Authority check failures are responsible for some of the largest exploits in Solana history, including the $52M Cashio hack (March 2022) and contributed to the $326M Wormhole bridge exploit (February 2022).

## Learning Objectives

After completing this deep-dive, you will understand:

1. How Solana's account ownership model relates to authority validation
2. The difference between `AccountInfo` and `Signer` in Anchor
3. Common authority check mistakes that lead to privilege escalation
4. How to use `constraint` expressions and helper functions for validation
5. Real-world incidents caused by authority check failures
6. How Solana authorization compares to traditional web authorization (RBAC/ACL)
7. A systematic approach to determining what authority checks are needed

## Table of Contents

| Section | Description |
|---------|-------------|
| [1. Ownership Model](./ownership-model.md) | Solana's account ownership model and authority relationships |
| [2. Common Mistakes](./common-mistakes.md) | Authority check mistakes that lead to exploits |
| [3. Real-World Examples](./real-world-examples.md) | Historical incidents and case studies |
| [4. Web Comparison](./web-comparison.md) | Mapping RBAC/ACL concepts to Solana |
| [5. Decision Tree](./decision-tree.md) | Systematic approach to authority check design |
| [6. Common Patterns](./common-patterns.md) | Secure authority patterns with code examples |

## Pattern 02 Implementation

This documentation references the **Pattern 02: Authority Checks** implementation in this repository:

```
patterns/02-authority-checks/
├── programs/
│   ├── vulnerable/src/lib.rs    # Demonstrates authority vulnerabilities
│   └── secure/src/lib.rs        # Demonstrates secure authority patterns
└── tests/
    └── exploit-demo.ts          # Attack scenarios and security verification
```

The vulnerable program shows what happens when authority checks are missing:
- Using `UncheckedAccount` instead of `Signer`
- No `constraint` validating caller against stored authority
- No `is_admin()` helper for array membership checks

The secure program demonstrates proper implementation:
- Using `Signer<'info>` for cryptographic signature verification
- Using `constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin`
- Using `is_admin()` helper for admin_list membership validation

## Quick Reference: Vulnerable vs Secure

| Aspect | Vulnerable | Secure |
|--------|------------|--------|
| Caller type | `UncheckedAccount<'info>` | `Signer<'info>` |
| Super admin check | None | `constraint = caller.key() == admin_config.super_admin` |
| Admin list check | None | `constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key)` |
| PDA validation | `#[account(mut)]` | `#[account(mut, seeds = [b"admin_config"], bump)]` |
| Error handling | Silent failures | Custom errors: `NotSuperAdmin`, `NotAdmin` |

## Authority Hierarchy

Pattern 02 implements a three-tier authority hierarchy:

```
super_admin (highest privilege)
    ├── Can pause/unpause protocol
    ├── Can add/remove admins
    │
    └── admin_list members
            ├── Can modify fees
            ├── Can create managers
            │
            └── managers
                    └── Limited delegated permissions
```

Each level requires proper validation before any privileged operation.

## Key Takeaways

1. **Always use `Signer<'info>`** for accounts that must authorize an action
2. **Add constraint checks** validating caller against stored authority fields
3. **Use PDA seeds constraints** to prevent account substitution attacks
4. **Validate authority at every level** of the authority chain
5. **Use helper functions** like `is_admin()` for consistent validation logic

## Related Patterns

- Pattern 01: Missing Account Validation (Coming Soon) - Account existence and ownership checks
- Pattern 03: Integer Overflow (Coming Soon)
- Pattern 04: Reentrancy (Coming Soon)

## External Resources

- [Anchor Constraints Documentation](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Sealevel Attacks Repository](https://github.com/coral-xyz/sealevel-attacks)
