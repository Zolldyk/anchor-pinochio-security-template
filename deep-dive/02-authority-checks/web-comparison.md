# Web Authorization Comparison

## Overview

If you come from a web development background, you're likely familiar with authorization models like RBAC (Role-Based Access Control) and ACL (Access Control Lists). This section maps these familiar concepts to their Solana equivalents, making it easier to understand how authority works on-chain.

## Quick Reference: Web to Solana Mapping

| Web Concept | Solana Equivalent | Implementation |
|-------------|------------------|----------------|
| Principal | Pubkey / Signer | `caller: Signer<'info>` |
| Session/Token | Transaction Signature | Cryptographic signature |
| Role | admin_list membership | `is_admin()` helper |
| Permission | Constraint expression | `constraint = ...` |
| ACL Entry | has_one constraint | `has_one = authority` |
| Middleware | Account Validation | `#[derive(Accounts)]` |

## Concept Mapping In-Depth

### Principal → Pubkey/Signer

In web applications, a **principal** is the entity (user, service, system) attempting to perform an action.

**Web example (Node.js/Express):**

```javascript
// Principal is extracted from JWT/session
app.post('/admin/users', authenticateJWT, (req, res) => {
    const principal = req.user; // { id: '123', email: 'admin@example.com' }
    // Principal is whoever's token was validated
});
```

**Solana equivalent:**

```rust
// Principal is the Signer account
pub struct AddAdmin<'info> {
    // SECURITY: caller is the principal - their signature proves identity
    pub caller: Signer<'info>,  // This IS the principal

    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,
}
```

**Key differences:**

| Aspect | Web | Solana |
|--------|-----|--------|
| Identity proof | Token/session | Cryptographic signature |
| Forgery risk | Token theft, session hijacking | Private key compromise |
| Revocation | Invalidate token | Can't revoke signatures |
| Identity storage | Server-side session | Pubkey in transaction |

### Session/Token → Transaction Signature

Web applications use sessions or tokens to maintain authenticated state across requests.

**Web example:**

```javascript
// JWT contains encoded principal identity
const token = jwt.sign({ userId: '123', role: 'admin' }, SECRET_KEY);

// Server validates token on each request
function authenticateJWT(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user; // Attach principal to request
        next();
    });
}
```

**Solana equivalent:**

```rust
// No equivalent needed - every transaction is inherently signed
// The Signer type in Anchor enforces signature verification

pub struct UpdateFee<'info> {
    // SECURITY: By declaring Signer, Anchor automatically verifies
    // that this account signed the transaction
    pub caller: Signer<'info>,
}
```

**Key insight:** Solana doesn't need sessions because every transaction contains a fresh cryptographic signature. There's no "logged in" state - each transaction proves identity anew.

### Role → admin_list Membership

RBAC assigns permissions to roles, then assigns roles to users.

**Web RBAC example:**

```javascript
// Database schema
const roles = {
    SUPER_ADMIN: { permissions: ['pause', 'add_admin', 'update_fee', 'create_manager'] },
    ADMIN: { permissions: ['update_fee', 'create_manager'] },
    MANAGER: { permissions: ['view_reports'] }
};

const userRoles = {
    'alice_id': 'SUPER_ADMIN',
    'bob_id': 'ADMIN',
    'charlie_id': 'MANAGER'
};

// Middleware checks role
function requireRole(allowedRoles) {
    return (req, res, next) => {
        const userRole = userRoles[req.user.id];
        if (allowedRoles.includes(userRole)) {
            next();
        } else {
            res.status(403).json({ error: 'Insufficient permissions' });
        }
    };
}

app.post('/admin/pause', requireRole(['SUPER_ADMIN']), pauseHandler);
app.post('/admin/fee', requireRole(['SUPER_ADMIN', 'ADMIN']), updateFeeHandler);
```

**Solana RBAC equivalent (Pattern 02):**

```rust
// "Roles" stored in account data
pub struct AdminConfig {
    pub super_admin: Pubkey,           // SUPER_ADMIN role
    pub admin_list: [Pubkey; 3],       // ADMIN role membership
    pub admin_count: u8,
    // ...
}

// "Role check" as constraint
#[derive(Accounts)]
pub struct PauseProtocol<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Equivalent to requireRole(['SUPER_ADMIN'])
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateFee<'info> {
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // SECURITY: Equivalent to requireRole(['SUPER_ADMIN', 'ADMIN'])
        constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key)
            @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub caller: Signer<'info>,
}

// Helper function for role check
pub fn is_admin(admin_list: &[Pubkey; MAX_ADMINS], admin_count: u8, key: &Pubkey) -> bool {
    admin_list.iter().take(admin_count as usize).any(|admin| admin == key)
}
```

### Permission → Constraint Expression

Fine-grained permissions in web apps map to Anchor constraints.

**Web permission example:**

```javascript
// Check specific permission
function hasPermission(user, permission) {
    const role = userRoles[user.id];
    return roles[role].permissions.includes(permission);
}

// Usage
if (!hasPermission(req.user, 'update_fee')) {
    return res.status(403).json({ error: 'Missing permission: update_fee' });
}
```

**Solana permission equivalent:**

```rust
// Permission encoded in manager account
pub struct ManagerAccount {
    pub authority: Pubkey,      // Who created this manager
    pub manager: Pubkey,        // The manager's identity
    pub can_modify_fees: bool,  // Permission flag
    pub can_pause: bool,        // Permission flag
    pub is_active: bool,
    pub bump: u8,
}

// Check permission in constraint
#[derive(Accounts)]
pub struct ManagerUpdateFee<'info> {
    #[account(mut)]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        seeds = [b"manager", manager_account.manager.as_ref()],
        bump = manager_account.bump,
        // SECURITY: Permission check - equivalent to hasPermission(user, 'update_fee')
        constraint = manager_account.can_modify_fees @ ErrorCode::InsufficientPermission,
        // SECURITY: Also verify manager is still active
        constraint = manager_account.is_active @ ErrorCode::ManagerNotActive
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    // SECURITY: The manager must sign
    pub manager: Signer<'info>,
}
```

### ACL Entry → has_one Constraint

ACL (Access Control Lists) map specific resources to specific users who can access them.

**Web ACL example:**

```javascript
// ACL stored with resource
const document = {
    id: 'doc_123',
    content: 'Secret document',
    owner: 'alice_id',           // Owner has full access
    readAccess: ['bob_id'],      // Bob can read
    writeAccess: []              // No one else can write
};

// Check ACL
function canRead(userId, document) {
    return document.owner === userId || document.readAccess.includes(userId);
}

function canWrite(userId, document) {
    return document.owner === userId || document.writeAccess.includes(userId);
}
```

**Solana ACL equivalent:**

```rust
// ACL stored in account
pub struct UserDocument {
    pub owner: Pubkey,                 // Owner has full access
    pub read_access: [Pubkey; 5],      // Read ACL
    pub read_count: u8,
    pub content: [u8; 256],
}

// has_one enforces ownership
#[derive(Accounts)]
pub struct UpdateDocument<'info> {
    #[account(
        mut,
        // SECURITY: ACL check - only owner can write
        has_one = owner @ ErrorCode::NotOwner
    )]
    pub document: Account<'info, UserDocument>,

    // SECURITY: owner must sign
    pub owner: Signer<'info>,
}

// Custom constraint for read ACL
#[derive(Accounts)]
pub struct ReadDocument<'info> {
    #[account(
        // SECURITY: ACL check - owner OR in read_access list
        constraint = document.owner == reader.key()
            || is_in_read_list(&document.read_access, document.read_count, reader.key)
            @ ErrorCode::NoReadAccess
    )]
    pub document: Account<'info, UserDocument>,

    pub reader: Signer<'info>,
}
```

### Middleware → Account Validation

Web middleware processes requests before handlers. Anchor's account validation serves a similar purpose.

**Web middleware example:**

```javascript
// Middleware stack
app.post('/admin/action',
    authenticateJWT,           // Verify identity
    requireRole(['ADMIN']),    // Check role
    validateRequest,           // Validate input
    rateLimit,                 // Rate limiting
    handler                    // Finally, run the handler
);
```

**Solana equivalent - validation in #[derive(Accounts)]:**

```rust
#[derive(Accounts)]
pub struct AdminAction<'info> {
    // Equivalent to authenticateJWT + requireRole(['ADMIN'])
    #[account(
        mut,
        seeds = [b"admin_config"],
        bump = admin_config.bump,
        // Role check
        constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key)
            @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,

    // Identity verification (Signer = authenticated)
    pub caller: Signer<'info>,

    // Input validation
    #[account(
        constraint = amount > 0 @ ErrorCode::InvalidAmount,
        constraint = amount <= MAX_AMOUNT @ ErrorCode::ExceedsLimit
    )]
    pub amount: u64,
}

// Handler only runs if ALL validation passes
pub fn admin_action(ctx: Context<AdminAction>) -> Result<()> {
    // By the time we get here, all "middleware" has passed
    // ...
    Ok(())
}
```

---

## RBAC Implementation Pattern

Complete RBAC-like pattern in Anchor:

```rust
// Role definitions (conceptual - stored in account structure)
// SUPER_ADMIN: admin_config.super_admin
// ADMIN: admin_config.admin_list[0..admin_count]
// MANAGER: manager_account.is_active && specific permission flags

// Role hierarchy
pub struct AdminConfig {
    pub super_admin: Pubkey,           // Highest role
    pub admin_list: [Pubkey; MAX_ADMINS],
    pub admin_count: u8,
    pub fee_basis_points: u16,
    pub paused: bool,
    pub bump: u8,
}

pub struct ManagerAccount {
    pub authority: Pubkey,             // Admin who created this
    pub manager: Pubkey,
    pub can_modify_fees: bool,         // Permission
    pub can_pause: bool,               // Permission
    pub is_active: bool,               // Role enabled/disabled
    pub bump: u8,
}

// Role-based instruction access

// SUPER_ADMIN only
#[derive(Accounts)]
pub struct SuperAdminOnly<'info> {
    #[account(
        constraint = caller.key() == admin_config.super_admin @ ErrorCode::NotSuperAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,
    pub caller: Signer<'info>,
}

// ADMIN or higher
#[derive(Accounts)]
pub struct AdminOrHigher<'info> {
    #[account(
        // Super admin is also in admin_list[0], so this check works for both
        constraint = is_admin(&admin_config.admin_list, admin_config.admin_count, caller.key)
            @ ErrorCode::NotAdmin
    )]
    pub admin_config: Account<'info, AdminConfig>,
    pub caller: Signer<'info>,
}

// MANAGER with specific permission
#[derive(Accounts)]
pub struct ManagerWithPermission<'info> {
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        constraint = manager_account.is_active @ ErrorCode::ManagerNotActive,
        constraint = manager_account.can_modify_fees @ ErrorCode::InsufficientPermission
    )]
    pub manager_account: Account<'info, ManagerAccount>,

    #[account(
        constraint = caller.key() == manager_account.manager @ ErrorCode::NotManager
    )]
    pub caller: Signer<'info>,
}
```

---

## ACL Implementation Pattern

Complete ACL-like pattern in Anchor:

```rust
// Resource with access control list
pub struct ProtectedResource {
    pub owner: Pubkey,
    pub admins: [Pubkey; 3],        // Full access
    pub admin_count: u8,
    pub viewers: [Pubkey; 10],      // Read-only access
    pub viewer_count: u8,
    pub data: [u8; 256],
    pub bump: u8,
}

// Helper functions for ACL checks
pub fn is_owner(resource: &ProtectedResource, key: &Pubkey) -> bool {
    resource.owner == *key
}

pub fn is_admin_acl(resource: &ProtectedResource, key: &Pubkey) -> bool {
    resource.admins.iter()
        .take(resource.admin_count as usize)
        .any(|admin| admin == key)
}

pub fn is_viewer(resource: &ProtectedResource, key: &Pubkey) -> bool {
    resource.viewers.iter()
        .take(resource.viewer_count as usize)
        .any(|viewer| viewer == key)
}

pub fn can_read(resource: &ProtectedResource, key: &Pubkey) -> bool {
    is_owner(resource, key) || is_admin_acl(resource, key) || is_viewer(resource, key)
}

pub fn can_write(resource: &ProtectedResource, key: &Pubkey) -> bool {
    is_owner(resource, key) || is_admin_acl(resource, key)
}

// Owner-only operation
#[derive(Accounts)]
pub struct OwnerOnly<'info> {
    #[account(
        mut,
        has_one = owner @ ErrorCode::NotOwner
    )]
    pub resource: Account<'info, ProtectedResource>,
    pub owner: Signer<'info>,
}

// Admin or owner can write
#[derive(Accounts)]
pub struct WriteAccess<'info> {
    #[account(
        mut,
        constraint = can_write(&resource, caller.key) @ ErrorCode::NoWriteAccess
    )]
    pub resource: Account<'info, ProtectedResource>,
    pub caller: Signer<'info>,
}

// Anyone in ACL can read
#[derive(Accounts)]
pub struct ReadAccess<'info> {
    #[account(
        constraint = can_read(&resource, caller.key) @ ErrorCode::NoReadAccess
    )]
    pub resource: Account<'info, ProtectedResource>,
    pub caller: Signer<'info>,
}
```

---

## Comparison Summary Table

| Web Pattern | Solana Pattern | When to Use |
|-------------|---------------|-------------|
| JWT/Session auth | `Signer<'info>` | Every authenticated operation |
| `requireRole()` | `constraint = is_admin(...)` | Role-based access |
| `hasPermission()` | `constraint = account.can_x` | Permission flags |
| ACL `owner ==` | `has_one = owner` | Ownership checks |
| ACL `list.includes()` | Custom constraint + helper | List membership |
| Auth middleware stack | `#[derive(Accounts)]` | All validation |

## Key Differences to Remember

| Aspect | Web | Solana |
|--------|-----|--------|
| State | Server maintains session | Stateless transactions |
| Identity | Can impersonate with stolen token | Requires private key |
| Revocation | Easy (invalidate token) | Hard (can't revoke signatures) |
| Granularity | Middleware can be flexible | Constraints must be explicit |
| Audit | Logs on server | All on-chain |
| Speed | Milliseconds | Seconds (block confirmation) |

## Next Section

Continue to [Decision Tree](./decision-tree.md) for a systematic approach to determining what authority checks your program needs.
