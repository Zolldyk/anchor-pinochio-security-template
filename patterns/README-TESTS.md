# Test Suite Documentation

This document explains how to run, interpret, and understand the security pattern test suite.

## Test Output Format

### Naming Conventions

Tests use Unicode prefixes to clearly indicate their purpose:

| Prefix | Meaning | Example |
|--------|---------|---------|
| `✗` | Vulnerable program exploit (passes = vulnerability works) | `✗ allows unauthorized balance update` |
| `✓` | Secure program protection (passes = attack blocked) | `✓ blocks unauthorized balance update` |

### What "Passing" Means

**For vulnerable program tests (✗ prefix):**
- A **passing** test means the exploit succeeded
- This demonstrates the vulnerability is real and exploitable
- The test validates that unprotected code allows the attack

**For secure program tests (✓ prefix):**
- A **passing** test means the attack was blocked
- This demonstrates the security protection works
- The test validates that protected code prevents the attack

### Console Output Structure

Each test produces structured console output:

```
  ----------------------------------------
  TEST: [Test Name]
  ----------------------------------------

  Scenario: [What is being tested]
  Expected: [Anticipated outcome]

  Step 1: [Action description]
  [State values]

  Step 2: [Next action]
  [State values]

  Step 3: [Verification]
  [Before/After comparison]

  [OUTCOME MESSAGE]
  [Root cause or security explanation]
  ----------------------------------------
```

### Outcome Messages

| Message | Meaning |
|---------|---------|
| `⚠️ EXPLOIT SUCCESSFUL` | Vulnerability exploited (expected for vulnerable tests) |
| `✓ SECURITY VERIFIED` | Attack blocked (expected for secure tests) |
| `✓ SUCCESS` | Legitimate operation completed correctly |

## Running Tests

### Run All Patterns

```bash
# From project root
./scripts/test-all.sh

# Or using npm
npm test
```

### Run Individual Pattern

```bash
# Pattern 01: Missing Validation
cd patterns/01-missing-validation && anchor test

# Pattern 02: Authority Checks
cd patterns/02-authority-checks && anchor test

# Pattern 03: Unsafe Arithmetic
cd patterns/03-unsafe-arithmetic && anchor test

# Pattern 04: CPI Re-entrancy
cd patterns/04-cpi-reentrancy && anchor test

# Pattern 05: PDA Derivation
cd patterns/05-pda-derivation && anchor test

# Pattern 06: Token Validation
cd patterns/06-token-validation && anchor test
```

### Using npm Scripts

```bash
npm run test:01  # Pattern 01
npm run test:02  # Pattern 02
npm run test:03  # Pattern 03
npm run test:04  # Pattern 04
npm run test:05  # Pattern 05
npm run test:06  # Pattern 06
```

## Expected Results

### Current Test Counts

| Pattern | Passing | Failing | Notes |
|---------|---------|---------|-------|
| 01-missing-validation | 5 | 3 | Pinocchio tests fail (not deployed) |
| 02-authority-checks | 15 | 2 | Pinocchio tests fail (not deployed) |
| 03-unsafe-arithmetic | 33 | 2 | Pinocchio tests fail (not deployed) |
| 04-cpi-reentrancy | 15 | 0 | All tests pass |
| 05-pda-derivation | 10 | 0 | All tests pass |
| 06-token-validation | 15 | 0 | All tests pass |
| **Total** | **93** | **7** | 7 Pinocchio failures expected |

### Why Some Tests Fail

The 7 failing tests are **Pinocchio comparison tests** that require Pinocchio programs to be deployed. These programs are written but not yet deployed to the local validator. The failures show:

```
Error: Simulation failed.
Message: Transaction simulation failed: Attempt to load a program that does not exist.
```

This is expected behavior and does not indicate a problem with the test suite.

## Example Output Walkthrough

### Pattern 01: Missing Validation

```
  ========================================
  MISSING VALIDATION PATTERN - EXPLOIT DEMO
  ========================================

  Vulnerable Program ID: Bkh2Wph3fz5iNNcUFy585rRjrRPniCpKs7T3DZZVYeYb
  Secure Program ID: 78x68Ufm5nCVRUpyzdKd1VjZk7gFeNNFVryqT48mE1kL

    VULNERABLE Program

  ----------------------------------------
  TEST: Unauthorized Balance Update Exploit
  ----------------------------------------

  Scenario: Attacker attempts to update victim's balance
  Expected: Unauthorized modification succeeds (vulnerability)

  Step 1: Victim initializes account...
  Victim's initial balance: 0
  Victim's authority: 8jikaaw7UbH3SfTq7YQAGn26mQAgj9aSV3J68S5xPL5m

  Step 2: Attacker attempts unauthorized update...
  Attacker pubkey: 9s77J3GJk6GA2WqDbjUKfZUWYpRbBU48qJyJHKFycfs5

  Step 3: Verifying exploit results...
  Balance BEFORE attack: 0
  Balance AFTER attack: 999999

  ⚠️  EXPLOIT SUCCESSFUL: Unauthorized modification!
  The attacker modified victim's balance without authorization.
  Root cause: authority account is not verified as a signer.
  ----------------------------------------

      ✔ ✗ allows unauthorized balance update (931ms)
```

**Interpretation:**
- The `✗` prefix indicates this tests a vulnerable program
- The test **passes** because the exploit succeeded
- `EXPLOIT SUCCESSFUL` confirms the vulnerability is real
- The root cause explains what validation is missing

### Pattern 03: Unsafe Arithmetic

```
  ========================================
  UNSAFE ARITHMETIC PATTERN - EXPLOIT DEMO
  ========================================

  VULNERABLE Program

      Scenario: Attacker exploits overflow to reset balance
      Attack: Deposit values that sum to > u64::MAX, causing wraparound

      Initial balance: 0

      Step 1: Depositing 18446744073709551605
      Balance after large deposit: 18446744073709551605

      Step 2: Depositing 20 (causes overflow!)
      Expected: Balance wraps from near-MAX to small value
      Balance after overflow: 9

      ⚠️ EXPLOIT SUCCESSFUL: Balance wrapped from near-MAX to 9!
      Impact: User deposited massive amount but balance shows nearly zero

      ✔ ✗ VULNERABLE: Balance overflow via large deposit
```

**Interpretation:**
- Shows numeric state before/after the overflow
- Demonstrates the wrapping behavior clearly
- Explains the real-world impact

## Test File Structure

Each `exploit-demo.ts` file follows this structure:

```typescript
/**
 * [Pattern Name] - Exploit Demonstration Tests
 *
 * Pattern: [Pattern Category]
 * Vulnerability: [Brief description]
 * Impact: [Security impact]
 *
 * Key Insight: [Core educational takeaway]
 */

describe("[Pattern Name]", () => {
  before(async () => {
    // Banner and setup explanation
  });

  describe("VULNERABLE Program", () => {
    it("✗ [exploit description]", async () => {
      // ATTACK: Comment explaining the exploit
      // ... exploit code with state logging
    });
  });

  describe("SECURE Program", () => {
    it("✓ [protection description]", async () => {
      // SECURITY: Comment explaining the protection
      // ... protection verification with error catching
    });
  });

  after(() => {
    // Summary of findings and key takeaways
  });
});
```

## Capturing Test Output

To capture test output for analysis:

```bash
# Capture all output with timestamps
./scripts/test-all.sh 2>&1 | tee test-output-$(date +%Y%m%d).log

# Run single pattern with verbose output
cd patterns/01-missing-validation && anchor test 2>&1 | tee pattern-01-output.log
```

## Attack Markers

All exploit code is annotated with `// ATTACK:` comments for easy identification:

```typescript
// ATTACK: Attacker can update victim's balance by passing victim's pubkey
// as authority WITHOUT signing as that authority. The vulnerable program only
// uses authority to derive the PDA, but doesn't verify the signer.
await vulnerableProgram.methods
  .updateBalance(new BN(maliciousBalance))
  .accounts({
    userAccount: victimVulnerablePda,
    authority: victimKeypair.publicKey, // Victim's pubkey, but attacker sends tx
  })
  .signers([]) // No signer needed - this is the vulnerability!
  .rpc();
```

## Key Takeaways by Pattern

| Pattern | Key Security Lesson |
|---------|---------------------|
| 01 | Always use `Signer<'info>` and `has_one` constraints |
| 02 | Validate authority at every level of the authority chain |
| 03 | Use `checked_*` methods; overflow wraps silently in release mode |
| 04 | Update state BEFORE CPI calls (checks-effects-interactions) |
| 05 | Re-derive PDAs with `seeds` constraint; never trust user bumps |
| 06 | Validate mint and owner on all token operations |
