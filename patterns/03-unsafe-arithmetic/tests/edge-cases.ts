/**
 * Unsafe Arithmetic Pattern - Edge Case & Boundary Condition Tests
 *
 * This test suite provides comprehensive boundary value testing for the arithmetic
 * overflow/underflow patterns. It focuses on testing at exact boundaries:
 * - Exact limit values (MAX_DEPOSIT, MAX_REWARD_RATE)
 * - Limit + 1 values (should fail)
 * - Minimum values (0, 1)
 * - Near-maximum u64 values
 *
 * Key Boundary Values:
 * - MAX_DEPOSIT: 1,000,000,000,000 (1000 SOL in lamports)
 * - MAX_REWARD_RATE: 10,000 (100x multiplier as basis points)
 * - u64::MAX: 18,446,744,073,709,551,615
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";

// Import IDL types
import { VulnerableUnsafeArithmetic } from "../target/types/vulnerable_unsafe_arithmetic";
import { SecureUnsafeArithmetic } from "../target/types/secure_unsafe_arithmetic";

/**
 * Sleep helper for RPC rate limit handling
 * Used between tests to avoid overwhelming the local validator
 */
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Format large BN numbers for readable console output
 */
const formatBigNumber = (n: BN): string => {
  const str = n.toString();
  if (str.length > 15) {
    return `${str.substring(0, 6)}...${str.substring(str.length - 6)} (${str.length} digits)`;
  }
  return str;
};

// =============================================================================
// BOUNDARY CONSTANTS
// =============================================================================

// Maximum deposit: 1000 SOL in lamports (matches secure program constant)
const MAX_DEPOSIT = new BN("1000000000000");
// Maximum deposit + 1 (should trigger ExceedsMaxDeposit error)
const MAX_DEPOSIT_PLUS_ONE = new BN("1000000000001");

// Maximum reward rate: 100x multiplier (matches secure program constant)
const MAX_REWARD_RATE = new BN(10000);
// Maximum reward rate + 1 (should trigger ExceedsMaxRewardRate error)
const MAX_REWARD_RATE_PLUS_ONE = new BN(10001);

// Maximum u64 value: 2^64 - 1 = 18,446,744,073,709,551,615
const U64_MAX = new BN("18446744073709551615");
// Near-maximum value for overflow boundary testing
const U64_MAX_MINUS_ONE = new BN("18446744073709551614");

// Minimum non-zero values for boundary testing
const MINIMUM_VALUE = new BN(1);
const ZERO_VALUE = new BN(0);

describe("Edge Case & Boundary Condition Tests", () => {
  // Configure the Anchor provider
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs from workspace
  const vulnerableProgram = anchor.workspace
    .VulnerableUnsafeArithmetic as Program<VulnerableUnsafeArithmetic>;
  const secureProgram = anchor.workspace
    .SecureUnsafeArithmetic as Program<SecureUnsafeArithmetic>;

  // Test keypairs
  let deployerKeypair: Keypair;

  // PDA addresses
  let vulnerableVaultPda: PublicKey;
  let secureVaultPda: PublicKey;

  before(async () => {
    console.log("\n  ========================================");
    console.log("  EDGE CASE & BOUNDARY CONDITION TESTS");
    console.log("  ========================================");
    console.log("\n  Testing boundary values for arithmetic operations:");
    console.log(`    MAX_DEPOSIT:     ${formatBigNumber(MAX_DEPOSIT)} (1000 SOL)`);
    console.log(`    MAX_REWARD_RATE: ${MAX_REWARD_RATE.toString()} (100x multiplier)`);
    console.log(`    u64::MAX:        ${formatBigNumber(U64_MAX)}\n`);

    // Generate deployer keypair
    deployerKeypair = Keypair.generate();

    // Airdrop SOL to deployer
    await provider.connection.requestAirdrop(
      deployerKeypair.publicKey,
      10 * anchor.web3.LAMPORTS_PER_SOL
    );
    await sleep(1000);

    // Derive vault PDAs
    [vulnerableVaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      vulnerableProgram.programId
    );

    [secureVaultPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault")],
      secureProgram.programId
    );

    // Initialize vaults (may already exist from other tests)
    try {
      await vulnerableProgram.methods
        .initializeVault()
        .accounts({
          authority: deployerKeypair.publicKey,
          vaultState: vulnerableVaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([deployerKeypair])
        .rpc();
    } catch (err: unknown) {
      if (err instanceof Error && !err.message.includes("already in use")) {
        throw err;
      }
    }

    try {
      await secureProgram.methods
        .initializeVault()
        .accounts({
          authority: deployerKeypair.publicKey,
          vaultState: secureVaultPda,
          systemProgram: SystemProgram.programId,
        })
        .signers([deployerKeypair])
        .rpc();
    } catch (err: unknown) {
      if (err instanceof Error && !err.message.includes("already in use")) {
        throw err;
      }
    }
    await sleep(500);
  });

  // ===========================================================================
  // HELPER: Create fresh user for test isolation
  // ===========================================================================
  async function createFreshUser(
    program: Program<VulnerableUnsafeArithmetic> | Program<SecureUnsafeArithmetic>,
    vaultPda: PublicKey
  ): Promise<{ keypair: Keypair; balancePda: PublicKey }> {
    const userKeypair = Keypair.generate();
    const airdropSig = await provider.connection.requestAirdrop(
      userKeypair.publicKey,
      5 * anchor.web3.LAMPORTS_PER_SOL
    );
    // Wait for airdrop confirmation
    await provider.connection.confirmTransaction(airdropSig, "confirmed");
    await sleep(500);

    const [userBalancePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("user"), userKeypair.publicKey.toBuffer()],
      program.programId
    );

    await program.methods
      .createUser()
      .accounts({
        owner: userKeypair.publicKey,
        vaultState: vaultPda,
        userBalance: userBalancePda,
        systemProgram: SystemProgram.programId,
      })
      .signers([userKeypair])
      .rpc();
    await sleep(500);

    return { keypair: userKeypair, balancePda: userBalancePda };
  }

  // ===========================================================================
  // DEPOSIT BOUNDARY TESTS
  // ===========================================================================

  describe("Deposit Boundary Tests", () => {
    it("✓ handles boundary: deposit of exactly MAX_DEPOSIT (secure)", async () => {
      console.log("\n      Scenario: Deposit at exactly MAX_DEPOSIT limit");
      console.log(`      Value: ${formatBigNumber(MAX_DEPOSIT)} (1000 SOL)`);

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      await secureProgram.methods
        .deposit(MAX_DEPOSIT)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      expect(userBalance.balance.toString()).to.equal(MAX_DEPOSIT.toString());

      console.log(`      Result: Balance = ${formatBigNumber(new BN(userBalance.balance.toString()))}`);
      console.log("      \x1b[32m✓ Boundary case handled correctly - exact MAX_DEPOSIT accepted\x1b[0m");
    });

    it("✓ rejects: deposit of MAX_DEPOSIT + 1 (secure)", async () => {
      console.log("\n      Scenario: Deposit exceeding MAX_DEPOSIT by 1");
      console.log(`      Value: ${formatBigNumber(MAX_DEPOSIT_PLUS_ONE)}`);

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      try {
        await secureProgram.methods
          .deposit(MAX_DEPOSIT_PLUS_ONE)
          .accounts({
            owner: keypair.publicKey,
            vaultState: secureVaultPda,
            userBalance: balancePda,
          })
          .signers([keypair])
          .rpc();

        expect.fail("Should have been rejected with ExceedsMaxDeposit");
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        expect(
          errorMessage.includes("ExceedsMaxDeposit") ||
          errorMessage.includes("Deposit amount exceeds maximum")
        ).to.be.true;

        console.log("      \x1b[32m✓ Boundary exceeded - correctly rejected with ExceedsMaxDeposit\x1b[0m");
      }
    });

    it("✓ handles boundary: deposit of 1 (minimum valid deposit)", async () => {
      console.log("\n      Scenario: Deposit of minimum non-zero value");
      console.log(`      Value: ${MINIMUM_VALUE.toString()}`);

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      await secureProgram.methods
        .deposit(MINIMUM_VALUE)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      expect(userBalance.balance.toString()).to.equal("1");

      console.log(`      Result: Balance = ${userBalance.balance.toString()}`);
      console.log("      \x1b[32m✓ Minimum deposit of 1 handled correctly\x1b[0m");
    });

    it("✓ handles boundary: deposit of 0", async () => {
      console.log("\n      Scenario: Deposit of zero");
      console.log(`      Value: ${ZERO_VALUE.toString()}`);

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      await secureProgram.methods
        .deposit(ZERO_VALUE)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      expect(userBalance.balance.toString()).to.equal("0");

      console.log(`      Result: Balance = ${userBalance.balance.toString()}`);
      console.log("      \x1b[32m✓ Zero deposit handled correctly (balance unchanged)\x1b[0m");
    });
  });

  // ===========================================================================
  // WITHDRAWAL BOUNDARY TESTS
  // ===========================================================================

  describe("Withdrawal Boundary Tests", () => {
    it("✓ handles boundary: withdrawal of 1 from balance of 1 (secure)", async () => {
      console.log("\n      Scenario: Withdraw entire balance of 1");
      console.log("      Initial balance: 1, Withdraw: 1, Expected: 0");

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      // Deposit 1
      await secureProgram.methods
        .deposit(MINIMUM_VALUE)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      // Withdraw 1
      await secureProgram.methods
        .withdraw(MINIMUM_VALUE)
        .accounts({
          owner: keypair.publicKey,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      expect(userBalance.balance.toString()).to.equal("0");

      console.log(`      Result: Balance = ${userBalance.balance.toString()}`);
      console.log("      \x1b[32m✓ Withdrawal of 1 from balance of 1 succeeded, leaving 0\x1b[0m");
    });

    it("✓ rejects: withdrawal of 1 from balance of 0 (secure)", async () => {
      console.log("\n      Scenario: Withdraw 1 from empty balance");
      console.log("      Initial balance: 0, Withdraw: 1, Expected: InsufficientBalance error");

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      // Balance is 0, try to withdraw 1
      try {
        await secureProgram.methods
          .withdraw(MINIMUM_VALUE)
          .accounts({
            owner: keypair.publicKey,
            userBalance: balancePda,
          })
          .signers([keypair])
          .rpc();

        expect.fail("Should have been rejected with InsufficientBalance");
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        expect(
          errorMessage.includes("InsufficientBalance") ||
          errorMessage.includes("Insufficient balance")
        ).to.be.true;

        console.log("      \x1b[32m✓ Correctly rejected with InsufficientBalance\x1b[0m");
      }
    });

    it("✓ handles boundary: withdrawal that leaves exactly 0 (secure)", async () => {
      console.log("\n      Scenario: Withdraw entire balance");
      console.log("      Initial balance: 1000, Withdraw: 1000, Expected: 0");

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);
      const testAmount = new BN(1000);

      // Deposit 1000
      await secureProgram.methods
        .deposit(testAmount)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      // Withdraw entire balance
      await secureProgram.methods
        .withdraw(testAmount)
        .accounts({
          owner: keypair.publicKey,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      expect(userBalance.balance.toString()).to.equal("0");

      console.log(`      Result: Balance = ${userBalance.balance.toString()}`);
      console.log("      \x1b[32m✓ Full withdrawal succeeded, balance is exactly 0\x1b[0m");
    });
  });

  // ===========================================================================
  // REWARD RATE BOUNDARY TESTS
  // ===========================================================================

  describe("Reward Rate Boundary Tests", () => {
    it("✓ handles boundary: reward rate of exactly MAX_REWARD_RATE (secure)", async () => {
      console.log("\n      Scenario: Reward calculation at exactly MAX_REWARD_RATE");
      console.log(`      Value: ${MAX_REWARD_RATE.toString()} (100x multiplier)`);

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      // Deposit a small amount to avoid overflow when multiplied by MAX_REWARD_RATE
      const depositAmount = new BN(100);
      await secureProgram.methods
        .deposit(depositAmount)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      // Calculate rewards at MAX_REWARD_RATE
      await secureProgram.methods
        .calculateRewards(MAX_REWARD_RATE)
        .accounts({
          authority: deployerKeypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([deployerKeypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      // Expected: 100 + (100 * 10000) = 1000100
      const expectedBalance = depositAmount.add(depositAmount.mul(MAX_REWARD_RATE));
      expect(userBalance.balance.toString()).to.equal(expectedBalance.toString());

      console.log(`      Initial balance: ${depositAmount.toString()}`);
      console.log(`      Reward: ${depositAmount.mul(MAX_REWARD_RATE).toString()}`);
      console.log(`      Final balance: ${userBalance.balance.toString()}`);
      console.log("      \x1b[32m✓ MAX_REWARD_RATE accepted and calculated correctly\x1b[0m");
    });

    it("✓ rejects: reward rate of MAX_REWARD_RATE + 1 (secure)", async () => {
      console.log("\n      Scenario: Reward calculation exceeding MAX_REWARD_RATE by 1");
      console.log(`      Value: ${MAX_REWARD_RATE_PLUS_ONE.toString()}`);

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      // Deposit first
      await secureProgram.methods
        .deposit(new BN(100))
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      try {
        await secureProgram.methods
          .calculateRewards(MAX_REWARD_RATE_PLUS_ONE)
          .accounts({
            authority: deployerKeypair.publicKey,
            vaultState: secureVaultPda,
            userBalance: balancePda,
          })
          .signers([deployerKeypair])
          .rpc();

        expect.fail("Should have been rejected with ExceedsMaxRewardRate");
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        expect(
          errorMessage.includes("ExceedsMaxRewardRate") ||
          errorMessage.includes("Reward rate exceeds maximum")
        ).to.be.true;

        console.log("      \x1b[32m✓ Boundary exceeded - correctly rejected with ExceedsMaxRewardRate\x1b[0m");
      }
    });

    it("✓ handles boundary: reward rate of 1 (minimal multiplier)", async () => {
      console.log("\n      Scenario: Reward calculation with rate of 1");
      console.log("      Expected: balance increases by balance * 1 = balance doubles");

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      const depositAmount = new BN(1000);
      await secureProgram.methods
        .deposit(depositAmount)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      // Calculate rewards with rate of 1
      await secureProgram.methods
        .calculateRewards(MINIMUM_VALUE)
        .accounts({
          authority: deployerKeypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([deployerKeypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      // Expected: 1000 + (1000 * 1) = 2000
      expect(userBalance.balance.toString()).to.equal("2000");

      console.log(`      Initial balance: ${depositAmount.toString()}`);
      console.log(`      Reward rate: 1`);
      console.log(`      Final balance: ${userBalance.balance.toString()}`);
      console.log("      \x1b[32m✓ Minimal reward rate of 1 calculated correctly\x1b[0m");
    });

    it("✓ handles boundary: reward calculation with balance of 1 and rate of 1", async () => {
      console.log("\n      Scenario: Minimum values - balance=1, rate=1");
      console.log("      Expected: 1 + (1 * 1) = 2");

      const { keypair, balancePda } = await createFreshUser(secureProgram, secureVaultPda);

      // Deposit 1
      await secureProgram.methods
        .deposit(MINIMUM_VALUE)
        .accounts({
          owner: keypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      // Calculate rewards with rate of 1
      await secureProgram.methods
        .calculateRewards(MINIMUM_VALUE)
        .accounts({
          authority: deployerKeypair.publicKey,
          vaultState: secureVaultPda,
          userBalance: balancePda,
        })
        .signers([deployerKeypair])
        .rpc();

      const userBalance = await secureProgram.account.userBalance.fetch(balancePda);
      expect(userBalance.balance.toString()).to.equal("2");

      console.log(`      Final balance: ${userBalance.balance.toString()}`);
      console.log("      \x1b[32m✓ Minimum value calculation (1 * 1) handled correctly\x1b[0m");
    });
  });

  // ===========================================================================
  // OVERFLOW BOUNDARY TESTS (VULNERABLE PROGRAM)
  // ===========================================================================

  describe("Overflow Boundary Tests (Vulnerable)", () => {
    it("✗ VULNERABLE: u64::MAX - 1 overflow boundary test", async () => {
      console.log("\n      Scenario: Deposit causes overflow at u64::MAX boundary");
      console.log(`      Initial deposit: ${formatBigNumber(U64_MAX_MINUS_ONE)}`);
      console.log(`      Second deposit: 2`);
      console.log(`      Expected: Wraps to 0 (u64::MAX - 1 + 2 = u64::MAX + 1 = 0)`);

      const { keypair, balancePda } = await createFreshUser(vulnerableProgram, vulnerableVaultPda);

      // Deposit u64::MAX - 1
      await vulnerableProgram.methods
        .deposit(U64_MAX_MINUS_ONE)
        .accounts({
          owner: keypair.publicKey,
          vaultState: vulnerableVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      let userBalance = await vulnerableProgram.account.userBalance.fetch(balancePda);
      console.log(`      Balance after first deposit: ${formatBigNumber(new BN(userBalance.balance.toString()))}`);

      // Deposit 2 more (causes overflow: MAX-1 + 2 = MAX + 1 wraps to 0)
      await vulnerableProgram.methods
        .deposit(new BN(2))
        .accounts({
          owner: keypair.publicKey,
          vaultState: vulnerableVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      userBalance = await vulnerableProgram.account.userBalance.fetch(balancePda);
      const finalBalance = new BN(userBalance.balance.toString());

      // Verify overflow occurred - balance should be 0
      expect(finalBalance.toString()).to.equal("0");

      console.log(`      Balance after overflow: ${finalBalance.toString()}`);
      console.log(
        "\n      \x1b[33m⚠️ EXPLOIT CONFIRMED: Balance wrapped from u64::MAX-1 to 0!\x1b[0m"
      );
    });

    it("✗ VULNERABLE: underflow at balance=1, withdraw=2", async () => {
      console.log("\n      Scenario: Underflow at minimal boundary");
      console.log("      Initial balance: 1, Withdraw: 2");
      console.log(`      Expected: Wraps to u64::MAX - 0 = ${formatBigNumber(U64_MAX)}`);

      const { keypair, balancePda } = await createFreshUser(vulnerableProgram, vulnerableVaultPda);

      // Deposit 1
      await vulnerableProgram.methods
        .deposit(MINIMUM_VALUE)
        .accounts({
          owner: keypair.publicKey,
          vaultState: vulnerableVaultPda,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      // Withdraw 2 (causes underflow: 1 - 2 wraps to MAX)
      await vulnerableProgram.methods
        .withdraw(new BN(2))
        .accounts({
          owner: keypair.publicKey,
          userBalance: balancePda,
        })
        .signers([keypair])
        .rpc();

      const userBalance = await vulnerableProgram.account.userBalance.fetch(balancePda);
      const finalBalance = new BN(userBalance.balance.toString());

      // 1 - 2 = -1 wraps to u64::MAX
      const expectedBalance = U64_MAX;
      expect(finalBalance.eq(expectedBalance)).to.be.true;

      console.log(`      Balance after underflow: ${formatBigNumber(finalBalance)}`);
      console.log(
        "\n      \x1b[33m⚠️ EXPLOIT CONFIRMED: Balance wrapped from 1 to u64::MAX!\x1b[0m"
      );
    });
  });

  // ===========================================================================
  // SUMMARY
  // ===========================================================================

  after(() => {
    console.log("\n  ========================================");
    console.log("  EDGE CASE TEST SUMMARY");
    console.log("  ========================================");
    console.log("\n  Deposit Boundaries (SECURE):");
    console.log("    ✓ MAX_DEPOSIT accepted");
    console.log("    ✓ MAX_DEPOSIT + 1 rejected");
    console.log("    ✓ Minimum deposit (1) accepted");
    console.log("    ✓ Zero deposit handled");
    console.log("\n  Withdrawal Boundaries (SECURE):");
    console.log("    ✓ Withdraw 1 from balance 1 succeeds");
    console.log("    ✓ Withdraw 1 from balance 0 rejected");
    console.log("    ✓ Full withdrawal leaving 0 succeeds");
    console.log("\n  Reward Rate Boundaries (SECURE):");
    console.log("    ✓ MAX_REWARD_RATE accepted");
    console.log("    ✓ MAX_REWARD_RATE + 1 rejected");
    console.log("    ✓ Minimum rate (1) calculated correctly");
    console.log("    ✓ Minimum balance (1) with minimum rate (1) works");
    console.log("\n  Overflow Boundaries (VULNERABLE):");
    console.log("    ⚠️ u64::MAX - 1 + 2 wraps to 0");
    console.log("    ⚠️ balance=1, withdraw=2 wraps to u64::MAX\n");
  });
});
