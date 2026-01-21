/**
 * Pinocchio vs Anchor Unsafe Arithmetic Comparison Tests
 *
 * This test suite compares the behavior of Anchor and Pinocchio implementations
 * for the unsafe arithmetic vulnerability pattern. Both frameworks demonstrate
 * identical vulnerabilities (wrapping arithmetic) and identical protections
 * (checked arithmetic with error handling).
 *
 * Key Differences:
 * - Anchor: Uses IDL for type-safe method calls, #[error_code] macros
 * - Pinocchio: Manual instruction encoding, custom error enum
 * - Anchor: 8-byte instruction discriminators
 * - Pinocchio: Single-byte instruction discriminators
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { expect } from "chai";

// Import Anchor IDL types
import { VulnerableUnsafeArithmetic } from "../target/types/vulnerable_unsafe_arithmetic";
import { SecureUnsafeArithmetic } from "../target/types/secure_unsafe_arithmetic";

// =============================================================================
// PINOCCHIO PROGRAM CONSTANTS
// =============================================================================

// Program IDs from keypairs
const PINOCCHIO_VULNERABLE_PROGRAM_ID = new PublicKey(
  "4R677cX6tV6G5YeWMw1ndtPpDzvD4zrdz6HbNYWF9oQi"
);
const PINOCCHIO_SECURE_PROGRAM_ID = new PublicKey(
  "CVyZU6X4vBxHQaQar29cho6Gv9qYLX8wu1wBYCq1K4jW"
);

// Instruction discriminators (single byte, unlike Anchor's 8-byte sighash)
const INITIALIZE_VAULT_DISCRIMINATOR = 0;
const CREATE_USER_DISCRIMINATOR = 1;
const DEPOSIT_DISCRIMINATOR = 2;
const WITHDRAW_DISCRIMINATOR = 3;
const CALCULATE_REWARDS_DISCRIMINATOR = 4;

// Account sizes (no Anchor discriminator - 8 bytes less)
const VAULT_STATE_SIZE = 57; // 32 + 8 + 8 + 8 + 1
const USER_BALANCE_SIZE = 57; // 32 + 8 + 8 + 8 + 1

// PDA seeds
const VAULT_SEED = Buffer.from("vault");
const USER_SEED = Buffer.from("user");

// Maximum u64 value
const U64_MAX = new BN("18446744073709551615");
const U64_MAX_MINUS_10 = new BN("18446744073709551605");

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Sleep helper for RPC rate limit handling
 */
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Format large numbers for display
 */
const formatBigNumber = (n: BN): string => {
  const str = n.toString();
  if (str.length > 15) {
    return `${str.substring(0, 6)}...${str.substring(str.length - 6)} (${str.length} digits)`;
  }
  return str;
};

/**
 * Build instruction data for initialize_vault.
 * Format: [discriminator (1 byte)] [bump (1 byte)]
 */
function buildInitializeVaultInstructionData(bump: number): Buffer {
  const data = Buffer.alloc(2);
  data.writeUInt8(INITIALIZE_VAULT_DISCRIMINATOR, 0);
  data.writeUInt8(bump, 1);
  return data;
}

/**
 * Build instruction data for create_user.
 * Format: [discriminator (1 byte)] [bump (1 byte)]
 */
function buildCreateUserInstructionData(bump: number): Buffer {
  const data = Buffer.alloc(2);
  data.writeUInt8(CREATE_USER_DISCRIMINATOR, 0);
  data.writeUInt8(bump, 1);
  return data;
}

/**
 * Build instruction data for deposit.
 * Format: [discriminator (1 byte)] [amount (8 bytes, little-endian)]
 */
function buildDepositInstructionData(amount: BN): Buffer {
  const data = Buffer.alloc(9);
  data.writeUInt8(DEPOSIT_DISCRIMINATOR, 0);
  data.writeBigUInt64LE(BigInt(amount.toString()), 1);
  return data;
}

/**
 * Build instruction data for withdraw.
 * Format: [discriminator (1 byte)] [amount (8 bytes, little-endian)]
 */
function buildWithdrawInstructionData(amount: BN): Buffer {
  const data = Buffer.alloc(9);
  data.writeUInt8(WITHDRAW_DISCRIMINATOR, 0);
  data.writeBigUInt64LE(BigInt(amount.toString()), 1);
  return data;
}

/**
 * Build instruction data for calculate_rewards.
 * Format: [discriminator (1 byte)] [reward_rate (8 bytes, little-endian)]
 */
function buildCalculateRewardsInstructionData(rewardRate: BN): Buffer {
  const data = Buffer.alloc(9);
  data.writeUInt8(CALCULATE_REWARDS_DISCRIMINATOR, 0);
  data.writeBigUInt64LE(BigInt(rewardRate.toString()), 1);
  return data;
}

/**
 * Decode VaultState account data from raw bytes.
 */
function decodeVaultState(data: Buffer): {
  authority: PublicKey;
  totalDeposits: BN;
  userCount: BN;
  totalRewards: BN;
  bump: number;
} {
  return {
    authority: new PublicKey(data.slice(0, 32)),
    totalDeposits: new BN(data.readBigUInt64LE(32).toString()),
    userCount: new BN(data.readBigUInt64LE(40).toString()),
    totalRewards: new BN(data.readBigUInt64LE(48).toString()),
    bump: data[56],
  };
}

/**
 * Decode UserBalance account data from raw bytes.
 */
function decodeUserBalance(data: Buffer): {
  owner: PublicKey;
  balance: BN;
  deposits: BN;
  withdrawals: BN;
  bump: number;
} {
  return {
    owner: new PublicKey(data.slice(0, 32)),
    balance: new BN(data.readBigUInt64LE(32).toString()),
    deposits: new BN(data.readBigUInt64LE(40).toString()),
    withdrawals: new BN(data.readBigUInt64LE(48).toString()),
    bump: data[56],
  };
}

/**
 * Create and fund a new account for Pinocchio programs.
 */
async function createFundedAccount(
  connection: Connection,
  payer: Keypair,
  programId: PublicKey,
  space: number
): Promise<Keypair> {
  const account = Keypair.generate();
  const lamports = await connection.getMinimumBalanceForRentExemption(space);

  const tx = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: payer.publicKey,
      newAccountPubkey: account.publicKey,
      lamports,
      space,
      programId,
    })
  );

  await sendAndConfirmTransaction(connection, tx, [payer, account]);
  return account;
}

// =============================================================================
// TEST SUITE
// =============================================================================

describe("Pinocchio vs Anchor Unsafe Arithmetic Comparison", () => {
  // Anchor setup
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const vulnerableProgram = anchor.workspace
    .VulnerableUnsafeArithmetic as Program<VulnerableUnsafeArithmetic>;
  const secureProgram = anchor.workspace
    .SecureUnsafeArithmetic as Program<SecureUnsafeArithmetic>;

  // Connection
  const connection = provider.connection;

  // Test keypairs
  let deployerKeypair: Keypair;
  let attackerKeypair: Keypair;

  // Anchor PDAs
  let anchorVulnerableVaultPda: PublicKey;
  let anchorSecureVaultPda: PublicKey;

  // Pinocchio accounts (pre-allocated)
  let pinocchioVulnerableVaultAccount: Keypair;
  let pinocchioSecureVaultAccount: Keypair;

  // =============================================================================
  // SETUP
  // =============================================================================

  before(async () => {
    console.log("\n");
    console.log("  ========================================");
    console.log("  PINOCCHIO vs ANCHOR UNSAFE ARITHMETIC");
    console.log("  ========================================");
    console.log("");
    console.log("  This test suite compares arithmetic vulnerability handling");
    console.log("  between Anchor and Pinocchio frameworks.");
    console.log("");
    console.log("  Key Differences:");
    console.log("  - Anchor: IDL-based, require!() macro, #[error_code]");
    console.log("  - Pinocchio: Manual encoding, explicit if-checks, custom errors");
    console.log("");
    console.log("  Anchor Vulnerable:", vulnerableProgram.programId.toString());
    console.log("  Anchor Secure:", secureProgram.programId.toString());
    console.log("  Pinocchio Vulnerable:", PINOCCHIO_VULNERABLE_PROGRAM_ID.toString());
    console.log("  Pinocchio Secure:", PINOCCHIO_SECURE_PROGRAM_ID.toString());
    console.log("");

    // Generate keypairs
    deployerKeypair = Keypair.generate();
    attackerKeypair = Keypair.generate();

    // Airdrop SOL
    const airdropAmount = 10 * LAMPORTS_PER_SOL;
    await Promise.all([
      connection.requestAirdrop(deployerKeypair.publicKey, airdropAmount),
      connection.requestAirdrop(attackerKeypair.publicKey, airdropAmount),
    ]);
    await sleep(1000);

    // Derive Anchor PDAs
    [anchorVulnerableVaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      vulnerableProgram.programId
    );
    [anchorSecureVaultPda] = PublicKey.findProgramAddressSync(
      [VAULT_SEED],
      secureProgram.programId
    );

    console.log("  Test Accounts:");
    console.log(`    Deployer: ${deployerKeypair.publicKey.toBase58()}`);
    console.log(`    Attacker: ${attackerKeypair.publicKey.toBase58()}`);
    console.log("");
  });

  // =============================================================================
  // ANCHOR VULNERABLE PROGRAM TESTS
  // =============================================================================

  describe("ANCHOR VULNERABLE Program", () => {
    let anchorUserBalancePda: PublicKey;

    before(async () => {
      console.log("    Initializing Anchor vulnerable vault...");
      try {
        await vulnerableProgram.methods
          .initializeVault()
          .accounts({
            authority: deployerKeypair.publicKey,
            vaultState: anchorVulnerableVaultPda,
            systemProgram: SystemProgram.programId,
          })
          .signers([deployerKeypair])
          .rpc();
      } catch (err: any) {
        if (!err.message.includes("already in use")) throw err;
      }
      await sleep(500);

      [anchorUserBalancePda] = PublicKey.findProgramAddressSync(
        [USER_SEED, attackerKeypair.publicKey.toBuffer()],
        vulnerableProgram.programId
      );

      try {
        await vulnerableProgram.methods
          .createUser()
          .accounts({
            owner: attackerKeypair.publicKey,
            vaultState: anchorVulnerableVaultPda,
            userBalance: anchorUserBalancePda,
            systemProgram: SystemProgram.programId,
          })
          .signers([attackerKeypair])
          .rpc();
      } catch (err: any) {
        if (!err.message.includes("already in use")) throw err;
      }
      await sleep(500);
      console.log("    Anchor vulnerable vault ready.\n");
    });

    it("✗ ANCHOR VULNERABLE: Balance overflow via wrapping_add()", async () => {
      console.log("\n      [Anchor] Overflow exploit via wrapping_add()");

      // Deposit near-MAX amount
      await vulnerableProgram.methods
        .deposit(U64_MAX_MINUS_10)
        .accounts({
          owner: attackerKeypair.publicKey,
          vaultState: anchorVulnerableVaultPda,
          userBalance: anchorUserBalancePda,
        })
        .signers([attackerKeypair])
        .rpc();

      let userBalance = await vulnerableProgram.account.userBalance.fetch(anchorUserBalancePda);
      console.log(`      Balance after large deposit: ${formatBigNumber(new BN(userBalance.balance.toString()))}`);

      // Deposit small amount that causes overflow
      await vulnerableProgram.methods
        .deposit(new BN(20))
        .accounts({
          owner: attackerKeypair.publicKey,
          vaultState: anchorVulnerableVaultPda,
          userBalance: anchorUserBalancePda,
        })
        .signers([attackerKeypair])
        .rpc();

      userBalance = await vulnerableProgram.account.userBalance.fetch(anchorUserBalancePda);
      const finalBalance = new BN(userBalance.balance.toString());
      console.log(`      Balance after overflow: ${finalBalance.toString()}`);

      expect(finalBalance.toString()).to.equal("9");
      console.log("      \x1b[33m⚠️ ANCHOR EXPLOIT: Balance wrapped from near-MAX to 9!\x1b[0m");
    });
  });

  // =============================================================================
  // PINOCCHIO VULNERABLE PROGRAM TESTS
  // =============================================================================

  describe("PINOCCHIO VULNERABLE Program", () => {
    let pinocchioUserBalanceAccount: Keypair;

    before(async () => {
      console.log("    Initializing Pinocchio vulnerable vault...");

      // Create vault account
      pinocchioVulnerableVaultAccount = await createFundedAccount(
        connection,
        deployerKeypair,
        PINOCCHIO_VULNERABLE_PROGRAM_ID,
        VAULT_STATE_SIZE
      );

      // Initialize vault
      const initIx = new TransactionInstruction({
        programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioVulnerableVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: deployerKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildInitializeVaultInstructionData(0),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [deployerKeypair]);

      // Create user balance account
      pinocchioUserBalanceAccount = await createFundedAccount(
        connection,
        attackerKeypair,
        PINOCCHIO_VULNERABLE_PROGRAM_ID,
        USER_BALANCE_SIZE
      );

      // Initialize user
      const createUserIx = new TransactionInstruction({
        programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioVulnerableVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: pinocchioUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: attackerKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildCreateUserInstructionData(0),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(createUserIx), [attackerKeypair]);
      await sleep(500);
      console.log("    Pinocchio vulnerable vault ready.\n");
    });

    it("✗ PINOCCHIO VULNERABLE: Balance overflow via wrapping_add() - SAME VULNERABILITY", async () => {
      console.log("\n      [Pinocchio] Overflow exploit via wrapping_add()");

      // Deposit near-MAX amount
      const depositIx1 = new TransactionInstruction({
        programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioVulnerableVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: pinocchioUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: attackerKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildDepositInstructionData(U64_MAX_MINUS_10),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(depositIx1), [attackerKeypair]);

      let accountInfo = await connection.getAccountInfo(pinocchioUserBalanceAccount.publicKey);
      let userBalance = decodeUserBalance(accountInfo!.data);
      console.log(`      Balance after large deposit: ${formatBigNumber(userBalance.balance)}`);

      // Deposit small amount that causes overflow
      const depositIx2 = new TransactionInstruction({
        programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioVulnerableVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: pinocchioUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: attackerKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildDepositInstructionData(new BN(20)),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(depositIx2), [attackerKeypair]);

      accountInfo = await connection.getAccountInfo(pinocchioUserBalanceAccount.publicKey);
      userBalance = decodeUserBalance(accountInfo!.data);
      console.log(`      Balance after overflow: ${userBalance.balance.toString()}`);

      expect(userBalance.balance.toString()).to.equal("9");
      console.log("      \x1b[33m⚠️ PINOCCHIO EXPLOIT: Balance wrapped from near-MAX to 9!\x1b[0m");
    });

    it("✗ PINOCCHIO VULNERABLE: Balance underflow via wrapping_sub()", async () => {
      console.log("\n      [Pinocchio] Underflow exploit via wrapping_sub()");

      // Create fresh user for underflow test
      const freshUserKeypair = Keypair.generate();
      await connection.requestAirdrop(freshUserKeypair.publicKey, 5 * LAMPORTS_PER_SOL);
      await sleep(1000);

      const freshUserBalanceAccount = await createFundedAccount(
        connection,
        freshUserKeypair,
        PINOCCHIO_VULNERABLE_PROGRAM_ID,
        USER_BALANCE_SIZE
      );

      // Initialize user
      const createUserIx = new TransactionInstruction({
        programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioVulnerableVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: freshUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: freshUserKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildCreateUserInstructionData(0),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(createUserIx), [freshUserKeypair]);

      // Deposit small amount
      const depositIx = new TransactionInstruction({
        programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioVulnerableVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: freshUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: freshUserKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildDepositInstructionData(new BN(100)),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(depositIx), [freshUserKeypair]);

      let accountInfo = await connection.getAccountInfo(freshUserBalanceAccount.publicKey);
      let userBalance = decodeUserBalance(accountInfo!.data);
      console.log(`      Balance after deposit: ${userBalance.balance.toString()}`);

      // Withdraw more than balance (causes underflow)
      const withdrawIx = new TransactionInstruction({
        programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
        keys: [
          { pubkey: freshUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: freshUserKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildWithdrawInstructionData(new BN(200)),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [freshUserKeypair]);

      accountInfo = await connection.getAccountInfo(freshUserBalanceAccount.publicKey);
      userBalance = decodeUserBalance(accountInfo!.data);
      console.log(`      Balance after underflow: ${formatBigNumber(userBalance.balance)}`);

      // 100 - 200 = -100 wraps to MAX - 99
      const expectedUnderflow = U64_MAX.sub(new BN(99));
      expect(userBalance.balance.eq(expectedUnderflow)).to.be.true;

      console.log("      \x1b[33m⚠️ PINOCCHIO EXPLOIT: Balance wrapped from 100 to near-MAX!\x1b[0m");
    });
  });

  // =============================================================================
  // ANCHOR SECURE PROGRAM TESTS
  // =============================================================================

  describe("ANCHOR SECURE Program", () => {
    let anchorSecureUserBalancePda: PublicKey;
    let secureUserKeypair: Keypair;

    before(async () => {
      console.log("    Initializing Anchor secure vault...");
      try {
        await secureProgram.methods
          .initializeVault()
          .accounts({
            authority: deployerKeypair.publicKey,
            vaultState: anchorSecureVaultPda,
            systemProgram: SystemProgram.programId,
          })
          .signers([deployerKeypair])
          .rpc();
      } catch (err: any) {
        if (!err.message.includes("already in use")) throw err;
      }
      await sleep(500);

      secureUserKeypair = Keypair.generate();
      await connection.requestAirdrop(secureUserKeypair.publicKey, 5 * LAMPORTS_PER_SOL);
      await sleep(1000);

      [anchorSecureUserBalancePda] = PublicKey.findProgramAddressSync(
        [USER_SEED, secureUserKeypair.publicKey.toBuffer()],
        secureProgram.programId
      );

      try {
        await secureProgram.methods
          .createUser()
          .accounts({
            owner: secureUserKeypair.publicKey,
            vaultState: anchorSecureVaultPda,
            userBalance: anchorSecureUserBalancePda,
            systemProgram: SystemProgram.programId,
          })
          .signers([secureUserKeypair])
          .rpc();
      } catch (err: any) {
        if (!err.message.includes("already in use")) throw err;
      }
      await sleep(500);
      console.log("    Anchor secure vault ready.\n");
    });

    it("✓ ANCHOR SECURE: Rejects deposit exceeding MAX_DEPOSIT", async () => {
      console.log("\n      [Anchor] Excessive deposit blocked by MAX_DEPOSIT check");

      const excessiveDeposit = new BN("2000000000000"); // 2000 SOL > MAX_DEPOSIT

      try {
        await secureProgram.methods
          .deposit(excessiveDeposit)
          .accounts({
            owner: secureUserKeypair.publicKey,
            vaultState: anchorSecureVaultPda,
            userBalance: anchorSecureUserBalancePda,
          })
          .signers([secureUserKeypair])
          .rpc();

        expect.fail("Should have been blocked");
      } catch (err: any) {
        const isExpectedError =
          err.message.includes("ExceedsMaxDeposit") ||
          err.message.includes("Deposit amount exceeds maximum");
        expect(isExpectedError).to.be.true;
        console.log("      \x1b[32m✓ ANCHOR SECURE: Excessive deposit blocked\x1b[0m");
      }
    });

    it("✓ ANCHOR SECURE: Rejects withdrawal exceeding balance", async () => {
      console.log("\n      [Anchor] Underflow blocked by InsufficientBalance check");

      // First deposit valid amount
      await secureProgram.methods
        .deposit(new BN(100))
        .accounts({
          owner: secureUserKeypair.publicKey,
          vaultState: anchorSecureVaultPda,
          userBalance: anchorSecureUserBalancePda,
        })
        .signers([secureUserKeypair])
        .rpc();

      try {
        await secureProgram.methods
          .withdraw(new BN(500))
          .accounts({
            owner: secureUserKeypair.publicKey,
            userBalance: anchorSecureUserBalancePda,
          })
          .signers([secureUserKeypair])
          .rpc();

        expect.fail("Should have been blocked");
      } catch (err: any) {
        const isExpectedError =
          err.message.includes("InsufficientBalance") ||
          err.message.includes("Insufficient balance");
        expect(isExpectedError).to.be.true;
        console.log("      \x1b[32m✓ ANCHOR SECURE: Underflow withdrawal blocked\x1b[0m");
      }
    });

    it("✓ ANCHOR SECURE: Rejects reward rate exceeding MAX_REWARD_RATE", async () => {
      console.log("\n      [Anchor] Excessive reward rate blocked");

      try {
        await secureProgram.methods
          .calculateRewards(new BN(100000)) // > MAX_REWARD_RATE
          .accounts({
            authority: deployerKeypair.publicKey,
            vaultState: anchorSecureVaultPda,
            userBalance: anchorSecureUserBalancePda,
          })
          .signers([deployerKeypair])
          .rpc();

        expect.fail("Should have been blocked");
      } catch (err: any) {
        const isExpectedError =
          err.message.includes("ExceedsMaxRewardRate") ||
          err.message.includes("Reward rate exceeds maximum");
        expect(isExpectedError).to.be.true;
        console.log("      \x1b[32m✓ ANCHOR SECURE: Excessive reward rate blocked\x1b[0m");
      }
    });
  });

  // =============================================================================
  // PINOCCHIO SECURE PROGRAM TESTS
  // =============================================================================

  describe("PINOCCHIO SECURE Program", () => {
    let pinocchioSecureUserBalanceAccount: Keypair;
    let pinocchioSecureUserKeypair: Keypair;

    before(async () => {
      console.log("    Initializing Pinocchio secure vault...");

      pinocchioSecureUserKeypair = Keypair.generate();
      await connection.requestAirdrop(pinocchioSecureUserKeypair.publicKey, 5 * LAMPORTS_PER_SOL);
      await sleep(1000);

      // Create vault account
      pinocchioSecureVaultAccount = await createFundedAccount(
        connection,
        deployerKeypair,
        PINOCCHIO_SECURE_PROGRAM_ID,
        VAULT_STATE_SIZE
      );

      // Initialize vault
      const initIx = new TransactionInstruction({
        programId: PINOCCHIO_SECURE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: deployerKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildInitializeVaultInstructionData(0),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [deployerKeypair]);

      // Create user balance account
      pinocchioSecureUserBalanceAccount = await createFundedAccount(
        connection,
        pinocchioSecureUserKeypair,
        PINOCCHIO_SECURE_PROGRAM_ID,
        USER_BALANCE_SIZE
      );

      // Initialize user
      const createUserIx = new TransactionInstruction({
        programId: PINOCCHIO_SECURE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: pinocchioSecureUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: pinocchioSecureUserKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildCreateUserInstructionData(0),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(createUserIx), [pinocchioSecureUserKeypair]);
      await sleep(500);
      console.log("    Pinocchio secure vault ready.\n");
    });

    it("✓ PINOCCHIO SECURE: Rejects deposit exceeding MAX_DEPOSIT - MANUAL VALIDATION", async () => {
      console.log("\n      [Pinocchio] Excessive deposit blocked by if-check");

      const excessiveDeposit = new BN("2000000000000"); // 2000 SOL > MAX_DEPOSIT
      let attackSucceeded = false;

      try {
        const depositIx = new TransactionInstruction({
          programId: PINOCCHIO_SECURE_PROGRAM_ID,
          keys: [
            { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: pinocchioSecureUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: pinocchioSecureUserKeypair.publicKey, isSigner: true, isWritable: false },
          ],
          data: buildDepositInstructionData(excessiveDeposit),
        });

        await sendAndConfirmTransaction(connection, new Transaction().add(depositIx), [pinocchioSecureUserKeypair]);
        attackSucceeded = true;
      } catch (err: any) {
        // Error code 3 = ExceedsMaxDeposit
        console.log("      Transaction rejected (as expected)");
      }

      expect(attackSucceeded).to.be.false;
      console.log("      \x1b[32m✓ PINOCCHIO SECURE: Excessive deposit blocked\x1b[0m");
    });

    it("✓ PINOCCHIO SECURE: Rejects withdrawal exceeding balance - MANUAL VALIDATION", async () => {
      console.log("\n      [Pinocchio] Underflow blocked by balance check + checked_sub()");

      // First deposit valid amount
      const depositIx = new TransactionInstruction({
        programId: PINOCCHIO_SECURE_PROGRAM_ID,
        keys: [
          { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: pinocchioSecureUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
          { pubkey: pinocchioSecureUserKeypair.publicKey, isSigner: true, isWritable: false },
        ],
        data: buildDepositInstructionData(new BN(100)),
      });

      await sendAndConfirmTransaction(connection, new Transaction().add(depositIx), [pinocchioSecureUserKeypair]);

      let accountInfo = await connection.getAccountInfo(pinocchioSecureUserBalanceAccount.publicKey);
      let userBalance = decodeUserBalance(accountInfo!.data);
      console.log(`      Balance after deposit: ${userBalance.balance.toString()}`);

      let attackSucceeded = false;

      try {
        const withdrawIx = new TransactionInstruction({
          programId: PINOCCHIO_SECURE_PROGRAM_ID,
          keys: [
            { pubkey: pinocchioSecureUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: pinocchioSecureUserKeypair.publicKey, isSigner: true, isWritable: false },
          ],
          data: buildWithdrawInstructionData(new BN(500)),
        });

        await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [pinocchioSecureUserKeypair]);
        attackSucceeded = true;
      } catch (err: any) {
        // Error code 2 = InsufficientBalance
        console.log("      Transaction rejected (as expected)");
      }

      expect(attackSucceeded).to.be.false;

      // Verify balance unchanged
      accountInfo = await connection.getAccountInfo(pinocchioSecureUserBalanceAccount.publicKey);
      userBalance = decodeUserBalance(accountInfo!.data);
      expect(userBalance.balance.toString()).to.equal("100");

      console.log("      \x1b[32m✓ PINOCCHIO SECURE: Underflow withdrawal blocked\x1b[0m");
    });

    it("✓ PINOCCHIO SECURE: Rejects reward rate exceeding MAX_REWARD_RATE - MANUAL VALIDATION", async () => {
      console.log("\n      [Pinocchio] Excessive reward rate blocked by if-check");

      let attackSucceeded = false;

      try {
        const rewardsIx = new TransactionInstruction({
          programId: PINOCCHIO_SECURE_PROGRAM_ID,
          keys: [
            { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: pinocchioSecureUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: deployerKeypair.publicKey, isSigner: true, isWritable: false },
          ],
          data: buildCalculateRewardsInstructionData(new BN(100000)), // > MAX_REWARD_RATE
        });

        await sendAndConfirmTransaction(connection, new Transaction().add(rewardsIx), [deployerKeypair]);
        attackSucceeded = true;
      } catch (err: any) {
        // Error code 4 = ExceedsMaxRewardRate
        console.log("      Transaction rejected (as expected)");
      }

      expect(attackSucceeded).to.be.false;
      console.log("      \x1b[32m✓ PINOCCHIO SECURE: Excessive reward rate blocked\x1b[0m");
    });

    describe("Authorized Operations", () => {
      it("✓ PINOCCHIO SECURE: Allows valid deposit within limits", async () => {
        console.log("\n      [Pinocchio] Valid deposit accepted");

        // Create fresh user
        const validUserKeypair = Keypair.generate();
        await connection.requestAirdrop(validUserKeypair.publicKey, 5 * LAMPORTS_PER_SOL);
        await sleep(1000);

        const validUserBalanceAccount = await createFundedAccount(
          connection,
          validUserKeypair,
          PINOCCHIO_SECURE_PROGRAM_ID,
          USER_BALANCE_SIZE
        );

        // Create user
        const createUserIx = new TransactionInstruction({
          programId: PINOCCHIO_SECURE_PROGRAM_ID,
          keys: [
            { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: validUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: validUserKeypair.publicKey, isSigner: true, isWritable: false },
          ],
          data: buildCreateUserInstructionData(0),
        });

        await sendAndConfirmTransaction(connection, new Transaction().add(createUserIx), [validUserKeypair]);

        // Deposit at MAX_DEPOSIT limit
        const maxDeposit = new BN("1000000000000"); // 1000 SOL = MAX_DEPOSIT
        const depositIx = new TransactionInstruction({
          programId: PINOCCHIO_SECURE_PROGRAM_ID,
          keys: [
            { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: validUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: validUserKeypair.publicKey, isSigner: true, isWritable: false },
          ],
          data: buildDepositInstructionData(maxDeposit),
        });

        await sendAndConfirmTransaction(connection, new Transaction().add(depositIx), [validUserKeypair]);

        const accountInfo = await connection.getAccountInfo(validUserBalanceAccount.publicKey);
        const userBalance = decodeUserBalance(accountInfo!.data);

        expect(userBalance.balance.toString()).to.equal(maxDeposit.toString());
        console.log(`      Deposited: ${formatBigNumber(maxDeposit)}`);
        console.log("      \x1b[32m✓ SUCCESS: Valid deposit accepted\x1b[0m");
      });

      it("✓ PINOCCHIO SECURE: Allows valid reward calculation", async () => {
        console.log("\n      [Pinocchio] Valid reward calculation accepted");

        // Deposit first
        const validRate = new BN(100); // Within MAX_REWARD_RATE
        const rewardsIx = new TransactionInstruction({
          programId: PINOCCHIO_SECURE_PROGRAM_ID,
          keys: [
            { pubkey: pinocchioSecureVaultAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: pinocchioSecureUserBalanceAccount.publicKey, isSigner: false, isWritable: true },
            { pubkey: deployerKeypair.publicKey, isSigner: true, isWritable: false },
          ],
          data: buildCalculateRewardsInstructionData(validRate),
        });

        const balanceBefore = await connection.getAccountInfo(pinocchioSecureUserBalanceAccount.publicKey);
        const userBalanceBefore = decodeUserBalance(balanceBefore!.data);

        await sendAndConfirmTransaction(connection, new Transaction().add(rewardsIx), [deployerKeypair]);

        const balanceAfter = await connection.getAccountInfo(pinocchioSecureUserBalanceAccount.publicKey);
        const userBalanceAfter = decodeUserBalance(balanceAfter!.data);

        // Expected: balance + (balance * rate) = 100 + (100 * 100) = 10100
        console.log(`      Balance before: ${userBalanceBefore.balance.toString()}`);
        console.log(`      Balance after: ${userBalanceAfter.balance.toString()}`);
        console.log("      \x1b[32m✓ SUCCESS: Valid reward calculation accepted\x1b[0m");
      });
    });
  });

  // =============================================================================
  // FRAMEWORK COMPARISON SUMMARY
  // =============================================================================

  after(() => {
    console.log("\n");
    console.log("  ========================================");
    console.log("  FRAMEWORK COMPARISON: UNSAFE ARITHMETIC");
    console.log("  ========================================");
    console.log("");
    console.log("  | Feature                  | Anchor                         | Pinocchio                      |");
    console.log("  |--------------------------|--------------------------------|--------------------------------|");
    console.log("  | Safe arithmetic          | checked_add().ok_or()          | checked_add().ok_or()          |");
    console.log("  | Error definition         | #[error_code] enum             | Custom enum + impl From        |");
    console.log("  | Input validation         | require!(amount <= MAX)        | if amount > MAX { return Err } |");
    console.log("  | Error propagation        | ErrorCode::ExceedsMax          | SecureError::ExceedsMax.into() |");
    console.log("  | Instruction format       | 8-byte sighash discriminator   | 1-byte manual discriminator    |");
    console.log("  | Account serialization    | Automatic via #[account]       | Manual try_from_slice/serialize|");
    console.log("");
    console.log("  Security Implications:");
    console.log("  - Both frameworks support identical safe arithmetic patterns");
    console.log("  - Anchor's require!() macro is more concise");
    console.log("  - Pinocchio's manual checks are more verbose but equally effective");
    console.log("  - Both produce clear custom error codes");
    console.log("");
    console.log("  Key Takeaways:");
    console.log("  1. ALWAYS use checked_add/sub/mul for arithmetic operations");
    console.log("  2. ALWAYS validate inputs against maximum limits");
    console.log("  3. ALWAYS check balance >= withdrawal before subtraction");
    console.log("  4. Framework choice doesn't affect security - developer discipline does");
    console.log("  ========================================\n");
  });
});
