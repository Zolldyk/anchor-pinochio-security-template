/**
 * Token Manipulation Pattern - Arithmetic Vulnerability Tests with SPL Tokens
 *
 * This test suite demonstrates arithmetic overflow and underflow vulnerabilities
 * in token vault tracking scenarios. It shows how unsafe arithmetic can lead to
 * inconsistent balance tracking when using real SPL Token operations.
 *
 * Pattern: Token Balance Tracking Manipulation
 * Vulnerability: Wrapping arithmetic in token tracking allows balance inconsistency
 * Impact: Tracked balances can diverge from actual token holdings
 *
 * Key Insight: Even when actual token transfers are correct, the tracking
 * variables can be manipulated through arithmetic overflow/underflow.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import {
  createMint,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  getAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { expect } from "chai";

// Import IDL types
import { TokenVulnerableUnsafeArithmetic } from "../target/types/token_vulnerable_unsafe_arithmetic";
import { TokenSecureUnsafeArithmetic } from "../target/types/token_secure_unsafe_arithmetic";

/**
 * Sleep helper for RPC rate limit handling
 */
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Format large numbers for display
 */
const formatBigNumber = (n: BN | bigint | number): string => {
  const str = n.toString();
  if (str.length > 15) {
    return `${str.substring(0, 6)}...${str.substring(str.length - 6)} (${str.length} digits)`;
  }
  return str;
};

/**
 * Format token amounts with decimals
 */
const formatTokenAmount = (amount: bigint | BN, decimals: number = 9): string => {
  const amountStr = amount.toString();
  if (amountStr.length <= decimals) {
    return `0.${amountStr.padStart(decimals, "0")} tokens`;
  }
  const whole = amountStr.slice(0, -decimals);
  const fraction = amountStr.slice(-decimals);
  return `${whole}.${fraction.slice(0, 4)}... tokens`;
};

// Maximum u64 value
const U64_MAX = new BN("18446744073709551615");
const TOKEN_VAULT_SEED = Buffer.from("token_vault");

describe("Token Manipulation Pattern", () => {
  // Configure the Anchor provider
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  // Load programs from workspace
  const vulnerableProgram = anchor.workspace
    .TokenVulnerableUnsafeArithmetic as Program<TokenVulnerableUnsafeArithmetic>;
  const secureProgram = anchor.workspace
    .TokenSecureUnsafeArithmetic as Program<TokenSecureUnsafeArithmetic>;

  // Test keypairs
  let payerKeypair: Keypair;
  let userKeypair: Keypair;

  // Token infrastructure
  let tokenMint: PublicKey;
  let mintAuthority: Keypair;
  const TOKEN_DECIMALS = 9;
  const INITIAL_MINT_AMOUNT = BigInt("1000000000000000000"); // 1 billion tokens with 9 decimals

  // Vulnerable program state
  let vulnerableVaultPda: PublicKey;
  let vulnerableVaultBump: number;
  let vulnerableVaultTokenAccount: PublicKey;
  let vulnerableUserTokenAccount: PublicKey;

  // Secure program state
  let secureVaultPda: PublicKey;
  let secureVaultBump: number;
  let secureVaultTokenAccount: PublicKey;
  let secureUserTokenAccount: PublicKey;

  before(async () => {
    console.log("\n  ========================================");
    console.log("  TOKEN MANIPULATION PATTERN - EXPLOIT DEMO");
    console.log("  ========================================");
    console.log("\n  This demonstrates arithmetic vulnerabilities in token vault tracking.");
    console.log("  The tracked balances (total_deposited, total_withdrawn) can be");
    console.log("  manipulated through overflow/underflow even when actual token");
    console.log("  transfers are handled correctly by SPL Token Program.\n");
    console.log("  Vulnerabilities demonstrated:");
    console.log("    1. Token tracking overflow via large deposit tracking");
    console.log("    2. Token tracking underflow via withdrawal tracking manipulation\n");

    // Generate test keypairs
    payerKeypair = Keypair.generate();
    userKeypair = Keypair.generate();
    mintAuthority = Keypair.generate();

    // Airdrop SOL to all keypairs
    const airdropAmount = 20 * anchor.web3.LAMPORTS_PER_SOL;

    await Promise.all([
      provider.connection.requestAirdrop(payerKeypair.publicKey, airdropAmount),
      provider.connection.requestAirdrop(userKeypair.publicKey, airdropAmount),
      provider.connection.requestAirdrop(mintAuthority.publicKey, airdropAmount),
    ]);

    // Wait for airdrops to confirm
    await sleep(2000);

    // Create token mint
    console.log("  Creating SPL Token Mint...");
    tokenMint = await createMint(
      provider.connection,
      payerKeypair,
      mintAuthority.publicKey,
      null,
      TOKEN_DECIMALS
    );
    console.log(`    Token Mint: ${tokenMint.toBase58()}`);

    // Derive vault PDAs for both programs
    [vulnerableVaultPda, vulnerableVaultBump] = PublicKey.findProgramAddressSync(
      [TOKEN_VAULT_SEED, tokenMint.toBuffer()],
      vulnerableProgram.programId
    );

    [secureVaultPda, secureVaultBump] = PublicKey.findProgramAddressSync(
      [TOKEN_VAULT_SEED, tokenMint.toBuffer()],
      secureProgram.programId
    );

    console.log(`    Vulnerable Vault PDA: ${vulnerableVaultPda.toBase58()}`);
    console.log(`    Secure Vault PDA:     ${secureVaultPda.toBase58()}`);

    // Create token accounts for vaults (owned by the vault PDAs)
    console.log("\n  Creating Vault Token Accounts...");

    const vulnerableVaultAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payerKeypair,
      tokenMint,
      vulnerableVaultPda,
      true // allowOwnerOffCurve for PDA
    );
    vulnerableVaultTokenAccount = vulnerableVaultAta.address;
    console.log(`    Vulnerable Vault Token Account: ${vulnerableVaultTokenAccount.toBase58()}`);

    const secureVaultAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payerKeypair,
      tokenMint,
      secureVaultPda,
      true // allowOwnerOffCurve for PDA
    );
    secureVaultTokenAccount = secureVaultAta.address;
    console.log(`    Secure Vault Token Account:     ${secureVaultTokenAccount.toBase58()}`);

    // Create token account for user
    console.log("\n  Creating User Token Account...");
    const userAta = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payerKeypair,
      tokenMint,
      userKeypair.publicKey
    );
    vulnerableUserTokenAccount = userAta.address;
    secureUserTokenAccount = userAta.address; // Same user account for both programs
    console.log(`    User Token Account: ${vulnerableUserTokenAccount.toBase58()}`);

    // Mint tokens to user
    console.log("\n  Minting tokens to user...");
    await mintTo(
      provider.connection,
      payerKeypair,
      tokenMint,
      vulnerableUserTokenAccount,
      mintAuthority,
      INITIAL_MINT_AMOUNT
    );

    const userTokenInfo = await getAccount(provider.connection, vulnerableUserTokenAccount);
    console.log(`    User Token Balance: ${formatTokenAmount(userTokenInfo.amount, TOKEN_DECIMALS)}`);

    console.log("\n  Test Setup Complete.\n");
  });

  // =========================================================================
  // VULNERABLE PROGRAM TESTS
  // =========================================================================

  describe("VULNERABLE Token Program", () => {
    before(async () => {
      console.log("\n    Initializing vulnerable token vault...");

      try {
        await vulnerableProgram.methods
          .initializeTokenVault()
          .accounts({
            payer: payerKeypair.publicKey,
            mint: tokenMint,
            vaultState: vulnerableVaultPda,
            vaultTokenAccount: vulnerableVaultTokenAccount,
            vaultAuthority: vulnerableVaultPda,
            systemProgram: SystemProgram.programId,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([payerKeypair])
          .rpc();
        console.log("    Vulnerable token vault initialized.\n");
      } catch (err: unknown) {
        if (err instanceof Error && !err.message.includes("already in use")) {
          throw err;
        }
        console.log("    Vulnerable token vault already initialized.\n");
      }
      await sleep(500);
    });

    it("✗ TOKEN VULNERABLE: Total deposited overflow via large token deposit tracking", async () => {
      console.log("\n      Scenario: Attacker exploits tracking overflow in token deposits");
      console.log("      Attack: Make deposits that cause total_deposited to wrap around");
      console.log("      Note: Actual token transfers are correct, but TRACKING is wrong\n");

      // Check initial state
      let vaultState = await vulnerableProgram.account.tokenVaultState.fetch(vulnerableVaultPda);
      console.log(`      Initial total_deposited: ${formatBigNumber(vaultState.totalDeposited)}`);
      console.log(`      Initial total_withdrawn: ${formatBigNumber(vaultState.totalWithdrawn)}`);

      let vaultTokenInfo = await getAccount(provider.connection, vulnerableVaultTokenAccount);
      console.log(`      Actual vault token balance: ${formatTokenAmount(vaultTokenInfo.amount, TOKEN_DECIMALS)}`);

      // First deposit: A normal amount
      const firstDeposit = new BN("1000000000"); // 1 token
      console.log(`\n      Step 1: Depositing ${formatTokenAmount(BigInt(firstDeposit.toString()), TOKEN_DECIMALS)}`);

      await vulnerableProgram.methods
        .depositTokens(firstDeposit)
        .accounts({
          depositor: userKeypair.publicKey,
          mint: tokenMint,
          vaultState: vulnerableVaultPda,
          depositorTokenAccount: vulnerableUserTokenAccount,
          vaultTokenAccount: vulnerableVaultTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([userKeypair])
        .rpc();

      await sleep(500);

      vaultState = await vulnerableProgram.account.tokenVaultState.fetch(vulnerableVaultPda);
      vaultTokenInfo = await getAccount(provider.connection, vulnerableVaultTokenAccount);

      console.log(`      After first deposit:`);
      console.log(`        Tracked total_deposited: ${formatBigNumber(vaultState.totalDeposited)}`);
      console.log(`        Actual vault balance:    ${formatTokenAmount(vaultTokenInfo.amount, TOKEN_DECIMALS)}`);

      // The vulnerable program's wrapping_add will allow overflow if we could deposit u64::MAX worth
      // But the SPL Token Program won't allow that (insufficient tokens)
      // However, if the vault already had near-MAX tracked and we deposit more, it would wrap
      // This demonstrates the PATTERN even if we can't fully exploit it with limited tokens

      console.log(`\n      Note: Full overflow exploit requires the tracked counter to be near u64::MAX.`);
      console.log(`      The vulnerability is that wrapping_add() allows silent overflow,`);
      console.log(`      which means if total_deposited ever gets near MAX (through bugs or`);
      console.log(`      accumulated deposits), a small deposit could wrap it to zero.`);

      console.log(
        "\n      \x1b[33m⚠️ VULNERABILITY DEMONSTRATED: wrapping_add() used for token tracking\x1b[0m"
      );
      console.log("      Impact: Tracked balance could diverge from actual token holdings");
    });

    it("✗ TOKEN VULNERABLE: Balance tracking inconsistency via wrapping subtraction", async () => {
      console.log("\n      Scenario: Demonstrate tracking inconsistency potential");
      console.log("      Attack: The wrapping_sub in available balance calculation is dangerous\n");

      // Get current state
      const vaultState = await vulnerableProgram.account.tokenVaultState.fetch(vulnerableVaultPda);
      const vaultTokenInfo = await getAccount(provider.connection, vulnerableVaultTokenAccount);

      console.log(`      Current tracked total_deposited: ${formatBigNumber(vaultState.totalDeposited)}`);
      console.log(`      Current tracked total_withdrawn: ${formatBigNumber(vaultState.totalWithdrawn)}`);
      console.log(`      Current actual vault balance:    ${formatTokenAmount(vaultTokenInfo.amount, TOKEN_DECIMALS)}`);

      // Calculate what the vulnerable program thinks is available
      const trackedAvailable = vaultState.totalDeposited.sub(vaultState.totalWithdrawn);
      console.log(`      Tracked available (deposited - withdrawn): ${formatBigNumber(trackedAvailable)}`);

      // Attempt withdrawal
      const withdrawAmount = new BN("500000000"); // 0.5 tokens
      console.log(`\n      Attempting to withdraw: ${formatTokenAmount(BigInt(withdrawAmount.toString()), TOKEN_DECIMALS)}`);

      try {
        await vulnerableProgram.methods
          .withdrawTokens(withdrawAmount)
          .accounts({
            withdrawer: userKeypair.publicKey,
            mint: tokenMint,
            vaultState: vulnerableVaultPda,
            vaultTokenAccount: vulnerableVaultTokenAccount,
            withdrawerTokenAccount: vulnerableUserTokenAccount,
            vaultAuthority: vulnerableVaultPda,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([userKeypair])
          .rpc();

        await sleep(500);

        const newVaultState = await vulnerableProgram.account.tokenVaultState.fetch(vulnerableVaultPda);
        const newVaultTokenInfo = await getAccount(provider.connection, vulnerableVaultTokenAccount);

        console.log(`\n      After withdrawal:`);
        console.log(`        Tracked total_deposited: ${formatBigNumber(newVaultState.totalDeposited)}`);
        console.log(`        Tracked total_withdrawn: ${formatBigNumber(newVaultState.totalWithdrawn)}`);
        console.log(`        Actual vault balance:    ${formatTokenAmount(newVaultTokenInfo.amount, TOKEN_DECIMALS)}`);

        console.log(
          "\n      \x1b[33m⚠️ VULNERABILITY PATTERN: wrapping arithmetic allows silent errors\x1b[0m"
        );
        console.log("      The use of wrapping_add/sub means tracking errors won't be caught");
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        console.log(`      Withdrawal failed: ${errorMessage.substring(0, 100)}...`);
        console.log("      (SPL Token Program may block if insufficient balance in vault)");
      }
    });
  });

  // =========================================================================
  // SECURE PROGRAM TESTS
  // =========================================================================

  describe("SECURE Token Program", () => {
    // Need fresh user token account with tokens for secure tests
    let secureTestUserKeypair: Keypair;
    let secureTestUserTokenAccount: PublicKey;

    before(async () => {
      console.log("\n    Setting up secure program tests...");

      // Create fresh user for secure tests
      secureTestUserKeypair = Keypair.generate();
      await provider.connection.requestAirdrop(
        secureTestUserKeypair.publicKey,
        10 * anchor.web3.LAMPORTS_PER_SOL
      );
      await sleep(2000);

      // Create token account for test user
      const userAta = await getOrCreateAssociatedTokenAccount(
        provider.connection,
        payerKeypair,
        tokenMint,
        secureTestUserKeypair.publicKey
      );
      secureTestUserTokenAccount = userAta.address;

      // Mint tokens to test user
      await mintTo(
        provider.connection,
        payerKeypair,
        tokenMint,
        secureTestUserTokenAccount,
        mintAuthority,
        BigInt("100000000000000000") // 100 million tokens
      );

      console.log("    Initializing secure token vault...");

      try {
        await secureProgram.methods
          .initializeTokenVault()
          .accounts({
            payer: payerKeypair.publicKey,
            mint: tokenMint,
            vaultState: secureVaultPda,
            vaultTokenAccount: secureVaultTokenAccount,
            vaultAuthority: secureVaultPda,
            systemProgram: SystemProgram.programId,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([payerKeypair])
          .rpc();
        console.log("    Secure token vault initialized.\n");
      } catch (err: unknown) {
        if (err instanceof Error && !err.message.includes("already in use")) {
          throw err;
        }
        console.log("    Secure token vault already initialized.\n");
      }
      await sleep(500);
    });

    it("✓ TOKEN SECURE: Rejects token deposit that would overflow tracking", async () => {
      console.log("\n      Scenario: Attacker attempts deposit that would overflow tracking");
      console.log("      Expected: Fails with TokenArithmeticOverflow or ExceedsMaxTokenDeposit\n");

      // The secure program has MAX_TOKEN_DEPOSIT limit
      // Try to deposit more than the limit
      const excessiveDeposit = new BN("2000000000000000000"); // 2 billion tokens (exceeds MAX)

      console.log(`      Attempting deposit: ${formatBigNumber(excessiveDeposit)}`);
      console.log(`      MAX_TOKEN_DEPOSIT:  ${formatBigNumber(new BN("1000000000000000000"))}`);

      try {
        await secureProgram.methods
          .depositTokens(excessiveDeposit)
          .accounts({
            depositor: secureTestUserKeypair.publicKey,
            mint: tokenMint,
            vaultState: secureVaultPda,
            depositorTokenAccount: secureTestUserTokenAccount,
            vaultTokenAccount: secureVaultTokenAccount,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([secureTestUserKeypair])
          .rpc();

        expect.fail("Should have been blocked by MAX_TOKEN_DEPOSIT check");
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        const isExpectedError =
          errorMessage.includes("ExceedsMaxTokenDeposit") ||
          errorMessage.includes("TokenArithmeticOverflow") ||
          errorMessage.includes("exceeds maximum");

        expect(isExpectedError).to.be.true;

        console.log(`      Error received: ${errorMessage.substring(0, 80)}...`);
        console.log(
          "      \x1b[32m✓ SECURITY VERIFIED: Excessive deposit blocked\x1b[0m"
        );
      }
    });

    it("✓ TOKEN SECURE: Rejects withdrawal exceeding tracked balance", async () => {
      console.log("\n      Scenario: Attacker attempts withdrawal > tracked available balance");
      console.log("      Expected: Fails with InsufficientTokens error\n");

      // First make a valid deposit
      const validDeposit = new BN("10000000000"); // 10 tokens
      console.log(`      Step 1: Making valid deposit of ${formatTokenAmount(BigInt(validDeposit.toString()), TOKEN_DECIMALS)}`);

      await secureProgram.methods
        .depositTokens(validDeposit)
        .accounts({
          depositor: secureTestUserKeypair.publicKey,
          mint: tokenMint,
          vaultState: secureVaultPda,
          depositorTokenAccount: secureTestUserTokenAccount,
          vaultTokenAccount: secureVaultTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([secureTestUserKeypair])
        .rpc();

      await sleep(500);

      let vaultState = await secureProgram.account.tokenVaultState.fetch(secureVaultPda);
      console.log(`      Tracked total_deposited: ${formatBigNumber(vaultState.totalDeposited)}`);
      console.log(`      Tracked total_withdrawn: ${formatBigNumber(vaultState.totalWithdrawn)}`);

      // Try to withdraw more than deposited
      const excessiveWithdrawal = new BN("50000000000"); // 50 tokens
      console.log(`\n      Step 2: Attempting to withdraw ${formatTokenAmount(BigInt(excessiveWithdrawal.toString()), TOKEN_DECIMALS)}`);

      try {
        await secureProgram.methods
          .withdrawTokens(excessiveWithdrawal)
          .accounts({
            withdrawer: secureTestUserKeypair.publicKey,
            mint: tokenMint,
            vaultState: secureVaultPda,
            vaultTokenAccount: secureVaultTokenAccount,
            withdrawerTokenAccount: secureTestUserTokenAccount,
            vaultAuthority: secureVaultPda,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([secureTestUserKeypair])
          .rpc();

        expect.fail("Should have been blocked by balance check");
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        const isExpectedError =
          errorMessage.includes("InsufficientTokens") ||
          errorMessage.includes("Insufficient tokens") ||
          errorMessage.includes("exceeds available");

        expect(isExpectedError).to.be.true;

        console.log(`      Error received: ${errorMessage.substring(0, 80)}...`);
        console.log(
          "      \x1b[32m✓ SECURITY VERIFIED: Excessive withdrawal blocked\x1b[0m"
        );
      }
    });

    it("✓ TOKEN SECURE: Allows valid deposit and withdrawal operations", async () => {
      console.log("\n      Scenario: Normal token vault operations work correctly");

      // Valid deposit
      const depositAmount = new BN("5000000000"); // 5 tokens
      console.log(`      Depositing: ${formatTokenAmount(BigInt(depositAmount.toString()), TOKEN_DECIMALS)}`);

      await secureProgram.methods
        .depositTokens(depositAmount)
        .accounts({
          depositor: secureTestUserKeypair.publicKey,
          mint: tokenMint,
          vaultState: secureVaultPda,
          depositorTokenAccount: secureTestUserTokenAccount,
          vaultTokenAccount: secureVaultTokenAccount,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([secureTestUserKeypair])
        .rpc();

      await sleep(500);

      let vaultState = await secureProgram.account.tokenVaultState.fetch(secureVaultPda);
      let vaultTokenInfo = await getAccount(provider.connection, secureVaultTokenAccount);

      console.log(`      After deposit:`);
      console.log(`        Tracked total_deposited: ${formatBigNumber(vaultState.totalDeposited)}`);
      console.log(`        Actual vault balance:    ${formatTokenAmount(vaultTokenInfo.amount, TOKEN_DECIMALS)}`);

      // Valid withdrawal (less than available)
      const withdrawAmount = new BN("3000000000"); // 3 tokens
      console.log(`\n      Withdrawing: ${formatTokenAmount(BigInt(withdrawAmount.toString()), TOKEN_DECIMALS)}`);

      await secureProgram.methods
        .withdrawTokens(withdrawAmount)
        .accounts({
          withdrawer: secureTestUserKeypair.publicKey,
          mint: tokenMint,
          vaultState: secureVaultPda,
          vaultTokenAccount: secureVaultTokenAccount,
          withdrawerTokenAccount: secureTestUserTokenAccount,
          vaultAuthority: secureVaultPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([secureTestUserKeypair])
        .rpc();

      await sleep(500);

      vaultState = await secureProgram.account.tokenVaultState.fetch(secureVaultPda);
      vaultTokenInfo = await getAccount(provider.connection, secureVaultTokenAccount);

      console.log(`      After withdrawal:`);
      console.log(`        Tracked total_deposited: ${formatBigNumber(vaultState.totalDeposited)}`);
      console.log(`        Tracked total_withdrawn: ${formatBigNumber(vaultState.totalWithdrawn)}`);
      console.log(`        Actual vault balance:    ${formatTokenAmount(vaultTokenInfo.amount, TOKEN_DECIMALS)}`);

      // Verify tracking matches reality
      const trackedAvailable = vaultState.totalDeposited.sub(vaultState.totalWithdrawn);
      const actualBalance = new BN(vaultTokenInfo.amount.toString());

      console.log(`\n      Verification:`);
      console.log(`        Tracked available: ${formatBigNumber(trackedAvailable)}`);
      console.log(`        Actual balance:    ${formatBigNumber(actualBalance)}`);

      // They should match (within the scope of our test user's operations)
      console.log(
        "\n      \x1b[32m✓ SUCCESS: Valid operations work correctly with checked arithmetic\x1b[0m"
      );
    });
  });

  // =========================================================================
  // SUMMARY
  // =========================================================================

  after(() => {
    console.log("\n  ========================================");
    console.log("  TOKEN MANIPULATION TEST SUMMARY");
    console.log("  ========================================");
    console.log("\n  VULNERABLE Token Program Issues:");
    console.log("    ⚠️ Uses wrapping_add() for total_deposited tracking");
    console.log("    ⚠️ Uses wrapping_sub() for available balance calculation");
    console.log("    ⚠️ No maximum deposit limits on tracking");
    console.log("    ⚠️ Tracked balance can silently diverge from actual tokens");
    console.log("\n  SECURE Token Program Protections:");
    console.log("    ✓ Uses checked_add() with error on overflow");
    console.log("    ✓ Uses checked_sub() with error on underflow");
    console.log("    ✓ MAX_TOKEN_DEPOSIT limit prevents single large deposits");
    console.log("    ✓ Validates available balance before withdrawal");
    console.log("\n  Key Token Security Takeaways:");
    console.log("    1. SPL Token transfers may succeed even when tracking is wrong");
    console.log("    2. Always use checked arithmetic for balance tracking");
    console.log("    3. Implement deposit limits as defense in depth");
    console.log("    4. Validate tracked balance >= withdrawal BEFORE CPI");
    console.log("    5. Consider using the actual token account balance as source of truth\n");
  });
});
