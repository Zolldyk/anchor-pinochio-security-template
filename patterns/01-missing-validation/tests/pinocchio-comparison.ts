import * as anchor from "@coral-xyz/anchor";
import { expect } from "chai";
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

// =============================================================================
// PINOCCHIO PROGRAM CONSTANTS
// =============================================================================

/**
 * Pinocchio programs don't use Anchor's IDL system.
 * We must manually define program IDs and instruction data formats.
 *
 * This demonstrates a key difference from Anchor:
 * - Anchor: Uses IDL for type-safe method calls
 * - Pinocchio: Requires manual instruction encoding
 */

// Program IDs from keypairs
const PINOCCHIO_VULNERABLE_PROGRAM_ID = new PublicKey("FTu4tEsgTb1WJPdvxHYFULT7ocvfDpjSsBcFJu6VqYpR");
const PINOCCHIO_SECURE_PROGRAM_ID = new PublicKey("ENZfh7vCvh9qvbKNQgWDvThLcmaR95qAfzuourgUCMqq");

// Instruction discriminators (single byte, unlike Anchor's 8-byte sighash)
const INITIALIZE_DISCRIMINATOR = 0;
const UPDATE_BALANCE_DISCRIMINATOR = 1;

// Account size: authority (32) + balance (8) + is_initialized (1) + bump (1) = 42 bytes
const USER_ACCOUNT_SIZE = 42;

// PDA seed (same as Anchor programs for consistency)
const USER_ACCOUNT_SEED = Buffer.from("user_account");

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Derive PDA for a user account (same derivation as Anchor programs).
 */
function deriveUserAccountPda(authority: PublicKey, programId: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
        [USER_ACCOUNT_SEED, authority.toBuffer()],
        programId
    );
}

/**
 * Build instruction data for initialize instruction.
 * Format: [discriminator (1 byte)] [bump (1 byte)]
 */
function buildInitializeInstructionData(bump: number): Buffer {
    const data = Buffer.alloc(2);
    data.writeUInt8(INITIALIZE_DISCRIMINATOR, 0);
    data.writeUInt8(bump, 1);
    return data;
}

/**
 * Build instruction data for update_balance instruction.
 * Format: [discriminator (1 byte)] [new_balance (8 bytes, little-endian)]
 */
function buildUpdateBalanceInstructionData(newBalance: bigint): Buffer {
    const data = Buffer.alloc(9);
    data.writeUInt8(UPDATE_BALANCE_DISCRIMINATOR, 0);
    data.writeBigUInt64LE(newBalance, 1);
    return data;
}

/**
 * Decode user account data from raw bytes.
 * Layout: authority (32) | balance (8) | is_initialized (1) | bump (1)
 */
function decodeUserAccount(data: Buffer): {
    authority: PublicKey;
    balance: bigint;
    isInitialized: boolean;
    bump: number;
} {
    return {
        authority: new PublicKey(data.slice(0, 32)),
        balance: data.readBigUInt64LE(32),
        isInitialized: data[40] !== 0,
        bump: data[41],
    };
}

/**
 * Create and fund a new account for testing.
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

describe("Pinocchio Framework Comparison", () => {
    // Connection and wallet
    let connection: Connection;
    let payer: Keypair;

    // Test keypairs
    let victimKeypair: Keypair;
    let attackerKeypair: Keypair;

    // =============================================================================
    // SETUP HOOKS
    // =============================================================================

    before(async () => {
        // Use Anchor's provider for connection and payer
        const provider = anchor.AnchorProvider.env();
        connection = provider.connection;
        payer = (provider.wallet as any).payer;

        console.log("\n");
        console.log("  ========================================");
        console.log("  PINOCCHIO FRAMEWORK COMPARISON");
        console.log("  ========================================");
        console.log("");
        console.log("  This test suite compares Pinocchio programs against Anchor.");
        console.log("");
        console.log("  Key Differences:");
        console.log("  - Pinocchio: Manual instruction encoding, no IDL");
        console.log("  - Pinocchio: Single-byte discriminators vs Anchor's 8-byte");
        console.log("  - Pinocchio: No automatic account discriminator (8 bytes saved)");
        console.log("  - Pinocchio: Must manually check is_signer() and owned_by()");
        console.log("");
        console.log("  Pinocchio Vulnerable Program:", PINOCCHIO_VULNERABLE_PROGRAM_ID.toString());
        console.log("  Pinocchio Secure Program:", PINOCCHIO_SECURE_PROGRAM_ID.toString());
        console.log("");
    });

    beforeEach(async () => {
        // Create fresh keypairs for each test
        victimKeypair = Keypair.generate();
        attackerKeypair = Keypair.generate();

        // Airdrop SOL
        const airdropVictim = await connection.requestAirdrop(
            victimKeypair.publicKey,
            2 * LAMPORTS_PER_SOL
        );
        await connection.confirmTransaction(airdropVictim);

        const airdropAttacker = await connection.requestAirdrop(
            attackerKeypair.publicKey,
            2 * LAMPORTS_PER_SOL
        );
        await connection.confirmTransaction(airdropAttacker);
    });

    // =============================================================================
    // PINOCCHIO VULNERABLE PROGRAM TESTS
    // =============================================================================

    describe("PINOCCHIO VULNERABLE Program", () => {
        it("(Pinocchio) allows unauthorized balance update - SAME VULNERABILITY", async () => {
            /**
             * FRAMEWORK COMPARISON: Vulnerability in Pinocchio
             *
             * In Anchor, this vulnerability occurs when using AccountInfo instead of Signer.
             * In Pinocchio, this vulnerability occurs when forgetting to call is_signer().
             *
             * The root cause is identical - missing signature verification.
             * The fix is framework-specific but conceptually the same.
             */
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Balance Update Exploit");
            console.log("  ----------------------------------------");
            console.log("");
            console.log("  Pinocchio vulnerability: No is_signer() check");
            console.log("  Equivalent Anchor vulnerability: Using AccountInfo instead of Signer");
            console.log("");

            // Create account owned by the program
            const userAccount = await createFundedAccount(
                connection,
                victimKeypair,
                PINOCCHIO_VULNERABLE_PROGRAM_ID,
                USER_ACCOUNT_SIZE
            );

            // Step 1: Victim initializes account
            console.log("  Step 1: Victim initializes account...");
            const [, bump] = deriveUserAccountPda(victimKeypair.publicKey, PINOCCHIO_VULNERABLE_PROGRAM_ID);

            const initIx = new TransactionInstruction({
                programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
                keys: [
                    { pubkey: userAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: victimKeypair.publicKey, isSigner: true, isWritable: false },
                ],
                data: buildInitializeInstructionData(bump),
            });

            const initTx = new Transaction().add(initIx);
            await sendAndConfirmTransaction(connection, initTx, [victimKeypair]);

            // Verify initialization
            let accountInfo = await connection.getAccountInfo(userAccount.publicKey);
            let accountData = decodeUserAccount(accountInfo!.data);
            console.log("  Initial balance:", accountData.balance.toString());
            console.log("  Authority set to victim:", accountData.authority.toString());

            // Step 2: Attacker modifies balance WITHOUT signing
            console.log("");
            console.log("  Step 2: Attacker attempts unauthorized update...");
            console.log("  (Pinocchio vulnerable program lacks is_signer() check)");

            const maliciousBalance = BigInt(999999);

            // VULNERABILITY: Attacker can submit transaction without authority signing
            // The vulnerable Pinocchio program doesn't check if authority is a signer
            const updateIx = new TransactionInstruction({
                programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
                keys: [
                    { pubkey: userAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: victimKeypair.publicKey, isSigner: false, isWritable: false }, // NOT a signer!
                ],
                data: buildUpdateBalanceInstructionData(maliciousBalance),
            });

            const updateTx = new Transaction().add(updateIx);
            // Only attacker signs (to pay for tx), victim does NOT sign
            await sendAndConfirmTransaction(connection, updateTx, [attackerKeypair]);

            // Step 3: Verify exploit succeeded
            accountInfo = await connection.getAccountInfo(userAccount.publicKey);
            accountData = decodeUserAccount(accountInfo!.data);

            console.log("");
            console.log("  Step 3: Verifying exploit...");
            console.log("  Balance AFTER attack:", accountData.balance.toString());

            expect(accountData.balance).to.equal(maliciousBalance);

            console.log("");
            console.log("  EXPLOIT SUCCESSFUL: Pinocchio vulnerable program exploited!");
            console.log("");
            console.log("  Framework Comparison:");
            console.log("  - Anchor vulnerable: Uses AccountInfo (any pubkey accepted)");
            console.log("  - Pinocchio vulnerable: Omits is_signer() check (same effect)");
            console.log("  - Both allow transactions without proper signature verification");
            console.log("  ----------------------------------------\n");
        });
    });

    // =============================================================================
    // PINOCCHIO SECURE PROGRAM TESTS
    // =============================================================================

    describe("PINOCCHIO SECURE Program", () => {
        it("(Pinocchio) blocks unauthorized balance update - MANUAL VALIDATION", async () => {
            /**
             * FRAMEWORK COMPARISON: Security in Pinocchio
             *
             * In Anchor, security is achieved via:
             * - Signer<'info> type annotation
             * - has_one = authority constraint
             *
             * In Pinocchio, security is achieved via:
             * - Manual is_signer() check
             * - Manual pubkey comparison for ownership
             *
             * Pinocchio requires MORE code but offers MORE control.
             */
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Access Blocked");
            console.log("  ----------------------------------------");
            console.log("");
            console.log("  Pinocchio security: Manual is_signer() + ownership check");
            console.log("  Equivalent Anchor security: Signer<'info> + has_one constraint");
            console.log("");

            // Create account owned by the program
            const userAccount = await createFundedAccount(
                connection,
                victimKeypair,
                PINOCCHIO_SECURE_PROGRAM_ID,
                USER_ACCOUNT_SIZE
            );

            // Step 1: Victim initializes account
            console.log("  Step 1: Victim initializes account on SECURE program...");
            const [, bump] = deriveUserAccountPda(victimKeypair.publicKey, PINOCCHIO_SECURE_PROGRAM_ID);

            const initIx = new TransactionInstruction({
                programId: PINOCCHIO_SECURE_PROGRAM_ID,
                keys: [
                    { pubkey: userAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: victimKeypair.publicKey, isSigner: true, isWritable: false },
                ],
                data: buildInitializeInstructionData(bump),
            });

            const initTx = new Transaction().add(initIx);
            await sendAndConfirmTransaction(connection, initTx, [victimKeypair]);

            // Verify initialization
            let accountInfo = await connection.getAccountInfo(userAccount.publicKey);
            let accountData = decodeUserAccount(accountInfo!.data);
            console.log("  Initial balance:", accountData.balance.toString());
            console.log("  Authority set to victim:", accountData.authority.toString());

            // Step 2: Attacker attempts unauthorized update
            console.log("");
            console.log("  Step 2: Attacker attempts unauthorized update...");
            console.log("  (Pinocchio secure program checks is_signer() AND authority match)");

            let attackSucceeded = false;
            let errorMessage = "";

            try {
                // SECURITY TEST: Try to update with attacker as signer
                // This should fail because:
                // 1. Attacker's key doesn't match stored authority
                // 2. Even if attacker signs, the ownership check fails
                const updateIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: userAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: attackerKeypair.publicKey, isSigner: true, isWritable: false },
                    ],
                    data: buildUpdateBalanceInstructionData(BigInt(999999)),
                });

                const updateTx = new Transaction().add(updateIx);
                await sendAndConfirmTransaction(connection, updateTx, [attackerKeypair]);
                attackSucceeded = true;
            } catch (err: any) {
                errorMessage = err.message || err.toString();
                console.log("  Transaction rejected (as expected).");
            }

            // Step 3: Verify security held
            console.log("");
            console.log("  Step 3: Verifying security...");

            accountInfo = await connection.getAccountInfo(userAccount.publicKey);
            accountData = decodeUserAccount(accountInfo!.data);
            console.log("  Balance after attack attempt:", accountData.balance.toString());

            expect(attackSucceeded).to.be.false;
            expect(accountData.balance).to.equal(BigInt(0)); // Unchanged

            console.log("");
            console.log("  SECURITY VERIFIED: Pinocchio secure program blocked attack!");
            console.log("");
            console.log("  Framework Comparison:");
            console.log("  - Anchor secure: Declarative constraints (Signer, has_one)");
            console.log("  - Pinocchio secure: Explicit validation code (is_signer, pubkey compare)");
            console.log("  - Pinocchio: More verbose but gives explicit control and auditability");
            console.log("  ----------------------------------------\n");
        });

        it("(Pinocchio) allows authorized balance update - PROPER FLOW", async () => {
            /**
             * Demonstrates that the secure Pinocchio program DOES allow
             * legitimate updates when the true authority signs.
             */
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Authorized Access Allowed");
            console.log("  ----------------------------------------");
            console.log("");

            // Create account owned by the program
            const userAccount = await createFundedAccount(
                connection,
                victimKeypair,
                PINOCCHIO_SECURE_PROGRAM_ID,
                USER_ACCOUNT_SIZE
            );

            // Initialize account
            const [, bump] = deriveUserAccountPda(victimKeypair.publicKey, PINOCCHIO_SECURE_PROGRAM_ID);

            const initIx = new TransactionInstruction({
                programId: PINOCCHIO_SECURE_PROGRAM_ID,
                keys: [
                    { pubkey: userAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: victimKeypair.publicKey, isSigner: true, isWritable: false },
                ],
                data: buildInitializeInstructionData(bump),
            });

            await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [victimKeypair]);

            console.log("  Step 1: Account initialized, now TRUE authority updates...");

            // TRUE authority (victim) updates their own balance
            const legitimateBalance = BigInt(500);
            const updateIx = new TransactionInstruction({
                programId: PINOCCHIO_SECURE_PROGRAM_ID,
                keys: [
                    { pubkey: userAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: victimKeypair.publicKey, isSigner: true, isWritable: false },
                ],
                data: buildUpdateBalanceInstructionData(legitimateBalance),
            });

            await sendAndConfirmTransaction(connection, new Transaction().add(updateIx), [victimKeypair]);

            // Verify update succeeded
            const accountInfo = await connection.getAccountInfo(userAccount.publicKey);
            const accountData = decodeUserAccount(accountInfo!.data);

            console.log("  Balance after authorized update:", accountData.balance.toString());
            expect(accountData.balance).to.equal(legitimateBalance);

            console.log("");
            console.log("  VERIFIED: Authorized update succeeded!");
            console.log("  Pinocchio secure program correctly validates and allows true authority.");
            console.log("  ----------------------------------------\n");
        });
    });

    // =============================================================================
    // FRAMEWORK COMPARISON SUMMARY
    // =============================================================================

    describe("Framework Comparison Summary", () => {
        it("Documents key differences between Anchor and Pinocchio", async () => {
            console.log("\n");
            console.log("  ========================================");
            console.log("  ANCHOR vs PINOCCHIO COMPARISON SUMMARY");
            console.log("  ========================================");
            console.log("");
            console.log("  | Feature                    | Anchor                    | Pinocchio                   |");
            console.log("  |----------------------------|---------------------------|-----------------------------| ");
            console.log("  | Signer validation          | Signer<'info> type        | is_signer() method          |");
            console.log("  | Owner constraint           | has_one = field           | Manual pubkey comparison    |");
            console.log("  | Account discriminator      | 8 bytes (automatic)       | 0 bytes (manual if needed)  |");
            console.log("  | Instruction discriminator  | 8 bytes (sighash)         | 1+ bytes (manual)           |");
            console.log("  | IDL generation             | Automatic                 | None (manual docs)          |");
            console.log("  | CPI helpers                | Built-in context          | Manual instruction building |");
            console.log("  | Serialization              | Borsh via macros          | Manual or Borsh direct      |");
            console.log("  | Binary size                | Larger (framework code)   | Smaller (minimal overhead)  |");
            console.log("  | Security defaults          | Safer (constraints)       | Explicit (more control)     |");
            console.log("");
            console.log("  Security Implications:");
            console.log("  - Anchor's declarative constraints reduce chance of forgetting validation");
            console.log("  - Pinocchio requires explicit validation but gives more control");
            console.log("  - Both can be secure OR vulnerable depending on developer choices");
            console.log("");
            console.log("  When to Choose Each:");
            console.log("  - Anchor: Rapid development, team projects, complex programs");
            console.log("  - Pinocchio: Performance-critical code, minimal binary size, full control");
            console.log("  ========================================\n");

            // This test always passes - it's for documentation
            expect(true).to.be.true;
        });
    });
});
