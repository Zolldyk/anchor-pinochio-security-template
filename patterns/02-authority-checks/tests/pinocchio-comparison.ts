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
const PINOCCHIO_VULNERABLE_PROGRAM_ID = new PublicKey("E1VUgxWRMV2aPhMJuzz1f9mRDp7KoX5kBZu5oq1SyAqb");
const PINOCCHIO_SECURE_PROGRAM_ID = new PublicKey("3P6BDR7EK5DV7gWyVLSceYRbnUkywjDupYugSQre7eyp");

// Instruction discriminators (single byte, unlike Anchor's 8-byte sighash)
const INITIALIZE_CONFIG_DISCRIMINATOR = 0;
const ADD_ADMIN_DISCRIMINATOR = 1;
const UPDATE_FEE_DISCRIMINATOR = 2;
const PAUSE_PROTOCOL_DISCRIMINATOR = 3;
const UNPAUSE_PROTOCOL_DISCRIMINATOR = 4;
const CREATE_MANAGER_DISCRIMINATOR = 5;

// AdminConfig size: super_admin (32) + admin_list (96) + admin_count (1) + fee_basis_points (2) + paused (1) + bump (1) = 133 bytes
const ADMIN_CONFIG_SIZE = 133;

// ManagerAccount size: authority (32) + manager (32) + can_modify_fees (1) + can_pause (1) + is_active (1) + bump (1) = 68 bytes
const MANAGER_ACCOUNT_SIZE = 68;

// PDA seeds
const ADMIN_CONFIG_SEED = Buffer.from("admin_config");
const MANAGER_SEED = Buffer.from("manager");

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Build instruction data for initialize_config instruction.
 * Format: [discriminator (1 byte)] [bump (1 byte)]
 */
function buildInitializeConfigInstructionData(bump: number): Buffer {
    const data = Buffer.alloc(2);
    data.writeUInt8(INITIALIZE_CONFIG_DISCRIMINATOR, 0);
    data.writeUInt8(bump, 1);
    return data;
}

/**
 * Build instruction data for add_admin instruction.
 * Format: [discriminator (1 byte)]
 */
function buildAddAdminInstructionData(): Buffer {
    const data = Buffer.alloc(1);
    data.writeUInt8(ADD_ADMIN_DISCRIMINATOR, 0);
    return data;
}

/**
 * Build instruction data for update_fee instruction.
 * Format: [discriminator (1 byte)] [new_fee (2 bytes, little-endian)]
 */
function buildUpdateFeeInstructionData(newFee: number): Buffer {
    const data = Buffer.alloc(3);
    data.writeUInt8(UPDATE_FEE_DISCRIMINATOR, 0);
    data.writeUInt16LE(newFee, 1);
    return data;
}

/**
 * Build instruction data for pause_protocol instruction.
 * Format: [discriminator (1 byte)]
 */
function buildPauseProtocolInstructionData(): Buffer {
    const data = Buffer.alloc(1);
    data.writeUInt8(PAUSE_PROTOCOL_DISCRIMINATOR, 0);
    return data;
}

/**
 * Build instruction data for create_manager instruction.
 * Format: [discriminator (1 byte)] [can_modify_fees (1 byte)] [can_pause (1 byte)] [bump (1 byte)]
 */
function buildCreateManagerInstructionData(canModifyFees: boolean, canPause: boolean, bump: number): Buffer {
    const data = Buffer.alloc(4);
    data.writeUInt8(CREATE_MANAGER_DISCRIMINATOR, 0);
    data.writeUInt8(canModifyFees ? 1 : 0, 1);
    data.writeUInt8(canPause ? 1 : 0, 2);
    data.writeUInt8(bump, 3);
    return data;
}

/**
 * Decode AdminConfig account data from raw bytes.
 */
function decodeAdminConfig(data: Buffer): {
    superAdmin: PublicKey;
    adminList: PublicKey[];
    adminCount: number;
    feeBasisPoints: number;
    paused: boolean;
    bump: number;
} {
    const adminList: PublicKey[] = [];
    for (let i = 0; i < 3; i++) {
        const start = 32 + (i * 32);
        adminList.push(new PublicKey(data.slice(start, start + 32)));
    }

    return {
        superAdmin: new PublicKey(data.slice(0, 32)),
        adminList,
        adminCount: data[128],
        feeBasisPoints: data.readUInt16LE(129),
        paused: data[131] !== 0,
        bump: data[132],
    };
}

/**
 * Decode ManagerAccount data from raw bytes.
 */
function decodeManagerAccount(data: Buffer): {
    authority: PublicKey;
    manager: PublicKey;
    canModifyFees: boolean;
    canPause: boolean;
    isActive: boolean;
    bump: number;
} {
    return {
        authority: new PublicKey(data.slice(0, 32)),
        manager: new PublicKey(data.slice(32, 64)),
        canModifyFees: data[64] !== 0,
        canPause: data[65] !== 0,
        isActive: data[66] !== 0,
        bump: data[67],
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

describe("Pinocchio Authority Checks Framework Comparison", () => {
    // Connection and wallet
    let connection: Connection;
    let payer: Keypair;

    // Test keypairs
    let superAdminKeypair: Keypair;
    let attackerKeypair: Keypair;
    let legitAdminKeypair: Keypair;
    let managerKeypair: Keypair;

    // Pre-created accounts (Pinocchio programs require pre-allocated accounts)
    let vulnerableAdminConfigAccount: Keypair;
    let secureAdminConfigAccount: Keypair;

    // Test constants
    const NEW_FEE = 500; // 5% fee
    const MALICIOUS_FEE = 10000; // 100% fee

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
        console.log("  PINOCCHIO AUTHORITY CHECKS COMPARISON");
        console.log("  ========================================");
        console.log("");
        console.log("  This test suite compares Pinocchio authority programs against Anchor.");
        console.log("");
        console.log("  Key Differences:");
        console.log("  - Pinocchio: Manual instruction encoding, no IDL");
        console.log("  - Pinocchio: Single-byte discriminators vs Anchor's 8-byte");
        console.log("  - Pinocchio: Must manually check is_signer() and owned_by()");
        console.log("  - Pinocchio: Manual is_admin() helper vs Anchor constraints");
        console.log("");
        console.log("  Pinocchio Vulnerable Program:", PINOCCHIO_VULNERABLE_PROGRAM_ID.toString());
        console.log("  Pinocchio Secure Program:", PINOCCHIO_SECURE_PROGRAM_ID.toString());
        console.log("");

        // Generate test keypairs
        superAdminKeypair = Keypair.generate();
        attackerKeypair = Keypair.generate();
        legitAdminKeypair = Keypair.generate();
        managerKeypair = Keypair.generate();

        // Airdrop SOL to all keypairs
        const airdropAmount = 5 * LAMPORTS_PER_SOL;

        const airdropSuperAdmin = await connection.requestAirdrop(superAdminKeypair.publicKey, airdropAmount);
        await connection.confirmTransaction(airdropSuperAdmin);

        const airdropAttacker = await connection.requestAirdrop(attackerKeypair.publicKey, airdropAmount);
        await connection.confirmTransaction(airdropAttacker);

        const airdropLegitAdmin = await connection.requestAirdrop(legitAdminKeypair.publicKey, airdropAmount);
        await connection.confirmTransaction(airdropLegitAdmin);

        const airdropManager = await connection.requestAirdrop(managerKeypair.publicKey, airdropAmount);
        await connection.confirmTransaction(airdropManager);

        console.log("  Test Setup:");
        console.log(`    Super Admin: ${superAdminKeypair.publicKey.toBase58()}`);
        console.log(`    Attacker:    ${attackerKeypair.publicKey.toBase58()}`);
        console.log(`    Legit Admin: ${legitAdminKeypair.publicKey.toBase58()}`);
        console.log(`    Manager:     ${managerKeypair.publicKey.toBase58()}`);
        console.log("");
    });

    // =============================================================================
    // PINOCCHIO VULNERABLE PROGRAM TESTS
    // =============================================================================

    describe("PINOCCHIO VULNERABLE Program", () => {
        before(async () => {
            // Create admin_config account for vulnerable program
            console.log("    Creating admin_config account for vulnerable program...");
            vulnerableAdminConfigAccount = await createFundedAccount(
                connection,
                superAdminKeypair,
                PINOCCHIO_VULNERABLE_PROGRAM_ID,
                ADMIN_CONFIG_SIZE
            );
            console.log(`    Vulnerable admin_config: ${vulnerableAdminConfigAccount.publicKey.toBase58()}`);

            // Initialize admin_config
            const initIx = new TransactionInstruction({
                programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
                keys: [
                    { pubkey: vulnerableAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: superAdminKeypair.publicKey, isSigner: true, isWritable: false },
                ],
                data: buildInitializeConfigInstructionData(0),
            });

            const initTx = new Transaction().add(initIx);
            await sendAndConfirmTransaction(connection, initTx, [superAdminKeypair]);
            console.log("    Vulnerable admin_config initialized.\n");
        });

        it("(Pinocchio) allows non-super_admin to add admin - SAME VULNERABILITY", async () => {
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Admin Add Exploit");
            console.log("  ----------------------------------------");
            console.log("");
            console.log("  Pinocchio vulnerability: No is_signer() check on caller");
            console.log("  Equivalent Anchor vulnerability: Using AccountInfo instead of Signer");
            console.log("");

            // EXPLOIT: Attacker adds themselves as admin without signing
            const addAdminIx = new TransactionInstruction({
                programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
                keys: [
                    { pubkey: vulnerableAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: attackerKeypair.publicKey, isSigner: false, isWritable: false }, // NOT a signer!
                    { pubkey: attackerKeypair.publicKey, isSigner: false, isWritable: false }, // new_admin
                ],
                data: buildAddAdminInstructionData(),
            });

            const addAdminTx = new Transaction().add(addAdminIx);
            // Only attacker signs (to pay for tx), not as caller
            await sendAndConfirmTransaction(connection, addAdminTx, [attackerKeypair]);

            // Verify attacker was added
            const accountInfo = await connection.getAccountInfo(vulnerableAdminConfigAccount.publicKey);
            const adminConfig = decodeAdminConfig(accountInfo!.data);

            const attackerInList = adminConfig.adminList
                .slice(0, adminConfig.adminCount)
                .some((admin) => admin.equals(attackerKeypair.publicKey));

            expect(attackerInList).to.be.true;

            console.log(`  Admin count after exploit: ${adminConfig.adminCount}`);
            console.log("  EXPLOIT SUCCESSFUL: Non-super_admin added admin on Pinocchio!");
            console.log("  ----------------------------------------\n");
        });

        it("(Pinocchio) allows non-admin to modify fees - SAME VULNERABILITY", async () => {
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Fee Update Exploit");
            console.log("  ----------------------------------------");
            console.log("");

            // Get fee before attack
            let accountInfo = await connection.getAccountInfo(vulnerableAdminConfigAccount.publicKey);
            let adminConfig = decodeAdminConfig(accountInfo!.data);
            console.log(`  Fee before attack: ${adminConfig.feeBasisPoints} basis points`);

            // EXPLOIT: Anyone can modify fees
            const updateFeeIx = new TransactionInstruction({
                programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
                keys: [
                    { pubkey: vulnerableAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: attackerKeypair.publicKey, isSigner: false, isWritable: false }, // NOT validated
                ],
                data: buildUpdateFeeInstructionData(MALICIOUS_FEE),
            });

            const updateFeeTx = new Transaction().add(updateFeeIx);
            await sendAndConfirmTransaction(connection, updateFeeTx, [attackerKeypair]);

            // Verify fee was modified
            accountInfo = await connection.getAccountInfo(vulnerableAdminConfigAccount.publicKey);
            adminConfig = decodeAdminConfig(accountInfo!.data);

            expect(adminConfig.feeBasisPoints).to.equal(MALICIOUS_FEE);

            console.log(`  Fee after attack: ${adminConfig.feeBasisPoints} basis points`);
            console.log("  EXPLOIT SUCCESSFUL: Non-admin modified fees on Pinocchio!");
            console.log("  ----------------------------------------\n");
        });

        it("(Pinocchio) allows non-super_admin to pause protocol - SAME VULNERABILITY", async () => {
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Pause Exploit");
            console.log("  ----------------------------------------");
            console.log("");

            // Get pause state before attack
            let accountInfo = await connection.getAccountInfo(vulnerableAdminConfigAccount.publicKey);
            let adminConfig = decodeAdminConfig(accountInfo!.data);
            console.log(`  Paused before attack: ${adminConfig.paused}`);

            // EXPLOIT: Anyone can pause the protocol
            const pauseIx = new TransactionInstruction({
                programId: PINOCCHIO_VULNERABLE_PROGRAM_ID,
                keys: [
                    { pubkey: vulnerableAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: attackerKeypair.publicKey, isSigner: false, isWritable: false }, // NOT validated
                ],
                data: buildPauseProtocolInstructionData(),
            });

            const pauseTx = new Transaction().add(pauseIx);
            await sendAndConfirmTransaction(connection, pauseTx, [attackerKeypair]);

            // Verify protocol was paused
            accountInfo = await connection.getAccountInfo(vulnerableAdminConfigAccount.publicKey);
            adminConfig = decodeAdminConfig(accountInfo!.data);

            expect(adminConfig.paused).to.be.true;

            console.log(`  Paused after attack: ${adminConfig.paused}`);
            console.log("  EXPLOIT SUCCESSFUL: Non-super_admin paused protocol on Pinocchio!");
            console.log("  ----------------------------------------\n");
        });
    });

    // =============================================================================
    // PINOCCHIO SECURE PROGRAM TESTS
    // =============================================================================

    describe("PINOCCHIO SECURE Program", () => {
        before(async () => {
            // Create admin_config account for secure program
            console.log("    Creating admin_config account for secure program...");
            secureAdminConfigAccount = await createFundedAccount(
                connection,
                superAdminKeypair,
                PINOCCHIO_SECURE_PROGRAM_ID,
                ADMIN_CONFIG_SIZE
            );
            console.log(`    Secure admin_config: ${secureAdminConfigAccount.publicKey.toBase58()}`);

            // Initialize admin_config
            const initIx = new TransactionInstruction({
                programId: PINOCCHIO_SECURE_PROGRAM_ID,
                keys: [
                    { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                    { pubkey: superAdminKeypair.publicKey, isSigner: true, isWritable: false },
                ],
                data: buildInitializeConfigInstructionData(0),
            });

            const initTx = new Transaction().add(initIx);
            await sendAndConfirmTransaction(connection, initTx, [superAdminKeypair]);
            console.log("    Secure admin_config initialized.\n");
        });

        it("(Pinocchio) blocks non-super_admin from adding admin - MANUAL VALIDATION", async () => {
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Admin Add Blocked");
            console.log("  ----------------------------------------");
            console.log("");
            console.log("  Pinocchio security: Manual is_signer() + super_admin check");
            console.log("");

            let attackSucceeded = false;

            try {
                // Attacker signs but is not super_admin
                const addAdminIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: attackerKeypair.publicKey, isSigner: true, isWritable: false },
                        { pubkey: attackerKeypair.publicKey, isSigner: false, isWritable: false },
                    ],
                    data: buildAddAdminInstructionData(),
                });

                const addAdminTx = new Transaction().add(addAdminIx);
                await sendAndConfirmTransaction(connection, addAdminTx, [attackerKeypair]);
                attackSucceeded = true;
            } catch (err: any) {
                console.log("  Transaction rejected (as expected).");
            }

            expect(attackSucceeded).to.be.false;

            console.log("  SECURITY VERIFIED: Non-super_admin blocked on Pinocchio!");
            console.log("  ----------------------------------------\n");
        });

        it("(Pinocchio) blocks non-admin from modifying fees - MANUAL VALIDATION", async () => {
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Fee Update Blocked");
            console.log("  ----------------------------------------");
            console.log("");

            let attackSucceeded = false;

            try {
                const updateFeeIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: attackerKeypair.publicKey, isSigner: true, isWritable: false },
                    ],
                    data: buildUpdateFeeInstructionData(MALICIOUS_FEE),
                });

                const updateFeeTx = new Transaction().add(updateFeeIx);
                await sendAndConfirmTransaction(connection, updateFeeTx, [attackerKeypair]);
                attackSucceeded = true;
            } catch (err: any) {
                console.log("  Transaction rejected (as expected).");
            }

            expect(attackSucceeded).to.be.false;

            // Verify fee unchanged
            const accountInfo = await connection.getAccountInfo(secureAdminConfigAccount.publicKey);
            const adminConfig = decodeAdminConfig(accountInfo!.data);
            expect(adminConfig.feeBasisPoints).to.equal(100); // Default

            console.log("  SECURITY VERIFIED: Non-admin blocked from fee modification on Pinocchio!");
            console.log("  ----------------------------------------\n");
        });

        it("(Pinocchio) blocks non-super_admin from pausing - MANUAL VALIDATION", async () => {
            console.log("\n");
            console.log("  ----------------------------------------");
            console.log("  PINOCCHIO: Unauthorized Pause Blocked");
            console.log("  ----------------------------------------");
            console.log("");

            let attackSucceeded = false;

            try {
                const pauseIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: attackerKeypair.publicKey, isSigner: true, isWritable: false },
                    ],
                    data: buildPauseProtocolInstructionData(),
                });

                const pauseTx = new Transaction().add(pauseIx);
                await sendAndConfirmTransaction(connection, pauseTx, [attackerKeypair]);
                attackSucceeded = true;
            } catch (err: any) {
                console.log("  Transaction rejected (as expected).");
            }

            expect(attackSucceeded).to.be.false;

            // Verify paused unchanged
            const accountInfo = await connection.getAccountInfo(secureAdminConfigAccount.publicKey);
            const adminConfig = decodeAdminConfig(accountInfo!.data);
            expect(adminConfig.paused).to.be.false;

            console.log("  SECURITY VERIFIED: Non-super_admin blocked from pausing on Pinocchio!");
            console.log("  ----------------------------------------\n");
        });

        describe("Authorized Operations", () => {
            it("(Pinocchio) allows super_admin to add admin - PROPER FLOW", async () => {
                console.log("\n");
                console.log("  ----------------------------------------");
                console.log("  PINOCCHIO: Authorized Admin Add");
                console.log("  ----------------------------------------");
                console.log("");

                const addAdminIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: superAdminKeypair.publicKey, isSigner: true, isWritable: false },
                        { pubkey: legitAdminKeypair.publicKey, isSigner: false, isWritable: false },
                    ],
                    data: buildAddAdminInstructionData(),
                });

                const addAdminTx = new Transaction().add(addAdminIx);
                await sendAndConfirmTransaction(connection, addAdminTx, [superAdminKeypair]);

                // Verify admin was added
                const accountInfo = await connection.getAccountInfo(secureAdminConfigAccount.publicKey);
                const adminConfig = decodeAdminConfig(accountInfo!.data);

                const legitAdminInList = adminConfig.adminList
                    .slice(0, adminConfig.adminCount)
                    .some((admin) => admin.equals(legitAdminKeypair.publicKey));

                expect(legitAdminInList).to.be.true;

                console.log(`  Admin count after add: ${adminConfig.adminCount}`);
                console.log("  SUCCESS: Super_admin added admin on Pinocchio!");
                console.log("  ----------------------------------------\n");
            });

            it("(Pinocchio) allows admin to update fees - PROPER FLOW", async () => {
                console.log("\n");
                console.log("  ----------------------------------------");
                console.log("  PINOCCHIO: Authorized Fee Update");
                console.log("  ----------------------------------------");
                console.log("");

                // super_admin is in admin_list, so can update fees
                const updateFeeIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: superAdminKeypair.publicKey, isSigner: true, isWritable: false },
                    ],
                    data: buildUpdateFeeInstructionData(NEW_FEE),
                });

                const updateFeeTx = new Transaction().add(updateFeeIx);
                await sendAndConfirmTransaction(connection, updateFeeTx, [superAdminKeypair]);

                // Verify fee was updated
                const accountInfo = await connection.getAccountInfo(secureAdminConfigAccount.publicKey);
                const adminConfig = decodeAdminConfig(accountInfo!.data);

                expect(adminConfig.feeBasisPoints).to.equal(NEW_FEE);

                console.log(`  Fee updated to: ${adminConfig.feeBasisPoints} basis points`);
                console.log("  SUCCESS: Admin updated fees on Pinocchio!");
                console.log("  ----------------------------------------\n");
            });

            it("(Pinocchio) allows super_admin to pause protocol - PROPER FLOW", async () => {
                console.log("\n");
                console.log("  ----------------------------------------");
                console.log("  PINOCCHIO: Authorized Pause");
                console.log("  ----------------------------------------");
                console.log("");

                const pauseIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: superAdminKeypair.publicKey, isSigner: true, isWritable: false },
                    ],
                    data: buildPauseProtocolInstructionData(),
                });

                const pauseTx = new Transaction().add(pauseIx);
                await sendAndConfirmTransaction(connection, pauseTx, [superAdminKeypair]);

                // Verify protocol was paused
                const accountInfo = await connection.getAccountInfo(secureAdminConfigAccount.publicKey);
                const adminConfig = decodeAdminConfig(accountInfo!.data);

                expect(adminConfig.paused).to.be.true;

                console.log(`  Protocol paused: ${adminConfig.paused}`);
                console.log("  SUCCESS: Super_admin paused protocol on Pinocchio!");
                console.log("  ----------------------------------------\n");
            });

            it("(Pinocchio) allows admin to create manager - PROPER FLOW", async () => {
                console.log("\n");
                console.log("  ----------------------------------------");
                console.log("  PINOCCHIO: Authorized Manager Creation");
                console.log("  ----------------------------------------");
                console.log("");

                // Create manager account
                const managerAccount = await createFundedAccount(
                    connection,
                    superAdminKeypair,
                    PINOCCHIO_SECURE_PROGRAM_ID,
                    MANAGER_ACCOUNT_SIZE
                );

                const createManagerIx = new TransactionInstruction({
                    programId: PINOCCHIO_SECURE_PROGRAM_ID,
                    keys: [
                        { pubkey: secureAdminConfigAccount.publicKey, isSigner: false, isWritable: false },
                        { pubkey: managerAccount.publicKey, isSigner: false, isWritable: true },
                        { pubkey: superAdminKeypair.publicKey, isSigner: true, isWritable: false },
                        { pubkey: managerKeypair.publicKey, isSigner: false, isWritable: false },
                    ],
                    data: buildCreateManagerInstructionData(true, false, 0),
                });

                const createManagerTx = new Transaction().add(createManagerIx);
                await sendAndConfirmTransaction(connection, createManagerTx, [superAdminKeypair]);

                // Verify manager was created
                const accountInfo = await connection.getAccountInfo(managerAccount.publicKey);
                const managerData = decodeManagerAccount(accountInfo!.data);

                expect(managerData.authority.equals(superAdminKeypair.publicKey)).to.be.true;
                expect(managerData.manager.equals(managerKeypair.publicKey)).to.be.true;
                expect(managerData.canModifyFees).to.be.true;
                expect(managerData.canPause).to.be.false;
                expect(managerData.isActive).to.be.true;

                console.log(`  Manager created: ${managerData.manager.toBase58()}`);
                console.log(`  Authority: ${managerData.authority.toBase58()}`);
                console.log("  SUCCESS: Admin created manager on Pinocchio!");
                console.log("  ----------------------------------------\n");
            });
        });
    });

    // =============================================================================
    // FRAMEWORK COMPARISON SUMMARY
    // =============================================================================

    describe("Authority Checks Framework Comparison Summary", () => {
        it("Documents key differences between Anchor and Pinocchio for authority validation", async () => {
            console.log("\n");
            console.log("  ========================================");
            console.log("  AUTHORITY CHECKS: ANCHOR vs PINOCCHIO");
            console.log("  ========================================");
            console.log("");
            console.log("  | Security Feature              | Anchor                        | Pinocchio                       |");
            console.log("  |-------------------------------|-------------------------------|--------------------------------- |");
            console.log("  | Signer validation             | Signer<'info> type            | is_signer() method               |");
            console.log("  | Super admin constraint        | constraint = caller == admin  | Manual pubkey comparison         |");
            console.log("  | Admin list membership         | Custom constraint function    | is_admin() helper function       |");
            console.log("  | Account ownership             | seeds = [...], bump           | owned_by() method                |");
            console.log("  | Error handling                | #[error_code] enum            | ProgramError::Custom(u32)        |");
            console.log("  | Instruction routing           | #[program] macro              | Manual match on discriminator    |");
            console.log("");
            console.log("  Security Implications for Authority Checks:");
            console.log("  - Anchor: Declarative constraints make it harder to forget checks");
            console.log("  - Pinocchio: Every check must be explicit - more verbose but auditable");
            console.log("  - Both can be secure OR vulnerable depending on developer discipline");
            console.log("");
            console.log("  Pinocchio Authority Patterns:");
            console.log("  1. is_signer() - Must call explicitly for every signer account");
            console.log("  2. owned_by(program_id) - Must verify account ownership");
            console.log("  3. Manual pubkey comparison for authority fields");
            console.log("  4. is_admin() helper for membership checks");
            console.log("");
            console.log("  When to Choose Each:");
            console.log("  - Anchor: Complex admin systems, team projects, rapid development");
            console.log("  - Pinocchio: Performance-critical, minimal CU usage, full control");
            console.log("  ========================================\n");

            expect(true).to.be.true;
        });
    });
});
