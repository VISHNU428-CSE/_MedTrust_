import { Context, Contract, Info, Transaction } from 'fabric-contract-api';
import {
  AccessStatus,
  ActorRole,
  AuditChainVerificationResult,
  AuditLogEntry
} from '../models/types';
import {
  assertZeroPHI,
  computeAuditEntryHash,
  GENESIS_BLOCK_HASH
} from '../utils/cryptoUtils';

interface AuditLedgerState {
  currentSeq: number;
  lastHash: string;
}

const AUDIT_STATE_KEY = 'AUDIT_LEDGER_CHAIN_STATE';

@Info({
  title: 'AuditTrailContract',
  description: 'Smart contract for immutable, cryptographically hash-chained audit logging and verification'
})
export class AuditTrailContract extends Contract {
  constructor() {
    super('AuditTrailContract');
  }

  /**
   * Helper to format sequence number into a sortable 12-digit key.
   */
  private getAuditKey(ctx: Context, seq: number): string {
    const padded = String(seq).padStart(12, '0');
    return ctx.stub.createCompositeKey('AuditEntry', [padded]);
  }

  /**
   * Helper to fetch current chain tip (latest sequence and entry hash).
   */
  private async getChainState(ctx: Context): Promise<AuditLedgerState> {
    const bytes = await ctx.stub.getState(AUDIT_STATE_KEY);
    if (!bytes || bytes.length === 0) {
      return {
        currentSeq: 0,
        lastHash: GENESIS_BLOCK_HASH
      };
    }
    return JSON.parse(bytes.toString());
  }

  /**
   * Append-only immutable logging of access and workflow events.
   * Chained cryptographically to previous block hash.
   */
  @Transaction()
  public async LogAccessEvent(
    ctx: Context,
    eventType: string,
    actorId: string,
    actorRole: ActorRole | string,
    targetPatientId: string,
    recordId: string = '',
    consentId: string = '',
    status: AccessStatus = 'ALLOWED',
    detail: string = ''
  ): Promise<string> {
    assertZeroPHI(
      { eventType, actorId, actorRole, targetPatientId, recordId, consentId, detail },
      'LogAccessEvent arguments'
    );

    const chainState = await this.getChainState(ctx);
    const newSeq = chainState.currentSeq + 1;
    const prevHash = chainState.lastHash;

    const txTime = ctx.stub.getTxTimestamp();
    const timestamp = Math.floor(txTime.seconds.low || Number(txTime.seconds));

    const entryWithoutHash: Omit<AuditLogEntry, 'entryHash'> = {
      docType: 'audit_entry',
      seq: newSeq,
      timestamp,
      eventType,
      actorId,
      actorRole,
      targetPatientId,
      recordId: recordId || undefined,
      consentId: consentId || undefined,
      status,
      detail,
      prevHash
    };

    const entryHash = computeAuditEntryHash(entryWithoutHash);

    const fullEntry: AuditLogEntry = {
      ...entryWithoutHash,
      entryHash
    };

    // 1. Write the new audit entry
    const key = this.getAuditKey(ctx, newSeq);
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(fullEntry)));

    // 2. Advance the chain tip state
    const newChainState: AuditLedgerState = {
      currentSeq: newSeq,
      lastHash: entryHash
    };
    await ctx.stub.putState(AUDIT_STATE_KEY, Buffer.from(JSON.stringify(newChainState)));

    return JSON.stringify(fullEntry);
  }

  /**
   * Retrieve all audit entries in sequence.
   */
  @Transaction(false)
  public async GetAllAuditEntries(ctx: Context): Promise<string> {
    const entries = await this.fetchAllEntries(ctx);
    return JSON.stringify(entries);
  }

  /**
   * Retrieve audit entries associated with a specific target patient.
   */
  @Transaction(false)
  public async GetAuditLogsByPatient(ctx: Context, patientId: string): Promise<string> {
    const all = await this.fetchAllEntries(ctx);
    const filtered = all.filter((entry) => entry.targetPatientId === patientId);
    return JSON.stringify(filtered);
  }

  /**
   * Retrieve audit entries initiated by a specific actor (doctor, auditor, patient).
   */
  @Transaction(false)
  public async GetAuditLogsByActor(ctx: Context, actorId: string): Promise<string> {
    const all = await this.fetchAllEntries(ctx);
    const filtered = all.filter((entry) => entry.actorId === actorId);
    return JSON.stringify(filtered);
  }

  /**
   * Cryptographically walks the audit ledger and validates hash-chain integrity.
   */
  @Transaction(false)
  public async VerifyAuditChain(ctx: Context): Promise<string> {
    const entries = await this.fetchAllEntries(ctx);

    let expectedPrev = GENESIS_BLOCK_HASH;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Check linkage to previous hash
      if (entry.prevHash !== expectedPrev) {
        const failure: AuditChainVerificationResult = {
          isIntact: false,
          entryCount: entries.length,
          lastHash: entry.prevHash,
          brokenIndex: i,
          message: `Broken chain link at index ${i}: expected prevHash ${expectedPrev}, found ${entry.prevHash}`
        };
        return JSON.stringify(failure);
      }

      // Recompute and verify entry hash
      const { entryHash, ...entryPayload } = entry;
      const recomputedHash = computeAuditEntryHash(entryPayload);

      if (entryHash !== recomputedHash) {
        const failure: AuditChainVerificationResult = {
          isIntact: false,
          entryCount: entries.length,
          lastHash: entryHash,
          brokenIndex: i,
          message: `Corrupted entry hash at index ${i}: stored ${entryHash}, computed ${recomputedHash}`
        };
        return JSON.stringify(failure);
      }

      expectedPrev = entryHash;
    }

    const success: AuditChainVerificationResult = {
      isIntact: true,
      entryCount: entries.length,
      lastHash: expectedPrev,
      message: 'Chain is cryptographically intact and unbroken.'
    };
    return JSON.stringify(success);
  }

  /**
   * Helper to retrieve all entries sorted by sequence.
   */
  private async fetchAllEntries(ctx: Context): Promise<AuditLogEntry[]> {
    const iterator = await ctx.stub.getStateByPartialCompositeKey('AuditEntry', []);
    const entries: AuditLogEntry[] = [];

    let res = await iterator.next();
    while (!res.done) {
      if (res.value && res.value.value) {
        try {
          const entry: AuditLogEntry = JSON.parse(Buffer.from(res.value.value).toString('utf8'));
          if (entry.docType === 'audit_entry') {
            entries.push(entry);
          }
        } catch {
          // ignore malformed keys
        }
      }
      res = await iterator.next();
    }
    await iterator.close();

    entries.sort((a, b) => a.seq - b.seq);
    return entries;
  }
}
