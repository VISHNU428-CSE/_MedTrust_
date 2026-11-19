import { Context, Contract, Info, Transaction } from 'fabric-contract-api';
import { MedicalRecordMetadata } from '../models/types';
import { assertZeroPHI } from '../utils/cryptoUtils';

const SHA256_HEX_REGEX = /^[a-fA-F0-9]{64}$/;

@Info({
  title: 'MedicalRecordContract',
  description: 'Smart contract for decentralized medical record metadata registration and cryptographic integrity verification'
})
export class MedicalRecordContract extends Contract {
  constructor() {
    super('MedicalRecordContract');
  }

  /**
   * Helper to construct composite key for medical record metadata.
   */
  private getRecordKey(ctx: Context, recordId: string): string {
    return ctx.stub.createCompositeKey('MedicalRecord', [recordId]);
  }

  /**
   * Helper to get transaction submission timestamp in seconds.
   */
  private getTxTimestamp(ctx: Context): number {
    const txTime = ctx.stub.getTxTimestamp();
    return Math.floor(txTime.seconds.low || Number(txTime.seconds));
  }

  /**
   * Register on-chain metadata for an encrypted medical record stored on IPFS.
   * ZERO PHI GUARANTEE: Never writes plaintext clinical content, diagnostic findings, or patient identifiers beyond synthetic/pseudonymous IDs.
   */
  @Transaction()
  public async RegisterRecord(
    ctx: Context,
    recordId: string,
    patientId: string,
    ipfsCid: string,
    checksum: string,
    recordType: string,
    facility: string = 'Synthetic Hospital',
    registeredBy: string = ''
  ): Promise<string> {
    // 1. Zero PHI enforcement
    assertZeroPHI(
      { recordId, patientId, ipfsCid, recordType, facility, registeredBy },
      'RegisterRecord metadata arguments'
    );

    // 2. Format validation
    if (!recordId || !recordId.trim()) {
      throw new Error('recordId cannot be empty');
    }
    if (!patientId || !patientId.trim()) {
      throw new Error('patientId cannot be empty');
    }
    if (!ipfsCid || !ipfsCid.trim()) {
      throw new Error('ipfsCid cannot be empty');
    }
    if (!SHA256_HEX_REGEX.test(checksum)) {
      throw new Error(
        `Invalid checksum format: '${checksum}'. Expected 64-character hexadecimal SHA-256 digest.`
      );
    }

    // 3. Verify collision / existence
    const key = this.getRecordKey(ctx, recordId);
    const existingBytes = await ctx.stub.getState(key);
    if (existingBytes && existingBytes.length > 0) {
      throw new Error(`Medical record metadata with recordId '${recordId}' already registered on ledger`);
    }

    const now = this.getTxTimestamp(ctx);
    const metadata: MedicalRecordMetadata = {
      docType: 'record_metadata',
      recordId,
      patientId,
      ipfsCid,
      checksum: checksum.toLowerCase(),
      recordType: recordType.toUpperCase(),
      facility,
      timestamp: now,
      registeredBy: registeredBy || patientId,
      metadataVersion: 1
    };

    await ctx.stub.putState(key, Buffer.from(JSON.stringify(metadata)));
    return JSON.stringify(metadata);
  }

  /**
   * Retrieve on-chain metadata for a record.
   */
  @Transaction(false)
  public async GetRecord(ctx: Context, recordId: string): Promise<string> {
    const key = this.getRecordKey(ctx, recordId);
    const data = await ctx.stub.getState(key);
    if (!data || data.length === 0) {
      throw new Error(`Medical record metadata not found for recordId: '${recordId}'`);
    }
    return data.toString();
  }

  /**
   * Retrieve all record metadata for a given patient.
   */
  @Transaction(false)
  public async GetRecordsByPatient(ctx: Context, patientId: string): Promise<string> {
    const iterator = await ctx.stub.getStateByPartialCompositeKey('MedicalRecord', []);
    const records: MedicalRecordMetadata[] = [];

    let res = await iterator.next();
    while (!res.done) {
      if (res.value && res.value.value) {
        try {
          const item: MedicalRecordMetadata = JSON.parse(Buffer.from(res.value.value).toString('utf8'));
          if (item.docType === 'record_metadata' && item.patientId === patientId) {
            records.push(item);
          }
        } catch {
          // ignore malformed keys
        }
      }
      res = await iterator.next();
    }
    await iterator.close();

    // Sort descending by timestamp
    records.sort((a, b) => b.timestamp - a.timestamp);
    return JSON.stringify(records);
  }

  /**
   * Cryptographic integrity verification: Verifies an IPFS-retrieved payload checksum against the immutable on-chain record.
   */
  @Transaction(false)
  public async VerifyRecordChecksum(
    ctx: Context,
    recordId: string,
    calculatedChecksum: string
  ): Promise<string> {
    const rawRecord = await this.GetRecord(ctx, recordId);
    const record: MedicalRecordMetadata = JSON.parse(rawRecord);

    const match = record.checksum.toLowerCase() === calculatedChecksum.toLowerCase();
    const result = {
      verified: match,
      recordId: record.recordId,
      expectedChecksum: record.checksum,
      calculatedChecksum: calculatedChecksum.toLowerCase(),
      ipfsCid: record.ipfsCid,
      status: match ? 'VERIFIED_INTACT' : 'CHECKSUM_MISMATCH'
    };

    return JSON.stringify(result);
  }
}
