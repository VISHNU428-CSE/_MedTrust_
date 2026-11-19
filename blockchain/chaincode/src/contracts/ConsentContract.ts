import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';
import { ConsentRecord, ConsentStatus, VerifyConsentResult } from '../models/types';
import { assertZeroPHI } from '../utils/cryptoUtils';

@Info({
  title: 'ConsentContract',
  description: 'Smart contract for decentralized patient consent lifecycle and verification'
})
export class ConsentContract extends Contract {
  constructor() {
    super('ConsentContract');
  }

  /**
   * Helper to construct ledger key for a consent record.
   */
  private getConsentKey(ctx: Context, consentId: string): string {
    return ctx.stub.createCompositeKey('Consent', [consentId]);
  }

  /**
   * Helper to retrieve transaction submission epoch in seconds.
   */
  private getTxTimestamp(ctx: Context): number {
    const txTime = ctx.stub.getTxTimestamp();
    return Math.floor(txTime.seconds.low || Number(txTime.seconds));
  }

  /**
   * Request consent by a doctor or clinician (creates consent in PENDING state).
   */
  @Transaction()
  public async RequestConsent(
    ctx: Context,
    consentId: string,
    patientId: string,
    doctorId: string,
    allowedRecordTypesJson: string,
    validUntilEpoch: number,
    purpose: string = ''
  ): Promise<string> {
    assertZeroPHI({ consentId, patientId, doctorId, purpose }, 'RequestConsent arguments');

    const key = this.getConsentKey(ctx, consentId);
    const existingBytes = await ctx.stub.getState(key);
    if (existingBytes && existingBytes.length > 0) {
      throw new Error(`Consent record ${consentId} already exists`);
    }

    let allowedRecordTypes: string[];
    try {
      allowedRecordTypes = JSON.parse(allowedRecordTypesJson);
      if (!Array.isArray(allowedRecordTypes) || allowedRecordTypes.length === 0) {
        throw new Error('allowedRecordTypes must be a non-empty array');
      }
    } catch {
      throw new Error(`Invalid JSON format for allowedRecordTypes: ${allowedRecordTypesJson}`);
    }

    const now = this.getTxTimestamp(ctx);
    if (validUntilEpoch <= now) {
      throw new Error(`validUntilEpoch (${validUntilEpoch}) must be in the future (current time: ${now})`);
    }

    const consent: ConsentRecord = {
      docType: 'consent',
      consentId,
      patientId,
      doctorId,
      allowedRecordTypes,
      status: ConsentStatus.PENDING,
      validUntil: validUntilEpoch,
      createdAt: now,
      updatedAt: now,
      purpose
    };

    await ctx.stub.putState(key, Buffer.from(JSON.stringify(consent)));
    return JSON.stringify(consent);
  }

  /**
   * Grant consent (Patient grants or approves consent).
   * Supports:
   * 1. Approving a PENDING consent.
   * 2. Direct grant of a new consent in APPROVED state.
   */
  @Transaction()
  public async GrantConsent(
    ctx: Context,
    consentId: string,
    patientId: string,
    doctorId: string = '',
    allowedRecordTypesJson: string = '["ALL"]',
    validUntilEpoch: number = 0,
    purpose: string = ''
  ): Promise<string> {
    assertZeroPHI({ consentId, patientId, doctorId, purpose }, 'GrantConsent arguments');

    const key = this.getConsentKey(ctx, consentId);
    const existingBytes = await ctx.stub.getState(key);
    const now = this.getTxTimestamp(ctx);

    if (existingBytes && existingBytes.length > 0) {
      // Existing consent transition
      const consent: ConsentRecord = JSON.parse(existingBytes.toString());

      if (consent.patientId !== patientId) {
        throw new Error(
          `Unauthorized: Patient ${patientId} is not the owner of consent ${consentId} (owner: ${consent.patientId})`
        );
      }

      if (consent.status === ConsentStatus.REVOKED) {
        throw new Error(`Invalid state transition: Cannot re-grant revoked consent ${consentId}. Create a new consent.`);
      }

      if (consent.status === ConsentStatus.REJECTED) {
        throw new Error(`Invalid state transition: Cannot grant previously rejected consent ${consentId}. Create a new consent.`);
      }

      // Valid state transition: PENDING -> APPROVED
      consent.status = ConsentStatus.APPROVED;
      consent.approvedAt = now;
      consent.updatedAt = now;
      if (validUntilEpoch > now) {
        consent.validUntil = validUntilEpoch;
      }

      await ctx.stub.putState(key, Buffer.from(JSON.stringify(consent)));
      return JSON.stringify(consent);
    } else {
      // Direct grant of new consent
      if (!doctorId) {
        throw new Error('doctorId is required when creating a new consent grant');
      }

      let allowedRecordTypes: string[];
      try {
        allowedRecordTypes = JSON.parse(allowedRecordTypesJson);
        if (!Array.isArray(allowedRecordTypes) || allowedRecordTypes.length === 0) {
          throw new Error('allowedRecordTypes must be a non-empty array');
        }
      } catch {
        throw new Error(`Invalid JSON format for allowedRecordTypes: ${allowedRecordTypesJson}`);
      }

      const expiry = validUntilEpoch > now ? validUntilEpoch : now + 86400 * 30; // default 30 days
      const consent: ConsentRecord = {
        docType: 'consent',
        consentId,
        patientId,
        doctorId,
        allowedRecordTypes,
        status: ConsentStatus.APPROVED,
        validUntil: expiry,
        createdAt: now,
        updatedAt: now,
        approvedAt: now,
        purpose
      };

      await ctx.stub.putState(key, Buffer.from(JSON.stringify(consent)));
      return JSON.stringify(consent);
    }
  }

  /**
   * Reject a pending consent request (Patient rejects doctor access).
   */
  @Transaction()
  public async RejectConsent(
    ctx: Context,
    consentId: string,
    patientId: string,
    reason: string = ''
  ): Promise<string> {
    const key = this.getConsentKey(ctx, consentId);
    const existingBytes = await ctx.stub.getState(key);

    if (!existingBytes || existingBytes.length === 0) {
      throw new Error(`Consent record ${consentId} not found`);
    }

    const consent: ConsentRecord = JSON.parse(existingBytes.toString());

    if (consent.patientId !== patientId) {
      throw new Error(
        `Unauthorized: Patient ${patientId} is not the owner of consent ${consentId} (owner: ${consent.patientId})`
      );
    }

    if (consent.status !== ConsentStatus.PENDING) {
      throw new Error(`Invalid state transition: Only PENDING consent can be rejected (current status: ${consent.status})`);
    }

    const now = this.getTxTimestamp(ctx);
    consent.status = ConsentStatus.REJECTED;
    consent.rejectedAt = now;
    consent.updatedAt = now;
    if (reason) {
      consent.purpose = `Rejected: ${reason}`;
    }

    await ctx.stub.putState(key, Buffer.from(JSON.stringify(consent)));
    return JSON.stringify(consent);
  }

  /**
   * Revoke an active consent with immediate effect.
   * Enforces patient ownership and transitions status to REVOKED.
   */
  @Transaction()
  public async RevokeConsent(
    ctx: Context,
    consentId: string,
    requestingPatientId: string
  ): Promise<string> {
    const key = this.getConsentKey(ctx, consentId);
    const existingBytes = await ctx.stub.getState(key);

    if (!existingBytes || existingBytes.length === 0) {
      throw new Error(`Consent record ${consentId} not found`);
    }

    const consent: ConsentRecord = JSON.parse(existingBytes.toString());

    // CRITICAL OWNERSHIP CHECK: Only the patient who owns the consent can revoke it
    if (consent.patientId !== requestingPatientId) {
      throw new Error(
        `Patient ${requestingPatientId} is not authorized to revoke consent ${consentId} owned by ${consent.patientId}`
      );
    }

    if (consent.status === ConsentStatus.REVOKED) {
      return JSON.stringify(consent); // idempotent revocation
    }

    const now = this.getTxTimestamp(ctx);
    consent.status = ConsentStatus.REVOKED;
    consent.revokedAt = now;
    consent.updatedAt = now;

    await ctx.stub.putState(key, Buffer.from(JSON.stringify(consent)));
    return JSON.stringify(consent);
  }

  /**
   * Verify whether a doctor has legitimate, active consent to access a patient's record.
   * Evaluates latest consent record and enforces revocation, expiration, and scoping.
   */
  @Transaction(false)
  public async VerifyConsent(
    ctx: Context,
    doctorId: string,
    patientId: string,
    recordType: string
  ): Promise<string> {
    const allConsents = await this.getConsentsForPair(ctx, patientId, doctorId);

    if (allConsents.length === 0) {
      const result: VerifyConsentResult = {
        allowed: false,
        reason: 'NO_CONSENT_FOUND'
      };
      return JSON.stringify(result);
    }

    const now = this.getTxTimestamp(ctx);

    // Evaluate newest consent first
    for (const consent of allConsents) {
      if (consent.status === ConsentStatus.REVOKED) {
        const result: VerifyConsentResult = {
          allowed: false,
          reason: 'CONSENT_REVOKED',
          consentId: consent.consentId
        };
        return JSON.stringify(result);
      }

      if (consent.status === ConsentStatus.REJECTED) {
        const result: VerifyConsentResult = {
          allowed: false,
          reason: 'CONSENT_REJECTED',
          consentId: consent.consentId
        };
        return JSON.stringify(result);
      }

      if (consent.status === ConsentStatus.PENDING) {
        const result: VerifyConsentResult = {
          allowed: false,
          reason: 'CONSENT_PENDING',
          consentId: consent.consentId
        };
        return JSON.stringify(result);
      }

      // Check expiration
      if (now > consent.validUntil) {
        const result: VerifyConsentResult = {
          allowed: false,
          reason: 'CONSENT_EXPIRED',
          consentId: consent.consentId,
          validUntil: consent.validUntil
        };
        return JSON.stringify(result);
      }

      // Check scope
      const isScoped =
        consent.allowedRecordTypes.includes('ALL') ||
        consent.allowedRecordTypes.includes(recordType);

      if (isScoped) {
        const result: VerifyConsentResult = {
          allowed: true,
          reason: 'CONSENT_ACTIVE',
          consentId: consent.consentId,
          validUntil: consent.validUntil,
          allowedRecordTypes: consent.allowedRecordTypes
        };
        return JSON.stringify(result);
      } else {
        const result: VerifyConsentResult = {
          allowed: false,
          reason: 'CONSENT_SCOPE_EXCLUDED',
          consentId: consent.consentId,
          allowedRecordTypes: consent.allowedRecordTypes
        };
        return JSON.stringify(result);
      }
    }

    const defaultResult: VerifyConsentResult = {
      allowed: false,
      reason: 'NO_CONSENT_FOUND'
    };
    return JSON.stringify(defaultResult);
  }

  /**
   * Read single consent record by ID.
   */
  @Transaction(false)
  public async GetConsent(ctx: Context, consentId: string): Promise<string> {
    const key = this.getConsentKey(ctx, consentId);
    const data = await ctx.stub.getState(key);
    if (!data || data.length === 0) {
      throw new Error(`Consent record ${consentId} not found`);
    }
    return data.toString();
  }

  /**
   * Retrieve all consents for a patient.
   */
  @Transaction(false)
  public async GetConsentsByPatient(ctx: Context, patientId: string): Promise<string> {
    const iterator = await ctx.stub.getStateByPartialCompositeKey('Consent', []);
    const results: ConsentRecord[] = [];

    let res = await iterator.next();
    while (!res.done) {
      if (res.value && res.value.value) {
        const record: ConsentRecord = JSON.parse(Buffer.from(res.value.value).toString('utf8'));
        if (record.docType === 'consent' && record.patientId === patientId) {
          results.push(record);
        }
      }
      res = await iterator.next();
    }
    await iterator.close();

    return JSON.stringify(results);
  }

  /**
   * Internal helper to fetch all consents for a specific patient-doctor pair.
   * Sorted in reverse chronological order (newest first).
   */
  private async getConsentsForPair(
    ctx: Context,
    patientId: string,
    doctorId: string
  ): Promise<ConsentRecord[]> {
    const iterator = await ctx.stub.getStateByPartialCompositeKey('Consent', []);
    const matches: ConsentRecord[] = [];

    let res = await iterator.next();
    while (!res.done) {
      if (res.value && res.value.value) {
        try {
          const record: ConsentRecord = JSON.parse(Buffer.from(res.value.value).toString('utf8'));
          if (
            record.docType === 'consent' &&
            record.patientId === patientId &&
            record.doctorId === doctorId
          ) {
            matches.push(record);
          }
        } catch {
          // ignore malformed keys
        }
      }
      res = await iterator.next();
    }
    await iterator.close();

    // Sort descending by createdAt
    matches.sort((a, b) => b.createdAt - a.createdAt);
    return matches;
  }
}
