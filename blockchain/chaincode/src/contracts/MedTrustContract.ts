import { Context, Contract, Info, Transaction } from 'fabric-contract-api';
import { ConsentContract } from './ConsentContract';
import { MedicalRecordContract } from './MedicalRecordContract';
import { AuditTrailContract } from './AuditTrailContract';
import { AccessStatus, ActorRole } from '../models/types';

@Info({
  title: 'MedTrustContract',
  description: 'Primary unified smart contract for MedTrust healthcare blockchain operations'
})
export class MedTrustContract extends Contract {
  private consentContract: ConsentContract;
  private recordContract: MedicalRecordContract;
  private auditContract: AuditTrailContract;

  constructor() {
    super('MedTrustContract');
    this.consentContract = new ConsentContract();
    this.recordContract = new MedicalRecordContract();
    this.auditContract = new AuditTrailContract();
  }

  /**
   * Initializes the ledger state with initial parameters if needed.
   */
  @Transaction()
  public async InitLedger(ctx: Context): Promise<string> {
    const initialized = await ctx.stub.getState('MEDTRUST_INITIALIZED');
    if (initialized && initialized.length > 0) {
      return JSON.stringify({ status: 'ALREADY_INITIALIZED' });
    }

    await ctx.stub.putState('MEDTRUST_INITIALIZED', Buffer.from('true'));
    // Log genesis audit event
    await this.auditContract.LogAccessEvent(
      ctx,
      'LEDGER_GENESIS_INIT',
      'SYSTEM',
      'SYSTEM',
      'SYSTEM',
      '',
      '',
      'RECORDED',
      'MedTrust Hyperledger Fabric Ledger Initialized'
    );

    return JSON.stringify({ status: 'INITIALIZED', timestamp: Date.now() });
  }

  // ==========================================
  // CONSENT MANAGEMENT
  // ==========================================

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
    const result = await this.consentContract.RequestConsent(
      ctx,
      consentId,
      patientId,
      doctorId,
      allowedRecordTypesJson,
      validUntilEpoch,
      purpose
    );

    // Auto-log to audit trail
    await this.auditContract.LogAccessEvent(
      ctx,
      'CONSENT_REQUESTED',
      doctorId,
      'DOCTOR',
      patientId,
      '',
      consentId,
      'RECORDED',
      `Consent requested by doctor ${doctorId}`
    );

    return result;
  }

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
    const result = await this.consentContract.GrantConsent(
      ctx,
      consentId,
      patientId,
      doctorId,
      allowedRecordTypesJson,
      validUntilEpoch,
      purpose
    );

    await this.auditContract.LogAccessEvent(
      ctx,
      'CONSENT_GRANTED',
      patientId,
      'PATIENT',
      patientId,
      '',
      consentId,
      'ALLOWED',
      `Consent granted by patient ${patientId}`
    );

    return result;
  }

  @Transaction()
  public async RejectConsent(
    ctx: Context,
    consentId: string,
    patientId: string,
    reason: string = ''
  ): Promise<string> {
    const result = await this.consentContract.RejectConsent(ctx, consentId, patientId, reason);

    await this.auditContract.LogAccessEvent(
      ctx,
      'CONSENT_REJECTED',
      patientId,
      'PATIENT',
      patientId,
      '',
      consentId,
      'DENIED',
      `Consent rejected by patient: ${reason}`
    );

    return result;
  }

  @Transaction()
  public async RevokeConsent(
    ctx: Context,
    consentId: string,
    requestingPatientId: string
  ): Promise<string> {
    const result = await this.consentContract.RevokeConsent(ctx, consentId, requestingPatientId);

    await this.auditContract.LogAccessEvent(
      ctx,
      'CONSENT_REVOCATION',
      requestingPatientId,
      'PATIENT',
      requestingPatientId,
      '',
      consentId,
      'ALLOWED',
      `Consent ${consentId} revoked with immediate effect by patient ${requestingPatientId}`
    );

    return result;
  }

  @Transaction(false)
  public async VerifyConsent(
    ctx: Context,
    doctorId: string,
    patientId: string,
    recordType: string
  ): Promise<string> {
    return this.consentContract.VerifyConsent(ctx, doctorId, patientId, recordType);
  }

  @Transaction(false)
  public async GetConsent(ctx: Context, consentId: string): Promise<string> {
    return this.consentContract.GetConsent(ctx, consentId);
  }

  @Transaction(false)
  public async GetConsentsByPatient(ctx: Context, patientId: string): Promise<string> {
    return this.consentContract.GetConsentsByPatient(ctx, patientId);
  }

  // ==========================================
  // MEDICAL RECORD METADATA REGISTRATION
  // ==========================================

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
    const result = await this.recordContract.RegisterRecord(
      ctx,
      recordId,
      patientId,
      ipfsCid,
      checksum,
      recordType,
      facility,
      registeredBy
    );

    await this.auditContract.LogAccessEvent(
      ctx,
      'RECORD_REGISTERED',
      registeredBy || patientId,
      'SYSTEM',
      patientId,
      recordId,
      '',
      'RECORDED',
      `Record ${recordId} metadata registered on-chain with IPFS CID ${ipfsCid}`
    );

    return result;
  }

  @Transaction(false)
  public async GetRecord(ctx: Context, recordId: string): Promise<string> {
    return this.recordContract.GetRecord(ctx, recordId);
  }

  @Transaction(false)
  public async GetRecordsByPatient(ctx: Context, patientId: string): Promise<string> {
    return this.recordContract.GetRecordsByPatient(ctx, patientId);
  }

  @Transaction(false)
  public async VerifyRecordChecksum(
    ctx: Context,
    recordId: string,
    calculatedChecksum: string
  ): Promise<string> {
    return this.recordContract.VerifyRecordChecksum(ctx, recordId, calculatedChecksum);
  }

  // ==========================================
  // AUDIT TRAIL LOGGING & VERIFICATION
  // ==========================================

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
    return this.auditContract.LogAccessEvent(
      ctx,
      eventType,
      actorId,
      actorRole,
      targetPatientId,
      recordId,
      consentId,
      status,
      detail
    );
  }

  @Transaction(false)
  public async GetAuditLogsByPatient(ctx: Context, patientId: string): Promise<string> {
    return this.auditContract.GetAuditLogsByPatient(ctx, patientId);
  }

  @Transaction(false)
  public async GetAuditLogsByActor(ctx: Context, actorId: string): Promise<string> {
    return this.auditContract.GetAuditLogsByActor(ctx, actorId);
  }

  @Transaction(false)
  public async VerifyAuditChain(ctx: Context): Promise<string> {
    return this.auditContract.VerifyAuditChain(ctx);
  }
}
