import { MedTrustContract } from '../src/contracts/MedTrustContract';
import { AuditChainVerificationResult, VerifyConsentResult } from '../src/models/types';
import { createMockContext, MockStub } from './mockContext';

describe('MedTrustContract Integrated End-to-End Tests', () => {
  let contract: MedTrustContract;
  let ctx: any;
  let stub: MockStub;

  const PATIENT_ALICE = 'SYNTH-PAT-001';
  const DOCTOR_SMITH = 'SYNTH-DOC-101';
  const RECORD_ID = 'REC-LAB-ALICE-001';
  const MOCK_CID = 'bafybeimdt7318a47402636a2829210medtrust';
  const CHECKSUM = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const NOW_EPOCH = 1760250000;

  beforeEach(() => {
    contract = new MedTrustContract();
    ctx = createMockContext(NOW_EPOCH);
    stub = ctx.stub as unknown as MockStub;
  });

  test('Complete MedTrust Healthcare Workflow Lifecycle', async () => {
    // Step 0: Initialize Ledger
    const initRes = JSON.parse(await contract.InitLedger(ctx));
    expect(initRes.status).toBe('INITIALIZED');

    // Step 1: Lab registers medical record metadata
    const regRes = JSON.parse(
      await contract.RegisterRecord(
        ctx,
        RECORD_ID,
        PATIENT_ALICE,
        MOCK_CID,
        CHECKSUM,
        'LAB_REPORT',
        'Synthetic General Hospital Lab',
        'SYNTH-LAB-TECH-01'
      )
    );
    expect(regRes.recordId).toBe(RECORD_ID);

    // Step 2: Doctor verifies integrity of registered record checksum
    const verifyChecksum = JSON.parse(
      await contract.VerifyRecordChecksum(ctx, RECORD_ID, CHECKSUM)
    );
    expect(verifyChecksum.verified).toBe(true);
    expect(verifyChecksum.status).toBe('VERIFIED_INTACT');

    // Step 3: Doctor requests consent from Patient Alice
    const consentReq = JSON.parse(
      await contract.RequestConsent(
        ctx,
        'CONSENT-ALICE-SMITH-001',
        PATIENT_ALICE,
        DOCTOR_SMITH,
        JSON.stringify(['LAB_REPORT']),
        NOW_EPOCH + 86400,
        'Consultation and lab analysis'
      )
    );
    expect(consentReq.status).toBe('PENDING');

    // Doctor checks consent before patient grants -> PENDING
    const checkBeforeGrant: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(checkBeforeGrant.allowed).toBe(false);
    expect(checkBeforeGrant.reason).toBe('CONSENT_PENDING');

    // Step 4: Patient Alice grants consent
    const grantRes = JSON.parse(
      await contract.GrantConsent(ctx, 'CONSENT-ALICE-SMITH-001', PATIENT_ALICE)
    );
    expect(grantRes.status).toBe('APPROVED');

    // Step 5: Doctor checks consent -> ACTIVE / ALLOWED
    const checkAfterGrant: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(checkAfterGrant.allowed).toBe(true);
    expect(checkAfterGrant.reason).toBe('CONSENT_ACTIVE');

    // Doctor accesses cardiology report -> SCOPE EXCLUDED
    const checkCardiology: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'CARDIOLOGY_VISIT')
    );
    expect(checkCardiology.allowed).toBe(false);
    expect(checkCardiology.reason).toBe('CONSENT_SCOPE_EXCLUDED');

    // Step 6: Patient Alice revokes consent
    const revokeRes = JSON.parse(
      await contract.RevokeConsent(ctx, 'CONSENT-ALICE-SMITH-001', PATIENT_ALICE)
    );
    expect(revokeRes.status).toBe('REVOKED');

    // Step 7: Doctor checks consent immediately after revocation -> REVOKED / DENIED
    const checkAfterRevoke: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(checkAfterRevoke.allowed).toBe(false);
    expect(checkAfterRevoke.reason).toBe('CONSENT_REVOKED');

    // Step 8: Verify audit trail completeness and cryptographic chain integrity
    const auditChain: AuditChainVerificationResult = JSON.parse(
      await contract.VerifyAuditChain(ctx)
    );
    expect(auditChain.isIntact).toBe(true);
    expect(auditChain.entryCount).toBeGreaterThanOrEqual(5);

    // Step 9: Verify patient Alice can view her own audit trail
    const aliceAuditLogs = JSON.parse(
      await contract.GetAuditLogsByPatient(ctx, PATIENT_ALICE)
    );
    expect(aliceAuditLogs.length).toBeGreaterThanOrEqual(4);

    // Step 10: Verify queries on MedTrustContract
    const rec = JSON.parse(await contract.GetRecord(ctx, RECORD_ID));
    expect(rec.recordId).toBe(RECORD_ID);

    const patientRecs = JSON.parse(await contract.GetRecordsByPatient(ctx, PATIENT_ALICE));
    expect(patientRecs.length).toBeGreaterThanOrEqual(1);

    const consentData = JSON.parse(await contract.GetConsent(ctx, 'CONSENT-ALICE-SMITH-001'));
    expect(consentData.consentId).toBe('CONSENT-ALICE-SMITH-001');

    const patientConsents = JSON.parse(await contract.GetConsentsByPatient(ctx, PATIENT_ALICE));
    expect(patientConsents.length).toBeGreaterThanOrEqual(1);

    const docLogs = JSON.parse(await contract.GetAuditLogsByActor(ctx, DOCTOR_SMITH));
    expect(docLogs.length).toBeGreaterThanOrEqual(1);
  });

  test('MedTrustContract RejectConsent workflow', async () => {
    await contract.RequestConsent(
      ctx,
      'CONSENT-REJECT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    const rejectRes = JSON.parse(
      await contract.RejectConsent(ctx, 'CONSENT-REJECT-001', PATIENT_ALICE, 'Not interested')
    );
    expect(rejectRes.status).toBe('REJECTED');

    const verifyRes = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(verifyRes.allowed).toBe(false);
    expect(verifyRes.reason).toBe('CONSENT_REJECTED');
  });
});

