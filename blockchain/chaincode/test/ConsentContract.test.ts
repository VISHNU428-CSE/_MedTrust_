import { ConsentContract } from '../src/contracts/ConsentContract';
import { ConsentStatus, VerifyConsentResult } from '../src/models/types';
import { createMockContext, MockStub } from './mockContext';

describe('ConsentContract Unit Tests', () => {
  let contract: ConsentContract;
  let ctx: any;
  let stub: MockStub;

  const PATIENT_ALICE = 'SYNTH-PAT-001';
  const PATIENT_BOB = 'SYNTH-PAT-002';
  const DOCTOR_SMITH = 'SYNTH-DOC-101';
  const NOW_EPOCH = 1760250000;

  beforeEach(() => {
    contract = new ConsentContract();
    ctx = createMockContext(NOW_EPOCH);
    stub = ctx.stub as unknown as MockStub;
  });

  test('RequestConsent: Creates consent in PENDING state', async () => {
    const consentJson = await contract.RequestConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600,
      'Routine annual checkup'
    );

    const consent = JSON.parse(consentJson);
    expect(consent.consentId).toBe('CONSENT-001');
    expect(consent.patientId).toBe(PATIENT_ALICE);
    expect(consent.doctorId).toBe(DOCTOR_SMITH);
    expect(consent.status).toBe(ConsentStatus.PENDING);
    expect(consent.allowedRecordTypes).toEqual(['LAB_REPORT']);
    expect(consent.validUntil).toBe(NOW_EPOCH + 3600);
  });

  test('RequestConsent: Prevents duplicate consent ID', async () => {
    await contract.RequestConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    await expect(
      contract.RequestConsent(
        ctx,
        'CONSENT-001',
        PATIENT_ALICE,
        DOCTOR_SMITH,
        JSON.stringify(['LAB_REPORT']),
        NOW_EPOCH + 3600
      )
    ).rejects.toThrow('already exists');
  });

  test('GrantConsent: Approves PENDING consent', async () => {
    await contract.RequestConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    const approvedJson = await contract.GrantConsent(ctx, 'CONSENT-001', PATIENT_ALICE);
    const approved = JSON.parse(approvedJson);
    expect(approved.status).toBe(ConsentStatus.APPROVED);
    expect(approved.approvedAt).toBe(NOW_EPOCH);
  });

  test('GrantConsent: Direct grant without prior request creates APPROVED consent', async () => {
    const grantedJson = await contract.GrantConsent(
      ctx,
      'CONSENT-DIRECT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['ALL']),
      NOW_EPOCH + 7200,
      'Direct grant'
    );

    const granted = JSON.parse(grantedJson);
    expect(granted.status).toBe(ConsentStatus.APPROVED);
    expect(granted.doctorId).toBe(DOCTOR_SMITH);
    expect(granted.allowedRecordTypes).toEqual(['ALL']);
  });

  test('GrantConsent: Unauthorized patient cannot approve another patient consent', async () => {
    await contract.RequestConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    await expect(
      contract.GrantConsent(ctx, 'CONSENT-001', PATIENT_BOB)
    ).rejects.toThrow('not the owner');
  });

  test('RejectConsent: Rejects PENDING consent', async () => {
    await contract.RequestConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    const rejectedJson = await contract.RejectConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      'Patient declined'
    );
    const rejected = JSON.parse(rejectedJson);
    expect(rejected.status).toBe(ConsentStatus.REJECTED);
  });

  test('RevokeConsent: Immediate atomic revocation by patient', async () => {
    await contract.GrantConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    const revokedJson = await contract.RevokeConsent(ctx, 'CONSENT-001', PATIENT_ALICE);
    const revoked = JSON.parse(revokedJson);
    expect(revoked.status).toBe(ConsentStatus.REVOKED);
    expect(revoked.revokedAt).toBe(NOW_EPOCH);
  });

  test('RevokeConsent: Cross-patient revocation tampering is blocked', async () => {
    await contract.GrantConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['ALL']),
      NOW_EPOCH + 3600
    );

    await expect(
      contract.RevokeConsent(ctx, 'CONSENT-001', PATIENT_BOB)
    ).rejects.toThrow('not authorized to revoke consent');
  });

  test('VerifyConsent: Full access verification workflow', async () => {
    // 1. No consent exists
    const check1: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(check1.allowed).toBe(false);
    expect(check1.reason).toBe('NO_CONSENT_FOUND');

    // 2. Grant consent for LAB_REPORT
    await contract.GrantConsent(
      ctx,
      'CONSENT-001',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    // 3. Verify allowed for LAB_REPORT
    const check2: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(check2.allowed).toBe(true);
    expect(check2.reason).toBe('CONSENT_ACTIVE');

    // 4. Verify scope isolation: CARDIOLOGY_VISIT denied
    const check3: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'CARDIOLOGY_VISIT')
    );
    expect(check3.allowed).toBe(false);
    expect(check3.reason).toBe('CONSENT_SCOPE_EXCLUDED');

    // 5. Expiration check: Advance clock past validUntil
    stub.setTxTimestamp(NOW_EPOCH + 4000);
    const check4: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(check4.allowed).toBe(false);
    expect(check4.reason).toBe('CONSENT_EXPIRED');

    // 6. Reset clock and revoke consent
    stub.setTxTimestamp(NOW_EPOCH + 10);
    await contract.RevokeConsent(ctx, 'CONSENT-001', PATIENT_ALICE);

    // 7. Verify immediate block upon revocation
    const check5: VerifyConsentResult = JSON.parse(
      await contract.VerifyConsent(ctx, DOCTOR_SMITH, PATIENT_ALICE, 'LAB_REPORT')
    );
    expect(check5.allowed).toBe(false);
    expect(check5.reason).toBe('CONSENT_REVOKED');
  });

  test('Zero PHI: Enforces security check against prohibited PHI patterns', async () => {
    await expect(
      contract.RequestConsent(
        ctx,
        'CONSENT-LEAK',
        PATIENT_ALICE,
        DOCTOR_SMITH,
        JSON.stringify(['LAB_REPORT']),
        NOW_EPOCH + 3600,
        'Patient SSN is 123-45-6789'
      )
    ).rejects.toThrow('COMPLIANCE VIOLATION');
  });

  test('GetConsent and GetConsentsByPatient: Retrieve stored consents', async () => {
    await contract.GrantConsent(
      ctx,
      'CONSENT-QUERY-01',
      PATIENT_ALICE,
      DOCTOR_SMITH,
      JSON.stringify(['LAB_REPORT']),
      NOW_EPOCH + 3600
    );

    const singleJson = await contract.GetConsent(ctx, 'CONSENT-QUERY-01');
    const single = JSON.parse(singleJson);
    expect(single.consentId).toBe('CONSENT-QUERY-01');

    const patientListJson = await contract.GetConsentsByPatient(ctx, PATIENT_ALICE);
    const patientList = JSON.parse(patientListJson);
    expect(patientList.length).toBeGreaterThanOrEqual(1);

    await expect(contract.GetConsent(ctx, 'NON-EXISTENT')).rejects.toThrow('not found');
  });

  test('Edge cases: Rejects past validUntilEpoch and non-existent reject', async () => {
    await expect(
      contract.RequestConsent(
        ctx,
        'CONSENT-PAST',
        PATIENT_ALICE,
        DOCTOR_SMITH,
        JSON.stringify(['LAB_REPORT']),
        NOW_EPOCH - 100
      )
    ).rejects.toThrow('must be in the future');

    await expect(
      contract.RejectConsent(ctx, 'NON-EXISTENT', PATIENT_ALICE)
    ).rejects.toThrow('not found');
  });
});

