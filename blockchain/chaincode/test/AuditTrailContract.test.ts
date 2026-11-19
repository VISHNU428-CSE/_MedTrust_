import { AuditTrailContract } from '../src/contracts/AuditTrailContract';
import { AuditChainVerificationResult, AuditLogEntry } from '../src/models/types';
import { GENESIS_BLOCK_HASH } from '../src/utils/cryptoUtils';
import { createMockContext, MockStub } from './mockContext';

describe('AuditTrailContract Unit Tests', () => {
  let contract: AuditTrailContract;
  let ctx: any;
  let stub: MockStub;

  const PATIENT_ALICE = 'SYNTH-PAT-001';
  const DOCTOR_SMITH = 'SYNTH-DOC-101';

  beforeEach(() => {
    contract = new AuditTrailContract();
    ctx = createMockContext();
    stub = ctx.stub as unknown as MockStub;
  });

  test('LogAccessEvent: Appends first entry chained to GENESIS_BLOCK_HASH', async () => {
    const entryJson = await contract.LogAccessEvent(
      ctx,
      'PATIENT_SELF_READ',
      PATIENT_ALICE,
      'PATIENT',
      PATIENT_ALICE,
      'REC-LAB-001',
      '',
      'ALLOWED',
      'Patient accessed their own record'
    );

    const entry: AuditLogEntry = JSON.parse(entryJson);
    expect(entry.seq).toBe(1);
    expect(entry.prevHash).toBe(GENESIS_BLOCK_HASH);
    expect(entry.entryHash).toBeDefined();
    expect(entry.entryHash.length).toBe(64);
  });

  test('LogAccessEvent: Multiple entries form unbroken cryptographic chain', async () => {
    const e1Json = await contract.LogAccessEvent(
      ctx,
      'EVENT_1',
      PATIENT_ALICE,
      'PATIENT',
      PATIENT_ALICE,
      'REC-1',
      '',
      'ALLOWED',
      'Initial'
    );
    const e1: AuditLogEntry = JSON.parse(e1Json);

    const e2Json = await contract.LogAccessEvent(
      ctx,
      'EVENT_2',
      DOCTOR_SMITH,
      'DOCTOR',
      PATIENT_ALICE,
      'REC-1',
      'CON-1',
      'ALLOWED',
      'Doctor read'
    );
    const e2: AuditLogEntry = JSON.parse(e2Json);

    expect(e2.seq).toBe(2);
    expect(e2.prevHash).toBe(e1.entryHash);

    const verifyJson = await contract.VerifyAuditChain(ctx);
    const verify: AuditChainVerificationResult = JSON.parse(verifyJson);
    expect(verify.isIntact).toBe(true);
    expect(verify.entryCount).toBe(2);
    expect(verify.message).toContain('cryptographically intact');
  });

  test('VerifyAuditChain: Detects malicious tampering of stored audit record', async () => {
    await contract.LogAccessEvent(
      ctx,
      'EVENT_1',
      PATIENT_ALICE,
      'PATIENT',
      PATIENT_ALICE,
      'REC-1',
      '',
      'ALLOWED',
      'Init'
    );
    await contract.LogAccessEvent(
      ctx,
      'EVENT_2',
      DOCTOR_SMITH,
      'DOCTOR',
      PATIENT_ALICE,
      'REC-1',
      'CON-1',
      'ALLOWED',
      'Read'
    );
    await contract.LogAccessEvent(
      ctx,
      'EVENT_3',
      'SYNTH-MAL-999',
      'ATTACKER',
      PATIENT_ALICE,
      'REC-1',
      '',
      'DENIED',
      'Unauthorized probe'
    );

    // Tamper with event 3 in raw storage (change DENIED to ALLOWED)
    const key = '\x00AuditEntry\x00' + String(3).padStart(12, '0') + '\x00';
    const rawBytes = await stub.getState(key);
    const item = JSON.parse(rawBytes.toString());
    item.status = 'ALLOWED'; // tampering!
    await stub.putState(key, Buffer.from(JSON.stringify(item)));

    const verifyJson = await contract.VerifyAuditChain(ctx);
    const verify: AuditChainVerificationResult = JSON.parse(verifyJson);
    expect(verify.isIntact).toBe(false);
    expect(verify.message).toContain('Corrupted entry hash');
  });

  test('Queries: Retrieves logs filtered by patient and actor', async () => {
    await contract.LogAccessEvent(
      ctx,
      'EVENT_1',
      DOCTOR_SMITH,
      'DOCTOR',
      PATIENT_ALICE,
      'REC-1',
      'CON-1',
      'ALLOWED',
      'Read'
    );
    await contract.LogAccessEvent(
      ctx,
      'EVENT_2',
      PATIENT_ALICE,
      'PATIENT',
      PATIENT_ALICE,
      'REC-1',
      '',
      'ALLOWED',
      'Self read'
    );

    const patientLogs: AuditLogEntry[] = JSON.parse(
      await contract.GetAuditLogsByPatient(ctx, PATIENT_ALICE)
    );
    expect(patientLogs.length).toBe(2);

    const doctorLogs: AuditLogEntry[] = JSON.parse(
      await contract.GetAuditLogsByActor(ctx, DOCTOR_SMITH)
    );
    expect(doctorLogs.length).toBe(1);
    expect(doctorLogs[0].actorId).toBe(DOCTOR_SMITH);
  });
});
