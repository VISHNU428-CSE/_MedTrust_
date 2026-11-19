import { MedicalRecordContract } from '../src/contracts/MedicalRecordContract';
import { createMockContext } from './mockContext';

describe('MedicalRecordContract Unit Tests', () => {
  let contract: MedicalRecordContract;
  let ctx: any;

  const PATIENT_ALICE = 'SYNTH-PAT-001';
  const VALID_CHECKSUM = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const MOCK_CID = 'bafybeimdt7318a47402636a2829210medtrust';

  beforeEach(() => {
    contract = new MedicalRecordContract();
    ctx = createMockContext();
  });

  test('RegisterRecord: Successfully registers record metadata on-chain', async () => {
    const recordJson = await contract.RegisterRecord(
      ctx,
      'REC-LAB-001',
      PATIENT_ALICE,
      MOCK_CID,
      VALID_CHECKSUM,
      'LAB_REPORT',
      'Synthetic General Hospital',
      'SYNTH-DOC-101'
    );

    const record = JSON.parse(recordJson);
    expect(record.recordId).toBe('REC-LAB-001');
    expect(record.patientId).toBe(PATIENT_ALICE);
    expect(record.ipfsCid).toBe(MOCK_CID);
    expect(record.checksum).toBe(VALID_CHECKSUM);
    expect(record.recordType).toBe('LAB_REPORT');
    expect(record.facility).toBe('Synthetic General Hospital');
  });

  test('RegisterRecord: Rejects duplicate record IDs', async () => {
    await contract.RegisterRecord(
      ctx,
      'REC-LAB-001',
      PATIENT_ALICE,
      MOCK_CID,
      VALID_CHECKSUM,
      'LAB_REPORT'
    );

    await expect(
      contract.RegisterRecord(
        ctx,
        'REC-LAB-001',
        PATIENT_ALICE,
        MOCK_CID,
        VALID_CHECKSUM,
        'LAB_REPORT'
      )
    ).rejects.toThrow('already registered');
  });

  test('RegisterRecord: Rejects invalid checksum format', async () => {
    await expect(
      contract.RegisterRecord(
        ctx,
        'REC-LAB-002',
        PATIENT_ALICE,
        MOCK_CID,
        'invalid-checksum-short',
        'LAB_REPORT'
      )
    ).rejects.toThrow('Expected 64-character hexadecimal SHA-256 digest');
  });

  test('GetRecord: Retrieves registered metadata', async () => {
    await contract.RegisterRecord(
      ctx,
      'REC-LAB-001',
      PATIENT_ALICE,
      MOCK_CID,
      VALID_CHECKSUM,
      'LAB_REPORT'
    );

    const recordJson = await contract.GetRecord(ctx, 'REC-LAB-001');
    const record = JSON.parse(recordJson);
    expect(record.recordId).toBe('REC-LAB-001');
  });

  test('GetRecordsByPatient: Retrieves all records for given patient', async () => {
    await contract.RegisterRecord(
      ctx,
      'REC-001',
      PATIENT_ALICE,
      MOCK_CID,
      VALID_CHECKSUM,
      'LAB_REPORT'
    );
    await contract.RegisterRecord(
      ctx,
      'REC-002',
      PATIENT_ALICE,
      MOCK_CID,
      VALID_CHECKSUM,
      'CARDIOLOGY_VISIT'
    );

    const recordsJson = await contract.GetRecordsByPatient(ctx, PATIENT_ALICE);
    const records = JSON.parse(recordsJson);
    expect(records.length).toBe(2);
    expect(records.map((r: any) => r.recordId)).toContain('REC-001');
    expect(records.map((r: any) => r.recordId)).toContain('REC-002');
  });

  test('VerifyRecordChecksum: Verifies intact checksum match', async () => {
    await contract.RegisterRecord(
      ctx,
      'REC-LAB-001',
      PATIENT_ALICE,
      MOCK_CID,
      VALID_CHECKSUM,
      'LAB_REPORT'
    );

    const resJson = await contract.VerifyRecordChecksum(ctx, 'REC-LAB-001', VALID_CHECKSUM);
    const res = JSON.parse(resJson);
    expect(res.verified).toBe(true);
    expect(res.status).toBe('VERIFIED_INTACT');
  });

  test('VerifyRecordChecksum: Detects tampering or bit-flip corruption', async () => {
    await contract.RegisterRecord(
      ctx,
      'REC-LAB-001',
      PATIENT_ALICE,
      MOCK_CID,
      VALID_CHECKSUM,
      'LAB_REPORT'
    );

    const tamperedChecksum = '1111111111111111111111111111111111111111111111111111111111111111';
    const resJson = await contract.VerifyRecordChecksum(ctx, 'REC-LAB-001', tamperedChecksum);
    const res = JSON.parse(resJson);
    expect(res.verified).toBe(false);
    expect(res.status).toBe('CHECKSUM_MISMATCH');
  });
});
