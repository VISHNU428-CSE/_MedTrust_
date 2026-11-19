import { MedTrustContract } from '../src/contracts/MedTrustContract';
import { MedicalRecordMetadata } from '../src/models/types';
import { createMockContext, MockStub } from './mockContext';

describe('MedTrustContract Verify Ledger Records Suite (rec-001, rec-002, rec-003)', () => {
  let contract: MedTrustContract;
  let ctx: any;
  let stub: MockStub;

  const PATIENT_ID = 'pat-984210';
  const NOW_EPOCH = 1760250000;

  const RECORDS_FIXTURE = [
    {
      recordId: 'rec-001',
      patientId: PATIENT_ID,
      ipfsCid: 'bafkreiajkhnxasfkrk67gw3duvtupx2gbc7b5kfs52vhgrgo3adbk5rm54',
      checksum: '0951db7048aa8abdf35b63a56747df4608be1ea8b2eeaa7344ced80615762cef',
      recordType: 'IMAGING_MRI',
      facility: 'Metro General Hospital',
      registeredBy: 'Dr. Marcus Sterling, MD'
    },
    {
      recordId: 'rec-002',
      patientId: PATIENT_ID,
      ipfsCid: 'bafkreictuhch5gilp2jxajuaapi65hmeh4tqs5swvdjnkvk74esryocdqq',
      checksum: '53a1c47e990b7e9370268003d1ee9d843f27097656a8d2d5555fe1251c384384',
      recordType: 'LAB_REPORT',
      facility: 'Metro Labs & Diagnostics',
      registeredBy: 'Dr. Sarah Lin, MD'
    },
    {
      recordId: 'rec-003',
      patientId: PATIENT_ID,
      ipfsCid: 'bafkreia3ptjqohjrgx7vxpefcr56dlgudoohqfgqzqu7w4lo3w4ycjriny',
      checksum: '1b7cd3071d3135ff5bbc85147be1acd41b9c7814d0cc29fb716eddb98126286e',
      recordType: 'PRESCRIPTION',
      facility: 'Metro General Hospital',
      registeredBy: 'Dr. Marcus Sterling, MD'
    }
  ];

  beforeEach(async () => {
    contract = new MedTrustContract();
    ctx = createMockContext(NOW_EPOCH);
    stub = ctx.stub as unknown as MockStub;

    await contract.InitLedger(ctx);

    for (const r of RECORDS_FIXTURE) {
      await contract.RegisterRecord(
        ctx,
        r.recordId,
        r.patientId,
        r.ipfsCid,
        r.checksum,
        r.recordType,
        r.facility,
        r.registeredBy
      );
    }
  });

  test('Query GetRecord returns valid on-chain metadata for rec-001, rec-002, rec-003', async () => {
    for (const fixture of RECORDS_FIXTURE) {
      const raw = await contract.GetRecord(ctx, fixture.recordId);
      const record: MedicalRecordMetadata = JSON.parse(raw);

      expect(record.recordId).toBe(fixture.recordId);
      expect(record.patientId).toBe(fixture.patientId);
      expect(record.ipfsCid).toBe(fixture.ipfsCid);
      expect(record.checksum).toBe(fixture.checksum.toLowerCase());
      expect(record.recordType).toBe(fixture.recordType.toUpperCase());
      expect(record.facility).toBe(fixture.facility);
      expect(record.registeredBy).toBe(fixture.registeredBy);
    }
  });

  test('Query VerifyRecordChecksum verifies intact integrity for rec-001, rec-002, rec-003', async () => {
    for (const fixture of RECORDS_FIXTURE) {
      const raw = await contract.VerifyRecordChecksum(ctx, fixture.recordId, fixture.checksum);
      const res = JSON.parse(raw);

      expect(res.verified).toBe(true);
      expect(res.recordId).toBe(fixture.recordId);
      expect(res.expectedChecksum).toBe(fixture.checksum.toLowerCase());
      expect(res.calculatedChecksum).toBe(fixture.checksum.toLowerCase());
      expect(res.ipfsCid).toBe(fixture.ipfsCid);
      expect(res.status).toBe('VERIFIED_INTACT');
    }
  });

  test('Query VerifyRecordChecksum flags mismatch when hash is corrupted', async () => {
    const corruptedHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const raw = await contract.VerifyRecordChecksum(ctx, 'rec-001', corruptedHash);
    const res = JSON.parse(raw);

    expect(res.verified).toBe(false);
    expect(res.recordId).toBe('rec-001');
    expect(res.expectedChecksum).toBe(RECORDS_FIXTURE[0].checksum.toLowerCase());
    expect(res.calculatedChecksum).toBe(corruptedHash);
    expect(res.status).toBe('CHECKSUM_MISMATCH');
  });

  test('Query GetRecordsByPatient returns all 3 records for pat-984210', async () => {
    const raw = await contract.GetRecordsByPatient(ctx, PATIENT_ID);
    const records: MedicalRecordMetadata[] = JSON.parse(raw);

    expect(records.length).toBe(3);
    const recordIds = records.map((r) => r.recordId).sort();
    expect(recordIds).toEqual(['rec-001', 'rec-002', 'rec-003']);
  });
});
