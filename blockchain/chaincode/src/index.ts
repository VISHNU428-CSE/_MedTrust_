import { ConsentContract } from './contracts/ConsentContract';
import { MedicalRecordContract } from './contracts/MedicalRecordContract';
import { AuditTrailContract } from './contracts/AuditTrailContract';
import { MedTrustContract } from './contracts/MedTrustContract';

export { ConsentContract } from './contracts/ConsentContract';
export { MedicalRecordContract } from './contracts/MedicalRecordContract';
export { AuditTrailContract } from './contracts/AuditTrailContract';
export { MedTrustContract } from './contracts/MedTrustContract';

export const contracts: any[] = [
  MedTrustContract,
  ConsentContract,
  MedicalRecordContract,
  AuditTrailContract
];
