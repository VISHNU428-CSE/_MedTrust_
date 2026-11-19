import * as crypto from 'crypto';
import { AuditLogEntry } from '../models/types';

export const GENESIS_BLOCK_HASH = 'GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000';

// Regex to detect SSN-like patterns
const SSN_PATTERN = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/;

/**
 * Computes a SHA-256 hexadecimal hash string.
 */
export function sha256Hex(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex').toLowerCase();
}

/**
 * Serializes an object with recursively sorted keys to ensure deterministic JSON representation.
 */
export function canonicalJsonStringify(obj: any): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map((item) => canonicalJsonStringify(item)).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj).sort();
  const entries: string[] = [];
  for (const key of sortedKeys) {
    if (obj[key] !== undefined) {
      entries.push(`${JSON.stringify(key)}:${canonicalJsonStringify(obj[key])}`);
    }
  }
  return '{' + entries.join(',') + '}';
}

/**
 * Computes the cryptographic hash for an audit log entry.
 * Note: 'entryHash' field is excluded from calculation.
 */
export function computeAuditEntryHash(entry: Omit<AuditLogEntry, 'entryHash'>): string {
  const payloadToHash: Record<string, any> = {
    docType: entry.docType,
    seq: entry.seq,
    timestamp: entry.timestamp,
    eventType: entry.eventType,
    actorId: entry.actorId,
    actorRole: entry.actorRole,
    targetPatientId: entry.targetPatientId,
    recordId: entry.recordId ?? null,
    consentId: entry.consentId ?? null,
    status: entry.status,
    detail: entry.detail,
    prevHash: entry.prevHash
  };
  const canonicalString = canonicalJsonStringify(payloadToHash);
  return sha256Hex(canonicalString);
}

/**
 * Enforces Zero PHI and compliance checks on input values.
 * Throws an error if sensitive PHI patterns or private credentials are found.
 */
export function assertZeroPHI(data: any, fieldDescription: string = 'payload'): void {
  const serialized = typeof data === 'string' ? data : JSON.stringify(data);

  if (SSN_PATTERN.test(serialized)) {
    throw new Error(`COMPLIANCE VIOLATION in ${fieldDescription}: Prohibited SSN pattern detected!`);
  }

  const forbiddenTerms = [
    '-----BEGIN RSA PRIVATE KEY-----',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN EC PRIVATE KEY-----',
    '"password":',
    '"secret":'
  ];

  for (const term of forbiddenTerms) {
    if (serialized.includes(term)) {
      throw new Error(`SECURITY VIOLATION in ${fieldDescription}: Secret/key material detected!`);
    }
  }
}
