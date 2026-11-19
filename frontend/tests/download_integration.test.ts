import test from 'node:test';
import assert from 'node:assert/strict';

import {
  extractFilenameFromHeader,
  formatDownloadErrorMessage,
  triggerFileDownload,
  ApiDownloadError,
  apiService,
} from '../src/services/api.ts';

test('extractFilenameFromHeader extracts standard quoted filename', () => {
  const header = 'attachment; filename="patient_mri_report.pdf"';
  const result = extractFilenameFromHeader(header, 'fallback.pdf');
  assert.equal(result, 'patient_mri_report.pdf');
});

test('extractFilenameFromHeader extracts unquoted filename', () => {
  const header = 'attachment; filename=lab_results.pdf';
  const result = extractFilenameFromHeader(header, 'fallback.pdf');
  assert.equal(result, 'lab_results.pdf');
});

test('extractFilenameFromHeader decodes RFC 5987 utf-8 encoded filename', () => {
  const header = "attachment; filename*=utf-8''cardiac%20discharge%20notes.pdf";
  const result = extractFilenameFromHeader(header, 'fallback.pdf');
  assert.equal(result, 'cardiac discharge notes.pdf');
});

test('extractFilenameFromHeader handles malformed URI components gracefully', () => {
  const header = "attachment; filename*=utf-8''invalid%XXname.pdf";
  const result = extractFilenameFromHeader(header, 'fallback.pdf');
  assert.equal(result, 'invalid%XXname.pdf');
});

test('extractFilenameFromHeader returns fallback when header is null or empty', () => {
  assert.equal(extractFilenameFromHeader(null, 'default_name.pdf'), 'default_name.pdf');
  assert.equal(extractFilenameFromHeader('', 'default_name.pdf'), 'default_name.pdf');
  assert.equal(extractFilenameFromHeader('inline', 'default_name.pdf'), 'default_name.pdf');
});

test('formatDownloadErrorMessage handles HTTP 403 authorization and consent denials', () => {
  const err = new ApiDownloadError(403, 'Clinical download denied: Doctor does not have active consent.');
  const msg = formatDownloadErrorMessage(err);
  assert.match(msg, /denied/i);
  assert.equal(msg, 'Clinical download denied: Doctor does not have active consent.');

  // Default 403 message when detail is missing
  const errNoDetail = { status: 403 };
  const msgDefault = formatDownloadErrorMessage(errNoDetail);
  assert.match(msgDefault, /access denied/i);
  assert.match(msgDefault, /consent/i);
});

test('formatDownloadErrorMessage handles HTTP 404 distinguishing legacy records from missing files', () => {
  // Legacy record
  const legacyErr = new ApiDownloadError(404, "Encryption key for record 'rec-001' not found. Legacy records operate in ledger-verification-only mode.");
  const legacyMsg = formatDownloadErrorMessage(legacyErr);
  assert.match(legacyMsg, /legacy record/i);
  assert.match(legacyMsg, /verification-only mode/i);

  // Missing attachment
  const notFoundErr = new ApiDownloadError(404, "No prescription attachment found for record 'rec-999'.");
  const notFoundMsg = formatDownloadErrorMessage(notFoundErr);
  assert.equal(notFoundMsg, "No prescription attachment found for record 'rec-999'.");

  // Missing detail fallback
  assert.match(formatDownloadErrorMessage({ status: 404 }), /not available/i);
});

test('formatDownloadErrorMessage handles HTTP 409 cryptographic integrity failure', () => {
  const err409 = new ApiDownloadError(409, 'Cryptographic integrity failure: IPFS ciphertext checksum mismatch against Fabric ledger.');
  const msg409 = formatDownloadErrorMessage(err409);
  assert.match(msg409, /integrity alert/i);
  assert.match(msg409, /checksum mismatch/i);
  assert.match(msg409, /blocked/i);

  // Missing detail fallback
  assert.match(formatDownloadErrorMessage({ status: 409 }), /checksum mismatch/i);
});

test('formatDownloadErrorMessage handles HTTP 503 service unavailability', () => {
  const err503 = new ApiDownloadError(503, 'Ledger service unavailable: unable to retrieve record metadata.');
  const msg503 = formatDownloadErrorMessage(err503);
  assert.match(msg503, /service unavailable/i);
  assert.match(msg503, /ipfs/i);
  assert.match(msg503, /fabric ledger/i);

  // Missing detail fallback
  assert.match(formatDownloadErrorMessage({ status: 503 }), /service unavailable/i);
});

test('formatDownloadErrorMessage handles HTTP 500 cryptographic decryption failure', () => {
  const err500 = new ApiDownloadError(500, 'Decryption failed: cryptographic verification error.');
  const msg500 = formatDownloadErrorMessage(err500);
  assert.match(msg500, /decryption failed/i);
  assert.match(msg500, /cryptographic/i);

  // Missing detail fallback
  assert.match(formatDownloadErrorMessage({ status: 500 }), /decryption failed/i);
});

test('formatDownloadErrorMessage gracefully handles unknown errors', () => {
  assert.equal(formatDownloadErrorMessage('simple string error'), 'simple string error');
  assert.equal(formatDownloadErrorMessage(null, 'Custom fallback'), 'Custom fallback');
  assert.equal(formatDownloadErrorMessage(new Error('Generic failure')), 'Generic failure');
});

test('apiService.downloadRecordDocument handles successful binary download', async () => {
  const originalFetch = globalThis.fetch;
  const mockContent = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // %PDF
  const mockBlob = new Blob([mockContent], { type: 'application/pdf' });

  let calledUrl = '';
  let calledHeaders: Record<string, string> = {};

  try {
    apiService.setToken('test-token-patient');
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      calledUrl = String(url);
      calledHeaders = (init?.headers as Record<string, string>) || {};
      return new Response(mockBlob, {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename="rec-100_document.pdf"',
          'Content-Length': String(mockContent.length),
        },
      });
    }) as typeof fetch;

    const result = await apiService.downloadRecordDocument('rec-100');
    assert.match(calledUrl, /\/records\/rec-100\/download$/);
    assert.equal(calledHeaders['Authorization'], 'Bearer test-token-patient');
    assert.equal(result.filename, 'rec-100_document.pdf');
    assert.equal(result.blob.size, mockBlob.size);
  } finally {
    globalThis.fetch = originalFetch;
    apiService.setToken(null);
  }
});

test('apiService.downloadRecordPrescription handles successful binary download', async () => {
  const originalFetch = globalThis.fetch;
  const mockContent = new Uint8Array([0x50, 0x4b, 0x03, 0x04]); // PK..
  const mockBlob = new Blob([mockContent], { type: 'application/pdf' });

  let calledUrl = '';

  try {
    apiService.setToken('test-token-doctor');
    globalThis.fetch = (async (url: string | URL | Request) => {
      calledUrl = String(url);
      return new Response(mockBlob, {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename="rx_metro_cardio.pdf"',
        },
      });
    }) as typeof fetch;

    const result = await apiService.downloadRecordPrescription('rec-100');
    assert.match(calledUrl, /\/records\/rec-100\/prescription\/download$/);
    assert.equal(result.filename, 'rx_metro_cardio.pdf');
    assert.equal(result.blob.size, mockBlob.size);
  } finally {
    globalThis.fetch = originalFetch;
    apiService.setToken(null);
  }
});

test('apiService.downloadRecordDocument surfaces ApiDownloadError with status and detail on 403', async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({ detail: 'Clinical download denied: Missing active consent' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    await assert.rejects(
      async () => {
        await apiService.downloadRecordDocument('rec-secret');
      },
      (err: unknown) => {
        assert(err instanceof ApiDownloadError);
        assert.equal((err as ApiDownloadError).status, 403);
        assert.equal((err as ApiDownloadError).detail, 'Clinical download denied: Missing active consent');
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('apiService.downloadRecordPrescription surfaces ApiDownloadError on 404 missing key / legacy', async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({ detail: "Encryption key for prescription in record 'rec-003' not found. Legacy records operate in ledger-verification-only mode." }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    await assert.rejects(
      async () => {
        await apiService.downloadRecordPrescription('rec-003');
      },
      (err: unknown) => {
        assert(err instanceof ApiDownloadError);
        assert.equal((err as ApiDownloadError).status, 404);
        assert.match((err as ApiDownloadError).detail, /legacy records operate in ledger-verification-only mode/i);
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('apiService.downloadRecordDocument surfaces ApiDownloadError with status and detail on 409 checksum mismatch', async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({ detail: 'Cryptographic integrity failure: IPFS ciphertext checksum mismatch against Fabric ledger.' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    await assert.rejects(
      async () => {
        await apiService.downloadRecordDocument('rec-tampered');
      },
      (err: unknown) => {
        assert(err instanceof ApiDownloadError);
        assert.equal((err as ApiDownloadError).status, 409);
        assert.match((err as ApiDownloadError).detail, /checksum mismatch/i);
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('apiService.downloadRecordDocument surfaces ApiDownloadError on 503 service unavailable', async () => {
  const originalFetch = globalThis.fetch;

  try {
    globalThis.fetch = (async () => {
      return new Response(JSON.stringify({ detail: 'Failed to retrieve record content from IPFS storage.' }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;

    await assert.rejects(
      async () => {
        await apiService.downloadRecordDocument('rec-offline');
      },
      (err: unknown) => {
        assert(err instanceof ApiDownloadError);
        assert.equal((err as ApiDownloadError).status, 503);
        assert.match((err as ApiDownloadError).detail, /ipfs storage/i);
        return true;
      }
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('triggerFileDownload creates object URL, attaches link, triggers click, and schedules cleanup', (_t, done) => {
  const origWindow = globalThis.window;
  const origDocument = globalThis.document;

  let createdUrl = '';
  let revokedUrl = '';
  let clicked = false;
  let appendedChild = false;
  let removedChild = false;

  const mockBlob = new Blob(['sample data'], { type: 'application/pdf' });

  const mockWindow = {
    URL: {
      createObjectURL: (_blob: Blob) => {
        createdUrl = 'blob:http://localhost:5173/mock-uuid-1234';
        return createdUrl;
      },
      revokeObjectURL: (url: string) => {
        revokedUrl = url;
      },
    },
  };

  const mockLink = {
    href: '',
    download: '',
    click: () => {
      clicked = true;
    },
  };

  const mockDocument = {
    body: {
      appendChild: (_el: unknown) => {
        appendedChild = true;
      },
      removeChild: (_el: unknown) => {
        removedChild = true;
      },
    },
    createElement: (tag: string) => {
      if (tag === 'a') return mockLink;
      return {};
    },
  };

  // @ts-expect-error Mocking DOM environment
  globalThis.window = mockWindow;
  // @ts-expect-error Mocking DOM environment
  globalThis.document = mockDocument;

  try {
    triggerFileDownload(mockBlob, 'verified_discharge_notes.pdf');

    assert.equal(appendedChild, true);
    assert.equal(clicked, true);
    assert.equal(removedChild, true);
    assert.equal(mockLink.download, 'verified_discharge_notes.pdf');
    assert.equal(mockLink.href, createdUrl);

    // Revocation happens asynchronously via setTimeout
    setTimeout(() => {
      try {
        assert.equal(revokedUrl, createdUrl);
        done();
      } finally {
        globalThis.window = origWindow;
        globalThis.document = origDocument;
      }
    }, 1100);
  } catch (e) {
    globalThis.window = origWindow;
    globalThis.document = origDocument;
    throw e;
  }
});
