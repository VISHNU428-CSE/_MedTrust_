MedTrust — Design System and Product UI Specification

1. Product Vision

MedTrust is a privacy-first medical record sharing and consent management platform using React, FastAPI, IPFS, encryption, and Hyperledger Fabric.

Create an original, premium healthcare SaaS experience suitable for a final-year engineering project demonstration and viva. Use the supplied inspiration video for quality and layout inspiration, not as a template to copy.

2. Design Principles

- Professional, trustworthy, modern, and accessible.
- Real API data instead of hardcoded counts or fabricated transactions.
- Clear patient and doctor workflows.
- Responsive desktop and mobile layouts.
- Reusable components and consistent spacing.
- Helpful loading, empty, success, warning, and error states.
- Never show success when an operation failed or timed out.

3. Color Palette

- Primary navy: "#14263D"
- Teal accent: "#147D78"
- Page background: "#F5F7FA"
- Card background: "#FFFFFF"
- Main text: "#182230"
- Secondary text: "#5B6675"
- Success: "#237A52"
- Warning: "#9A6700"
- Error: "#B42318"
- Border: "#E1E7EF"

Use restrained shadows, consistent corner radii, readable typography, and accessible contrast. Avoid excessive gradients and unnecessary animations.

4. Shared Components

Create or refine reusable components for:

- Application navigation and page headers.
- Buttons, forms, and accessible dialogs.
- Medical record cards and metadata rows.
- Consent and verification status badges.
- Loading indicators and skeletons.
- Empty states and useful error messages.
- Audit events and system-health indicators.
- Record verification results.

Reuse existing dependencies wherever practical.

5. Public Landing Page

Include:

- Original MedTrust branding and a clear value proposition.
- An explanation of secure medical record sharing.
- A visual explanation of patient consent.
- Architecture overview: React, FastAPI, encryption, IPFS, and Hyperledger Fabric.
- Security and privacy features.
- Clear navigation to the demo or login.

Do not claim regulatory compliance or production readiness without evidence.

6. Patient Dashboard

Show:

- Medical records and upload status.
- Upload action with progress and actual API result.
- Pending doctor access requests.
- Active permissions, purpose, scope, and expiration.
- Grant, reject, and revoke actions with confirmation.
- Record verification and audit history.

All counts and statuses must come from real API responses.

7. Doctor Dashboard

Show:

- Authorized patient records only.
- Access request status and purpose.
- Allowed record types and expiration.
- Clear explanations when access is pending, expired, revoked, or outside the granted scope.

The backend must enforce authorization on every protected retrieval.

8. Record Detail and Verify Ledger

Display:

- Record title and type.
- Actual IPFS CID.
- Encryption algorithm and safe key fingerprint metadata.
- Expected ledger checksum and computed checksum when available.
- Real verification status and diagnostic details.

Distinguish "VERIFIED", "CHECKSUM_MISMATCH", "IPFS_UNAVAILABLE", "LEDGER_UNAVAILABLE", and unexpected errors as appropriate to the actual API contract.

Never label a record verified if the payload was not retrieved and checked. A successful health check alone does not prove a record's integrity.

9. Audit and System Health

Provide:

- Audit events from the backend.
- Real audit-chain integrity results.
- Separate status for FastAPI, IPFS, Fabric Gateway, and ledger queries.
- Last checked time and clear recovery guidance.

Do not fabricate transaction IDs or display a connected status without evidence.

10. Security and Privacy

- Use synthetic patient data only.
- Never store passwords, access tokens, encryption keys, or confidential medical file contents on the blockchain.
- Do not expose secrets or medical content in logs.
- Enforce consent, record scope, and revocation in the backend.
- Explain that revocation blocks future application access but cannot erase copies previously downloaded by an authorized recipient.
- Treat IPFS availability and ledger integrity as separate checks.

11. Engineering Constraints

- Audit the existing repository before editing.
- Preserve working features and existing agent changes.
- Keep the MedTrust frontend on port "5174" and backend on port "8001" unless a verified reason requires a change.
- Never stop, rebuild, or reconfigure the separate ReactFastAPI-RedisCache containers.
- Prefer small, reviewable changes and existing dependencies.
- Run relevant lint, build, backend, and integration tests.
- Report actual command outputs and unresolved blockers.

12. Definition of Done

Demonstrate in the browser:

1. Patient login and record listing.
2. Synthetic file upload with an actual IPFS CID and checksum.
3. Doctor access request and patient consent decision.
4. Authorized retrieval and denial after revocation.
5. Verify Ledger showing the actual result.
6. Audit integrity and accurate system health.

Update setup instructions, architecture documentation, and a concise viva demonstration script.

A successful build alone is not proof of a working integration. Do not declare completion until the critical workflows have been demonstrated successfully.