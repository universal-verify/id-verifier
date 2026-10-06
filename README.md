# ID Verifier

A JavaScript library that simplifies requesting and verifying mobile IDs. [See it in action here](https://universal-verify.github.io/id-verifier/), and consider sponsoring this project or at least giving it a shoutout if you feel it's helped in any way ⭐

## Features

- **Cross-platform**: Works in both browser and Node.js environments
- **Protocol Support**: Supports OpenID4VP and ISO mDoc protocols
- **Document Types**: Supports multiple document types including Mobile Driver's License, Photo ID, EU Personal ID, and Japan My Number Card
- **Security**: Includes nonce generation, timeouts, and trusted issuer verification

## Installation

```bash
npm install id-verifier
```

## Quick Start

```javascript
import {
    Verifier,
    generateNonce,
    generateJWK,
    DocumentType,
    Claim
} from 'id-verifier';

try {
  const verifier = new Verifier();

  // Generate security parameters
  const nonce = generateNonce();
  const jwk = await generateJWK();

  // Create credentials request
  const requestParams = verifier.createWebCredentialsRequest({
    documentTypes: [DocumentType.MOBILE_DRIVERS_LICENSE],
    claims: [
      Claim.GIVEN_NAME,
      Claim.FAMILY_NAME,
      Claim.AGE_OVER_21
    ],
    nonce,
    jwk
  });

  // Request credentials
  const credentials = await verifier.requestCredentials(requestParams);

  // Process and verify the credentials
  const result = await verifier.processCredentials(credentials, {
    nonce,
    jwk,
    origin: window.location.origin
  });

  console.log('Credentials processed successfully!');
  console.log('Available claims:', result.claims);
  console.log('Trusted:', result.trusted);
  console.log('Valid:', result.valid);
  
} catch (error) {
  console.error('Credential request failed:', error.message);
}
```

While this example does run on the frontend, it is __strongly__ encouraged to create the credentials request and process the credentials response on your backend. The generated security nonce and jwk should stay on your backend

## API Reference

### Constants

#### `DocumentType`

Supported document types:

- `MOBILE_DRIVERS_LICENSE` - Mobile Driver's License (ISO 18013-5 mDL)
- `PHOTO_ID` - Photo ID (ISO 23220)
- `EU_PERSONAL_ID` - EU Personal ID (European Digital Identity)
- `JAPAN_MY_NUMBER_CARD` - Japan My Number Card

#### `Claim`

Supported claim fields that can be requested:

- `GIVEN_NAME` - Given name
- `FAMILY_NAME` - Family name
- `BIRTH_DATE` - Birth date
- `BIRTH_YEAR` - Birth year
- `AGE` - Age
- `AGE_OVER_18` - Age over 18 verification
- `AGE_OVER_21` - Age over 21 verification
- `SEX` - Sex/Gender
- `HEIGHT` - Height
- `WEIGHT` - Weight
- `EYE_COLOR` - Eye color
- `HAIR_COLOR` - Hair color
- `ADDRESS` - Address
- `CITY` - City
- `STATE` - State/Province
- `POSTAL_CODE` - Postal code
- `COUNTRY` - Country
- `NATIONALITY` - Nationality
- `PLACE_OF_BIRTH` - Place of birth
- `DOCUMENT_NUMBER` - Document number
- `ISSUING_AUTHORITY` - Issuing authority
- `ISSUING_COUNTRY` - Issuing country
- `ISSUING_JURISDICTION` - Issuing jurisdiction
- `ISSUE_DATE` - Issue date
- `EXPIRY_DATE` - Expiry date
- `DRIVING_PRIVILEGES` - Driving privileges
- `PORTRAIT` - Portrait photo
- `SIGNATURE` - Signature

#### `TrustList`

Supported trust lists that can be used in `trustLists`:

- `UV` - Issuers trusted by Universal Verify
- `AAMVA_DTS` - Issuers trusted by the American Association of Motor Vehicle Administrators

#### `RevocationCheckMode`

Controls document signer certificate revocation checks through CRLs:

- `SKIP` - Skip revocation checks (default)
- `BEST_EFFORT` - Reject confirmed revocation; allow undetermined status
- `REQUIRED` - Reject confirmed revocation and undetermined status

#### `InvalidReason`

Failure codes for `processedDocuments[].invalidReasons`, used when a document fails cryptographic or data-integrity verification.

- `MSO_NOT_YET_VALID` - MSO is not yet valid
- `MSO_EXPIRED` - MSO is expired
- `ISSUER_AUTH_SIGNATURE_INVALID` - IssuerAuth signature verification failed
- `DOCUMENT_SIGNER_CERTIFICATE_MISSING` - Document signer certificate is missing from IssuerAuth x5chain
- `DEVICE_AUTH_FAILED` - Failed to verify device authentication
- `CLAIM_DIGEST_MISMATCH` - Claim digest does not match IssuerAuth value digest

#### `UntrustedReason`

Trust failure codes from `trusted-issuer-registry`, used in `processedDocuments[].untrustedReasons` and `processedDocuments[].issuer.certificates[].untrustedReasons`.

- `CERTIFICATE_MISSING` - Document signer certificate is required to determine issuer trust
- `CERTIFICATE_AKI_MISSING` - Document signer certificate does not contain an Authority Key Identifier
- `CERTIFICATE_NOT_YET_VALID` - Document signer certificate is not yet valid
- `CERTIFICATE_EXPIRED` - Document signer certificate is expired
- `CERTIFICATE_REVOKED` - Document signer certificate has been revoked by CRL
- `REVOCATION_STATUS_UNDETERMINED` - Unable to determine document signer certificate revocation status
- `ISSUER_FETCH_FAILED` - Unable to retrieve issuer from trusted issuer registry
- `ISSUER_CERTIFICATE_NOT_FOUND` - No trusted issuer certificate found to validate the document signer certificate
- `CERTIFICATE_SIGNATURE_VERIFICATION_FAILED` - Document signer certificate signature could not be verified with the issuer certificate
- `ISSUER_CERTIFICATE_NOT_YET_VALID` - Issuer certificate is not yet valid
- `ISSUER_CERTIFICATE_EXPIRED` - Issuer certificate is expired
- `ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS` - Issuer certificate is not trusted by the requested trust lists
- `ISSUER_MISSING_REQUIRED_TRUST_SCOPE` - Issuer is not authorized for government-issued identity documents

### Classes

#### `Verifier`

Creates an ID verifier with optional verification configuration.

**Constructor options:**

- `trustLists` (Array<string>): Registry trust lists to use for determining trust (default: `TrustList.UV` and `TrustList.AAMVA_DTS`). An empty array skips registry lookups and only looks at user provided `trustedIssuerCertificates`
- `trustedIssuerRegistry` (Object): Issuer certificate, revocation, and network configuration
    - `trustedIssuerCertificates` (Array<string|Object>): PEM-encoded X.509 issuer certificates trusted directly by the verifier for government-issued identity documents. Use this when you want to trust issuers not listed in the [trusted-issuer-registry](https://github.com/universal-verify/trusted-issuer-registry). Entries can also be objects with a `data` PEM string and optional `format`, `entity_type`, `entity_metadata`, and `display` fields, as described in the [registry constructor documentation](https://github.com/universal-verify/trusted-issuer-registry#new-registryoptions--).
    - `revocationCheckMode` (string): CRL checking mode from `RevocationCheckMode` (default: `RevocationCheckMode.SKIP`)
    - `timeout` (number): Timeout in milliseconds for each issuer, deprecation, or CRL request, including reading its response body (default: 10000)
    - `cacheEnabled` (boolean): Whether to cache issuer, deprecation, and CRL responses in memory per verifier (default: true)
    - `cacheTTL` (number): Cache lifetime in milliseconds (default: 86400000)

Registry trust lists are sourced from the [trusted-issuer-registry](https://github.com/universal-verify/trusted-issuer-registry). Current values are `aamva_dts` and `uv` at the time of writing.

Certificates passed through `trustedIssuerRegistry.trustedIssuerCertificates` will not be filtered out by `trustLists`. Their returned certificate metadata uses `trust_lists: ['user_provided']`.

Issuer trust always requires the `government_issued_id` scope. This scope is automatically added to user-provided certificates, preserving any existing scopes.

**Example:**
```javascript
import { Verifier, TrustList, RevocationCheckMode } from 'id-verifier';

const verifier = new Verifier({
  trustLists: [TrustList.UV],
  trustedIssuerRegistry: {
    trustedIssuerCertificates: [
      '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
      // or pass in issuer objects
      {
        data: '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
        entity_type: 'government',
        entity_metadata: { country: 'CA', region: 'QC' },
        display: { name: 'Québec SAAQ' }
      }
    ],
    revocationCheckMode: RevocationCheckMode.BEST_EFFORT,
    timeout: 10000,
    cacheEnabled: true,
    cacheTTL: 86400000
  }
});
```

### Utilities and Methods

#### `generateNonce()`

Generates a cryptographically secure nonce for request security. Meant for backend use

**Returns:** String - Hex string with 128 bits of entropy

**Example:**
```javascript
const nonce = generateNonce();
```

#### `generateJWK()`

Generates a JSON Web Key using the P-256 curve for encryption. Meant for backend use

**Returns:** Promise<Object> - Promise that resolves to the JWK

**Example:**
```javascript
const jwk = await generateJWK();
```

#### `verifier.createWebCredentialsRequest(options)`

Creates request parameters for digital credential verification. Meant for backend use

**Parameters:**
- `options` (Object):
  - `documentTypes` (Array<string>): Type(s) of documents to request (default: `[DocumentType.MOBILE_DRIVERS_LICENSE]`)
  - `claims` (Array<string>): Array of claim fields from `Claim` to request (default: `[]`)
  - `nonce` (string): Security nonce (required)
  - `jwk` (Object): JSON Web Key for encryption (required)

**Returns:** Object compatible with Digital Credentials API

**Example:**
```javascript
const params = verifier.createWebCredentialsRequest({
  documentTypes: [DocumentType.MOBILE_DRIVERS_LICENSE, DocumentType.PHOTO_ID],
  claims: [
    Claim.GIVEN_NAME,
    Claim.FAMILY_NAME,
    Claim.AGE_OVER_21,
    Claim.ADDRESS
  ],
  nonce: nonce,
  jwk: jwk
});
```

#### `verifier.requestCredentials(requestParams, options)`

Requests digital credentials from the user (browser-only)

**Parameters:**
- `requestParams` (Object): Request parameters from `verifier.createWebCredentialsRequest`
- `options` (Object):
  - `timeout` (number): Request timeout in milliseconds (default: 300000)

**Returns:** Promise that resolves to credential data

**Example:**
```javascript
const credentials = await verifier.requestCredentials(requestParams, {
  timeout: 600000 // 10 minutes
});
```

#### `verifier.processCredentials(credentials, params)`

Processes and verifies a digital credential response. Meant for backend use

**Parameters:**
- `credentials` (Object): The credentials response from `verifier.requestCredentials`
- `params` (Object):
  - `nonce` (string): The nonce from the original request (required)
  - `jwk` (Object): The JWK used to encrypt the request (required)
  - `origin` (string): The origin of the request (required)

**Returns:** Promise that resolves to verification result

**Example:**
```javascript
const result = await verifier.processCredentials(credentials, {
  nonce,
  jwk,
  origin: window.location.origin
});
```

### Verification Result

The `verifier.processCredentials` function returns an object with the following structure:

**Success Response:**
```javascript
{
  "claims": {
    "given_name": "Erika",
    "family_name": "Mustermann",
    "age_over_21": true
  },
  "valid": true,
  "trusted": true,
  "processedDocuments": [
    {
      "claims": {
        "given_name": "Erika",
        "family_name": "Mustermann",
        "age_over_21": true
      },
      "valid": true,
      "trusted": true,
      "document": "...", // Full document data
      "issuer": {
        "issuer_id": "x509_aki:q2Ub4FbCkFPx3X9s5Ie-aN5gyfU",
        "entity_type": "government",
        "entity_metadata": {
          "country": "US",
          "region": "VA"
        },
        "display": {
          "name": "Multipaz IACA Test",
          "logo": "https://avatars.githubusercontent.com/u/131064301",
          "description": "Official issuer of mobile driver's licenses and proof of age credentials in Multipaz."
        },
        "trust_scopes": ["government_issued_id"],
        "certificates": [
          {
            "data": "-----BEGIN CERTIFICATE-----\n...",
            "format": "pem",
            "trust_lists": ["uv"],
            "trusted": true,
            "revocationStatus": "not_checked"
          }
        ]
      }
    }
  ],
  "sessionTranscript": "..." // Session transcript data
}
```

**Response Fields:**

- `claims` (Object): Combined claims from all processed documents
- `valid` (Boolean): Whether all documents are valid
- `trusted` (Boolean): Whether all documents are from trusted issuers
- `processedDocuments` (Array): Array of individual processed documents
  - `claims` (Object): Claims extracted from this specific document
  - `valid` (Boolean): Whether this document is valid
  - `trusted` (Boolean): Whether the document signer and at least one issuer certificate pass the requested trust checks
  - `invalidReasons` (Array<string>): Reasons this document is invalid, present only when `valid` is false
  - `untrustedReasons` (Array<string>): Reasons this document is untrusted, present only when `trusted` is false
  - `document` (Object): Full unencrypted document data
  - `issuer` (Object): Issuer metadata merged from user-provided certificates and the [trusted-issuer-registry](https://github.com/universal-verify/trusted-issuer-registry), `null` when no issuer is found
    - `trust_scopes` (Array<string>): Supported issuer scopes
    - `certificates` (Array<Object>): All issuer certificates, each with `data`, `format`, `trust_lists`, `trusted`, and `revocationStatus` (`not_checked`, `not_revoked`, or `revoked`). Untrusted certificates also include `untrustedReasons`
- `sessionTranscript` (Object): Session transcript that was used for decryption/verification

## Browser Support

This library requires browsers that support the Digital Credentials API. Currently, this is an experimental API and may not be available in all browsers.

## How to test

### Android

- Have an android device handy or run an android emulator
  - If your ID is not currently supported in Google Wallet or you're using the emulator, download a wallet that allows you to create test credentials. [Here is one option](https://apps.multipaz.org)
- Go to [our demo page](https://universal-verify.github.io/id-verifier/)
- Tap on "Request Credentials"

### iOS

- Have an iPhone or simulator running iOS 26 or later
  - If using a real iphone, make sure you've added your ID to your Apple Wallet if supported
  - If your ID is not currently supported in Apple Wallet or you don't have an iphone, the simulator has test credentials preinstalled
- Go to [our demo page](https://universal-verify.github.io/id-verifier/)
- Tap on "Request Credentials"

Test credentials may use issuer certificates that are not in the trusted issuer registry. The demo page lets you paste PEM-encoded issuer certificates so you can trust those issuers directly while testing.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request (submit an issue first please)

To help others find this repo, please consider giving us a star ⭐

## License

This project is licensed under the Mozilla Public License 2.0
