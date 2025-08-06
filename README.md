# ID Verifier

A JavaScript library that simplifies requesting mobile IDs built on top of the new W3C Digital Credentials API. [See it in action here](https://universal-verify.github.io/id-verifier/), and consider sponsoring this project or least giving it a shoutout if you feel it's helped in any way ⭐

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
    createCredentialsRequest,
    requestCredentials,
    processCredentials,
    generateNonce,
    generateJWK,
    DocumentType,
    Claim
} from 'id-verifier';

try {
  // Generate security parameters
  const nonce = generateNonce();
  const jwk = await generateJWK();

  // Create credentials request
  const requestParams = createCredentialsRequest({
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
  const credentials = await requestCredentials(requestParams);

  // Process and verify the credentials
  const result = await processCredentials(credentials, {
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

### Functions

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

#### `createCredentialsRequest(options)`

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
const params = createCredentialsRequest({
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

#### `requestCredentials(requestParams, options)`

Requests digital credentials from the user (browser-only)

**Parameters:**
- `requestParams` (Object): Request parameters from `createCredentialsRequest`
- `options` (Object):
  - `timeout` (number): Request timeout in milliseconds (default: 300000)

**Returns:** Promise that resolves to credential data

**Example:**
```javascript
const credentials = await requestCredentials(requestParams, {
  timeout: 600000 // 10 minutes
});
```

#### `processCredentials(credentials, params)`

Processes and verifies a digital credential response. Meant for backend use

**Parameters:**
- `credentials` (Object): The credentials response from `requestCredentials`
- `params` (Object):
  - `nonce` (string): The nonce from the original request (required)
  - `jwk` (Object): The JWK used to encrypt the request (required)
  - `origin` (string): The origin of the request (required)
  - `trustLists` (Array<string>): Names of trust lists to use for determining trust (default: all available)

_Trust lists are sourced from the [trusted-issuer-registry](https://github.com/universal-verify/trusted-issuer-registry). Current values are `aamva_dts` and `uv` at the time of writing_

**Returns:** Promise that resolves to verification result

**Example:**
```javascript
const result = await processCredentials(credentials, {
  nonce,
  jwk,
  origin: window.location.origin,
  trustLists: ['universal-verify']
});
```

### Verification Result

The `processCredentials` function returns an object with the following structure:

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
          "region": "VA",
          "government_level": "state",
          "official_name": "Multipaz"
        },
        "display": {
          "name": "Multipaz IACA Test",
          "logo": "https://avatars.githubusercontent.com/u/131064301",
          "description": "Official issuer of mobile driver's licenses and proof of age credentials in Multipaz."
        },
        "signature": "MEUCIQDrmlcELKPJHKiwlb/90zNPoiweAry0tF+j/LA21wxlWAIgNIeWgJc3dijrwrjRmMjJwecxif4hMi87zD55k7DOLLM=",
        "certificate": {
          "data": "-----BEGIN CERTIFICATE-----\n...",
          "format": "pem",
          "trust_lists": ["uv"]
        }
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
  - `trusted` (Boolean): Whether this document's issuer is trusted by one of the given trust lists
  - `document` (Object): Full unencrypted document data
  - `issuer` (Object): Issuer information sourced from the [trusted-issuer-registry](https://github.com/universal-verify/trusted-issuer-registry)
- `sessionTranscript` (Object): Session transcript that was used for decryption/verification

## Browser Support

This library requires browsers that support the Digital Credentials API. Currently, this is an experimental API and may not be available in all browsers.

## How to test

### Android

- Have an android device handy or run an android emulator
- Download a wallet that allows you to create test credentials. [Here is one option](https://apps.multipaz.org)
- Go to chrome://flags in your browser
- Enable DigitalCredentials
- Go to [our demo page](https://universal-verify.github.io/id-verifier/)
- Tap on "Request Credentials"

### iOS

- Have an iPhone or simulator running iOS 26 or later
  - If using a real iphone, make sure you've added your ID to your wallet if supported
  - If your ID is not currently supported or you don't have an iphone, the simulator has test credentials preinstalled
- Go to the device's Settings -> Apps -> Safari -> Advanced -> Feature Flags
- Enabled the Digital Credentials API
- Go to [our demo page](https://universal-verify.github.io/id-verifier/)
- Tap on "Request Credentials"

_Test credentials won't present issuer information, however the demo page supports using the trusted-issuer-registry's test data. Test wallet providers are more than welcome to add their public certificates to the repo's test data. In the near future we will allow you to supply your own list of trusted credentials to the library, but until then, c'est la vie_

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request (submit an issue first please)

To help others find this repo, please consider giving us a star ⭐

## License

This project is licensed under the Mozilla Public License 2.0
