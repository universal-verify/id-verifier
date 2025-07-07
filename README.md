# ID Verifier - Digital Credentials API Wrapper

A JavaScript library that simplifies digital ID verification using the W3C Digital Credentials API. This library provides functions for both backend and frontend usage to create credential requests, retrieve credentials from users, and verify credential responses.

## Features

- **Cross-platform**: Works in both browser and Node.js environments
- **Protocol Support**: Supports OpenID4VP and ISO mDoc protocols
- **Document Types**: Supports multiple document types including Mobile Driver's License, Photo ID, EU Personal ID, and Japan My Number Card
- **Type Safety**: Built-in validation for document types and claims
- **Security**: Includes nonce generation, timeouts, and trusted issuer verification
- **Flexible**: Configurable for different use cases and requirements

## Installation

```bash
npm install id-verifier
```

## Quick Start

### Backend: Create Request Parameters

```javascript
import { createRequestParams, DocumentType, Claim } from 'id-verifier';

// Create request parameters for a driver's license verification
const requestParams = createRequestParams({
  documentTypes: [DocumentType.MOBILE_DRIVERS_LICENSE],
  claims: [
    Claim.GIVEN_NAME,
    Claim.FAMILY_NAME,
    Claim.AGE_OVER_21
  ]
});

// Send these parameters to your frontend
```

### Frontend: Request Credentials

```javascript
import { getCredentials } from 'id-verifier';

// Request credentials from the user
try {
  const credentialResponse = await getCredentials(requestParams, {
    timeout: 300000 // 5 minutes
  });
  
  // Send the credential response to your backend for verification
  const verificationResult = await fetch('/api/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentialResponse)
  });
  
} catch (error) {
  console.error('Credential request failed:', error.message);
}
```

### Backend: Verify Credentials

```javascript
import { verifyCredentials } from 'id-verifier';

// Verify the credential response
const verificationResult = await verifyCredentials(credentialResponse, {
  trustFrameworks: ['uv']
});

if (verificationResult.verified) {
  console.log('Credential verified successfully!');
  console.log('Available claims:', verificationResult.claims);
  console.log('Trusted issuer:', verificationResult.issuer);
} else {
  console.error('Verification failed:', verificationResult.error);
}
```

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
- `FULL_NAME` - Full name
- `BIRTH_DATE` - Birth date
- `AGE` - Age
- `AGE_OVER_18` - Age over 18 verification
- `AGE_OVER_21` - Age over 21 verification
- `ADDRESS` - Address
- `CITY` - City
- `STATE` - State/Province
- `POSTAL_CODE` - Postal code
- `COUNTRY` - Country
- `NATIONALITY` - Nationality
- `GENDER` - Gender
- `PLACE_OF_BIRTH` - Place of birth
- `DOCUMENT_NUMBER` - Document number
- `ISSUING_AUTHORITY` - Issuing authority
- `ISSUE_DATE` - Issue date
- `EXPIRY_DATE` - Expiry date
- `PORTRAIT` - Portrait photo
- `SIGNATURE` - Signature

### Functions

#### `createRequestParams(options)`

Creates request parameters for digital credential verification.

**Parameters:**
- `options` (Object):
  - `documentTypes` (string|Array<string>): Type(s) of documents to request (default: `[DocumentType.MOBILE_DRIVERS_LICENSE]`)
  - `claims` (Array<string>): Array of claim fields from `Claim` to request (default: `[]`)

**Returns:** Object compatible with Digital Credentials API

**Example:**
```javascript
const params = createRequestParams({
  documentTypes: [DocumentType.MOBILE_DRIVERS_LICENSE, DocumentType.PHOTO_ID],
  claims: [
    Claim.GIVEN_NAME,
    Claim.FAMILY_NAME,
    Claim.AGE_OVER_21,
    Claim.ADDRESS
  ]
});
```

#### `getCredentials(requestParams, options)`

Requests digital credentials from the user (browser-only).

**Parameters:**
- `requestParams` (Object): Request parameters from `createRequestParams`
- `options` (Object):
  - `timeout` (number): Request timeout in milliseconds (default: 300000)

**Returns:** Promise that resolves to credential data

**Example:**
```javascript
const credential = await getCredentials(requestParams, {
  timeout: 600000 // 10 minutes
});
```

#### `verifyCredentials(credentialResponse, options)`

Verifies a digital credential response.

**Parameters:**
- `credentialResponse` (Object): The credential response from `getCredentials`
- `options` (Object):
  - `trustFrameworks` (Array<string>): List of trust frameworks to use for determining trust (default: `['uv']`)

**Returns:** Promise that resolves to verification result

**Example:**
```javascript
const result = await verifyCredentials(credentialResponse, {
  trustFrameworks: ['uv']
});
```

### Verification Result

The `verifyCredentials` function returns an object with the following structure:

**Success Response:**
```javascript
{
  "verified": true,
  "claims": {
    "given_name": "Erika",
    "family_name": "Mustermann",
    "age_over_21": true
  },
  "trusted": true,
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
    "trust_frameworks": ["uv"],
    "certificates": [
      {
        "certificate": "-----BEGIN CERTIFICATE-----\n...",
        "certificate_format": "pem"
      }
    ],
    "expires_at": 4286822400,
    "signature": "MEQCIAlQbTxkJp80r/p5zrY8DaNDCtpwmycDLESdDpigR1GoAiBpKT17XHvEvmncdMtfTh5atPPnLr0vVJvAuhzCnVCJzA=="
  }
}
```

**Error Response:**
```javascript
{
  "verified": false,
  "error": "Verification failed: Invalid credential response",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Complete Example

Here's a complete example showing how to use the library:

```javascript
import { createRequestParams, getCredentials, verifyCredentials, DocumentType, Claim } from 'id-verifier';

// Backend: Create request parameters
const requestParams = createRequestParams({
  documentTypes: [DocumentType.MOBILE_DRIVERS_LICENSE],
  claims: [
    Claim.GIVEN_NAME,
    Claim.FAMILY_NAME,
    Claim.AGE_OVER_21,
    Claim.ADDRESS
  ]
});

// Frontend: Request credentials
try {
  const credential = await getCredentials(requestParams);
  console.log('Credential received:', credential);
  
  // Send to backend for verification
  const verificationResult = await verifyCredentials(credential, {
    trustFrameworks: ['uv']
  });
  
  if (verificationResult.verified) {
    console.log('Verification successful!');
    console.log('Claims:', verificationResult.claims);
    console.log('Issuer:', verificationResult.issuer);
  } else {
    console.error('Verification failed:', verificationResult.error);
  }
  
} catch (error) {
  console.error('Error:', error.message);
}
```

## Error Handling

The library provides comprehensive error handling:

```javascript
try {
  const credential = await getCredentials(requestParams);
} catch (error) {
  switch (error.message) {
    case 'Digital Credentials API not supported in this browser':
      // Handle unsupported browser
      break;
    case 'User denied credential request':
      // Handle user rejection
      break;
    case 'Credential request timed out':
      // Handle timeout
      break;
    case 'No credential was provided by the user':
      // Handle no credential provided
      break;
    default:
      // Handle other errors
  }
}
```

## Browser Support

This library requires browsers that support the Digital Credentials API. Currently, this is an experimental API and may not be available in all browsers.

## Security Considerations

- Always validate credential responses on the backend
- Use trusted issuer lists to prevent spoofing
- Implement proper timeout handling
- Store sensitive credential data securely
- Follow privacy best practices for handling personal information
- Use HTTPS in production environments

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MPL-2.0 License - see the LICENSE file for details.
