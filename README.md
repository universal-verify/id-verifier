# ID Verifier - Digital Credentials API Wrapper

A JavaScript library that simplifies digital ID verification using the W3C Digital Credentials API. This library provides functions for both backend and frontend usage to create credential requests, retrieve credentials from users, and verify credential responses.

## Features

- **Cross-platform**: Works in both browser and Node.js environments
- **Protocol Support**: Supports mDoc, W3C Verifiable Credentials, and ISO 18013-5 protocols
- **Type Safety**: Built-in validation for credential types and protocols
- **Security**: Includes nonce generation and timeout handling
- **Flexible**: Configurable for different use cases and requirements

## Installation

```bash
npm install id-verifier
```

## Quick Start

### Backend: Create Request Parameters

```javascript
import { createRequestParams, CREDENTIAL_TYPES, PROTOCOLS } from 'id-verifier';

// Create request parameters for a driver's license verification
const requestParams = createRequestParams({
  credentialTypes: [CREDENTIAL_TYPES.DRIVERS_LICENSE],
  protocol: PROTOCOLS.MDOC,
  verifierId: 'your-verifier-id',
  purpose: 'age_verification',
  requestData: {
    // Additional data specific to your use case
    requiredAttributes: ['given_name', 'family_name', 'birth_date']
  }
});

// Send these parameters to your frontend
```

### Frontend: Request Credentials

```javascript
import { getCredentials } from 'id-verifier';

// Request credentials from the user
try {
  const credentialResponse = await getCredentials(requestParams, {
    timeout: 30000, // 30 seconds
    silent: false   // Show user prompts
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
import { verifyCredentials, PROTOCOLS, CREDENTIAL_TYPES } from 'id-verifier';

// Verify the credential response
const verificationResult = await verifyCredentials(credentialResponse, {
  expectedProtocol: PROTOCOLS.MDOC,
  expectedTypes: [CREDENTIAL_TYPES.DRIVERS_LICENSE],
  verifierId: 'your-verifier-id',
  trustedIssuers: ['trusted-issuer-1', 'trusted-issuer-2']
});

if (verificationResult.verified) {
  console.log('Credential verified successfully!');
  console.log('Available ID information:', verificationResult.idInformation);
} else {
  console.error('Verification failed:', verificationResult.error);
}
```

## API Reference

### Constants

#### `CREDENTIAL_TYPES`
Supported credential types:
- `DRIVERS_LICENSE` - Driver's license
- `PASSPORT` - Passport
- `NATIONAL_ID` - National ID card
- `GOVERNMENT_ID` - Government-issued ID
- `EMPLOYMENT_VERIFICATION` - Employment verification
- `EDUCATION_VERIFICATION` - Education verification

#### `PROTOCOLS`
Supported protocols:
- `MDOC` - mDoc (ISO 18013-5)
- `W3C_VC` - W3C Verifiable Credentials
- `ISO_18013_5` - ISO 18013-5 standard

### Functions

#### `createRequestParams(options)`

Creates request parameters for digital credential verification.

**Parameters:**
- `options` (Object):
  - `credentialTypes` (string|Array<string>): Type(s) of credentials to request
  - `protocol` (string): Protocol to use for credential exchange
  - `requestData` (Object): Additional data for the credential request
  - `verifierId` (string): Unique identifier for the verifier
  - `purpose` (string): Purpose of the credential request

**Returns:** Object compatible with Digital Credentials API

**Example:**
```javascript
const params = createRequestParams({
  credentialTypes: [CREDENTIAL_TYPES.DRIVERS_LICENSE, CREDENTIAL_TYPES.PASSPORT],
  protocol: PROTOCOLS.MDOC,
  verifierId: 'my-app-verifier',
  purpose: 'identity_verification'
});
```

#### `getCredentials(requestParams, options)`

Requests digital credentials from the user (browser-only).

**Parameters:**
- `requestParams` (Object): Request parameters from `createRequestParams`
- `options` (Object):
  - `silent` (boolean): Whether to suppress user prompts (default: false)
  - `timeout` (number): Request timeout in milliseconds (default: 30000)

**Returns:** Promise that resolves to credential data

**Example:**
```javascript
const credential = await getCredentials(requestParams, {
  timeout: 60000,
  silent: false
});
```

#### `verifyCredentials(credentialResponse, options)`

Verifies a digital credential response.

**Parameters:**
- `credentialResponse` (Object): The credential response from `getCredentials`
- `options` (Object):
  - `expectedProtocol` (string): Expected protocol for verification
  - `expectedTypes` (Array<string>): Expected credential types
  - `verifierId` (string): Verifier ID for validation
  - `trustedIssuers` (Array<string>): List of trusted issuer identifiers

**Returns:** Promise that resolves to verification result

**Example:**
```javascript
const result = await verifyCredentials(credentialResponse, {
  expectedProtocol: PROTOCOLS.MDOC,
  expectedTypes: [CREDENTIAL_TYPES.DRIVERS_LICENSE],
  trustedIssuers: ['dmv.gov', 'state.gov']
});
```

## Response Formats

### Credential Response
```javascript
{
  id: "credential-id",
  type: "digital-credential",
  data: { /* credential data */ },
  protocol: "mdoc",
  timestamp: "2024-01-01T00:00:00.000Z"
}
```

### Verification Result
```javascript
{
  verified: true,
  protocol: "mdoc",
  credentialId: "credential-id",
  timestamp: "2024-01-01T00:00:00.000Z",
  verificationDetails: {
    protocol: "mdoc",
    documentsVerified: 1,
    verificationResults: [/* ... */]
  },
  idInformation: {
    protocol: "mdoc",
    documents: [/* ... */],
    personalInfo: { /* ... */ },
    extractedAt: "2024-01-01T00:00:00.000Z"
  }
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MPL-2.0 License - see the LICENSE file for details.
