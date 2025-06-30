/**
 * Basic Usage Example
 * Demonstrates how to use the ID Verifier library for digital credential verification
 */

import { 
  createRequestParams, 
  getCredentials, 
  verifyCredentials, 
  CREDENTIAL_TYPES, 
  PROTOCOLS 
} from '../scripts/id-verifier.js';

// Example 1: Backend - Create request parameters
async function createBackendRequest() {
  console.log('=== Backend: Creating Request Parameters ===');
  
  const requestParams = createRequestParams({
    credentialTypes: [CREDENTIAL_TYPES.DRIVERS_LICENSE],
    protocol: PROTOCOLS.MDOC,
    verifierId: 'example-verifier-123',
    purpose: 'age_verification',
    requestData: {
      requiredAttributes: ['given_name', 'family_name', 'birth_date'],
      optionalAttributes: ['portrait', 'address']
    }
  });
  
  console.log('Request parameters created:', JSON.stringify(requestParams, null, 2));
  return requestParams;
}

// Example 2: Frontend - Request credentials (browser-only)
async function requestUserCredentials(requestParams) {
  console.log('\n=== Frontend: Requesting User Credentials ===');
  
  try {
    const credentialResponse = await getCredentials(requestParams, {
      timeout: 30000,
      silent: false
    });
    
    console.log('Credential received:', JSON.stringify(credentialResponse, null, 2));
    return credentialResponse;
    
  } catch (error) {
    console.error('Credential request failed:', error.message);
    // In a real app, you might want to handle different error types differently
    throw error;
  }
}

// Example 3: Backend - Verify credentials
async function verifyUserCredentials(credentialResponse) {
  console.log('\n=== Backend: Verifying Credentials ===');
  
  const verificationResult = await verifyCredentials(credentialResponse, {
    expectedProtocol: PROTOCOLS.MDOC,
    expectedTypes: [CREDENTIAL_TYPES.DRIVERS_LICENSE],
    verifierId: 'example-verifier-123',
    trustedIssuers: ['dmv.gov', 'state.gov', 'trusted-issuer.com']
  });
  
  console.log('Verification result:', JSON.stringify(verificationResult, null, 2));
  
  if (verificationResult.verified) {
    console.log('✅ Credential verified successfully!');
    console.log('📄 Available ID information:', verificationResult.idInformation);
  } else {
    console.log('❌ Verification failed:', verificationResult.error);
  }
  
  return verificationResult;
}

// Example 4: Complete workflow
async function completeWorkflow() {
  try {
    // Step 1: Backend creates request parameters
    const requestParams = await createBackendRequest();
    
    // Step 2: Frontend requests credentials (simulated)
    console.log('\nNote: This step requires a browser environment with Digital Credentials API support');
    console.log('In a real application, this would be called from the frontend');
    
    // Simulate a credential response for demonstration
    const mockCredentialResponse = {
      id: 'credential-123',
      type: 'digital-credential',
      data: {
        documents: [{
          docType: 'drivers_license',
          issuer: 'dmv.gov',
          attributes: {
            given_name: { value: 'John' },
            family_name: { value: 'Doe' },
            birth_date: { value: '1990-01-01' }
          }
        }]
      },
      protocol: 'mdoc',
      timestamp: new Date().toISOString()
    };
    
    // Step 3: Backend verifies credentials
    await verifyUserCredentials(mockCredentialResponse);
    
  } catch (error) {
    console.error('Workflow failed:', error.message);
  }
}

// Example 5: Multiple credential types
async function multipleCredentialTypes() {
  console.log('\n=== Multiple Credential Types Example ===');
  
  const requestParams = createRequestParams({
    credentialTypes: [
      CREDENTIAL_TYPES.DRIVERS_LICENSE,
      CREDENTIAL_TYPES.PASSPORT,
      CREDENTIAL_TYPES.NATIONAL_ID
    ],
    protocol: PROTOCOLS.MDOC,
    verifierId: 'multi-verifier',
    purpose: 'comprehensive_identity_verification'
  });
  
  console.log('Multi-credential request parameters:', JSON.stringify(requestParams, null, 2));
}

// Example 6: Error handling
async function demonstrateErrorHandling() {
  console.log('\n=== Error Handling Examples ===');
  
  // Invalid credential type
  try {
    createRequestParams({
      credentialTypes: ['invalid_type'],
      protocol: PROTOCOLS.MDOC
    });
  } catch (error) {
    console.log('✅ Caught invalid credential type error:', error.message);
  }
  
  // Invalid protocol
  try {
    createRequestParams({
      credentialTypes: [CREDENTIAL_TYPES.DRIVERS_LICENSE],
      protocol: 'invalid_protocol'
    });
  } catch (error) {
    console.log('✅ Caught invalid protocol error:', error.message);
  }
  
  // Invalid credential response
  try {
    await verifyCredentials({ invalid: 'response' });
  } catch (error) {
    console.log('✅ Caught invalid credential response error:', error.message);
  }
}

// Run examples
async function runExamples() {
  console.log('🚀 ID Verifier - Digital Credentials API Examples\n');
  
  await completeWorkflow();
  await multipleCredentialTypes();
  await demonstrateErrorHandling();
  
  console.log('\n✨ Examples completed!');
}

// Export functions for use in other modules
export {
  createBackendRequest,
  requestUserCredentials,
  verifyUserCredentials,
  completeWorkflow,
  multipleCredentialTypes,
  demonstrateErrorHandling,
  runExamples
};

// Run examples if this file is executed directly
if (typeof window === 'undefined' && typeof process !== 'undefined') {
  // Node.js environment
  runExamples().catch(console.error);
} 