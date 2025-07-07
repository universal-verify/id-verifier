import { DocumentType, Protocol, CredentialFormat, ProtocolFormats, SupportedClaim } from './constants.js';
import OpenID4VPProtocolHelper from './OpenID4VPProtocolHelper.js';

/**
 * Digital Credentials API Wrapper
 * A library to simplify digital ID verification using the W3C Digital Credentials API
 */

/**
 * Creates request parameters for digital credential verification
 * Used by backend services to generate credential request options
 * 
 * @param {Object} options - Configuration options
 * @param {string|Array<string>} options.documentTypes - Type(s) of documents to request
 * @param {Array<string>} options.claims - Array of claim fields from SupportedClaim to request
 * @returns {Object} Request parameters compatible with Digital Credentials API
 */
export const createRequestParams = (options = {}) => {
    const {
        documentTypes = [DocumentType.MOBILE_DRIVERS_LICENSE],
        claims = []
    } = options;

    // Normalize credential types to array
    const types = Array.isArray(documentTypes) ? documentTypes : [documentTypes];

    // Validate credential types
    const validTypes = Object.values(DocumentType);
    const invalidTypes = types.filter(type => !validTypes.includes(type));
    if (invalidTypes.length > 0) {
        throw new Error(`Invalid document types: ${invalidTypes.join(', ')}`);
    }

    // Validate claims
    const validClaims = Object.values(SupportedClaim);
    const invalidClaims = claims.filter(claim => !validClaims.includes(claim));
    if (invalidClaims.length > 0) {
        throw new Error(`Invalid claims: ${invalidClaims.join(', ')}`);
    }

    // Create requests for both protocols
    const requests = [];

    for (const protocol of Object.values(Protocol)) {
        let credentials = [];
        if(protocol === Protocol.OPENID4VP) {
            credentials = OpenID4VPProtocolHelper.createQueryCredentials(types, claims);
        }
        if (credentials.length > 0) {
            requests.push({
                protocol,
                data: {
                    dcql_query: {
                        credentials
                    },
                    nonce: generateNonce(),
                    response_mode: "dc_api",
                    response_type: "vp_token",
                }
            });
        }
    }

    // Return the Digital Credentials API compatible structure
    return {
        digital: {
            requests: requests
        }
    };
};

/**
 * Requests digital credentials from the user
 * Used by frontend applications to initiate credential presentation
 * 
 * @param {Object} requestParams - Request parameters from createRequestParams
 * @param {Object} options - Additional options for the request
 * @param {number} options.timeout - Request timeout in milliseconds (default: 300000)
 * @returns {Promise<Object>} Promise that resolves to credential data or rejects with error
 */
export const getCredentials = async (requestParams, options = {}) => {
    const { timeout = 300000 } = options;

    // Validate that we're in a browser environment
    if (typeof window === 'undefined') {
        throw new Error('getCredentials can only be called in a browser environment');
    }

    // Validate that the Digital Credentials API is available
    if (!navigator.credentials) {
        throw new Error('Digital Credentials API not supported in this browser');
    }

    try {
        // Create the credential request options following the official spec
        const credentialRequestOptions = {
            ...requestParams,
            mediation: "required",
            signal: AbortSignal.timeout(timeout)
        };

        // Request the credential
        const credential = await navigator.credentials.get(credentialRequestOptions);

        console.log('credential', credential);

        if (!credential) {
            throw new Error('No credential was provided by the user');
        }

        // Return the credential data
        return {
            id: credential.id,
            type: credential.type,
            data: credential.data,
            protocol: credential.protocol,
            timestamp: new Date().toISOString()
        };

    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('Credential request timed out');
        }
        if (error.name === 'NotAllowedError') {
            throw new Error('User denied credential request');
        }
        if (error.name === 'NotSupportedError') {
            throw new Error('Credential type not supported');
        }
        throw error;
    }
};

/**
 * Verifies a digital credential response
 * Used by backend services to validate and extract information from credential responses
 * 
 * @param {Object} credentialResponse - The credential response from getCredentials
 * @param {Object} options - Verification options
 * @param {string} options.expectedProtocol - Expected protocol for verification
 * @param {Array<string>} options.expectedTypes - Expected credential types
 * @param {string} options.verifierId - Verifier ID for validation
 * @param {Object} options.trustedIssuers - List of trusted issuer identifiers
 * @returns {Promise<Object>} Promise that resolves to verified credential information
 */
export const verifyCredentials = async (credentialResponse, options = {}) => {
    const {
        expectedTypes = [],
        verifierId,
        trustedIssuers = []
    } = options;

    try {
        // Validate input
        if (!credentialResponse || typeof credentialResponse !== 'object') {
            throw new Error('Invalid credential response');
        }

        if (!credentialResponse.data) {
            throw new Error('Credential response missing data');
        }

        // Extract and validate credential data
        const credentialData = credentialResponse.data;

        let verificationResult;
        if(credentialResponse.protocol === Protocol.OPENID4VP) {
            verificationResult = await OpenID4VPProtocolHelper.verify(credentialData, options);
        } else {
            throw new Error(`Unsupported protocol: ${credentialResponse.protocol}`);
        }

        return {
            verified: true,
            claims: verificationResult.claims,
            trusted: verificationResult.trusted,
            trustedIssuer: verificationResult.trustedIssuer,
        };

    } catch (error) {
        console.error('Error verifying credentials', error);
        return {
            verified: false,
            error: error.message,
            timestamp: new Date().toISOString()
        };
    }
};

/**
 * Helper function to generate a nonce for request security
 * @private
 */
const generateNonce = () => {
    const array = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(array);
    } else {
        // Fallback for environments without crypto API
        for (let i = 0; i < array.length; i++) {
            array[i] = Math.floor(Math.random() * 256);
        }
    }
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
};

export {
    DocumentType,
    Protocol,
    CredentialFormat,
    ProtocolFormats,
    SupportedClaim
};