import { DocumentType, Protocol, CredentialFormat, ProtocolFormats, Claim, ALL_TRUST_LISTS } from './constants.js';
import OpenID4VPProtocolHelper from './openid-4vp-protocol-helper.js';
import MDOCProtocolHelper from './mdoc-protocol-helper.js';

/**
 * Digital Credentials API Wrapper
 * A library to simplify digital ID verification using the W3C Digital Credentials API
 */

/**
 * Creates request parameters for digital credential verification
 * Used by backend services to generate credential request options
 *
 * @param {Object} options - Configuration options
 * @param {Array<string>} options.documentTypes - Type(s) of documents to request
 * @param {Array<string>} options.claims - Array of Claim enum values to request
 * @param {string} options.nonce - Security nonce to use in the request
 * @param {Object} options.jwk - JSON Web Key to use for encryption
 * @returns {Object} Request parameters compatible with Digital Credentials API
 */
export const createRequestParams = (options = {}) => {
    const {
        nonce = generateNonce(),
        jwk,
        documentTypes = [DocumentType.MOBILE_DRIVERS_LICENSE],
        claims = [],
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
    const validClaims = Object.values(Claim);
    const invalidClaims = claims.filter(claim => !validClaims.includes(claim));
    if (invalidClaims.length > 0) {
        throw new Error(`Invalid claims: ${invalidClaims.join(', ')}`);
    }

    // Create requests for both protocols
    const requests = [];

    for (const protocol of Object.values(Protocol)) {
        let request;
        if(protocol === Protocol.OPENID4VP) {
            request = OpenID4VPProtocolHelper.createRequest(types, claims, nonce);
        } else if(protocol === Protocol.MDOC) {
            request = MDOCProtocolHelper.createRequest(types, claims, nonce, jwk);
        }
        if (request) requests.push(request);
    }

    // Return the Digital Credentials API compatible structure
    return {
        mediation: 'required',
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

    //filter out requests that are not supported by the browser
    requestParams.digital.requests = requestParams.digital.requests.filter(request => {
        //TODO: Replace with DigitalCredentials.userAgentAllowsProtocol(request.protocol) once the API is available
        return request.protocol === Protocol.OPENID4VP;//DigitalCredentials.userAgentAllowsProtocol(request.protocol);
    });

    try {
        // Create the credential request options following the official spec
        const credentialRequestOptions = {
            ...requestParams,
            mediation: 'required',
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
        console.error('Error getting credentials', error);
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
 * @param {Array<string>} options.trustLists - Names of trust lists to use for determining trust. Defaults to all
 * @param {string} options.origin - The origin of the request (for session transcript generation)
 * @param {string} options.nonce - The nonce from the original request (for session transcript generation)
 * @returns {Promise<Object>} Promise that resolves to verified credential information
 */
export const verifyCredentials = async (credentialResponse, options = {}) => {
    const {
        trustLists = ALL_TRUST_LISTS,
        origin = null,
        nonce = null
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
            verificationResult = await OpenID4VPProtocolHelper.verify(credentialData, trustLists, origin, nonce);
        } else if(credentialResponse.protocol === Protocol.MDOC) {
            verificationResult = await MDOCProtocolHelper.verify(credentialData, trustLists, origin, nonce);
        } else {
            throw new Error(`Unsupported protocol: ${credentialResponse.protocol}`);
        }

        return {
            verified: true,
            claims: verificationResult.claims,
            trusted: verificationResult.trusted,
            issuers: verificationResult.issuers,
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
 * @returns {string} Nonce with 128 bits of entropy
 */
export const generateNonce = () => {
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

/**
 * Generates a JWK (JSON Web Key) using the P-256 curve
 * @returns {Promise<Object>} Promise that resolves to the JWK
 */
export const generateJWK = async () => {
    const keyPair = await crypto.subtle.generateKey({
        name: 'ECDSA',
        namedCurve: 'P-256',
    }, true, ['sign']);
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return jwk;
};

export {
    DocumentType,
    Protocol,
    CredentialFormat,
    ProtocolFormats,
    Claim
};