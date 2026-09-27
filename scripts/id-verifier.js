import { DocumentType, Protocol, CredentialFormat, ProtocolFormats, Claim, InvalidReason, UntrustedReason, ALL_TRUST_LISTS } from './constants.js';
import { setTestDataUsage } from './trusted-issuer-registry-helper.js';
import OpenID4VPProtocolHelper from './openid-4vp-protocol-helper.js';
import MDOCProtocolHelper from './mdoc-protocol-helper.js';

/**
 * Digital Credentials API Wrapper
 * A library to simplify digital ID verification using the W3C Digital Credentials API
 */

export class Verifier {
    constructor(options = {}) {
        options = options || {};
        this.registry = normalizeRegistryConfig(options.registry);
        this.issuerCertificates = normalizeIssuerCertificates(options.issuerCertificates);
        this.crl = normalizeCRLConfig(options.crl);
        this.crlCache = new Map();
    }

    /**
     * Creates request structure for digital credentials
     *
     * @param {Object} options - Configuration options
     * @param {Array<string>} options.documentTypes - Type(s) of documents to request
     * @param {Array<string>} options.claims - Array of Claim enum values to request
     * @param {string} options.nonce - Security nonce to use in the request
     * @param {Object} options.jwk - JSON Web Key to use for encryption
     * @returns {Object} Request parameters compatible with Digital Credentials API
     */
    createCredentialsRequest(options = {}) {
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
    }

    /**
     * Requests digital credentials from the user
     *
     * @param {Object} requestParams - Request parameters from createCredentialsRequest
     * @param {Object} options - Additional options for the request
     * @param {number} options.timeout - Request timeout in milliseconds (default: 300000)
     * @returns {Promise<Object>} Promise that resolves to credential data or rejects with error
     */
    async requestCredentials(requestParams, options = {}) {
        const { timeout = 300000 } = options;

        // Validate that we're in a browser environment
        if (typeof window === 'undefined') {
            throw new Error('requestCredentials can only be called in a browser environment');
        }

        // Validate that the Digital Credentials API is available
        const DigitalCredentialAPI = globalThis.DigitalCredential;
        if (typeof navigator === 'undefined' || !navigator.credentials || typeof DigitalCredentialAPI === 'undefined') {
            throw new Error('Digital Credentials API not supported in this browser');
        }
        if (typeof DigitalCredentialAPI.userAgentAllowsProtocol !== 'function') {
            throw new Error('Digital Credentials protocol detection not supported in this browser');
        }

        const supportedRequest = requestParams.digital.requests.find(request => {
            return DigitalCredentialAPI.userAgentAllowsProtocol(request.protocol);
        });
        if(!supportedRequest) {
            throw new Error('No supported digital credential protocol available in this browser');
        }

        try {
            // Create the credential request options following the official spec
            const credentialRequestOptions = {
                ...requestParams,
                digital: {
                    ...requestParams.digital,
                    requests: [supportedRequest]
                },
                mediation: 'required',
                signal: AbortSignal.timeout(timeout)
            };

            // Request the credential
            const credential = await navigator.credentials.get(credentialRequestOptions);

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
            throw error;
        }
    }

    /**
     * Processes a digital credential response
     *
     * @param {Object} credentials - The credentials response from requestCredentials
     * @param {Object} params - Verification params
     * @param {string} params.origin - The origin of the request (for session transcript generation)
     * @param {string} params.nonce - The nonce from the original request (for session transcript generation)
     * @param {Object} params.jwk - The JWK used to encrypt the request
     * @returns {Promise<Object>} Promise that resolves to the processed credential information
     */
    async processCredentials(credentials, params = {}) {
        const {
            origin = null,
            nonce = null,
            jwk = null,
        } = params;
        if (!credentials || typeof credentials !== 'object')
            throw new Error('Invalid credential response');
        if (!credentials.data)
            throw new Error('Credential response missing data');

        const verificationOptions = {
            registryEnabled: this.registry.enabled,
            trustLists: this.registry.trustLists,
            checkCRL: this.crl.enabled,
            crlTimeout: this.crl.timeout,
            crlCacheEnabled: this.crl.cache.enabled,
            crlCacheTTL: this.crl.cache.ttl,
            crlCache: this.crlCache,
        };

        if(credentials.protocol === Protocol.OPENID4VP) {
            return await OpenID4VPProtocolHelper.verify(credentials.data, origin, nonce, verificationOptions);
        } else if(credentials.protocol === Protocol.MDOC) {
            return await MDOCProtocolHelper.verify(credentials.data, origin, nonce, jwk, verificationOptions);
        } else {
            throw new Error(`Unsupported protocol: ${credentials.protocol}`);
        }
    }
}

const normalizeRegistryConfig = (registry = {}) => {
    registry = registry || {};
    return {
        enabled: registry.enabled !== false,
        trustLists: Array.isArray(registry.trustLists) ? [...registry.trustLists] : registry.trustLists || ALL_TRUST_LISTS,
    };
};

const normalizeIssuerCertificates = (issuerCertificates = []) => {
    return Array.isArray(issuerCertificates) ? [...issuerCertificates] : [];
};

const normalizeCRLConfig = (crl = {}) => {
    crl = crl || {};
    const cache = crl.cache || {};
    return {
        enabled: crl.enabled === true,
        timeout: crl.timeout,
        cache: {
            enabled: cache.enabled,
            ttl: cache.ttl,
        },
    };
};

/**
 * Helper function to generate a nonce for request security
 * @returns {string} Nonce hex string with 128 bits of entropy
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
        name: 'ECDH',
        namedCurve: 'P-256',
    }, true, ['deriveKey', 'deriveBits']);
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return jwk;
};

export {
    DocumentType,
    Protocol,
    CredentialFormat,
    ProtocolFormats,
    Claim,
    InvalidReason,
    UntrustedReason,
    setTestDataUsage
};
