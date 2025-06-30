/**
 * Digital Credentials API Wrapper
 * A library to simplify digital ID verification using the W3C Digital Credentials API
 */

/**
 * Supported document types for common identification documents
 */
export const DocumentType = {
    PHOTO_ID: 'org.iso.23220.photoid.1',
    EU_PERSONAL_ID: 'eu.europa.ec.eudi.pid.1',
    JAPAN_MY_NUMBER_CARD: 'org.iso.23220.1.jp.mnc',
    MOBILE_DRIVERS_LICENSE: 'org.iso.18013.5.1.mDL',
};

/**
 * Supported protocols for credential exchange
 */
const PROTOCOLS = {
    OPENID4VP: 'openid4vp',
    MDOC: 'org-iso-mdoc'
};

/**
 * Supported credential formats
 */
const CREDENTIAL_FORMATS = {
    MSO_MDOC: 'mso_mdoc',
    DC_SD_JWT: 'dc+sd-jwt',
    LDP_VC: 'ldp_vc',
    JWT_VC_JSON: 'jwt_vc_json'
};

const PROTOCOL_FORMATS = {
    [PROTOCOLS.OPENID4VP]: [CREDENTIAL_FORMATS.MSO_MDOC, CREDENTIAL_FORMATS.DC_SD_JWT, CREDENTIAL_FORMATS.LDP_VC, CREDENTIAL_FORMATS.JWT_VC_JSON],
    [PROTOCOLS.MDOC]: [CREDENTIAL_FORMATS.MSO_MDOC]
}

/**
 * Supported claim fields that can be requested
 */
export const SupportedClaim = {
    GIVEN_NAME: 'givenName',
    FAMILY_NAME: 'familyName',
    FULL_NAME: 'fullName',
    BIRTH_DATE: 'birthDate',
    AGE: 'age',
    AGE_OVER_18: 'ageOver18',
    AGE_OVER_21: 'ageOver21',
    ADDRESS: 'address',
    CITY: 'city',
    STATE: 'state',
    POSTAL_CODE: 'postalCode',
    COUNTRY: 'country',
    NATIONALITY: 'nationality',
    GENDER: 'gender',
    PLACE_OF_BIRTH: 'placeOfBirth',
    DOCUMENT_NUMBER: 'documentNumber',
    ISSUING_AUTHORITY: 'issuingAuthority',
    ISSUE_DATE: 'issueDate',
    EXPIRY_DATE: 'expiryDate',
    PORTRAIT: 'portrait',
    SIGNATURE: 'signature',
};

/**
 * Claim mappings for different credential formats
 */
const CLAIM_MAPPINGS = {
    [CREDENTIAL_FORMATS.MSO_MDOC]: {
        [DocumentType.MOBILE_DRIVERS_LICENSE]: {
            [SupportedClaim.GIVEN_NAME]: ['org.iso.18013.5.1', 'given_name'],
            [SupportedClaim.FAMILY_NAME]: ['org.iso.18013.5.1', 'family_name'],
            [SupportedClaim.FULL_NAME]: ['org.iso.18013.5.1', 'name_national_character'],
            [SupportedClaim.BIRTH_DATE]: ['org.iso.18013.5.1', 'birthdate'],
            [SupportedClaim.AGE]: ['org.iso.18013.5.1', 'age'],
            [SupportedClaim.AGE_OVER_18]: ['org.iso.18013.5.1', 'age_over_18'],
            [SupportedClaim.AGE_OVER_21]: ['org.iso.18013.5.1', 'age_over_21'],
            [SupportedClaim.ADDRESS]: ['org.iso.18013.5.1', 'resident_address'],
            [SupportedClaim.CITY]: ['org.iso.18013.5.1', 'resident_city'],
            [SupportedClaim.STATE]: ['org.iso.18013.5.1', 'resident_state'],
            [SupportedClaim.POSTAL_CODE]: ['org.iso.18013.5.1', 'resident_postal_code'],
            [SupportedClaim.COUNTRY]: ['org.iso.18013.5.1', 'issuing_country'],
            [SupportedClaim.NATIONALITY]: ['org.iso.18013.5.1', 'nationality'],
            [SupportedClaim.GENDER]: ['org.iso.18013.5.1', 'gender'],
            [SupportedClaim.PLACE_OF_BIRTH]: ['org.iso.18013.5.1', 'birthplace'],
            [SupportedClaim.DOCUMENT_NUMBER]: ['org.iso.18013.5.1', 'document_number'],
            [SupportedClaim.ISSUING_AUTHORITY]: ['org.iso.18013.5.1', 'issuing_authority'],
            [SupportedClaim.ISSUE_DATE]: ['org.iso.18013.5.1', 'issue_date'],
            [SupportedClaim.EXPIRY_DATE]: ['org.iso.18013.5.1', 'expiry_date'],
            [SupportedClaim.PORTRAIT]: ['org.iso.18013.5.1', 'portrait'],
            [SupportedClaim.SIGNATURE]: ['org.iso.18013.5.1', 'signature_usual_mark']
        }
    }
};

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

    for (const protocol of Object.values(PROTOCOLS)) {
        const credentials = [];
        for (const format of PROTOCOL_FORMATS[protocol]) {
            for(const documentType of types) {
                const formatClaims = [];

                // Add claims for this format
                claims.forEach(claim => {
                    const claimPath = CLAIM_MAPPINGS[format]?.[documentType]?.[claim];
                    if (claimPath) {
                        formatClaims.push({
                            path: claimPath
                        });
                    }
                });

                if (formatClaims.length > 0) {
                    const credential = {
                        format,
                        id: `cred_${format}`,
                        claims: formatClaims,
                        meta: {}
                    };
                    if(format === CREDENTIAL_FORMATS.MSO_MDOC) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.3
                        credential.meta.doctype_value = documentType;
                    } else if(format === CREDENTIAL_FORMATS.DC_SD_JWT) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.5
                        credential.meta.vct_values = [];
                    } else if(format === CREDENTIAL_FORMATS.LDP_VC) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.1
                        credential.meta.type_values = [];
                    }

                    credentials.push(credential);
                }
            }
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
        expectedProtocol,
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

        // Protocol validation
        if (expectedProtocol && credentialResponse.protocol !== expectedProtocol) {
            throw new Error(`Protocol mismatch: expected ${expectedProtocol}, got ${credentialResponse.protocol}`);
        }

        // Extract and validate credential data
        const credentialData = credentialResponse.data;

        // Verify credential structure based on protocol
        const verificationResult = await verifyCredentialByProtocol(
            credentialData,
            credentialResponse.protocol, {
                expectedTypes,
                verifierId,
                trustedIssuers
            }
        );

        // Extract available ID information
        const idInformation = extractIdInformation(credentialData, credentialResponse.protocol);

        return {
            verified: true,
            protocol: credentialResponse.protocol,
            credentialId: credentialResponse.id,
            timestamp: credentialResponse.timestamp,
            verificationDetails: verificationResult,
            idInformation
        };

    } catch (error) {
        return {
            verified: false,
            error: error.message,
            timestamp: new Date().toISOString()
        };
    }
};

/**
 * Helper function to verify credentials based on their protocol
 * @private
 */
const verifyCredentialByProtocol = async (credentialData, protocol, options) => {
    const {
        expectedTypes,
        verifierId,
        trustedIssuers
    } = options;

    switch (protocol) {
        case PROTOCOLS.MDOC:
            return verifyMDocCredential(credentialData, options);
        case PROTOCOLS.W3C_VC:
            return verifyW3CCredential(credentialData, options);
        case PROTOCOLS.ISO_18013_5:
            return verifyISO18013Credential(credentialData, options);
        default:
            throw new Error(`Unsupported protocol: ${protocol}`);
    }
};

/**
 * Helper function to verify mDoc credentials
 * @private
 */
const verifyMDocCredential = async (credentialData, options) => {
    // Basic mDoc validation - in a real implementation, this would include
    // cryptographic verification, signature validation, etc.

    if (!credentialData.documents || !Array.isArray(credentialData.documents)) {
        throw new Error('Invalid mDoc structure: missing documents array');
    }

    const verificationResults = [];

    for (const doc of credentialData.documents) {
        if (!doc.docType) {
            throw new Error('Invalid mDoc document: missing docType');
        }

        // Validate against expected types if specified
        if (options.expectedTypes.length > 0 && !options.expectedTypes.includes(doc.docType)) {
            throw new Error(`Unexpected document type: ${doc.docType}`);
        }

        // Basic issuer validation
        if (options.trustedIssuers.length > 0 && doc.issuer) {
            if (!options.trustedIssuers.includes(doc.issuer)) {
                throw new Error(`Untrusted issuer: ${doc.issuer}`);
            }
        }

        verificationResults.push({
            docType: doc.docType,
            issuer: doc.issuer,
            valid: true
        });
    }

    return {
        protocol: PROTOCOLS.MDOC,
        documentsVerified: verificationResults.length,
        verificationResults
    };
};

/**
 * Helper function to verify W3C Verifiable Credentials
 * @private
 */
const verifyW3CCredential = async (credentialData, options) => {
    // Basic W3C VC validation
    if (!credentialData.credential) {
        throw new Error('Invalid W3C VC structure: missing credential');
    }

    const credential = credentialData.credential;

    if (!credential.type || !Array.isArray(credential.type)) {
        throw new Error('Invalid W3C VC: missing or invalid type');
    }

    if (!credential.issuer) {
        throw new Error('Invalid W3C VC: missing issuer');
    }

    // Validate against expected types
    if (options.expectedTypes.length > 0) {
        const hasExpectedType = options.expectedTypes.some(expectedType =>
            credential.type.includes(expectedType)
        );
        if (!hasExpectedType) {
            throw new Error(`Unexpected credential type: ${credential.type.join(', ')}`);
        }
    }

    // Basic issuer validation
    if (options.trustedIssuers.length > 0) {
        const issuerId = typeof credential.issuer === 'string' ? credential.issuer : credential.issuer.id;
        if (!options.trustedIssuers.includes(issuerId)) {
            throw new Error(`Untrusted issuer: ${issuerId}`);
        }
    }

    return {
        protocol: PROTOCOLS.W3C_VC,
        credentialType: credential.type,
        issuer: credential.issuer,
        valid: true
    };
};

/**
 * Helper function to verify ISO 18013-5 credentials
 * @private
 */
const verifyISO18013Credential = async (credentialData, options) => {
    // Basic ISO 18013-5 validation
    if (!credentialData.mobileSecurityObject) {
        throw new Error('Invalid ISO 18013-5 structure: missing mobileSecurityObject');
    }

    const mso = credentialData.mobileSecurityObject;

    if (!mso.version) {
        throw new Error('Invalid ISO 18013-5: missing version');
    }

    // Validate document types
    if (credentialData.documents) {
        for (const doc of credentialData.documents) {
            if (options.expectedTypes.length > 0 && !options.expectedTypes.includes(doc.docType)) {
                throw new Error(`Unexpected document type: ${doc.docType}`);
            }
        }
    }

    return {
        protocol: PROTOCOLS.ISO_18013_5,
        version: mso.version,
        valid: true
    };
};

/**
 * Helper function to extract ID information from credential data
 * @private
 */
const extractIdInformation = (credentialData, protocol) => {
    const idInfo = {
        protocol,
        documents: [],
        personalInfo: {},
        extractedAt: new Date().toISOString()
    };

    switch (protocol) {
        case PROTOCOLS.MDOC:
            if (credentialData.documents) {
                for (const doc of credentialData.documents) {
                    const docInfo = {
                        docType: doc.docType,
                        issuer: doc.issuer,
                        attributes: {}
                    };

                    // Extract common attributes
                    if (doc.attributes) {
                        for (const [key, value] of Object.entries(doc.attributes)) {
                            if (value && value.value) {
                                docInfo.attributes[key] = value.value;
                            }
                        }
                    }

                    idInfo.documents.push(docInfo);
                }
            }
            break;

        case PROTOCOLS.W3C_VC:
            if (credentialData.credential && credentialData.credential.credentialSubject) {
                idInfo.personalInfo = credentialData.credential.credentialSubject;
            }
            break;

        case PROTOCOLS.ISO_18013_5:
            if (credentialData.documents) {
                for (const doc of credentialData.documents) {
                    const docInfo = {
                        docType: doc.docType,
                        attributes: {}
                    };

                    if (doc.attributes) {
                        for (const [key, value] of Object.entries(doc.attributes)) {
                            if (value && value.value) {
                                docInfo.attributes[key] = value.value;
                            }
                        }
                    }

                    idInfo.documents.push(docInfo);
                }
            }
            break;
    }

    return idInfo;
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

/**
 * Legacy function for backward compatibility
 */
export const verify = () => {
    console.log("TODO: This function is deprecated. Use verifyCredentials instead.");
};
