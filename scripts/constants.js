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
export const Protocol = {
    OPENID4VP: 'openid4vp-v1-unsigned',
    //MDOC: 'org-iso-mdoc'
};

/**
 * Supported credential formats
 */
export const CredentialFormat = {
    MSO_MDOC: 'mso_mdoc',
    DC_SD_JWT: 'dc+sd-jwt',
    LDP_VC: 'ldp_vc',
    JWT_VC_JSON: 'jwt_vc_json'
};

export const ProtocolFormats = {
    [Protocol.OPENID4VP]: [CredentialFormat.MSO_MDOC, CredentialFormat.DC_SD_JWT, CredentialFormat.LDP_VC, CredentialFormat.JWT_VC_JSON],
    [Protocol.MDOC]: [CredentialFormat.MSO_MDOC]
}

/**
 * Supported claim fields that can be requested
 */
export const SupportedClaim = {
    AGE: 'age',
    AGE_OVER_18: 'age_over_18',
    AGE_OVER_21: 'age_over_21',
    BIRTH_DATE: 'birth_date',
    BIRTH_YEAR: 'birth_year',
    FAMILY_NAME: 'family_name',
    GIVEN_NAME: 'given_name',
    SEX: 'sex',
    HEIGHT: 'height',
    WEIGHT: 'weight',
    EYE_COLOR: 'eye_color',
    HAIR_COLOR: 'hair_color',
    ADDRESS: 'address',
    CITY: 'city',
    STATE: 'state',
    POSTAL_CODE: 'postal_code',
    COUNTRY: 'country',
    NATIONALITY: 'nationality',
    PLACE_OF_BIRTH: 'place_of_birth',
    DOCUMENT_NUMBER: 'document_number',
    ISSUING_AUTHORITY: 'issuing_authority',
    ISSUING_COUNTRY: 'issuing_country',
    ISSUING_JURISDICTION: 'issuing_jurisdiction',
    ISSUE_DATE: 'issue_date',
    EXPIRY_DATE: 'expiry_date',
    DRIVING_PRIVILEGES: 'driving_privileges',
    PORTRAIT: 'portrait',
    SIGNATURE: 'signature',
};

export const ClaimMappings = {
    [CredentialFormat.MSO_MDOC]: {
        [DocumentType.MOBILE_DRIVERS_LICENSE]: {
            [SupportedClaim.GIVEN_NAME]: ['org.iso.18013.5.1', 'given_name'],
            [SupportedClaim.FAMILY_NAME]: ['org.iso.18013.5.1', 'family_name'],
            [SupportedClaim.BIRTH_DATE]: ['org.iso.18013.5.1', 'birth_date'],
            [SupportedClaim.BIRTH_YEAR]: ['org.iso.18013.5.1', 'age_birth_year'],
            [SupportedClaim.AGE]: ['org.iso.18013.5.1', 'age_in_years'],
            [SupportedClaim.AGE_OVER_18]: ['org.iso.18013.5.1', 'age_over_18'],
            [SupportedClaim.AGE_OVER_21]: ['org.iso.18013.5.1', 'age_over_21'],
            [SupportedClaim.HEIGHT]: ['org.iso.18013.5.1', 'height'],
            [SupportedClaim.WEIGHT]: ['org.iso.18013.5.1', 'weight'],
            [SupportedClaim.EYE_COLOR]: ['org.iso.18013.5.1', 'eye_colour'],
            [SupportedClaim.HAIR_COLOR]: ['org.iso.18013.5.1', 'hair_colour'],
            [SupportedClaim.ADDRESS]: ['org.iso.18013.5.1', 'resident_address'],
            [SupportedClaim.CITY]: ['org.iso.18013.5.1', 'resident_city'],
            [SupportedClaim.STATE]: ['org.iso.18013.5.1', 'resident_state'],
            [SupportedClaim.POSTAL_CODE]: ['org.iso.18013.5.1', 'resident_postal_code'],
            [SupportedClaim.COUNTRY]: ['org.iso.18013.5.1', 'resident_country'],
            [SupportedClaim.NATIONALITY]: ['org.iso.18013.5.1', 'nationality'],
            [SupportedClaim.SEX]: ['org.iso.18013.5.1', 'sex'],
            [SupportedClaim.PLACE_OF_BIRTH]: ['org.iso.18013.5.1', 'birth_place'],
            [SupportedClaim.DOCUMENT_NUMBER]: ['org.iso.18013.5.1', 'document_number'],
            [SupportedClaim.ISSUING_AUTHORITY]: ['org.iso.18013.5.1', 'issuing_authority'],
            [SupportedClaim.ISSUING_COUNTRY]: ['org.iso.18013.5.1', 'issuing_country'],
            [SupportedClaim.ISSUING_JURISDICTION]: ['org.iso.18013.5.1', 'issuing_jurisdiction'],
            [SupportedClaim.ISSUE_DATE]: ['org.iso.18013.5.1', 'issue_date'],
            [SupportedClaim.EXPIRY_DATE]: ['org.iso.18013.5.1', 'expiry_date'],
            [SupportedClaim.DRIVING_PRIVILEGES]: ['org.iso.18013.5.1', 'driving_privileges'],
            [SupportedClaim.PORTRAIT]: ['org.iso.18013.5.1', 'portrait'],
            [SupportedClaim.SIGNATURE]: ['org.iso.18013.5.1', 'signature_usual_mark']
        }
    }
};

export const REVERSE_CLAIM_MAPPINGS = {};
for(let format in ClaimMappings) {
    REVERSE_CLAIM_MAPPINGS[format] = {};
    for(let documentType in ClaimMappings[format]) {
        REVERSE_CLAIM_MAPPINGS[format][documentType] = {};
        for(let claim in ClaimMappings[format][documentType]) {
            let mappedValue = ClaimMappings[format][documentType][claim];
            mappedValue = mappedValue[mappedValue.length - 1];
            REVERSE_CLAIM_MAPPINGS[format][documentType][mappedValue] = claim;
        }
    }
}

export const CoseAlgToWebCrypto = {
    [-7]:   { name: 'ECDSA', hash: 'SHA-256', namedCurve: 'P-256' },       // ES256
    [-35]:  { name: 'ECDSA', hash: 'SHA-384', namedCurve: 'P-384' },       // ES384
    [-36]:  { name: 'ECDSA', hash: 'SHA-512', namedCurve: 'P-521' },       // ES512
  
    [-37]:  { name: 'RSASSA-PSS', hash: 'SHA-256' },                       // PS256
    [-38]:  { name: 'RSASSA-PSS', hash: 'SHA-384' },                       // PS384
    [-39]:  { name: 'RSASSA-PSS', hash: 'SHA-512' },                       // PS512
  
    [-257]: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },                // RS256
    [-258]: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },                // RS384
    [-259]: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }                 // RS512
  };