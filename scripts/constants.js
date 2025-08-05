/**
 * Supported trust lists
 */
export const TrustList = {
    UV: 'uv',
    AAMVA_DTS: 'aamva_dts',
};

export const ALL_TRUST_LISTS = ['all_trust_lists'];

/**
 * Supported document types for common identification documents
 */
export const DocumentType = {
    PHOTO_ID: 'org.iso.23220.photoID.1',
    EU_PERSONAL_ID: 'eu.europa.ec.eudi.pid.1',
    JAPAN_MY_NUMBER_CARD: 'org.iso.23220.1.jp.mnc',
    MOBILE_DRIVERS_LICENSE: 'org.iso.18013.5.1.mDL',
};

/**
 * Supported protocols for credential exchange
 */
export const Protocol = {
    OPENID4VP: 'openid4vp-v1-unsigned',
    MDOC: 'org-iso-mdoc'
};

/**
 * Supported credential formats
 */
export const CredentialFormat = {
    MSO_MDOC: 'mso_mdoc',
    //DC_SD_JWT: 'dc+sd-jwt',
    //LDP_VC: 'ldp_vc',
    //JWT_VC_JSON: 'jwt_vc_json'
};

export const ProtocolFormats = {
    [Protocol.OPENID4VP]: [CredentialFormat.MSO_MDOC],//CredentialFormat.DC_SD_JWT, CredentialFormat.LDP_VC, CredentialFormat.JWT_VC_JSON],
    [Protocol.MDOC]: [CredentialFormat.MSO_MDOC]
};

export const createCredentialId = (format, documentType) => {
    //replace all non-alphanumeric characters with an underscore
    return `cred-${format.replace(/[^a-zA-Z0-9]/g, '_')}-${documentType.replace(/[^a-zA-Z0-9]/g, '_')}`;
};

export const CredentialId = {
    'cred-mso_mdoc-org_iso_23220_photoID_1': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.PHOTO_ID },
    'cred-mso_mdoc-eu_europa_ec_eudi_pid_1': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.EU_PERSONAL_ID },
    'cred-mso_mdoc-org_iso_23220_1_jp_mnc': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.JAPAN_MY_NUMBER_CARD },
    'cred-mso_mdoc-org_iso_18013_5_1_mDL': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.MOBILE_DRIVERS_LICENSE },
};

/**
 * Supported claim fields that can be requested
 */
export const Claim = {
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
        [DocumentType.PHOTO_ID]: {
            [Claim.GIVEN_NAME]: ['org.iso.23220.1', 'given_name_unicode'],
            [Claim.FAMILY_NAME]: ['org.iso.23220.1', 'family_name_unicode'],
            [Claim.BIRTH_DATE]: ['org.iso.23220.1', 'birth_date'],
            [Claim.BIRTH_YEAR]: ['org.iso.23220.1', 'age_birth_year'],
            [Claim.AGE]: ['org.iso.23220.1', 'age_in_years'],
            [Claim.AGE_OVER_18]: ['org.iso.23220.1', 'age_over_18'],
            [Claim.AGE_OVER_21]: ['org.iso.23220.1', 'age_over_21'],
            //[Claim.HEIGHT]: ['', ''],
            //[Claim.WEIGHT]: ['', ''],
            //[Claim.EYE_COLOR]: ['', ''],
            //[Claim.HAIR_COLOR]: ['', ''],
            [Claim.ADDRESS]: ['org.iso.23220.1', 'resident_address_unicode'],
            [Claim.CITY]: ['org.iso.23220.1', 'resident_city_unicode'],
            [Claim.STATE]: ['org.iso.23220.photoID.1', 'resident_state'],
            [Claim.POSTAL_CODE]: ['org.iso.23220.1', 'resident_postal_code'],
            [Claim.COUNTRY]: ['org.iso.23220.1', 'resident_country'],
            [Claim.NATIONALITY]: ['org.iso.23220.1', 'nationality'],
            [Claim.SEX]: ['org.iso.23220.1', 'sex'],
            [Claim.PLACE_OF_BIRTH]: ['org.iso.23220.1', 'birthplace'],
            [Claim.DOCUMENT_NUMBER]: ['org.iso.23220.1', 'document_number'],
            [Claim.ISSUING_AUTHORITY]: ['org.iso.23220.1', 'issuing_authority_unicode'],
            [Claim.ISSUING_COUNTRY]: ['org.iso.23220.1', 'issuing_country'],
            [Claim.ISSUING_JURISDICTION]: ['org.iso.23220.1', 'issuing_subdivision'],
            [Claim.ISSUE_DATE]: ['org.iso.23220.1', 'issue_date'],
            [Claim.EXPIRY_DATE]: ['org.iso.23220.1', 'expiry_date'],
            //[Claim.DRIVING_PRIVILEGES]: ['', ''],
            [Claim.PORTRAIT]: ['org.iso.23220.1', 'portrait'],
            //[Claim.SIGNATURE]: ['', '']
        },
        [DocumentType.EU_PERSONAL_ID]: {
            [Claim.GIVEN_NAME]: ['eu.europa.ec.eudi.pid.1', 'given_name'],
            [Claim.FAMILY_NAME]: ['eu.europa.ec.eudi.pid.1', 'family_name'],
            [Claim.BIRTH_DATE]: ['eu.europa.ec.eudi.pid.1', 'birth_date'],
            [Claim.BIRTH_YEAR]: ['eu.europa.ec.eudi.pid.1', 'age_birth_year'],
            [Claim.AGE]: ['eu.europa.ec.eudi.pid.1', 'age_in_years'],
            [Claim.AGE_OVER_18]: ['eu.europa.ec.eudi.pid.1', 'age_over_18'],
            [Claim.AGE_OVER_21]: ['eu.europa.ec.eudi.pid.1', 'age_over_21'],
            //[Claim.HEIGHT]: ['', 'height'],
            //[Claim.WEIGHT]: ['', 'weight'],
            //[Claim.EYE_COLOR]: ['', 'eye_colour'],
            //[Claim.HAIR_COLOR]: ['', 'hair_colour'],
            [Claim.ADDRESS]: ['eu.europa.ec.eudi.pid.1', 'resident_address'],
            [Claim.CITY]: ['eu.europa.ec.eudi.pid.1', 'resident_city'],
            [Claim.STATE]: ['eu.europa.ec.eudi.pid.1', 'resident_state'],
            [Claim.POSTAL_CODE]: ['eu.europa.ec.eudi.pid.1', 'resident_postal_code'],
            [Claim.COUNTRY]: ['eu.europa.ec.eudi.pid.1', 'resident_country'],
            [Claim.NATIONALITY]: ['eu.europa.ec.eudi.pid.1', 'nationality'],
            [Claim.SEX]: ['eu.europa.ec.eudi.pid.1', 'sex'],
            [Claim.PLACE_OF_BIRTH]: ['eu.europa.ec.eudi.pid.1', 'birth_place'],
            [Claim.DOCUMENT_NUMBER]: ['eu.europa.ec.eudi.pid.1', 'document_number'],
            [Claim.ISSUING_AUTHORITY]: ['eu.europa.ec.eudi.pid.1', 'issuing_authority'],
            [Claim.ISSUING_COUNTRY]: ['eu.europa.ec.eudi.pid.1', 'issuing_country'],
            [Claim.ISSUING_JURISDICTION]: ['eu.europa.ec.eudi.pid.1', 'issuing_jurisdiction'],
            [Claim.ISSUE_DATE]: ['eu.europa.ec.eudi.pid.1', 'issuance_date'],
            [Claim.EXPIRY_DATE]: ['eu.europa.ec.eudi.pid.1', 'expiry_date'],
            //[Claim.DRIVING_PRIVILEGES]: ['', 'driving_privileges'],
            [Claim.PORTRAIT]: ['eu.europa.ec.eudi.pid.1', 'portrait'],
            //[Claim.SIGNATURE]: ['', 'signature_usual_mark']
        },
        [DocumentType.JAPAN_MY_NUMBER_CARD]: {
            [Claim.GIVEN_NAME]: ['org.iso.23220.1', 'given_name_unicode'],
            [Claim.FAMILY_NAME]: ['org.iso.23220.1', 'family_name_unicode'],
            [Claim.BIRTH_DATE]: ['org.iso.23220.1', 'birth_date'],
            [Claim.BIRTH_YEAR]: ['org.iso.23220.1', 'age_birth_year'],
            [Claim.AGE]: ['org.iso.23220.1', 'age_in_years'],
            [Claim.AGE_OVER_18]: ['org.iso.23220.1', 'age_over_18'],
            [Claim.AGE_OVER_21]: ['org.iso.23220.1', 'age_over_21'],
            //[Claim.HEIGHT]: ['', ''],
            //[Claim.WEIGHT]: ['', ''],
            //[Claim.EYE_COLOR]: ['', ''],
            //[Claim.HAIR_COLOR]: ['', ''],
            [Claim.ADDRESS]: ['org.iso.23220.1.jp', 'resident_address_unicode'],
            [Claim.CITY]: ['org.iso.23220.1', 'resident_city_unicode'],
            //[Claim.STATE]: ['', 'resident_state'],
            [Claim.POSTAL_CODE]: ['org.iso.23220.1', 'resident_postal_code'],
            [Claim.COUNTRY]: ['org.iso.23220.1', 'resident_country'],
            [Claim.NATIONALITY]: ['org.iso.23220.1', 'nationality'],
            [Claim.SEX]: ['org.iso.23220.1', 'sex'],
            [Claim.PLACE_OF_BIRTH]: ['org.iso.23220.1', 'birthplace'],
            [Claim.DOCUMENT_NUMBER]: ['org.iso.23220.1', 'document_number'],
            [Claim.ISSUING_AUTHORITY]: ['org.iso.23220.1', 'issuing_authority_unicode'],
            [Claim.ISSUING_COUNTRY]: ['org.iso.23220.1', 'issuing_country'],
            [Claim.ISSUING_JURISDICTION]: ['org.iso.23220.1', 'issuing_subdivision'],
            [Claim.ISSUE_DATE]: ['org.iso.23220.1', 'issue_date'],
            [Claim.EXPIRY_DATE]: ['org.iso.23220.1', 'expiry_date'],
            //[Claim.DRIVING_PRIVILEGES]: ['', ''],
            [Claim.PORTRAIT]: ['org.iso.23220.1', 'portrait'],
            //[Claim.SIGNATURE]: ['', '']
        },
        [DocumentType.MOBILE_DRIVERS_LICENSE]: {
            [Claim.GIVEN_NAME]: ['org.iso.18013.5.1', 'given_name'],
            [Claim.FAMILY_NAME]: ['org.iso.18013.5.1', 'family_name'],
            [Claim.BIRTH_DATE]: ['org.iso.18013.5.1', 'birth_date'],
            [Claim.BIRTH_YEAR]: ['org.iso.18013.5.1', 'age_birth_year'],
            [Claim.AGE]: ['org.iso.18013.5.1', 'age_in_years'],
            [Claim.AGE_OVER_18]: ['org.iso.18013.5.1', 'age_over_18'],
            [Claim.AGE_OVER_21]: ['org.iso.18013.5.1', 'age_over_21'],
            [Claim.HEIGHT]: ['org.iso.18013.5.1', 'height'],
            [Claim.WEIGHT]: ['org.iso.18013.5.1', 'weight'],
            [Claim.EYE_COLOR]: ['org.iso.18013.5.1', 'eye_colour'],
            [Claim.HAIR_COLOR]: ['org.iso.18013.5.1', 'hair_colour'],
            [Claim.ADDRESS]: ['org.iso.18013.5.1', 'resident_address'],
            [Claim.CITY]: ['org.iso.18013.5.1', 'resident_city'],
            [Claim.STATE]: ['org.iso.18013.5.1', 'resident_state'],
            [Claim.POSTAL_CODE]: ['org.iso.18013.5.1', 'resident_postal_code'],
            [Claim.COUNTRY]: ['org.iso.18013.5.1', 'resident_country'],
            [Claim.NATIONALITY]: ['org.iso.18013.5.1', 'nationality'],
            [Claim.SEX]: ['org.iso.18013.5.1', 'sex'],
            [Claim.PLACE_OF_BIRTH]: ['org.iso.18013.5.1', 'birth_place'],
            [Claim.DOCUMENT_NUMBER]: ['org.iso.18013.5.1', 'document_number'],
            [Claim.ISSUING_AUTHORITY]: ['org.iso.18013.5.1', 'issuing_authority'],
            [Claim.ISSUING_COUNTRY]: ['org.iso.18013.5.1', 'issuing_country'],
            [Claim.ISSUING_JURISDICTION]: ['org.iso.18013.5.1', 'issuing_jurisdiction'],
            [Claim.ISSUE_DATE]: ['org.iso.18013.5.1', 'issue_date'],
            [Claim.EXPIRY_DATE]: ['org.iso.18013.5.1', 'expiry_date'],
            [Claim.DRIVING_PRIVILEGES]: ['org.iso.18013.5.1', 'driving_privileges'],
            [Claim.PORTRAIT]: ['org.iso.18013.5.1', 'portrait'],
            [Claim.SIGNATURE]: ['org.iso.18013.5.1', 'signature_usual_mark']
        }
    }
};

export const REVERSE_CLAIM_MAPPINGS = {};
for(const format in ClaimMappings) {
    REVERSE_CLAIM_MAPPINGS[format] = {};
    for(const documentType in ClaimMappings[format]) {
        REVERSE_CLAIM_MAPPINGS[format][documentType] = {};
        for(const claim in ClaimMappings[format][documentType]) {
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

export const CoseKtyMap = {
    1: 'OKP',
    2: 'EC',
    3: 'RSA'
};

export const CoseCrvMap = {
    // EC2 Curves
    1: 'P-256',
    2: 'P-384',
    3: 'P-521',
    // OKP Curves
    6: 'Ed25519',
    7: 'Ed448',
    8: 'X25519',
    9: 'X448'
};

export const CoseKeyAlgoMap = {
    'EC-P-256': { name: 'ECDSA', namedCurve: 'P-256' },
    'EC-P-384': { name: 'ECDSA', namedCurve: 'P-384' },
    'EC-P-521': { name: 'ECDSA', namedCurve: 'P-521' },
    'OKP-Ed25519': { name: 'Ed25519' },
    'OKP-Ed448': { name: 'Ed448' },
    'OKP-X25519': { name: 'ECDH' },
    'OKP-X448': { name: 'ECDH' },
    'RSA': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
};