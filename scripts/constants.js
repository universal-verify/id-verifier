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

export const ClaimMappings = {
    [CredentialFormat.MSO_MDOC]: {
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