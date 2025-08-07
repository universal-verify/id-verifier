import TrustedIssuerRegistry, { verifySignatureWithPem } from 'trusted-issuer-registry';
import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import * as cbor2 from 'cbor2';
import { CipherSuite, Aes128Gcm, HkdfSha256, DhkemP256HkdfSha256 } from '@hpke/core';

/**
 * Supported trust lists
 */

const ALL_TRUST_LISTS = ['all_trust_lists'];

/**
 * Supported document types for common identification documents
 */
const DocumentType = {
    PHOTO_ID: 'org.iso.23220.photoid.1',
    EU_PERSONAL_ID: 'eu.europa.ec.eudi.pid.1',
    JAPAN_MY_NUMBER_CARD: 'org.iso.23220.1.jp.mnc',
    MOBILE_DRIVERS_LICENSE: 'org.iso.18013.5.1.mDL',
};

/**
 * Supported protocols for credential exchange
 */
const Protocol = {
    OPENID4VP: 'openid4vp-v1-unsigned',
    MDOC: 'org-iso-mdoc'
};

/**
 * Supported credential formats
 */
const CredentialFormat = {
    MSO_MDOC: 'mso_mdoc',
    //DC_SD_JWT: 'dc+sd-jwt',
    //LDP_VC: 'ldp_vc',
    //JWT_VC_JSON: 'jwt_vc_json'
};

const ProtocolFormats = {
    [Protocol.OPENID4VP]: [CredentialFormat.MSO_MDOC],//CredentialFormat.DC_SD_JWT, CredentialFormat.LDP_VC, CredentialFormat.JWT_VC_JSON],
    [Protocol.MDOC]: [CredentialFormat.MSO_MDOC]
};

const createCredentialId = (format, documentType) => {
    //replace all non-alphanumeric characters with an underscore
    return `cred-${format.replace(/[^a-zA-Z0-9]/g, '_')}-${documentType.replace(/[^a-zA-Z0-9]/g, '_')}`;
};

const CredentialId = {
    'cred-mso_mdoc-org_iso_23220_photoid_1': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.PHOTO_ID },
    'cred-mso_mdoc-eu_europa_ec_eudi_pid_1': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.EU_PERSONAL_ID },
    'cred-mso_mdoc-org_iso_23220_1_jp_mnc': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.JAPAN_MY_NUMBER_CARD },
    'cred-mso_mdoc-org_iso_18013_5_1_mDL': { format: CredentialFormat.MSO_MDOC, documentType: DocumentType.MOBILE_DRIVERS_LICENSE },
};

/**
 * Supported claim fields that can be requested
 */
const Claim = {
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

const ClaimMappings = {
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
            [Claim.STATE]: ['org.iso.23220.photoid.1', 'resident_state'],
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

const REVERSE_CLAIM_MAPPINGS = {};
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

const CoseAlgToWebCrypto = {
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

const CoseKtyMap = {
    1: 'OKP',
    2: 'EC',
    3: 'RSA'
};

const CoseCrvMap = {
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

const CoseKeyAlgoMap = {
    'EC-P-256': { name: 'ECDSA', namedCurve: 'P-256' },
    'EC-P-384': { name: 'ECDSA', namedCurve: 'P-384' },
    'EC-P-521': { name: 'ECDSA', namedCurve: 'P-521' },
    'OKP-Ed25519': { name: 'Ed25519' },
    'OKP-Ed448': { name: 'Ed448' },
    'OKP-X25519': { name: 'ECDH' },
    'OKP-X448': { name: 'ECDH' },
    'RSA': { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
};

/**
 * Convert a base64 string to a Uint8Array
 * @param {string} base64 - The base64 string
 * @returns {Uint8Array} - The Uint8Array
 */
const base64ToUint8Array = (base64) => {
    if(typeof Buffer == 'function') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
    } else if(typeof atob === 'function') {
        const raw = atob(base64);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            bytes[i] = raw.charCodeAt(i);
        }
        return bytes;
    } else {
        throw new Error('No base64 decoder available in this environment');
    }
};

/**
 * Convert a base64url string to a Uint8Array
 * @param {string} base64url - The base64url string
 * @returns {Uint8Array} - The Uint8Array
 */
const base64urlToUint8Array = (base64url) => {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    return base64ToUint8Array(base64 + pad);
};

const bufferToBase64 = (input) => {
    let bytes;
    if (input instanceof Uint8Array) {
        bytes = input;
    } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
    } else if (input.buffer instanceof ArrayBuffer) {
        bytes = new Uint8Array(input.buffer).slice(input.byteOffset, input.byteOffset + input.byteLength);
    } else {
        throw new Error('Invalid input type');
    }

    // Convert to base64 string
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = typeof Buffer == 'function'
        ? Buffer.from(binary, 'binary').toString('base64')
        : btoa(binary);

    return base64;
};

const bufferToBase64Url = (input) => {
    const base64 = bufferToBase64(input);

    // Convert base64 to base64url
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/**
 * Parse a X.509 chain into a PKIjs Certificate object
 * @param {Array|Uint8Array} x5chain - The X.509 chain
 * @returns {Certificate} - The parsed Certificate object
 */
const parseX5Chain = (x5chain) => {
    if(x5chain instanceof Array) x5chain = x5chain[0];
    if(!x5chain) return null;
    const arrayBuffer = x5chain.buffer.slice(x5chain.byteOffset, x5chain.byteOffset + x5chain.byteLength);
    const asn1 = asn1js.fromBER(arrayBuffer);
    const cert = new Certificate({ schema: asn1.result });
    return cert;
};

/**
 * Get the AuthorityKeyIdentifier from a X.509 certificate
 * @param {Certificate} x509Cert - The X.509 certificate
 * @returns {string} - The AuthorityKeyIdentifier in base64url format
 */
const getAuthorityKeyIdentifier = (x509Cert) => {
    if(!x509Cert) return null;
    const authorityKeyId = x509Cert.extensions?.find(ext => ext.extnID === '2.5.29.35');
    if (authorityKeyId) {
        try {
            const akidValue = asn1js.fromBER(authorityKeyId.extnValue.valueBlock.valueHex);
            if (akidValue.result.valueBlock.value) {
                return bufferToBase64Url(akidValue.result.valueBlock.value[0].valueBlock.valueHex);
            }
        } catch (e) {
            console.error('Could not parse AuthorityKeyIdentifier value', e);
        }
    }
    return null;
};

/**
 * Convert a X.509 certificate to a Web Crypto public key
 * @param {Certificate} x509Cert - The X.509 certificate
 * @param {string} coseAlg - The COSE algorithm
 * @returns {Promise<CryptoKey>} - The Web Crypto public key
 */
const x509ToWebCryptoKey = async (x509Cert, coseAlg) => {
    try {
        const publicKeyInfo = x509Cert.subjectPublicKeyInfo;
        const spkiBytes = publicKeyInfo.toSchema().toBER();
        const webCryptoAlg = CoseAlgToWebCrypto[coseAlg];
        const certKey = await crypto.subtle.importKey(
            'spki',
            spkiBytes,
            webCryptoAlg,
            false,
            ['verify']
        );

        return certKey;
    } catch (error) {
        console.error('Error converting X.509 to SPKI:', error);
        throw error;
    }
};

/**
 * Validate a certificate against a list of issuer certificates in PEM format
 * @param {Certificate} certificate - The certificate to validate
 * @param {Array} issuerCertificates - The list of issuer certificates in PEM format
 * @returns {Promise<object>} - The issuer certificate object if the certificate is valid, null otherwise
 */
const validateCertificateAgainstIssuer = async (certificate, issuerCertificates) => {
    if (!issuerCertificates || !Array.isArray(issuerCertificates)) {
        console.error('Unexpected input, no issuer certificates provided or not an array');
        return null;
    }

    let signature, tbsBytes;
    try {
        signature = certificate.signatureValue.valueBlock.valueHex;
        const tbsCertificate = certificate.tbsView; //TBS = To Be Signed (data to be signed)
        tbsBytes = new Uint8Array(tbsCertificate);
    } catch (error) {
        console.error('Could not parse signature value from certificate', error);
        return null;
    }


    for (let i = 0; i < issuerCertificates.length; i++) {
        const issuerCert = issuerCertificates[i];
        try {
            if (typeof issuerCert.data === 'string') {
                const isValid = await verifySignatureWithPem(issuerCert.data, signature, tbsBytes);
                if (isValid) return issuerCert;
            }
        } catch (error) {
            continue;
        }
    }

    return null;
};

let registry = new TrustedIssuerRegistry();
const ONE_DAY = 24 * 60 * 60 * 1000;

let endOfLifeDate, priorWarning;
let priorCheck = 0;

/**
 * Sets whether to use the trusted-issuer-registry's test data
 * @param {boolean} useTestData - Whether to use test data
 */
const setTestDataUsage = (useTestData) => {
    registry = new TrustedIssuerRegistry({ useTestData });
    priorCheck = 0;
    priorWarning = 0;
    endOfLifeDate = null;
};

const getIssuer = async (certificate) => {
    try {
        const aki = getAuthorityKeyIdentifier(certificate);
        if(!aki) return null;
        checkRegistryDeprecation();//No need to wait for this to complete
        const issuer = await registry.getIssuerFromX509AKI(aki);
        if(!issuer) return null;

        // Validate certificate against one of the certificates in issuer.certificates[].certificate (which is a string PEM)
        const matchedCertificate = await validateCertificateAgainstIssuer(certificate, issuer.certificates);
        if (matchedCertificate) {
            delete issuer.certificates;
            issuer.certificate = matchedCertificate;
            return issuer;
        }

        return null;
    } catch(error) {
        console.error('Error getting issuer', error);
        return null;
    }
};

async function checkRegistryDeprecation() {
    if(endOfLifeDate) {
        if(priorWarning < Date.now() - ONE_DAY) logEndOfLifeWarning();
    } else if(priorCheck < Date.now() - ONE_DAY) {
        try {
            endOfLifeDate = await registry.getEndOfLifeDate();
        } catch(error) {
            console.error('Error encountered while trying to get trusted-issuer-registry end of life date');
            console.error(error);
        }
        if(endOfLifeDate) logEndOfLifeWarning();
        priorCheck = Date.now();
    }
}

function logEndOfLifeWarning() {
    if(endOfLifeDate.getTime() < Date.now()) {
        console.warn(`trusted-issuer-registry minor version ${TrustedIssuerRegistry.minorVersion} has reached its end of life, please update to the latest major/minor version as soon as possible to receive the latest issuer information`);
    } else {
        console.warn(`trusted-issuer-registry minor version ${TrustedIssuerRegistry.minorVersion} reaching end of life on ${endOfLifeDate.toISOString().split('T')[0]}, please update to the latest major/minor version before then to avoid outdated issuer information`);
    }
    priorWarning = Date.now();
}

const verifyCoseSign1 = async (coseKey, publicKey) => {
    try {
        const [protectedHeadersRaw, _unprotectedHeaders, payloadRaw, signatureRaw] = coseKey;
        const protectedHeaders = await cbor2.decode(protectedHeadersRaw);
        const coseAlg = protectedHeaders.get(1);


        // Create the data to be signed
        const toBeSigned = [
            'Signature1', // context string for COSE_Sign1
            protectedHeadersRaw, // encoded protected headers
            new Uint8Array(0), // external_aad (empty for this case)
            payloadRaw || null // payload
        ];

        // Encode the to-be-signed data
        const toBeSignedEncoded = cbor2.encode(toBeSigned);

        // Verify the signature
        const isValid = await crypto.subtle.verify(
            CoseAlgToWebCrypto[coseAlg],
            publicKey,
            signatureRaw,
            toBeSignedEncoded
        );

        return isValid;

    } catch (error) {
        console.error('Error verifying COSE_Sign1 signature:', error);
        throw error;
    }
};

const coseKeyToWebCryptoKey = async (coseKey) => {
    const kty = CoseKtyMap[coseKey.get(1)];
    const crv = CoseCrvMap[coseKey.get(-1)];
    const algo = kty == 'RSA' ? CoseKeyAlgoMap['RSA'] : CoseKeyAlgoMap[`${kty}-${crv}`];
    if (!kty || !crv || !algo) throw new Error('Unsupported kty or crv');
    const x = bufferToBase64Url(coseKey.get(-2));
    const y = bufferToBase64Url(coseKey.get(-3));
    const jwk = {
        kty: kty,
        ext: true,
        key_ops: ['verify']
    };
    if(kty === 'EC') {
        jwk.x = x;
        jwk.y = y;
        jwk.crv = crv;
    } else if(kty === 'OKP') {
        jwk.x = x;
        jwk.crv = crv;
    } else if(kty === 'RSA') {
        jwk.n = crv;
        jwk.e = x;
    }
    return await crypto.subtle.importKey('jwk', jwk, algo, true, ['verify']);
};

const jwkToCoseKey = (jwk) => {
    if (jwk.kty !== 'EC') {
        throw new Error('Only EC keys supported at this time. Open a pull request if you need support for other key types.');
    }
    if (jwk.crv !== 'P-256') {
        throw new Error('Only P-256 curve supported at this time. Open a pull request if you need support for other curves.');
    }

    const x = base64urlToUint8Array(jwk.x);
    const y = base64urlToUint8Array(jwk.y);

    const coseKey = new Map();
    coseKey.set(1, 2);    // kty: EC2
    coseKey.set(-1, 1);   // crv: P-256
    coseKey.set(-2, x);   // x-coordinate
    coseKey.set(-3, y);   // y-coordinate

    return coseKey;
};

const decodeVpToken = async (vp_token) => {
    const uint8Array = base64urlToUint8Array(vp_token);
    const decoded = await cbor2.decode(uint8Array);
    return decoded;
};

const verifyDocument = async (document, sessionTranscript) => {
    const claims = {};
    const invalidReasons = [];
    const { docType, issuerSigned, deviceSigned } = document;
    const { issuerAuth, nameSpaces } = issuerSigned;
    const { valid, issuerAuthPayload, certificate, invalidReason } = await verifyIssuerAuth(issuerAuth);
    if(!valid) invalidReasons.push(invalidReason);
    const deviceValid = await verifyDeviceAuth(deviceSigned, issuerAuthPayload, sessionTranscript);
    if(!deviceValid) invalidReasons.push('Failed to verify device authentication');
    let claimsValid = true;
    for(const namespace in nameSpaces) {
        for(const claim of nameSpaces[namespace]) {
            const claimValid = await setClaim(claims, docType, namespace, claim, issuerAuthPayload);
            if(!claimValid && claimsValid) {
                claimsValid = false;
                invalidReasons.push("Claim values don't match IssuerAuth value digests");
            }
        }
    }
    const issuer = await getIssuer(certificate);
    return {
        claims: claims,
        issuer: issuer,
        valid: valid && deviceValid && claimsValid,
        invalidReasons: invalidReasons,
    };
};

async function verifyIssuerAuth(issuerAuth) {
    let invalidReason, certificate;
    const [protectedHeadersRaw, unprotectedHeaders, payloadRaw, _signatureRaw] = issuerAuth;
    const protectedHeaders = await cbor2.decode(protectedHeadersRaw);
    const payload = await cbor2.decode(payloadRaw);
    const issuerAuthPayload = cbor2.decode(payload.contents); //This is the Mobile Security Object (MSO)
    const now = new Date();
    if(new Date(issuerAuthPayload.validityInfo.validFrom) > now) {
        invalidReason = 'MSO is not yet valid';
    } else if(new Date(issuerAuthPayload.validityInfo.validUntil) < now) {
        invalidReason = 'MSO is expired';
    }
    if(!invalidReason) {
        const coseAlg = protectedHeaders.get(1);
        //https://datatracker.ietf.org/doc/rfc9360/
        const x5bag = unprotectedHeaders.get(32);
        const x5chain = unprotectedHeaders.get(33);
        unprotectedHeaders.get(34);
        unprotectedHeaders.get(35);
        if(x5bag) ; else if(x5chain) {
            certificate = parseX5Chain(x5chain);
        } else ;
        if(certificate) {
            const publicKey = await x509ToWebCryptoKey(certificate, coseAlg);
            const signatureValid = await verifyCoseSign1(issuerAuth, publicKey);
            if(!signatureValid)
                invalidReason = 'IssuerAuth signature verification failed';
        } else {
            invalidReason = 'No certificate found in IssuerAuth header';
        }
    }

    return {
        certificate: certificate,
        issuerAuthPayload: issuerAuthPayload,
        valid: !invalidReason,
        invalidReason: invalidReason,
    };
}

async function verifyDeviceAuth(deviceSigned, issuerAuthPayload, sessionTranscript) {
    const { deviceAuth, nameSpaces } = deviceSigned;
    const { deviceSignature } = deviceAuth;
    const { deviceKeyInfo, docType } = issuerAuthPayload;
    const deviceKey = await coseKeyToWebCryptoKey(deviceKeyInfo.deviceKey);
    const deviceAuthentication = cbor2.encode(['DeviceAuthentication', cbor2.decode(sessionTranscript), docType, nameSpaces]);
    const encodedDeviceAuthentication = cbor2.encode(new cbor2.Tag(24, deviceAuthentication));
    //console.log('encodedDeviceAuthentication as hex', Array.from(encodedDeviceAuthentication).map(b => b.toString(16).padStart(2, '0')).join(''));
    const signatureValid = await verifyCoseSign1([deviceSignature[0], deviceSignature[1], encodedDeviceAuthentication, deviceSignature[3]], deviceKey);
    return signatureValid;
}

async function setClaim(claims, docType, namespace, claim, issuerAuthPayload) {
    const { isValid, decodedClaim } = await verifyClaim(namespace, claim, issuerAuthPayload);
    let claimIdentifier = decodedClaim.elementIdentifier;
    let claimValue = decodedClaim.elementValue;
    if(claimValue.tag === 1004) {
        claimValue = claimValue.contents;
    } else if(namespace === 'org.iso.18013.5.1') {
        if(claimIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        } else if(claimIdentifier === 'driving_privileges' && claimValue && claimValue.length > 0) {
            claimValue = JSON.parse(JSON.stringify(claimValue));
            for(const privilege of claimValue) {
                for(const key in privilege) {
                    if(privilege[key]?.tag === 1004) {
                        privilege[key] = privilege[key].contents;
                    }
                }
            }
        }
    } else if(namespace === 'org.iso.23220.1') {
        if(claimIdentifier === 'birth_date' && claimValue.birth_date && claimValue.birth_date.tag === 1004) {
            claimValue = claimValue.birth_date.contents;
        } else if(claimIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        }
    } else if(namespace === 'eu.europa.ec.eudi.pid.1') {
        if(claimIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        }
    }
    const reverseClaimMapping = REVERSE_CLAIM_MAPPINGS[CredentialFormat.MSO_MDOC][docType][claimIdentifier];
    if(reverseClaimMapping) claimIdentifier = reverseClaimMapping;
    claims[claimIdentifier] = claimValue;
    return isValid;
}

async function verifyClaim(namespace, claim, issuerAuthPayload) {
    const decodedClaim = cbor2.decode(claim.contents);
    const digestId = decodedClaim.digestID;
    const digest = issuerAuthPayload.valueDigests[namespace].get(digestId);
    const encodedClaim = cbor2.encode(claim);
    const sha256 = await crypto.subtle.digest('SHA-256', encodedClaim);
    const sha256Uint8Array = new Uint8Array(sha256);
    return {
        isValid: uint8ArrayBytewiseEqual(sha256Uint8Array, digest),
        decodedClaim: decodedClaim
    };
}

function uint8ArrayBytewiseEqual(a, b) {
    return a.length === b.length && a.every((value, index) => value === b[index]);
}

class OpenID4VPProtocolHelper {
    constructor() {
        this.protocol = Protocol.OPENID4VP;
    }

    createRequest(documentTypes, claims, nonce) {
        const credentials = this._createQueryCredentials(documentTypes, claims);
        if (credentials.length > 0) {
            return {
                protocol: this.protocol,
                data: {
                    dcql_query: {
                        credentials
                    },
                    nonce: nonce,
                    response_mode: 'dc_api',
                    response_type: 'vp_token',
                }
            };
        }
        return null;
    }

    _createQueryCredentials(documentTypes, claims) {
        const credentials = [];
        for (const format of ProtocolFormats[this.protocol]) {
            for(const documentType of documentTypes) {
                const formatClaims = [];

                // Add claims for this format
                claims.forEach(claim => {
                    const claimPath = ClaimMappings[format]?.[documentType]?.[claim];
                    if (claimPath) {
                        formatClaims.push({
                            path: claimPath
                        });
                    }
                });

                if (formatClaims.length > 0) {
                    const credential = {
                        format,
                        id: createCredentialId(format, documentType),
                        claims: formatClaims,
                        meta: {},
                    };
                    if(format === CredentialFormat.MSO_MDOC) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.3
                        credential.meta.doctype_value = documentType;
                    } else if(format === CredentialFormat.DC_SD_JWT) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.5
                        credential.meta.vct_values = [];
                    } else if(format === CredentialFormat.LDP_VC) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.1
                        credential.meta.type_values = [];
                    }

                    credentials.push(credential);
                }
            }
        }
        return credentials;
    }

    async verify(credentialData, trustLists, origin, nonce) {
        const vpToken = credentialData.vp_token;
        for(const key in vpToken) {
            if(CredentialId[key].format === CredentialFormat.MSO_MDOC) {
                //TODO: Support response with multiple credential formats in the future
                return this._verifyMsoMdoc(vpToken[key], trustLists, origin, nonce);
            }
        }
        throw new Error('Unsupported credential format');
    }

    async _verifyMsoMdoc(tokens, trustLists, origin, nonce) {
        const processedDocuments = [];
        const decodedTokens = [];
        const documents = [];
        const claims = {};
        let trusted = true;
        let valid = true;

        // Generate session transcript if origin and nonce are provided
        const sessionTranscript = await this._generateSessionTranscript(origin, nonce);

        for(const token of tokens) {
            //verify base64url-encoded CBOR data
            const decoded = await decodeVpToken(token);
            console.log('decoded', decoded);
            decodedTokens.push(decoded);
        }
        for(const decodedToken of decodedTokens) {
            documents.push(...decodedToken.documents);
        }
        for(const document of documents) {
            const { claims: documentClaims, issuer, valid: documentValid, invalidReasons } = await verifyDocument(document, sessionTranscript);
            const issuerTrusted = issuer && (trustLists == ALL_TRUST_LISTS || issuer.certificate.trust_lists.some(tl => trustLists.includes(tl)));
            trusted = trusted && issuerTrusted;
            valid = valid && documentValid;
            for(const key in documentClaims) {
                claims[key] = documentClaims[key];
            }
            const processedDocument = {
                claims: documentClaims,
                valid: documentValid,
                trusted: !!issuerTrusted,
                document: document,
            };
            if(issuer) processedDocument.issuer = issuer;
            if(!documentValid) processedDocument.invalidReasons = invalidReasons;
            processedDocuments.push(processedDocument);
        }
        return {
            claims: claims,
            valid: !!valid,
            trusted: !!trusted,
            processedDocuments: processedDocuments,
            sessionTranscript: sessionTranscript,
        };
    }

    async _generateSessionTranscript(origin, nonce, jwkThumbprint = null) {
        if(!origin) throw new Error('Origin is required for generating session transcript');
        if(!nonce) throw new Error('Nonce is required for generating session transcript');

        // Create OpenID4VPDCAPIHandoverInfo structure
        const handoverInfo = [origin, nonce, jwkThumbprint];

        // Encode handoverInfo as CBOR
        const handoverInfoBytes = cbor2.encode(handoverInfo);

        // Calculate SHA-256 hash of the handoverInfoBytes
        const hashBuffer = await crypto.subtle.digest('SHA-256', handoverInfoBytes);
        const hashArray = new Uint8Array(hashBuffer);

        // Create OpenID4VPDCAPIHandover structure
        const handover = ['OpenID4VPDCAPIHandover', hashArray];

        // Create SessionTranscript structure
        // [DeviceEngagementBytes, EReaderKeyBytes, Handover]
        // For dc_api, DeviceEngagementBytes and EReaderKeyBytes MUST be null
        const sessionTranscript = cbor2.encode([null, null, handover]);
        return sessionTranscript;
    }
}

const openid4vpProtocolHelper = new OpenID4VPProtocolHelper();

class MDOCProtocolHelper {
    constructor() {
        this.protocol = Protocol.MDOC;
    }

    createRequest(documentTypes, claims, nonce, jwk) {
        const deviceRequest = this._createDeviceRequest(documentTypes, claims);
        const encryptionInfo = this._createEncryptionInfo(nonce, jwk);
        if (deviceRequest) {
            return {
                protocol: this.protocol,
                data: {
                    deviceRequest: deviceRequest,
                    encryptionInfo: encryptionInfo,
                }
            };
        }
        return null;
    }

    _createDeviceRequest(documentTypes, claims) {
        const version = '1.1';
        const docRequests = [];
        const readerAuthAll = [];//TODO: Waiting on Apple to approve my business connect request so I can test how this works
        const documentSets = [];
        let i = 0;
        for(const documentType of documentTypes) {
            const nameSpaces = {};

            claims.forEach(claim => {
                const claimPath = ClaimMappings[CredentialFormat.MSO_MDOC]?.[documentType]?.[claim];
                if (claimPath) {
                    if(!nameSpaces[claimPath[0]]) {
                        nameSpaces[claimPath[0]] = {};
                    }
                    nameSpaces[claimPath[0]][claimPath[1]] = true;
                }
            });

            if (Object.keys(nameSpaces).length > 0) {
                const itemsRequest = {
                    docType: documentType,
                    nameSpaces: nameSpaces,
                };
                docRequests.push({
                    itemsRequest: new cbor2.Tag(24, cbor2.encode(itemsRequest)),
                });
                documentSets.push([i++]);
            }
        }
        const deviceRequestInfo = new cbor2.Tag(24, cbor2.encode({
            useCases: [{
                mandatory: true,
                documentSets: documentSets,
            }]
        }));
        return bufferToBase64Url(cbor2.encode({
            version: version,
            docRequests: docRequests,
            readerAuthAll: readerAuthAll,
            deviceRequestInfo: deviceRequestInfo,
        }));
    }

    _createEncryptionInfo(nonceHex, jwk) {
        const nonce = new Uint8Array(nonceHex.length / 2);
        for (let i = 0; i < nonceHex.length; i += 2) {
            nonce[i / 2] = parseInt(nonceHex.substr(i, 2), 16);
        }
        const encryptionInfo = cbor2.encode(['dcapi', {
            nonce: nonce,
            recipientPublicKey: jwkToCoseKey(jwk),
        }]);
        return bufferToBase64Url(encryptionInfo);
    }

    async verify(credentialData, trustLists, origin, nonce, jwk) {
        const response = credentialData.response;
        const decodedResponse = await decodeVpToken(response);
        if(!Array.isArray(decodedResponse) || decodedResponse[0] !== 'dcapi') {
            throw new Error('Expected decoded response to be an array with dcapi as first element');
        }
        const { enc, cipherText } = decodedResponse[1] || {};
        if(!enc || !cipherText) {
            throw new Error('Expected enc and cipherText in decoded response');
        }
        const sessionTranscript = await this._generateSessionTranscript(origin, nonce, jwk);
        const decrypted = await this._decryptCipherText(cipherText, enc, sessionTranscript, jwk);
        return this._verifyMsoMdoc(decrypted.documents, trustLists, sessionTranscript);
    }

    async _decryptCipherText(cipherText, enc, sessionTranscript, jwk) {
        const cryptoKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' },
            true, ['deriveKey', 'deriveBits']);
        const suite = new CipherSuite({
            kem: new DhkemP256HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes128Gcm(),
        });

        const recipient = await suite.createRecipientContext({
            recipientKey: cryptoKey,
            enc: enc,
            info: sessionTranscript,
        });

        try {
            const decrypted = await recipient.open(cipherText);
            return cbor2.decode(new Uint8Array(decrypted));
        } catch (error) {
            console.error('Error decrypting cipherText', error);
            throw error;
        }
    }

    async _verifyMsoMdoc(documents, trustLists, sessionTranscript) {
        const processedDocuments = [];
        const claims = {};
        let trusted = true;
        let valid = true;

        for(const document of documents) {
            const { claims: documentClaims, issuer, valid: documentValid, invalidReasons } = await verifyDocument(document, sessionTranscript);
            const issuerTrusted = issuer && (trustLists == ALL_TRUST_LISTS || issuer.certificate.trust_lists.some(tl => trustLists.includes(tl)));
            trusted = trusted && issuerTrusted;
            valid = valid && documentValid;
            for(const key in documentClaims) {
                claims[key] = documentClaims[key];
            }
            const processedDocument = {
                claims: documentClaims,
                valid: documentValid,
                trusted: !!issuerTrusted,
                document: document,
            };
            if(issuer) processedDocument.issuer = issuer;
            if(!documentValid) processedDocument.invalidReasons = invalidReasons;
            processedDocuments.push(processedDocument);
        }
        return {
            claims: claims,
            valid: !!valid,
            trusted: !!trusted,
            processedDocuments: processedDocuments,
            sessionTranscript: sessionTranscript,
        };
    }

    async _generateSessionTranscript(origin, nonceHex, jwk) {
        if(!origin) throw new Error('Origin is required for generating session transcript');
        if(!nonceHex) throw new Error('Nonce is required for generating session transcript');
        if(!jwk) throw new Error('JWK is required for generating session transcript');

        const nonce = new Uint8Array(nonceHex.length / 2);
        for (let i = 0; i < nonceHex.length; i += 2) {
            nonce[i / 2] = parseInt(nonceHex.substr(i, 2), 16);
        }
        const arfEncryptionInfo = {
            nonce: nonce,
            recipientPublicKey: jwkToCoseKey(jwk)
        };

        const encryptionInfo = bufferToBase64Url(cbor2.encode(['dcapi', arfEncryptionInfo]));

        const dcapiInfo = cbor2.encode([encryptionInfo, origin]);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dcapiInfo);
        const hashArray = new Uint8Array(hashBuffer);

        const handover = ['dcapi', hashArray];

        const sessionTranscript = cbor2.encode([null, null, handover]);
        return sessionTranscript;
    }
}

const mdocProtocolHelper = new MDOCProtocolHelper();

/**
 * Digital Credentials API Wrapper
 * A library to simplify digital ID verification using the W3C Digital Credentials API
 */

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
const createCredentialsRequest = (options = {}) => {
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
            request = openid4vpProtocolHelper.createRequest(types, claims, nonce);
        } else if(protocol === Protocol.MDOC) {
            request = mdocProtocolHelper.createRequest(types, claims, nonce, jwk);
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
 *
 * @param {Object} requestParams - Request parameters from createRequestParams
 * @param {Object} options - Additional options for the request
 * @param {number} options.timeout - Request timeout in milliseconds (default: 300000)
 * @returns {Promise<Object>} Promise that resolves to credential data or rejects with error
 */
const requestCredentials = async (requestParams, options = {}) => {
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
        const allowedProtocol = navigator.userAgent.includes('Safari') ? Protocol.MDOC : Protocol.OPENID4VP;
        return request.protocol === allowedProtocol;
        //return DigitalCredential.userAgentAllowsProtocol(request.protocol);
    }).slice(0, 1);

    try {
        // Create the credential request options following the official spec
        const credentialRequestOptions = {
            ...requestParams,
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
};

/**
 * Processes a digital credential response
 *
 * @param {Object} credentials - The credentials response from requestCredentials
 * @param {Object} params - Verification params
 * @param {Array<string>} params.trustLists - Names of trust lists to use for determining trust. Defaults to all
 * @param {string} params.origin - The origin of the request (for session transcript generation)
 * @param {string} params.nonce - The nonce from the original request (for session transcript generation)
 * @param {Object} params.jwk - The JWK used to encrypt the request
 * @returns {Promise<Object>} Promise that resolves to the processed credential information
 */
const processCredentials = async (credentials, params = {}) => {
    const {
        trustLists = ALL_TRUST_LISTS,
        origin = null,
        nonce = null,
        jwk = null
    } = params;

    if (!credentials || typeof credentials !== 'object')
        throw new Error('Invalid credential response');
    if (!credentials.data)
        throw new Error('Credential response missing data');

    if(credentials.protocol === Protocol.OPENID4VP) {
        return await openid4vpProtocolHelper.verify(credentials.data, trustLists, origin, nonce);
    } else if(credentials.protocol === Protocol.MDOC) {
        return await mdocProtocolHelper.verify(credentials.data, trustLists, origin, nonce, jwk);
    } else {
        throw new Error(`Unsupported protocol: ${credentials.protocol}`);
    }
};

/**
 * Helper function to generate a nonce for request security
 * @returns {string} Nonce hex string with 128 bits of entropy
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
 * Generates a JWK (JSON Web Key) using the P-256 curve
 * @returns {Promise<Object>} Promise that resolves to the JWK
 */
const generateJWK = async () => {
    const keyPair = await crypto.subtle.generateKey({
        name: 'ECDH',
        namedCurve: 'P-256',
    }, true, ['deriveKey', 'deriveBits']);
    const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return jwk;
};

export { Claim, CredentialFormat, DocumentType, Protocol, ProtocolFormats, createCredentialsRequest, generateJWK, generateNonce, processCredentials, requestCredentials, setTestDataUsage };
