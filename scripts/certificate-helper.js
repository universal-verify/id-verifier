import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import { CoseAlgToWebCrypto } from './constants.js';
import { bufferToBase64Url, base64ToUint8Array } from './utils.js';
import { verifySignatureWithPem } from 'trusted-issuer-registry';

/**
 * Parse a X.509 chain into a PKIjs Certificate object
 * @param {Array|Uint8Array} x5chain - The X.509 chain
 * @returns {Certificate} - The parsed Certificate object
 */
export const parseX5Chain = (x5chain) => {
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
export const getAuthorityKeyIdentifier = (x509Cert) => {
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
export const x509ToWebCryptoKey = async (x509Cert, coseAlg) => {
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
 * Convert a PKIjs Certificate object to a PEM certificate string
 * @param {Certificate} x509Cert - The X.509 certificate
 * @returns {string} - The PEM certificate string
 */
export const certificateToPem = (x509Cert) => {
    // Get the raw certificate bytes
    const certBytes = x509Cert.toSchema().toBER();
    const certArray = new Uint8Array(certBytes);

    // Convert to URL-safe base64 first, then convert to standard base64
    const urlSafeBase64 = bufferToBase64Url(certArray);
    const base64 = urlSafeBase64.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const paddedBase64 = base64 + pad;

    // Format as PEM with 64-character lines and proper line endings
    const pemLines = [];
    for (let i = 0; i < paddedBase64.length; i += 64) {
        pemLines.push(paddedBase64.slice(i, i + 64));
    }

    return `-----BEGIN CERTIFICATE-----\r\n${pemLines.join('\r\n')}\r\n-----END CERTIFICATE-----`;
};

/**
 * Parse a PEM certificate string into a PKIjs Certificate object
 * @param {string} pemString - The PEM certificate string
 * @returns {Certificate} - The parsed Certificate object
 */
export const parsePemCertificate = (pemString) => {
    const pemContent = pemString
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');

    const bytes = base64ToUint8Array(pemContent);

    const asn1 = asn1js.fromBER(bytes.buffer);
    const cert = new Certificate({ schema: asn1.result });
    return cert;
};

/**
 * Validate a certificate against a list of issuer certificates in PEM format
 * @param {Certificate} certificate - The certificate to validate
 * @param {Array} issuerCertificates - The list of issuer certificates in PEM format
 * @returns {Promise<object>} - The issuer certificate object if the certificate is valid, null otherwise
 */
export const validateCertificateAgainstIssuer = async (certificate, issuerCertificates) => {
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