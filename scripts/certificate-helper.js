import { Certificate } from 'pkijs';
import { CoseAlgToWebCrypto } from './constants.js';

/**
 * Parse the document signer certificate from an X.509 chain
 * @param {Array|Uint8Array} x5chain - The X.509 chain
 * @returns {Certificate|null} - The parsed document signer certificate
 */
export const parseX5Chain = (x5chain) => {
    if(Array.isArray(x5chain)) x5chain = x5chain[0];
    return x5chain ? Certificate.fromBER(x5chain) : null;
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
