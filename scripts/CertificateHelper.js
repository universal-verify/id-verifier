import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import { CoseAlgToWebCrypto } from './constants.js';
import { bufferToBase64Url } from './utils.js';

export const parseX5Chain = (x5chain) => {
    if(x5chain instanceof Array) x5chain = x5chain[0];
    const arrayBuffer = x5chain.buffer.slice(x5chain.byteOffset, x5chain.byteOffset + x5chain.byteLength);
    const asn1 = asn1js.fromBER(arrayBuffer);
    const cert = new Certificate({ schema: asn1.result });
    return cert;
}

export const getAuthorityKeyIdentifier = (x509Cert) => {
    const authorityKeyId = x509Cert.extensions?.find(ext => ext.extnID === '2.5.29.35');
    if (authorityKeyId) {
        try {
            const akidValue = asn1js.fromBER(authorityKeyId.extnValue.valueBlock.valueHex);
            if (akidValue.result.valueBlock.value) {
                return bufferToBase64Url(akidValue.result.valueBlock.value[0].valueBlock.valueHex);
            }
        } catch (e) {
            console.log('Could not parse AuthorityKeyIdentifier value', e);
        }
    }
    return null;
}

export const x509ToSpkiKey = async (x509Cert, coseAlg) => {
    try {
        const publicKeyInfo = x509Cert.subjectPublicKeyInfo;
        const publicKeyRaw = new Uint8Array(publicKeyInfo.subjectPublicKey.valueBlock.valueHex);
        
        // Use the COSE algorithm to determine the SPKI structure
        const algorithmIdentifier = buildAlgorithmIdentifierForCose(coseAlg);
        
        // BIT STRING encoding: prepend 0x00 for "unused bits"
        const bitString = new Uint8Array(publicKeyRaw.length + 1);
        bitString[0] = 0x00;
        bitString.set(publicKeyRaw, 1);
        
        // Full SPKI: SEQUENCE { algorithmIdentifier, BIT STRING { publicKey } }
        // Calculate total length
        const totalLen = algorithmIdentifier.length + bitString.length + 2; // 2 bytes for BIT STRING tag/len
        const spki = new Uint8Array(totalLen + 2); // 2 bytes for SEQUENCE tag/len
        spki[0] = 0x30; // SEQUENCE
        spki[1] = totalLen;
        spki.set(algorithmIdentifier, 2);
        spki[2 + algorithmIdentifier.length] = 0x03; // BIT STRING
        spki[3 + algorithmIdentifier.length] = bitString.length; // BIT STRING length
        spki.set(bitString, 4 + algorithmIdentifier.length);

        const webCryptoAlg = CoseAlgToWebCrypto[coseAlg];
        const certKey = await crypto.subtle.importKey(
            'spki',
            spki,
            webCryptoAlg,
            false,
            ['verify']
        );
        
        return certKey;
    } catch (error) {
        console.error('Error converting X.509 to SPKI:', error);
        throw error;
    }
}

function buildAlgorithmIdentifierForCose(coseAlg) {
    switch (coseAlg) {
        case -7: // ES256 (ECDSA P-256)
            return new Uint8Array([
                0x30, 0x13, // SEQUENCE, length 19
                0x06, 0x07, // OBJECT IDENTIFIER, length 7
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
                0x06, 0x08, // OBJECT IDENTIFIER, length 8
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 // 1.2.840.10045.3.1.7 (P-256)
            ]);
        case -35: // ES384 (ECDSA P-384)
            return new Uint8Array([
                0x30, 0x13, // SEQUENCE, length 19
                0x06, 0x07, // OBJECT IDENTIFIER, length 7
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
                0x06, 0x08, // OBJECT IDENTIFIER, length 8
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x0B // 1.2.840.10045.3.1.11 (P-384)
            ]);
        case -36: // ES512 (ECDSA P-521)
            return new Uint8Array([
                0x30, 0x13, // SEQUENCE, length 19
                0x06, 0x07, // OBJECT IDENTIFIER, length 7
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // 1.2.840.10045.2.1 (ecPublicKey)
                0x06, 0x08, // OBJECT IDENTIFIER, length 8
                0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x0D // 1.2.840.10045.3.1.13 (P-521)
            ]);
        case -257: // RS256 (RSA PKCS#1 v1.5)
            return new Uint8Array([
                0x30, 0x0D, // SEQUENCE, length 13
                0x06, 0x09, // OBJECT IDENTIFIER, length 9
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1 (rsaEncryption)
                0x05, 0x00 // NULL
            ]);
        case -258: // RS384 (RSA PKCS#1 v1.5)
            return new Uint8Array([
                0x30, 0x0D, // SEQUENCE, length 13
                0x06, 0x09, // OBJECT IDENTIFIER, length 9
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1 (rsaEncryption)
                0x05, 0x00 // NULL
            ]);
        case -259: // RS512 (RSA PKCS#1 v1.5)
            return new Uint8Array([
                0x30, 0x0D, // SEQUENCE, length 13
                0x06, 0x09, // OBJECT IDENTIFIER, length 9
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // 1.2.840.113549.1.1.1 (rsaEncryption)
                0x05, 0x00 // NULL
            ]);
        case -37: // PS256 (RSA PSS)
            return new Uint8Array([
                0x30, 0x0D, // SEQUENCE, length 13
                0x06, 0x09, // OBJECT IDENTIFIER, length 9
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, // 1.2.840.113549.1.1.10 (rsassaPss)
                0x05, 0x00 // NULL
            ]);
        case -38: // PS384 (RSA PSS)
            return new Uint8Array([
                0x30, 0x0D, // SEQUENCE, length 13
                0x06, 0x09, // OBJECT IDENTIFIER, length 9
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, // 1.2.840.113549.1.1.10 (rsassaPss)
                0x05, 0x00 // NULL
            ]);
        case -39: // PS512 (RSA PSS)
            return new Uint8Array([
                0x30, 0x0D, // SEQUENCE, length 13
                0x06, 0x09, // OBJECT IDENTIFIER, length 9
                0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, // 1.2.840.113549.1.1.10 (rsassaPss)
                0x05, 0x00 // NULL
            ]);
        default:
            throw new Error(`Unsupported COSE algorithm: ${coseAlg}`);
    }
}