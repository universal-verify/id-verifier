import * as cbor2 from 'cbor2';
import { bufferToBase64Url } from './utils.js';
import { CoseAlgToWebCrypto, CoseKtyMap, CoseCrvMap, CoseKeyAlgoMap } from './constants.js';

export const verifyCoseSign1 = async (coseKey, publicKey) => {
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

export const coseKeyToWebCryptoKey = async (coseKey) => {
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