import * as cbor2 from 'cbor2';
import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import { CoseAlgToWebCrypto } from './constants.js';
import { x509ToSpkiKey } from './CertificateHelper.js';

function createCoseSign1ToBeSigned(protectedHeaders, externalAAD, payload) {
    // COSE_Sign1 structure: [protected headers, external_aad, payload]
    const toBeSigned = [
        'Signature1', // context string for COSE_Sign1
        protectedHeaders, // protected headers (encoded)
        externalAAD || new Uint8Array(0), // external_aad (empty if not provided)
        payload // payload
    ];
    
    return toBeSigned;
}

export const verifyCoseSign1 = async (issuerAuth, publicKey, algorithm) => {
    try {
        const [protectedHeadersRaw, unprotectedHeaders, payloadRaw, signatureRaw] = issuerAuth;
        
        // Create the data to be signed
        const toBeSigned = createCoseSign1ToBeSigned(
            protectedHeadersRaw, // encoded protected headers
            new Uint8Array(0), // external_aad (empty for this case)
            payloadRaw // payload
        );
        
        // Encode the to-be-signed data
        const toBeSignedEncoded = cbor2.encode(toBeSigned);
        //console.log('To-be-signed data length:', toBeSignedEncoded.length);
        
        // Verify the signature
        const isValid = await crypto.subtle.verify(
            algorithm,
            publicKey,
            signatureRaw,
            toBeSignedEncoded
        );
        
        //console.log('Signature verification result:', isValid);
        return isValid;
        
    } catch (error) {
        console.error('Error verifying COSE_Sign1 signature:', error);
        throw error;
    }
};