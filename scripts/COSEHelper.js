import * as cbor2 from 'cbor2';

export const verifyCoseSign1 = async (issuerAuth, publicKey, algorithm) => {
    try {
        const [protectedHeadersRaw, unprotectedHeaders, payloadRaw, signatureRaw] = issuerAuth;
        
        // Create the data to be signed
        const toBeSigned = [
            'Signature1', // context string for COSE_Sign1
            protectedHeadersRaw, // encoded protected headers
            new Uint8Array(0), // external_aad (empty for this case)
            payloadRaw // payload
        ];
        
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