import * as cbor2 from 'cbor2';

function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));

    if (typeof atob === 'function') {
        // Browser
        const binary = atob(base64 + pad);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
           bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } else if (typeof Buffer === 'function') {
        // Node.js
        return new Uint8Array(Buffer.from(base64 + pad, 'base64'));
    } else {
        throw new Error('No base64 decoder available in this environment');
    }
    
}

export const decodeVpToken = async (vp_token) => {
    const buffer = base64urlToBuffer(vp_token);
    const decoded = await cbor2.decode(buffer);  // or decodeAll if you expect multiple items
    return decoded;
};

function mapToByteArray(contentsMap) {
    // Get the number of bytes from the highest key
    const length = Object.keys(contentsMap).length;
    const byteArray = new Uint8Array(length);
  
    for (let i = 0; i < length; i++) {
        byteArray[i] = contentsMap[i];
    }
  
    return byteArray;
}

async function verifyIssuerAuth(issuerAuth) {
    const protectedHeader = issuerAuth[0];
    const unprotectedHeader = issuerAuth[1];
    const payload = issuerAuth[2];
    const signature = issuerAuth[3];
    let bytes = [
        mapToByteArray(protectedHeader), 
        mapToByteArray(unprotectedHeader), 
        mapToByteArray(payload), 
        mapToByteArray(signature)
    ];
    let payloadData = await cbor2.decode(bytes[2]);
    //console.log('protectedHeader', await cbor2.decode(bytes[0]));
    //console.log('unprotectedHeader', await cbor2.decode(bytes[1]));
    //console.log('payload', payloadData);
    //console.log('signature', await cbor2.decode(bytes[3]));
    //console.log('payloadData', await cbor2.decode(payloadData.contents));
    return true;
}

async function verifyDeviceAuth(deviceAuth) {
    const protectedHeader = deviceAuth[0];
    const unprotectedHeader = deviceAuth[1];
    const payload = deviceAuth[2];
    const signature = deviceAuth[3];
    let bytes = [
        mapToByteArray(protectedHeader), 
        mapToByteArray(unprotectedHeader), 
        mapToByteArray(payload), 
        mapToByteArray(signature)
    ];
    return true;
}

export const verifyDocument = async (document) => {
    const claims = {}
    const { docType, issuerSigned, deviceSigned } = document;
    const { issuerAuth, nameSpaces } = issuerSigned;
    let verified = await verifyIssuerAuth(issuerAuth);
    if(!verified) return { claims: claims, verified: false };
    for(let namespace in nameSpaces) {
        for(let encodedObject of nameSpaces[namespace]) {
            let byteArray = mapToByteArray(encodedObject.contents);
            //CBOR decode the byteArray
            let decoded = await cbor2.decode(byteArray);
            console.log('decoded', decoded);
            claims[decoded.elementIdentifier] = decoded.elementValue;
        }
    }
    return {
        claims: claims,
        verified: true
    }
}