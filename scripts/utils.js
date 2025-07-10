import * as cbor2 from 'cbor2';

/**
 * Convert a base64 string to a Uint8Array
 * @param {string} base64 - The base64 string
 * @returns {Uint8Array} - The Uint8Array
 */
export const base64ToUint8Array = (base64) => {
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
}

/**
 * Convert a base64url string to a Uint8Array
 * @param {string} base64url - The base64url string
 * @returns {Uint8Array} - The Uint8Array
 */
export const base64urlToUint8Array = (base64url) => {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    return base64ToUint8Array(base64 + pad);
};

export const bufferToBase64 = (input) => {
    let bytes;
    if (input instanceof Uint8Array) {
        bytes = input;
    } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
    } else if (input.buffer instanceof ArrayBuffer) {
        bytes = new Uint8Array(input.buffer).slice(input.byteOffset, input.byteOffset + input.byteLength);
    } else {
        throw new Error("Invalid input type");
    }
  
    // Convert to base64 string
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    let base64 = typeof Buffer == 'function'
        ? Buffer.from(binary, 'binary').toString('base64')
        : btoa(binary);
  
    return base64;
}

export const bufferToBase64Url = (input) => {
    let base64 = bufferToBase64(input);
  
    // Convert base64 to base64url
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const generateSessionTranscript = async (origin, nonce, jwkThumbprint = null) => {
    // Create OpenID4VPDCAPIHandoverInfo structure
    const handoverInfo = [origin, nonce, jwkThumbprint];
    
    // Encode handoverInfo as CBOR
    const handoverInfoBytes = cbor2.encode(handoverInfo);

    // Calculate SHA-256 hash of the handoverInfoBytes
    const hashBuffer = await crypto.subtle.digest('SHA-256', handoverInfoBytes);
    const hashArray = new Uint8Array(hashBuffer);
    
    // Create OpenID4VPDCAPIHandover structure
    const handover = ["OpenID4VPDCAPIHandover", hashArray];

    // Create SessionTranscript structure
    // [DeviceEngagementBytes, EReaderKeyBytes, Handover]
    // For dc_api, DeviceEngagementBytes and EReaderKeyBytes MUST be null
    const sessionTranscript = cbor2.encode([null, null, handover]);
    return sessionTranscript;
}