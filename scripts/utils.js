export const base64urlToBuffer = (base64url) => {
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
    
};

export const bufferToBase64Url = (input) => {
    let bytes;
    if (input instanceof ArrayBuffer) {
      bytes = new Uint8Array(input);
    } else if (input.buffer instanceof ArrayBuffer) {
      bytes = new Uint8Array(input.buffer);
    } else {
      throw new Error("Invalid input type");
    }
  
    // Convert to base64 string
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    let base64 = typeof btoa !== 'undefined'
      ? btoa(binary)
      : Buffer.from(binary, 'binary').toString('base64');
  
    // Convert base64 to base64url
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }