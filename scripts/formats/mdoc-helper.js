import * as cbor2 from 'cbor2';
import { getIssuer } from '../trusted-issuer-registry-helper.js';
import { REVERSE_CLAIM_MAPPINGS, CredentialFormat } from '../constants.js';
import { parseX5Chain, x509ToWebCryptoKey } from '../certificate-helper.js';
import { verifyCoseSign1, coseKeyToWebCryptoKey } from '../cose-helper.js';
import { base64urlToUint8Array } from '../utils.js';

export const decodeVpToken = async (vp_token) => {
    const uint8Array = base64urlToUint8Array(vp_token);
    const decoded = await cbor2.decode(uint8Array);
    return decoded;
};

export const verifyDocument = async (document, sessionTranscript) => {
    const claims = {};
    const { docType, issuerSigned, deviceSigned } = document;
    const { issuerAuth, nameSpaces } = issuerSigned;
    const { valid, issuerAuthPayload, certificate } = await verifyIssuerAuth(issuerAuth);
    if(!valid) throw new Error('Issuer certificate verification failed');
    if(sessionTranscript) {
        const deviceValid = await verifyDeviceAuth(deviceSigned, issuerAuthPayload, sessionTranscript);
        if(!deviceValid) throw new Error('Failed to verify device authentication');
    } else {
        console.warn('Skipping deviceAuth verification, likely due to missing origin and/or nonce in verifyCredentials call');
    }
    for(const namespace in nameSpaces) {
        for(const claim of nameSpaces[namespace]) {
            await setClaim(claims, docType, namespace, claim, issuerAuthPayload);
        }
    }
    const trustedIssuer = await getIssuer(certificate);
    return {
        claims: claims,
        trustedIssuer: trustedIssuer,
    };
};

async function verifyIssuerAuth(issuerAuth) {
    const [protectedHeadersRaw, unprotectedHeaders, payloadRaw, _signatureRaw] = issuerAuth;
    const protectedHeaders = await cbor2.decode(protectedHeadersRaw);
    const payload = await cbor2.decode(payloadRaw);
    const issuerAuthPayload = cbor2.decode(payload.contents); //This is the Mobile Security Object (MSO)
    const now = new Date();
    if(new Date(issuerAuthPayload.validityInfo.validFrom) > now) {
        throw new Error('Credential is not yet valid');
    } else if(new Date(issuerAuthPayload.validityInfo.validUntil) < now) {
        throw new Error('Credential is expired');
    }
    const coseAlg = protectedHeaders.get(1);
    //https://datatracker.ietf.org/doc/rfc9360/
    const x5bag = unprotectedHeaders.get(32);
    const x5chain = unprotectedHeaders.get(33);
    const x5t = unprotectedHeaders.get(34);
    const x5u = unprotectedHeaders.get(35);
    let certificate;
    if(x5bag) {
    } else if(x5chain) {
        certificate = parseX5Chain(x5chain);
    } else if(x5t) {
    } else if(x5u) {
    } else {
        return { valid: false };
    }

    const publicKey = await x509ToWebCryptoKey(certificate, coseAlg);
    const signatureValid = await verifyCoseSign1(issuerAuth, publicKey);

    return {
        certificate: certificate,
        issuerAuthPayload: issuerAuthPayload,
        publicKey: publicKey,
        valid: signatureValid,
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
    if(!isValid) throw new Error('Claim verification failed');
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