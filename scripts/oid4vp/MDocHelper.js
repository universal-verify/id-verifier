import * as cbor2 from 'cbor2';
import TrustedIssuerRegistry from 'trusted-issuer-registry';
import { CoseAlgToWebCrypto, REVERSE_CLAIM_MAPPINGS, CredentialFormat } from '../constants.js';
import { parseX5Chain, x509ToWebCryptoKey, getAuthorityKeyIdentifier, validateCertificateAgainstIssuer } from '../CertificateHelper.js';
import { verifyCoseSign1, coseKeyToWebCryptoKey } from '../COSEHelper.js';
import { base64urlToUint8Array } from '../utils.js';

const registry = new TrustedIssuerRegistry({ useTestIssuers: true });

export const decodeVpToken = async (vp_token) => {
    const uint8Array = base64urlToUint8Array(vp_token);
    const decoded = await cbor2.decode(uint8Array);
    return decoded;
};

export const verifyDocument = async (document, sessionTranscript) => {
    const claims = {}
    const { docType, issuerSigned, deviceSigned } = document;
    const { issuerAuth, nameSpaces } = issuerSigned;
    let { valid, issuerAuthPayload, certificate } = await verifyIssuerAuth(issuerAuth);
    if(!valid) throw new Error('Issuer certificate verification failed');
    if(sessionTranscript) {
        valid = await verifyDeviceAuth(deviceSigned, issuerAuthPayload, sessionTranscript);
        if(!valid) throw new Error('Failed to verify device authentication');
    } else {
        console.warn("Skipping deviceAuth verification, likely due to missing origin and/or nonce in verifyCredentials call");
    }
    for(let namespace in nameSpaces) {
        for(let claim of nameSpaces[namespace]) {
            await setClaim(claims, docType, namespace, claim, issuerAuthPayload);
        }
    }
    const trustedIssuer = await getIssuer(certificate);
    return {
        claims: claims,
        trustedIssuer: trustedIssuer,
    }
}

async function verifyIssuerAuth(issuerAuth) {
    const [protectedHeadersRaw, unprotectedHeaders, payloadRaw, signatureRaw] = issuerAuth;
    const protectedHeaders = await cbor2.decode(protectedHeadersRaw);
    const payload = await cbor2.decode(payloadRaw);
    const issuerAuthPayload = cbor2.decode(payload.contents); //This is the Mobile Security Object (MSO)
    let now = new Date();
    if(new Date(issuerAuthPayload.validityInfo.validFrom) > now) {
        throw new Error('Credential is not yet valid');
    } else if(new Date(issuerAuthPayload.validityInfo.validUntil) < now) {
        throw new Error('Credential is expired');
    }
    const coseAlg = protectedHeaders.get(1);
    //https://datatracker.ietf.org/doc/rfc9360/
    let x5bag = unprotectedHeaders.get(32);
    let x5chain = unprotectedHeaders.get(33);
    let x5t = unprotectedHeaders.get(34);
    let x5u = unprotectedHeaders.get(35);
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
    let { isValid, decodedClaim } = await verifyClaim(namespace, claim, issuerAuthPayload);
    if(!isValid) throw new Error('Claim verification failed');
    let claimValue = decodedClaim.elementValue;
    if(claimValue.tag === 1004) {
        claimValue = claimValue.contents;
    } else if(namespace === 'org.iso.18013.5.1') {
        if(decodedClaim.elementIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        } else if(decodedClaim.elementIdentifier === 'driving_privileges' && claimValue && claimValue.length > 0) {
            for(let privilege of claimValue) {
                for(let key in privilege) {
                    if(privilege[key]?.tag === 1004) {
                        privilege[key] = privilege[key].contents;
                    }
                }
            }
        }
    } else if(namespace === 'org.iso.23220.1') {
        if(decodedClaim.elementIdentifier === 'birth_date' && claimValue.birth_date && claimValue.birth_date.tag === 1004) {
            claimValue = claimValue.birth_date.contents;
        } else if(decodedClaim.elementIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        }
    } else if(namespace === 'eu.europa.ec.eudi.pid.1') {
        if(decodedClaim.elementIdentifier === 'sex' && typeof claimValue === 'number') {
            claimValue = claimValue === 1 ? 'M' : claimValue === 2 ? 'F' : null;
        }
    }
    let claimIdentifier = decodedClaim.elementIdentifier;
    let reverseClaimMapping = REVERSE_CLAIM_MAPPINGS[CredentialFormat.MSO_MDOC][docType][claimIdentifier];
    if(reverseClaimMapping) claimIdentifier = reverseClaimMapping;
    claims[claimIdentifier] = claimValue;
}

async function verifyClaim(namespace, claim, issuerAuthPayload) {
    let decodedClaim = cbor2.decode(claim.contents);
    let digestId = decodedClaim.digestID;
    let digest = issuerAuthPayload.valueDigests[namespace].get(digestId);
    let encodedClaim = cbor2.encode(claim);
    let sha256 = await crypto.subtle.digest('SHA-256', encodedClaim);
    let sha256Uint8Array = new Uint8Array(sha256);
    return {
        isValid: uint8ArrayBytewiseEqual(sha256Uint8Array, digest),
        decodedClaim: decodedClaim
    };
}

async function getIssuer(certificate) {
    try {
        const aki = getAuthorityKeyIdentifier(certificate);
        if(!aki) return null;
        const issuer = await registry.getIssuerFromX509AKI(aki);
        if(!issuer) return null;
        
        // Validate certificate against one of the certificates in issuer.certificates[].certificate (which is a string PEM)
        if (await validateCertificateAgainstIssuer(certificate, issuer.certificates)) {
            return issuer;
        }
        
        return null;
    } catch(error) {
        console.error('Error getting issuer', error);
        return null;
    }
}

function uint8ArrayBytewiseEqual(a, b) {
    return a.length === b.length && a.every((value, index) => value === b[index]);
}