import * as cbor2 from 'cbor2';
import { CoseAlgToWebCrypto, REVERSE_CLAIM_MAPPINGS, CredentialFormat } from '../constants.js';
import { parseX5Chain, x509ToSpkiKey, getAuthorityKeyIdentifier } from '../CertificateHelper.js';
import { verifyCoseSign1 } from '../COSEHelper.js';
import { base64urlToBuffer } from '../utils.js';

export const decodeVpToken = async (vp_token) => {
    const buffer = base64urlToBuffer(vp_token);
    const decoded = await cbor2.decode(buffer);
    return decoded;
};

export const verifyDocument = async (document) => {
    const claims = {}
    const { docType, issuerSigned, deviceSigned } = document;
    const { issuerAuth, nameSpaces } = issuerSigned;
    let { valid, issuerAuthPayload } = await verifyIssuerAuth(issuerAuth);
    if(!valid) throw new Error('Issuer certificate verification failed');
    for(let namespace in nameSpaces) {
        for(let claim of nameSpaces[namespace]) {
            await setClaim(claims, docType, namespace, claim, issuerAuthPayload);
        }
    }
    return {
        claims: claims,
    }
}

export const verifyIssuerAuth = async (issuerAuth) => {
    const [protectedHeadersRaw, unprotectedHeaders, payloadRaw, signatureRaw] = issuerAuth;
    const protectedHeaders = await cbor2.decode(protectedHeadersRaw);
    const payload = await cbor2.decode(payloadRaw);
    const alg = protectedHeaders.get(1);
    const webCryptoAlg = CoseAlgToWebCrypto[alg];
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
        return false;
    }

    const publicKey = await x509ToSpkiKey(certificate, alg);
    const signatureValid = await verifyCoseSign1(issuerAuth, publicKey, webCryptoAlg);

    const akid = getAuthorityKeyIdentifier(certificate);

    return {
        certificate: certificate,
        issuerAuthPayload: cbor2.decode(payload.contents),
        publicKey: publicKey,
        valid: signatureValid,
    };
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

function uint8ArrayBytewiseEqual(a, b) {
    return a.length === b.length && a.every((value, index) => value === b[index]);
}