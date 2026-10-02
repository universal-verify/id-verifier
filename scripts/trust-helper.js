import { TrustList, UntrustedReason, USER_PROVIDED_TRUST_LIST } from './constants.js';
import { checkCertificateRevocation } from './crl-helper.js';
import {
    getAuthorityKeyIdentifier,
    getDocumentSignerCertificateValidityReason,
    getIssuerCertificateValidityReason,
} from './certificate-helper.js';
import { getIssuerCandidatesForCertificate as getLocalIssuerCandidates } from './local-issuer-helper.js';
import { getIssuerCandidatesForCertificate as getRegistryIssuerCandidates } from './trusted-issuer-registry-helper.js';

export const getDocumentTrustInfo = async (certificate, options = {}) => {
    const untrustedReason = checkIfCertificateHasIssuerInfo(certificate);
    if(untrustedReason) {
        return {
            issuer: null,
            trusted: false,
            untrustedReasons: [untrustedReason],
        };
    }
    const signerCertInvalidReason = getDocumentSignerCertificateValidityReason(
        certificate);

    const { issuer, untrustedReasons } = await getIssuer(certificate, options);
    if(signerCertInvalidReason) untrustedReasons.push(signerCertInvalidReason);

    if(!issuer) {
        return {
            issuer: null,
            trusted: false,
            untrustedReasons: untrustedReasons,
        };
    }

    if(untrustedReasons.length === 0 && options.checkCRL) {
        const revocation = await checkCertificateRevocation(certificate, issuer.certificate, options);
        if(revocation.revoked) untrustedReasons.push(UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_REVOKED);
    }

    return {
        issuer: issuer,
        trusted: untrustedReasons.length === 0,
        untrustedReasons: untrustedReasons,
    };
};

const checkIfCertificateHasIssuerInfo = (certificate) => {
    if(!certificate) return UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_MISSING;
    if(!getAuthorityKeyIdentifier(certificate))
        return UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_AKI_MISSING;
};

const getIssuer = async (certificate, options = {}) => {
    let registryFetchFailed = false;
    const candidates = await getLocalIssuerCandidates(certificate,
        options.trustedIssuerCertificates);
    if(options.trustedIssuerRegistryEnabled !== false) {
        try {
            candidates.push(...await getRegistryIssuerCandidates(certificate));
        } catch(error) {
            registryFetchFailed = true;
        }
    }
    if(candidates.length === 0) {
        return {
            issuer: null,
            untrustedReasons: [registryFetchFailed
                ? UntrustedReason.ISSUER_FETCH_FAILED
                : UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND],
        };
    }
    for(const candidate of candidates) {
        const reason = getIssuerCertificateValidityReason(candidate.certificate);
        const trusted = isIssuerTrustedByTrustLists(candidate, options.trustLists);
        if(!reason && trusted) return {
            issuer: candidate,
            untrustedReasons: [],
        };
    }
    const issuer = candidates[0];
    const reason = getIssuerCertificateValidityReason(issuer.certificate);
    const trusted = isIssuerTrustedByTrustLists(issuer, options.trustLists);
    const untrustedReasons = [];
    if(reason) untrustedReasons.push(reason);
    if(!trusted) untrustedReasons.push(UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS);

    return { issuer, untrustedReasons };
};

const isIssuerTrustedByTrustLists = (issuer, trustLists) => {
    if(!Array.isArray(issuer.certificate?.trust_lists)) return false;
    if(issuer.certificate.trust_lists.includes(USER_PROVIDED_TRUST_LIST)) return true;
    if(!trustLists) trustLists = Object.values(TrustList);
    return issuer.certificate.trust_lists.some(trustList => trustLists.includes(trustList));
};
