import { ALL_TRUST_LISTS, UntrustedReason } from './constants.js';
import { checkCertificateRevocation } from './crl-helper.js';
import { getIssuerForCertificate } from './trusted-issuer-registry-helper.js';

export const getDocumentTrustInfo = async (certificate, options = {}) => {
    const { issuer, untrustedReasons } = options.registryEnabled === false
        ? getUnavailableRegistryTrustInfo(certificate)
        : await getRegistryTrustInfo(certificate);

    if(!issuer) {
        return {
            issuer: null,
            trusted: false,
            untrustedReasons: untrustedReasons.length > 0 ? untrustedReasons : [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND],
        };
    }

    if(!isIssuerTrustedByTrustLists(issuer, options.trustLists || ALL_TRUST_LISTS)) {
        untrustedReasons.push(UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS);
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

const getUnavailableRegistryTrustInfo = (certificate) => {
    return {
        issuer: null,
        untrustedReasons: [
            certificate
                ? UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND
                : UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_MISSING
        ],
    };
};

const getRegistryTrustInfo = async (certificate) => {
    const { issuer, untrustedReason } = await getIssuerForCertificate(certificate);
    return {
        issuer: issuer || null,
        untrustedReasons: untrustedReason ? [untrustedReason] : [],
    };
};

const isIssuerTrustedByTrustLists = (issuer, trustLists) => {
    const requestedTrustLists = Array.isArray(trustLists) ? trustLists : [trustLists];
    if(trustLists == ALL_TRUST_LISTS || requestedTrustLists.includes(ALL_TRUST_LISTS[0])) return true;
    if(!Array.isArray(issuer.certificate?.trust_lists)) return false;
    return issuer.certificate.trust_lists.some(trustList => requestedTrustLists.includes(trustList));
};
