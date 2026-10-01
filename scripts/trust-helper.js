import { TrustList, UntrustedReason, USER_PROVIDED_TRUST_LIST } from './constants.js';
import { checkCertificateRevocation } from './crl-helper.js';
import { getIssuerForCertificate as getIssuerFromLocalCertificates } from './local-issuer-helper.js';
import { getIssuerForCertificate as getIssuerFromRegistry } from './trusted-issuer-registry-helper.js';

export const getDocumentTrustInfo = async (certificate, options = {}) => {
    const { issuer, untrustedReasons } = await getIssuerTrustInfo(certificate, options);

    if(!issuer) {
        return {
            issuer: null,
            trusted: false,
            untrustedReasons: untrustedReasons.length > 0 ? untrustedReasons : [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND],
        };
    }

    if(!isIssuerTrustedByTrustLists(issuer, options.trustLists)) {
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

const getIssuerTrustInfo = async (certificate, options = {}) => {
    let result = await getIssuerFromLocalCertificates(certificate, options.trustedIssuerCertificates);

    if(!result.issuer && options.trustedIssuerRegistryEnabled !== false) {
        result = await getIssuerFromRegistry(certificate);
    }

    return {
        issuer: result.issuer || null,
        untrustedReasons: result.untrustedReason ? [result.untrustedReason] : [],
    };
};

const isIssuerTrustedByTrustLists = (issuer, trustLists) => {
    if(!Array.isArray(issuer.certificate?.trust_lists)) return false;
    if(issuer.certificate.trust_lists.includes(USER_PROVIDED_TRUST_LIST)) return true;
    if(!trustLists) trustLists = Object.values(TrustList);
    return issuer.certificate.trust_lists.some(trustList => trustLists.includes(trustList));
};
