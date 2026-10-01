import { USER_PROVIDED_TRUST_LIST, UntrustedReason } from './constants.js';
import {
    getAuthorityKeyIdentifier,
    getCertificateDisplayName,
    getSubjectKeyIdentifier,
    parsePemCertificate,
    validateCertificateAgainstIssuer,
} from './certificate-helper.js';

export const normalizeIssuerCertificates = (trustedIssuerCertificates = []) => {
    const localIssuers = {};
    if(!Array.isArray(trustedIssuerCertificates)) return localIssuers;
    for(const trustedIssuerCertificate of trustedIssuerCertificates) {
        const certInfo = normalizeLocalIssuerCertificate(
            trustedIssuerCertificate);
        const subjectKeyIdentifier = certInfo.subjectKeyIdentifier;
        if(!localIssuers[subjectKeyIdentifier])
            localIssuers[subjectKeyIdentifier] = [];
        localIssuers[subjectKeyIdentifier].push(certInfo.issuer);
    }
    return localIssuers;
};

export const getIssuerForCertificate = async (certificate, localIssuers = {})=>{
    if(!certificate) {
        return {
            untrustedReason:UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_MISSING,
        };
    }
    if(!hasLocalIssuers(localIssuers))
        return { untrustedReason: UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND};

    const aki = getAuthorityKeyIdentifier(certificate);
    if(!aki) {
        return {
            untrustedReason: UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_AKI_MISSING,
        };
    }

    const matchingIssuers = localIssuers[aki] || [];
    const matchedCertificate = await validateCertificateAgainstIssuer(
        certificate,
        matchingIssuers.map(issuer => issuer.certificate)
    );
    if(!matchedCertificate) {
        return {
            untrustedReason: UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND,
        };
    }

    const issuer = matchingIssuers.find(
        issuer => issuer.certificate === matchedCertificate);

    return {
        issuer: {
            ...issuer,
            display: { ...issuer.display },
            entity_metadata: { ...issuer.entity_metadata },
            certificate: { ...issuer.certificate },
        },
    };
};

const hasLocalIssuers = (localIssuers) => {
    return localIssuers && typeof localIssuers === 'object'
        && Object.keys(localIssuers).length > 0;
};

const normalizeLocalIssuerCertificate = (issuerCertificate) => {
    const options = typeof issuerCertificate === 'string'
        ? { data: issuerCertificate }
        : { ...issuerCertificate };

    if(typeof options.data !== 'string') {
        throw new Error('trustedIssuerCertificates entries must be PEM strings or objects with a data PEM string');
    }
    if(options.format && options.format !== 'pem') {
        throw new Error(`Unsupported issuer certificate format: ${options.format}`);
    }

    const parsedCertificate = parsePemCertificate(options.data);
    const subjectKeyIdentifier = getSubjectKeyIdentifier(parsedCertificate);
    if(!subjectKeyIdentifier) {
        throw new Error('trustedIssuerCertificates entries must include a Subject Key Identifier extension');
    }

    const issuerId = `x509_aki:${subjectKeyIdentifier}`;
    const display = { ...(options.display || {}) };
    if(!display.name)
        display.name = getCertificateDisplayName(parsedCertificate) || issuerId;

    const certificate = {
        data: options.data,
        format: 'pem',
        trust_lists: [USER_PROVIDED_TRUST_LIST],
    };

    return {
        subjectKeyIdentifier,
        issuer: {
            issuer_id: issuerId,
            entity_type: options.entity_type || 'other',
            entity_metadata: { ...(options.entity_metadata || {}) },
            display,
            certificate,
        },
    };
};
