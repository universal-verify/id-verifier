import { USER_PROVIDED_TRUST_LIST } from './constants.js';
import {
    getAuthorityKeyIdentifier,
    getCertificateDisplayName,
    getMatchingIssuerCertificates,
    getSubjectKeyIdentifier,
    parsePemCertificate,
} from './certificate-helper.js';

export const normalizeIssuerCertificates = (trustedIssuerCertificates = []) => {
    const localIssuers = {};
    if(!Array.isArray(trustedIssuerCertificates)) return localIssuers;
    for(const trustedIssuerCertificate of trustedIssuerCertificates) {
        const certInfo = normalizeIssuerCertificate(trustedIssuerCertificate);
        const subjectKeyIdentifier = certInfo.subjectKeyIdentifier;
        if(!localIssuers[subjectKeyIdentifier]) {
            localIssuers[subjectKeyIdentifier] = certInfo.issuer;
        } else {
            localIssuers[subjectKeyIdentifier].certificates.push(...certInfo.issuer.certificates);
        }
    }
    return localIssuers;
};

export const getIssuerCandidatesForCertificate = async (certificate, localIssuers = {}) => {
    if(!certificate || !hasLocalIssuers(localIssuers)) return [];

    const aki = getAuthorityKeyIdentifier(certificate);
    if(!aki) return [];

    const issuer = localIssuers[aki];
    if(!issuer) return [];

    const matchingCertificates = await getMatchingIssuerCertificates(certificate, issuer.certificates);
    return matchingCertificates.map(matchedCertificate =>
        createIssuerCandidate(issuer, matchedCertificate));
};

const createIssuerCandidate = (issuer, certificate) => {
    const { certificates: _certificates, ...issuerFields } = issuer;

    return {
        ...issuerFields,
        display: { ...(issuer.display || {}) },
        entity_metadata: { ...(issuer.entity_metadata || {}) },
        certificate: {
            ...certificate,
            trust_lists: [...(certificate.trust_lists || [])],
        },
    };
};

const hasLocalIssuers = (localIssuers) => {
    return localIssuers && typeof localIssuers === 'object'
        && Object.keys(localIssuers).length > 0;
};

const normalizeIssuerCertificate = (issuerCertificate) => {
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
            certificates: [certificate],
        },
    };
};
