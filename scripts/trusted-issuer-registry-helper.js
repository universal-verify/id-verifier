import TrustedIssuerRegistry from 'trusted-issuer-registry';
import {
    getAuthorityKeyIdentifier,
    getMatchingIssuerCertificates,
} from './certificate-helper.js';

let registry = new TrustedIssuerRegistry();
const WARNING_INTERVAL_MS = 24 * 60 * 60 * 1000;

let priorWarning = 0;

/**
 * Sets whether to use the trusted-issuer-registry's test data
 * @param {boolean} useTestData - Whether to use test data
 */
export const setTestDataUsage = (useTestData) => {
    registry = new TrustedIssuerRegistry({ useTestData });
    priorWarning = 0;
};

export const getIssuerCandidatesForCertificate = async (certificate) => {
    if(!certificate) return [];

    const aki = getAuthorityKeyIdentifier(certificate);
    if(!aki) return [];

    checkRegistryDeprecation();//No need to wait for this to complete
    const issuer = await registry.getIssuerFromX509AKI(aki);
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

async function checkRegistryDeprecation() {
    try {
        const endOfLifeDate = await registry.getEndOfLifeDate();
        if(endOfLifeDate && priorWarning < Date.now() - WARNING_INTERVAL_MS) logEndOfLifeWarning(endOfLifeDate);
    } catch(error) {
        console.error('Error encountered while trying to get trusted-issuer-registry end of life date');
        console.error(error);
    }
}

function logEndOfLifeWarning(endOfLifeDate) {
    if(endOfLifeDate.getTime() < Date.now()) {
        console.warn(`trusted-issuer-registry minor version ${TrustedIssuerRegistry.minorVersion} has reached its end of life, please update to the latest major/minor version as soon as possible to receive the latest issuer information`);
    } else {
        console.warn(`trusted-issuer-registry minor version ${TrustedIssuerRegistry.minorVersion} reaching end of life on ${endOfLifeDate.toISOString().split('T')[0]}, please update to the latest major/minor version before then to avoid outdated issuer information`);
    }
    priorWarning = Date.now();
}
