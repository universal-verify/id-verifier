import TrustedIssuerRegistry from 'trusted-issuer-registry';
import { UntrustedReason } from './constants.js';
import { getAuthorityKeyIdentifier, validateCertificateAgainstIssuer } from './certificate-helper.js';

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

export const getIssuerForCertificate = async (certificate) => {
    try {
        if(!certificate) {
            return {
                untrustedReason: UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_MISSING,
            };
        }
        const aki = getAuthorityKeyIdentifier(certificate);
        if(!aki) {
            return {
                untrustedReason: UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_AKI_MISSING,
            };
        }
        checkRegistryDeprecation();//No need to wait for this to complete
        const issuer = await registry.getIssuerFromX509AKI(aki);
        if(!issuer) {
            return {
                untrustedReason: UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND,
            };
        }

        // Validate certificate against one of the certificates in issuer.certificates[].certificate (which is a string PEM)
        const matchedCertificate = await validateCertificateAgainstIssuer(certificate, issuer.certificates);
        if (matchedCertificate) {
            delete issuer.certificates;
            issuer.certificate = matchedCertificate;
            return { issuer: issuer };
        }

        return {
            untrustedReason: UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND,
        };
    } catch(error) {
        console.error('Error getting issuer', error);
        return { untrustedReason: UntrustedReason.ISSUER_FETCH_FAILED };
    }
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
