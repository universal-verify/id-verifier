import TrustedIssuerRegistry from 'trusted-issuer-registry';
import { getAuthorityKeyIdentifier, validateCertificateAgainstIssuer } from './certificate-helper.js';

let registry = new TrustedIssuerRegistry();
const ONE_DAY = 24 * 60 * 60 * 1000;

let endOfLifeDate, priorWarning;
let priorCheck = 0;

/**
 * Sets whether to use the trusted-issuer-registry's test data
 * @param {boolean} useTestData - Whether to use test data
 */
export const setTestDataUsage = (useTestData) => {
    registry = new TrustedIssuerRegistry({ useTestData });
    priorCheck = 0;
    priorWarning = 0;
    endOfLifeDate = null;
}

export const getIssuer = async (certificate) => {
    try {
        const aki = getAuthorityKeyIdentifier(certificate);
        if(!aki) return null;
        checkRegistryDeprecation();//No need to wait for this to complete
        const issuer = await registry.getIssuerFromX509AKI(aki);
        if(!issuer) return null;

        // Validate certificate against one of the certificates in issuer.certificates[].certificate (which is a string PEM)
        const matchedCertificate = await validateCertificateAgainstIssuer(certificate, issuer.certificates);
        if (matchedCertificate) {
            delete issuer.certificates;
            issuer.certificate = matchedCertificate;
            return issuer;
        }

        return null;
    } catch(error) {
        console.error('Error getting issuer', error);
        return null;
    }
};

async function checkRegistryDeprecation() {
    if(endOfLifeDate) {
        if(priorWarning < Date.now() - ONE_DAY) logEndOfLifeWarning();
    } else if(priorCheck < Date.now() - ONE_DAY) {
        try {
            endOfLifeDate = await registry.getEndOfLifeDate();
        } catch(error) {
            console.error('Error encountered while trying to get trusted-issuer-registry end of life date');
            console.error(error);
        }
        if(endOfLifeDate) logEndOfLifeWarning();
        priorCheck = Date.now();
    }
}

function logEndOfLifeWarning() {
    if(endOfLifeDate.getTime() < Date.now()) {
        console.warn(`trusted-issuer-registry minor version ${TrustedIssuerRegistry.minorVersion} has reached its end of life, please update to the latest major/minor version as soon as possible to receive the latest issuer information`);
    } else {
        console.warn(`trusted-issuer-registry minor version ${TrustedIssuerRegistry.minorVersion} reaching end of life on ${endOfLifeDate.toISOString().split('T')[0]}, please update to the latest major/minor version before then to avoid outdated issuer information`);
    }
    priorWarning = Date.now();
}