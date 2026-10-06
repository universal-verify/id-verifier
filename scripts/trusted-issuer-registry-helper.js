import { Registry } from 'trusted-issuer-registry';

const WARNING_INTERVAL_MS = 24 * 60 * 60 * 1000;
let priorWarning = 0;

export async function checkRegistryDeprecation(registry) {
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
        console.warn(`trusted-issuer-registry minor version ${Registry.minorVersion} has reached its end of life, please update to the latest major/minor version as soon as possible to receive the latest issuer information`);
    } else {
        console.warn(`trusted-issuer-registry minor version ${Registry.minorVersion} reaching end of life on ${endOfLifeDate.toISOString().split('T')[0]}, please update to the latest major/minor version before then to avoid outdated issuer information`);
    }
    priorWarning = Date.now();
}
