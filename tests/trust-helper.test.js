import test from 'node:test';
import assert from 'node:assert/strict';
import { getDocumentTrustInfo } from '../scripts/trust-helper.js';
import { UntrustedReason } from '../scripts/constants.js';

test('getDocumentTrustInfo reports missing document signer certificate when registry is unavailable', async () => {
    const trustInfo = await getDocumentTrustInfo(null, { registryEnabled: false });

    assert.equal(trustInfo.trusted, false);
    assert.equal(trustInfo.issuer, null);
    assert.deepEqual(trustInfo.untrustedReasons, [UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_MISSING]);
});

test('getDocumentTrustInfo reports missing issuer certificate when registry is unavailable', async () => {
    const trustInfo = await getDocumentTrustInfo({ certificate: 'test' }, { registryEnabled: false });

    assert.equal(trustInfo.trusted, false);
    assert.equal(trustInfo.issuer, null);
    assert.deepEqual(trustInfo.untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND]);
});
