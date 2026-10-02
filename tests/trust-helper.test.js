import test from 'node:test';
import assert from 'node:assert/strict';
import { getDocumentTrustInfo } from '../scripts/trust-helper.js';
import { TrustList, UntrustedReason } from '../scripts/constants.js';
import { parsePemCertificate } from '../scripts/certificate-helper.js';
import { normalizeIssuerCertificates } from '../scripts/local-issuer-helper.js';

const TEST_IACA_CERT = `-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIUbHUBhA6c7mDVnFLnyOOk1xYW4y0wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJVGVzdCBJQUNBMB4XDTI2MDkyNjE4MTExMloXDTM2MDkyMzE4
MTExMlowFDESMBAGA1UEAwwJVGVzdCBJQUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEKuHmTNyXR4teRBzniaPBMt7b8RfnvIqwq3Ed7ycmpU7B4lusX4fGZROy
vSYH9q8/ITQhiaFkrODt9jNb2aoph6NmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAO
BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFKE40Bi/qWwHQYcDQVp64R8lZJLiMB8G
A1UdIwQYMBaAFKE40Bi/qWwHQYcDQVp64R8lZJLiMAoGCCqGSM49BAMCA0gAMEUC
IB/Sf/Rrfe/NtvP40wiqvxgh4tmsaFhb4NafBER6zj1CAiEAyiGwvQoWBMzFPDW6
9Mf/Q3Yuy5xMPy2WiUkJeN2BjTY=
-----END CERTIFICATE-----`;
const TEST_DOCUMENT_SIGNER_CERT = `-----BEGIN CERTIFICATE-----
MIIBtTCCAVugAwIBAgICEAEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJ
QUNBMB4XDTI2MDkyNDE3MDQ0OFoXDTM2MDkyMTE3MDQ0OFowHzEdMBsGA1UEAwwU
VGVzdCBEb2N1bWVudCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATF
PicZCdTSGicPpPr5zF/SNR3BDp1E6zztbeE0n+Gw5QqlTq+yNXxC/Mph7h2sc2VW
VeFpA837cQie/hOFUmpco4GRMIGOMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
AgeAMB0GA1UdDgQWBBTLxDfKjx3XTsN01efByUymRC7d3jAfBgNVHSMEGDAWgBSh
ONAYv6lsB0GHA0FaeuEfJWSS4jAuBgNVHR8EJzAlMCOgIaAfhh1odHRwczovL2V4
YW1wbGUudGVzdC90ZXN0LmNybDAKBggqhkjOPQQDAgNIADBFAiEAhjxW7T429LPy
riSTqnSboT2Y0Olasia1B9Cge8knIEICIG0A5O9wuioXSniU/5ryATtJjHvQN0j/
JikmryiDWnYJ
-----END CERTIFICATE-----`;

test('getDocumentTrustInfo reports missing document signer certificate when registry is unavailable', async () => {
    const trustInfo = await getDocumentTrustInfo(null, { trustedIssuerRegistryEnabled: false });

    assert.equal(trustInfo.trusted, false);
    assert.equal(trustInfo.issuer, null);
    assert.deepEqual(trustInfo.untrustedReasons, [UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_MISSING]);
});

test('getDocumentTrustInfo reports missing issuer certificate when registry is unavailable', async () => {
    const trustInfo = await getDocumentTrustInfo({ certificate: 'test' }, { trustedIssuerRegistryEnabled: false });

    assert.equal(trustInfo.trusted, false);
    assert.equal(trustInfo.issuer, null);
    assert.deepEqual(trustInfo.untrustedReasons, [UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_AKI_MISSING]);
});

test('getDocumentTrustInfo trusts a document signer from a user-provided issuer certificate', async () => {
    const trustedIssuerCertificates = normalizeIssuerCertificates([TEST_IACA_CERT]);
    const trustInfo = await getDocumentTrustInfo(parsePemCertificate(TEST_DOCUMENT_SIGNER_CERT), {
        trustedIssuerRegistryEnabled: false,
        trustLists: [TrustList.UV],
        trustedIssuerCertificates,
    });

    assert.equal(trustInfo.trusted, true);
    assert.deepEqual(trustInfo.untrustedReasons, []);
    assert.equal(trustInfo.issuer.issuer_id, 'x509_aki:oTjQGL-pbAdBhwNBWnrhHyVkkuI');
    assert.equal(trustInfo.issuer.entity_type, 'other');
    assert.deepEqual(trustInfo.issuer.entity_metadata, {});
    assert.deepEqual(trustInfo.issuer.display, { name: 'Test IACA' });
    assert.deepEqual(trustInfo.issuer.certificate.trust_lists, ['user_provided']);
});

test('normalizeIssuerCertificates preserves user metadata and fills missing display name', () => {
    const trustedIssuerCertificates = normalizeIssuerCertificates([{
        data: TEST_IACA_CERT,
        entity_type: 'government',
        entity_metadata: {
            country: 'US',
        },
        display: {
            logo: 'https://example.test/logo.png',
        },
    }]);
    const issuer = trustedIssuerCertificates['oTjQGL-pbAdBhwNBWnrhHyVkkuI'];

    assert.equal(issuer.entity_type, 'government');
    assert.deepEqual(issuer.entity_metadata, {
        country: 'US',
    });
    assert.deepEqual(issuer.display, {
        logo: 'https://example.test/logo.png',
        name: 'Test IACA',
    });
});

test('normalizeIssuerCertificates preserves provided display name', () => {
    const trustedIssuerCertificates = normalizeIssuerCertificates([{
        data: TEST_IACA_CERT,
        display: {
            name: 'Custom Issuer Name',
        },
    }]);

    assert.deepEqual(trustedIssuerCertificates['oTjQGL-pbAdBhwNBWnrhHyVkkuI'].display, {
        name: 'Custom Issuer Name',
    });
});


test('normalizeIssuerCertificates groups certificates with the same subject key identifier', () => {
    const trustedIssuerCertificates = normalizeIssuerCertificates([
        TEST_IACA_CERT,
        {
            data: TEST_IACA_CERT,
            display: {
                name: 'Ignored Duplicate Name',
            },
        },
    ]);
    const issuer = trustedIssuerCertificates['oTjQGL-pbAdBhwNBWnrhHyVkkuI'];

    assert.equal(issuer.display.name, 'Test IACA');
    assert.equal(issuer.certificates.length, 2);
});
