import test from 'node:test';
import assert from 'node:assert/strict';
import {
    certificateToPem,
    getCertificateDisplayName,
    getCertificateSubject,
    getDocumentSignerCertificateValidityReason,
    getIssuerCertificateValidityReason,
    getSubjectKeyIdentifier,
    parsePemCertificate,
} from '../scripts/certificate-helper.js';
import { UntrustedReason } from '../scripts/constants.js';

const TEST_CERT = `-----BEGIN CERTIFICATE-----
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

test('certificateToPem formats a parsed certificate as PEM', () => {
    const certificate = parsePemCertificate(TEST_CERT);
    const pem = certificateToPem(certificate);

    assert.equal(getPemContent(pem), getPemContent(TEST_CERT));
    assert.equal(pem.startsWith('-----BEGIN CERTIFICATE-----\r\n'), true);
    assert.equal(pem.endsWith('\r\n-----END CERTIFICATE-----'), true);
    for(const line of getPemLines(pem)) {
        assert.ok(line.length <= 64);
    }
});

test('certificate helper extracts issuer metadata from a parsed certificate', () => {
    const certificate = parsePemCertificate(TEST_CERT);

    assert.equal(getSubjectKeyIdentifier(certificate), 'oTjQGL-pbAdBhwNBWnrhHyVkkuI');
    assert.deepEqual(getCertificateSubject(certificate), {
        commonName: 'Test IACA',
    });
    assert.equal(getCertificateDisplayName(certificate), 'Test IACA');
});

const getPemContent = (pem) => {
    return pem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');
};

const getPemLines = (pem) => {
    return pem
        .split(/\r?\n/)
        .filter(line => !line.includes('CERTIFICATE') && line.length > 0);
};


test('certificate helper reports certificate validity reasons', () => {
    const certificate = parsePemCertificate(TEST_CERT);

    assert.equal(getDocumentSignerCertificateValidityReason(certificate, new Date('2026-10-01T00:00:00Z')), null);
    assert.equal(
        getDocumentSignerCertificateValidityReason(certificate, new Date('2026-09-01T00:00:00Z')),
        UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_NOT_YET_VALID
    );
    assert.equal(
        getDocumentSignerCertificateValidityReason(certificate, new Date('2037-01-01T00:00:00Z')),
        UntrustedReason.DOCUMENT_SIGNER_CERTIFICATE_EXPIRED
    );
    assert.equal(
        getIssuerCertificateValidityReason({ data: TEST_CERT }, new Date('2026-09-01T00:00:00Z')),
        UntrustedReason.ISSUER_CERTIFICATE_NOT_YET_VALID
    );
    assert.equal(
        getIssuerCertificateValidityReason({ data: TEST_CERT }, new Date('2037-01-01T00:00:00Z')),
        UntrustedReason.ISSUER_CERTIFICATE_EXPIRED
    );
});
