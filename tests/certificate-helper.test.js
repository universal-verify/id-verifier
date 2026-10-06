import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePemCertificate } from 'trusted-issuer-registry';
import { parseX5Chain, x509ToWebCryptoKey } from '../scripts/certificate-helper.js';

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

test('parseX5Chain reads the first signer certificate and handles sliced buffers', () => {
    const certificate = parsePemCertificate(TEST_CERT);
    const bytes = new Uint8Array(certificate.toSchema().toBER());
    const padded = new Uint8Array(bytes.length + 10);
    padded.set(bytes, 5);
    const chainEntry = padded.subarray(5, bytes.length + 5);

    for(const chain of [chainEntry, [chainEntry, new Uint8Array(0)]]) {
        assert.deepEqual(parseX5Chain(chain).toSchema().toBER(), certificate.toSchema().toBER());
    }
    assert.equal(parseX5Chain(null), null);
    assert.equal(parseX5Chain([]), null);
});

test('x509ToWebCryptoKey imports the signer key for COSE signature verification', async () => {
    const key = await x509ToWebCryptoKey(parsePemCertificate(TEST_CERT), -7);

    assert.equal(key.type, 'public');
    assert.deepEqual(key.algorithm, { name: 'ECDSA', namedCurve: 'P-256' });
    assert.deepEqual(key.usages, ['verify']);
});
