import test from 'node:test';
import assert from 'node:assert/strict';
import * as asn1js from 'asn1js';
import { CertificateRevocationList, CRLDistributionPoints, DistributionPoint, IssuingDistributionPoint } from 'pkijs';
import { checkCertificateRevocation } from '../scripts/crl-helper.js';
import { parsePemCertificate } from '../scripts/certificate-helper.js';

const CRL_URL = 'https://example.test/test.crl';
const CACHE_CRL_URL = 'https://example.test/cache.crl';
const MISSING_CRL_URL = 'https://example.test/missing.crl';
const MIRROR_PRIMARY_CRL_URL = 'https://example.test/mirror-primary.crl';
const MIRROR_BACKUP_CRL_URL = 'https://example.test/mirror-backup.crl';
const MIRROR_SLOW_CRL_URL = 'https://example.test/mirror-slow.crl';
const REASON_SCOPED_CRL_URL = 'https://example.test/reason-scoped.crl';
const FULL_COVERAGE_CRL_URL = 'https://example.test/full-coverage.crl';
const STALE_CACHE_CRL_URL = 'https://example.test/stale-cache.crl';
const DELTA_CRL_URL = 'https://example.test/delta.crl';
const FUTURE_CRL_URL = 'https://example.test/future.crl';
const CRL_DISTRIBUTION_POINTS_OID = '2.5.29.31';
const KEY_USAGE_OID = '2.5.29.15';
const DELTA_CRL_INDICATOR_OID = '2.5.29.27';
const KEY_COMPROMISE_REASON_MASK = 1 << 1;
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
const TEST_CACHE_DOCUMENT_SIGNER_CERT = `-----BEGIN CERTIFICATE-----
MIIBtDCCAVmgAwIBAgICEAIwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJ
QUNBMB4XDTI2MDkyNDE3MDQ0OFoXDTM2MDkyMTE3MDQ0OFowHDEaMBgGA1UEAwwR
VGVzdCBDYWNoZSBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3R39p
q9HLS+Vas4Uzu38YYfY7negA9+oZpGRXP+nMXx30Omw/mVEusCnmDQ3xh5vIGYWA
Qul4sXz2Bo9SByKBo4GSMIGPMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
MB0GA1UdDgQWBBR9fP8ysRytGEvr9B7dfT7GCEdG+TAfBgNVHSMEGDAWgBShONAY
v6lsB0GHA0FaeuEfJWSS4jAvBgNVHR8EKDAmMCSgIqAghh5odHRwczovL2V4YW1w
bGUudGVzdC9jYWNoZS5jcmwwCgYIKoZIzj0EAwIDSQAwRgIhAKpMhiBq3uZiiRsm
noMdWVlXnC4igpaER0Dj00ZdHnHDAiEA6o4K0huf2bUbff57+lQpqviBhfcNGALo
lwEE+elzS+c=
-----END CERTIFICATE-----`;
const TEST_MISSING_CRL_DOCUMENT_SIGNER_CERT = `-----BEGIN CERTIFICATE-----
MIIBuzCCAWGgAwIBAgICEAMwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJ
QUNBMB4XDTI2MDkyNDE3MDQ0OFoXDTM2MDkyMTE3MDQ0OFowIjEgMB4GA1UEAwwX
VGVzdCBNaXNzaW5nIENSTCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAS9vE2E7bsEjXRptfDL5nNHkUOkuT7qy3qMG0daEHVhjrmLlksjTqi2HH0UCJgW
mCIM9XAv+7o+9jnfUxwEKmUpo4GUMIGRMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/
BAQDAgeAMB0GA1UdDgQWBBRq8N2FGMLrcZd1BB23VmbgzWr1WzAfBgNVHSMEGDAW
gBShONAYv6lsB0GHA0FaeuEfJWSS4jAxBgNVHR8EKjAoMCagJKAihiBodHRwczov
L2V4YW1wbGUudGVzdC9taXNzaW5nLmNybDAKBggqhkjOPQQDAgNIADBFAiEAnPTm
EG7is4l9UmgBgew/lqQ0OEAzg255TLZ4cSAPEMICID7XKPOeXDt122TXOFlg3Hj9
MbmJMfHPssGg/rg1Hpyo
-----END CERTIFICATE-----`;
const CURRENT_REVOKED_CRL = `-----BEGIN X509 CRL-----
MIHQMHkCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJQUNBFw0yNjA5
MjQxNzA0NDhaFw0zNjAxMDEwMDAwMDBaMCMwIQICEAEXDTI2MDkyNjE4MTExMlow
DDAKBgNVHRUEAwoBAaAPMA0wCwYDVR0UBAQCAhACMAoGCCqGSM49BAMCA0cAMEQC
ICRS/PzlqnbgqF4T/eKiNSU6hoSSwoCWX2JH09MQ+k4EAiBSNVOHy33VMJdrsU1t
lKNNkfnJs79GpV1nEkUaObXvow==
-----END X509 CRL-----`;
const CURRENT_EMPTY_CRL = `-----BEGIN X509 CRL-----
MIGsMFQCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJQUNBFw0yNjA5
MjQxNzA0NDhaFw0zNjAxMDEwMDAwMDBaoA8wDTALBgNVHRQEBAICEAAwCgYIKoZI
zj0EAwIDSAAwRQIgB7OdFVmVr5iCtq84sHlnODgW5N8rOlWlhWeSfJCuv+ICIQC+
ozd2wJmqIomydzGRuXvf6lg49yfOCZIK3oajkK4bQw==
-----END X509 CRL-----`;
const STALE_REVOKED_CRL = `-----BEGIN X509 CRL-----
MIHRMHkCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJQUNBFw0xOTAx
MDEwMDAwMDBaFw0yMDAxMDEwMDAwMDBaMCMwIQICEAEXDTI2MDkyNjE4MTExMlow
DDAKBgNVHRUEAwoBAaAPMA0wCwYDVR0UBAQCAhADMAoGCCqGSM49BAMCA0gAMEUC
IQDng8is6dSoZDyppd4fRfRi3KZXtIIP2cE4K2+DzGJNcQIgLbgx9x5hHgRTAlHn
EbC572w3bl+74ZVfQaAKJcWR4l8=
-----END X509 CRL-----`;
const STALE_EMPTY_CRL = `-----BEGIN X509 CRL-----
MIGsMFQCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJQUNBFw0xOTAx
MDEwMDAwMDBaFw0yMDAxMDEwMDAwMDBaoA8wDTALBgNVHRQEBAICEAEwCgYIKoZI
zj0EAwIDSAAwRQIgIPbhgplWa4OuF3v/UjbKlJd3X+RxKzFz+Puea8fypasCIQCB
O13gcBzpEjbiYrc3V1XQcUUn1eo88MCLGeSpPXy2tA==
-----END X509 CRL-----`;
const INVALID_SIGNATURE_CRL = `-----BEGIN X509 CRL-----
MIGuMFUCAQEwCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwKT3RoZXIgSUFDQRcNMjYw
OTI0MTcwNDQ4WhcNMzYwMTAxMDAwMDAwWqAPMA0wCwYDVR0UBAQCAiAAMAoGCCqG
SM49BAMCA0kAMEYCIQCBV47V/ilex8VFw1oK5JN7eNLmiq5TpAtO7uyelNOhVAIh
AJ/gnL/YvQ365zibIRy9QP4ZNtDPu6t77srO8AL62wyY
-----END X509 CRL-----`;

const issuerCertificate = { data: TEST_IACA_CERT };
const documentSignerCertificate = parsePemCertificate(TEST_DOCUMENT_SIGNER_CERT);
const cacheDocumentSignerCertificate = parsePemCertificate(TEST_CACHE_DOCUMENT_SIGNER_CERT);
const missingCRLDocumentSignerCertificate = parsePemCertificate(TEST_MISSING_CRL_DOCUMENT_SIGNER_CERT);
const noCacheOptions = { crlCacheEnabled: false };

test('checkCertificateRevocation reports revoked document signer certificate from DER CRL', async () => {
    await withMockedCRL(pemToDerBytes(CURRENT_REVOKED_CRL), async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, true);
        assert.equal(result.revoked, true);
        assert.equal(result.url, CRL_URL);
    });
});

test('checkCertificateRevocation accepts non-revoked document signer certificate from PEM CRL', async () => {
    await withMockedCRL(textBytes(CURRENT_EMPTY_CRL), async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, true);
        assert.equal(result.revoked, false);
        assert.equal(result.url, CRL_URL);
    });
});

test('checkCertificateRevocation treats URIs in the same distribution point as mirrors', async () => {
    const mirroredCertificate = certificateWithDistributionPoints([
        distributionPoint([MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL]),
    ]);
    const requestedUrls = [];

    await withMockedFetch(async (url) => {
        requestedUrls.push(url);
        if(url === MIRROR_PRIMARY_CRL_URL) return { ok: false, status: 500 };
        return crlResponse(textBytes(CURRENT_EMPTY_CRL));
    }, async () => {
        const result = await checkCertificateRevocation(mirroredCertificate, issuerCertificate, noCacheOptions);

        assert.deepEqual(requestedUrls, [MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL]);
        assert.equal(result.checked, true);
        assert.equal(result.revoked, false);
        assert.equal(result.url, MIRROR_BACKUP_CRL_URL);
    });
});

test('checkCertificateRevocation fetches uncached CRL URLs concurrently', async () => {
    const mirroredCertificate = certificateWithDistributionPoints([
        distributionPoint([MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL]),
    ]);
    const requestedUrls = [];
    let releasePrimary;
    const primaryResponse = new Promise(resolve => {
        releasePrimary = () => resolve(crlResponse(textBytes(CURRENT_EMPTY_CRL)));
    });

    await withMockedFetch((url) => {
        requestedUrls.push(url);
        if(url === MIRROR_PRIMARY_CRL_URL) return primaryResponse;
        if(url === MIRROR_BACKUP_CRL_URL) return crlResponse(textBytes(CURRENT_EMPTY_CRL));
        throw new Error(`Unexpected CRL URL ${url}`);
    }, async () => {
        const verification = checkCertificateRevocation(mirroredCertificate, issuerCertificate, noCacheOptions);

        await Promise.resolve();
        const requestedBeforePrimaryResolved = [...requestedUrls];
        let result;
        try {
            result = await promiseResultWithin(verification, 250);
        } finally {
            releasePrimary();
        }

        assert.deepEqual(requestedBeforePrimaryResolved, [MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL]);
        assert.notEqual(result, null);
        assert.equal(result.checked, true);
        assert.equal(result.revoked, false);
    });
});

test('checkCertificateRevocation returns when a fetched CRL proves revocation', async () => {
    const mirroredCertificate = certificateWithDistributionPoints([
        distributionPoint([MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL]),
    ]);
    let releasePrimary;
    const primaryResponse = new Promise(resolve => {
        releasePrimary = () => resolve(crlResponse(textBytes(CURRENT_EMPTY_CRL)));
    });

    await withMockedFetch((url) => {
        if(url === MIRROR_PRIMARY_CRL_URL) return primaryResponse;
        if(url === MIRROR_BACKUP_CRL_URL) return crlResponse(textBytes(CURRENT_REVOKED_CRL));
        throw new Error(`Unexpected CRL URL ${url}`);
    }, async () => {
        const verification = checkCertificateRevocation(mirroredCertificate, issuerCertificate, noCacheOptions);
        let result;
        try {
            result = await promiseResultWithin(verification, 250);
        } finally {
            releasePrimary();
        }

        assert.notEqual(result, null);
        assert.equal(result.checked, true);
        assert.equal(result.revoked, true);
        assert.equal(result.url, MIRROR_BACKUP_CRL_URL);
    });
});

test('checkCertificateRevocation caches each pending usable CRL after early return', async () => {
    const mirroredCertificate = certificateWithDistributionPoints([
        distributionPoint([MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL, MIRROR_SLOW_CRL_URL]),
    ]);
    const crlCache = new Map();
    let releasePrimary;
    const primaryResponse = new Promise(resolve => {
        releasePrimary = () => resolve(crlResponse(textBytes(CURRENT_EMPTY_CRL)));
    });
    const slowResponse = new Promise(() => {});

    await withMockedFetch((url) => {
        if(url === MIRROR_PRIMARY_CRL_URL) return primaryResponse;
        if(url === MIRROR_BACKUP_CRL_URL) return crlResponse(textBytes(CURRENT_REVOKED_CRL));
        if(url === MIRROR_SLOW_CRL_URL) return slowResponse;
        throw new Error(`Unexpected CRL URL ${url}`);
    }, async () => {
        const result = await checkCertificateRevocation(mirroredCertificate, issuerCertificate, {
            crlCache: crlCache,
            crlTimeout: 1,
        });

        assert.equal(result.checked, true);
        assert.equal(result.revoked, true);
        assert.equal(result.url, MIRROR_BACKUP_CRL_URL);
        assert.equal(crlCache.has(MIRROR_PRIMARY_CRL_URL), false);

        releasePrimary();
        await waitFor(() => crlCache.has(MIRROR_PRIMARY_CRL_URL));

        assert.equal(crlCache.has(MIRROR_PRIMARY_CRL_URL), true);
    });
});

test('checkCertificateRevocation does not fetch uncached URLs after cached CRL establishes status', async () => {
    const mirroredCertificate = certificateWithDistributionPoints([
        distributionPoint([MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL]),
    ]);

    await withMockedFetch(async () => {
        assert.fail('Uncached CRL URL should not be fetched after cached CRL establishes status');
    }, async () => {
        const result = await checkCertificateRevocation(mirroredCertificate, issuerCertificate, {
            crlCache: crlCacheWith(MIRROR_PRIMARY_CRL_URL, parseTestCRL(CURRENT_EMPTY_CRL)),
        });

        assert.equal(result.checked, true);
        assert.equal(result.revoked, false);
        assert.equal(result.url, MIRROR_PRIMARY_CRL_URL);
    });
});

test('checkCertificateRevocation does not fetch delegated CRL distribution point URLs', async () => {
    const delegatedCertificate = certificateWithDistributionPoints([
        delegatedDistributionPoint([MIRROR_PRIMARY_CRL_URL]),
    ]);

    await withMockedFetch(async () => {
        assert.fail('Delegated CRL distribution point URL should not be fetched');
    }, async () => {
        const result = await checkCertificateRevocation(delegatedCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, false);
        assert.equal(result.revoked, false);
        assert.match(result.error, /Delegated CRL issuers are not supported/);
    });
});

test('checkCertificateRevocation treats reason-scoped CRLs as incomplete coverage', async () => {
    const reasonScopedCertificate = certificateWithDistributionPoints([
        distributionPoint([REASON_SCOPED_CRL_URL], KEY_COMPROMISE_REASON_MASK),
    ]);

    await withMockedFetch(async (url) => {
        assert.equal(url, REASON_SCOPED_CRL_URL);
        return crlResponse(textBytes(CURRENT_EMPTY_CRL));
    }, async () => {
        const result = await checkCertificateRevocation(reasonScopedCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, false);
        assert.equal(result.revoked, false);
        assert.match(result.error, /CRL coverage is incomplete/);
    });
});

test('checkCertificateRevocation continues after partial coverage until a full CRL is checked', async () => {
    const partitionedCertificate = certificateWithDistributionPoints([
        distributionPoint([REASON_SCOPED_CRL_URL], KEY_COMPROMISE_REASON_MASK),
        distributionPoint([FULL_COVERAGE_CRL_URL]),
    ]);
    const requestedUrls = [];

    await withMockedFetch(async (url) => {
        requestedUrls.push(url);
        return crlResponse(textBytes(CURRENT_EMPTY_CRL));
    }, async () => {
        const result = await checkCertificateRevocation(partitionedCertificate, issuerCertificate, noCacheOptions);

        assert.deepEqual(requestedUrls, [REASON_SCOPED_CRL_URL, FULL_COVERAGE_CRL_URL]);
        assert.equal(result.checked, true);
        assert.equal(result.revoked, false);
        assert.equal(result.url, FULL_COVERAGE_CRL_URL);
    });
});

test('checkCertificateRevocation treats stale non-revoked CRL as unchecked', async () => {
    await withMockedCRL(textBytes(STALE_EMPTY_CRL), async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, false);
        assert.equal(result.revoked, false);
        assert.match(result.error, /CRL is stale/);
    });
});

test('checkCertificateRevocation does not cache stale non-revoked CRLs', async () => {
    const staleCacheCertificate = certificateWithDistributionPoints([
        distributionPoint([STALE_CACHE_CRL_URL]),
    ]);
    let fetchCount = 0;

    await withMockedFetch(async (url) => {
        fetchCount++;
        assert.equal(url, STALE_CACHE_CRL_URL);
        return crlResponse(textBytes(fetchCount === 1 ? STALE_EMPTY_CRL : CURRENT_EMPTY_CRL));
    }, async () => {
        const first = await checkCertificateRevocation(staleCacheCertificate, issuerCertificate);
        const second = await checkCertificateRevocation(staleCacheCertificate, issuerCertificate);

        assert.equal(fetchCount, 2);
        assert.equal(first.checked, false);
        assert.equal(first.revoked, false);
        assert.equal(second.checked, true);
        assert.equal(second.revoked, false);
    });
});

test('checkCertificateRevocation still reports revoked document signer certificate from stale CRL', async () => {
    await withMockedCRL(textBytes(STALE_REVOKED_CRL), async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, true);
        assert.equal(result.revoked, true);
    });
});

test('checkCertificateRevocation treats invalid CRL signature as unchecked', async () => {
    await withMockedCRL(textBytes(INVALID_SIGNATURE_CRL), async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, false);
        assert.equal(result.revoked, false);
        assert.match(result.error, /Invalid CRL signature/);
    });
});

test('checkCertificateRevocation requires issuer certificate cRLSign key usage', async () => {
    const issuerWithoutKeyUsage = parsePemCertificate(TEST_IACA_CERT);
    issuerWithoutKeyUsage.extensions = issuerWithoutKeyUsage.extensions.filter(ext => ext.extnID !== KEY_USAGE_OID);

    const result = await checkCertificateRevocation(documentSignerCertificate, {
        parsedCertificate: issuerWithoutKeyUsage,
    }, noCacheOptions);

    assert.equal(result.checked, false);
    assert.equal(result.revoked, false);
    assert.match(result.error, /key usage does not allow CRL signing/);
});

test('checkCertificateRevocation reports failed CRL fetch as unchecked', async () => {
    await withMockedFetch(async () => ({ ok: false, status: 500 }), async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, noCacheOptions);

        assert.equal(result.checked, false);
        assert.equal(result.revoked, false);
        assert.match(result.error, /HTTP 500/);
    });
});

test('checkCertificateRevocation treats future-dated CRLs as unchecked', async () => {
    const futureCRL = parseTestCRL(CURRENT_EMPTY_CRL);
    futureCRL.thisUpdate.value = new Date(Date.now() + 1000 * 60 * 60);
    const futureCertificate = certificateWithDistributionPoints([
        distributionPoint([FUTURE_CRL_URL]),
    ]);

    const result = await checkCertificateRevocation(futureCertificate, issuerCertificate, {
        crlCache: crlCacheWith(FUTURE_CRL_URL, futureCRL),
    });

    assert.equal(result.checked, false);
    assert.equal(result.revoked, false);
    assert.match(result.error, /CRL is not yet valid/);
});

test('checkCertificateRevocation treats non-revoked delta CRLs as unchecked', async () => {
    const deltaCRL = crlWithExtension(CURRENT_EMPTY_CRL, {
        extnID: DELTA_CRL_INDICATOR_OID,
    });
    const deltaCertificate = certificateWithDistributionPoints([
        distributionPoint([DELTA_CRL_URL]),
    ]);

    const result = await checkCertificateRevocation(deltaCertificate, issuerCertificate, {
        crlCache: crlCacheWith(DELTA_CRL_URL, deltaCRL),
    });

    assert.equal(result.checked, false);
    assert.equal(result.revoked, false);
    assert.match(result.error, /Delta CRL cannot establish non-revoked status/);
});

test('checkCertificateRevocation reports revoked document signer certificate from delta CRL', async () => {
    const deltaCRL = crlWithExtension(CURRENT_REVOKED_CRL, {
        extnID: DELTA_CRL_INDICATOR_OID,
    });
    const deltaCertificate = certificateWithDistributionPoints([
        distributionPoint([DELTA_CRL_URL]),
    ]);

    const result = await checkCertificateRevocation(deltaCertificate, issuerCertificate, {
        crlCache: crlCacheWith(DELTA_CRL_URL, deltaCRL),
    });

    assert.equal(result.checked, true);
    assert.equal(result.revoked, true);
    assert.equal(result.url, DELTA_CRL_URL);
});

test('checkCertificateRevocation accepts overlapping issuing distribution point names', async () => {
    const mirroredCertificate = certificateWithDistributionPoints([
        distributionPoint([MIRROR_PRIMARY_CRL_URL, MIRROR_BACKUP_CRL_URL]),
    ]);
    const crl = crlWithExtension(CURRENT_EMPTY_CRL, {
        extnID: '2.5.29.28',
        parsedValue: new IssuingDistributionPoint({
            distributionPoint: [{
                type: 6,
                value: MIRROR_BACKUP_CRL_URL,
            }],
        }),
    });

    const result = await checkCertificateRevocation(mirroredCertificate, issuerCertificate, {
        crlCache: crlCacheWith(MIRROR_PRIMARY_CRL_URL, crl),
    });

    assert.equal(result.checked, true);
    assert.equal(result.revoked, false);
    assert.equal(result.url, MIRROR_PRIMARY_CRL_URL);
});

test('checkCertificateRevocation reuses cached current CRLs by URL', async () => {
    let fetchCount = 0;
    await withMockedFetch(async (url) => {
        fetchCount++;
        assert.equal(url, CACHE_CRL_URL);
        return crlResponse(textBytes(CURRENT_EMPTY_CRL));
    }, async () => {
        const first = await checkCertificateRevocation(cacheDocumentSignerCertificate, issuerCertificate);
        const second = await checkCertificateRevocation(cacheDocumentSignerCertificate, issuerCertificate);

        assert.equal(fetchCount, 1);
        assert.equal(first.checked, true);
        assert.equal(second.checked, true);
        assert.equal(second.revoked, false);
    });
});

test('checkCertificateRevocation caches 404 as unchecked by URL', async () => {
    let fetchCount = 0;
    await withMockedFetch(async (url) => {
        fetchCount++;
        assert.equal(url, MISSING_CRL_URL);
        return { ok: false, status: 404 };
    }, async () => {
        const first = await checkCertificateRevocation(missingCRLDocumentSignerCertificate, issuerCertificate);
        const second = await checkCertificateRevocation(missingCRLDocumentSignerCertificate, issuerCertificate);

        assert.equal(fetchCount, 1);
        assert.equal(first.checked, false);
        assert.equal(first.revoked, false);
        assert.match(first.error, /HTTP 404/);
        assert.equal(second.checked, false);
        assert.equal(second.revoked, false);
        assert.match(second.error, /HTTP 404/);
    });
});

async function withMockedCRL(crlBytes, callback) {
    return withMockedFetch(async (url) => {
        assert.equal(url, CRL_URL);
        return crlResponse(crlBytes);
    }, callback);
}

async function withMockedFetch(fetchImplementation, callback) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchImplementation;
    try {
        return await callback();
    } finally {
        globalThis.fetch = originalFetch;
    }
}

function crlResponse(crlBytes) {
    return {
        ok: true,
        status: 200,
        arrayBuffer: async () => crlBytes.buffer.slice(crlBytes.byteOffset, crlBytes.byteOffset + crlBytes.byteLength),
    };
}

function pemToDerBytes(pem) {
    const base64 = pem
        .replace(/-----BEGIN X509 CRL-----/, '')
        .replace(/-----END X509 CRL-----/, '')
        .replace(/\s/g, '');
    return new Uint8Array(Buffer.from(base64, 'base64'));
}

function parseTestCRL(pem) {
    const derBytes = pemToDerBytes(pem);
    const asn1 = asn1js.fromBER(derBytes.buffer);
    return new CertificateRevocationList({ schema: asn1.result });
}

function crlWithExtension(pem, extension) {
    const crl = parseTestCRL(pem);
    crl.crlExtensions.extensions.push(extension);
    return crl;
}

function crlCacheWith(url, crl) {
    return new Map([[
        url,
        {
            crl: crl,
            expiresAt: Date.now() + 1000 * 60 * 60,
        },
    ]]);
}

function textBytes(text) {
    return new TextEncoder().encode(text);
}

function certificateWithDistributionPoints(distributionPoints) {
    const certificate = parsePemCertificate(TEST_DOCUMENT_SIGNER_CERT);
    certificate.extensions = certificate.extensions.filter(ext => ext.extnID !== CRL_DISTRIBUTION_POINTS_OID);
    certificate.extensions.push({
        extnID: CRL_DISTRIBUTION_POINTS_OID,
        parsedValue: new CRLDistributionPoints({ distributionPoints: distributionPoints }),
    });
    return certificate;
}

function distributionPoint(urls, reasonsMask = null) {
    const parameters = {
        distributionPoint: urls.map(url => ({
            type: 6,
            value: url,
        })),
    };
    if(reasonsMask) {
        parameters.reasons = new asn1js.BitString({
            valueHex: reasonMaskToBytes(reasonsMask).buffer,
        });
    }
    return new DistributionPoint(parameters);
}

function delegatedDistributionPoint(urls) {
    const delegated = distributionPoint(urls);
    delegated.cRLIssuer = [{
        type: 6,
        value: 'https://example.test/crl-issuer',
    }];
    return delegated;
}

function reasonMaskToBytes(mask) {
    const bytes = new Uint8Array(2);
    for(let bitIndex = 0; bitIndex < 16; bitIndex++) {
        if(mask & (1 << bitIndex)) {
            bytes[Math.floor(bitIndex / 8)] |= 0x80 >> (bitIndex % 8);
        }
    }
    return bytes;
}

function promiseResultWithin(promise, timeout) {
    return Promise.race([
        promise,
        new Promise(resolve => setTimeout(() => resolve(null), timeout)),
    ]);
}

async function waitFor(predicate) {
    for(let attempt = 0; attempt < 20; attempt++) {
        if(predicate()) return;
        await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(predicate(), true);
}
