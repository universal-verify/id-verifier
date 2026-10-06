import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import * as asn1js from 'asn1js';
import * as cbor2 from 'cbor2';
import {
    AttributeTypeAndValue, AuthorityKeyIdentifier, BasicConstraints,
    Certificate, CryptoEngine, Extension, RelativeDistinguishedNames, Time, setEngine,
} from 'pkijs';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { certificateToPem, parsePemCertificate, TrustScope } from 'trusted-issuer-registry';
import * as registryExports from 'trusted-issuer-registry';
import {
    Verifier, DocumentType, Protocol, TrustList, RevocationCheckMode,
    UntrustedReason, generateJWK,
} from '../scripts/id-verifier.js';
import MDOCProtocolHelper from '../scripts/mdoc-protocol-helper.js';
import OpenID4VPProtocolHelper from '../scripts/openid-4vp-protocol-helper.js';
import { jwkToCoseKey } from '../scripts/cose-helper.js';
import { bufferToBase64Url } from '../scripts/utils.js';

const VALID_FROM = new Date('2000-01-01T00:00:00Z');
const VALID_UNTIL = new Date('2100-01-01T00:00:00Z');
const params = { origin: 'https://example.test', nonce: '00112233445566778899aabbccddeeff' };
let issuerKeyPair;
let signerKeyPair;
let issuerCertificate;
let expiredIssuerCertificate;
let signerCertificate;
const credentials = {};

before(async () => {
    setEngine('test', new CryptoEngine({ name: 'test', crypto: globalThis.crypto }));
    issuerKeyPair = await generateKeyPair();
    signerKeyPair = await generateKeyPair();
    issuerCertificate = await createIssuerCertificate();
    expiredIssuerCertificate = await createIssuerCertificate({ notAfter: VALID_FROM, serial: 2 });
    signerCertificate = await createSignerCertificate();
    params.jwk = await generateJWK();
    for(const protocol of Object.values(Protocol)) {
        credentials[protocol] = await createCredentials(protocol);
    }
});

for(const protocol of Object.values(Protocol)) {
    test(`${protocol} trusts raw PEMs with the registry disabled and returns certificate results`, async t => {
        const fetch = t.mock.method(globalThis, 'fetch', async () => {
            throw new Error('Registry-disabled PEM trust must not fetch');
        });
        const verifier = new Verifier({
            trustLists: [],
            trustedIssuerRegistry: {
                trustedIssuerCertificates: [certificateToPem(issuerCertificate)],
            },
        });
        const result = await verifier.processCredentials(credentials[protocol], params);

        assert.equal(result.valid, true);
        assert.equal(result.trusted, true);
        assert.equal(result.claims.given_name, 'Test');
        const document = result.processedDocuments[0];
        assert.equal(document.untrustedReasons, undefined);
        assert.equal(document.issuer.display.name, 'Test IACA');
        assert.deepEqual(document.issuer.trust_scopes, [TrustScope.GOVERNMENT_ISSUED_ID]);
        assert.equal(document.issuer.certificates.length, 1);
        assert.deepEqual(document.issuer.certificates[0].trust_lists, ['user_provided']);
        assert.equal(document.issuer.certificates[0].trusted, true);
        assert.equal(document.issuer.certificates[0].revocationStatus, 'not_checked');
        assert.equal(fetch.mock.callCount(), 0);
    });

    test(`${protocol} adds government ID scope to issuer objects without changing caller metadata`, async () => {
        for(const trustScopes of [
            undefined,
            [],
            [TrustScope.DOCUMENT_SIGNING],
            [TrustScope.GOVERNMENT_ISSUED_ID],
            [TrustScope.GOVERNMENT_ISSUED_ID, TrustScope.DOCUMENT_SIGNING],
        ]) {
            const certificateOptions = Object.freeze({
                data: certificateToPem(issuerCertificate),
                entity_type: 'government',
                entity_metadata: { country: 'CA', region: 'QC' },
                display: { name: 'Custom Issuer', logo: 'https://example.test/logo.png' },
                ...(trustScopes && { trust_scopes: Object.freeze(trustScopes) }),
            });
            const options = {
                trustLists: [],
                trustedIssuerRegistry: Object.freeze({
                    trustedIssuerCertificates: Object.freeze([certificateOptions]),
                }),
            };
            const result = await new Verifier(options).processCredentials(credentials[protocol], params);
            const issuer = result.processedDocuments[0].issuer;
            assert.equal(result.trusted, true);
            assert.deepEqual(issuer.display, certificateOptions.display);
            assert.deepEqual(issuer.entity_metadata, certificateOptions.entity_metadata);
            assert.equal(issuer.entity_type, certificateOptions.entity_type);
            assert.deepEqual(issuer.trust_scopes, trustScopes?.includes(TrustScope.GOVERNMENT_ISSUED_ID)
                ? trustScopes : [...trustScopes || [], TrustScope.GOVERNMENT_ISSUED_ID]);
            assert.equal(certificateOptions.trust_scopes, trustScopes);
        }
    });

    test(`${protocol} always requires government ID scope from registry issuers`, async t => {
        for(const trustScopes of [
            [],
            [TrustScope.DOCUMENT_SIGNING],
            [TrustScope.GOVERNMENT_ISSUED_ID],
            [TrustScope.DOCUMENT_SIGNING, TrustScope.GOVERNMENT_ISSUED_ID],
        ]) {
            const verifier = new Verifier({
                trustLists: [TrustList.UV],
                trustScope: TrustScope.DOCUMENT_SIGNING,
            });
            // Supply an issuer as returned by the registry's verified response cache.
            t.mock.method(verifier._registry._cachedFetcher, 'fetch', async (_url, purpose) => purpose === 'issuer'
                ? { ok: true, issuer: {
                    issuer_id: 'x509_aki:AQIDBA',
                    entity_type: 'government',
                    entity_metadata: {},
                    display: { name: 'Registry Issuer' },
                    trust_scopes: trustScopes,
                    certificates: [{ data: certificateToPem(issuerCertificate), format: 'pem', trust_lists: [TrustList.UV] }],
                } }
                : { ok: false, status: 404 });
            const result = await verifier.processCredentials(credentials[protocol], params);
            const document = result.processedDocuments[0];
            const expectedTrusted = trustScopes.includes(TrustScope.GOVERNMENT_ISSUED_ID);
            assert.equal(result.valid, true);
            assert.equal(result.trusted, expectedTrusted);
            assert.equal(document.issuer.certificates[0].trusted, expectedTrusted);
            assert.deepEqual(document.issuer.trust_scopes, trustScopes);
            assert.deepEqual(document.untrustedReasons, expectedTrusted
                ? undefined : [UntrustedReason.ISSUER_MISSING_REQUIRED_TRUST_SCOPE]);
            assert.equal('trustScope' in verifier, false);
        }
    });

    test(`${protocol} forwards best-effort and required revocation modes`, async () => {
        for(const mode of [RevocationCheckMode.BEST_EFFORT, RevocationCheckMode.REQUIRED]) {
            const verifier = new Verifier({
                trustLists: [],
                trustedIssuerRegistry: {
                    trustedIssuerCertificates: [certificateToPem(issuerCertificate)],
                    revocationCheckMode: mode,
                },
            });
            const result = await verifier.processCredentials(credentials[protocol], params);
            assert.equal(result.valid, true);
            assert.equal(result.trusted, mode === RevocationCheckMode.BEST_EFFORT);
            if(!result.trusted) {
                assert.deepEqual(result.processedDocuments[0].untrustedReasons, [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
            }
        }
    });
}

test('issuer results retain expired certificates while a valid certificate establishes trust', async () => {
    const verifier = new Verifier({
        trustLists: [],
        trustedIssuerRegistry: {
            trustedIssuerCertificates: [
                certificateToPem(expiredIssuerCertificate),
                { data: certificateToPem(issuerCertificate), display: { logo: 'https://example.test/logo.png' } },
            ],
        },
    });
    const result = await verifier.processCredentials(credentials[Protocol.OPENID4VP], params);
    const issuer = result.processedDocuments[0].issuer;
    assert.equal(result.trusted, true);
    assert.equal(issuer.display.name, 'Test IACA');
    assert.equal(issuer.certificates.length, 2);
    assert.equal(issuer.certificates[0].trusted, false);
    assert.deepEqual(issuer.certificates[0].untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_EXPIRED]);
    assert.equal(issuer.certificates[1].trusted, true);
});

test('signer and issuer validity failures both reach the document result', async () => {
    const expiredSigner = await createSignerCertificate({ notAfter: VALID_FROM });
    const verifier = new Verifier({
        trustLists: [],
        trustedIssuerRegistry: {
            trustedIssuerCertificates: [certificateToPem(expiredIssuerCertificate)],
        },
    });
    const result = await verifier.processCredentials(await createCredentials(Protocol.OPENID4VP, expiredSigner), params);
    assert.equal(result.trusted, false);
    assert.deepEqual(result.processedDocuments[0].untrustedReasons, [
        UntrustedReason.CERTIFICATE_EXPIRED, UntrustedReason.ISSUER_CERTIFICATE_EXPIRED,
    ]);
});

test('an invalid signer certificate signature retains issuer details and reports the registry reason', async () => {
    const tamperedSigner = parsePemCertificate(certificateToPem(signerCertificate));
    tamperedSigner.signatureValue.valueBlock.valueHexView[0] ^= 1;
    const verifier = new Verifier({
        trustLists: [],
        trustedIssuerRegistry: {
            trustedIssuerCertificates: [certificateToPem(issuerCertificate)],
        },
    });
    const result = await verifier.processCredentials(await createCredentials(Protocol.OPENID4VP, tamperedSigner), params);
    assert.equal(result.valid, true);
    assert.equal(result.trusted, false);
    assert.deepEqual(result.processedDocuments[0].untrustedReasons, [UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED]);
    assert.equal(result.processedDocuments[0].issuer.display.name, 'Test IACA');
});

test('empty trust lists suppress registry and deprecation requests', async t => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => {
        throw new Error('Empty trust lists must not fetch');
    });
    const verifier = new Verifier({
        trustLists: [],
        trustedIssuerRegistry: {
            trustedIssuerCertificates: [certificateToPem(issuerCertificate)],
        },
    });
    assert.equal((await verifier.processCredentials(credentials[Protocol.OPENID4VP], params)).trusted, true);
    assert.equal(fetch.mock.callCount(), 0);
});

test('omitted trust lists default to UV and AAMVA while explicit selections are preserved', async t => {
    t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 404 }));
    const resolver = t.mock.method(registryExports.Registry.prototype, 'resolveCertificateTrust');
    const cases = [
        [{}, [TrustList.UV, TrustList.AAMVA_DTS]],
        [{ trustedIssuerRegistry: {} }, [TrustList.UV, TrustList.AAMVA_DTS]],
        [{ trustLists: undefined }, [TrustList.UV, TrustList.AAMVA_DTS]],
        [{ trustLists: [TrustList.UV] }, [TrustList.UV]],
        [{ trustLists: [] }, []],
    ];
    for(const [options, expected] of cases) {
        const verifier = new Verifier(options);
        // Later changes to the caller's array must not alter the verifier's configuration.
        options.trustLists?.push(TrustList.AAMVA_DTS);
        await verifier.processCredentials(credentials[Protocol.OPENID4VP], params);
        assert.deepEqual(resolver.mock.calls.at(-1).arguments[1].trustLists, expected);
    }
});

test('default trust lists query the registry and reuse its cache within one verifier', async t => {
    const requests = [];
    t.mock.method(globalThis, 'fetch', async url => {
        requests.push(url);
        return new Response(null, { status: 404 });
    });
    const verifier = new Verifier();
    for(let i = 0; i < 2; i++) {
        const result = await verifier.processCredentials(credentials[Protocol.OPENID4VP], params);
        assert.equal(result.trusted, false);
        assert.equal(result.processedDocuments[0].issuer, null);
        assert.deepEqual(result.processedDocuments[0].untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND]);
    }
    assert.equal(requests.filter(url => url.includes('/issuers/')).length, 1);
    assert.equal(requests.filter(url => url.endsWith('/deprecation_notice.json')).length, 1);
});

test('registry cache controls apply to issuer and deprecation requests', async t => {
    const requests = [];
    t.mock.method(globalThis, 'fetch', async url => {
        requests.push(url);
        return new Response(null, { status: 404 });
    });
    for(const registryOptions of [{ cacheEnabled: false }, { cacheTTL: 0 }]) {
        requests.length = 0;
        const verifier = new Verifier({ trustedIssuerRegistry: registryOptions });
        for(let i = 0; i < 2; i++) {
            await verifier.processCredentials(credentials[Protocol.OPENID4VP], params);
        }
        assert.equal(requests.filter(url => url.includes('/issuers/')).length, 2);
        assert.equal(requests.filter(url => url.endsWith('/deprecation_notice.json')).length, 2);
    }
});

test('local trust survives registry fetch failures and missing issuers report those failures', async t => {
    let issuerRequests = 0;
    t.mock.method(globalThis, 'fetch', async url => {
        if(url.endsWith('/deprecation_notice.json')) return new Response(null, { status: 404 });
        issuerRequests++;
        throw new Error('Registry unavailable');
    });
    const verifier = new Verifier({
        trustedIssuerRegistry: {
            cacheEnabled: false,
            trustedIssuerCertificates: [certificateToPem(issuerCertificate)],
        },
    });
    for(let i = 0; i < 2; i++) {
        assert.equal((await verifier.processCredentials(credentials[Protocol.OPENID4VP], params)).trusted, true);
    }
    assert.equal(issuerRequests, 2);
    const untrusted = await new Verifier().processCredentials(credentials[Protocol.OPENID4VP], params);
    assert.deepEqual(untrusted.processedDocuments[0].untrustedReasons, [
        UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND, UntrustedReason.ISSUER_FETCH_FAILED,
    ]);
});

test('issuer fetching uses the configured network timeout', async t => {
    t.mock.method(globalThis, 'fetch', async (url, { signal }) => {
        if(url.endsWith('/deprecation_notice.json')) return new Response(null, { status: 404 });
        return new Promise((_resolve, reject) => {
            signal.addEventListener('abort', () => reject(new Error('Request aborted')));
        });
    });
    const verifier = new Verifier({ trustedIssuerRegistry: { timeout: 1 } });
    const result = await verifier.processCredentials(credentials[Protocol.OPENID4VP], params);
    assert.equal(result.trusted, false);
    assert.ok(result.processedDocuments[0].untrustedReasons.includes(UntrustedReason.ISSUER_FETCH_FAILED));
});

test('the constructor rejects unsupported revocation modes and malformed PEM inputs', () => {
    assert.throws(() => new Verifier({ trustedIssuerRegistry: { revocationCheckMode: 'unsupported' } }), /Unsupported CRL check mode/);
    assert.throws(() => new Verifier({ trustedIssuerRegistry: { trustedIssuerCertificates: ['not a certificate'] } }));
    assert.throws(() => new Verifier({ trustedIssuerRegistry: { trustedIssuerCertificates: 'not an array' } }), /trustedIssuerCertificates must be an array/);
});

test('all SDK builds expose registry constants and resolve PEM trust for both protocols', async t => {
    t.mock.method(globalThis, 'fetch', async () => {
        throw new Error('Registry-disabled builds must not fetch');
    });
    for(const filename of ['id-verifier.js', 'id-verifier.min.js', 'id-verifier.bundled.js', 'id-verifier.bundled.min.js']) {
        const sdk = await import(`../build/${filename}`);
        for(const name of ['TrustList', 'RevocationCheckMode', 'UntrustedReason']) {
            assert.deepEqual(sdk[name], registryExports[name], `${filename}: ${name}`);
        }
        assert.equal('TrustScope' in sdk, false, filename);
        for(const protocol of Object.values(Protocol)) {
            const verifier = new sdk.Verifier({
                trustLists: [],
                trustedIssuerRegistry: {
                    trustedIssuerCertificates: [certificateToPem(issuerCertificate)],
                },
            });
            const result = await verifier.processCredentials(credentials[protocol], params);
            assert.equal(result.valid, true, `${filename}: ${protocol}`);
            assert.equal(result.trusted, true, `${filename}: ${protocol}`);
            assert.deepEqual(result.processedDocuments[0].issuer.trust_scopes, [TrustScope.GOVERNMENT_ISSUED_ID]);
            assert.equal(result.processedDocuments[0].issuer.certificates[0].trusted, true);
        }
    }
});

async function generateKeyPair() {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

function extension(oid, value, critical = false) {
    return new Extension({ extnID: oid, critical, extnValue: value.toSchema ? value.toSchema().toBER() : value.toBER() });
}

function name(value) {
    return new RelativeDistinguishedNames({ typesAndValues: [
        new AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value }) }),
    ] });
}

async function createIssuerCertificate(options = {}) {
    const subject = name('Test IACA');
    const certificate = new Certificate({
        version: 2,
        serialNumber: new asn1js.Integer({ value: options.serial || 1 }),
        subject,
        issuer: subject,
        notBefore: new Time({ type: 1, value: VALID_FROM }),
        notAfter: new Time({ type: 1, value: options.notAfter || VALID_UNTIL }),
        extensions: [
            extension('2.5.29.14', new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3, 4]).buffer })),
            extension('2.5.29.19', new BasicConstraints({ cA: true }), true),
        ],
    });
    await certificate.subjectPublicKeyInfo.importKey(issuerKeyPair.publicKey);
    await certificate.sign(issuerKeyPair.privateKey, 'SHA-256');
    return parsePemCertificate(certificateToPem(certificate));
}

async function createSignerCertificate(options = {}) {
    const certificate = new Certificate({
        version: 2,
        serialNumber: new asn1js.Integer({ value: 100 }),
        subject: name('Test Document Signer'),
        issuer: issuerCertificate.subject,
        notBefore: new Time({ type: 1, value: VALID_FROM }),
        notAfter: new Time({ type: 1, value: options.notAfter || VALID_UNTIL }),
        extensions: [extension('2.5.29.35', new AuthorityKeyIdentifier({
            keyIdentifier: new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3, 4]).buffer }),
        }))],
    });
    await certificate.subjectPublicKeyInfo.importKey(signerKeyPair.publicKey);
    await certificate.sign(issuerKeyPair.privateKey, 'SHA-256');
    return parsePemCertificate(certificateToPem(certificate));
}

async function signCose(payload) {
    const protectedHeaders = cbor2.encode(new Map([[1, -7]]));
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signerKeyPair.privateKey,
        cbor2.encode(['Signature1', protectedHeaders, new Uint8Array(0), payload]));
    return [protectedHeaders, new Map(), payload, new Uint8Array(signature)];
}

async function createCredentials(protocol, certificate = signerCertificate) {
    const sessionTranscript = protocol === Protocol.OPENID4VP
        ? await OpenID4VPProtocolHelper._generateSessionTranscript(params.origin, params.nonce)
        : await MDOCProtocolHelper._generateSessionTranscript(params.origin, params.nonce, params.jwk);
    const namespace = 'org.iso.18013.5.1';
    const docType = DocumentType.MOBILE_DRIVERS_LICENSE;
    const claim = new cbor2.Tag(24, cbor2.encode({
        digestID: 0, random: new Uint8Array(16), elementIdentifier: 'given_name', elementValue: 'Test',
    }));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', cbor2.encode(claim)));
    const signerJWK = await crypto.subtle.exportKey('jwk', signerKeyPair.publicKey);
    const payload = cbor2.encode(new cbor2.Tag(24, cbor2.encode({
        docType,
        validityInfo: { validFrom: VALID_FROM.toISOString(), validUntil: VALID_UNTIL.toISOString() },
        deviceKeyInfo: { deviceKey: jwkToCoseKey(signerJWK) },
        valueDigests: { [namespace]: new Map([[0, digest]]) },
    })));
    const issuerAuth = await signCose(payload);
    issuerAuth[1].set(33, new Uint8Array(certificate.toSchema().toBER()));
    const nameSpaces = new cbor2.Tag(24, cbor2.encode({}));
    const deviceAuthentication = cbor2.encode(['DeviceAuthentication', cbor2.decode(sessionTranscript), docType, nameSpaces]);
    const document = {
        docType,
        issuerSigned: { issuerAuth, nameSpaces: { [namespace]: [claim] } },
        deviceSigned: { nameSpaces, deviceAuth: { deviceSignature: await signCose(cbor2.encode(new cbor2.Tag(24, deviceAuthentication))) } },
    };
    const response = cbor2.encode({ documents: [document] });
    if(protocol === Protocol.OPENID4VP) {
        return { protocol, data: { vp_token: { 'cred-mso_mdoc-org_iso_18013_5_1_mDL': [bufferToBase64Url(response)] } } };
    }
    const { d: _d, ...publicJWK } = params.jwk;
    const recipientPublicKey = await crypto.subtle.importKey('jwk', { ...publicJWK, key_ops: [] },
        { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
    const sender = await suite.createSenderContext({ recipientPublicKey, info: sessionTranscript });
    const cipherText = new Uint8Array(await sender.seal(response));
    return { protocol, data: { response: bufferToBase64Url(cbor2.encode(['dcapi', { enc: new Uint8Array(sender.enc), cipherText }])) } };
}
