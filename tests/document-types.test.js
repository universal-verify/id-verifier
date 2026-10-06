import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import * as cbor2 from 'cbor2';
import { Verifier, Claim, DocumentType, Protocol, generateJWK } from '../scripts/id-verifier.js';
import { base64urlToUint8Array } from '../scripts/utils.js';

let jwk;
before(async () => {
    jwk = await generateJWK();
});

for(const [documentType, expectedPaths] of [
    [DocumentType.EU_AGE_VERIFICATION, [
        ['eu.europa.ec.av.1', 'age_over_18'],
        ['eu.europa.ec.av.1', 'age_over_21'],
        ['eu.europa.ec.av.1', 'portrait'],
    ]],
    [DocumentType.JAPAN_MY_NUMBER_CARD, [
        ['org.iso.23220.1', 'age_over_18'],
        ['org.iso.23220.1', 'age_over_21'],
        ['org.iso.23220.1.jp', 'resident_address_unicode'],
        ['org.iso.23220.1.jp', 'individual_number_unicode'],
        ['org.iso.23220.1.jp', 'portrait'],
    ]],
]) {
    test(`${documentType} requests mapped claims through both protocols and omits unsupported claims`, () => {
        const request = new Verifier({ trustLists: [] }).createWebCredentialsRequest({
            documentTypes: [documentType],
            claims: [Claim.GIVEN_NAME, Claim.FAMILY_NAME, Claim.BIRTH_YEAR, Claim.AGE_OVER_18,
                Claim.AGE_OVER_21, Claim.ADDRESS, Claim.DOCUMENT_NUMBER, Claim.PORTRAIT, Claim.COUNTRY],
            nonce: '00112233445566778899aabbccddeeff',
            jwk,
        });
        assert.equal(request.digital.requests.length, 2);

        const openidRequest = request.digital.requests.find(entry => entry.protocol === Protocol.OPENID4VP);
        const [credential] = openidRequest.data.dcql_query.credentials;
        assert.equal(credential.meta.doctype_value, documentType);
        assert.deepEqual(credential.claims.map(claim => claim.path), expectedPaths);

        const mdocRequest = request.digital.requests.find(entry => entry.protocol === Protocol.MDOC);
        const deviceRequest = cbor2.decode(base64urlToUint8Array(mdocRequest.data.deviceRequest));
        assert.equal(deviceRequest.docRequests.length, 1);
        const itemsRequest = cbor2.decode(deviceRequest.docRequests[0].itemsRequest.contents);
        assert.equal(itemsRequest.docType, documentType);
        const expectedNameSpaces = {};
        for(const [namespace, identifier] of expectedPaths) {
            (expectedNameSpaces[namespace] ??= {})[identifier] = true;
        }
        assert.deepEqual(itemsRequest.nameSpaces, expectedNameSpaces);
    });
}
