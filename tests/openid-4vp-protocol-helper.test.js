import test from 'node:test';
import assert from 'node:assert/strict';
import OpenID4VPProtocolHelper from '../scripts/openid-4vp-protocol-helper.js';

test('OpenID4VPProtocolHelper._generateSessionTranscript', async () => {
    //Sourced from https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-wg-draft.html#appendix-B.2.6.2-14
    const expected = '83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a';
    const origin = 'https://example.com';
    const nonce = 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA';
    const jwkThumbprint = new Uint8Array([66, 131, 236, 146, 122, 224, 242, 8, 218, 170, 45, 2, 106, 129, 79, 43, 34, 220, 165, 44, 248, 95, 250, 143, 63, 134, 38, 198, 189, 102, 144, 71]);
    const sessionTranscript = await OpenID4VPProtocolHelper._generateSessionTranscript(origin, nonce, jwkThumbprint);
    const sessionTranscriptHex = Buffer.from(sessionTranscript).toString('hex');
    assert.equal(sessionTranscriptHex, expected);
});