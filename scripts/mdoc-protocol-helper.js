import { Protocol, CredentialFormat, ClaimMappings, ALL_TRUST_LISTS } from './constants.js';
import { decodeVpToken, verifyDocument } from './formats/mdoc-helper.js';
import { bufferToBase64Url } from './utils.js';
import { jwkToCoseKey } from './cose-helper.js';
import * as cbor2 from 'cbor2';
import {
    Aes128Gcm,
    CipherSuite,
    DhkemP256HkdfSha256,
    HkdfSha256,
} from '@hpke/core';

class MDOCProtocolHelper {
    constructor() {
        this.protocol = Protocol.MDOC;
    }

    createRequest(documentTypes, claims, nonce, jwk) {
        const deviceRequest = this._createDeviceRequest(documentTypes, claims);
        const encryptionInfo = this._createEncryptionInfo(nonce, jwk);
        if (deviceRequest) {
            return {
                protocol: this.protocol,
                data: {
                    deviceRequest: deviceRequest,
                    encryptionInfo: encryptionInfo,
                }
            };
        }
        return null;
    }

    _createDeviceRequest(documentTypes, claims) {
        const version = '1.1';
        const docRequests = [];
        const readerAuthAll = [];//TODO: Waiting on Apple to approve my business connect request so I can test how this works
        const documentSets = [];
        let i = 0;
        for(const documentType of documentTypes) {
            const nameSpaces = {};

            claims.forEach(claim => {
                const claimPath = ClaimMappings[CredentialFormat.MSO_MDOC]?.[documentType]?.[claim];
                if (claimPath) {
                    if(!nameSpaces[claimPath[0]]) {
                        nameSpaces[claimPath[0]] = {};
                    }
                    nameSpaces[claimPath[0]][claimPath[1]] = true;
                }
            });

            if (Object.keys(nameSpaces).length > 0) {
                const itemsRequest = {
                    docType: documentType,
                    nameSpaces: nameSpaces,
                };
                docRequests.push({
                    itemsRequest: new cbor2.Tag(24, cbor2.encode(itemsRequest)),
                });
                documentSets.push([i++]);
            }
        }
        const deviceRequestInfo = new cbor2.Tag(24, cbor2.encode({
            useCases: [{
                mandatory: true,
                documentSets: documentSets,
            }]
        }));
        return bufferToBase64Url(cbor2.encode({
            version: version,
            docRequests: docRequests,
            readerAuthAll: readerAuthAll,
            deviceRequestInfo: deviceRequestInfo,
        }));
    }

    _createEncryptionInfo(nonceHex, jwk) {
        const nonce = new Uint8Array(nonceHex.length / 2);
        for (let i = 0; i < nonceHex.length; i += 2) {
            nonce[i / 2] = parseInt(nonceHex.substr(i, 2), 16);
        }
        const encryptionInfo = cbor2.encode(['dcapi', {
            nonce: nonce,
            recipientPublicKey: jwkToCoseKey(jwk),
        }]);
        return bufferToBase64Url(encryptionInfo);
    }

    async verify(credentialData, trustLists, origin, nonce, jwk) {
        const response = credentialData.response;
        const decodedResponse = await decodeVpToken(response);
        if(!Array.isArray(decodedResponse) || decodedResponse[0] !== 'dcapi') {
            throw new Error('Expected decoded response to be an array with dcapi as first element');
        }
        const { enc, cipherText } = decodedResponse[1] || {};
        if(!enc || !cipherText) {
            throw new Error('Expected enc and cipherText in decoded response');
        }
        const sessionTranscript = await generateSessionTranscript(origin, nonce, jwk);
        const decrypted = await this._decryptCipherText(cipherText, enc, sessionTranscript, jwk);
        return this._verifyMsoMdoc(decrypted.documents, trustLists, sessionTranscript);
    }

    async _decryptCipherText(cipherText, enc, sessionTranscript, jwk) {
        const cryptoKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' },
            true, ['deriveKey', 'deriveBits']);
        const suite = new CipherSuite({
            kem: new DhkemP256HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes128Gcm(),
        });

        const recipient = await suite.createRecipientContext({
            recipientKey: cryptoKey,
            enc: enc,
            info: sessionTranscript,
        });

        try {
            const decrypted = await recipient.open(cipherText);
            return cbor2.decode(new Uint8Array(decrypted));
        } catch (error) {
            console.error('Error decrypting cipherText', error);
            throw error;
        }
    }

    async _verifyMsoMdoc(documents, trustLists, sessionTranscript) {
        const processedDocuments = [];
        const claims = {};
        let trusted = true;
        let valid = true;

        for(const document of documents) {
            const { claims: documentClaims, issuer, valid: documentValid, invalidReasons } = await verifyDocument(document, sessionTranscript);
            const issuerTrusted = issuer && (trustLists == ALL_TRUST_LISTS || issuer.certificate.trust_lists.some(tl => trustLists.includes(tl)));
            trusted = trusted && issuerTrusted;
            valid = valid && documentValid;
            for(const key in documentClaims) {
                claims[key] = documentClaims[key];
            }
            const processedDocument = {
                claims: documentClaims,
                valid: documentValid,
                trusted: !!issuerTrusted,
                document: document,
            };
            if(issuer) processedDocument.issuer = issuer;
            if(!documentValid) processedDocument.invalidReasons = invalidReasons;
            processedDocuments.push(processedDocument);
        }
        return {
            claims: claims,
            valid: !!valid,
            trusted: !!trusted,
            processedDocuments: processedDocuments,
            sessionTranscript: sessionTranscript,
        };
    }
}

async function generateSessionTranscript(origin, nonceHex, jwk) {
    if(!origin) throw new Error('Origin is required for generating session transcript');
    if(!nonceHex) throw new Error('Nonce is required for generating session transcript');
    if(!jwk) throw new Error('JWK is required for generating session transcript');

    const nonce = new Uint8Array(nonceHex.length / 2);
    for (let i = 0; i < nonceHex.length; i += 2) {
        nonce[i / 2] = parseInt(nonceHex.substr(i, 2), 16);
    }
    const arfEncryptionInfo = {
        nonce: nonce,
        recipientPublicKey: jwkToCoseKey(jwk)
    };

    const encryptionInfo = bufferToBase64Url(cbor2.encode(['dcapi', arfEncryptionInfo]));

    const dcapiInfo = cbor2.encode([encryptionInfo, origin]);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dcapiInfo);
    const hashArray = new Uint8Array(hashBuffer);

    const handover = ['dcapi', hashArray];

    const sessionTranscript = cbor2.encode([null, null, handover]);
    return sessionTranscript;
}

const mdocProtocolHelper = new MDOCProtocolHelper();
export default mdocProtocolHelper;