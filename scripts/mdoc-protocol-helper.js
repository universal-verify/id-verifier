import { Protocol, CredentialFormat, ClaimMappings, ALL_TRUST_LISTS } from './constants.js';
import { decodeVpToken, verifyDocument } from './formats/mdoc-helper.js';
import { generateSessionTranscript, jwkToCoseKey, bufferToBase64Url } from './utils.js';
import * as cbor2 from 'cbor2';

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
        return {
            version: version,
            docRequests: docRequests,
            readerAuthAll: readerAuthAll,
            deviceRequestInfo: deviceRequestInfo,
        };
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

    async verify(credentialData, trustLists, origin, nonce) {
        const response = credentialData.response;
        console.log('decoded response', await decodeVpToken(response));
        throw new Error('Unexpected response format for MDOC protocol');
    }

    async _verifyMsoMdoc(tokens, trustLists, origin, nonce) {
        const decodedTokens = [];
        const claims = {};
        const documents = [];
        let trusted = true;
        const issuers = [];

        // Generate session transcript if origin and nonce are provided
        let sessionTranscript;
        if (origin && nonce) {
            sessionTranscript = await generateSessionTranscript(origin, nonce);
        }

        for(const token of tokens) {
            //verify base64url-encoded CBOR data
            const decoded = await decodeVpToken(token);
            console.log('decoded', decoded);
            decodedTokens.push(decoded);
        }
        for(const decodedToken of decodedTokens) {
            documents.push(...decodedToken.documents);
        }
        for(const document of documents) {
            const { claims: documentClaims, trustedIssuer: trustedIssuer } = await verifyDocument(document, sessionTranscript);
            issuers.push(trustedIssuer);
            trusted = trusted && trustedIssuer && (trustLists == ALL_TRUST_LISTS || trustedIssuer.certificate.trust_lists.some(tl => trustLists.includes(tl)));
            for(const key in documentClaims) {
                claims[key] = documentClaims[key];
            }
        }
        return {
            claims: claims,
            trusted: trusted,
            issuers: issuers,
        };
    }
}

const mdocProtocolHelper = new MDOCProtocolHelper();
export default mdocProtocolHelper;