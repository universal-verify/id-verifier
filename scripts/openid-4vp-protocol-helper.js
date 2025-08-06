import { Protocol, ProtocolFormats, CredentialFormat, ClaimMappings, CredentialId, createCredentialId, ALL_TRUST_LISTS } from './constants.js';
import { decodeVpToken, verifyDocument } from './formats/mdoc-helper.js';
import * as cbor2 from 'cbor2';

class OpenID4VPProtocolHelper {
    constructor() {
        this.protocol = Protocol.OPENID4VP;
    }

    createRequest(documentTypes, claims, nonce) {
        const credentials = this._createQueryCredentials(documentTypes, claims);
        if (credentials.length > 0) {
            return {
                protocol: this.protocol,
                data: {
                    dcql_query: {
                        credentials
                    },
                    nonce: nonce,
                    response_mode: 'dc_api',
                    response_type: 'vp_token',
                }
            };
        }
        return null;
    }

    _createQueryCredentials(documentTypes, claims) {
        const credentials = [];
        for (const format of ProtocolFormats[this.protocol]) {
            for(const documentType of documentTypes) {
                const formatClaims = [];

                // Add claims for this format
                claims.forEach(claim => {
                    const claimPath = ClaimMappings[format]?.[documentType]?.[claim];
                    if (claimPath) {
                        formatClaims.push({
                            path: claimPath
                        });
                    }
                });

                if (formatClaims.length > 0) {
                    const credential = {
                        format,
                        id: createCredentialId(format, documentType),
                        claims: formatClaims,
                        meta: {},
                    };
                    if(format === CredentialFormat.MSO_MDOC) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.3
                        credential.meta.doctype_value = documentType;
                    } else if(format === CredentialFormat.DC_SD_JWT) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.5
                        credential.meta.vct_values = [];
                    } else if(format === CredentialFormat.LDP_VC) {
                        //https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1.1
                        credential.meta.type_values = [];
                    }

                    credentials.push(credential);
                }
            }
        }
        return credentials;
    }

    async verify(credentialData, trustLists, origin, nonce) {
        const vpToken = credentialData.vp_token;
        for(const key in vpToken) {
            if(CredentialId[key].format === CredentialFormat.MSO_MDOC) {
                //TODO: Support response with multiple credential formats in the future
                return this._verifyMsoMdoc(vpToken[key], trustLists, origin, nonce);
            }
        }
        throw new Error('Unsupported credential format');
    }

    async _verifyMsoMdoc(tokens, trustLists, origin, nonce) {
        const processedDocuments = [];
        const decodedTokens = [];
        const documents = [];
        const claims = {};
        let trusted = true;
        let valid = true;

        // Generate session transcript if origin and nonce are provided
        const sessionTranscript = await generateSessionTranscript(origin, nonce);

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
            const { claims: documentClaims, issuer, valid: documentValid, invalidReasons } = await verifyDocument(document, sessionTranscript);
            let issuerTrusted = issuer && (trustLists == ALL_TRUST_LISTS || issuer.certificate.trust_lists.some(tl => trustLists.includes(tl)));
            trusted = trusted && issuerTrusted;
            valid = valid && documentValid;
            for(const key in documentClaims) {
                claims[key] = documentClaims[key];
            }
            let processedDocument = {
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

async function generateSessionTranscript(origin, nonce, jwkThumbprint = null) {
    if(!origin) throw new Error('Origin is required for generating session transcript');
    if(!nonce) throw new Error('Nonce is required for generating session transcript');

    // Create OpenID4VPDCAPIHandoverInfo structure
    const handoverInfo = [origin, nonce, jwkThumbprint];

    // Encode handoverInfo as CBOR
    const handoverInfoBytes = cbor2.encode(handoverInfo);

    // Calculate SHA-256 hash of the handoverInfoBytes
    const hashBuffer = await crypto.subtle.digest('SHA-256', handoverInfoBytes);
    const hashArray = new Uint8Array(hashBuffer);

    // Create OpenID4VPDCAPIHandover structure
    const handover = ['OpenID4VPDCAPIHandover', hashArray];

    // Create SessionTranscript structure
    // [DeviceEngagementBytes, EReaderKeyBytes, Handover]
    // For dc_api, DeviceEngagementBytes and EReaderKeyBytes MUST be null
    const sessionTranscript = cbor2.encode([null, null, handover]);
    return sessionTranscript;
}

const openid4vpProtocolHelper = new OpenID4VPProtocolHelper();
export default openid4vpProtocolHelper;