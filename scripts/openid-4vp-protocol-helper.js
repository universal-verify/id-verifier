import { DocumentType, Protocol, ProtocolFormats, CredentialFormat, ClaimMappings } from './constants.js';
import { decodeVpToken, verifyDocument } from './formats/mdoc-helper.js';
import * as cbor2 from 'cbor2';

class OpenID4VPProtocolHelper {
    constructor() {
        this.protocol = Protocol.OPENID4VP;
    }

    createRequest(documentTypes, claims, nonce) {
        const credentials = this._createQueryCredentials(documentTypes, claims);
        if (credentials.length > 0) {
            const dcqlQuery = {
                credentials,
            };
            if(credentials.length > 1) {
                dcqlQuery.credential_sets = [{
                    options: credentials.map(credential => [credential.id]),
                }];
            }
            return {
                protocol: this.protocol,
                data: {
                    dcql_query: dcqlQuery,
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
                        id: createCredentialQueryId(format, documentType),
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

    async verify(credentialData, origin, nonce, options = {}) {
        const vpToken = credentialData.vp_token;
        for(const key in vpToken) {
            if(credentialQueryById[key]?.format === CredentialFormat.MSO_MDOC) {
                //TODO: Support response with multiple credential formats in the future
                return this._verifyMsoMdoc(vpToken[key], origin, nonce, options);
            }
        }
        throw new Error('Unsupported credential format');
    }

    async _verifyMsoMdoc(tokens, origin, nonce, options = {}) {
        const processedDocuments = [];
        const decodedTokens = [];
        const documents = [];
        const claims = {};
        let trusted = true;
        let valid = true;

        // Generate session transcript if origin and nonce are provided
        const sessionTranscript = await this._generateSessionTranscript(origin, nonce);

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
            const { claims: documentClaims, certificate, valid: documentValid, invalidReasons } = await verifyDocument(document, sessionTranscript);
            const trustInfo = await options.registry.resolveCertificateTrust(certificate, options);
            trusted = trusted && trustInfo.trusted;
            valid = valid && documentValid;
            for(const key in documentClaims) {
                claims[key] = documentClaims[key];
            }
            const processedDocument = {
                claims: documentClaims,
                valid: documentValid,
                trusted: trustInfo.trusted,
                issuer: trustInfo.issuer || null,
                document: document,
            };
            if(!documentValid) processedDocument.invalidReasons = invalidReasons;
            if(!trustInfo.trusted) processedDocument.untrustedReasons = trustInfo.untrustedReasons;
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

    async _generateSessionTranscript(origin, nonce, jwkThumbprint = null) {
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
}

const createCredentialQueryId = (format, credentialType) => {
    return `cred-${format.replace(/[^a-zA-Z0-9]/g, '_')}-${credentialType.replace(/[^a-zA-Z0-9]/g, '_')}`;
};

const credentialQueryById = {};
for(const format of ProtocolFormats[Protocol.OPENID4VP]) {
    for(const documentType of Object.values(DocumentType)) {
        credentialQueryById[createCredentialQueryId(format, documentType)] = {
            format: format,
            documentType: documentType,
        };
    }
}

const openid4vpProtocolHelper = new OpenID4VPProtocolHelper();
export default openid4vpProtocolHelper;
