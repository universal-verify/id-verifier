import { Protocol, ProtocolFormats, CredentialFormat, ClaimMappings, CredentialId, createCredentialId } from './constants.js';
import { decodeVpToken, verifyDocument } from './oid4vp/mdoc-helper.js';
import { generateSessionTranscript } from './utils.js';

class OpenID4VPProtocolHelper {
    constructor() {
        this.protocol = Protocol.OPENID4VP;
    }

    createQueryCredentials(documentTypes, claims) {
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

    async verify(credentialData, trustFrameworks, origin, nonce) {
        const vpToken = credentialData.vp_token;
        for(const key in vpToken) {
            if(CredentialId[key].format === CredentialFormat.MSO_MDOC) {
                //TODO: Support response with multiple credentials in the future
                return this.verifyMsoMdoc(vpToken[key], trustFrameworks, origin, nonce);
            }
        }
        throw new Error('Unsupported credential format');
    }

    async verifyMsoMdoc(tokens, trustFrameworks, origin, nonce) {
        const decodedTokens = [];
        const claims = {};
        const documents = [];
        let issuer = true;

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
            issuer = issuer && trustedIssuer;
            for(const key in documentClaims) {
                claims[key] = documentClaims[key];
            }
        }
        return {
            claims: claims,
            trusted: !!issuer && issuer.trust_frameworks.some(tf => trustFrameworks.includes(tf)),
            issuer: typeof issuer === 'object' ? issuer : null,
        };
    }
}

const openid4vpProtocolHelper = new OpenID4VPProtocolHelper();
export default openid4vpProtocolHelper;