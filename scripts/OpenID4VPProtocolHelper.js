import { Protocol, ProtocolFormats, CredentialFormat, ClaimMappings } from './constants.js';
import { decodeVpToken, verifyDocument } from './CBORHelper.js';

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
                        id: `cred_${format}`,
                        claims: formatClaims,
                        meta: {}
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

    async verify(credentialData, options) {
        let vpToken = credentialData.vp_token;
        if(vpToken.cred_mso_mdoc) {
            return this.verifyMsoMdoc(vpToken.cred_mso_mdoc);
        }
        throw new Error('Unsupported credential format');
    }

    async verifyMsoMdoc(tokens) {
        const decodedTokens = [];
        const claims = {};
        const documents = [];
        for(let token of tokens) {
            //verify base64url-encoded CBOR data
            const decoded = await decodeVpToken(token);
            console.log('decoded', decoded);
            decodedTokens.push(decoded);
        }
        for(let decodedToken of decodedTokens) {
            documents.push(...decodedToken.documents);
        }
        for(let document of documents) {
            let { claims: documentClaims, verified: documentVerified } = await verifyDocument(document);
            for(let key in documentClaims) {
                claims[key] = {
                    value: documentClaims[key],
                    verified: documentVerified,
                    trusted: true,
                };
            }
        }
        return {
            verified: true,
            claims: claims,
        };
    }
}

let openid4vpProtocolHelper = new OpenID4VPProtocolHelper();
export default openid4vpProtocolHelper;