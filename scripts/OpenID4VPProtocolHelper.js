import { Protocol, ProtocolFormats, CredentialFormat, ClaimMappings } from './constants.js';
import { decodeVpToken, verifyDocument } from './oid4vp/MDocHelper.js';

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
                        meta: {},
                        trusted_authorities: [{
                            "type": "aki",
                            "values": ["s9tIpPmhxdiuN"]
                          }]
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

    async verify(credentialData, trustFrameworks) {
        let vpToken = credentialData.vp_token;
        if(vpToken.cred_mso_mdoc) {
            return this.verifyMsoMdoc(vpToken.cred_mso_mdoc, trustFrameworks);
        }
        throw new Error('Unsupported credential format');
    }

    async verifyMsoMdoc(tokens, trustFrameworks) {
        const decodedTokens = [];
        const claims = {};
        const documents = [];
        let issuer = true;
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
            let { claims: documentClaims, trustedIssuer: trustedIssuer } = await verifyDocument(document);
            issuer = issuer && trustedIssuer;
            for(let key in documentClaims) {
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

let openid4vpProtocolHelper = new OpenID4VPProtocolHelper();
export default openid4vpProtocolHelper;