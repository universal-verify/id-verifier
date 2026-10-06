# Claim mappings

This reference shows the claims ID Verifier supports for each document type.

These mappings apply to `mso_mdoc` credentials requested through both OpenID4VP and ISO mdoc. Claims without a mapping are omitted from requests for that document type. A mapped claim may still be absent from an individual credential.

## Supported claims

`Yes` means the SDK has a mapping for that claim. `—` means it has no mapping for that document type.

| Claim | Mobile Driver's License | Photo ID | EU Personal ID | EU Age Verification | Japan My Number Card |
| --- | --- | --- | --- | --- | --- |
| `Claim.GIVEN_NAME` | Yes | Yes | Yes | — | — |
| `Claim.FAMILY_NAME` | Yes | Yes | Yes | — | — |
| `Claim.BIRTH_DATE` | Yes | Yes | Yes | — | Yes |
| `Claim.BIRTH_YEAR` | Yes | Yes | Yes | — | — |
| `Claim.AGE` | Yes | Yes | Yes | — | Yes |
| `Claim.AGE_OVER_18` | Yes | Yes | Yes | Yes | Yes |
| `Claim.AGE_OVER_21` | Yes | Yes | Yes | Yes | Yes |
| `Claim.SEX` | Yes | Yes | Yes | — | Yes |
| `Claim.HEIGHT` | Yes | — | — | — | — |
| `Claim.WEIGHT` | Yes | — | — | — | — |
| `Claim.EYE_COLOR` | Yes | — | — | — | — |
| `Claim.HAIR_COLOR` | Yes | — | — | — | — |
| `Claim.ADDRESS` | Yes | Yes | Yes | — | Yes |
| `Claim.CITY` | Yes | Yes | Yes | — | — |
| `Claim.STATE` | Yes | Yes | Yes | — | — |
| `Claim.POSTAL_CODE` | Yes | Yes | Yes | — | — |
| `Claim.COUNTRY` | Yes | Yes | Yes | — | — |
| `Claim.NATIONALITY` | Yes | Yes | Yes | — | — |
| `Claim.PLACE_OF_BIRTH` | Yes | Yes | Yes | — | — |
| `Claim.DOCUMENT_NUMBER` | Yes | Yes | Yes | — | Yes |
| `Claim.ISSUING_AUTHORITY` | Yes | Yes | Yes | — | — |
| `Claim.ISSUING_COUNTRY` | Yes | Yes | Yes | — | — |
| `Claim.ISSUING_JURISDICTION` | Yes | Yes | Yes | — | — |
| `Claim.ISSUE_DATE` | Yes | Yes | Yes | — | — |
| `Claim.EXPIRY_DATE` | Yes | Yes | Yes | — | — |
| `Claim.DRIVING_PRIVILEGES` | Yes | — | — | — | — |
| `Claim.PORTRAIT` | Yes | Yes | Yes | Yes | Yes |
| `Claim.SIGNATURE` | Yes | — | — | — | — |

## Field mappings

Each mapped claim identifies a namespace and a field within that namespace. See `ClaimMappings` in [scripts/constants.js](../scripts/constants.js) for the details.
