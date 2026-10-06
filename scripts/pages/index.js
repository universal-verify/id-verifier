// Import the library
import {
    Verifier,
    generateNonce,
    generateJWK,
    Claim,
    DocumentType,
    TrustList,
} from '../../build/id-verifier.bundled.js';

class IndexPage {
    constructor() {
        this.statusEl = null;
        this.requestBtn = null;
        this.resultEl = null;
        this.verifier = new Verifier();

        this.setup();
    }

    static DEFAULT_TRUST_LISTS = [TrustList.UV, TrustList.AAMVA_DTS];

    setup() {
        this.statusEl = document.getElementById('status');
        this.requestBtn = document.getElementById('requestBtn');
        this.resultEl = document.getElementById('result');

        this.checkCompatibility();
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Add event listeners to buttons
        if (this.requestBtn) {
            this.requestBtn.addEventListener('click', () => this.requestCredentials());
        }

        // Add event listeners to configuration inputs for live sample script updates
        this.setupConfigurationListeners();
    }

    setupConfigurationListeners() {
        const checkboxes = document.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updateSampleScript());
        });

        const trustedIssuerCertificates = document.getElementById('trustedIssuerCertificates');
        if(trustedIssuerCertificates) {
            trustedIssuerCertificates.addEventListener('input', () => this.updateSampleScript());
        }

        // Initial update
        this.updateSampleScript();
    }

    /**
     * Read the user's document type configuration from the checkboxes
     * @returns {Array<string>} Array of selected document type values
     */
    getDocumentTypeConfiguration() {
        const selectedDocumentTypes = [];

        // Map of checkbox names to DocumentType values
        const documentTypeMapping = {
            'mobileDriversLicense': DocumentType.MOBILE_DRIVERS_LICENSE,
            'photoId': DocumentType.PHOTO_ID,
            'euPersonalId': DocumentType.EU_PERSONAL_ID,
            'japanMyNumberCard': DocumentType.JAPAN_MY_NUMBER_CARD
        };

        // Check each document type checkbox
        for (const [checkboxName, documentTypeValue] of Object.entries(documentTypeMapping)) {
            const checkbox = document.querySelector(`input[name="${checkboxName}"]`);
            if (checkbox && checkbox.checked) {
                selectedDocumentTypes.push(documentTypeValue);
            }
        }

        return selectedDocumentTypes;
    }

    /**
     * Read the user's claim configuration from the checkboxes
     * @returns {Array<string>} Array of selected claim values
     */
    getClaimConfiguration() {
        const selectedClaims = [];

        // Map of checkbox names to Claim values
        const claimMapping = {
            'givenName': Claim.GIVEN_NAME,
            'familyName': Claim.FAMILY_NAME,
            'birthDate': Claim.BIRTH_DATE,
            'birthYear': Claim.BIRTH_YEAR,
            'age': Claim.AGE,
            'ageOver18': Claim.AGE_OVER_18,
            'ageOver21': Claim.AGE_OVER_21,
            'sex': Claim.SEX,
            'height': Claim.HEIGHT,
            'weight': Claim.WEIGHT,
            'eyeColor': Claim.EYE_COLOR,
            'hairColor': Claim.HAIR_COLOR,
            'address': Claim.ADDRESS,
            'city': Claim.CITY,
            'state': Claim.STATE,
            'postalCode': Claim.POSTAL_CODE,
            'country': Claim.COUNTRY,
            'nationality': Claim.NATIONALITY,
            'placeOfBirth': Claim.PLACE_OF_BIRTH,
            'documentNumber': Claim.DOCUMENT_NUMBER,
            'issuingAuthority': Claim.ISSUING_AUTHORITY,
            'issuingCountry': Claim.ISSUING_COUNTRY,
            'issuingJurisdiction': Claim.ISSUING_JURISDICTION,
            'issueDate': Claim.ISSUE_DATE,
            'expiryDate': Claim.EXPIRY_DATE,
            'drivingPrivileges': Claim.DRIVING_PRIVILEGES,
            'portrait': Claim.PORTRAIT,
            'signature': Claim.SIGNATURE
        };

        // Check each claim checkbox
        for (const [checkboxName, claimValue] of Object.entries(claimMapping)) {
            const checkbox = document.querySelector(`input[name="${checkboxName}"]`);
            if (checkbox && checkbox.checked) {
                selectedClaims.push(claimValue);
            }
        }

        return selectedClaims;
    }

    getTrustListConfiguration() {
        const trustLists = [];
        const trustListMapping = {
            uv: TrustList.UV,
            aamva_dts: TrustList.AAMVA_DTS,
        };

        document.querySelectorAll('input[name="registryTrustList"]').forEach(checkbox => {
            if(checkbox.checked && trustListMapping[checkbox.value]) {
                trustLists.push(trustListMapping[checkbox.value]);
            }
        });

        return trustLists;
    }

    usesDefaultTrustLists(trustLists) {
        return trustLists.length === IndexPage.DEFAULT_TRUST_LISTS.length
            && IndexPage.DEFAULT_TRUST_LISTS.every(trustList => trustLists.includes(trustList));
    }

    getTrustedIssuerCertificatesConfiguration(options = {}) {
        const {
            strict = true,
        } = options;
        const input = this.normalizeTrustedIssuerCertificateInput(
            document.getElementById('trustedIssuerCertificates')?.value || ''
        ).trim();
        if(!input) return [];

        const pemRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
        const certificates = input.match(pemRegex) || [];
        const extraText = input.replace(pemRegex, '').trim();

        if(strict && (certificates.length === 0 || extraText.length > 0)) {
            throw new Error('Trusted issuer certificates must be PEM-encoded X.509 certificates.');
        }

        return certificates.map(certificate => certificate.trim());
    }

    normalizeTrustedIssuerCertificateInput(input) {
        return input
            .replace(/\\r\\n/g, '\n')
            .replace(/\\n/g, '\n')
            .replace(/\\r/g, '\n');
    }

    getVerifierConfiguration(options = {}) {
        const verifierConfig = {};
        const trustLists = this.getTrustListConfiguration();
        const trustedIssuerCertificates = this.getTrustedIssuerCertificatesConfiguration(options);

        if(!this.usesDefaultTrustLists(trustLists)) verifierConfig.trustLists = trustLists;
        if(trustedIssuerCertificates.length > 0) {
            verifierConfig.trustedIssuerRegistry = { trustedIssuerCertificates };
        }

        return verifierConfig;
    }

    updateSampleScript() {
        const claimsListElement = document.getElementById('claimsList');
        const documentTypesListElement = document.getElementById('documentTypesList');

        if (!claimsListElement || !documentTypesListElement) return;

        const claims = this.getClaimConfiguration();
        const documentTypes = this.getDocumentTypeConfiguration();
        const verifierConfig = this.getVerifierConfiguration({ strict: false });

        if (claims.length === 0) {
            claimsListElement.textContent = '// No claims selected';
        } else {
            // Create reverse mapping from Claim values to enum names
            const claimEnumNames = {};
            for (const [enumName, enumValue] of Object.entries(Claim)) {
                claimEnumNames[enumValue] = `Claim.${enumName}`;
            }

            // Format the claims using enum format
            const formattedClaims = claims.map(claim =>
                claimEnumNames[claim] || `'${claim}'`
            ).join(', ');
            claimsListElement.textContent = formattedClaims;
        }

        if (documentTypes.length === 0) {
            documentTypesListElement.textContent = '// No document types selected';
        } else {
            // Create reverse mapping from DocumentType values to enum names
            const documentTypeEnumNames = {};
            for (const [enumName, enumValue] of Object.entries(DocumentType)) {
                documentTypeEnumNames[enumValue] = `DocumentType.${enumName}`;
            }

            // Format the document types using enum format
            const formattedDocumentTypes = documentTypes.map(docType =>
                documentTypeEnumNames[docType] || `'${docType}'`
            ).join(', ');
            documentTypesListElement.textContent = formattedDocumentTypes;
        }

        const verifierConfigElement = document.getElementById('verifierConfig');
        if(verifierConfigElement) {
            this.updateVerifierSample(verifierConfig, verifierConfigElement);
        }
    }

    updateVerifierSample(verifierConfig, verifierConfigElement) {
        const hasVerifierConfig = Object.keys(verifierConfig).length > 0;
        const hasTrustListConstants = verifierConfig.trustLists?.length > 0;
        document.getElementById('trustListImport')?.classList.toggle('hidden', !hasTrustListConstants);
        document.getElementById('verifierDefaultLine')?.classList.toggle('hidden', hasVerifierConfig);
        document.getElementById('verifierConfiguredStart')?.classList.toggle('hidden', !hasVerifierConfig);
        document.getElementById('verifierConfiguredEnd')?.classList.toggle('hidden', !hasVerifierConfig);
        verifierConfigElement.classList.toggle('hidden', !hasVerifierConfig);
        verifierConfigElement.innerHTML = hasVerifierConfig ? this.formatObjectProperties(verifierConfig, 1) : '';
    }

    formatObjectProperties(object, indentLevel) {
        return Object.entries(object)
            .map(([key, value], index, entries) => this.formatProperty(
                key,
                value,
                indentLevel,
                index < entries.length - 1
            ))
            .join('');
    }

    formatProperty(key, value, indentLevel, includeComma) {
        const comma = includeComma ? ',' : '';
        const keyHtml = `<span class="text-blue-600">${this.escapeHtml(key)}</span>`;
        if(Array.isArray(value)) {
            if(value.length === 0) {
                return this.formatSampleLine(`${this.formatIndent(indentLevel)}${keyHtml}: []${comma}`);
            }
            return [
                this.formatSampleLine(`${this.formatIndent(indentLevel)}${keyHtml}: [`),
                ...value.map((item, index) => this.formatSampleLine(
                    `${this.formatIndent(indentLevel + 1)}${this.formatValue(item, key)}${index < value.length - 1 ? ',' : ''}`
                )),
                this.formatSampleLine(`${this.formatIndent(indentLevel)}]${comma}`),
            ].join('');
        }
        if(value && typeof value === 'object') {
            return [
                this.formatSampleLine(`${this.formatIndent(indentLevel)}${keyHtml}: {`),
                this.formatObjectProperties(value, indentLevel + 1),
                this.formatSampleLine(`${this.formatIndent(indentLevel)}}${comma}`),
            ].join('');
        }
        return this.formatSampleLine(`${this.formatIndent(indentLevel)}${keyHtml}: ${this.formatValue(value)}${comma}`);
    }

    formatValue(value, key) {
        if(key === 'trustLists') {
            const constant = Object.entries(TrustList).find(([, trustList]) => trustList === value);
            if(constant) {
                return `<span class="text-blue-600">TrustList.${this.escapeHtml(constant[0])}</span>`;
            }
        }
        if(typeof value === 'string') {
            return `<span class="text-green-600">'${this.escapeHtml(this.escapeJavaScriptString(value))}'</span>`;
        }
        if(typeof value === 'boolean') {
            return `<span class="text-purple-600">${value}</span>`;
        }
        return this.escapeHtml(String(value));
    }

    formatSampleLine(content) {
        return `<div class="mb-2">${content}</div>`;
    }

    formatIndent(indentLevel) {
        return '&nbsp;'.repeat(indentLevel * 2);
    }

    escapeJavaScriptString(value) {
        return value
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/\r?\n/g, '\\n');
    }

    escapeHtml(value) {
        return value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    checkCompatibility() {
        if (typeof navigator === 'undefined' || !navigator.credentials || typeof DigitalCredential === 'undefined') {
            this.updateStatus('❌ Digital Credentials API not found. Please try enabling the DigitalCredentials feature flag in Chrome or Safari (iOS 26+).', 'error');
            return false;
        }

        this.updateStatus('✅ Digital Credentials API found! Requests <a href="https://caniuse.com/mdn-api_digitalcredential" target="_blank" style="text-decoration: underline; color: #007bff;">might</a> work.', 'success');
        this.enableButtons();
        return true;
    }

    updateStatus(message, type = 'info') {
        if (!this.statusEl) return;

        this.statusEl.innerHTML = message;

        const classes = {
            info: 'bg-blue-50 border border-blue-200 text-blue-800 rounded-md p-4 mb-4',
            success: 'bg-green-50 border border-green-200 text-green-800 rounded-md p-4 mb-4',
            error: 'bg-red-50 border border-red-200 text-red-800 rounded-md p-4 mb-4'
        };

        this.statusEl.className = classes[type] || classes.info;
    }

    enableButtons() {
        if (this.requestBtn) this.requestBtn.disabled = false;
    }

    showResult(message, type = 'info') {
        if (!this.resultEl) return;

        this.resultEl.style.display = 'block';
        this.resultEl.textContent = message;

        const classes = {
            info: 'bg-blue-50 border border-blue-200 text-blue-800 rounded-md p-4 mt-4 whitespace-pre-wrap font-mono text-sm overflow-x-auto text-nowrap',
            success: 'bg-green-50 border border-green-200 text-green-800 rounded-md p-4 mt-4 whitespace-pre-wrap font-mono text-sm overflow-x-auto text-nowrap',
            error: 'bg-red-50 border border-red-200 text-red-800 rounded-md p-4 mt-4 whitespace-pre-wrap font-mono text-sm overflow-x-auto text-nowrap'
        };

        this.resultEl.className = classes[type] || classes.info;
    }

    async requestCredentials() {
        this.showResult('Reading configuration and requesting credentials...', 'info');
        console.log('Reading configuration...');

        try {
            // Get the user's configuration
            const claims = this.getClaimConfiguration();
            const documentTypes = this.getDocumentTypeConfiguration();
            this.verifier = new Verifier(this.getVerifierConfiguration());

            const nonce = generateNonce();
            const jwk = await generateJWK();
            const origin = window.location.origin;

            // Create request parameters using the user's configuration
            const requestParams = this.verifier.createWebCredentialsRequest({
                documentTypes,
                claims,
                nonce,
                jwk,
            });
            console.log('Request parameters:', JSON.stringify(requestParams, null, 2));

            // Request the credential
            const credentials = await this.verifier.requestCredentials(requestParams);
            console.log('Credential:', credentials);

            this.showResult('✅ Credential received successfully!\n\nProcessing credential...', 'info');

            // Verify the credential
            const result = await this.verifier.processCredentials(credentials, { nonce, origin, jwk });
            console.log('Credential processed:', result);

            const replaceKeys = ['document', 'sessionTranscript'];
            this.showResult('✅ Credential request successful!\n\n' +
                JSON.stringify(result, (key, value) => replaceKeys.includes(key) ? '...' : value, 2).replaceAll('"..."', '...'), 'success');

        } catch (error) {
            let errorMessage = error.name;
            if(error.message) errorMessage += `: ${error.message}`;
            if(navigator.userAgent.includes('Safari')) {
                if(error.name === 'TypeError') {
                    errorMessage += ' (Safari currently lacks support outside of iOS 26)';
                } else if(error.name === 'NotSupportedError') {
                    errorMessage += ' (Safari currently lacks support outside of iOS 26)';
                } else if(error.name === 'UnknownError') {
                    errorMessage += ' (Safari uses this error to indicate user closed the dialog)';
                }
            }
            this.showResult('❌ Credential request failed:\n' + errorMessage, 'error');
            console.error('Credential request failed:', error);
        }
    }
}

// Create and export the page instance
const indexPage = new IndexPage();
export default indexPage;
