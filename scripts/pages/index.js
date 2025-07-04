// Import the library
import { 
    createRequestParams, 
    getCredentials, 
    verifyCredentials,
    SupportedClaim,
    DocumentType
} from '../id-verifier.js';

class IndexPage {
    constructor() {
        this.statusEl = null;
        this.requestBtn = null;
        this.resultEl = null;
        
        this.setup();
    }

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
        
        // Add event listeners to checkboxes for live sample script updates
        this.setupCheckboxListeners();
    }

    setupCheckboxListeners() {
        // Get all checkboxes in the configuration section
        const checkboxes = document.querySelectorAll('input[type="checkbox"]');
        
        // Add change event listener to each checkbox
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', () => {
                this.updateSampleScript();
            });
        });
        
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
        
        // Map of checkbox names to SupportedClaim values
        const claimMapping = {
            'givenName': SupportedClaim.GIVEN_NAME,
            'familyName': SupportedClaim.FAMILY_NAME,
            'birthDate': SupportedClaim.BIRTH_DATE,
            'birthYear': SupportedClaim.BIRTH_YEAR,
            'age': SupportedClaim.AGE,
            'ageOver18': SupportedClaim.AGE_OVER_18,
            'ageOver21': SupportedClaim.AGE_OVER_21,
            'sex': SupportedClaim.SEX,
            'height': SupportedClaim.HEIGHT,
            'weight': SupportedClaim.WEIGHT,
            'eyeColor': SupportedClaim.EYE_COLOR,
            'hairColor': SupportedClaim.HAIR_COLOR,
            'address': SupportedClaim.ADDRESS,
            'city': SupportedClaim.CITY,
            'state': SupportedClaim.STATE,
            'postalCode': SupportedClaim.POSTAL_CODE,
            'country': SupportedClaim.COUNTRY,
            'nationality': SupportedClaim.NATIONALITY,
            'placeOfBirth': SupportedClaim.PLACE_OF_BIRTH,
            'documentNumber': SupportedClaim.DOCUMENT_NUMBER,
            'issuingAuthority': SupportedClaim.ISSUING_AUTHORITY,
            'issuingCountry': SupportedClaim.ISSUING_COUNTRY,
            'issuingJurisdiction': SupportedClaim.ISSUING_JURISDICTION,
            'issueDate': SupportedClaim.ISSUE_DATE,
            'expiryDate': SupportedClaim.EXPIRY_DATE,
            'drivingPrivileges': SupportedClaim.DRIVING_PRIVILEGES,
            'portrait': SupportedClaim.PORTRAIT,
            'signature': SupportedClaim.SIGNATURE
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

    updateSampleScript() {
        const claimsListElement = document.getElementById('claimsList');
        const documentTypesListElement = document.getElementById('documentTypesList');
        
        if (!claimsListElement || !documentTypesListElement) return;
        
        const claims = this.getClaimConfiguration();
        const documentTypes = this.getDocumentTypeConfiguration();
        
        if (claims.length === 0) {
            claimsListElement.textContent = '// No claims selected';
        } else {
            // Format the claims as a nice string with quotes
            const formattedClaims = claims.map(claim => `'${claim}'`).join(', ');
            claimsListElement.textContent = formattedClaims;
        }
        
        if (documentTypes.length === 0) {
            documentTypesListElement.textContent = '// No document types selected';
        } else {
            // Format the document types as a nice string with quotes
            const formattedDocumentTypes = documentTypes.map(docType => `'${docType}'`).join(', ');
            documentTypesListElement.textContent = formattedDocumentTypes;
        }
    }

    checkCompatibility() {
        if (typeof navigator === 'undefined' || !navigator.credentials) {
            this.updateStatus('❌ Digital Credentials API not supported in this browser', 'error');
            return false;
        }

        this.updateStatus('✅ Digital Credentials API is supported! You can request credentials.', 'success');
        this.enableButtons();
        return true;
    }

    updateStatus(message, type = 'info') {
        if (!this.statusEl) return;

        this.statusEl.textContent = message;
        
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
            
            console.log('Selected claims:', claims);
            console.log('Selected document types:', documentTypes);

            // Create request parameters using the user's configuration
            const requestParams = createRequestParams({
                documentTypes,
                claims
            });
            console.log('Request parameters:', JSON.stringify(requestParams, null, 2));

            // Request the credential
            const credential = await getCredentials(requestParams);
            console.log('Credential:', credential);

            this.showResult('✅ Credential received successfully!\n\n' + 
                JSON.stringify(credential, null, 2), 'success');
            
            // Verify the credential
            const verified = await verifyCredentials(credential);
            console.log('Credential verified:', verified);

            this.showResult('✅ Credential verified successfully!\n\n' + 
                JSON.stringify(verified, null, 2), 'success');

        } catch (error) {
            this.showResult('❌ Credential request failed:\n' + error.message, 'error');
            console.error('Credential request failed:', error);
        }
    }
}

// Create and export the page instance
let indexPage = new IndexPage();
export default indexPage;