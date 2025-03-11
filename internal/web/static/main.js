// Reference to the noble-ed25519 library (loaded from jsdelivr in the HTML)
// The library exposes its methods directly on the window namespace as nobleEd25519
document.addEventListener('DOMContentLoaded', () => {
    // Check if the noble library is loaded
    if (typeof window.nobleEd25519 === 'undefined') {
        console.error('Noble ed25519 library not loaded. Check the script tag in the HTML.');
    }
});

// Polyfill Buffer for browser environments if not available
if (typeof Buffer === 'undefined') {
    window.Buffer = {
        from: function(data, encoding) {
            if (encoding === 'hex') {
                // Convert hex string to Uint8Array
                const hexString = data.toString();
                const result = new Uint8Array(hexString.length / 2);
                for (let i = 0; i < hexString.length; i += 2) {
                    result[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
                }
                return result;
            } else {
                // Default behavior for other encodings
                return new TextEncoder().encode(data.toString());
            }
        },
        toString: function(buffer, encoding) {
            if (encoding === 'hex') {
                return Array.from(buffer)
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            } else {
                return new TextDecoder().decode(buffer);
            }
        }
    };
}

document.addEventListener('DOMContentLoaded', () => {
    // Element references
    const addFileBtn = document.getElementById('add-file');
    const filesContainer = document.getElementById('files-container');
    const nextToVaultsBtn = document.getElementById('next-to-vaults');
    const backToFilesBtn = document.getElementById('back-to-files');
    const recoverVaultBtn = document.getElementById('recover-vault');
    const startOverBtn = document.getElementById('start-over');
    const backFromErrorBtn = document.getElementById('back-from-error');

    // Step elements
    const steps = {
        files: document.getElementById('step-1'),
        vaults: document.getElementById('step-2'),
        results: document.getElementById('step-3')
    };

    // Loading and results elements
    const vaultsLoading = document.getElementById('vaults-loading');
    const vaultsContainer = document.getElementById('vaults-container');
    const vaultsList = document.getElementById('vaults-list');
    const recoveryLoading = document.getElementById('recovery-loading');
    const recoveryError = document.getElementById('recovery-error');
    const errorMessage = document.getElementById('error-message');
    const recoveryResults = document.getElementById('recovery-results');

    // Transaction dialogs
    const transactionDialogs = {
        xrpl: document.getElementById('xrpl-transaction-dialog'),
        bittensor: document.getElementById('bittensor-transaction-dialog'),
        solana: document.getElementById('solana-transaction-dialog')
    };

    // Current state
    let fileCounter = 1;
    let selectedVaultId = null;
    let selectedVaultName = null;
    let recoveredKeys = null;

    // ==================
    // Event Listeners
    // ==================

    // Add file button
    addFileBtn.addEventListener('click', addFileInput);

    // Next button to go to vaults list
    nextToVaultsBtn.addEventListener('click', () => {
        if (validateFilesAndMnemonics()) {
            showStep('vaults');
            loadVaults();
        }
    });

    // Back button from vaults to files
    backToFilesBtn.addEventListener('click', () => {
        showStep('files');
    });

    // Recover vault button
    recoverVaultBtn.addEventListener('click', () => {
        if (selectedVaultId) {
            showStep('results');
            recoverVault();
        } else {
            alert('Please select a vault to recover');
        }
    });

    // Start over button
    startOverBtn.addEventListener('click', () => {
        resetState();
        showStep('files');
    });

    // Back button from error
    backFromErrorBtn.addEventListener('click', () => {
        showStep('vaults');
        recoveryError.style.display = 'none';
    });

    // Initialize copy buttons
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            const targetElement = document.getElementById(targetId);
            copyToClipboard(targetElement.textContent);

            // Change button text briefly
            const originalText = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => {
                btn.textContent = originalText;
            }, 1500);
        });
    });

    // Transaction buttons
    document.querySelectorAll('.transaction-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const blockchain = btn.getAttribute('data-blockchain');
            openTransactionDialog(blockchain);
        });
    });

    // Close dialog buttons
    document.querySelectorAll('.close-dialog').forEach(closeBtn => {
        closeBtn.addEventListener('click', () => {
            closeBtn.closest('.transaction-dialog').style.display = 'none';
        });
    });

    // Close dialogs when clicking outside the content
    window.addEventListener('click', (event) => {
        Object.values(transactionDialogs).forEach(dialog => {
            if (event.target === dialog) {
                dialog.style.display = 'none';
            }
        });
    });

    // Connect terminal buttons
    document.getElementById('xrpl-check-balance').addEventListener('click', checkXRPLBalance);
    document.getElementById('xrpl-create-tx').addEventListener('click', () => createTerminalTransaction('xrpl'));
    document.getElementById('xrpl-terminal-close').addEventListener('click', () => closeTerminal('xrpl'));
    
    document.getElementById('bittensor-create-tx').addEventListener('click', () => createTerminalTransaction('bittensor'));
    document.getElementById('bittensor-terminal-close').addEventListener('click', () => closeTerminal('bittensor'));
    
    document.getElementById('solana-check-balance').addEventListener('click', checkSolanaBalance);
    document.getElementById('solana-create-tx').addEventListener('click', () => createTerminalTransaction('solana'));
    document.getElementById('solana-terminal-close').addEventListener('click', () => closeTerminal('solana'));

    // ==================
    // Functions
    // ==================

    // Show a specific step and hide others
    function showStep(stepName) {
        Object.entries(steps).forEach(([name, element]) => {
            if (name === stepName) {
                element.classList.add('active');
            } else {
                element.classList.remove('active');
            }
        });
    }

    // Add a new file input group
    function addFileInput() {
        fileCounter++;

        const fileGroup = document.createElement('div');
        fileGroup.className = 'file-input-group';
        fileGroup.dataset.index = fileCounter;

        fileGroup.innerHTML = `
            <div class="file-upload">
                <label for="file-${fileCounter}">Select File</label>
                <input type="file" id="file-${fileCounter}" class="file-input" accept=".json,.bin">
                <span class="file-name">No file selected</span>
            </div>
            <div class="mnemonic-input">
                <label for="mnemonic-${fileCounter}">24-word Mnemonic Phrase</label>
                <textarea id="mnemonic-${fileCounter}" class="mnemonic" rows="3" placeholder="Enter your 24-word mnemonic phrase for this file..."></textarea>
            </div>
            <button class="remove-file" data-index="${fileCounter}">✕</button>
        `;

        filesContainer.appendChild(fileGroup);

        // Add event listener for the new file input
        const fileInput = document.getElementById(`file-${fileCounter}`);
        fileInput.addEventListener('change', handleFileSelection);

        // Add event listener for the remove button
        const removeBtn = fileGroup.querySelector('.remove-file');
        removeBtn.addEventListener('click', removeFileInput);
    }

    // Remove a file input group
    function removeFileInput(event) {
        const index = event.target.dataset.index;
        const fileGroup = document.querySelector(`.file-input-group[data-index="${index}"]`);

        // Only allow removal if there's more than one file input
        if (document.querySelectorAll('.file-input-group').length > 1) {
            fileGroup.remove();
        }
    }

    // Handle file selection event
    function handleFileSelection(event) {
        const fileInput = event.target;
        const fileName = fileInput.files[0]?.name || 'No file selected';
        const fileNameEl = fileInput.parentElement.querySelector('.file-name');
        fileNameEl.textContent = fileName;
    }

    // Add event listeners to initial file input
    function initializeFileInputs() {
        document.querySelectorAll('.file-input').forEach(input => {
            input.addEventListener('change', handleFileSelection);
        });

        document.querySelectorAll('.remove-file').forEach(btn => {
            btn.addEventListener('click', removeFileInput);
        });
        
        // Clear error message when a file is selected or mnemonic is entered
        const errorContainer = document.getElementById('files-error');
        
        document.querySelectorAll('.file-input, .mnemonic').forEach(input => {
            input.addEventListener('change', () => {
                errorContainer.style.display = 'none';
            });
        });
        
        document.querySelectorAll('.mnemonic').forEach(textarea => {
            textarea.addEventListener('input', () => {
                errorContainer.style.display = 'none';
            });
        });
    }

    // Validate files and mnemonics before proceeding
    function validateFilesAndMnemonics() {
        const fileInputs = document.querySelectorAll('.file-input');
        const mnemonicInputs = document.querySelectorAll('.mnemonic');
        const errorContainer = document.getElementById('files-error');
        const errorMessage = document.getElementById('files-error-message');

        // Hide previous error messages
        errorContainer.style.display = 'none';
        
        // Check if at least one file is selected
        let hasFile = false;
        fileInputs.forEach(input => {
            if (input.files.length > 0) {
                hasFile = true;
            }
        });

        if (!hasFile) {
            errorMessage.textContent = 'Please select at least one vault file';
            errorContainer.style.display = 'flex';
            return false;
        }

        // Check if each file has a corresponding mnemonic
        let valid = true;
        fileInputs.forEach((input, index) => {
            if (input.files.length > 0) {
                const mnemonic = mnemonicInputs[index].value.trim();
                if (!mnemonic) {
                    errorMessage.textContent = `Please enter the mnemonic phrase for ${input.files[0].name}`;
                    errorContainer.style.display = 'flex';
                    valid = false;
                    return;
                }

                // Basic validation for mnemonic (24 words)
                const words = mnemonic.split(/\s+/);
                if (words.length !== 24) {
                    errorMessage.textContent = `The mnemonic phrase for ${input.files[0].name} should contain 24 words (found ${words.length})`;
                    errorContainer.style.display = 'flex';
                    valid = false;
                    return;
                }
            }
        });

        return valid;
    }

    // Load vaults from the selected files
    function loadVaults() {
        // Get error container references
        const errorContainer = document.getElementById('files-error');
        const errorMessage = document.getElementById('files-error-message');
        
        // Hide any previous error messages
        errorContainer.style.display = 'none';
        
        // Show loading indicator
        vaultsLoading.style.display = 'block';
        vaultsContainer.style.display = 'none';

        // Create form data with files and mnemonics
        const formData = new FormData();

        document.querySelectorAll('.file-input').forEach((input, index) => {
            if (input.files.length > 0) {
                formData.append('files', input.files[0]);
                const mnemonicInput = document.querySelectorAll('.mnemonic')[index];
                formData.append('mnemonics', mnemonicInput.value.trim());
            }
        });

        // Send the API request
        fetch('/api/list-vaults', {
            method: 'POST',
            body: formData
        })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text);
                    });
                }
                return response.json();
            })
            .then(vaults => {
                displayVaults(vaults);
                vaultsLoading.style.display = 'none';
                vaultsContainer.style.display = 'block';
            })
            .catch(error => {
                // Hide loading indicator
                vaultsLoading.style.display = 'none';
                
                // Show inline error message and go back to step 1
                errorMessage.textContent = `Error loading vaults: ${error.message}`;
                errorContainer.style.display = 'flex';
                showStep('files');
            });
    }

    // Display vaults in the table
    function displayVaults(vaults) {
        vaultsList.innerHTML = '';

        if (!vaults || vaults.length === 0) {
            // Go back to step 1 and show an error message
            const errorContainer = document.getElementById('files-error');
            const errorMessage = document.getElementById('files-error-message');
            
            errorMessage.textContent = 'No vaults found in the provided files. Please check your files and mnemonics.';
            errorContainer.style.display = 'flex';
            showStep('files');
            return;
        }

        vaults.forEach(vault => {
            const row = document.createElement('tr');

            row.innerHTML = `
                <td>${escapeHTML(vault.Name)}</td>
                <td>${escapeHTML(vault.VaultID)}</td>
                <td>${vault.Quorum}</td>
                <td>${vault.NumberOfShares}</td>
                <td><button class="select-vault-btn" data-id="${escapeHTML(vault.VaultID)}">Select</button></td>
            `;

            vaultsList.appendChild(row);
        });

        // Add event listeners to select buttons
        document.querySelectorAll('.select-vault-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                // Store selected vault ID and name
                selectedVaultId = btn.dataset.id;
                const row = btn.closest('tr');
                selectedVaultName = row.querySelector('td:first-child').textContent;

                // Highlight the selected row and button
                document.querySelectorAll('#vaults-list tr').forEach(row => {
                    row.classList.remove('selected');
                });
                document.querySelectorAll('.select-vault-btn').forEach(button => {
                    button.classList.remove('selected');
                    button.textContent = 'Select';
                });
                
                row.classList.add('selected');
                btn.classList.add('selected');
                btn.textContent = 'Selected';
            });
        });
    }

    // Recover the selected vault
    function recoverVault() {
        recoveryLoading.style.display = 'block';
        recoveryResults.style.display = 'none';
        recoveryError.style.display = 'none';

        // Create form data with files, mnemonics, and options
        const formData = new FormData();

        // Add files and mnemonics
        document.querySelectorAll('.file-input').forEach((input, index) => {
            if (input.files.length > 0) {
                formData.append('files', input.files[0]);
                const mnemonicInput = document.querySelectorAll('.mnemonic')[index];
                formData.append('mnemonics', mnemonicInput.value.trim());
            }
        });

        // Add vault ID and advanced options
        formData.append('vaultId', selectedVaultId);

        const nonceOverride = document.getElementById('nonce-override').value;
        if (nonceOverride) {
            formData.append('nonceOverride', nonceOverride);
        }

        const quorumOverride = document.getElementById('quorum-override').value;
        if (quorumOverride) {
            formData.append('quorumOverride', quorumOverride);
        }

        const password = document.getElementById('export-password').value;
        if (password) {
            formData.append('password', password);
        }

        const exportFile = document.getElementById('export-file').value;
        if (exportFile) {
            formData.append('exportFile', exportFile);
        }

        // Send the API request
        fetch('/api/recover', {
            method: 'POST',
            body: formData
        })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        throw new Error(text);
                    });
                }
                return response.json();
            })
            .then(result => {
                recoveryLoading.style.display = 'none';

                if (result.success) {
                    recoveredKeys = result; // Store the keys for transaction tools
                    displayRecoveryResults(result);
                    recoveryResults.style.display = 'block';
                } else {
                    errorMessage.textContent = result.errorMessage;
                    recoveryError.style.display = 'block';
                }
            })
            .catch(error => {
                recoveryLoading.style.display = 'none';
                errorMessage.textContent = error.message;
                recoveryError.style.display = 'block';
            });
    }

    // Display recovery results
    function displayRecoveryResults(result) {
        // Display vault information
        document.getElementById('vault-name').textContent = selectedVaultName || 'Unknown';
        document.getElementById('vault-id').textContent = selectedVaultId || 'Unknown';
        
        // Fill in all the key display elements
        document.getElementById('eth-address').textContent = result.address;
        document.getElementById('ecdsa-private-key').textContent = result.ecdsaPrivateKey;
        document.getElementById('testnet-wif').textContent = result.testnetWIF;
        document.getElementById('mainnet-wif').textContent = result.mainnetWIF;

        // EdDSA related fields (may not be present for older vaults)
        const eddsaSection = document.getElementById('eddsa-section');

        if (result.eddsaPrivateKey) {
            document.getElementById('eddsa-private-key').textContent = result.eddsaPrivateKey;
            document.getElementById('eddsa-public-key').textContent = result.eddsaPublicKey || 'N/A';
            document.getElementById('xrpl-address').textContent = result.xrplAddress || 'N/A';
            document.getElementById('bittensor-address').textContent = result.bittensorAddress || 'N/A';
            document.getElementById('solana-address').textContent = result.solanaAddress || 'N/A';
            eddsaSection.style.display = 'block';
        } else {
            eddsaSection.style.display = 'none';
        }
    }

    // Reset the application state
    function resetState() {
        // Hide error message
        document.getElementById('files-error').style.display = 'none';
        
        // Clear files
        filesContainer.innerHTML = `
            <div class="file-input-group" data-index="1">
                <div class="file-upload">
                    <label for="file-1">Select File</label>
                    <input type="file" id="file-1" class="file-input" accept=".json,.bin">
                    <span class="file-name">No file selected</span>
                </div>
                <div class="mnemonic-input">
                    <label for="mnemonic-1">24-word Mnemonic Phrase</label>
                    <textarea id="mnemonic-1" class="mnemonic" rows="3" placeholder="Enter your 24-word mnemonic phrase for this file..."></textarea>
                </div>
                <button class="remove-file" data-index="1">✕</button>
            </div>
        `;

        // Reset file counter
        fileCounter = 1;

        // Reset selected vault
        selectedVaultId = null;
        selectedVaultName = null;
        recoveredKeys = null;
        
        // Clear any selected vault UI elements
        document.querySelectorAll('#vaults-list tr').forEach(row => {
            row.classList.remove('selected');
        });
        document.querySelectorAll('.select-vault-btn').forEach(button => {
            button.classList.remove('selected');
            button.textContent = 'Select';
        });

        // Clear advanced options
        document.getElementById('nonce-override').value = '';
        document.getElementById('quorum-override').value = '';
        document.getElementById('export-password').value = '';
        document.getElementById('export-file').value = '';

        // Initialize file input event listeners
        initializeFileInputs();
    }

    // Copy text to clipboard
    function copyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
    }

    // Escape HTML to prevent XSS
    function escapeHTML(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // ==================
    // Transaction Dialog Functions
    // ==================

    // Open a transaction dialog
    function openTransactionDialog(blockchain) {
        if (!recoveredKeys || !recoveredKeys.eddsaPrivateKey) {
            alert('Error: No EdDSA private key recovered. This blockchain operation requires an EdDSA key.');
            return;
        }

        // Reset the dialog form
        resetTransactionDialog(blockchain);

        // Show the dialog
        transactionDialogs[blockchain].style.display = 'block';
    }

    // Reset a transaction dialog
    function resetTransactionDialog(blockchain) {
        const dialog = transactionDialogs[blockchain];

        // Reset input fields
        dialog.querySelectorAll('input[type="text"], input[type="number"]').forEach(input => {
            if (!input.value.includes('wss://')) { // Don't clear endpoint fields
                input.value = '';
            }
        });
        
        // Hide the terminal container if visible
        const terminalContainer = document.getElementById(`${blockchain}-terminal-container`);
        if (terminalContainer) {
            terminalContainer.style.display = 'none';
        }
        
        // Reset status if it exists (for balance check)
        const statusEl = document.getElementById(`${blockchain}-status`);
        if (statusEl) {
            statusEl.textContent = '';
            statusEl.className = 'transaction-status';
            statusEl.style.display = 'none';
        }
    }

    // ==================
    // Balance Check Functions
    // ==================
    let xrplClient = null;
    let solanaConnection = null;

    async function initXRPLClient() {
        // This function would initialize the XRPL client using a library like xrpl.js
        // Import and create client dynamically
        if (!window.xrpl) {
            // Load xrpl.js script if not already loaded
            const script = document.createElement('script');
            script.src = 'https://unpkg.com/xrpl@2.7.0/build/xrpl-latest-min.js';
            script.async = true;

            await new Promise((resolve, reject) => {
                script.onload = resolve;
                script.onerror = reject;
                document.head.appendChild(script);
            });
        }

        // Get the network selection
        const useMainNet = document.querySelector('input[name="xrpl-network"]:checked').value === 'mainnet';
        const rpcUrl = useMainNet ? 'wss://s1.ripple.com' : 'wss://testnet.xrpl-labs.com';

        // Create client
        xrplClient = new xrpl.Client(rpcUrl);
        await xrplClient.connect();

        return xrplClient;
    }

    async function checkXRPLBalance() {
        // Create status element if it doesn't exist
        let statusEl = document.getElementById('xrpl-status');
        if (!statusEl) {
            statusEl = document.createElement('div');
            statusEl.id = 'xrpl-status';
            statusEl.className = 'transaction-status';
            document.querySelector('#xrpl-transaction-dialog .transaction-actions').after(statusEl);
        }
        
        statusEl.textContent = 'Connecting to XRPL network...';
        statusEl.className = 'transaction-status info';
        statusEl.style.display = 'block';

        try {
            const client = await initXRPLClient();

            // Create wallet from the private key
            const privateKey = recoveredKeys.eddsaPrivateKey;
            const publicKey = recoveredKeys.eddsaPublicKey;
            const wallet = new xrpl.Wallet('ed' + publicKey, 'ed' + privateKey);

            // Get account info
            const accountInfo = await client.request({
                command: 'account_info',
                account: wallet.address,
                ledger_index: 'validated'
            });

            const xrpBalance = Number(accountInfo.result.account_data.Balance) / 1000000;

            statusEl.textContent = `Balance: ${xrpBalance} XRP`;
            statusEl.className = 'transaction-status success';

        } catch (error) {
            statusEl.textContent = `Error: ${error.message}`;
            statusEl.className = 'transaction-status error';

            // If the error is related to account not found, provide a friendly message
            if (error.message.includes('Account not found')) {
                statusEl.textContent = 'Account not found. This account may not be activated yet or may not exist on this network.';
            }
        } finally {
            if (xrplClient) {
                await xrplClient.disconnect();
                xrplClient = null;
            }
        }
    }

    // XRPL validation functions
    async function validateXRPLDestination(address) {
        try {
            const formData = new FormData();
            formData.append('address', address);

            const response = await fetch('/api/validate/xrpl', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Validation request failed');
            }

            const result = await response.json();
            return result.valid;
        } catch (error) {
            console.error('Error validating XRPL address:', error);
            // Fallback to local validation if server validation fails
            // Implement basic validation matching the server-side requirements:
            // - Address must start with 'r'
            // - Address must be 25-35 characters long
            // - Address must contain only valid base58 characters
            if (!address.startsWith('r') || address.length < 25 || address.length > 35) {
                return false;
            }
            
            // Check for valid base58 characters (same as used in XRPL's alphabet)
            const base58Chars = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
            for (let i = 0; i < address.length; i++) {
                if (!base58Chars.includes(address[i])) {
                    return false;
                }
            }
            
            return true;
        }
    }

    function validateXRPAmount(amount) {
        const num = Number(amount);
        return !isNaN(num) && num > 0 && num <= 100000000000;
    }

    // Bittensor validation functions
    async function validateBittensorAddress(address) {
        try {
            const formData = new FormData();
            formData.append('address', address);

            const response = await fetch('/api/validate/bittensor', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Validation request failed');
            }

            const result = await response.json();
            return result.valid;
        } catch (error) {
            console.error('Error validating Bittensor address:', error);
            // Fallback to local validation if server validation fails
            // This matches the validation logic in the bittensor package
            
            // Bittensor addresses should be 48 characters long
            if (address.length !== 48) {
                return false;
            }
            
            // Ensure the address contains only valid base58 characters
            // The exact same validation as used in the Bittensor tool
            return /^[1-9A-HJ-NP-Za-km-z]+$/.test(address);
            
            // Note: We can't validate the SS58 prefix (42) in the browser
            // without the full SS58 decoding implementation
        }
    }

    function validateAmount(amount) {
        const num = Number(amount);
        return !isNaN(num) && num > 0;
    }

    // ==================
    // Solana Transaction Functions
    // ==================
    // Note: solanaConnection is already declared above
    let solanaPreparedTx = null;

    async function initSolanaConnection() {
        // This function would initialize the Solana connection using web3.js
        if (!window.solanaWeb3) {
            // Load solana web3.js
            const script = document.createElement('script');
            script.src = 'https://unpkg.com/@solana/web3.js@latest/lib/index.iife.min.js';
            script.async = true;

            await new Promise((resolve, reject) => {
                script.onload = resolve;
                script.onerror = reject;
                document.head.appendChild(script);
            });
        }

        // Get network selection
        const networkValue = document.querySelector('input[name="solana-network"]:checked').value;
        let endpoint;

        switch (networkValue) {
            case 'mainnet':
                endpoint = 'https://api.mainnet-beta.solana.com';
                break;
            case 'testnet':
                endpoint = 'https://api.testnet.solana.com';
                break;
            case 'devnet':
            default:
                endpoint = 'https://api.devnet.solana.com';
                break;
        }

        // Create connection
        solanaConnection = new solanaWeb3.Connection(endpoint, 'confirmed');
        return solanaConnection;
    }

    async function checkSolanaBalance() {
        // Create status element if it doesn't exist
        let statusEl = document.getElementById('solana-status');
        if (!statusEl) {
            statusEl = document.createElement('div');
            statusEl.id = 'solana-status';
            statusEl.className = 'transaction-status';
            document.querySelector('#solana-transaction-dialog .transaction-actions').after(statusEl);
        }
        
        statusEl.textContent = 'Connecting to Solana network...';
        statusEl.className = 'transaction-status info';
        statusEl.style.display = 'block';

        try {
            const connection = await initSolanaConnection();

            // Create public key from address
            const publicKeyStr = document.getElementById('solana-address').textContent;
            const publicKey = new solanaWeb3.PublicKey(publicKeyStr);

            // Get balance
            const balance = await connection.getBalance(publicKey);
            const solBalance = balance / solanaWeb3.LAMPORTS_PER_SOL;

            statusEl.textContent = `Balance: ${solBalance} SOL`;
            statusEl.className = 'transaction-status success';

        } catch (error) {
            statusEl.textContent = `Error: ${error.message}`;
            statusEl.className = 'transaction-status error';

            // If the error is related to account not found, provide a friendly message
            if (error.message.includes('Account not found')) {
                statusEl.textContent = 'Account not found. This account may not be activated yet or may not exist on this network.';
            }
        }
    }

    // Solana validation function
    async function validateSolanaAddress(address) {
        // First, try server-side validation
        try {
            const formData = new FormData();
            formData.append('address', address);

            const response = await fetch('/api/validate/solana', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Validation request failed');
            }

            const result = await response.json();
            if (result.valid) {
                return true;
            }
        } catch (error) {
            console.error('Error in server validation:', error);
            // Continue to fallback validation
        }

        // Fallback: web3 library validation if available
        if (window.solanaWeb3) {
            try {
                new solanaWeb3.PublicKey(address);
                return true;
            } catch (error) {
                return false;
            }
        }

        // Final fallback: regex validation for Solana addresses
        // Matching the validation in the solana.go package: base58 format, length between 32-44 chars
        return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);
    }


    // ==================
    // Crypto Utility Functions
    // ==================

    // Adapted from the Node.js scripts for browser compatibility
    async function signWithScalar(messageHex, privateKeyHex) {
        // Remove '0x' prefix if present from inputs
        messageHex = messageHex.replace(/^0x/, '');
        privateKeyHex = privateKeyHex.replace(/^0x/, '');

        // Convert hex message to Uint8Array using our helper function
        const message = hexToBytes(messageHex);

        // Convert hex private key scalar to Uint8Array
        const privateKeyBytes = hexToBytes(privateKeyHex);

        try {
            // Calculate public key directly from private key scalar using the Noble ed25519 library
            // Access it from the window object where it's loaded from jsdelivr
            const publicKey = await window.nobleEd25519.getPublicKey(privateKeyBytes);

            // Sign the message
            const signature = await window.nobleEd25519.sign(message, privateKeyBytes);

            // Convert outputs to hex strings
            return {
                signature: bytesToHex(signature),
                publicKey: bytesToHex(publicKey)
            };
        } catch (error) {
            console.error('Error in signWithScalar:', error);
            throw error;
        }
    }

    // Helper function to convert hex string to Uint8Array
    function hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    // Helper function to convert Uint8Array to hex string
    function bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // Initialize file input event listeners
    initializeFileInputs();
    
    // ==================
    // Terminal WebSocket Functions
    // ==================
    
    // WebSocket connection
    let terminalSocket = null;
    let activeTerminal = null;
    let waitingForTerminal = false;
    
    // Create or reconnect WebSocket
    function connectWebSocket() {
        // Close existing connection if any
        if (terminalSocket) {
            terminalSocket.close();
        }
        
        // Create WebSocket URL based on the current page URL
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/terminal`;
        
        // Create new WebSocket connection
        terminalSocket = new WebSocket(wsUrl);
        
        // Set up event handlers
        terminalSocket.onopen = (event) => {
            console.log('Terminal WebSocket connection established');
            // If we were waiting to start a terminal, send the command now
            if (waitingForTerminal && activeTerminal) {
                setTimeout(() => sendTerminalCommand(activeTerminal), 500);
            }
        };
        
        terminalSocket.onmessage = (event) => {
            const message = JSON.parse(event.data);
            handleTerminalMessage(message);
        };
        
        terminalSocket.onclose = (event) => {
            console.log('Terminal WebSocket connection closed');
            // Try to reconnect after a delay if we're still using a terminal
            if (activeTerminal) {
                setTimeout(connectWebSocket, 2000);
            }
        };
        
        terminalSocket.onerror = (event) => {
            console.error('Terminal WebSocket error:', event);
        };
    }
    
    // Handle terminal messages
    function handleTerminalMessage(message) {
        if (!activeTerminal) return;
        
        const terminal = document.getElementById(`${activeTerminal}-terminal`);
        
        switch (message.type) {
            case 'output':
                appendToTerminal(terminal, message.data);
                break;
                
            case 'error':
                appendToTerminal(terminal, message.data, 'error');
                break;
                
            case 'exit':
                appendToTerminal(terminal, `\nProcess exited with code ${message.exitCode}`, 
                    message.exitCode === 0 ? 'success' : 'error');
                break;
                
            default:
                console.warn('Unknown message type:', message.type);
        }
        
        // Scroll to bottom
        terminal.scrollTop = terminal.scrollHeight;
    }
    
    // Append text to the terminal with optional class
    function appendToTerminal(terminal, text, className = 'output') {
        const line = document.createElement('div');
        line.className = `terminal-line terminal-${className}`;
        line.textContent = text;
        terminal.appendChild(line);
    }
    
    // Create transaction in terminal
    function createTerminalTransaction(chain) {
        // Set active terminal
        activeTerminal = chain;
        
        // Get terminal element and container
        const terminal = document.getElementById(`${chain}-terminal`);
        const terminalContainer = document.getElementById(`${chain}-terminal-container`);
        
        // Clear terminal
        terminal.innerHTML = '';
        
        // Show terminal
        terminalContainer.style.display = 'block';
        
        // Connect WebSocket if not already connected
        if (!terminalSocket || terminalSocket.readyState !== WebSocket.OPEN) {
            connectWebSocket();
            waitingForTerminal = true;
        } else {
            // Send the command
            sendTerminalCommand(chain);
        }
    }
    
    // Send command to start chain script
    function sendTerminalCommand(chain) {
        waitingForTerminal = false;
        
        // Prepare arguments based on chain
        const args = {};
        
        // Common arguments for all chains: private key and confirm
        args.privateKey = recoveredKeys.eddsaPrivateKey;
        args.confirm = "true"; // Auto-confirm transactions
        
        switch (chain) {
            case 'xrpl':
                args.publicKey = recoveredKeys.eddsaPublicKey;
                args.destination = document.getElementById('xrpl-destination').value;
                args.amount = document.getElementById('xrpl-amount').value;
                args.network = document.querySelector('input[name="xrpl-network"]:checked').value;
                break;
                
            case 'bittensor':
                args.destination = document.getElementById('bittensor-destination').value;
                args.amount = document.getElementById('bittensor-amount').value;
                args.endpoint = document.getElementById('bittensor-endpoint').value;
                break;
                
            case 'solana':
                args.destination = document.getElementById('solana-destination').value;
                args.amount = document.getElementById('solana-amount').value;
                args.network = document.querySelector('input[name="solana-network"]:checked').value;
                break;
                
            default:
                console.error('Unknown chain:', chain);
                return;
        }
        
        // Send command to server
        const message = {
            type: 'command',
            chain: chain,
            arguments: args
        };
        
        terminalSocket.send(JSON.stringify(message));
        
        // Add command line to terminal
        const terminal = document.getElementById(`${chain}-terminal`);
        appendToTerminal(terminal, `> Starting ${chain} transaction process...`, 'command');
    }
    
    // Close terminal
    function closeTerminal(chain) {
        if (terminalSocket && terminalSocket.readyState === WebSocket.OPEN) {
            // Send exit command
            terminalSocket.send(JSON.stringify({ type: 'exit' }));
        }
        
        // Hide terminal container
        document.getElementById(`${chain}-terminal-container`).style.display = 'none';
        
        // Clear active terminal if it's the one we're closing
        if (activeTerminal === chain) {
            activeTerminal = null;
        }
    }
});