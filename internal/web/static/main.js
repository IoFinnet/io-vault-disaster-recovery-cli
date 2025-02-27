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

    // XRPL transaction buttons
    document.getElementById('xrpl-check-balance').addEventListener('click', checkXRPLBalance);
    document.getElementById('xrpl-prepare-tx').addEventListener('click', prepareXRPLTransaction);
    document.getElementById('xrpl-sign-tx').addEventListener('click', signXRPLTransaction);
    document.getElementById('xrpl-broadcast-tx').addEventListener('click', broadcastXRPLTransaction);

    // Bittensor transaction buttons
    document.getElementById('bittensor-prepare-tx').addEventListener('click', prepareBittensorTransaction);
    document.getElementById('bittensor-broadcast-tx').addEventListener('click', broadcastBittensorTransaction);

    // Solana transaction buttons
    document.getElementById('solana-check-balance').addEventListener('click', checkSolanaBalance);
    document.getElementById('solana-prepare-tx').addEventListener('click', prepareSolanaTransaction);
    document.getElementById('solana-sign-tx').addEventListener('click', signSolanaTransaction);
    document.getElementById('solana-broadcast-tx').addEventListener('click', broadcastSolanaTransaction);

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
    }

    // Validate files and mnemonics before proceeding
    function validateFilesAndMnemonics() {
        const fileInputs = document.querySelectorAll('.file-input');
        const mnemonicInputs = document.querySelectorAll('.mnemonic');

        // Check if at least one file is selected
        let hasFile = false;
        fileInputs.forEach(input => {
            if (input.files.length > 0) {
                hasFile = true;
            }
        });

        if (!hasFile) {
            alert('Please select at least one vault file');
            return false;
        }

        // Check if each file has a corresponding mnemonic
        let valid = true;
        fileInputs.forEach((input, index) => {
            if (input.files.length > 0) {
                const mnemonic = mnemonicInputs[index].value.trim();
                if (!mnemonic) {
                    alert(`Please enter the mnemonic phrase for ${input.files[0].name}`);
                    valid = false;
                }

                // Basic validation for mnemonic (24 words)
                const words = mnemonic.split(/\s+/);
                if (words.length !== 24) {
                    alert(`The mnemonic phrase for ${input.files[0].name} should contain 24 words (found ${words.length})`);
                    valid = false;
                }
            }
        });

        return valid;
    }

    // Load vaults from the selected files
    function loadVaults() {
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
                vaultsLoading.style.display = 'none';
                alert(`Error loading vaults: ${error.message}`);
            });
    }

    // Display vaults in the table
    function displayVaults(vaults) {
        vaultsList.innerHTML = '';

        if (!vaults || vaults.length === 0) {
            vaultsList.innerHTML = '<tr><td colspan="5">No vaults found in the provided files</td></tr>';
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
                selectedVaultId = btn.dataset.id;

                // Highlight the selected row
                document.querySelectorAll('#vaults-list tr').forEach(row => {
                    row.classList.remove('selected');
                });
                btn.closest('tr').classList.add('selected');
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
        recoveredKeys = null;

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

        // Reset status and prepared transaction sections
        dialog.querySelector('.transaction-status').textContent = '';
        dialog.querySelector('.transaction-status').className = 'transaction-status';
        dialog.querySelector('.tx-details').textContent = '';
        dialog.querySelector('.prepared-transaction').style.display = 'none';
    }

    // ==================
    // XRPL Transaction Functions
    // ==================
    let xrplClient = null;
    let xrplPreparedTx = null;

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
        const statusEl = document.getElementById('xrpl-status');
        statusEl.textContent = 'Connecting to XRPL network...';
        statusEl.className = 'transaction-status info';

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

    async function prepareXRPLTransaction() {
        const statusEl = document.getElementById('xrpl-status');
        statusEl.textContent = 'Preparing transaction...';
        statusEl.className = 'transaction-status info';

        const destination = document.getElementById('xrpl-destination').value;
        const amount = document.getElementById('xrpl-amount').value;

        // Validate inputs
        const isValidDestination = await validateXRPLDestination(destination);
        if (!isValidDestination) {
            statusEl.textContent = 'Invalid destination address format. Must be a valid XRPL address starting with "r".';
            statusEl.className = 'transaction-status error';
            return;
        }

        if (!validateXRPAmount(amount)) {
            statusEl.textContent = 'Invalid amount. Must be a positive number less than 100 billion XRP.';
            statusEl.className = 'transaction-status error';
            return;
        }

        try {
            const client = await initXRPLClient();

            // Create wallet from the private key
            const privateKey = recoveredKeys.eddsaPrivateKey;
            const publicKey = recoveredKeys.eddsaPublicKey;
            const wallet = new xrpl.Wallet('ed' + publicKey, 'ed' + privateKey);

            // Prepare transaction
            const tx = await client.autofill({
                TransactionType: 'Payment',
                Account: wallet.address,
                Destination: destination,
                Amount: xrpl.xrpToDrops(amount),
            });

            tx.SigningPubKey = wallet.publicKey;
            if (tx.LastLedgerSequence) {
                // Adds 15 minutes worth of ledgers (assuming 4 ledgers per second) to the existing LastLedgerSequence value
                tx.LastLedgerSequence = tx.LastLedgerSequence + 15 * 60 * 4;
            }

            // Store prepared transaction
            xrplPreparedTx = tx;

            // Display transaction details
            document.getElementById('xrpl-tx-details').textContent = JSON.stringify(tx, null, 2);
            document.getElementById('xrpl-prepared-tx').style.display = 'block';

            statusEl.textContent = 'Transaction prepared successfully. Review the details and proceed to sign.';
            statusEl.className = 'transaction-status success';

        } catch (error) {
            statusEl.textContent = `Error: ${error.message}`;
            statusEl.className = 'transaction-status error';
        } finally {
            if (xrplClient) {
                await xrplClient.disconnect();
                xrplClient = null;
            }
        }
    }

    async function signXRPLTransaction() {
        const statusEl = document.getElementById('xrpl-status');

        if (!xrplPreparedTx) {
            statusEl.textContent = 'No transaction prepared. Please prepare a transaction first.';
            statusEl.className = 'transaction-status error';
            return;
        }

        statusEl.textContent = 'Signing transaction...';
        statusEl.className = 'transaction-status info';

        try {
            // Create wallet from the private key for signature verification
            const privateKey = recoveredKeys.eddsaPrivateKey;
            const publicKey = recoveredKeys.eddsaPublicKey;

            // Use signWithScalar for XRPL transactions (we'll implement this later)
            const preImageHex = xrpl.encodeForSigning(xrplPreparedTx);

            // Sign the transaction
            const { signature } = await signWithScalar(preImageHex, privateKey);
            xrplPreparedTx.TxnSignature = signature;

            // Encode the signed transaction
            const encodedTxHex = xrpl.encode(xrplPreparedTx);
            xrplPreparedTx.encodedTx = encodedTxHex;

            // Update the transaction details
            document.getElementById('xrpl-tx-details').textContent = JSON.stringify({
                ...xrplPreparedTx,
                signedTxBlob: encodedTxHex
            }, null, 2);

            statusEl.textContent = 'Transaction signed successfully. You can now broadcast it to the network.';
            statusEl.className = 'transaction-status success';

        } catch (error) {
            statusEl.textContent = `Error signing transaction: ${error.message}`;
            statusEl.className = 'transaction-status error';
        }
    }

    async function broadcastXRPLTransaction() {
        const statusEl = document.getElementById('xrpl-status');

        if (!xrplPreparedTx || !xrplPreparedTx.encodedTx) {
            statusEl.textContent = 'No signed transaction available. Please prepare and sign a transaction first.';
            statusEl.className = 'transaction-status error';
            return;
        }

        statusEl.textContent = 'Broadcasting transaction...';
        statusEl.className = 'transaction-status info';

        try {
            const client = await initXRPLClient();

            // Submit the signed transaction
            const submit = await client.submit(xrplPreparedTx.encodedTx);

            if (submit.result.engine_result.includes('SUCCESS')) {
                const txHash = submit.result.tx_json.hash;

                statusEl.innerHTML = `Transaction submitted successfully with hash: <strong>${txHash}</strong>
                                     <br><br>Initial status: ${submit.result.engine_result_message}`;
                statusEl.className = 'transaction-status success';

                // Wait for validation (optional)
                statusEl.innerHTML += '<br><br>Waiting for validation...';

                // Poll for transaction outcome
                setTimeout(async () => {
                    try {
                        const txResponse = await client.request({
                            command: 'tx',
                            transaction: txHash
                        });

                        if (txResponse.result.validated) {
                            statusEl.innerHTML += '<br><br>Transaction validated!';
                        } else {
                            statusEl.innerHTML += '<br><br>Transaction not yet validated. It may take a few seconds to be included in a ledger.';
                        }
                    } catch (error) {
                        // Transaction may not be in the ledger yet
                        statusEl.innerHTML += '<br><br>Transaction pending validation...';
                    } finally {
                        await client.disconnect();
                    }
                }, 5000);

            } else {
                statusEl.textContent = `Transaction failed: ${submit.result.engine_result_message}`;
                statusEl.className = 'transaction-status error';
                await client.disconnect();
            }

        } catch (error) {
            statusEl.textContent = `Error broadcasting transaction: ${error.message}`;
            statusEl.className = 'transaction-status error';

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

    // ==================
    // Bittensor Transaction Functions
    // ==================
    let bittensorPreparedTx = null;

    async function prepareBittensorTransaction() {
        const statusEl = document.getElementById('bittensor-status');
        statusEl.textContent = 'Preparing transaction...';
        statusEl.className = 'transaction-status info';

        const endpoint = document.getElementById('bittensor-endpoint').value;
        const destination = document.getElementById('bittensor-destination').value;
        const amount = document.getElementById('bittensor-amount').value;

        // Validate inputs
        const isValidDestination = await validateBittensorAddress(destination);
        if (!isValidDestination) {
            statusEl.textContent = 'Invalid destination address format. Must be a valid Bittensor SS58 address.';
            statusEl.className = 'transaction-status error';
            return;
        }

        if (!validateAmount(amount)) {
            statusEl.textContent = 'Invalid amount. Must be a positive number.';
            statusEl.className = 'transaction-status error';
            return;
        }

        // In a full implementation, we would load the Polkadot.js API here
        // Since we can't fully implement this in the browser without adding dependencies,
        // we'll create a transaction preview

        // Format transaction details for display
        const fromAddress = document.getElementById('bittensor-address').textContent;
        const amountInPlanck = Number(amount) * 1000000000; // 9 decimals

        bittensorPreparedTx = {
            from: fromAddress,
            to: destination,
            amount: amount,
            amountInPlanck: amountInPlanck.toString(),
            endpoint: endpoint
        };

        // Display transaction details
        document.getElementById('bittensor-tx-details').textContent = JSON.stringify(bittensorPreparedTx, null, 2);
        document.getElementById('bittensor-prepared-tx').style.display = 'block';

        statusEl.innerHTML = `Transaction prepared for preview.
                            <br><br>Note: Full Bittensor transaction functionality requires the Polkadot.js API which is not fully supported in the browser.
                            <br><br>In a production environment, this transaction would send ${amount} TAO from ${fromAddress} to ${destination}.`;
        statusEl.className = 'transaction-status info';
    }

    async function broadcastBittensorTransaction() {
        const statusEl = document.getElementById('bittensor-status');

        if (!bittensorPreparedTx) {
            statusEl.textContent = 'No transaction prepared. Please prepare a transaction first.';
            statusEl.className = 'transaction-status error';
            return;
        }

        statusEl.innerHTML = `<strong>Bittensor Transaction Notice</strong>
                           <br><br>Due to technical limitations, Bittensor transactions cannot be broadcast directly from the browser. The Substrate/Polkadot.js libraries used for Bittensor transactions are not fully compatible with browser environments.
                           <br><br>To complete this transaction, please:
                           <br><br>1. Ensure Node.js is installed on your computer
                           <br><br>2. Open a terminal and navigate to the Bittensor tool directory:
                           <br><code>cd scripts/bittensor-tool</code>
                           <br><br>3. Install dependencies and run the tool:
                           <br><code>npm i</code>
                           <br><code>npm start</code>
                           <br><br>4. Enter your private key and transaction details when prompted
                           <br><br>The Node.js script uses the exact same transaction building and signing code, but includes all required libraries to complete the transaction.`;
        statusEl.className = 'transaction-status info';
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
    let solanaConnection = null;
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
        const statusEl = document.getElementById('solana-status');
        statusEl.textContent = 'Connecting to Solana network...';
        statusEl.className = 'transaction-status info';

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

    async function prepareSolanaTransaction() {
        const statusEl = document.getElementById('solana-status');
        statusEl.textContent = 'Preparing transaction...';
        statusEl.className = 'transaction-status info';

        const destination = document.getElementById('solana-destination').value;
        const amount = document.getElementById('solana-amount').value;

        statusEl.textContent = 'Validating inputs...';

        try {
            // Load noble-ed25519 library if not already loaded
            if (!window.nobleEd25519) {
                statusEl.textContent = 'Loading necessary crypto libraries...';
                const script = document.createElement('script');
                script.src = 'https://cdn.jsdelivr.net/npm/@noble/ed25519@1.7.3/lib/index.min.js';
                script.async = true;

                await new Promise((resolve, reject) => {
                    script.onload = resolve;
                    script.onerror = reject;
                    document.head.appendChild(script);
                });
            }
            
            // Validate inputs
            const isValidDestination = await validateSolanaAddress(destination);

            if (!isValidDestination) {
                statusEl.textContent = `Invalid destination address format: ${destination}`;
                statusEl.className = 'transaction-status error';
                return;
            }

            if (!validateAmount(amount)) {
                statusEl.textContent = 'Invalid amount. Must be a positive number.';
                statusEl.className = 'transaction-status error';
                return;
            }

            statusEl.textContent = 'Inputs validated, preparing transaction...';
        } catch (error) {
            console.error('Error in validation:', error);
            statusEl.textContent = `Validation error: ${error.message}`;
            statusEl.className = 'transaction-status error';
            return;
        }

        try {
            const connection = await initSolanaConnection();

            // Create keypair from private key
            const privateKey = recoveredKeys.eddsaPrivateKey;
            const wallet = createSolanaKeypair(privateKey);

            // Create destination public key
            const destinationPubkey = new solanaWeb3.PublicKey(destination);
            const lamports = Math.floor(parseFloat(amount) * solanaWeb3.LAMPORTS_PER_SOL);

            // Create a new transaction
            const transaction = new solanaWeb3.Transaction();

            // Get recent blockhash
            const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
            transaction.recentBlockhash = blockhash;
            transaction.lastValidBlockHeight = lastValidBlockHeight;

            // Set fee payer
            transaction.feePayer = wallet.publicKey;

            // Add transfer instruction
            transaction.add(
                solanaWeb3.SystemProgram.transfer({
                    fromPubkey: wallet.publicKey,
                    toPubkey: destinationPubkey,
                    lamports: lamports,
                })
            );

            // Store prepared transaction
            solanaPreparedTx = {
                transaction: transaction,
                blockhash: blockhash,
                lastValidBlockHeight: lastValidBlockHeight,
                networkName: document.querySelector('input[name="solana-network"]:checked').value
            };

            // Display transaction details
            const txDetails = {
                from: wallet.publicKey.toString(),
                to: destination,
                amount: `${amount} SOL (${lamports} lamports)`,
                network: document.querySelector('input[name="solana-network"]:checked').value,
                recentBlockhash: blockhash,
                instructions: transaction.instructions.map(inst => ({
                    programId: inst.programId.toString(),
                    data: `[${inst.data.length} bytes]`
                }))
            };

            document.getElementById('solana-tx-details').textContent = JSON.stringify(txDetails, null, 2);
            document.getElementById('solana-prepared-tx').style.display = 'block';

            statusEl.textContent = 'Transaction prepared successfully. Review the details and proceed to sign.';
            statusEl.className = 'transaction-status success';

        } catch (error) {
            statusEl.textContent = `Error: ${error.message}`;
            statusEl.className = 'transaction-status error';
        }
    }

    async function signSolanaTransaction() {
        const statusEl = document.getElementById('solana-status');

        if (!solanaPreparedTx) {
            statusEl.textContent = 'No transaction prepared. Please prepare a transaction first.';
            statusEl.className = 'transaction-status error';
            return;
        }

        statusEl.textContent = 'Signing transaction...';
        statusEl.className = 'transaction-status info';

        try {
            // Get private key
            const privateKey = recoveredKeys.eddsaPrivateKey;

            // Get transaction message to sign
            const transaction = solanaPreparedTx.transaction;
            const messageBytes = transaction.serializeMessage();

            // Sign message with our private key
            const { signature } = await signWithScalar(Buffer.from(messageBytes).toString('hex'), privateKey);

            // Add signature to transaction
            transaction.addSignature(
                new solanaWeb3.PublicKey(document.getElementById('solana-address').textContent),
                Buffer.from(signature, 'hex')
            );

            // Update stored transaction
            solanaPreparedTx.transaction = transaction;
            solanaPreparedTx.signedTransaction = transaction.serialize();

            // Update the transaction details display
            const txDetails = JSON.parse(document.getElementById('solana-tx-details').textContent);
            txDetails.signatures = transaction.signatures.map(sig => ({
                publicKey: sig.publicKey.toString(),
                signature: sig.signature ? `[${sig.signature.length} bytes]` : null
            }));
            txDetails.signed = true;

            document.getElementById('solana-tx-details').textContent = JSON.stringify(txDetails, null, 2);

            statusEl.textContent = 'Transaction signed successfully. You can now broadcast it to the network.';
            statusEl.className = 'transaction-status success';

        } catch (error) {
            statusEl.textContent = `Error signing transaction: ${error.message}`;
            statusEl.className = 'transaction-status error';
        }
    }

    async function broadcastSolanaTransaction() {
        const statusEl = document.getElementById('solana-status');

        if (!solanaPreparedTx || !solanaPreparedTx.signedTransaction) {
            statusEl.textContent = 'No signed transaction available. Please prepare and sign a transaction first.';
            statusEl.className = 'transaction-status error';
            return;
        }

        statusEl.textContent = 'Broadcasting transaction...';
        statusEl.className = 'transaction-status info';

        try {
            const connection = await initSolanaConnection();

            // Send transaction
            const signature = await connection.sendRawTransaction(
                solanaPreparedTx.signedTransaction,
                { skipPreflight: false, preflightCommitment: 'confirmed' }
            );

            statusEl.textContent = `Transaction sent! Signature: ${signature}`;
            statusEl.className = 'transaction-status success';

            // Wait for confirmation
            statusEl.textContent += '\n\nWaiting for confirmation...';

            // Create explorer URL based on network
            const network = solanaPreparedTx.networkName;
            const explorerUrl = network === 'mainnet'
                ? `https://explorer.solana.com/tx/${signature}`
                : `https://explorer.solana.com/tx/${signature}?cluster=${network}`;

            // Poll for confirmation (optional)
            setTimeout(async () => {
                try {
                    const confirmation = await connection.confirmTransaction({
                        blockhash: solanaPreparedTx.blockhash,
                        lastValidBlockHeight: solanaPreparedTx.lastValidBlockHeight,
                        signature: signature
                    }, 'confirmed');

                    if (confirmation.value.err) {
                        statusEl.innerHTML += `<br><br>Transaction failed: ${JSON.stringify(confirmation.value.err)}`;
                    } else {
                        statusEl.innerHTML += `<br><br>Transaction confirmed! <a href="${explorerUrl}" target="_blank">View on Explorer</a>`;
                    }
                } catch (error) {
                    statusEl.innerHTML += `<br><br>Error checking confirmation: ${error.message}`;
                }
            }, 5000);

        } catch (error) {
            statusEl.textContent = `Error broadcasting transaction: ${error.message}`;
            statusEl.className = 'transaction-status error';
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

    function createSolanaKeypair(privateKeyHex) {
        try {
            // Calculate public key directly from private key scalar using the same method as in the Solana tool
            // Convert hex string to Uint8Array directly if Buffer is causing issues
            let privateKeyBytes;
            if (typeof Buffer !== 'undefined' && typeof Buffer.from === 'function') {
                privateKeyBytes = Buffer.from(privateKeyHex, 'hex');
            } else {
                // Manual hex string to Uint8Array conversion
                privateKeyBytes = new Uint8Array(privateKeyHex.length / 2);
                for (let i = 0; i < privateKeyHex.length; i += 2) {
                    privateKeyBytes[i / 2] = parseInt(privateKeyHex.substring(i, i + 2), 16);
                }
            }
            
            // Validate private key length (32 bytes for Ed25519)
            if (privateKeyBytes.length !== 32) {
                throw new Error('Private key must be 32 bytes');
            }
            
            // Calculate public key directly from private key scalar using BASE point multiplication
            const publicKeyBytes = window.nobleEd25519.getPublicKey(privateKeyBytes);
            
            // Create a public key object directly using the Uint8Array
            const publicKey = new solanaWeb3.PublicKey(publicKeyBytes);
            
            // Return object with the public key and secretKey for Solana transaction signing
            return {
                publicKey: publicKey,
                secretKey: privateKeyBytes
            };
        } catch (error) {
            console.error('Error creating Solana keypair:', error);
            throw error;
        }
    }

    // ==================
    // Crypto Utility Functions
    // ==================

    // Adapted from the Node.js scripts for browser compatibility
    async function signWithScalar(messageHex, privateKeyHex) {
        // Remove '0x' prefix if present from inputs
        messageHex = messageHex.replace(/^0x/, '');
        privateKeyHex = privateKeyHex.replace(/^0x/, '');

        // Load noble-ed25519 library if not already loaded
        if (!window.nobleEd25519) {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/@noble/ed25519@1.7.3/lib/index.min.js';
            script.async = true;

            await new Promise((resolve, reject) => {
                script.onload = resolve;
                script.onerror = reject;
                document.head.appendChild(script);
            });
        }

        // Convert hex message to Uint8Array using our helper function
        const message = hexToBytes(messageHex);

        // Convert hex private key scalar to Uint8Array
        const privateKeyBytes = hexToBytes(privateKeyHex);

        try {
            // Calculate public key directly from private key scalar
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
});