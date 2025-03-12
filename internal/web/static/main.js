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

    // Connect transaction buttons with HTML5 validation
    const xrplCheckBalanceBtn = document.getElementById('xrpl-check-balance');
    const xrplCreateTxBtn = document.getElementById('xrpl-create-tx');
    
    xrplCheckBalanceBtn.addEventListener('click', () => {
        if (recoveredKeys && recoveredKeys.xrplAddress) {
            createBalanceCheckCommand('xrpl');
        } else {
            alert('No valid XRPL address found for this vault');
        }
    });
    
    xrplCreateTxBtn.addEventListener('click', () => {
        // Use browser's built-in form validation
        const xrplDestInput = document.getElementById('xrpl-destination');
        const xrplAmountInput = document.getElementById('xrpl-amount');
        
        if (xrplDestInput.checkValidity() && xrplAmountInput.checkValidity()) {
            createTerminalTransaction('xrpl');
        } else {
            // Trigger the browser's validation UI
            if (!xrplDestInput.checkValidity()) xrplDestInput.reportValidity();
            if (!xrplAmountInput.checkValidity()) xrplAmountInput.reportValidity();
        }
    });
    
    document.getElementById('xrpl-terminal-close').addEventListener('click', () => closeTerminal('xrpl'));
    
    const bittensorCheckBalanceBtn = document.getElementById('bittensor-check-balance');
    const bittensorCreateTxBtn = document.getElementById('bittensor-create-tx');
    
    bittensorCheckBalanceBtn.addEventListener('click', () => {
        if (recoveredKeys && recoveredKeys.bittensorAddress) {
            createBalanceCheckCommand('bittensor');
        } else {
            alert('No valid Bittensor address found for this vault');
        }
    });
    
    bittensorCreateTxBtn.addEventListener('click', () => {
        // Use browser's built-in form validation
        const bittensorDestInput = document.getElementById('bittensor-destination');
        const bittensorAmountInput = document.getElementById('bittensor-amount');
        
        if (bittensorDestInput.checkValidity() && bittensorAmountInput.checkValidity()) {
            createTerminalTransaction('bittensor');
        } else {
            // Trigger the browser's validation UI
            if (!bittensorDestInput.checkValidity()) bittensorDestInput.reportValidity();
            if (!bittensorAmountInput.checkValidity()) bittensorAmountInput.reportValidity();
        }
    });
    
    document.getElementById('bittensor-terminal-close').addEventListener('click', () => closeTerminal('bittensor'));
    
    const solanaCheckBalanceBtn = document.getElementById('solana-check-balance');
    const solanaCreateTxBtn = document.getElementById('solana-create-tx');
    
    solanaCheckBalanceBtn.addEventListener('click', () => {
        if (recoveredKeys && recoveredKeys.solanaAddress) {
            createBalanceCheckCommand('solana');
        } else {
            alert('No valid Solana address found for this vault');
        }
    });
    
    solanaCreateTxBtn.addEventListener('click', () => {
        // Use browser's built-in form validation
        const solanaDestInput = document.getElementById('solana-destination');
        const solanaAmountInput = document.getElementById('solana-amount');
        
        if (solanaDestInput.checkValidity() && solanaAmountInput.checkValidity()) {
            createTerminalTransaction('solana');
        } else {
            // Trigger the browser's validation UI
            if (!solanaDestInput.checkValidity()) solanaDestInput.reportValidity();
            if (!solanaAmountInput.checkValidity()) solanaAmountInput.reportValidity();
        }
    });
    
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
    // Simple Validation Functions
    // ==================

    function validateAmount(amount) {
        const num = Number(amount);
        return !isNaN(num) && num > 0;
    }

    // Initialize file input event listeners
    initializeFileInputs();
    
    // ==================
    // Command Generation Functions
    // ==================
    
    // Generate and display the command for the user to run
    function createTerminalTransaction(chain) {
        // Get terminal element and container
        const terminal = document.getElementById(`${chain}-terminal`);
        const terminalContainer = document.getElementById(`${chain}-terminal-container`);
        
        // Clear terminal
        terminal.innerHTML = '';
        
        // Show terminal container
        terminalContainer.style.display = 'block';
        
        // Generate and display the command
        const command = generateScriptCommand(chain);
        displayCommand(terminal, command, chain);
    }
    
    // Generate script command based on chain and form values
    function generateScriptCommand(chain) {
        // Base command with npx added for cross-platform compatibility
        let scriptPath, command, args = [];
        
        // Common arguments for all chains: private key and confirm
        const privateKey = recoveredKeys.eddsaPrivateKey;
        
        switch (chain) {
            case 'xrpl':
                scriptPath = "scripts/xrpl-tool";
                args.push("--private-key", privateKey);
                args.push("--public-key", recoveredKeys.eddsaPublicKey);
                
                const xrplDestination = document.getElementById('xrpl-destination').value;
                if (xrplDestination) args.push("--destination", xrplDestination);
                
                const xrplAmount = document.getElementById('xrpl-amount').value;
                if (xrplAmount) args.push("--amount", xrplAmount);
                
                const xrplNetwork = document.querySelector('input[name="xrpl-network"]:checked').value;
                args.push("--network", xrplNetwork);
                break;
                
            case 'bittensor':
                scriptPath = "scripts/bittensor-tool";
                args.push("--private-key", privateKey);
                
                const bittensorDestination = document.getElementById('bittensor-destination').value;
                if (bittensorDestination) args.push("--destination", bittensorDestination);
                
                const bittensorAmount = document.getElementById('bittensor-amount').value;
                if (bittensorAmount) args.push("--amount", bittensorAmount);
                
                const bittensorNetwork = document.querySelector('input[name="bittensor-network"]:checked').value;
                
                // Set the correct endpoint based on network selection
                const endpoint = bittensorNetwork === 'mainnet' 
                    ? 'wss://entrypoint-finney.opentensor.ai:443'
                    : 'wss://test.finney.opentensor.ai:443';
                    
                args.push("--endpoint", endpoint);
                args.push("--network", bittensorNetwork);
                break;
                
            case 'solana':
                scriptPath = "scripts/solana-tool";
                args.push("--private-key", privateKey);
                
                const solanaDestination = document.getElementById('solana-destination').value;
                if (solanaDestination) args.push("--destination", solanaDestination);
                
                const solanaAmount = document.getElementById('solana-amount').value;
                if (solanaAmount) args.push("--amount", solanaAmount);
                
                const solanaNetwork = document.querySelector('input[name="solana-network"]:checked').value;
                args.push("--network", solanaNetwork);
                break;
                
            default:
                console.error('Unknown chain:', chain);
                return "";
        }
        
        // Create two separate commands with cross-platform return to original directory
        // For Unix/Linux/Mac (bash/zsh)
        const installCommand = `cd ${scriptPath} && npm install && cd -`;
        const runCommand = `cd ${scriptPath} && npm start -- ${args.join(' ')} && cd -`;
        
        // For Windows CMD
        const installCommandWin = `pushd ${scriptPath} && npm install && popd`;
        const runCommandWin = `pushd ${scriptPath} && npm start -- ${args.join(' ')} && popd`;
        
        return { 
            installCommand, 
            runCommand,
            installCommandWin,
            runCommandWin
        };
    }
    
    // Display the commands in the terminal
    function displayCommand(terminal, commands, chain, isBalanceCheck = false) {
        // Create header
        const header = document.createElement('div');
        header.className = 'terminal-line terminal-header';
        header.innerHTML = isBalanceCheck
            ? `<strong>Two-step process to check balance securely:</strong>`
            : `<strong>Two-step process for secure transaction:</strong>`;
        terminal.appendChild(header);
        
        // STEP 1: Install dependencies (requires internet)
        const step1Header = document.createElement('div');
        step1Header.className = 'terminal-line terminal-step-header';
        step1Header.innerHTML = `<span class="step-number">Step 1:</span> <span class="step-title">Install dependencies (requires internet connection)</span>`;
        terminal.appendChild(step1Header);
        
        // For Mac/Linux
        const osHeader1 = document.createElement('div');
        osHeader1.className = 'terminal-line terminal-os-header';
        osHeader1.textContent = 'Mac/Linux:';
        terminal.appendChild(osHeader1);
        
        const installBox = document.createElement('div');
        installBox.className = 'terminal-line terminal-command-box';
        installBox.textContent = commands.installCommand;
        terminal.appendChild(installBox);
        
        // Create copy button for Unix install command
        const installCopyBtn = document.createElement('button');
        installCopyBtn.className = 'terminal-copy-btn';
        installCopyBtn.textContent = 'Copy Mac/Linux Command';
        installCopyBtn.onclick = function() {
            copyToClipboard(commands.installCommand);
            installCopyBtn.textContent = 'Copied!';
            setTimeout(() => {
                installCopyBtn.textContent = 'Copy Mac/Linux Command';
            }, 1500);
        };
        terminal.appendChild(installCopyBtn);
        
        // For Windows
        const osHeader1Win = document.createElement('div');
        osHeader1Win.className = 'terminal-line terminal-os-header';
        osHeader1Win.textContent = 'Windows:';
        terminal.appendChild(osHeader1Win);
        
        const installBoxWin = document.createElement('div');
        installBoxWin.className = 'terminal-line terminal-command-box';
        installBoxWin.textContent = commands.installCommandWin;
        terminal.appendChild(installBoxWin);
        
        // Create copy button for Windows install command
        const installCopyBtnWin = document.createElement('button');
        installCopyBtnWin.className = 'terminal-copy-btn';
        installCopyBtnWin.textContent = 'Copy Windows Command';
        installCopyBtnWin.onclick = function() {
            copyToClipboard(commands.installCommandWin);
            installCopyBtnWin.textContent = 'Copied!';
            setTimeout(() => {
                installCopyBtnWin.textContent = 'Copy Windows Command';
            }, 1500);
        };
        terminal.appendChild(installCopyBtnWin);
        
        // STEP 2: Run the command
        const step2Header = document.createElement('div');
        step2Header.className = 'terminal-line terminal-step-header';
        step2Header.innerHTML = isBalanceCheck 
            ? `<span class="step-number">Step 2:</span> <span class="step-title">Check balance</span>`
            : `<span class="step-number">Step 2:</span> <span class="step-title">Execute transaction</span>`;
        terminal.appendChild(step2Header);
        
        // For Mac/Linux
        const osHeader2 = document.createElement('div');
        osHeader2.className = 'terminal-line terminal-os-header';
        osHeader2.textContent = 'Mac/Linux:';
        terminal.appendChild(osHeader2);
        
        const runBox = document.createElement('div');
        runBox.className = 'terminal-line terminal-command-box';
        runBox.textContent = commands.runCommand;
        terminal.appendChild(runBox);
        
        // Create copy button for Unix run command
        const runCopyBtn = document.createElement('button');
        runCopyBtn.className = 'terminal-copy-btn';
        runCopyBtn.textContent = 'Copy Mac/Linux Command';
        runCopyBtn.onclick = function() {
            copyToClipboard(commands.runCommand);
            runCopyBtn.textContent = 'Copied!';
            setTimeout(() => {
                runCopyBtn.textContent = 'Copy Mac/Linux Command';
            }, 1500);
        };
        terminal.appendChild(runCopyBtn);
        
        // For Windows
        const osHeader2Win = document.createElement('div');
        osHeader2Win.className = 'terminal-line terminal-os-header';
        osHeader2Win.textContent = 'Windows:';
        terminal.appendChild(osHeader2Win);
        
        const runBoxWin = document.createElement('div');
        runBoxWin.className = 'terminal-line terminal-command-box';
        runBoxWin.textContent = commands.runCommandWin;
        terminal.appendChild(runBoxWin);
        
        // Create copy button for Windows run command
        const runCopyBtnWin = document.createElement('button');
        runCopyBtnWin.className = 'terminal-copy-btn';
        runCopyBtnWin.textContent = 'Copy Windows Command';
        runCopyBtnWin.onclick = function() {
            copyToClipboard(commands.runCommandWin);
            runCopyBtnWin.textContent = 'Copied!';
            setTimeout(() => {
                runCopyBtnWin.textContent = 'Copy Windows Command';
            }, 1500);
        };
        terminal.appendChild(runCopyBtnWin);
        
        // Add prerequisites section
        const prerequisites = document.createElement('div');
        prerequisites.className = 'terminal-line terminal-prerequisites';
        prerequisites.innerHTML = `<h4>Prerequisites:</h4>
<p>You need Node.js installed on your computer to run this command.</p>
<p>If you don't have Node.js installed:</p>
<p>1. Download and install from <a href="https://nodejs.org" target="_blank">nodejs.org</a> (LTS version recommended)</p>
<p>2. Verify installation by typing <code>node --version</code> in your terminal</p>`;
        terminal.appendChild(prerequisites);
        
        // Add instructions
        const instructions = document.createElement('div');
        instructions.className = 'terminal-line terminal-instructions';
        instructions.innerHTML = `<h4>Instructions:</h4>
<p>1. <strong>First, with an internet connection</strong>: Navigate to the recovery tool directory and run the Step 1 install command</p>
<p>2. <strong>Then, disconnect from the internet</strong> for maximum security</p>
<p>3. Run the Step 2 command to execute the ${chain.toUpperCase()} transaction in offline mode</p>
<p class="security-tip">For maximum security, perform Step 1 and Step 2 in separate sessions. Install dependencies while connected to the internet, then disconnect completely before performing the actual transaction with your private keys.</p>
<p class="security-tip">Ideally, use a disposable virtual machine (VM) that you can discard after the recovery process is complete.</p>`;
        terminal.appendChild(instructions);
    }
    
    // Close command display
    function closeTerminal(chain) {
        // Hide terminal container
        document.getElementById(`${chain}-terminal-container`).style.display = 'none';
    }
    
    // Generate and display a balance check command
    function createBalanceCheckCommand(chain) {
        // Get terminal element and container
        const terminal = document.getElementById(`${chain}-terminal`);
        const terminalContainer = document.getElementById(`${chain}-terminal-container`);
        
        // Clear terminal
        terminal.innerHTML = '';
        
        // Show terminal container
        terminalContainer.style.display = 'block';
        
        // Generate the command with --check-balance flag
        let scriptPath, command, args = [];
        
        args.push("--check-balance");
        
        switch (chain) {
            case 'xrpl':
                scriptPath = "scripts/xrpl-tool";
                
                // For XRPL, we'll use the address directly instead of private key for balance check
                if (recoveredKeys.xrplAddress) {
                    args.push("--address", recoveredKeys.xrplAddress);
                } else {
                    // Fallback to using private key if address isn't available
                    args.push("--private-key", recoveredKeys.eddsaPrivateKey);
                    args.push("--public-key", recoveredKeys.eddsaPublicKey);
                }
                
                const xrplNetwork = document.querySelector('input[name="xrpl-network"]:checked').value;
                args.push("--network", xrplNetwork);
                break;
                
            case 'bittensor':
                scriptPath = "scripts/bittensor-tool";
                
                // For Bittensor, use the address directly
                if (recoveredKeys.bittensorAddress) {
                    args.push("--address", recoveredKeys.bittensorAddress);
                } else {
                    // Fallback to using private key if address isn't available
                    args.push("--private-key", recoveredKeys.eddsaPrivateKey);
                }
                
                const bittensorNetwork = document.querySelector('input[name="bittensor-network"]:checked').value;
                
                // Set the correct endpoint based on network selection
                const endpoint = bittensorNetwork === 'mainnet' 
                    ? 'wss://entrypoint-finney.opentensor.ai:443'
                    : 'wss://test.finney.opentensor.ai:443';
                    
                args.push("--network", bittensorNetwork);
                break;
                
            case 'solana':
                scriptPath = "scripts/solana-tool";
                
                // For Solana, use the address directly
                if (recoveredKeys.solanaAddress) {
                    args.push("--address", recoveredKeys.solanaAddress);
                } else {
                    // Fallback to using private key if address isn't available
                    args.push("--private-key", recoveredKeys.eddsaPrivateKey);
                }
                
                const solanaNetwork = document.querySelector('input[name="solana-network"]:checked').value;
                args.push("--network", solanaNetwork);
                break;
                
            default:
                console.error('Unsupported chain for balance check:', chain);
                return;
        }
        
        // Create two separate commands with cross-platform return to original directory
        // For Unix/Linux/Mac (bash/zsh)
        const installCommand = `cd ${scriptPath} && npm install && cd -`;
        const runCommand = `cd ${scriptPath} && npm start -- ${args.join(' ')} && cd -`;
        
        // For Windows CMD
        const installCommandWin = `pushd ${scriptPath} && npm install && popd`;
        const runCommandWin = `pushd ${scriptPath} && npm start -- ${args.join(' ')} && popd`;
        
        // Display the commands, indicating this is a balance check
        displayCommand(terminal, { 
            installCommand, 
            runCommand,
            installCommandWin,
            runCommandWin
        }, chain, true);
    }
});
