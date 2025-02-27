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
    
    // Current state
    let fileCounter = 1;
    let selectedVaultId = null;
    
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
        
        // Clear advanced options
        document.getElementById('nonce-override').value = '';
        document.getElementById('quorum-override').value = '';
        document.getElementById('export-password').value = '';
        document.getElementById('export-file').value = 'wallet.json';
        
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
    
    // Initialize file input event listeners
    initializeFileInputs();
});