// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.
package recoverypipeline

import (
	"fmt"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
)

// pickLatestDRRequestID picks a vault's current reshare by walking the .dr previousRequestId
// chain for the one request id no other entry references, honoring -request-id if set. An
// ambiguous chain is a hard error once a vault is selected (a wrong guess reconstructs the wrong
// key), but tolerated with a best-effort pick during listing.
func pickLatestDRRequestID(byRequestID map[string]*drVaultShares, vID string, requestIDOverride string, justListingVaults bool) (string, error) {
	if !justListingVaults && requestIDOverride != "" {
		if _, ok := byRequestID[requestIDOverride]; !ok {
			return "", nil // not a show stopper: this vault has no .dr shares matching the override
		}
		return requestIDOverride, nil
	}

	referenced := make(map[string]bool, len(byRequestID))
	for _, entry := range byRequestID {
		if entry.previousRequestId != "" {
			referenced[entry.previousRequestId] = true
		}
	}
	var head string
	heads := 0
	for requestID := range byRequestID {
		if !referenced[requestID] {
			head = requestID
			heads++
		}
	}
	if heads == 1 || justListingVaults {
		return head, nil
	}
	return "", fmt.Errorf("⚠ vault %s: found %d root epoch(s) among its .dr files' previousRequestId chain (expected exactly 1): %w", vID, heads, ErrAmbiguousRootRequestID)
}

// rejectOnRequestIDDisagreement hard-errors if vID's chosen request id disagrees with one already
// recorded for it, since mixing shares from two reshares would silently produce a wrong key.
func rejectOnRequestIDDisagreement(vID, requestID string, clearVaults ClearVaultMap, vaultLastRequestIDs map[string]string) error {
	if glbRequestID, ok := vaultLastRequestIDs[vID]; ok && glbRequestID != requestID {
		vaultName := vID
		if cv, ok2 := clearVaults[vID]; ok2 && cv != nil {
			vaultName = cv.Name
		}
		return fmt.Errorf("⚠ vault `%s`: %w (%s vs %s)", vaultName, ErrRequestIDMismatch, glbRequestID, requestID)
	}
	vaultLastRequestIDs[vID] = requestID
	return nil
}

// pickLastLegacyNonce picks the highest nonce surviving the -nonce override, warning if it
// disagrees with another legacy file's pick for the same vault. The warning's CLI-flag wording is
// swapped for a neutral one when presentation.Path is set (the web frontend). Returns -1 if no
// nonce survives the override.
func pickLastLegacyNonce(nonces map[int]bool, vID string, clearVaults ClearVaultMap, nonceOverride int, nonceOverrideSet bool,
	justListingVaults bool, vaultLastLegacyNonces map[string]int, presentation ErrorPresentation) int {

	lastReshareNonce := -1
	for nonce := range nonces {
		// support the -nonce flag to override the last reshare nonce we use
		if !justListingVaults && nonceOverrideSet && nonceOverride != nonce {
			continue
		}
		if nonce > lastReshareNonce {
			lastReshareNonce = nonce
		}
	}
	if lastReshareNonce == -1 {
		return -1
	}
	if glbLastReShareNonce, ok := vaultLastLegacyNonces[vID]; ok && glbLastReShareNonce != lastReshareNonce {
		vaultName := vID
		if cv, ok2 := clearVaults[vID]; ok2 && cv != nil {
			vaultName = cv.Name
		}
		if presentation.Path == nil {
			fmt.Println(ui.PlainTextf("\n⚠ Non matching reshare nonce for vault `%s`. You may have to specify prior reshare config with -nonce and -threshold when recovering that vault.", vaultName))
			if lastReshareNonce-1 >= 0 {
				fmt.Println(ui.PlainTextf("⚠ If you have problems recovering that vault, you could try: -vault-id %s -nonce %d -threshold x. Replace x with previous vault threshold.", vID, lastReshareNonce-1))
			} else {
				fmt.Println()
			}
		} else {
			fmt.Println(ui.PlainTextf("\n⚠ Non matching reshare nonce for vault `%s`. You may have to specify a prior reshare config when recovering that vault.", vaultName))
			if lastReshareNonce-1 >= 0 {
				fmt.Println(ui.PlainTextf("⚠ If you have problems recovering that vault, try the previous reshare nonce (%d) and that reshare's threshold.", lastReshareNonce-1))
			} else {
				fmt.Println()
			}
		}
	}
	vaultLastLegacyNonces[vID] = lastReshareNonce
	return lastReshareNonce
}
