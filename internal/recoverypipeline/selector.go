// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.
package recoverypipeline

import (
	"fmt"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
)

// pickLatestDRRequestID selects the current epoch's request id for a vault from its .dr files, by
// walking the previousRequestId chain built by processDRFile: the request id in byRequestID that
// is not referenced as any other entry's previousRequestId is the head (most recent) epoch.
// Honors the -request-id override, used directly instead of chain-walking.
//
// Unlike a legacy reshare nonce (where "highest wins" is always well-defined even amid
// disagreement across files), an ambiguous chain has no safe fallback: if !justListingVaults, an
// ambiguous chain without an override is a hard error rather than a guess, since a wrong guess
// here reconstructs the wrong key. During listing (no vault selected yet), ambiguity is tolerated
// with a best-effort pick, since nothing here yet influences key reconstruction.
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
	return "", fmt.Errorf("⚠ vault %s: found %d root epoch(s) among its .dr files' previousRequestId chain (expected exactly 1): %w", vID, heads, ErrAmbiguousEpoch)
}

// rejectOnRequestIDDisagreement records vID's chosen request id and errors out if it disagrees
// with the request id already recorded for vID from a previously-processed v4 JSON entry or the
// .dr chain's resolved head: mixing shares from two different reshare epochs into one
// reconstruction pool would silently produce a wrong key, so this must be a hard error rather
// than a warning. Tracked separately from the legacy nonce disagreement warning in
// pickLastLegacyNonce, since a nonce and a request id are never comparable.
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

// pickLastLegacyNonce selects the reshare nonce to use for a vault from the set of nonces found
// in one legacy flat-nonce JSON file (honoring the -nonce override), warning if it disagrees with
// the nonce already picked for this vault from another legacy file. Returns -1 if no nonce
// survives the override filter.
//
// The disagreement warning is CLI-flag wording (-nonce, -threshold, -vault-id) printed directly to
// stdout, so it is only meaningful for the CLI frontend; presentation.Path is nil only for the
// CLI's zero-value ErrorPresentation (see Options doc comment), so it doubles as that signal here.
// The web frontend gets a neutral warning instead, since it has no such flags and this print
// reaches the server's log, not the browser.
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
