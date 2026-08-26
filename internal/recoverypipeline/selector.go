// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.
package recoverypipeline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/IoFinnet/io-vault-disaster-recovery-cli/internal/ui"
)

// pick selects which reshare to recover from this chain. Returns "" with no error
// when .dr shares should be skipped for this vault (override didn't match, or the
// JSON path alone has quorum at a different reshare).
func (c drReshareChain) pick(override, manifestHint string, json jsonContribution) (string, []Warning, error) {
	if len(c) == 0 {
		return "", nil, nil
	}

	// Explicit override.
	if override != "" {
		if _, ok := c[override]; !ok {
			return "", nil, nil
		}
		return override, nil, nil
	}

	// JSON path alone has quorum at a reshare not in this chain — skip .dr.
	if json.RequestID != "" && json.ECDSA > 0 {
		if _, inChain := c[json.RequestID]; !inChain {
			if entry := c[chainHeadID(c)]; entry != nil && entry.threshold > 0 &&
				json.ECDSA >= entry.threshold &&
				(!entry.hasEdDSA || json.EdDSA >= entry.threshold) {
				return "", nil, nil
			}
		}
	}

	// Manifest hint.
	if manifestHint != "" {
		if entry, ok := c[manifestHint]; ok {
			extra := jsonExtras(manifestHint, json)
			if hasQuorum(entry, extra.ECDSA, extra.EdDSA) {
				return manifestHint, nil, nil
			}
		}
	}

	// Chain walk.
	ordered, roots := chainHead(c)

	var warnings []Warning
	if len(roots) > 1 {
		sort.Strings(roots)
		warnings = append(warnings, Warning{
			Code:    WarningReshareAmbiguousRoot,
			Message: fmt.Sprintf("found %d disconnected roots in previousRequestId chain (candidates: %s)", len(roots), strings.Join(roots, ", ")),
		})
		return "", warnings, fmt.Errorf("%w (candidates: %s)", ErrAmbiguousRootRequestID, strings.Join(roots, ", "))
	}

	// Walk newest-to-oldest, pick first viable.
	for _, reqID := range ordered {
		entry := c[reqID]
		extra := jsonExtras(reqID, json)
		if hasQuorum(entry, extra.ECDSA, extra.EdDSA) {
			if reqID != ordered[0] {
				warnings = append(warnings, Warning{
					Code:    WarningReshareFallback,
					Message: fmt.Sprintf("chain head not viable, fell back to older reshare %s", reqID),
				})
			}
			return reqID, warnings, nil
		}
	}

	// No viable reshare found.
	if len(ordered) > 0 {
		head := c[ordered[0]]
		extra := jsonExtras(ordered[0], json)
		ecdsaCount := len(head.ecdsa) + extra.ECDSA
		eddsaCount := len(head.eddsa) + extra.EdDSA
		if head.hasEdDSA {
			return "", warnings, fmt.Errorf("not enough shares at any reshare (best candidate %s: %d/%d ECDSA, %d/%d EdDSA, need %d)",
				ordered[0], ecdsaCount, head.threshold, eddsaCount, head.threshold, head.threshold)
		}
		return "", warnings, fmt.Errorf("not enough shares at any reshare (best candidate %s: %d ECDSA, need %d)",
			ordered[0], ecdsaCount, head.threshold)
	}
	return "", warnings, fmt.Errorf("no reshares found in chain")
}

// pickForListing returns a best-effort reshare for the vault listing pass.
// Always returns a request id (never empty for a non-empty chain), never errors.
func (c drReshareChain) pickForListing() string {
	if len(c) == 0 {
		return ""
	}
	return chainHeadID(c)
}

// chainHead returns request IDs ordered newest-first by finding unpointed-to roots
// and walking previousRequestId. Multiple roots means an ambiguous chain.
func chainHead(c drReshareChain) (ordered []string, roots []string) {
	referenced := make(map[string]bool, len(c))
	for _, entry := range c {
		if entry.previousRequestId != "" {
			referenced[entry.previousRequestId] = true
		}
	}
	for reqID := range c {
		if !referenced[reqID] {
			roots = append(roots, reqID)
		}
	}

	if len(roots) == 0 {
		// Cycle: every node is referenced. Treat all as disconnected roots.
		for reqID := range c {
			roots = append(roots, reqID)
		}
		sort.Strings(roots)
		return roots, roots
	}

	sort.Strings(roots)

	// Roots are newest (nothing points to them). Walk each one down via previousRequestId.
	visited := make(map[string]bool, len(c))
	for i := len(roots) - 1; i >= 0; i-- {
		cur := roots[i]
		for cur != "" && !visited[cur] {
			entry, ok := c[cur]
			if !ok {
				break
			}
			visited[cur] = true
			ordered = append(ordered, cur)
			cur = entry.previousRequestId
		}
	}
	return ordered, roots
}

// chainHeadID is a shortcut that returns a single head request id (lex-max root).
func chainHeadID(c drReshareChain) string {
	_, roots := chainHead(c)
	if len(roots) == 0 {
		return ""
	}
	sort.Strings(roots)
	return roots[len(roots)-1]
}

// hasQuorum reports whether a reshare has enough shares for reconstruction.
// extraECDSA/extraEdDSA are shares from other paths (e.g. JSON/mobile) that will
// combine with this reshare's .dr shares at reconstruction time.
func hasQuorum(entry *drVaultShares, extraECDSA, extraEdDSA int) bool {
	if entry.threshold < 1 {
		return false
	}
	if len(entry.ecdsa)+extraECDSA < entry.threshold {
		return false
	}
	if entry.hasEdDSA && len(entry.eddsa)+extraEdDSA < entry.threshold {
		return false
	}
	return true
}

// jsonExtras returns the extra share counts to add when evaluating a specific reshare.
// JSON-path shares count when they belong to the same reshare, OR when they have no
// request ID (legacy shares are not bound to a specific reshare).
func jsonExtras(reqID string, json jsonContribution) jsonContribution {
	if json.RequestID == "" || json.RequestID == reqID {
		return json
	}
	return jsonContribution{}
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
