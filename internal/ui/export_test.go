// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package ui

// LooksLikeLegacyFlatNonceJSONForTest exports the peek helper for external tests.
var LooksLikeLegacyFlatNonceJSONForTest = looksLikeLegacyFlatNonceJSON

// Synthetic SavedData shapes for tests (no key material). Mobile v4 and v5 share the
// same pre-decrypt wrapper, so one fixture covers both beside bundles.
const (
	LegacyFlatNonceJSONForTest = `{"vaults":{"v1":{"0":{"ciphertext":"YQ==","nonce":"YQ=="}}}}`
	MobileWrapperJSONForTest   = `{"vaults":{"v1":{"currentRequestId":"req-1","requests":{"req-1":{"ciphertext":"YQ==","nonce":"YQ=="}}}}}`
)
