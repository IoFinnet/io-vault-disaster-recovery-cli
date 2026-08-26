// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package recoverypipeline

import (
	"encoding/json"
	"fmt"
	"strconv"

	ecdsa_keygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	eddsa_keygen "github.com/binance-chain/tss-lib/eddsa/keygen"
)

const (
	v2MagicPrefix = "_V2_"
)

// WarningCode labels warning categories
type WarningCode string

const (
	WarningManifestIgnored      WarningCode = "manifest.ignored"
	WarningBundleEntryIgnored   WarningCode = "bundle.entry-ignored" // entry DROPPED
	WarningBundleFileProblem    WarningCode = "bundle.file-problem"  // kept; manifest flags it
	WarningBundleFileMismatch   WarningCode = "bundle.file-mismatch" // kept anyway, or declared-but-absent
	WarningDuplicateArtifact    WarningCode = "input.duplicate-artifact"
	WarningCleanupFailed        WarningCode = "cleanup.failed"
	WarningReshareAmbiguousRoot WarningCode = "reshare.ambiguous-root"
	WarningReshareFallback      WarningCode = "reshare.fallback-older"
)

// Warning is a non-fatal finding. Never carries key material.
type Warning struct {
	Code      WarningCode
	Message   string
	VaultID   string
	RequestID string
	SourceID  string
}

type (
	SavedData struct {
		Vaults map[string]VaultEntry `json:"vaults"`
	}

	// VaultEntry is one vault's entry in a legacy mnemonic-encrypted JSON file's "vaults" map.
	// Two on-disk shapes exist, detected and normalized by UnmarshalJSON:
	//   - legacy (real, already-existing exports, and the only shape this tool ever produced):
	//     a flat map of reshare-nonce-string -> CipheredVault, e.g. {"2": {...}, "3": {...}}.
	//     There is no signal for "which reshare is current" beyond the nonce itself, so these are
	//     decoded into LegacyByNonce and picked by highest nonce (same as always).
	//   - v4 mobile app export: {"currentRequestId": "<uuid>", "requests": {"<uuid>": {...}}}.
	//     The exporter (which has live access to io-sign) directly names the current request,
	//     so no picking is needed - see CurrentRequestID/Requests.
	VaultEntry struct {
		IsLegacy         bool
		LegacyByNonce    map[int]CipheredVault
		CurrentRequestID string
		Requests         map[string]CipheredVault
	}

	CipheredVault struct {
		CipherTextB64 string       `json:"ciphertext"`
		CipherParams  CipherParams `json:"cipherparams"`
		Cipher        string       `json:"cipher"`
		Hash          string       `json:"hash"`
	}
	CipherParams struct {
		IV  string `json:"iv"`
		Tag string `json:"tag"`
	}

	ClearVaultMap   map[string]*ClearVault
	ClearVaultCurve struct {
		Algorithm string   `json:"algorithm"`
		Shares    []string `json:"shares"`
	}
	ClearVault struct {
		Name         string   `json:"name"`
		Quroum       int      `json:"threshold"`
		SharesLegacy []string `json:"shares"`
		// LastRequestID is the identifier of the reshare actually chosen for this vault: the
		// request id string for a .dr file or v4 JSON entry, or the legacy reshare nonce
		// formatted as a string for an old flat-nonce JSON entry (there is no request id in
		// that case, so the nonce stands in as that identifier).
		LastRequestID string            `json:"-"`
		Curves        []ClearVaultCurve `json:"curves"`
	}

	VaultAllSharesECDSA map[string][]*ecdsa_keygen.LocalPartySaveData
	VaultAllSharesEdDSA map[string][]*eddsa_keygen.LocalPartySaveData

	// drVaultShares accumulates one reshare's worth of .dr shares for a vault (one .dr file
	// per device per algorithm, all sharing the same RequestId), pending the "pick the current
	// reshare" selection in runTool. previousRequestId is that reshare's chain pointer (empty for
	// a keygen-originated reshare), used to walk the chain across a vault's .dr files.
	drVaultShares struct {
		threshold         int
		previousRequestId string
		ecdsa             []*ecdsa_keygen.LocalPartySaveData
		eddsa             []*eddsa_keygen.LocalPartySaveData
		hasEdDSA          bool
	}

	// drReshareChain is one vault's .dr shares grouped by request id. Each entry is
	// one reshare; the previousRequestId fields link them into a chain.
	drReshareChain map[string]*drVaultShares

	// jsonContribution describes what the JSON/mobile path already contributed for a
	// vault before the .dr selection runs.
	jsonContribution struct {
		RequestID string // which reshare the mobile shares belong to, "" if none
		ECDSA     int    // ECDSA shares already in the pool
		EdDSA     int    // EdDSA shares already in the pool
	}

	SaveData interface{}
)

// UnmarshalJSON detects whether a vault entry is the legacy flat nonce-keyed shape or the v4
// {currentRequestId, requests} shape and normalizes either into VaultEntry.
func (v *VaultEntry) UnmarshalJSON(raw []byte) error {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return err
	}

	if rawRequests, ok := probe["requests"]; ok {
		var requests map[string]CipheredVault
		if err := json.Unmarshal(rawRequests, &requests); err != nil {
			return fmt.Errorf("invalid v4 vault entry \"requests\": %w", err)
		}
		var currentRequestID string
		if rawCurrent, ok := probe["currentRequestId"]; ok {
			if err := json.Unmarshal(rawCurrent, &currentRequestID); err != nil {
				return fmt.Errorf("invalid v4 vault entry \"currentRequestId\": %w", err)
			}
		}
		if currentRequestID == "" {
			return fmt.Errorf("invalid v4 vault entry: missing or empty \"currentRequestId\"")
		}
		if _, ok := requests[currentRequestID]; !ok {
			return fmt.Errorf("invalid v4 vault entry: \"currentRequestId\" %q not present in \"requests\"", currentRequestID)
		}
		v.CurrentRequestID = currentRequestID
		v.Requests = requests
		return nil
	}

	legacy := make(map[int]CipheredVault, len(probe))
	for key, rawCV := range probe {
		nonce, err := strconv.Atoi(key)
		if err != nil {
			return fmt.Errorf("invalid vault entry key %q: expected a reshare nonce or a v4 \"requests\" map", key)
		}
		var cv CipheredVault
		if err := json.Unmarshal(rawCV, &cv); err != nil {
			return fmt.Errorf("invalid vault entry for nonce %d: %w", nonce, err)
		}
		legacy[nonce] = cv
	}
	v.IsLegacy = true
	v.LegacyByNonce = legacy
	return nil
}
