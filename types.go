// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

import (
	ecdsa_keygen "github.com/iofinnet/tss-lib/v3/tss/ecdsa/keygen"
	eddsa_keygen "github.com/iofinnet/tss-lib/v3/tss/schnorr/keygen"
)

type (
	SavedData struct {
		Vaults map[string]CipheredVaultMap `json:"vaults"`
	}

	CipheredVaultMap map[int]CipheredVault

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
		Name             string            `json:"name"`
		Quroum           int               `json:"threshold"`
		SharesLegacy     []string          `json:"shares"`
		LastReShareNonce int               `json:"-"`
		Curves           []ClearVaultCurve `json:"curves"`
	}

	VaultAllSharesECDSA map[string][]*ecdsa_keygen.LocalPartySaveData
	VaultAllSharesEdDSA map[string][]*eddsa_keygen.LocalPartySaveData

	SaveData interface {
	}
)
