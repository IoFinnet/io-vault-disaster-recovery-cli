// Copyright (C) 2021 io finnet group, inc.
// SPDX-License-Identifier: AGPL-3.0-or-later
// Full license text available in LICENSE file in repository root.

package main

func toBitcoinWIF(privKey []byte, testNet, compressed bool) string {
	if compressed {
		// Append 0x01 to tell Bitcoin wallet to use compressed public keys
		privKey = append(privKey, []byte{0x01}...)
	}
	// Convert bytes to base-58 check encoded string with version 0x80 (mainnet) or 0xef (testnet)
	ver := uint8(0x80)
	if testNet {
		ver = 0xef
	}
	return b58checkencode(ver, privKey)
}
